package verify

import (
	"errors"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jwk"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jws"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// JWS typ values (RFC-AITP-0001 §5.4.5).
const (
	TypTCT        = "aitp-tct+jwt"
	TypVoucher    = "aitp-grant+jwt"
	TypDelegation = "aitp-delegation+jwt"
)

// AttestationGrant is the reserved self-attestation marker grant
// (RFC-AITP-0005 §5.3).
const AttestationGrant = "aitp.attestation"

// TCT is a verified Trust Context Token's claims.
type TCT struct {
	JTI, Iss, Sub, Aud string
	IAT, Exp           int64
	Grants             []string
	JKT                string
	// Degraded is true when revocation status was unknown and a soft_fail
	// policy let the token through (RFC-AITP-0008 §3.1): the caller MUST
	// restrict the grants to its configured safe subset.
	Degraded bool
	ver      string
	iss, sub *aid.AID
}

// TCTOptions configures [VerifyTCT].
type TCTOptions struct {
	// Now is the verifier's current time in Unix seconds.
	Now int64
	// ExpectedAudience is the verifier's own AID (RFC-AITP-0005 §5.2).
	// It is required unless AnyAudience is set.
	ExpectedAudience string
	// AnyAudience skips the audience check. Only for callers that bind the
	// audience some other way (the issuer side of §10.5, which compares it
	// with a PoP-proven presenter instead).
	AnyAudience bool
	// IssuerKey, when set, MUST be the key the iss AID encodes; a TCT whose
	// iss names another key fails with TCT_SIGNATURE_INVALID.
	IssuerKey []byte
	// IssuerManifestExpiresAt, when non-zero, runs the RFC-AITP-0005 §10.4
	// bound: exp MUST NOT exceed it.
	IssuerManifestExpiresAt int64
	// Revocation, when set, is the issuer's revocation source, consulted
	// only after every signature and claims check (RFC-AITP-0008 §3.3).
	// nil means revocation is not checked by this call.
	Revocation RevocationSource
	// RevocationPolicy applies to an absent or discarded snapshot.
	RevocationPolicy RevocationPolicy
}

// VerifyTCT runs RFC-AITP-0005 §7.2 in order, in a grant context (§5.3).
func VerifyTCT(token string, opts TCTOptions) (*TCT, error) {
	if !opts.AnyAudience && opts.ExpectedAudience == "" {
		return nil, errors.New("verify: TCTOptions.ExpectedAudience is required unless AnyAudience is set")
	}
	t, err := verifyTCTSignature(token, opts.IssuerKey)
	if err != nil {
		return nil, err
	}
	if err := t.checkClaims(opts); err != nil {
		return nil, err
	}
	if opts.Revocation != nil {
		st := CheckRevocation(opts.Revocation, opts.RevocationPolicy, t.Iss, t.JTI, opts.Now)
		if st.Revoked {
			return nil, fail(aitpverifier.CodeTctRevoked, "jti %s is revoked, or its revocation status is unknown under fail_closed", t.JTI)
		}
		t.Degraded = st.Degraded
	}
	return t, nil
}

// verifyTCTSignature runs §7.2 steps 1 to 4.
func verifyTCTSignature(token string, issuerKey []byte) (*TCT, error) {
	sigFail := func(format string, args ...any) error {
		return fail(aitpverifier.CodeTctSignatureInvalid, format, args...)
	}
	tok, err := jws.Parse(token)
	if err != nil {
		return nil, sigFail("TCT: %v", err)
	}
	if err := tok.CheckTyp(TypTCT); err != nil {
		return nil, fail(aitpverifier.CodeTokenTypMismatch, "TCT: %v", err)
	}
	t, err := tctClaims(tok.Payload)
	if err != nil {
		return nil, err
	}
	k := t.iss.Key()
	if issuerKey != nil && string(issuerKey) != string(k.Raw()) {
		return nil, sigFail("TCT iss does not encode the resolved issuer key")
	}
	if err := tok.CheckAlg(k); err != nil {
		return nil, fail(aitpverifier.CodeTokenAlgMismatch, "TCT: %v", err)
	}
	if err := tok.VerifySignature(k); err != nil {
		return nil, sigFail("TCT signature: %v", err)
	}
	return t, nil
}

// tctClaims is the claims-membership clause of §7.2 step 1, against
// aitp-tct.schema.json. ver is checked at step 5, so only its type is
// checked here.
func tctClaims(v *strictjson.Value) (*TCT, error) {
	f, _ := asObject(v)
	bad := func(what string) error {
		return fail(aitpverifier.CodeTctSignatureInvalid, "TCT claim %s", what)
	}
	t := &TCT{}
	var ok bool
	if t.ver, ok = f.str("ver"); !ok {
		return nil, bad("ver is missing or not a string")
	}
	if t.JTI, ok = f.match("jti", reUUIDv4); !ok {
		return nil, bad("jti is not a lowercase UUIDv4 (RFC-AITP-0005 §2.2)")
	}
	var err error
	if t.Iss, t.iss, err = aidClaim(f, "iss"); err != nil {
		return nil, bad("iss is not a valid AID")
	}
	if t.Sub, t.sub, err = aidClaim(f, "sub"); err != nil {
		return nil, bad("sub is not a valid AID")
	}
	if t.Aud, ok = f.match("aud", reAID); !ok {
		return nil, bad("aud is not an AID")
	}
	if t.IAT, ok = f.integer("iat", 0); !ok {
		return nil, bad("iat is not a non-negative integer")
	}
	if t.Exp, ok = f.integer("exp", 1); !ok {
		return nil, bad("exp is not a positive integer")
	}
	if t.Grants, ok = f.strings("grants", reNoSpace, 1); !ok {
		return nil, bad("grants is not a non-empty unique array of grant strings")
	}
	if t.JKT, err = cnfClaim(f); err != nil {
		return nil, err
	}
	if x, ok := f.get("ext"); ok && x.Kind != strictjson.Object {
		return nil, bad("ext is not an object")
	}
	if k, ok := f.unknown("ver", "jti", "iss", "sub", "aud", "iat", "exp", "grants", "cnf", "ext"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "TCT claim %q is not registered", k)
	}
	return t, nil
}

func aidClaim(f fields, key string) (string, *aid.AID, error) {
	s, ok := f.match(key, reAID)
	if !ok {
		return "", nil, errors.New("not an AID")
	}
	a, err := aid.Parse(s)
	return s, a, err
}

// cnfClaim validates the cnf object and returns cnf.jkt. Its structural
// code is the TCT's; the delegation token reuses it and recodes.
func cnfClaim(f fields) (string, error) {
	cnf, ok := f.object("cnf")
	if !ok {
		return "", fail(aitpverifier.CodeTctSignatureInvalid, "cnf is missing or not an object")
	}
	jkt, ok := cnf.match("jkt", reJKT)
	if !ok {
		return "", fail(aitpverifier.CodeTctSignatureInvalid, "cnf.jkt is missing or not a 43-character thumbprint")
	}
	if k, ok := cnf.unknown("jkt"); ok {
		return "", fail(aitpverifier.CodeUnknownField, "cnf member %q is not defined", k)
	}
	return jkt, nil
}

// checkClaims is §7.2 step 5 plus the §10.4 bound.
func (t *TCT) checkClaims(opts TCTOptions) error {
	if err := t.checkCommonClaims(opts.Now); err != nil {
		return err
	}
	if !opts.AnyAudience && t.Aud != opts.ExpectedAudience {
		return fail(aitpverifier.CodeAudienceMismatch, "aud %s is not %s", t.Aud, opts.ExpectedAudience)
	}
	if opts.IssuerManifestExpiresAt != 0 && t.Exp > opts.IssuerManifestExpiresAt {
		return fail(aitpverifier.CodeTctExpiresAfterManifest, "exp %d is after the issuer Manifest's expires_at %d", t.Exp, opts.IssuerManifestExpiresAt)
	}
	return nil
}

// checkCommonClaims is step 5 without the audience: ver, exp, cnf.jkt and
// the grant-context rules of §5.3.
func (t *TCT) checkCommonClaims(now int64) error {
	// ver was required to be a string at step 1; its value is checked here.
	if err := t.checkVer(); err != nil {
		return err
	}
	if t.Exp <= now {
		return fail(aitpverifier.CodeTctExpired, "exp %d is not after now %d", t.Exp, now)
	}
	if jwk.Thumbprint(t.sub.Key()) != t.JKT {
		return fail(aitpverifier.CodeTctSignatureInvalid, "cnf.jkt is not the thumbprint of the sub key")
	}
	if t.Iss == t.Sub || t.iss.SameKey(t.sub) {
		return fail(aitpverifier.CodeTctSignatureInvalid, "self-issued TCT (iss == sub) in a grant context (RFC-AITP-0005 §5.3)")
	}
	if contains(t.Grants, AttestationGrant) {
		return fail(aitpverifier.CodeTctSignatureInvalid, "grants carry the %s marker in a grant context (RFC-AITP-0005 §5.3)", AttestationGrant)
	}
	return nil
}

func (t *TCT) checkVer() error {
	if t.ver != Version {
		return fail(aitpverifier.CodeUnknownVersion, "TCT ver is not %s", Version)
	}
	return nil
}

// SubjectKey returns the raw public key the sub AID encodes.
func (t *TCT) subjectKey() *keys.PublicKey { return t.sub.Key() }
