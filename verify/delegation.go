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

// Voucher is a verified grant voucher (RFC-AITP-0005 §8).
type Voucher struct {
	Iss, Sub string
	Grants   []string
	IAT, Exp int64
	SrcJTI   string
}

// VoucherOptions configures [VerifyVoucher].
type VoucherOptions struct {
	// Now is the verifier's current time in Unix seconds.
	Now int64
	// SelfAID is the verifier's own AID. A voucher is only ever verified
	// by its issuer, under its own key.
	SelfAID string
}

// VerifyVoucher verifies a grant voucher as its issuer does
// (RFC-AITP-0006 §4 steps 3 and 5): typ (TOKEN_TYP_MISMATCH), claims
// (DELEGATION_INVALID_VOUCHER, UNKNOWN_FIELD), the AID-pinned alg
// (TOKEN_ALG_MISMATCH), iss and signature under the verifier's own key
// (DELEGATION_INVALID_VOUCHER), then expiry (DELEGATION_EXPIRED).
func VerifyVoucher(token string, opts VoucherOptions) (*Voucher, error) {
	v, err := verifyVoucherSignature(token, opts.SelfAID)
	if err != nil {
		return nil, err
	}
	if v.Exp <= opts.Now {
		return nil, fail(aitpverifier.CodeDelegationExpired, "voucher exp %d is not after now %d", v.Exp, opts.Now)
	}
	return v, nil
}

func verifyVoucherSignature(token, selfAID string) (*Voucher, error) {
	invalid := func(format string, args ...any) error {
		return fail(aitpverifier.CodeDelegationInvalidVoucher, format, args...)
	}
	self, err := aid.Parse(selfAID)
	if err != nil {
		return nil, errors.New("verify: VoucherOptions.SelfAID is not a valid AID")
	}
	tok, err := jws.Parse(token)
	if err != nil {
		return nil, invalid("voucher: %v", err)
	}
	if err := tok.CheckTyp(TypVoucher); err != nil {
		return nil, fail(aitpverifier.CodeTokenTypMismatch, "voucher: %v", err)
	}
	f, _ := asObject(tok.Payload)
	v := &Voucher{}
	var ok bool
	if ver, ok := f.str("ver"); !ok || ver != Version {
		return nil, invalid("voucher ver is not %s", Version)
	}
	if v.Iss, ok = f.match("iss", reAID); !ok {
		return nil, invalid("voucher iss is not an AID")
	}
	if v.Sub, ok = f.match("sub", reAID); !ok {
		return nil, invalid("voucher sub is not an AID")
	}
	if v.Grants, ok = f.strings("grants", reNoSpace, 1); !ok {
		return nil, invalid("voucher grants is not a non-empty unique grant array")
	}
	if v.IAT, ok = f.integer("iat", 0); !ok {
		return nil, invalid("voucher iat is not a non-negative integer")
	}
	if v.Exp, ok = f.integer("exp", 1); !ok {
		return nil, invalid("voucher exp is not a positive integer")
	}
	if v.SrcJTI, ok = f.match("src_jti", reUUIDv4); !ok {
		return nil, invalid("voucher src_jti is not a UUIDv4")
	}
	if x, ok := f.get("ext"); ok && x.Kind != strictjson.Object {
		return nil, invalid("voucher ext is not an object")
	}
	if k, ok := f.unknown("ver", "iss", "sub", "grants", "iat", "exp", "src_jti", "ext"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "voucher claim %q is not registered", k)
	}
	if err := tok.CheckAlg(self.Key()); err != nil {
		return nil, fail(aitpverifier.CodeTokenAlgMismatch, "voucher: %v", err)
	}
	if v.Iss != selfAID {
		return nil, invalid("voucher iss %s is not the verifier's own AID", v.Iss)
	}
	if err := tok.VerifySignature(self.Key()); err != nil {
		return nil, invalid("voucher signature: %v", err)
	}
	return v, nil
}

// Delegation is a verified single-hop delegation token (RFC-AITP-0006).
type Delegation struct {
	Iss, Sub, Aud string
	Scope         []string
	Exp           int64
	Voucher       *Voucher
	sub           *aid.AID
}

// SubjectKey returns the raw public key of the delegate (the sub AID),
// against which the RFC-AITP-0006 §4 step 9 PoP exchange runs.
func (d *Delegation) SubjectKey() []byte { return d.sub.Key().Raw() }

// DelegationOptions configures [VerifyDelegation].
type DelegationOptions struct {
	// Now is the verifier's current time in Unix seconds.
	Now int64
	// SelfAID is the verifier's own AID (the token's aud and the voucher's
	// iss).
	SelfAID string
	// IssuerManifests is the verifier's whole Manifest source. The
	// delegator's key comes from the Manifest whose aid is the token's iss;
	// none ⇒ KEY_RESOLUTION_FAILED.
	IssuerManifests [][]byte
	// OwnRevocationList, when set, is the verifier's own deny list as a
	// signed snapshot (step 7). Its own failures keep their codes.
	OwnRevocationList []byte
}

// VerifyDelegation runs RFC-AITP-0006 §4 steps 1 to 8 and the multi-hop
// guard. Step 9, proof of possession by the delegate, is the caller's: run
// the RFC-AITP-0005 §6 exchange against [Delegation.SubjectKey] (or rely on
// a documented channel binding) and report DELEGATION_POP_FAILED.
func VerifyDelegation(token string, opts DelegationOptions) (*Delegation, error) {
	sigFail := func(format string, args ...any) error {
		return fail(aitpverifier.CodeDelegationInvalidSignature, format, args...)
	}
	tok, err := jws.Parse(token)
	if err != nil {
		return nil, sigFail("delegation token: %v", err)
	}
	f, _ := asObject(tok.Payload)
	if f.has("chain") {
		return nil, fail(aitpverifier.CodeDelegationMultihopNotSupported, "delegation token carries a chain claim (RFC-AITP-0011 is not enabled)")
	}
	if err := tok.CheckTyp(TypDelegation); err != nil {
		return nil, fail(aitpverifier.CodeTokenTypMismatch, "delegation token: %v", err)
	}
	d, voucherToken, jkt, err := delegationClaims(f)
	if err != nil {
		return nil, err
	}
	key, err := keyFromManifests(d.Iss, opts.IssuerManifests, opts.Now)
	if err != nil {
		return nil, err
	}
	if err := tok.CheckAlg(key); err != nil {
		return nil, fail(aitpverifier.CodeTokenAlgMismatch, "delegation token: %v", err)
	}
	if err := tok.VerifySignature(key); err != nil {
		return nil, sigFail("delegation signature: %v", err)
	}
	// Step 2.
	if d.Aud != opts.SelfAID {
		return nil, fail(aitpverifier.CodeDelegationAudienceMismatch, "aud %s is not %s", d.Aud, opts.SelfAID)
	}
	if d.Exp <= opts.Now {
		return nil, fail(aitpverifier.CodeDelegationExpired, "exp %d is not after now %d", d.Exp, opts.Now)
	}
	// Step 3: every voucher failure other than typ is DELEGATION_INVALID_VOUCHER.
	v, err := verifyVoucherSignature(voucherToken, opts.SelfAID)
	if err != nil {
		if code := CodeOf(err); code != aitpverifier.CodeTokenTypMismatch && code != "" {
			return nil, recode(err, aitpverifier.CodeDelegationInvalidVoucher)
		}
		return nil, err
	}
	d.Voucher = v
	// Step 4.
	if v.Sub != d.Iss {
		return nil, fail(aitpverifier.CodeDelegationInvalidVoucher, "voucher sub %s is not the delegator %s", v.Sub, d.Iss)
	}
	// Step 5.
	if v.Exp <= opts.Now || d.Exp > v.Exp {
		return nil, fail(aitpverifier.CodeDelegationExpired, "delegation exp %d must not outlive a live voucher (exp %d)", d.Exp, v.Exp)
	}
	// Step 6.
	if g, ok := subset(d.Scope, v.Grants); !ok {
		return nil, fail(aitpverifier.CodeDelegationScopeExceeded, "scope %q is not in the voucher grants", g)
	}
	// Step 7: the verifier's own list, local state; no policy applies.
	if opts.OwnRevocationList != nil {
		snap, err := VerifySnapshot(opts.OwnRevocationList, SnapshotOptions{Now: opts.Now, ExpectedIssuer: opts.SelfAID, MaxStalenessSecs: -1})
		if err != nil && !errors.Is(err, ErrSnapshotDiscarded) {
			return nil, err
		}
		if err != nil {
			return nil, fail(aitpverifier.CodeRevocationSnapshotInvalid, "own deny list: %v", err)
		}
		if snap.Revoked(v.SrcJTI) {
			return nil, fail(aitpverifier.CodeDelegationSourceTctRevoked, "source TCT %s is revoked", v.SrcJTI)
		}
	}
	// Step 8.
	if d.Iss == d.Sub || d.sub.SameKey(mustAID(d.Iss)) {
		return nil, sigFail("self-delegation (iss == sub)")
	}
	// The cnf binding that step 9 relies on.
	if jwk.Thumbprint(d.sub.Key()) != jkt {
		return nil, fail(aitpverifier.CodeDelegationPopFailed, "cnf.jkt is not the thumbprint of the sub key")
	}
	return d, nil
}

func mustAID(s string) *aid.AID {
	a, _ := aid.Parse(s)
	return a
}

func delegationClaims(f fields) (*Delegation, string, string, error) {
	bad := func(what string) (*Delegation, string, string, error) {
		return nil, "", "", fail(aitpverifier.CodeDelegationInvalidSignature, "delegation claim %s", what)
	}
	d := &Delegation{}
	var ok bool
	if ver, ok := f.str("ver"); !ok || ver != Version {
		return bad("ver is not " + Version)
	}
	if d.Iss, ok = f.match("iss", reAID); !ok || mustAID(d.Iss) == nil {
		return bad("iss is not a valid AID")
	}
	if d.Sub, ok = f.match("sub", reAID); !ok {
		return bad("sub is not an AID")
	}
	if d.sub = mustAID(d.Sub); d.sub == nil {
		return bad("sub does not encode a valid key")
	}
	if d.Aud, ok = f.match("aud", reAID); !ok {
		return bad("aud is not an AID")
	}
	if d.Scope, ok = f.strings("scope", reNoSpace, 1); !ok {
		return bad("scope is not a non-empty unique grant array")
	}
	if d.Exp, ok = f.integer("exp", 1); !ok {
		return bad("exp is not a positive integer")
	}
	jkt, err := cnfClaim(f)
	if err != nil {
		if CodeOf(err) == aitpverifier.CodeUnknownField {
			return nil, "", "", err
		}
		return nil, "", "", recode(err, aitpverifier.CodeDelegationInvalidSignature)
	}
	voucher, ok := f.match("voucher", reCompact)
	if !ok {
		return bad("voucher is missing or not a compact JWS")
	}
	if f.has("jti") {
		if _, ok := f.match("jti", reUUIDv4); !ok {
			return bad("jti is not a UUIDv4")
		}
	}
	if f.has("chain_hash") {
		return bad("chain_hash without chain")
	}
	if x, ok := f.get("ext"); ok && x.Kind != strictjson.Object {
		return bad("ext is not an object")
	}
	if k, ok := f.unknown("ver", "iss", "sub", "aud", "scope", "exp", "cnf", "voucher", "jti", "ext"); ok {
		return nil, "", "", fail(aitpverifier.CodeUnknownField, "delegation claim %q is not registered", k)
	}
	return d, voucher, jkt, nil
}

// keyFromManifests resolves an issuer's key from the verifier's Manifest
// source (RFC-AITP-0007 §1): the verified Manifest whose aid is issuer.
func keyFromManifests(issuer string, manifests [][]byte, now int64) (*keys.PublicKey, error) {
	for _, data := range manifests {
		m, err := VerifyManifest(data, ManifestOptions{Now: now})
		if err != nil || m.AID != issuer {
			continue
		}
		return m.aid.Key(), nil
	}
	return nil, fail(aitpverifier.CodeKeyResolutionFailed, "no verified Manifest designates a key for %s", issuer)
}
