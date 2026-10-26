package verify

import (
	"errors"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jwk"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// Downstream PoP message types (RFC-AITP-0005 §6.1).
const (
	PopChallengeType = "pop_challenge"
	PopResponseType  = "pop_response"
)

// PoP enforcement postures (RFC-AITP-0005 §6.2 conformance note).
const (
	// EnforceForMarked requires PoP only for grants the issuer marked.
	// It is this verifier's default posture.
	EnforceForMarked = "enforce-for-marked-only"
	// EnforceForAll requires PoP for every grant.
	EnforceForAll = "enforce-for-all"
)

// PopPolicy is the per-grant PoP enforcement surface the RFC-AITP-0005
// §6.2 conformance note requires.
type PopPolicy struct {
	// Posture is EnforceForMarked (the default when empty) or
	// EnforceForAll.
	Posture string
	// RequiredGrants are the grants the issuing peer marked as requiring
	// PoP. They are honoured under every posture.
	RequiredGrants []string
}

// Requires reports whether invoking grant needs a valid pop_response.
func (p PopPolicy) Requires(grant string) bool {
	return p.Posture == EnforceForAll || contains(p.RequiredGrants, grant)
}

// PopChallenge is an issued downstream PoP challenge.
type PopChallenge struct {
	TCTJTI, Nonce string
	// ExpiresAt, when non-zero, is when the challenge stops being
	// answerable (Unix seconds). A response at or after it is stale.
	ExpiresAt int64
}

// ParsePopChallenge verifies a pop_challenge envelope (RFC-AITP-0005
// §6.1 step 1). Envelope failures keep their codes; a payload defect is
// POP_CHALLENGE_INVALID.
func ParsePopChallenge(data []byte, opts EnvelopeOptions) (*PopChallenge, error) {
	e, err := VerifyEnvelope(data, opts)
	if err != nil {
		return nil, err
	}
	bad := func(what string) error {
		return fail(aitpverifier.CodePopChallengeInvalid, "pop_challenge %s", what)
	}
	if e.MessageType != PopChallengeType {
		return nil, bad("envelope message_type is " + e.MessageType)
	}
	f, _ := asObject(e.payload)
	c := &PopChallenge{}
	var ok bool
	if c.TCTJTI, ok = f.match("tct_jti", reUUIDv4); !ok {
		return nil, bad("tct_jti is missing or not a UUIDv4")
	}
	if c.Nonce, ok = f.match("nonce", reNonce); !ok {
		return nil, bad("nonce is missing or not a 128-bit base64url nonce")
	}
	if k, ok := f.unknown("tct_jti", "nonce", "extensions"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "pop_challenge payload member %q is not defined", k)
	}
	return c, nil
}

// popResponse is a parsed pop_response envelope.
type popResponse struct {
	env                          *Envelope
	tctJTI, nonceEcho, signature string
}

func parsePopResponse(data []byte, opts EnvelopeOptions) (*popResponse, error) {
	invalid := func(format string, args ...any) error {
		return fail(aitpverifier.CodePopResponseInvalid, format, args...)
	}
	v, err := strictjson.Parse(data)
	if err != nil {
		return nil, invalid("pop_response is not strict JSON: %v", err)
	}
	e, err := parseEnvelope(v, opts)
	if err != nil {
		return nil, recode(err, aitpverifier.CodePopResponseInvalid)
	}
	if e.MessageType != PopResponseType {
		return nil, invalid("envelope message_type is %s, not %s", e.MessageType, PopResponseType)
	}
	f, _ := asObject(e.payload)
	r := &popResponse{env: e}
	var ok bool
	if r.tctJTI, ok = f.match("tct_jti", reUUIDv4); !ok {
		return nil, invalid("pop_response tct_jti is missing or malformed")
	}
	if r.nonceEcho, ok = f.match("nonce_echo", reNonce); !ok {
		return nil, invalid("pop_response nonce_echo is missing or malformed")
	}
	if r.signature, ok = f.match("pop_signature", reSig); !ok {
		return nil, invalid("pop_response pop_signature is missing or malformed")
	}
	if k, ok := f.unknown("tct_jti", "nonce_echo", "pop_signature", "extensions"); ok {
		return nil, invalid("pop_response payload member %q is not defined", k)
	}
	return r, nil
}

// verify runs RFC-AITP-0005 §6.2 against the challenge and the TCT
// whose sub must hold the key. Every failure is POP_RESPONSE_INVALID; a
// stale challenge is POP_CHALLENGE_INVALID.
func (r *popResponse) verify(t *TCT, c PopChallenge, now int64) error {
	invalid := func(format string, args ...any) error {
		return fail(aitpverifier.CodePopResponseInvalid, format, args...)
	}
	if c.ExpiresAt != 0 && now >= c.ExpiresAt {
		return fail(aitpverifier.CodePopChallengeInvalid, "challenge expired at %d (now %d)", c.ExpiresAt, now)
	}
	if c.TCTJTI != t.JTI {
		return fail(aitpverifier.CodePopChallengeInvalid, "challenge is for jti %s, not %s", c.TCTJTI, t.JTI)
	}
	sub := t.sub
	// Step 1: the envelope is the holder's, signed by the sub key.
	if !r.env.senderAID.SameKey(sub) {
		return invalid("pop_response sender is not the TCT sub")
	}
	if err := r.env.verifySignature(sub.Key()); err != nil {
		return invalid("pop_response envelope signature: %v", err)
	}
	// Step 2.
	if r.tctJTI != c.TCTJTI || r.nonceEcho != c.Nonce {
		return invalid("pop_response does not answer this challenge")
	}
	// Step 3.
	if err := verifyNoncePoP(r.signature, sub, c.Nonce); err != nil {
		return invalid("pop_signature does not verify under the sub key: %v", err)
	}
	// Step 4.
	if jwk.Thumbprint(sub.Key()) != t.JKT {
		return invalid("cnf.jkt is not the thumbprint of the sub key")
	}
	return nil
}

// VerifyPopResponse verifies a pop_response envelope against the
// challenge the verifier issued and the TCT being exercised
// (RFC-AITP-0005 §6.2). The TCT must already have been verified.
func VerifyPopResponse(data []byte, t *TCT, c PopChallenge, opts EnvelopeOptions) error {
	if t == nil || t.sub == nil {
		return errors.New("verify: VerifyPopResponse needs a verified TCT")
	}
	r, err := parsePopResponse(data, opts)
	if err != nil {
		return err
	}
	if err := r.verify(t, c, opts.Now); err != nil {
		return err
	}
	opts.Replay.Add(r.env.MessageID, opts.Now)
	return nil
}

// IssuerOptions configures [VerifyTCTAsIssuer].
type IssuerOptions struct {
	// Envelope carries the clock, tolerance and replay cache for the
	// pop_response.
	Envelope EnvelopeOptions
	// SelfAID is the verifier's own AID, which must be the TCT's iss.
	SelfAID string
	// Challenges are the verifier's outstanding PoP challenges.
	Challenges []PopChallenge
	// Revocation and RevocationPolicy check the verifier's own deny list
	// last (item 6). nil Revocation skips the lookup.
	Revocation       RevocationSource
	RevocationPolicy RevocationPolicy
}

// Presentation is a TCT accepted by its issuer.
type Presentation struct {
	// PresenterAID is the PoP-proven presenter: the TCT's sub.
	PresenterAID string
	Grants       []string
	TCT          *TCT
}

// VerifyTCTAsIssuer runs RFC-AITP-0005 §10.5 for a TCT presented back to
// its issuer with a downstream pop_response. A nil response is the
// "no authenticated source" case: POP_RESPONSE_INVALID.
func VerifyTCTAsIssuer(token string, response []byte, opts IssuerOptions) (*Presentation, error) {
	self, err := aid.Parse(opts.SelfAID)
	if err != nil {
		return nil, errors.New("verify: IssuerOptions.SelfAID is not a valid AID")
	}
	// Items 1 and 2: §7.2 under the verifier's own key.
	t, err := verifyTCTSignature(token, nil)
	if err != nil {
		return nil, err
	}
	if t.Iss != opts.SelfAID || !t.iss.SameKey(self) {
		return nil, fail(aitpverifier.CodeTctSignatureInvalid, "TCT iss %s is not this verifier", t.Iss)
	}
	if err := t.checkCommonClaims(opts.Envelope.Now); err != nil {
		return nil, err
	}
	if t.Aud != t.Sub {
		return nil, fail(aitpverifier.CodeTctSignatureInvalid, "aud %s is not sub %s (RFC-AITP-0005 §10.5 item 2)", t.Aud, t.Sub)
	}
	// Item 3.
	if response == nil {
		return nil, fail(aitpverifier.CodePopResponseInvalid, "no pop_response or channel binding establishes the presenter")
	}
	r, err := parsePopResponse(response, opts.Envelope)
	if err != nil {
		return nil, err
	}
	var challenge *PopChallenge
	for i := range opts.Challenges {
		c := opts.Challenges[i]
		if c.TCTJTI == t.JTI && c.Nonce == r.nonceEcho {
			challenge = &c
			break
		}
	}
	if challenge == nil {
		return nil, fail(aitpverifier.CodePopChallengeInvalid, "no outstanding challenge for jti %s with that nonce", t.JTI)
	}
	if err := r.verify(t, *challenge, opts.Envelope.Now); err != nil {
		return nil, err
	}
	// Item 4: the presenter is the response's sender, proven to hold sub.
	if r.env.Sender != t.Sub {
		return nil, fail(aitpverifier.CodePopResponseInvalid, "presenter %s is not sub", r.env.Sender)
	}
	// Item 6.
	if opts.Revocation != nil {
		st := CheckRevocation(opts.Revocation, opts.RevocationPolicy, t.Iss, t.JTI, opts.Envelope.Now)
		if st.Revoked {
			return nil, fail(aitpverifier.CodeTctRevoked, "jti %s is revoked", t.JTI)
		}
		t.Degraded = st.Degraded
	}
	opts.Envelope.Replay.Add(r.env.MessageID, opts.Envelope.Now)
	return &Presentation{PresenterAID: t.Sub, Grants: t.Grants, TCT: t}, nil
}
