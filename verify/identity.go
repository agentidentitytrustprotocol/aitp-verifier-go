package verify

import (
	"strconv"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jwk"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jws"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/sigfield"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/timeutil"
)

// pinnedKeyTag is the RFC-AITP-0002 §3.1 domain tag, NUL included.
const pinnedKeyTag = "aitp-pinned-key-v1\x00"

// IssuerKeys resolves an OIDC issuer's signing keys (RFC-AITP-0007). It
// returns none for an issuer it does not know. It is consulted only after
// the issuer has passed the trust-anchor check.
type IssuerKeys func(issuer string) []*keys.PublicKey

// Identity is a parsed identity descriptor (RFC-AITP-0002 §1).
type Identity struct {
	Type, Issuer, Subject, PublicKey, Proof string
}

// IdentityOptions configures [VerifyIdentity]: the receiver's policy and
// the surrounding handshake message the proof is bound to.
type IdentityOptions struct {
	// Now is the verifier's current time in Unix seconds.
	Now int64
	// Tolerance bounds |iat - now| for OIDC proofs; 0 means
	// DefaultTolerance.
	Tolerance int64
	// SelfAID is the receiving peer's own AID.
	SelfAID string
	// TrustAnchors is the receiver's OIDC trust_anchors.
	TrustAnchors []string
	// IssuerKeys resolves trusted OIDC issuers' keys.
	IssuerKeys IssuerKeys
	// PinnedKeys is the receiver's pinned-key trust store, as AIDs.
	PinnedKeys []string
}

// boundMessage is the handshake message that carried the descriptor.
type boundMessage struct {
	sender    *aid.AID
	senderStr string
	messageID string
	timestamp int64
	popNonce  string
}

// parseIdentity is RFC-AITP-0004 §5.1 step 6's first check, the
// descriptor shape (aitp-identity.schema.json): IDENTITY_FAILED, or
// UNKNOWN_FIELD for a member outside the schema and outside extensions.
func parseIdentity(v *strictjson.Value) (*Identity, error) {
	bad := func(what string) error {
		return fail(aitpverifier.CodeIdentityFailed, "identity descriptor %s", what)
	}
	f, ok := asObject(v)
	if !ok {
		return nil, bad("is not an object")
	}
	id := &Identity{}
	if id.Type, ok = f.str("type"); !ok || !contains(identityTypes, id.Type) {
		return nil, bad("type is missing or unknown")
	}
	if id.Subject, ok = f.str("subject"); !ok || id.Subject == "" {
		return nil, bad("subject is missing or empty")
	}
	if id.Proof, ok = f.str("proof"); !ok || id.Proof == "" {
		return nil, bad("proof is missing or empty")
	}
	if f.has("issuer") {
		if id.Issuer, ok = f.str("issuer"); !ok || !isURI(id.Issuer) {
			return nil, bad("issuer is not a URI")
		}
	}
	if f.has("public_key") {
		if id.PublicKey, ok = f.match("public_key", rePublicKey); !ok {
			return nil, bad("public_key is not a 43- or 44-character base64url key")
		}
	}
	if x, ok := f.get("extensions"); ok && x.Kind != strictjson.Object {
		return nil, bad("extensions is not an object")
	}
	switch id.Type {
	case IdentityOIDC:
		if !f.has("issuer") || f.has("public_key") || f.has("svid_type") || f.has("x5c") {
			return nil, bad("of type oidc needs issuer and forbids public_key, svid_type and x5c (RFC-AITP-0002 §1)")
		}
	case IdentityPinnedKey:
		if !f.has("public_key") || f.has("issuer") || f.has("svid_type") || f.has("x5c") {
			return nil, bad("of type pinned_key needs public_key and forbids issuer, svid_type and x5c (RFC-AITP-0002 §1)")
		}
		if !reSig.MatchString(id.Proof) {
			return nil, bad("pinned_key proof is not a signature field")
		}
	case IdentitySPIFFE:
		if !f.has("svid_type") || f.has("issuer") || f.has("public_key") || len(id.Subject) > 2048 || !reSPIFFE.MatchString(id.Subject) {
			return nil, bad("of type spiffe needs svid_type and a SPIFFE ID subject, and forbids issuer and public_key")
		}
	}
	if k, ok := f.unknown("type", "issuer", "subject", "proof", "public_key", "svid_type", "x5c", "extensions"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "identity descriptor member %q is not defined", k)
	}
	return id, nil
}

// checkHint compares the descriptor with the Manifest's identity_hint
// (RFC-AITP-0004 §5.1 step 6, RFC-AITP-0003 §3.1): a mismatch is
// IDENTITY_FAILED, before either verification path runs.
func (id *Identity) checkHint(h IdentityHint, sender *aid.AID) error {
	mismatch := func(what string) error {
		return fail(aitpverifier.CodeIdentityFailed, "identity %s does not match the Manifest identity_hint", what)
	}
	if id.Type != h.Type {
		return mismatch("type")
	}
	if id.Subject != h.Subject {
		return mismatch("subject")
	}
	if id.Type == IdentityOIDC && id.Issuer != h.Issuer {
		return mismatch("issuer")
	}
	if id.Type == IdentityPinnedKey && (h.PublicKey != id.PublicKey || id.PublicKey != b64.Encode(sender.Key().Raw())) {
		return mismatch("public_key")
	}
	return nil
}

// checkTrust is the trust-anchor check of step 6, which runs before any
// key is resolved: an OIDC issuer outside the receiver's trust_anchors is
// INCOMPATIBLE_TRUST_ANCHORS (RFC-AITP-0002 §2.3 step 9).
func (id *Identity) checkTrust(opts IdentityOptions) error {
	if id.Type == IdentityOIDC && !contains(opts.TrustAnchors, id.Issuer) {
		return fail(aitpverifier.CodeIncompatibleTrustAnchors, "OIDC issuer %s is not in the receiver's trust_anchors", id.Issuer)
	}
	return nil
}

// verifyProof is the proof check of step 6: RFC-AITP-0002 §2.3 for OIDC
// and §3.2 for pinned_key. Every failure is IDENTITY_FAILED.
func (id *Identity) verifyProof(m boundMessage, opts IdentityOptions) error {
	switch id.Type {
	case IdentityOIDC:
		return id.verifyOIDC(m, opts)
	case IdentityPinnedKey:
		return id.verifyPinned(m, opts)
	default:
		return fail(aitpverifier.CodeIdentityFailed, "identity type %s is not implemented by this verifier", id.Type)
	}
}

func (id *Identity) verifyOIDC(m boundMessage, opts IdentityOptions) error {
	bad := func(format string, args ...any) error {
		return fail(aitpverifier.CodeIdentityFailed, "OIDC proof: "+format, args...)
	}
	tok, err := jws.Parse(id.Proof)
	if err != nil {
		return bad("%v", err)
	}
	if opts.IssuerKeys == nil {
		return bad("no key resolver for issuer %s", id.Issuer)
	}
	ks := opts.IssuerKeys(id.Issuer)
	if len(ks) == 0 {
		return bad("issuer %s has no resolvable key", id.Issuer)
	}
	verified := false
	for _, k := range ks {
		if tok.VerifySignature(k) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return bad("signature does not verify under issuer %s", id.Issuer)
	}
	c, _ := asObject(tok.Payload)
	if iss, _ := c.str("iss"); iss != id.Issuer {
		return bad("iss is not the descriptor issuer")
	}
	if sub, _ := c.str("sub"); sub != id.Subject {
		return bad("sub is not the descriptor subject")
	}
	exp, ok := c.integer("exp", 0)
	if !ok || exp <= opts.Now {
		return bad("exp is missing or not in the future")
	}
	tol := opts.Tolerance
	if tol == 0 {
		tol = DefaultTolerance
	}
	if iat, ok := c.integer("iat", 0); !ok || !timeutil.Within(opts.Now, iat, tol) {
		return bad("iat is missing or outside the tolerance")
	}
	if aud, ok := c.str("aud"); !ok || aud != opts.SelfAID {
		return bad("aud is missing or not the receiver's AID")
	}
	if nonce, ok := c.str("nonce"); !ok || nonce != m.popNonce {
		return bad("nonce is missing or not the handshake pop_nonce")
	}
	cnf, ok := c.object("cnf")
	if !ok {
		return bad("cnf is missing")
	}
	if jkt, ok := cnf.str("jkt"); !ok || jkt != jwk.Thumbprint(m.sender.Key()) {
		return bad("cnf.jkt is missing or not the thumbprint of the sender AID key")
	}
	return nil
}

func (id *Identity) verifyPinned(m boundMessage, opts IdentityOptions) error {
	bad := func(format string, args ...any) error {
		return fail(aitpverifier.CodeIdentityFailed, "pinned-key proof: "+format, args...)
	}
	// §3.2 step 2: public_key is the sender AID's key, byte for byte.
	if id.PublicKey != b64.Encode(m.sender.Key().Raw()) {
		return bad("public_key is not the sender AID key in its identifier form")
	}
	// Step 3: the (alg, key) pair is pinned locally.
	pinned := false
	for _, p := range opts.PinnedKeys {
		if a, err := aid.Parse(p); err == nil && a.SameKey(m.sender) {
			pinned = true
			break
		}
	}
	if !pinned {
		return bad("sender key is not in the pinned-key trust store")
	}
	// Steps 4 and 5.
	nonce, err := b64.DecodeLen(m.popNonce, 16)
	if err != nil {
		return bad("pop_nonce: %v", err)
	}
	input := pinnedProofInput(m.senderStr, opts.SelfAID, m.messageID, m.timestamp, nonce)
	if err := sigfield.Verify(id.Proof, m.sender.Key(), input); err != nil {
		return bad("%v", err)
	}
	return nil
}

// pinnedProofInput is the RFC-AITP-0002 §3.1 proof input.
func pinnedProofInput(sender, receiver, messageID string, timestamp int64, nonce []byte) []byte {
	b := []byte(pinnedKeyTag)
	b = append(b, sender...)
	b = append(b, 0)
	b = append(b, receiver...)
	b = append(b, 0)
	b = append(b, messageID...)
	b = append(b, 0)
	b = strconv.AppendInt(b, timestamp, 10)
	b = append(b, 0)
	return append(b, nonce...)
}

// BoundMessage is the handshake message an identity descriptor's proof is
// bound to (RFC-AITP-0002 §2.3, §3.1): its sender, message_id, timestamp
// and payload pop_nonce. An OIDC proof reads only Sender and PopNonce.
type BoundMessage struct {
	Sender    string
	MessageID string
	Timestamp int64
	PopNonce  string
}

// VerifyIdentity runs the RFC-AITP-0004 §5.1 step 6 identity checks on a
// standalone descriptor: shape, the Manifest identity_hint (skipped when
// hint is nil), trust anchors, then the RFC-AITP-0002 proof bound to m.
// [VerifyHello] runs the same checks on a descriptor inside a hello.
func VerifyIdentity(descriptor []byte, hint *IdentityHint, m BoundMessage, opts IdentityOptions) (*Identity, error) {
	v, err := strictjson.Parse(descriptor)
	if err != nil {
		return nil, fail(aitpverifier.CodeIdentityFailed, "identity descriptor is not strict JSON: %v", err)
	}
	sender, err := aid.Parse(m.Sender)
	if err != nil {
		return nil, fail(aitpverifier.CodeIdentityFailed, "sender %q is not a valid AID: %v", m.Sender, err)
	}
	id, err := parseIdentity(v)
	if err != nil {
		return nil, err
	}
	if hint != nil {
		if err := id.checkHint(*hint, sender); err != nil {
			return nil, err
		}
	}
	if err := id.checkTrust(opts); err != nil {
		return nil, err
	}
	bound := boundMessage{sender: sender, senderStr: m.Sender, messageID: m.MessageID, timestamp: m.Timestamp, popNonce: m.PopNonce}
	if err := id.verifyProof(bound, opts); err != nil {
		return nil, err
	}
	return id, nil
}

// PinnedKeyProofInput returns the RFC-AITP-0002 §3.1 pinned-key proof
// input for m received by receiver. popNonce must decode to 16 bytes.
func PinnedKeyProofInput(m BoundMessage, receiver string) ([]byte, error) {
	nonce, err := b64.DecodeLen(m.PopNonce, 16)
	if err != nil {
		return nil, fail(aitpverifier.CodeIdentityFailed, "pop_nonce: %v", err)
	}
	return pinnedProofInput(m.Sender, receiver, m.MessageID, m.Timestamp, nonce), nil
}
