package verify

import (
	"errors"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/sigfield"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// Mutual Handshake message types (RFC-AITP-0004 §3).
const (
	MutualHello     = "mutual_hello"
	MutualHelloAck  = "mutual_hello_ack"
	MutualCommit    = "mutual_commit"
	MutualCommitAck = "mutual_commit_ack"
)

// HelloOptions configures [VerifyHello]: the receiver's own configuration.
type HelloOptions struct {
	// Envelope carries the clock, tolerance and replay cache.
	Envelope EnvelopeOptions
	// Identity carries the receiver's AID and identity trust stores.
	Identity IdentityOptions
	// SentPopNonce, for a mutual_hello_ack, is the pop_nonce the receiver
	// sent in its mutual_hello. When set, pop_nonce_echo must equal it.
	SentPopNonce string
	// PeerAID, for a mutual_hello_ack, is the AID the receiver addressed in
	// its mutual_hello: the intended peer (RFC-AITP-0004 §2), taken from
	// the Manifest it fetched, never from the ack. It is required for an
	// ack, and a different envelope sender fails with PEER_MISMATCH
	// (§5.2 step 3).
	PeerAID string
	// AcceptedIdentityTypes is the receiver's own accepted_identity_types;
	// nil means DefaultAcceptedIdentityTypes (RFC-AITP-0003 §3.2).
	AcceptedIdentityTypes []string
	// SkipPolicy leaves RFC-AITP-0004 §5.1 step 8 to the caller. Steps 1
	// to 7 still run.
	SkipPolicy bool
}

// Hello is a verified mutual_hello or mutual_hello_ack.
type Hello struct {
	Envelope        *Envelope
	Manifest        *Manifest
	Identity        *Identity
	RequestedGrants []string
	PopNonce        string
	PopNonceEcho    string
}

// VerifyHello runs RFC-AITP-0004 §5.1 (mutual_hello) or §5.2
// (mutual_hello_ack) in order.
func VerifyHello(data []byte, opts HelloOptions) (*Hello, error) {
	v, err := strictjson.Parse(data)
	if err != nil {
		return nil, fail(aitpverifier.CodeInvalidEnvelope, "envelope is not strict JSON: %v", err)
	}
	if opts.Identity.SelfAID == "" {
		return nil, errors.New("verify: HelloOptions.Identity.SelfAID is required")
	}
	// Step 1.
	e, err := parseEnvelope(v, opts.Envelope)
	if err != nil {
		return nil, err
	}
	ack := e.MessageType == MutualHelloAck
	if e.MessageType != MutualHello && !ack {
		return nil, fail(aitpverifier.CodeInvalidEnvelope, "message_type %s is not a hello", e.MessageType)
	}
	// Step 2.
	h, manifestV, identityV, err := helloPayload(e.payload, ack)
	if err != nil {
		return nil, err
	}
	h.Envelope = e
	// §5.2 step 3: an ack must come from the peer the receiver addressed.
	if ack {
		if opts.PeerAID == "" {
			return nil, errors.New("verify: HelloOptions.PeerAID is required for a mutual_hello_ack")
		}
		if e.Sender != opts.PeerAID {
			return nil, fail(aitpverifier.CodePeerMismatch, "mutual_hello_ack sender is not the peer addressed in mutual_hello")
		}
	}
	// Step 3 (§5.2 step 4).
	mf, _ := asObject(manifestV)
	if maid, _ := mf.str("aid"); maid != e.Sender {
		return nil, fail(aitpverifier.CodeInvalidEnvelope, "manifest.aid is not envelope.sender.agent_id")
	}
	// Steps 4 and 5.
	if h.Manifest, err = verifyManifest(manifestV, ManifestOptions{Now: opts.Envelope.Now}); err != nil {
		return nil, err
	}
	// Step 6: descriptor and hint, trust anchors, proof.
	if h.Identity, err = parseIdentity(identityV); err != nil {
		return nil, err
	}
	if err := h.Identity.checkHint(h.Manifest.IdentityHint, e.senderAID); err != nil {
		return nil, err
	}
	if err := h.Identity.checkTrust(opts.Identity); err != nil {
		return nil, err
	}
	idOpts := opts.Identity
	idOpts.Now = opts.Envelope.Now
	if idOpts.Tolerance == 0 {
		idOpts.Tolerance = opts.Envelope.Tolerance
	}
	bound := boundMessage{sender: e.senderAID, senderStr: e.Sender, messageID: e.MessageID, timestamp: e.Timestamp, popNonce: h.PopNonce}
	if err := h.Identity.verifyProof(bound, idOpts); err != nil {
		return nil, err
	}
	// Step 7.
	if err := e.VerifySignature(); err != nil {
		return nil, err
	}
	// §5.2 step 9.
	if ack && opts.SentPopNonce != "" && h.PopNonceEcho != opts.SentPopNonce {
		return nil, fail(aitpverifier.CodeNonceMismatch, "pop_nonce_echo is not the pop_nonce sent in mutual_hello")
	}
	// Step 8 (§5.2 step 10).
	if !opts.SkipPolicy {
		accepted := opts.AcceptedIdentityTypes
		if accepted == nil {
			accepted = DefaultAcceptedIdentityTypes
		}
		if !contains(accepted, h.Identity.Type) {
			return nil, fail(aitpverifier.CodeIncompatibleIdentityType, "identity type %s is not in the receiver's accepted_identity_types", h.Identity.Type)
		}
		if err := h.Identity.checkTrust(opts.Identity); err != nil {
			return nil, err
		}
	}
	opts.Envelope.Replay.Add(e.MessageID, opts.Envelope.Now)
	return h, nil
}

func helloPayload(p *strictjson.Value, ack bool) (*Hello, *strictjson.Value, *strictjson.Value, error) {
	bad := func(what string) (*Hello, *strictjson.Value, *strictjson.Value, error) {
		return nil, nil, nil, fail(aitpverifier.CodeInvalidEnvelope, "hello payload %s", what)
	}
	f, _ := asObject(p)
	h := &Hello{}
	identityV, ok := f.get("identity")
	if !ok || identityV.Kind != strictjson.Object {
		return bad("identity is missing or not an object")
	}
	manifestV, ok := f.get("manifest")
	if !ok || manifestV.Kind != strictjson.Object {
		return bad("manifest is missing or not an object")
	}
	if h.RequestedGrants, ok = f.strings("requested_grants", reNoSpace, 0); !ok {
		return bad("requested_grants is missing or malformed")
	}
	if h.PopNonce, ok = f.match("pop_nonce", reNonce); !ok {
		return bad("pop_nonce is missing or not a 128-bit base64url nonce")
	}
	allowed := []string{"identity", "manifest", "requested_grants", "pop_nonce", "extensions"}
	if ack {
		if h.PopNonceEcho, ok = f.match("pop_nonce_echo", reNonce); !ok {
			return bad("pop_nonce_echo is missing or malformed")
		}
		allowed = append(allowed, "pop_nonce_echo")
	}
	if x, ok := f.get("extensions"); ok && x.Kind != strictjson.Object {
		return bad("extensions is not an object")
	}
	if k, ok := f.unknown(allowed...); ok {
		return nil, nil, nil, fail(aitpverifier.CodeUnknownField, "hello payload member %q is not defined", k)
	}
	return h, manifestV, identityV, nil
}

// CommitOptions configures [VerifyCommit] and [VerifyCommitPayload].
type CommitOptions struct {
	// Envelope carries the clock, tolerance and replay cache.
	Envelope EnvelopeOptions
	// SelfAID is the receiver's own AID: the TCT's expected sub and aud.
	SelfAID string
	// PeerAID is the peer's AID from its round-1 Manifest. Empty means the
	// envelope sender (or, for a bare payload, the TCT's iss).
	PeerAID string
	// OwnPopNonce is the pop_nonce the receiver sent in round 1. When set,
	// pop_nonce_echo must equal it and the PoP signature is checked over
	// it. When empty, the PoP signature is checked over the echo.
	OwnPopNonce string
	// OfferedCapabilities, when non-nil, bounds the TCT grants
	// (GRANT_OVERFLOW).
	OfferedCapabilities []string
	// RequiredPeerCapabilities lists what the receiver requires of its
	// peer (INSUFFICIENT_GRANTS).
	RequiredPeerCapabilities []string
	// PeerManifestExpiresAt, when non-zero, is the peer Manifest's
	// expires_at for the RFC-AITP-0005 §10.4 bound.
	PeerManifestExpiresAt int64
}

// Commit is a verified mutual_commit or mutual_commit_ack.
type Commit struct {
	TCT          *TCT
	GrantVoucher string
}

// VerifyCommit runs RFC-AITP-0004 §5.3 (mutual_commit) or §5.4
// (mutual_commit_ack) on an envelope.
func VerifyCommit(data []byte, opts CommitOptions) (*Commit, error) {
	e, err := ParseEnvelope(data, opts.Envelope)
	if err != nil {
		return nil, err
	}
	if e.MessageType != MutualCommit && e.MessageType != MutualCommitAck {
		return nil, fail(aitpverifier.CodeInvalidEnvelope, "message_type %s is not a commit", e.MessageType)
	}
	peer := e.senderAID
	if opts.PeerAID != "" {
		if peer, err = aid.Parse(opts.PeerAID); err != nil {
			return nil, errors.New("verify: CommitOptions.PeerAID is not a valid AID")
		}
		if !peer.SameKey(e.senderAID) {
			return nil, fail(aitpverifier.CodeInvalidSignature, "envelope sender is not the round-1 peer")
		}
	}
	if err := e.verifySignature(peer.Key()); err != nil {
		return nil, err
	}
	c, err := verifyCommitPayload(e.payload, peer, opts)
	if err != nil {
		return nil, err
	}
	opts.Envelope.Replay.Add(e.MessageID, opts.Envelope.Now)
	return c, nil
}

// VerifyCommitPayload runs RFC-AITP-0004 §5.3 / §5.4 steps 2 onward on a
// commit payload whose envelope the caller has already verified.
func VerifyCommitPayload(payload []byte, opts CommitOptions) (*Commit, error) {
	v, err := strictjson.Parse(payload)
	if err != nil || v.Kind != strictjson.Object {
		return nil, fail(aitpverifier.CodeInvalidEnvelope, "commit payload is not a strict JSON object")
	}
	peerAID := opts.PeerAID
	if peerAID == "" {
		f, _ := asObject(v)
		tok, ok := f.match("tct", reCompact)
		if !ok {
			return nil, fail(aitpverifier.CodeInvalidEnvelope, "commit payload tct is missing or not a compact JWS")
		}
		t, err := verifyTCTSignature(tok, nil)
		if err != nil {
			return nil, err
		}
		peerAID = t.Iss
	}
	peer, err := aid.Parse(peerAID)
	if err != nil {
		return nil, errors.New("verify: commit peer is not a valid AID")
	}
	return verifyCommitPayload(v, peer, opts)
}

func verifyCommitPayload(p *strictjson.Value, peer *aid.AID, opts CommitOptions) (*Commit, error) {
	bad := func(what string) error {
		return fail(aitpverifier.CodeInvalidEnvelope, "commit payload %s", what)
	}
	f, _ := asObject(p)
	tok, ok := f.match("tct", reCompact)
	if !ok {
		return nil, bad("tct is missing or not a compact JWS")
	}
	c := &Commit{}
	if f.has("grant_voucher") {
		if c.GrantVoucher, ok = f.match("grant_voucher", reCompact); !ok {
			return nil, bad("grant_voucher is not a compact JWS")
		}
	}
	popSig, ok := f.match("pop_signature", reSig)
	if !ok {
		return nil, bad("pop_signature is missing or malformed")
	}
	echo, ok := f.match("pop_nonce_echo", reNonce)
	if !ok {
		return nil, bad("pop_nonce_echo is missing or malformed")
	}
	if x, ok := f.get("extensions"); ok && x.Kind != strictjson.Object {
		return nil, bad("extensions is not an object")
	}
	if k, ok := f.unknown("tct", "grant_voucher", "pop_signature", "pop_nonce_echo", "extensions"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "commit payload member %q is not defined", k)
	}
	// Step 3.
	nonce := echo
	if opts.OwnPopNonce != "" {
		if echo != opts.OwnPopNonce {
			return nil, fail(aitpverifier.CodeNonceMismatch, "pop_nonce_echo is not the receiver's round-1 pop_nonce")
		}
		nonce = opts.OwnPopNonce
	}
	// Step 4.
	if err := verifyNoncePoP(popSig, peer, nonce); err != nil {
		return nil, fail(aitpverifier.CodePopVerificationFailed, "pop_signature: %v", err)
	}
	// Step 5.
	t, err := verifyTCTSignature(tok, peer.Key().Raw())
	if err != nil {
		return nil, err
	}
	if err := t.checkClaims(TCTOptions{Now: opts.Envelope.Now, ExpectedAudience: opts.SelfAID, IssuerManifestExpiresAt: opts.PeerManifestExpiresAt}); err != nil {
		return nil, err
	}
	if t.Sub != opts.SelfAID {
		return nil, fail(aitpverifier.CodeAudienceMismatch, "TCT sub %s is not the receiver %s", t.Sub, opts.SelfAID)
	}
	if opts.OfferedCapabilities != nil {
		if g, ok := subset(t.Grants, opts.OfferedCapabilities); !ok {
			return nil, fail(aitpverifier.CodeGrantOverflow, "grant %q is not an offered capability", g)
		}
	}
	if g, ok := subset(opts.RequiredPeerCapabilities, t.Grants); !ok {
		return nil, fail(aitpverifier.CodeInsufficientGrants, "required capability %q was not granted", g)
	}
	c.TCT = t
	return c, nil
}

// verifyNoncePoP checks sign(key, sha256(base64url_decode(nonce))), the
// handshake and downstream PoP signature (RFC-AITP-0004 §3.3,
// RFC-AITP-0005 §6.1). sigfield.Verify applies the sha256.
func verifyNoncePoP(sig string, signer *aid.AID, nonce string) error {
	raw, err := b64.Decode(nonce)
	if err != nil {
		return err
	}
	return sigfield.Verify(sig, signer.Key(), raw)
}
