package main

import (
	"crypto/rand"
	"encoding/json"
	"net/http"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/verify"
)

// capabilityInvocation is the message type tct-007 and tct-026 wrap a
// capability invocation in. It is not in the envelope registry, so the
// adapter admits it explicitly.
const capabilityInvocation = "capability_invocation"

// adapter is the per-run state. begin_fixture drops everything but the
// clock and the enabled features.
type adapter struct {
	now      int64
	features []string
	issuers  verify.IssuerKeys
	// transport is the only HTTP transport any verifier gets. It refuses
	// every request and counts the attempts.
	transport *refusingTransport

	replay *verify.ReplayCache
	// challenge is the downstream PoP challenge of the current fixture.
	challenge *verify.PopChallenge
	// challenger is the AID that issued challenge.
	challenger string
	// response is the pop_response envelope produced in the fixture.
	response []byte
	// popIssued and authorized are the side effects of the PoP-enforcement
	// sequence.
	popIssued, authorized bool
}

func newAdapter() *adapter {
	a := &adapter{issuers: embeddedIssuers(), transport: &refusingTransport{}}
	a.reset()
	return a
}

func (a *adapter) reset() {
	a.replay = verify.NewReplayCache(verify.DefaultTolerance)
	a.challenge, a.challenger, a.response = nil, "", nil
	a.popIssued, a.authorized = false, false
	a.transport.reset()
}

// clock is the fixture's now param when given, else the set_clock value.
func (a *adapter) clock(p params) int64 {
	if n, ok := p.int("now"); ok {
		return n
	}
	return a.now
}

func (a *adapter) envelopeOptions(p params) verify.EnvelopeOptions {
	tol, _ := p.int("tolerance_seconds")
	return verify.EnvelopeOptions{Now: a.clock(p), Tolerance: tol, Replay: a.replay}
}

// ops maps every supported op to its handler. init lists exactly these.
var ops map[string]opFunc

func init() {
	ops = map[string]opFunc{
		"init":                            (*adapter).opInit,
		"shutdown":                        func(*adapter, params) (map[string]any, error) { return nil, nil },
		"set_features":                    (*adapter).opSetFeatures,
		"set_clock":                       (*adapter).opSetClock,
		"begin_fixture":                   func(a *adapter, _ params) (map[string]any, error) { a.reset(); return nil, nil },
		"verify_envelope":                 (*adapter).opVerifyEnvelope,
		"process_handshake_message":       (*adapter).opReplayOnly,
		"verify_manifest":                 (*adapter).opVerifyManifest,
		"verify_handshake_payload":        (*adapter).opVerifyHandshakePayload,
		"verify_tct":                      (*adapter).opVerifyTCT,
		"verify_tct_as_issuer":            (*adapter).opVerifyTCTAsIssuer,
		"verify_grant_voucher":            (*adapter).opVerifyGrantVoucher,
		"verify_delegation_token":         (*adapter).opVerifyDelegationToken,
		"verify_revocation_snapshot":      (*adapter).opVerifyRevocationSnapshot,
		"issue_pop_challenge":             (*adapter).opIssuePopChallenge,
		"produce_pop_response":            (*adapter).opProducePopResponse,
		"verify_pop_response":             (*adapter).opVerifyPopResponse,
		"authorize_capability_invocation": (*adapter).opAuthorizeCapabilityInvocation,
		"expect_pop_challenge_issued":     (*adapter).opExpectPopChallengeIssued,
		"withhold_pop_response":           (*adapter).opWithholdPopResponse,
	}
}

func supportedOps() []string {
	out := make([]string, 0, len(ops))
	for name := range ops {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

func (a *adapter) opInit(params) (map[string]any, error) {
	return map[string]any{
		"implementation":     implementation,
		"version":            aitpverifier.Version,
		"repository":         repository,
		"commit":             commit(),
		"supported_ops":      supportedOps(),
		"supported_features": []string{},
	}, nil
}

func (a *adapter) opSetFeatures(p params) (map[string]any, error) {
	a.features = p.strings("features")
	return nil, nil
}

func (a *adapter) opSetClock(p params) (map[string]any, error) {
	if n, ok := p.int("now_unix_secs"); ok {
		a.now = n
	} else if n, ok := p.int("now"); ok {
		a.now = n
	}
	return nil, nil
}

func sideEffects(a *adapter, extra map[string]any) map[string]any {
	se := map[string]any{
		"pop_challenge_issued":     a.popIssued,
		"capability_authorized":    a.authorized,
		"revocation_lookup_called": a.transport.calls() > 0,
		"network_fetch_called":     a.transport.calls() > 0,
	}
	for k, v := range extra {
		se[k] = v
	}
	return se
}

// opReplayOnly is the message_id-only replay scenario (env-004, mh-001):
// the first id is admitted, a repeat inside the window is REPLAY_DETECTED.
func (a *adapter) opReplayOnly(p params) (map[string]any, error) {
	id := p.str("message_id")
	now := a.clock(p)
	if err := a.replay.Check(id, now); err != nil {
		return nil, err
	}
	a.replay.Add(id, now)
	return nil, nil
}

func (a *adapter) opVerifyEnvelope(p params) (map[string]any, error) {
	switch {
	case p.has("envelope"):
		e, err := verify.VerifyEnvelope(p.raw("envelope"), a.envelopeOptions(p))
		if err != nil {
			return nil, err
		}
		return map[string]any{"message_id": e.MessageID, "sender": e.Sender}, nil
	case p.has("active_tct"):
		// env-002: the active TCT verifies, then the requested capability
		// is checked against its grants (RFC-AITP-0004 §4).
		t, err := verify.VerifyTCT(p.str("active_tct"), verify.TCTOptions{Now: a.clock(p), AnyAudience: true})
		if err != nil {
			return nil, err
		}
		capability := p.str("requested_capability")
		for _, g := range t.Grants {
			if g == capability {
				return map[string]any{"grants": t.Grants}, nil
			}
		}
		return nil, refuse(aitpverifier.CodePolicyViolation, "capability %s is not in the active TCT's grants", capability)
	case p.has("needed_key_for"):
		// env-003: every key source the fixture describes is empty or down.
		want := p.str("needed_key_for")
		for _, src := range []string{"pinned_keys", "well_known_keys"} {
			for _, k := range p.strings(src) {
				if k == want {
					return map[string]any{"resolved_from": src}, nil
				}
			}
		}
		return nil, refuse(aitpverifier.CodeKeyResolutionFailed, "no key source resolves %s", want)
	case p.has("message_id"):
		return a.opReplayOnly(p)
	}
	return nil, errNotSupported
}

func (a *adapter) opVerifyManifest(p params) (map[string]any, error) {
	m, err := verify.VerifyManifest(p.raw("manifest"), verify.ManifestOptions{Now: a.clock(p), SupportedVersions: p.strings("supported_versions")})
	if err != nil {
		return nil, err
	}
	return map[string]any{"aid": m.AID, "offered_capabilities": m.OfferedCapabilities}, nil
}

// trustedIssuers is the receiver's OIDC trust_anchors: self_trust_anchors
// when the fixture gives them, else the trusted test issuer alone
// (conformance README, "Receiver policy inputs").
func trustedIssuers(p params) []string {
	if p.has("self_trust_anchors") {
		return p.strings("self_trust_anchors")
	}
	return []string{trustedTestIssuer}
}

func (a *adapter) opVerifyHandshakePayload(p params) (map[string]any, error) {
	if p.has("peer_a") || p.has("peer_b") {
		return a.verifyCommitPair(p)
	}
	env := p.raw("envelope")
	var head struct {
		MessageType string `json:"message_type"`
	}
	_ = json.Unmarshal(env, &head)
	switch head.MessageType {
	case verify.MutualCommit, verify.MutualCommitAck:
		c, err := verify.VerifyCommit(env, verify.CommitOptions{
			Envelope:            a.envelopeOptions(p),
			SelfAID:             p.str("self_aid"),
			OwnPopNonce:         ownPopNonce(p),
			OfferedCapabilities: p.strings("issuer_offered_capabilities"),
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"grants": c.TCT.Grants, "tct_jti": c.TCT.JTI}, nil
	default:
		h, err := verify.VerifyHello(env, verify.HelloOptions{
			Envelope: a.envelopeOptions(p),
			Identity: verify.IdentityOptions{
				SelfAID:      p.str("self_aid"),
				TrustAnchors: trustedIssuers(p),
				IssuerKeys:   a.issuers,
				PinnedKeys:   p.strings("trust_store"),
			},
			SentPopNonce:          p.str("sent_pop_nonce"),
			AcceptedIdentityTypes: p.strings("self_accepted_identity_types"),
			// Receiver policy (step 8) runs when the fixture states the
			// receiver's accepted types; identity-only fixtures stop at 7.
			SkipPolicy: !p.has("self_accepted_identity_types"),
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"identity_type": h.Identity.Type, "pop_nonce": h.PopNonce, "requested_grants": h.RequestedGrants}, nil
	}
}

func ownPopNonce(p params) string {
	for _, k := range []string{"self_pop_nonce_sent_in_hello_ack", "self_pop_nonce_sent_in_hello", "sent_pop_nonce"} {
		if s := p.str(k); s != "" {
			return s
		}
	}
	return ""
}

// verifyCommitPair is mh-success-001: each peer verifies the commit
// payload it received.
func (a *adapter) verifyCommitPair(p params) (map[string]any, error) {
	result := map[string]any{}
	var grants []string
	for _, name := range []string{"peer_a", "peer_b"} {
		peer := p.object(name)
		if peer == nil {
			continue
		}
		c, err := verify.VerifyCommitPayload(peer.raw("received_payload"), verify.CommitOptions{
			Envelope:    verify.EnvelopeOptions{Now: a.clock(p)},
			SelfAID:     peer.str("self_aid"),
			OwnPopNonce: ownPopNonce(peer),
		})
		if err != nil {
			return nil, err
		}
		result[name] = map[string]any{"grants": c.TCT.Grants, "tct_jti": c.TCT.JTI}
		if grants == nil {
			grants = c.TCT.Grants
		}
	}
	result["grants"] = grants
	return result, nil
}

func (a *adapter) opVerifyTCT(p params) (map[string]any, error) {
	opts := verify.TCTOptions{Now: a.clock(p), ExpectedAudience: p.str("expected_audience")}
	opts.AnyAudience = opts.ExpectedAudience == ""
	if k := p.str("issuer_pubkey"); k != "" {
		raw, err := b64.Decode(k)
		if err != nil {
			return nil, refuse(aitpverifier.CodeTctSignatureInvalid, "issuer_pubkey is not base64url")
		}
		opts.IssuerKey = raw
	}
	if m := p.object("issuer_manifest"); m != nil {
		opts.IssuerManifestExpiresAt, _ = m.int("expires_at")
	}
	if l := p.object("issuer_revocation_list"); l != nil {
		opts.RevocationPolicy = verify.RevocationPolicy{Mode: verify.RevocationMode(l.str("fail_mode"))}
		if l.has("available") && !l.bool("available") || !l.has("snapshot") {
			opts.Revocation = verify.Unavailable{}
		} else {
			opts.Revocation = issuerSnapshots{l.str("issuer"): l.raw("snapshot")}
		}
	} else if p.bool("revocation_instrumented") {
		// rev-004: the real fetch path, through the refusing transport.
		opts.Revocation = verify.HTTPRevocationSource{
			Transport: a.transport,
			URL:       func(issuer string) (string, error) { return "https://revocation.invalid/" + issuer, nil },
		}
	}
	t, err := verify.VerifyTCT(p.str("tct_token"), opts)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"jti":          t.JTI,
		"grants":       t.Grants,
		"degraded":     t.Degraded,
		"side_effects": sideEffects(a, nil),
	}, nil
}

// issuerSnapshots is a revocation source holding one snapshot per issuer.
type issuerSnapshots map[string][]byte

func (s issuerSnapshots) Snapshot(issuer string) ([]byte, error) {
	if b, ok := s[issuer]; ok {
		return b, nil
	}
	return nil, verify.ErrRevocationUnavailable
}

func challenges(p params) []verify.PopChallenge {
	var out []verify.PopChallenge
	for _, c := range p.objects("outstanding_pop_challenges") {
		exp, _ := c.int("expires_at")
		out = append(out, verify.PopChallenge{TCTJTI: c.str("tct_jti"), Nonce: c.str("nonce"), ExpiresAt: exp})
	}
	return out
}

func (a *adapter) opVerifyTCTAsIssuer(p params) (map[string]any, error) {
	pr, err := verify.VerifyTCTAsIssuer(p.str("tct_token"), p.raw("envelope"), verify.IssuerOptions{
		Envelope:   a.envelopeOptions(p),
		SelfAID:    p.str("self_aid"),
		Challenges: challenges(p),
	})
	if err != nil {
		return nil, err
	}
	a.authorized = true
	return map[string]any{
		"presenter_aid": pr.PresenterAID,
		"grants":        pr.Grants,
		"side_effects":  sideEffects(a, nil),
	}, nil
}

func (a *adapter) opVerifyGrantVoucher(p params) (map[string]any, error) {
	v, err := verify.VerifyVoucher(p.str("voucher_token"), verify.VoucherOptions{Now: a.clock(p), SelfAID: p.str("verifier_aid")})
	if err != nil {
		return nil, err
	}
	return map[string]any{"grants": v.Grants, "sub": v.Sub, "src_jti": v.SrcJTI}, nil
}

func (a *adapter) opVerifyDelegationToken(p params) (map[string]any, error) {
	if legacy := p.object("delegation"); legacy != nil {
		// del-004: the v0.1 JSON delegation object. Its chain is the
		// multi-hop marker, refused before anything else is examined.
		if legacy.has("chain") {
			return nil, refuse(aitpverifier.CodeDelegationMultihopNotSupported, "delegation carries a chain (RFC-AITP-0011 is not enabled)")
		}
		return nil, refuse(aitpverifier.CodeDelegationInvalidSignature, "a JSON delegation object is not a compact JWS delegation token")
	}
	self := p.str("self_aid")
	var own []byte
	for _, s := range p.objects("revocation_snapshots") {
		if s.str("issuer_aid") == self {
			own = s.raw("snapshot")
		}
	}
	d, err := verify.VerifyDelegation(p.str("delegation_token"), verify.DelegationOptions{
		Now:               a.clock(p),
		SelfAID:           self,
		IssuerManifests:   p.rawList("issuer_manifests"),
		OwnRevocationList: own,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"grants": d.Scope, "delegator": d.Iss, "delegate": d.Sub}, nil
}

func (a *adapter) opVerifyRevocationSnapshot(p params) (map[string]any, error) {
	pol := p.object("policy")
	policy := verify.RevocationPolicy{}
	if pol != nil {
		policy.Mode = verify.RevocationMode(pol.str("fail_mode"))
		policy.MaxStalenessSecs, _ = pol.int("max_staleness_secs")
	}
	st, err := verify.ApplySnapshotPolicy(p.raw("snapshot"), policy,
		verify.SnapshotOptions{Now: a.clock(p), ExpectedIssuer: p.str("expected_issuer")}, p.str("queried_jti"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"revoked": st.Revoked, "absent": st.Absent, "degraded": st.Degraded}, nil
}

// --- Downstream PoP (tct-006) ---

func (a *adapter) opIssuePopChallenge(p params) (map[string]any, error) {
	c, err := verify.ParsePopChallenge(p.raw("envelope"), a.envelopeOptions(p))
	if err != nil {
		return nil, err
	}
	var head struct {
		Sender struct {
			AgentID string `json:"agent_id"`
		} `json:"sender"`
	}
	_ = json.Unmarshal(p.raw("envelope"), &head)
	a.challenge, a.challenger, a.popIssued = c, head.Sender.AgentID, true
	return map[string]any{"tct_jti": c.TCTJTI, "nonce": c.Nonce, "side_effects": sideEffects(a, nil)}, nil
}

func (a *adapter) opProducePopResponse(p params) (map[string]any, error) {
	a.response = p.raw("envelope")
	if a.response == nil {
		return nil, errNotSupported
	}
	return nil, nil
}

func (a *adapter) opVerifyPopResponse(p params) (map[string]any, error) {
	if a.challenge == nil {
		return nil, refuse(aitpverifier.CodePopChallengeInvalid, "no challenge was issued in this fixture")
	}
	if a.response == nil {
		return nil, refuse(aitpverifier.CodePopResponseInvalid, "no pop_response was produced")
	}
	token := p.str("tct_token")
	opts := a.envelopeOptions(p)
	// The challenger is the consuming peer. When it issued the TCT it
	// verifies as issuer (RFC-AITP-0005 §10.5); otherwise it is the TCT's
	// audience (§5.2) and runs §6.2 on the verified token.
	pr, err := verify.VerifyTCTAsIssuer(token, a.response, verify.IssuerOptions{
		Envelope: opts, SelfAID: a.challenger, Challenges: []verify.PopChallenge{*a.challenge},
	})
	if err == nil {
		return map[string]any{"presenter_aid": pr.PresenterAID, "grants": pr.Grants}, nil
	}
	if verify.CodeOf(err) != aitpverifier.CodeTctSignatureInvalid {
		return nil, err
	}
	t, terr := verify.VerifyTCT(token, verify.TCTOptions{Now: opts.Now, ExpectedAudience: a.challenger})
	if terr != nil {
		return nil, err
	}
	if err := verify.VerifyPopResponse(a.response, t, *a.challenge, opts); err != nil {
		return nil, err
	}
	return map[string]any{"presenter_aid": t.Sub, "grants": t.Grants}, nil
}

// --- PoP enforcement (tct-007, tct-026) ---

func popPolicy(p params) verify.PopPolicy {
	pol := p.object("issuer_policy")
	if pol == nil {
		return verify.PopPolicy{}
	}
	return verify.PopPolicy{Posture: pol.str("pop_posture"), RequiredGrants: pol.strings("pop_required_grants")}
}

// presentedTCT verifies the TCT an invocation presents. A TCT whose aud is
// its sub is a token presented back to its issuer (RFC-AITP-0005 §10.5),
// whose audience PoP alone can bind; any other is verified against the
// verifier's own AID.
func (a *adapter) presentedTCT(p params) (*verify.TCT, error) {
	self := p.str("self_aid")
	t, err := verify.VerifyTCT(p.str("tct_token"), verify.TCTOptions{Now: a.clock(p), AnyAudience: true})
	if err != nil {
		return nil, err
	}
	if t.Aud == t.Sub && (self == "" || self == t.Iss) {
		return t, nil
	}
	if self == "" || t.Aud != self {
		return nil, refuse(aitpverifier.CodeAudienceMismatch, "aud %s is not the verifier", t.Aud)
	}
	return t, nil
}

func (a *adapter) opAuthorizeCapabilityInvocation(p params) (map[string]any, error) {
	opts := a.envelopeOptions(p)
	opts.ExtraMessageTypes = []string{capabilityInvocation}
	e, err := verify.VerifyEnvelope(p.raw("envelope"), opts)
	if err != nil {
		return nil, err
	}
	t, err := a.presentedTCT(p)
	if err != nil {
		return nil, err
	}
	if e.Sender != t.Sub {
		return nil, refuse(aitpverifier.CodePolicyViolation, "the invoker %s is not the TCT's sub", e.Sender)
	}
	var inv struct {
		TCTJTI     string `json:"tct_jti"`
		Capability string `json:"capability"`
	}
	if json.Unmarshal(e.Payload(), &inv) != nil || inv.TCTJTI != t.JTI {
		return nil, refuse(aitpverifier.CodePolicyViolation, "the invocation does not name the presented TCT")
	}
	granted := false
	for _, g := range t.Grants {
		granted = granted || g == inv.Capability
	}
	if !granted {
		return nil, refuse(aitpverifier.CodePolicyViolation, "capability %s is not granted", inv.Capability)
	}
	if !popPolicy(p).Requires(inv.Capability) {
		a.authorized = true
		return map[string]any{"side_effects": sideEffects(a, nil)}, nil
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	a.challenge = &verify.PopChallenge{TCTJTI: t.JTI, Nonce: b64.Encode(nonce)}
	a.challenger, a.popIssued, a.authorized = t.Iss, true, false
	return map[string]any{
		"pop_challenge": map[string]any{"tct_jti": a.challenge.TCTJTI, "nonce": a.challenge.Nonce},
		"side_effects":  sideEffects(a, nil),
	}, nil
}

func (a *adapter) opExpectPopChallengeIssued(params) (map[string]any, error) {
	if !a.popIssued {
		return nil, refuse(aitpverifier.CodePopChallengeInvalid, "no pop_challenge was issued")
	}
	return map[string]any{"side_effects": sideEffects(a, nil)}, nil
}

func (a *adapter) opWithholdPopResponse(p params) (map[string]any, error) {
	if a.challenge == nil {
		// Nothing was challenged, so the invocation stands as decided.
		return map[string]any{"side_effects": sideEffects(a, nil)}, nil
	}
	a.authorized = false
	if a.challenger == p.str("self_aid") || p.str("self_aid") == "" {
		_, err := verify.VerifyTCTAsIssuer(p.str("tct_token"), nil, verify.IssuerOptions{
			Envelope: a.envelopeOptions(p), SelfAID: a.challenger, Challenges: []verify.PopChallenge{*a.challenge},
		})
		if err != nil {
			return nil, err
		}
	}
	return nil, refuse(aitpverifier.CodePopResponseInvalid, "no pop_response answered the challenge for a PoP-required grant")
}

// refusingTransport is the adapter's only HTTP transport: it refuses every
// request and counts them, so a fixture can tell whether a verifier tried.
// n is per fixture; total is for the whole run.
type refusingTransport struct{ n, total int }

func (t *refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.n++
	t.total++
	return nil, errNetworkRefused
}

func (t *refusingTransport) calls() int { return t.n }
func (t *refusingTransport) reset()     { t.n = 0 }
