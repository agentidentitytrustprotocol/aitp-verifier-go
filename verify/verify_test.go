package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
)

// The valid artifacts below come from the adapter transcript: the
// conformance fixtures with their placeholders substituted by the
// reference runner. Tests here only mutate them; nothing is signed.

type step struct {
	Op     string                     `json:"op"`
	Params map[string]json.RawMessage `json:"params"`
}

var corpus map[string][]step

const refNow = 1711900000

func load(t *testing.T, fixture string, i int) map[string]json.RawMessage {
	t.Helper()
	if corpus == nil {
		b, err := os.ReadFile("../cmd/aitp-verifier-adapter/testdata/transcript.json")
		if err != nil {
			t.Fatal(err)
		}
		var tr struct {
			Fixtures []struct {
				Fixture string `json:"fixture"`
				Steps   []step `json:"steps"`
			} `json:"fixtures"`
		}
		if err := json.Unmarshal(b, &tr); err != nil {
			t.Fatal(err)
		}
		corpus = map[string][]step{}
		for _, f := range tr.Fixtures {
			corpus[f.Fixture] = f.Steps
		}
	}
	s, ok := corpus[fixture]
	if !ok || i >= len(s) {
		t.Fatalf("no %s step %d in the transcript", fixture, i)
	}
	return s[i].Params
}

func str(t *testing.T, p map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(p[key], &s); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return s
}

// mutate decodes doc, applies f to the decoded object and re-encodes it.
func mutate(t *testing.T, doc []byte, f func(m map[string]any)) []byte {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(doc))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantCode(t *testing.T, name string, err error, code aitpverifier.ErrorCode) {
	t.Helper()
	if got := CodeOf(err); got != code {
		t.Errorf("%s: got %q (%v), want %s", name, got, err, code)
	}
}

func wantOK(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestErrors(t *testing.T) {
	if CodeOf(errors.New("x")) != "" || CodeOf(nil) != "" {
		t.Fatal("CodeOf of a non-verify error")
	}
	e := fail(aitpverifier.CodeTctExpired, "n=%d", 1)
	if e.Error() != "TCT_EXPIRED: n=1" {
		t.Fatal(e.Error())
	}
	if CodeOf(recode(e, aitpverifier.CodeTctRevoked)) != aitpverifier.CodeTctRevoked || CodeOf(recode(errors.New("y"), aitpverifier.CodeTctRevoked)) != aitpverifier.CodeTctRevoked {
		t.Fatal("recode")
	}
}

func TestReplayCache(t *testing.T) {
	var nilCache *ReplayCache
	nilCache.Add("a", 1)
	if nilCache.Seen("a", 1) || nilCache.Check("a", 1) != nil {
		t.Fatal("nil cache must admit everything")
	}
	c := NewReplayCache(10)
	c.Add("a", 100)
	wantCode(t, "replay", c.Check("a", 105), aitpverifier.CodeReplayDetected)
	if c.Check("a", 111) != nil {
		t.Fatal("entry outlived its window")
	}
}

func TestEnvelope(t *testing.T) {
	env := load(t, "env-005", 0)["envelope"]
	opts := EnvelopeOptions{Now: refNow, Replay: NewReplayCache(DefaultTolerance)}
	e, err := VerifyEnvelope(env, opts)
	wantOK(t, "env-005", err)
	if e.MessageType != "mutual_hello" || len(e.Payload()) == 0 {
		t.Fatalf("%+v", e)
	}
	_, err = VerifyEnvelope(env, opts)
	wantCode(t, "replayed", err, aitpverifier.CodeReplayDetected)

	cases := []struct {
		name string
		f    func(m map[string]any)
		code aitpverifier.ErrorCode
	}{
		{"unknown member", func(m map[string]any) { m["trace"] = 1 }, aitpverifier.CodeUnknownField},
		{"unknown sender member", func(m map[string]any) { m["sender"].(map[string]any)["x"] = 1 }, aitpverifier.CodeUnknownField},
		{"version", func(m map[string]any) { m["version"] = "aitp/0.2" }, aitpverifier.CodeUnknownVersion},
		{"stale", func(m map[string]any) { m["timestamp"] = refNow - 301 }, aitpverifier.CodeTimestampExpired},
		{"message type", func(m map[string]any) { m["message_type"] = "capability_invocation" }, aitpverifier.CodeInvalidEnvelope},
		{"message id", func(m map[string]any) { m["message_id"] = "x" }, aitpverifier.CodeInvalidEnvelope},
		{"no payload", func(m map[string]any) { delete(m, "payload") }, aitpverifier.CodeInvalidEnvelope},
		{"no sender", func(m map[string]any) { delete(m, "sender") }, aitpverifier.CodeInvalidEnvelope},
		{"bad agent id", func(m map[string]any) { m["sender"] = map[string]any{"agent_id": "x"} }, aitpverifier.CodeInvalidEnvelope},
		{"no type", func(m map[string]any) { delete(m, "message_type") }, aitpverifier.CodeInvalidEnvelope},
		{"no timestamp", func(m map[string]any) { delete(m, "timestamp") }, aitpverifier.CodeInvalidEnvelope},
		{"no signature", func(m map[string]any) { delete(m, "signature") }, aitpverifier.CodeInvalidEnvelope},
		{"extensions", func(m map[string]any) { m["extensions"] = 1 }, aitpverifier.CodeInvalidEnvelope},
		{"payload changed", func(m map[string]any) { m["payload"] = map[string]any{"hello": false} }, aitpverifier.CodeInvalidSignature},
	}
	for _, c := range cases {
		_, err := VerifyEnvelope(mutate(t, env, c.f), EnvelopeOptions{Now: refNow})
		wantCode(t, c.name, err, c.code)
	}
	for _, bad := range []string{"", "[]", `{"a":1,"a":2}`} {
		_, err := ParseEnvelope([]byte(bad), EnvelopeOptions{Now: refNow})
		wantCode(t, "not an object: "+bad, err, aitpverifier.CodeInvalidEnvelope)
	}
	ok := mutate(t, env, func(m map[string]any) { m["message_type"] = "capability_invocation" })
	if _, err := ParseEnvelope(ok, EnvelopeOptions{Now: refNow, ExtraMessageTypes: []string{"capability_invocation"}}); err != nil {
		t.Fatal(err)
	}
}

func TestManifest(t *testing.T) {
	m := load(t, "man-005", 0)["manifest"]
	got, err := VerifyManifest(m, ManifestOptions{Now: refNow})
	wantOK(t, "man-005", err)
	_, err = VerifyManifest(m, ManifestOptions{Now: got.ExpiresAt})
	wantCode(t, "expired", err, aitpverifier.CodeManifestExpired)
	_, err = VerifyManifest(m, ManifestOptions{Now: refNow, SupportedVersions: []string{"aitp/0.4"}})
	wantCode(t, "unsupported", err, aitpverifier.CodeManifestVersionUnknown)
	_, err = VerifyManifest(m, ManifestOptions{Now: refNow, AcceptedIdentityTypes: []string{IdentityPinnedKey}})
	wantCode(t, "identity type", err, aitpverifier.CodeIncompatibleIdentityType)
	_, err = VerifyManifest(m, ManifestOptions{Now: refNow, TrustAnchors: []string{"https://other.example"}})
	wantCode(t, "trust anchors", err, aitpverifier.CodeIncompatibleTrustAnchors)
	_, err = VerifyManifest([]byte("{"), ManifestOptions{})
	wantCode(t, "not JSON", err, aitpverifier.CodeManifestInvalid)
	_, err = VerifyManifest([]byte("1"), ManifestOptions{})
	wantCode(t, "not an object", err, aitpverifier.CodeManifestInvalid)

	for _, k := range []string{"aid", "identity_hint", "handshake_endpoint", "accepted_trust_anchors", "offered_capabilities", "proof_of_possession", "published_at", "expires_at", "signature"} {
		_, err := VerifyManifest(mutate(t, m, func(o map[string]any) { delete(o, k) }), ManifestOptions{Now: refNow})
		wantCode(t, "missing "+k, err, aitpverifier.CodeManifestInvalid)
	}
	invalid := map[string]any{
		"display_name":                  strings.Repeat("x", 129),
		"handshake_endpoint":            "http://example.com",
		"accepted_trust_anchors":        []any{"not a uri"},
		"offered_capabilities":          []any{"a b"},
		"required_peer_capabilities":    "x",
		"accepted_identity_types":       []any{"x509"},
		"accepted_signature_algorithms": []any{"rsa"},
		"extensions":                    "x",
		"identity_hint":                 map[string]any{"type": "spiffe", "subject": "x"},
		"proof_of_possession":           map[string]any{"challenge": "x", "signature": "y"},
	}
	for k, v := range invalid {
		_, err := VerifyManifest(mutate(t, m, func(o map[string]any) { o[k] = v }), ManifestOptions{Now: refNow})
		wantCode(t, "invalid "+k, err, aitpverifier.CodeManifestInvalid)
	}
	_, err = VerifyManifest(mutate(t, m, func(o map[string]any) { o["region"] = "x" }), ManifestOptions{Now: refNow})
	wantCode(t, "unknown", err, aitpverifier.CodeUnknownField)
	_, err = VerifyManifest(mutate(t, m, func(o map[string]any) { o["identity_hint"].(map[string]any)["x"] = 1 }), ManifestOptions{Now: refNow})
	wantCode(t, "unknown hint member", err, aitpverifier.CodeUnknownField)
	_, err = VerifyManifest(mutate(t, m, func(o map[string]any) { o["offered_capabilities"] = []any{"other"} }), ManifestOptions{Now: refNow})
	wantCode(t, "signed body changed", err, aitpverifier.CodeManifestSignatureInvalid)
	_, err = VerifyManifest(mutate(t, m, func(o map[string]any) {
		o["proof_of_possession"].(map[string]any)["challenge"] = "AAAAAAAAAAAAAAAAAAAAAA"
	}), ManifestOptions{Now: refNow})
	wantCode(t, "pop", err, aitpverifier.CodeManifestPopFailed)
}

func TestTCT(t *testing.T) {
	p := load(t, "tct-012", 0)
	tok, aud := str(t, p, "tct_token"), str(t, p, "expected_audience")
	got, err := VerifyTCT(tok, TCTOptions{Now: refNow, ExpectedAudience: aud})
	wantOK(t, "tct-012", err)
	if got.subjectKey() == nil || len(got.Grants) == 0 {
		t.Fatal("claims")
	}
	if _, err := VerifyTCT(tok, TCTOptions{Now: refNow}); err == nil || CodeOf(err) != "" {
		t.Fatal("missing ExpectedAudience must be a configuration error")
	}
	_, err = VerifyTCT(tok, TCTOptions{Now: refNow, ExpectedAudience: got.Iss})
	wantCode(t, "audience", err, aitpverifier.CodeAudienceMismatch)
	_, err = VerifyTCT(tok, TCTOptions{Now: got.Exp, ExpectedAudience: aud})
	wantCode(t, "expired", err, aitpverifier.CodeTctExpired)
	_, err = VerifyTCT(tok, TCTOptions{Now: refNow, ExpectedAudience: aud, IssuerManifestExpiresAt: got.Exp - 1})
	wantCode(t, "manifest bound", err, aitpverifier.CodeTctExpiresAfterManifest)
	_, err = VerifyTCT(tok, TCTOptions{Now: refNow, ExpectedAudience: aud, IssuerKey: make([]byte, 32)})
	wantCode(t, "issuer key", err, aitpverifier.CodeTctSignatureInvalid)
	_, err = VerifyTCT("a.b", TCTOptions{Now: refNow, AnyAudience: true})
	wantCode(t, "malformed", err, aitpverifier.CodeTctSignatureInvalid)
	parts := strings.Split(tok, ".")
	_, err = VerifyTCT(parts[0]+"."+parts[1]+".AAAA", TCTOptions{Now: refNow, AnyAudience: true})
	wantCode(t, "signature", err, aitpverifier.CodeTctSignatureInvalid)

	base := TCTOptions{Now: refNow, ExpectedAudience: aud}
	revCases := []struct {
		name     string
		src      RevocationSource
		mode     RevocationMode
		code     aitpverifier.ErrorCode
		degraded bool
	}{
		{"unavailable default", Unavailable{}, "", aitpverifier.CodeTctRevoked, false},
		{"unavailable fail_open", Unavailable{}, FailOpen, "", false},
		{"unavailable soft_fail", Unavailable{}, SoftFail, "", true},
		{"garbage snapshot", StaticSnapshot("{}"), FailClosed, aitpverifier.CodeTctRevoked, false},
	}
	for _, c := range revCases {
		o := base
		o.Revocation, o.RevocationPolicy = c.src, RevocationPolicy{Mode: c.mode}
		got, err := VerifyTCT(tok, o)
		wantCode(t, c.name, err, c.code)
		if err == nil && got.Degraded != c.degraded {
			t.Errorf("%s: degraded %v", c.name, got.Degraded)
		}
	}
}

func TestSnapshot(t *testing.T) {
	p := load(t, "rev-003", 0)
	snap, issuer, jti := []byte(p["snapshot"]), str(t, p, "expected_issuer"), str(t, p, "queried_jti")
	opts := SnapshotOptions{Now: refNow + 100, ExpectedIssuer: issuer}
	s, err := VerifySnapshot(snap, opts)
	wantOK(t, "rev-003", err)
	if s.Revoked(jti) {
		t.Fatal("queried jti is not listed")
	}
	st, err := ApplySnapshotPolicy(snap, RevocationPolicy{}, opts, jti)
	if err != nil || st.Revoked || st.Absent {
		t.Fatalf("%+v %v", st, err)
	}
	var listed string
	for j := range s.revoked {
		listed = j
	}
	_, err = ApplySnapshotPolicy(snap, RevocationPolicy{}, opts, listed)
	wantCode(t, "listed", err, aitpverifier.CodeTctRevoked)
	_, err = ApplySnapshotPolicy(snap, RevocationPolicy{MaxStalenessSecs: 10}, opts, jti)
	wantCode(t, "stale fail_closed", err, aitpverifier.CodeTctRevoked)
	st, err = ApplySnapshotPolicy(snap, RevocationPolicy{Mode: SoftFail, MaxStalenessSecs: 10}, opts, jti)
	if err != nil || !st.Degraded {
		t.Fatalf("soft_fail: %+v %v", st, err)
	}
	_, err = VerifySnapshot(snap, SnapshotOptions{Now: refNow, ExpectedIssuer: "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"})
	if !errors.Is(err, ErrSnapshotDiscarded) {
		t.Fatalf("wrong issuer: %v", err)
	}
	_, err = VerifySnapshot(snap, SnapshotOptions{Now: s.ExpiresAt})
	if !errors.Is(err, ErrSnapshotDiscarded) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := VerifySnapshot(snap, SnapshotOptions{Now: refNow + 100000, MaxStalenessSecs: -1}); !errors.Is(err, ErrSnapshotDiscarded) {
		t.Fatalf("expired, staleness off: %v", err)
	}

	inner := func(f func(b map[string]any)) []byte {
		return mutate(t, snap, func(m map[string]any) { f(m["revocation_list"].(map[string]any)) })
	}
	cases := []struct {
		name string
		doc  []byte
		code aitpverifier.ErrorCode
	}{
		{"not JSON", []byte("{"), aitpverifier.CodeRevocationSnapshotInvalid},
		{"not object", []byte("[]"), aitpverifier.CodeRevocationSnapshotInvalid},
		{"no list", mutate(t, snap, func(m map[string]any) { delete(m, "revocation_list") }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"list type", mutate(t, snap, func(m map[string]any) { m["revocation_list"] = 1 }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"no signature", mutate(t, snap, func(m map[string]any) { delete(m, "signature") }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"wrapper member", mutate(t, snap, func(m map[string]any) { m["x"] = 1 }), aitpverifier.CodeUnknownField},
		{"version", inner(func(b map[string]any) { b["version"] = "aitp/9.9" }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"issuer", inner(func(b map[string]any) { b["issuer"] = "x" }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"published_at", inner(func(b map[string]any) { delete(b, "published_at") }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"expires_at", inner(func(b map[string]any) { b["expires_at"] = 0 }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"entries", inner(func(b map[string]any) { b["entries"] = map[string]any{} }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"entry", inner(func(b map[string]any) { b["entries"] = []any{1} }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"entry jti", inner(func(b map[string]any) { b["entries"] = []any{map[string]any{"jti": "x", "revoked_at": 1}} }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"entry revoked_at", inner(func(b map[string]any) {
			b["entries"] = []any{map[string]any{"jti": "550e8400-e29b-41d4-a716-446655440000"}}
		}), aitpverifier.CodeRevocationSnapshotInvalid},
		{"entry reason", inner(func(b map[string]any) {
			b["entries"] = []any{map[string]any{"jti": "550e8400-e29b-41d4-a716-446655440000", "revoked_at": 1, "reason": 1}}
		}), aitpverifier.CodeRevocationSnapshotInvalid},
		{"entry member", inner(func(b map[string]any) {
			b["entries"] = []any{map[string]any{"jti": "550e8400-e29b-41d4-a716-446655440000", "revoked_at": 1, "x": 1}}
		}), aitpverifier.CodeUnknownField},
		{"extensions", inner(func(b map[string]any) { b["extensions"] = 1 }), aitpverifier.CodeRevocationSnapshotInvalid},
		{"body member", inner(func(b map[string]any) { b["x"] = 1 }), aitpverifier.CodeUnknownField},
		{"body changed", inner(func(b map[string]any) { b["entries"] = []any{} }), aitpverifier.CodeRevocationSnapshotSignatureInvalid},
	}
	for _, c := range cases {
		_, err := VerifySnapshot(c.doc, opts)
		wantCode(t, c.name, err, c.code)
		_, err = ApplySnapshotPolicy(c.doc, RevocationPolicy{Mode: FailOpen}, opts, jti)
		wantCode(t, c.name+" (policy)", err, c.code)
	}
}

type fakeTransport struct {
	status int
	body   []byte
	err    error
	n      int
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.n++
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(bytes.NewReader(f.body)), Request: r}, nil
}

func TestHTTPRevocationSource(t *testing.T) {
	p := load(t, "rev-003", 0)
	snap, issuer := []byte(p["snapshot"]), str(t, p, "expected_issuer")
	url := func(string) (string, error) { return "https://issuer.example/revoked", nil }

	ok := &fakeTransport{status: 200, body: snap}
	st := CheckRevocation(HTTPRevocationSource{Transport: ok, URL: url}, RevocationPolicy{}, issuer, "550e8400-e29b-41d4-a716-446655440111", refNow+100)
	if st.Revoked || st.Absent || ok.n != 1 {
		t.Fatalf("fetched snapshot: %+v, %d calls", st, ok.n)
	}
	for name, src := range map[string]HTTPRevocationSource{
		"no transport": {URL: url},
		"url error":    {Transport: ok, URL: func(string) (string, error) { return "", errors.New("none") }},
		"bad url":      {Transport: ok, URL: func(string) (string, error) { return "://", nil }},
		"refused":      {Transport: &fakeTransport{err: errors.New("refused")}, URL: url},
		"404":          {Transport: &fakeTransport{status: 404}, URL: url},
		"oversized":    {Transport: &fakeTransport{status: 200, body: snap}, URL: url, MaxBytes: 10},
	} {
		if _, err := src.Snapshot(issuer); !errors.Is(err, ErrRevocationUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVoucher(t *testing.T) {
	p := load(t, "vch-001", 0)
	tok, self := str(t, p, "voucher_token"), str(t, p, "verifier_aid")
	v, err := VerifyVoucher(tok, VoucherOptions{Now: refNow, SelfAID: self})
	wantOK(t, "vch-001", err)
	_, err = VerifyVoucher(tok, VoucherOptions{Now: v.Exp, SelfAID: self})
	wantCode(t, "expired", err, aitpverifier.CodeDelegationExpired)
	_, err = VerifyVoucher(tok, VoucherOptions{Now: refNow, SelfAID: v.Sub})
	wantCode(t, "other self", err, aitpverifier.CodeDelegationInvalidVoucher)
	_, err = VerifyVoucher("x", VoucherOptions{Now: refNow, SelfAID: self})
	wantCode(t, "malformed", err, aitpverifier.CodeDelegationInvalidVoucher)
	if _, err := VerifyVoucher(tok, VoucherOptions{Now: refNow, SelfAID: "x"}); err == nil || CodeOf(err) != "" {
		t.Fatal("invalid SelfAID must be a configuration error")
	}
	tct := str(t, load(t, "tct-012", 0), "tct_token")
	_, err = VerifyVoucher(tct, VoucherOptions{Now: refNow, SelfAID: self})
	wantCode(t, "a TCT as voucher", err, aitpverifier.CodeTokenTypMismatch)
}

func TestDelegation(t *testing.T) {
	p := load(t, "del-001", 0)
	tok, self := str(t, p, "delegation_token"), str(t, p, "self_aid")
	var manifests []json.RawMessage
	_ = json.Unmarshal(p["issuer_manifests"], &manifests)
	ms := make([][]byte, len(manifests))
	for i, m := range manifests {
		ms[i] = m
	}
	opts := DelegationOptions{Now: refNow, SelfAID: self, IssuerManifests: ms}
	d, err := VerifyDelegation(tok, opts)
	wantOK(t, "del-001", err)
	if len(d.SubjectKey()) == 0 || d.Voucher == nil {
		t.Fatal("result")
	}
	o := opts
	o.IssuerManifests = nil
	_, err = VerifyDelegation(tok, o)
	wantCode(t, "no manifest", err, aitpverifier.CodeKeyResolutionFailed)
	o = opts
	o.SelfAID = d.Sub
	_, err = VerifyDelegation(tok, o)
	wantCode(t, "audience", err, aitpverifier.CodeDelegationAudienceMismatch)
	o = opts
	o.Now = d.Exp
	_, err = VerifyDelegation(tok, o)
	if c := CodeOf(err); c != aitpverifier.CodeDelegationExpired && c != aitpverifier.CodeKeyResolutionFailed {
		t.Errorf("expired: %v", err)
	}
	_, err = VerifyDelegation("x", opts)
	wantCode(t, "malformed", err, aitpverifier.CodeDelegationInvalidSignature)
	tct := str(t, load(t, "tct-012", 0), "tct_token")
	_, err = VerifyDelegation(tct, opts)
	wantCode(t, "a TCT as delegation", err, aitpverifier.CodeTokenTypMismatch)

	own := load(t, "rev-003", 0)["snapshot"]
	o = opts
	o.OwnRevocationList = own
	_, err = VerifyDelegation(tok, o)
	if c := CodeOf(err); c != aitpverifier.CodeRevocationSnapshotInvalid && c != aitpverifier.CodeRevocationSnapshotSignatureInvalid && err != nil {
		t.Errorf("own list from another issuer: %v", err)
	}
}

func TestHello(t *testing.T) {
	p := load(t, "id-017", 0)
	env, self := []byte(p["envelope"]), str(t, p, "self_aid")
	var pinned []string
	_ = json.Unmarshal(p["trust_store"], &pinned)
	opts := HelloOptions{
		Envelope:   EnvelopeOptions{Now: refNow},
		Identity:   IdentityOptions{SelfAID: self, PinnedKeys: pinned},
		SkipPolicy: true,
	}
	h, err := VerifyHello(env, opts)
	wantOK(t, "id-017", err)
	if h.Identity.Type != IdentityPinnedKey || h.Manifest == nil {
		t.Fatal("result")
	}
	o := opts
	o.SkipPolicy = false
	_, err = VerifyHello(env, o)
	wantCode(t, "default accepted types", err, aitpverifier.CodeIncompatibleIdentityType)
	o.AcceptedIdentityTypes = []string{IdentityPinnedKey}
	_, err = VerifyHello(env, o)
	wantOK(t, "pinned accepted", err)
	o = opts
	o.Identity.PinnedKeys = nil
	_, err = VerifyHello(env, o)
	wantCode(t, "not pinned", err, aitpverifier.CodeIdentityFailed)
	o = opts
	o.Identity.SelfAID = ""
	if _, err := VerifyHello(env, o); err == nil || CodeOf(err) != "" {
		t.Fatal("missing SelfAID must be a configuration error")
	}
	o = opts
	o.Identity.SelfAID = h.Envelope.Sender
	_, err = VerifyHello(env, o)
	wantCode(t, "other receiver", err, aitpverifier.CodeIdentityFailed)

	payload := func(f func(pl map[string]any)) []byte {
		return mutate(t, env, func(m map[string]any) { f(m["payload"].(map[string]any)) })
	}
	ident := func(f func(id map[string]any)) []byte {
		return payload(func(pl map[string]any) { f(pl["identity"].(map[string]any)) })
	}
	cases := []struct {
		name string
		doc  []byte
		code aitpverifier.ErrorCode
	}{
		{"not JSON", []byte("{"), aitpverifier.CodeInvalidEnvelope},
		{"commit type", mutate(t, env, func(m map[string]any) { m["message_type"] = "mutual_commit" }), aitpverifier.CodeInvalidEnvelope},
		{"payload member", payload(func(pl map[string]any) { pl["x"] = 1 }), aitpverifier.CodeUnknownField},
		{"no identity", payload(func(pl map[string]any) { delete(pl, "identity") }), aitpverifier.CodeInvalidEnvelope},
		{"no manifest", payload(func(pl map[string]any) { delete(pl, "manifest") }), aitpverifier.CodeInvalidEnvelope},
		{"grants", payload(func(pl map[string]any) { pl["requested_grants"] = "x" }), aitpverifier.CodeInvalidEnvelope},
		{"nonce", payload(func(pl map[string]any) { pl["pop_nonce"] = "x" }), aitpverifier.CodeInvalidEnvelope},
		{"payload extensions", payload(func(pl map[string]any) { pl["extensions"] = 1 }), aitpverifier.CodeInvalidEnvelope},
		{"manifest aid", payload(func(pl map[string]any) {
			pl["manifest"].(map[string]any)["aid"] = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
		}), aitpverifier.CodeInvalidEnvelope},
		{"identity member", ident(func(id map[string]any) { id["x"] = 1 }), aitpverifier.CodeUnknownField},
		{"identity issuer", ident(func(id map[string]any) { id["issuer"] = "https://auth.openai.com" }), aitpverifier.CodeIdentityFailed},
		{"identity type", ident(func(id map[string]any) { id["type"] = "x" }), aitpverifier.CodeIdentityFailed},
		{"identity subject", ident(func(id map[string]any) { id["subject"] = "other" }), aitpverifier.CodeIdentityFailed},
		{"no proof", ident(func(id map[string]any) { delete(id, "proof") }), aitpverifier.CodeIdentityFailed},
		{"proof form", ident(func(id map[string]any) { id["proof"] = "x" }), aitpverifier.CodeIdentityFailed},
		{"public key", ident(func(id map[string]any) { id["public_key"] = strings.Repeat("A", 43) }), aitpverifier.CodeIdentityFailed},
		{"public key form", ident(func(id map[string]any) { id["public_key"] = "x" }), aitpverifier.CodeIdentityFailed},
		{"identity extensions", ident(func(id map[string]any) { id["extensions"] = 1 }), aitpverifier.CodeIdentityFailed},
		{"spiffe", ident(func(id map[string]any) { id["type"] = "spiffe" }), aitpverifier.CodeIdentityFailed},
		{"identity not object", payload(func(pl map[string]any) { pl["identity"] = 1 }), aitpverifier.CodeInvalidEnvelope},
	}
	for _, c := range cases {
		_, err := VerifyHello(c.doc, opts)
		wantCode(t, c.name, err, c.code)
	}
}

func TestHelloOIDC(t *testing.T) {
	p := load(t, "id-023", 0)
	env, self := []byte(p["envelope"]), str(t, p, "self_aid")
	h, err := VerifyHello(env, HelloOptions{Envelope: EnvelopeOptions{Now: refNow}, Identity: IdentityOptions{SelfAID: self, TrustAnchors: []string{"https://auth.openai.com"}}, SkipPolicy: true})
	wantCode(t, "no issuer keys", err, aitpverifier.CodeIdentityFailed)
	_ = h
	_, err = VerifyHello(env, HelloOptions{Envelope: EnvelopeOptions{Now: refNow}, Identity: IdentityOptions{SelfAID: self}, SkipPolicy: true})
	wantCode(t, "untrusted issuer", err, aitpverifier.CodeIncompatibleTrustAnchors)
}

func TestCommit(t *testing.T) {
	p := load(t, "mh-success-001", 0)
	var peerA map[string]json.RawMessage
	_ = json.Unmarshal(p["peer_a"], &peerA)
	payload, self, nonce := []byte(peerA["received_payload"]), str(t, peerA, "self_aid"), str(t, peerA, "self_pop_nonce_sent_in_hello")
	opts := CommitOptions{Envelope: EnvelopeOptions{Now: refNow}, SelfAID: self, OwnPopNonce: nonce}
	c, err := VerifyCommitPayload(payload, opts)
	wantOK(t, "mh-success-001", err)
	if c.GrantVoucher == "" || c.TCT == nil {
		t.Fatal("result")
	}
	o := opts
	o.OwnPopNonce = "AAAAAAAAAAAAAAAAAAAAAA"
	_, err = VerifyCommitPayload(payload, o)
	wantCode(t, "nonce", err, aitpverifier.CodeNonceMismatch)
	o = opts
	o.OfferedCapabilities = []string{"other"}
	_, err = VerifyCommitPayload(payload, o)
	wantCode(t, "overflow", err, aitpverifier.CodeGrantOverflow)
	o = opts
	o.RequiredPeerCapabilities = []string{"other"}
	_, err = VerifyCommitPayload(payload, o)
	wantCode(t, "insufficient", err, aitpverifier.CodeInsufficientGrants)
	o = opts
	o.PeerAID = self
	_, err = VerifyCommitPayload(payload, o)
	wantCode(t, "wrong peer", err, aitpverifier.CodePopVerificationFailed)
	o = opts
	o.PeerManifestExpiresAt = refNow
	_, err = VerifyCommitPayload(payload, o)
	wantCode(t, "manifest bound", err, aitpverifier.CodeTctExpiresAfterManifest)
	o = opts
	o.SelfAID = c.TCT.Iss
	_, err = VerifyCommitPayload(payload, o)
	wantCode(t, "other receiver", err, aitpverifier.CodeAudienceMismatch)

	for name, doc := range map[string][]byte{
		"member":        mutate(t, payload, func(m map[string]any) { m["x"] = 1 }),
		"no tct":        mutate(t, payload, func(m map[string]any) { delete(m, "tct") }),
		"voucher form":  mutate(t, payload, func(m map[string]any) { m["grant_voucher"] = "x" }),
		"no pop":        mutate(t, payload, func(m map[string]any) { delete(m, "pop_signature") }),
		"no echo":       mutate(t, payload, func(m map[string]any) { delete(m, "pop_nonce_echo") }),
		"extensions":    mutate(t, payload, func(m map[string]any) { m["extensions"] = 1 }),
		"not an object": []byte("[]"),
	} {
		_, err := VerifyCommitPayload(doc, opts)
		code := aitpverifier.CodeInvalidEnvelope
		if name == "member" {
			code = aitpverifier.CodeUnknownField
		}
		wantCode(t, name, err, code)
	}

	// The envelope form, from mh-008 (a commit whose PoP is bad).
	m8 := load(t, "mh-008", 0)
	_, err = VerifyCommit(m8["envelope"], CommitOptions{Envelope: EnvelopeOptions{Now: refNow}, SelfAID: str(t, m8, "self_aid"), OwnPopNonce: str(t, m8, "self_pop_nonce_sent_in_hello_ack")})
	wantCode(t, "mh-008", err, aitpverifier.CodePopVerificationFailed)
	_, err = VerifyCommit(m8["envelope"], CommitOptions{Envelope: EnvelopeOptions{Now: refNow}, SelfAID: str(t, m8, "self_aid"), PeerAID: str(t, m8, "self_aid")})
	wantCode(t, "mh-008 other peer", err, aitpverifier.CodeInvalidSignature)
	_, err = VerifyCommit(load(t, "env-005", 0)["envelope"], CommitOptions{Envelope: EnvelopeOptions{Now: refNow}})
	wantCode(t, "hello as commit", err, aitpverifier.CodeInvalidEnvelope)
}

func TestPop(t *testing.T) {
	ch := load(t, "tct-006", 0)
	resp := load(t, "tct-006", 1)["envelope"]
	tok := str(t, ch, "tct_token")
	c, err := ParsePopChallenge(ch["envelope"], EnvelopeOptions{Now: refNow})
	wantOK(t, "challenge", err)
	tct, err := VerifyTCT(tok, TCTOptions{Now: refNow, AnyAudience: true})
	wantOK(t, "tct", err)
	wantOK(t, "response", VerifyPopResponse(resp, tct, *c, EnvelopeOptions{Now: refNow}))
	stale := *c
	stale.ExpiresAt = refNow
	wantCode(t, "stale", VerifyPopResponse(resp, tct, stale, EnvelopeOptions{Now: refNow}), aitpverifier.CodePopChallengeInvalid)
	other := *c
	other.Nonce = "AAAAAAAAAAAAAAAAAAAAAA"
	wantCode(t, "other nonce", VerifyPopResponse(resp, tct, other, EnvelopeOptions{Now: refNow}), aitpverifier.CodePopResponseInvalid)
	wantCode(t, "challenge as response", VerifyPopResponse(ch["envelope"], tct, *c, EnvelopeOptions{Now: refNow}), aitpverifier.CodePopResponseInvalid)
	if VerifyPopResponse(resp, nil, *c, EnvelopeOptions{}) == nil {
		t.Fatal("nil TCT")
	}
	_, err = ParsePopChallenge(resp, EnvelopeOptions{Now: refNow})
	wantCode(t, "response as challenge", err, aitpverifier.CodePopChallengeInvalid)
	for name, f := range map[string]func(pl map[string]any){
		"no jti":   func(pl map[string]any) { delete(pl, "tct_jti") },
		"no nonce": func(pl map[string]any) { delete(pl, "nonce") },
	} {
		doc := mutate(t, ch["envelope"], func(m map[string]any) { f(m["payload"].(map[string]any)) })
		_, err := ParsePopChallenge(doc, EnvelopeOptions{Now: refNow})
		if CodeOf(err) == "" {
			t.Errorf("%s: %v", name, err)
		}
	}

	pol := PopPolicy{RequiredGrants: []string{"a"}}
	if !pol.Requires("a") || pol.Requires("b") || !(PopPolicy{Posture: EnforceForAll}).Requires("b") {
		t.Fatal("PopPolicy")
	}
}

func TestIssuerSide(t *testing.T) {
	p := load(t, "tct-029", 0)
	tok, env, self := str(t, p, "tct_token"), []byte(p["envelope"]), str(t, p, "self_aid")
	var chs []struct {
		TCTJTI    string `json:"tct_jti"`
		Nonce     string `json:"nonce"`
		ExpiresAt int64  `json:"expires_at"`
	}
	_ = json.Unmarshal(p["outstanding_pop_challenges"], &chs)
	var challenges []PopChallenge
	for _, c := range chs {
		challenges = append(challenges, PopChallenge{TCTJTI: c.TCTJTI, Nonce: c.Nonce, ExpiresAt: c.ExpiresAt})
	}
	opts := IssuerOptions{Envelope: EnvelopeOptions{Now: refNow}, SelfAID: self, Challenges: challenges}
	pr, err := VerifyTCTAsIssuer(tok, env, opts)
	wantOK(t, "tct-029", err)
	if pr.PresenterAID != pr.TCT.Sub {
		t.Fatal("presenter")
	}
	_, err = VerifyTCTAsIssuer(tok, nil, opts)
	wantCode(t, "no response", err, aitpverifier.CodePopResponseInvalid)
	o := opts
	o.Challenges = nil
	_, err = VerifyTCTAsIssuer(tok, env, o)
	wantCode(t, "no challenge", err, aitpverifier.CodePopChallengeInvalid)
	o = opts
	o.SelfAID = pr.TCT.Sub
	_, err = VerifyTCTAsIssuer(tok, env, o)
	wantCode(t, "not the issuer", err, aitpverifier.CodeTctSignatureInvalid)
	o = opts
	o.Revocation = Unavailable{}
	_, err = VerifyTCTAsIssuer(tok, env, o)
	wantCode(t, "own list unavailable", err, aitpverifier.CodeTctRevoked)
	o.RevocationPolicy = RevocationPolicy{Mode: SoftFail}
	pr, err = VerifyTCTAsIssuer(tok, env, o)
	if err != nil || !pr.TCT.Degraded {
		t.Fatalf("soft_fail: %v", err)
	}
	if _, err := VerifyTCTAsIssuer(tok, env, IssuerOptions{SelfAID: "x"}); err == nil || CodeOf(err) != "" {
		t.Fatal("invalid SelfAID must be a configuration error")
	}
	_, err = VerifyTCTAsIssuer(tok, []byte("{"), opts)
	wantCode(t, "garbage response", err, aitpverifier.CodePopResponseInvalid)
	// A TCT whose aud is not its sub is not one the issuer handed out for
	// presentation (tct-012 names a third party as aud).
	t12 := str(t, load(t, "tct-012", 0), "tct_token")
	tc, _ := VerifyTCT(t12, TCTOptions{Now: refNow, AnyAudience: true})
	_, err = VerifyTCTAsIssuer(t12, env, IssuerOptions{Envelope: EnvelopeOptions{Now: refNow}, SelfAID: tc.Iss})
	if CodeOf(err) == "" {
		t.Fatalf("tct-012 as issuer: %v", err)
	}
}
