package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/verify"
)

type transcript struct {
	SpecCommit string `json:"spec_commit"`
	Fixtures   []struct {
		Fixture string `json:"fixture"`
		Now     int64  `json:"now"`
		Steps   []struct {
			Op        string          `json:"op"`
			Params    json.RawMessage `json:"params"`
			Outcome   *string         `json:"outcome"`
			ErrorCode *string         `json:"error_code"`
		} `json:"steps"`
	} `json:"fixtures"`
}

func loadTranscript(t *testing.T) transcript {
	t.Helper()
	b, err := os.ReadFile("testdata/transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	var tr transcript
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile("../../SPEC_VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if tr.SpecCommit != strings.TrimSpace(string(pin)) {
		t.Fatalf("transcript was recorded at spec %s, SPEC_VERSION is %s: re-run scripts/record-transcript.py", tr.SpecCommit, pin)
	}
	return tr
}

// TestTranscript replays every core fixture step the runner sent and
// checks each answer against the outcome the fixture expects. It also
// proves the refusing transport is never reached.
func TestTranscript(t *testing.T) {
	tr := loadTranscript(t)
	a := newAdapter()
	n := 0
	for _, f := range tr.Fixtures {
		a.now = f.Now
		a.reset()
		for i, s := range f.Steps {
			n++
			resp := a.handle(request{ID: fmt.Sprintf("req-%d", n), Op: s.Op, Params: s.Params})
			name := fmt.Sprintf("%s step %d (%s)", f.Fixture, i+1, s.Op)
			if resp.ID != fmt.Sprintf("req-%d", n) {
				t.Errorf("%s: id %q not echoed", name, resp.ID)
			}
			if !resp.OK && resp.Message == "" {
				t.Errorf("%s: failure without a message", name)
			}
			if resp.ErrorCode == codeOpNotSupported {
				t.Errorf("%s: OP_NOT_SUPPORTED (%s)", name, resp.Message)
				continue
			}
			switch {
			case s.Outcome == nil:
			case *s.Outcome == "success" && !resp.OK:
				t.Errorf("%s: want success, got %s: %s", name, resp.ErrorCode, resp.Message)
			case *s.Outcome == "failure" && resp.OK:
				t.Errorf("%s: want failure %v, got success", name, deref(s.ErrorCode))
			case *s.Outcome == "failure" && s.ErrorCode != nil && resp.ErrorCode != *s.ErrorCode:
				t.Errorf("%s: want %s, got %s: %s", name, *s.ErrorCode, resp.ErrorCode, resp.Message)
			}
		}
	}
	if len(tr.Fixtures) < 94 {
		t.Errorf("transcript covers %d fixtures, want every core fixture", len(tr.Fixtures))
	}
	if a.transport.total != 0 {
		t.Errorf("the refusing transport was reached %d times; verifiers must not touch the network", a.transport.total)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<any>"
	}
	return *s
}

// TestIssuerSideResult checks the values tct-029 asserts in result.
func TestIssuerSideResult(t *testing.T) {
	tr := loadTranscript(t)
	for _, f := range tr.Fixtures {
		if f.Fixture != "tct-029" {
			continue
		}
		a := newAdapter()
		a.now = f.Now
		resp := a.handle(request{ID: "req-1", Op: f.Steps[0].Op, Params: f.Steps[0].Params})
		r, _ := resp.Result.(map[string]any)
		var p struct {
			TCT string `json:"tct_token"`
		}
		_ = json.Unmarshal(f.Steps[0].Params, &p)
		tok, err := verify.VerifyTCT(p.TCT, verify.TCTOptions{Now: f.Now, AnyAudience: true})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.OK || r["presenter_aid"] != tok.Sub {
			t.Fatalf("tct-029: %+v", resp)
		}
		return
	}
	t.Fatal("tct-029 not in transcript")
}

func TestServe(t *testing.T) {
	in := strings.Join([]string{
		`{"id":"req-1","op":"init","params":{"version":"1"}}`,
		``,
		`{"id":"req-2","op":"no_such_op","params":{}}`,
		`{"id":"req-3","op":"set_clock","params":{"now_unix_secs":1711900000,"now":1711900000}}`,
		`{"id":"req-4","op":"set_features","params":{"features":["x"]}}`,
		`{"id":"req-5","op":"verify_envelope","params":{"message_id":"m"}}`,
		`{"id":"req-6","op":"verify_envelope","params":{"message_id":"m"}}`,
		`{"id":"req-7","op":"verify_envelope","params":{}}`,
		`not json`,
		`{"id":"req-9","op":"verify_tct","params":[1]}`,
		`{"id":"req-10","op":"shutdown","params":{}}`,
		`{"id":"req-11","op":"init","params":{}}`,
	}, "\n")
	var out bytes.Buffer
	a := newAdapter()
	if err := serve(strings.NewReader(in), &out, a); err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %s", sc.Text())
		}
		lines = append(lines, m)
	}
	if len(lines) != 10 {
		t.Fatalf("%d responses, want 10 (nothing after shutdown)", len(lines))
	}
	init := lines[0]["result"].(map[string]any)
	for _, k := range []string{"implementation", "version", "repository", "commit", "supported_ops", "supported_features"} {
		if _, ok := init[k]; !ok {
			t.Errorf("init result lacks %s", k)
		}
	}
	ops := init["supported_ops"].([]any)
	for _, want := range []string{"init", "shutdown", "set_clock", "begin_fixture", "set_features", "verify_tct_as_issuer"} {
		found := false
		for _, o := range ops {
			found = found || o == want
		}
		if !found {
			t.Errorf("supported_ops lacks %s", want)
		}
	}
	checks := []struct {
		i    int
		ok   bool
		code string
	}{
		{1, false, codeOpNotSupported},
		{2, true, ""},
		{3, true, ""},
		{4, true, ""},
		{5, false, "REPLAY_DETECTED"},
		{6, false, codeOpNotSupported},
		{7, false, "INVALID_ENVELOPE"},
		{8, false, "INVALID_ENVELOPE"},
		{9, true, ""},
	}
	for _, c := range checks {
		l := lines[c.i]
		if l["ok"] != c.ok || (c.code != "" && l["error_code"] != c.code) {
			t.Errorf("response %d: %v", c.i, l)
		}
	}
	if a.now != 1711900000 || len(a.features) != 1 {
		t.Errorf("clock %d, features %v", a.now, a.features)
	}
}

// TestRefusingTransport shows the transport refuses and counts, and that a
// revocation source built on it reports the issuer as unavailable.
func TestRefusingTransport(t *testing.T) {
	a := newAdapter()
	src := verify.HTTPRevocationSource{Transport: a.transport, URL: func(string) (string, error) { return "https://example.invalid/", nil }}
	if _, err := src.Snapshot("aid:pubkey:x"); !errors.Is(err, verify.ErrRevocationUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if a.transport.calls() != 1 || a.transport.total != 1 {
		t.Fatalf("calls %d total %d", a.transport.calls(), a.transport.total)
	}
	a.reset()
	if a.transport.calls() != 0 || a.transport.total != 1 {
		t.Fatalf("after reset: calls %d total %d", a.transport.calls(), a.transport.total)
	}
}

func TestEmbeddedIssuersMatchSpec(t *testing.T) {
	spec, err := os.ReadFile("../../testdata/spec/schemas/conformance/known-answer/oidc-test-issuers.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spec, oidcTestIssuers) {
		t.Fatal("cmd/aitp-verifier-adapter/oidc-test-issuers.json differs from testdata/spec: copy it again")
	}
	keys := embeddedIssuers()
	if len(keys(trustedTestIssuer)) != 1 {
		t.Fatal("trusted test issuer has no key")
	}
	if len(keys("")) != 0 || len(keys("https://auth.unknown-vendor.example")) != 0 {
		t.Fatal("untrusted issuer resolved")
	}
}

func TestCommit(t *testing.T) {
	if commit() == "" {
		t.Fatal("empty commit")
	}
}
