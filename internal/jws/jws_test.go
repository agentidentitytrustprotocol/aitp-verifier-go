package jws

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/curves"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jcs"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/kat"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// verifyByIss parses tok, checks typ, and verifies it under the key of its
// own iss AID.
func verifyByIss(t *testing.T, tok, typ string) (*Token, error) {
	t.Helper()
	tk, err := Parse(tok)
	if err != nil {
		return nil, err
	}
	if err := tk.CheckTyp(typ); err != nil {
		return tk, err
	}
	iss, _ := tk.Payload.Get("iss")
	a, err := aid.Parse(iss.Str)
	if err != nil {
		t.Fatal(err)
	}
	return tk, tk.VerifySignature(a.Key())
}

func sameJSON(t *testing.T, a, b *strictjson.Value) bool {
	t.Helper()
	x, err := jcs.Canonicalize(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := jcs.Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(x) == string(y)
}

// TestKnownAnswerSignedJWS verifies every committed compact-JWS signed
// example as transmitted, checks the decoded claims, and rejects the
// double-hash negatives.
func TestKnownAnswerSignedJWS(t *testing.T) {
	cases := []struct{ file, member, typ string }{
		{"tct/kat-keypair-001-issues-002.json", "tct_token", "aitp-tct+jwt"},
		{"tct/kat-keypair-001-self-attestation.json", "tct_token", "aitp-tct+jwt"},
		{"tct/kat-keypair-005-issues-002.json", "tct_token", "aitp-tct+jwt"},
		{"tct/kat-keypair-005-self-attestation.json", "tct_token", "aitp-tct+jwt"},
		{"grant-voucher/kat-voucher-001.json", "voucher_token", "aitp-grant+jwt"},
		{"delegation/single-hop-001-002-003.json", "delegation_token", "aitp-delegation+jwt"},
	}
	pos, neg := 0, 0
	for _, c := range cases {
		ex := kat.Load(t, "signed-examples/"+c.file)
		tok := kat.Str(t, ex, c.member)
		tk, err := verifyByIss(t, tok, c.typ)
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		claims, _ := ex.Get("decoded_claims")
		if !sameJSON(t, tk.Payload, claims) {
			t.Errorf("%s: payload differs from decoded_claims", c.file)
		}
		pos++
		if voucher, ok := tk.Payload.Get("voucher"); ok {
			if _, err := verifyByIss(t, voucher.Str, "aitp-grant+jwt"); err != nil {
				t.Errorf("%s: embedded voucher: %v", c.file, err)
			}
			pos++
		}
		if mnv, ok := ex.Get("_must_not_verify"); ok {
			dh, _ := mnv.Get("double_hash_jws")
			if _, err := verifyByIss(t, dh.Str, c.typ); !errors.Is(err, curves.ErrSignature) {
				t.Errorf("%s: double-hash JWS: %v", c.file, err)
			}
			neg++
		}
	}
	for _, v := range kat.Vectors(t, "jcs-sha256.json") {
		if kat.Str(t, v, "id") != "kat-multihop-chain-001" {
			continue
		}
		if _, err := verifyByIss(t, kat.Str(t, v, "voucher_jws"), "aitp-grant+jwt"); err != nil {
			t.Errorf("multihop voucher: %v", err)
		}
		chain, _ := v.Get("chain")
		for _, e := range chain.Arr {
			if _, err := verifyByIss(t, e.Str, "aitp-delegation+jwt"); err != nil {
				t.Errorf("multihop chain entry: %v", err)
			}
			pos++
		}
		if _, err := verifyByIss(t, kat.Str(t, v, "outer_delegation_jws"), "aitp-delegation+jwt"); err != nil {
			t.Errorf("multihop outer delegation: %v", err)
		}
		pos += 2
	}
	if pos != 10 || neg != 2 {
		t.Fatalf("checked %d tokens and %d negatives", pos, neg)
	}
	t.Logf("%d compact JWS verified as transmitted, %d negatives rejected", pos, neg)
}

// TestTCT017HighS: the committed high-S ES256 TCT of fixture tct-017 is
// rejected for its S value alone.
func TestTCT017HighS(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(kat.Root(t), "testdata", "spec", "schemas", "conformance", "tct-017-es256-high-s-rejected.json"))
	if err != nil {
		t.Fatal(err)
	}
	fx, err := strictjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := fx.Get("input")
	tok, _ := in.Get("tct_token")
	if _, err := verifyByIss(t, tok.Str, "aitp-tct+jwt"); !errors.Is(err, curves.ErrHighS) {
		t.Fatalf("got %v", err)
	}
}

// mint builds a compact JWS from raw header and payload JSON, signed with
// the all-zero-seed Ed25519 key (kat-keypair-001), for negative tests.
func mint(header, payload string) (string, *keys.PublicKey) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	k, _ := keys.Parse(keys.Ed25519, priv.Public().(ed25519.PublicKey))
	in := b64.Encode([]byte(header)) + "." + b64.Encode([]byte(payload))
	return in + "." + b64.Encode(ed25519.Sign(priv, []byte(in))), k
}

func TestStrictParsing(t *testing.T) {
	good, k := mint(`{"alg":"EdDSA","typ":"aitp-tct+jwt"}`, `{"ver":"aitp/0.3"}`)
	tk, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.VerifySignature(k); err != nil {
		t.Fatal(err)
	}
	if string(tk.PayloadBytes) != `{"ver":"aitp/0.3"}` || tk.Alg != "EdDSA" || tk.Typ != "aitp-tct+jwt" {
		t.Fatal("token fields")
	}
	sig := good[len(good)-86:]
	cases := map[string]struct {
		tok  string
		want error
	}{
		"two segments":       {good[:len(good)-87], ErrMalformed},
		"four segments":      {good + ".AA", ErrMalformed},
		"empty signature":    {good[:len(good)-86], ErrMalformed},
		"empty payload":      {"eyJhbGciOiJFZERTQSIsInR5cCI6ImFpdHAtdGN0K2p3dCJ9.." + sig, ErrMalformed},
		"padding":            {good + "==", ErrMalformed},
		"standard alphabet":  {good[:len(good)-1] + "+", ErrMalformed},
		"JSON serialization": {`{"payload":"x"}`, ErrMalformed},
	}
	for name, c := range cases {
		if _, err := Parse(c.tok); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	headers := map[string]string{
		"extra kid":      `{"alg":"EdDSA","typ":"aitp-tct+jwt","kid":"x"}`,
		"crit":           `{"alg":"EdDSA","crit":["x"]}`,
		"missing typ":    `{"alg":"EdDSA"}`,
		"missing alg":    `{"typ":"aitp-tct+jwt"}`,
		"duplicate alg":  `{"alg":"EdDSA","alg":"none"}`,
		"non-string alg": `{"alg":1,"typ":"aitp-tct+jwt"}`,
		"non-string typ": `{"alg":"EdDSA","typ":null}`,
		"two others":     `{"a":"EdDSA","b":"x"}`,
		"array":          `["EdDSA","aitp-tct+jwt"]`,
		"not JSON":       `alg=EdDSA`,
	}
	for name, h := range headers {
		tok, _ := mint(h, `{}`)
		if _, err := Parse(tok); !errors.Is(err, ErrHeader) {
			t.Errorf("header %s: got %v", name, err)
		}
	}
	payloads := map[string]string{
		"array":            `[1]`,
		"string":           `"x"`,
		"duplicate claim":  `{"exp":1,"exp":2}`,
		"nested duplicate": `{"ext":{"a":{"b":{"c":1,"c":2}}}}`,
		"trailing data":    `{} {}`,
		"invalid UTF-8":    "{\"a\":\"\xff\"}",
	}
	for name, p := range payloads {
		tok, _ := mint(`{"alg":"EdDSA","typ":"aitp-tct+jwt"}`, p)
		if _, err := Parse(tok); !errors.Is(err, ErrPayload) {
			t.Errorf("payload %s: got %v", name, err)
		}
	}
}

func TestTypAndAlg(t *testing.T) {
	p256, err := aid.Parse("aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR")
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"none", "None", "NONE", "ES256", "HS256", "eddsa", "Ed25519"} {
		tok, k := mint(`{"alg":"`+alg+`","typ":"aitp-tct+jwt"}`, `{}`)
		tk, err := Parse(tok)
		if err != nil {
			t.Fatal(err)
		}
		if err := tk.VerifySignature(k); !errors.Is(err, ErrAlgMismatch) {
			t.Errorf("alg %q under an Ed25519 key: %v", alg, err)
		}
	}
	tok, k := mint(`{"alg":"EdDSA","typ":"aitp-grant+jwt"}`, `{}`)
	tk, _ := Parse(tok)
	if err := tk.CheckTyp("aitp-tct+jwt"); !errors.Is(err, ErrTypMismatch) {
		t.Error("typ mismatch")
	}
	if err := tk.CheckTyp("aitp-grant+jwt"); err != nil {
		t.Error(err)
	}
	if err := tk.VerifySignature(p256.Key()); !errors.Is(err, ErrAlgMismatch) {
		t.Error("EdDSA token under a P-256 key (alg confusion)")
	}
	if err := tk.VerifySignature(k); err != nil {
		t.Error(err)
	}
}
