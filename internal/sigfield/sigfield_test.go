package sigfield

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/curves"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jcs"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/kat"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

func key(t *testing.T, s string) *keys.PublicKey {
	t.Helper()
	a, err := aid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return a.Key()
}

// verifyPrehashed checks a field over input; the jcs-sha256.json proof
// vectors pin d = SHA-256(input), which this recomputes first.
func verifyPrehashed(t *testing.T, id string, v *strictjson.Value, input []byte, field string) {
	t.Helper()
	d := sha256.Sum256(input)
	if hex.EncodeToString(d[:]) != kat.Str(t, v, "sha256_hex") || b64.Encode(d[:]) != kat.Str(t, v, "sha256_b64url") {
		t.Errorf("%s: digest differs", id)
	}
	if err := Verify(field, key(t, kat.Str(t, v, "signer_aid")), input); err != nil {
		t.Errorf("%s: %v", id, err)
	}
}

// TestKnownAnswerProofSignatures verifies every signature pinned in
// jcs-sha256.json over its signing input, and rejects every double-hash
// and high-S negative.
func TestKnownAnswerProofSignatures(t *testing.T) {
	pos, neg := 0, 0
	for _, v := range kat.Vectors(t, "jcs-sha256.json") {
		id := kat.Str(t, v, "id")
		if !kat.Has(v, "signer_aid") {
			continue // a digest-only vector (kat-derived-uuid-001)
		}
		var input []byte
		switch {
		case kat.Has(v, "proof_input_hex"):
			input = kat.Hex(t, v, "proof_input_hex")
		case kat.Has(v, "decoded_hex"):
			dec, err := b64.Decode(kat.Str(t, v, "challenge"))
			if err != nil || hex.EncodeToString(dec) != kat.Str(t, v, "decoded_hex") {
				t.Fatalf("%s: challenge decoding", id)
			}
			input = dec
		case kat.Has(v, "preimage_hex"):
			input = kat.Hex(t, v, "preimage_hex")
		default:
			continue
		}
		field := kat.Str(t, v, "signature_b64url")
		if kat.Has(v, "signature") {
			field = kat.Str(t, v, "signature")
			if strings.TrimPrefix(field, "p256.") != kat.Str(t, v, "signature_b64url") {
				t.Errorf("%s: signature and signature_b64url differ", id)
			}
		}
		verifyPrehashed(t, id, v, input, field)
		pos++
		for _, nk := range []string{"double_hash_signature_MUST_NOT_verify", "high_s_sibling_MUST_NOT_verify"} {
			if !kat.Has(v, nk) {
				continue
			}
			if err := Verify(kat.Str(t, v, nk), key(t, kat.Str(t, v, "signer_aid")), input); !errors.Is(err, curves.ErrSignature) {
				t.Errorf("%s %s: got %v", id, nk, err)
			}
			neg++
		}
	}
	if pos != 7 || neg != 4 {
		t.Fatalf("checked %d signatures and %d negatives", pos, neg)
	}
	t.Logf("%d proof/PoP signatures verified, %d negatives rejected", pos, neg)
}

func load(t *testing.T, rel string) *strictjson.Value { return kat.Load(t, "signed-examples/"+rel) }

func canon(t *testing.T, v *strictjson.Value) []byte {
	t.Helper()
	b, err := jcs.Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func get(v *strictjson.Value, path ...string) *strictjson.Value {
	for _, p := range path {
		v, _ = v.Get(p)
	}
	return v
}

// TestKnownAnswerSignedExamples verifies the committed JCS-profile signed
// examples as committed (no re-minting) and rejects their negatives.
func TestKnownAnswerSignedExamples(t *testing.T) {
	n := 0
	for _, f := range []string{"envelope/kat-keypair-001-envelope.json", "envelope/kat-keypair-005-envelope.json"} {
		ex := load(t, f)
		env := get(ex, "envelope")
		input := append([]byte("aitp-envelope-v2\x00"), canon(t, env.Without("signature"))...)
		if hex.EncodeToString(input) != kat.Str(t, ex, "sig_input_v2_hex") {
			t.Errorf("%s: sig_input_v2 differs", f)
		}
		d := sha256.Sum256(input)
		if hex.EncodeToString(d[:]) != kat.Str(t, ex, "sig_input_v2_sha256_hex") {
			t.Errorf("%s: digest differs", f)
		}
		k := key(t, get(env, "sender", "agent_id").Str)
		if err := Verify(get(env, "signature").Str, k, input); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		mnv := get(ex, "_must_not_verify")
		for _, m := range mnv.Obj {
			if strings.HasSuffix(m.Key, "signature") {
				if err := Verify(m.Value.Str, k, input); err == nil {
					t.Errorf("%s: %s verified over sig_input_v2", f, m.Key)
				}
			}
		}
		if v1, ok := mnv.Get("v1_signature"); ok {
			// The retired pipe input: the v1 signature is over it, so it
			// verifies there and nowhere else.
			if err := Verify(v1.Str, k, []byte(get(mnv, "v1_sig_input").Str)); err != nil {
				t.Errorf("%s: v1 signature over its own input: %v", f, err)
			}
		}
		n++
	}
	for _, f := range []string{"manifest/kat-keypair-001-manifest.json", "manifest/kat-keypair-005-manifest.json"} {
		ex := load(t, f)
		man := get(ex, "manifest")
		k := key(t, get(man, "aid").Str)
		input := canon(t, man.Without("signature"))
		if err := Verify(get(man, "signature").Str, k, input); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		pop := get(man, "proof_of_possession")
		challenge, err := b64.DecodeLen(get(pop, "challenge").Str, 16)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(get(pop, "signature").Str, k, challenge); err != nil {
			t.Errorf("%s PoP: %v", f, err)
		}
		// The wrapper is never signed.
		wrapped := canon(t, &strictjson.Value{Kind: strictjson.Object, Obj: []strictjson.Member{{Key: "manifest", Value: man.Without("signature")}}})
		if Verify(get(man, "signature").Str, k, wrapped) == nil {
			t.Errorf("%s: verified over the transport wrapper", f)
		}
		if mnv, ok := ex.Get("_must_not_verify"); ok {
			if Verify(get(mnv, "double_hash_signature").Str, k, input) == nil || Verify(get(mnv, "double_hash_pop_signature").Str, k, challenge) == nil {
				t.Errorf("%s: double-hash negative verified", f)
			}
		}
		n++
	}
	for _, f := range []string{"revocation/kat-keypair-001-snapshot.json", "revocation/kat-keypair-005-snapshot.json"} {
		ex := load(t, f)
		body := get(ex, "revocation_list")
		k := key(t, get(body, "issuer").Str)
		input := canon(t, body)
		if err := Verify(get(ex, "signature").Str, k, input); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		if mnv, ok := ex.Get("_must_not_verify"); ok && Verify(get(mnv, "double_hash_signature").Str, k, input) == nil {
			t.Errorf("%s: double-hash negative verified", f)
		}
		n++
	}
	ex := load(t, "session-bundle/kat-keypair-001-bundle.json")
	b := get(ex, "session_bundle")
	if err := Verify(get(b, "signature").Str, key(t, get(b, "coordinator").Str), canon(t, b.Without("signature"))); err != nil {
		t.Errorf("session bundle: %v", err)
	}
	n++
	t.Logf("%d JCS-profile signed examples verified as committed", n)
}

func TestParse(t *testing.T) {
	raw := make([]byte, 64)
	enc := b64.Encode(raw)
	for in, want := range map[string]keys.Alg{enc: keys.Ed25519, "ed25519." + enc: keys.Ed25519, "p256." + enc: keys.P256} {
		s, err := Parse(in)
		if err != nil || s.Alg != want || s.Tagged != strings.Contains(in, ".") {
			t.Errorf("%q: %v", in, err)
		}
	}
	for in, want := range map[string]error{
		"rsa." + enc:          ErrUnknownAlg,
		"P256." + enc:         ErrUnknownAlg,
		"." + enc:             ErrUnknownAlg,
		enc[:85]:              ErrMalformed,
		enc + "A":             ErrMalformed,
		"p256." + enc + "=":   ErrMalformed,
		"p256.p256." + enc:    ErrMalformed,
		"ed25519." + enc[:85]: ErrMalformed,
	} {
		if _, err := Parse(in); !errors.Is(err, want) {
			t.Errorf("%q: got %v, want %v", in, err, want)
		}
	}
}

// TestAlgorithmMismatch: a p256-tagged signature never verifies under an
// Ed25519 key and vice versa (§5.4.3 step 3).
func TestAlgorithmMismatch(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	k, _ := keys.Parse(keys.Ed25519, priv.Public().(ed25519.PublicKey))
	input := []byte("x")
	d := sha256.Sum256(input)
	sig := b64.Encode(ed25519.Sign(priv, d[:]))
	if err := Verify(sig, k, input); err != nil {
		t.Fatal(err)
	}
	if err := Verify("ed25519."+sig, k, input); err != nil {
		t.Fatal(err)
	}
	if err := Verify("p256."+sig, k, input); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("got %v", err)
	}
	if err := Verify("bad", k, input); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
	p := key(t, "aid:pubkey:p256:AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR")
	if err := Verify(sig, p, input); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("untagged (Ed25519) signature under a P-256 key: %v", err)
	}
}
