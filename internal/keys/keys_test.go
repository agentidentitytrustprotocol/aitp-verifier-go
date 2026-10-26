package keys

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/curves"
)

func TestAlg(t *testing.T) {
	for _, c := range []struct {
		a        Alg
		tag, jws string
		n        int
	}{{Ed25519, "ed25519", "EdDSA", 32}, {P256, "p256", "ES256", 33}, {Alg(9), "", "", 0}} {
		if c.a.Tag() != c.tag || c.a.JWSAlg() != c.jws || c.a.RawLen() != c.n {
			t.Errorf("%d", c.a)
		}
		if a, ok := AlgFromTag(c.tag); c.tag != "" && (!ok || a != c.a) {
			t.Errorf("AlgFromTag(%q)", c.tag)
		}
	}
	if _, ok := AlgFromTag("ES256"); ok {
		t.Error("JOSE name accepted as a tag")
	}
}

func TestParse(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	k, err := Parse(Ed25519, pub)
	if err != nil || k.Alg() != Ed25519 || string(k.Raw()) != string(pub) || k.ECDSA() != nil {
		t.Fatal(err)
	}
	ident := make([]byte, 32)
	ident[0] = 1
	if _, err := Parse(Ed25519, ident); !errors.Is(err, ErrInvalidKey) || !errors.Is(err, curves.ErrSmallOrder) {
		t.Errorf("identity key: %v", err)
	}
	if _, err := Parse(P256, make([]byte, 33)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("zero P-256 key: %v", err)
	}
	if _, err := Parse(Alg(0), pub); !errors.Is(err, ErrInvalidKey) {
		t.Error("unknown alg")
	}
	if err := k.VerifyDigest(make([]byte, 31), make([]byte, 64)); !errors.Is(err, curves.ErrSignature) {
		t.Error("short digest")
	}
}

func TestVerify(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	k, _ := Parse(Ed25519, priv.Public().(ed25519.PublicKey))
	d := make([]byte, 32)
	if err := k.VerifyDigest(d, ed25519.Sign(priv, d)); err != nil {
		t.Fatal(err)
	}
	if err := k.VerifyJWS([]byte("a.b"), ed25519.Sign(priv, []byte("a.b"))); err != nil {
		t.Fatal(err)
	}
	if err := k.VerifyJWS([]byte("a.c"), ed25519.Sign(priv, []byte("a.b"))); err == nil {
		t.Fatal("wrong input accepted")
	}
}
