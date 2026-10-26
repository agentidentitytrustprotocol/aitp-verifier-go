package aid

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/curves"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/kat"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
)

// TestKnownAnswerKeypairs re-derives every keypairs.json vector: seed (or
// P-256 scalar) -> public key -> AID, byte for byte, and parses the AID.
func TestKnownAnswerKeypairs(t *testing.T) {
	n := 0
	for id, v := range kat.Keypairs(t) {
		var pub []byte
		var k *keys.PublicKey
		var err error
		if kat.Has(v, "seed_hex") {
			pub = ed25519.NewKeyFromSeed(kat.Hex(t, v, "seed_hex")).Public().(ed25519.PublicKey)
			k, err = keys.Parse(keys.Ed25519, pub)
		} else {
			priv, perr := ecdh.P256().NewPrivateKey(kat.Hex(t, v, "private_scalar_hex"))
			if perr != nil {
				t.Fatal(perr)
			}
			ec, perr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), priv.PublicKey().Bytes())
			if perr != nil {
				t.Fatal(perr)
			}
			pub, _ = curves.P256Compress(ec)
			k, err = keys.Parse(keys.P256, pub)
		}
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if b64.Encode(pub) != kat.Str(t, v, "pubkey_b64url") {
			t.Errorf("%s: public key differs", id)
		}
		want := kat.Str(t, v, "aid")
		a, err := Parse(want)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if FromKey(k, a.Tagged()) != want || a.String() != want || string(a.Key().Raw()) != string(pub) {
			t.Errorf("%s: AID differs", id)
		}
		if kat.Has(v, "untagged_aid") {
			u, err := Parse(kat.Str(t, v, "untagged_aid"))
			if err != nil || !u.SameKey(a) || u.String() == a.String() || u.Tagged() {
				t.Errorf("%s: tagged and untagged forms", id)
			}
		}
		n++
	}
	if n != 7 {
		t.Fatalf("%d keypair vectors", n)
	}
	t.Logf("%d keypair vectors re-derived", n)
}

func TestParseRejects(t *testing.T) {
	ed := "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
	p256 := "AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR"
	// id-012: the 65-byte SEC1 uncompressed encoding of the same P-256 point.
	uncompressed := "BAeBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMRY35HpPmUZKD9zkSojsfXA6kYPB0GVS2eLWt2BpSBxXc"
	for _, s := range []string{
		"aid:pubkey:p256:" + uncompressed,
		"aid:pubkey:" + uncompressed,
		"aid:pubkey:p256:" + ed,                                        // 43 chars for p256
		"aid:pubkey:ed25519:" + p256,                                   // 44 chars for ed25519
		"aid:pubkey:" + p256,                                           // untagged means Ed25519
		"aid:pubkey:secp256k1:" + p256,                                 // unregistered tag
		"aid:pubkey:ED25519:" + ed,                                     // tags are case-sensitive
		"aid:pubkey:" + ed + "=",                                       // padding
		"aid:pubkey:" + ed[:42] + "+",                                  // outside the alphabet
		"aid:pubkey:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",       // identity: small order
		"aid:pubkey:p256:BAeBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR", // prefix 04
		"aid:key:" + ed,
		"did:key:" + ed,
		"",
	} {
		if _, err := Parse(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := Parse("aid:pubkey:rsa:" + ed); !errors.Is(err, ErrUnknownAlg) {
		t.Error("unknown tag not reported as such")
	}
	a, _ := Parse("aid:pubkey:p256:" + p256)
	b, _ := Parse("aid:pubkey:" + ed)
	if a.Alg() != keys.P256 || b.Alg() != keys.Ed25519 || a.SameKey(b) || !a.Tagged() || b.Tagged() {
		t.Error("accessors")
	}
	if FromKey(a.Key(), false) != "aid:pubkey:p256:"+p256 || FromKey(b.Key(), true) != "aid:pubkey:ed25519:"+ed {
		t.Error("FromKey")
	}
}
