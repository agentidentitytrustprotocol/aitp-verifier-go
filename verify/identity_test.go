package verify

import (
	"testing"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
)

func TestVerifyIdentityRejects(t *testing.T) {
	const sender = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
	cases := []struct {
		name, desc, sender string
	}{
		{"not JSON", `{`, sender},
		{"bad sender", `{"type":"pinned_key","subject":"s","public_key":"x","proof":"y"}`, "aid:nope"},
		{"unknown type", `{"type":"x509","subject":"s","proof":"y"}`, sender},
		{"pinned key not in store", `{"type":"pinned_key","subject":"s","public_key":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik","proof":"y"}`, sender},
	}
	for _, c := range cases {
		_, err := VerifyIdentity([]byte(c.desc), nil, BoundMessage{Sender: c.sender, PopNonce: "AAECAwQFBgcICQoLDA0ODw"}, IdentityOptions{})
		if CodeOf(err) != aitpverifier.CodeIdentityFailed {
			t.Errorf("%s: got %v, want IDENTITY_FAILED", c.name, err)
		}
	}
}

func TestPinnedKeyProofInputNonce(t *testing.T) {
	if _, err := PinnedKeyProofInput(BoundMessage{PopNonce: "short"}, "r"); err == nil {
		t.Fatal("a pop_nonce that is not 16 bytes was accepted")
	}
}
