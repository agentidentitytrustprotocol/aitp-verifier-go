package jwk

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/kat"
)

// TestKnownAnswerThumbprints recomputes every jwk-thumbprints.json vector
// from its keypair's AID: canonical JWK bytes, digest and jkt.
func TestKnownAnswerThumbprints(t *testing.T) {
	pairs := kat.Keypairs(t)
	n := 0
	for _, v := range kat.Vectors(t, "jwk-thumbprints.json") {
		id := kat.Str(t, v, "id")
		a, err := aid.Parse(kat.Str(t, pairs[kat.Str(t, v, "keypair_ref")], "aid"))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		c := Canonical(a.Key())
		h := sha256.Sum256(c)
		if string(c) != kat.Str(t, v, "jwk_canonical") || hex.EncodeToString(c) != kat.Str(t, v, "jwk_canonical_hex") {
			t.Errorf("%s: canonical JWK %s", id, c)
		}
		if hex.EncodeToString(h[:]) != kat.Str(t, v, "sha256_hex") || Thumbprint(a.Key()) != kat.Str(t, v, "jkt") {
			t.Errorf("%s: thumbprint differs", id)
		}
		n++
	}
	if n != 5 {
		t.Fatalf("%d thumbprint vectors", n)
	}
	t.Logf("%d thumbprint vectors recomputed byte-exactly", n)
}
