// Package jwk computes RFC 7638 JWK thumbprints of AITP keys, the cnf.jkt
// values of RFC-AITP-0001 §5.4.4.
package jwk

import (
	"crypto/sha256"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
)

// Canonical returns the RFC 7638 §3.2 canonical JWK: the required members
// only, in lexicographic order, no whitespace. Member values are
// base64url strings and fixed names, so no escaping is ever needed.
func Canonical(k *keys.PublicKey) []byte {
	if k.Alg() == keys.Ed25519 {
		return []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64.Encode(k.Raw()) + `"}`)
	}
	ec := k.ECDSA()
	unc, _ := ec.Bytes() // a parsed key always encodes
	return []byte(`{"crv":"P-256","kty":"EC","x":"` + b64.Encode(unc[1:33]) + `","y":"` + b64.Encode(unc[33:]) + `"}`)
}

// Thumbprint returns the SHA-256 JWK thumbprint, base64url-unpadded.
func Thumbprint(k *keys.PublicKey) string {
	h := sha256.Sum256(Canonical(k))
	return b64.Encode(h[:])
}
