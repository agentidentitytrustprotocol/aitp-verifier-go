// Package keys is an AITP public key: Ed25519 or P-256, as an AID encodes
// it (RFC-AITP-0001 §5.3), with the two verification primitives AITP uses.
package keys

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/curves"
)

// Alg is a signature algorithm.
type Alg int

// The two v0.3 algorithms (RFC-AITP-0001 §5.4.3).
const (
	Ed25519 Alg = iota + 1
	P256
)

// Tag is the algorithm's identifier in AIDs and tagged signatures.
func (a Alg) Tag() string {
	switch a {
	case Ed25519:
		return "ed25519"
	case P256:
		return "p256"
	}
	return ""
}

// JWSAlg is the sole JOSE alg value a key of this algorithm accepts
// (RFC-AITP-0001 §5.4.5).
func (a Alg) JWSAlg() string {
	switch a {
	case Ed25519:
		return "EdDSA"
	case P256:
		return "ES256"
	}
	return ""
}

// RawLen is the length of the key's raw AID encoding.
func (a Alg) RawLen() int {
	switch a {
	case Ed25519:
		return 32
	case P256:
		return 33
	}
	return 0
}

// AlgFromTag maps an AID / signature tag to its Alg.
func AlgFromTag(tag string) (Alg, bool) {
	switch tag {
	case "ed25519":
		return Ed25519, true
	case "p256":
		return P256, true
	}
	return 0, false
}

// ErrInvalidKey reports a key that is not a valid point for its algorithm.
var ErrInvalidKey = errors.New("keys: invalid public key")

// PublicKey is a validated Ed25519 or P-256 public key.
type PublicKey struct {
	alg Alg
	raw []byte // 32-byte Ed25519 key or 33-byte SEC1 compressed P-256 point
	ec  *ecdsa.PublicKey
}

// Parse validates raw as a key of alg. Ed25519 keys must be canonical and
// not of small order; P-256 keys must be a compressed point on the curve.
func Parse(alg Alg, raw []byte) (*PublicKey, error) {
	switch alg {
	case Ed25519:
		if err := curves.Ed25519CheckPoint(raw); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return &PublicKey{alg: alg, raw: append([]byte(nil), raw...)}, nil
	case P256:
		ec, err := curves.P256Decompress(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return &PublicKey{alg: alg, raw: append([]byte(nil), raw...), ec: ec}, nil
	}
	return nil, fmt.Errorf("%w: unknown algorithm", ErrInvalidKey)
}

// Alg returns the key's algorithm.
func (k *PublicKey) Alg() Alg { return k.alg }

// Raw returns the key's raw AID encoding (a copy).
func (k *PublicKey) Raw() []byte { return append([]byte(nil), k.raw...) }

// ECDSA returns the P-256 key, or nil for Ed25519.
func (k *PublicKey) ECDSA() *ecdsa.PublicKey { return k.ec }

// VerifyDigest verifies a JCS-profile or proof signature over the 32-byte
// digest d = SHA-256(signing input) (RFC-AITP-0001 §5.4.6): Ed25519 signs d
// as its message; P-256 uses d as e without hashing again.
func (k *PublicKey) VerifyDigest(d, sig []byte) error {
	if len(d) != sha256.Size {
		return fmt.Errorf("%w: digest must be 32 bytes", curves.ErrSignature)
	}
	if k.alg == Ed25519 {
		return curves.Ed25519Verify(k.raw, d, sig)
	}
	return curves.P256VerifyDigest(k.ec, d, sig)
}

// VerifyJWS verifies a compact-JWS signature over the exact signing input
// ASCII(header "." payload): EdDSA over the input, ES256 over its SHA-256
// (RFC 7518 §3.4), both with the §5.4.7 strictness rules.
func (k *PublicKey) VerifyJWS(input, sig []byte) error {
	if k.alg == Ed25519 {
		return curves.Ed25519Verify(k.raw, input, sig)
	}
	h := sha256.Sum256(input)
	return curves.P256VerifyDigest(k.ec, h[:], sig)
}
