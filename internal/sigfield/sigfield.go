// Package sigfield parses JCS-profile signature fields (RFC-AITP-0001
// §5.4.3): an untagged 86-char Ed25519 signature, or "ed25519." / "p256."
// followed by 86 chars of strict base64url over 64 raw bytes.
package sigfield

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
)

// Errors returned by Parse and Verify.
var (
	ErrMalformed   = errors.New("sigfield: malformed signature field")
	ErrUnknownAlg  = errors.New("sigfield: unregistered algorithm tag")
	ErrAlgMismatch = errors.New("sigfield: algorithm tag does not match the signer's key")
)

// Sig is a parsed signature field.
type Sig struct {
	Alg    keys.Alg
	Tagged bool
	Bytes  []byte // 64 bytes
}

// Parse parses a signature field.
func Parse(s string) (*Sig, error) {
	alg, tagged, enc := keys.Ed25519, false, s
	if tag, rest, found := strings.Cut(s, "."); found {
		a, known := keys.AlgFromTag(tag)
		if !known {
			return nil, fmt.Errorf("%w %q", ErrUnknownAlg, tag)
		}
		alg, tagged, enc = a, true, rest
	}
	raw, err := b64.DecodeLen(enc, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return &Sig{Alg: alg, Tagged: tagged, Bytes: raw}, nil
}

// Verify checks the field against key over the signing input: the field's
// algorithm must be the key's (the anti-downgrade rule of §5.4.3 step 3),
// and the signature must verify over d = SHA-256(input) (§5.4.6).
func Verify(field string, key *keys.PublicKey, input []byte) error {
	sig, err := Parse(field)
	if err != nil {
		return err
	}
	if sig.Alg != key.Alg() {
		return ErrAlgMismatch
	}
	d := sha256.Sum256(input)
	return key.VerifyDigest(d[:], sig.Bytes)
}
