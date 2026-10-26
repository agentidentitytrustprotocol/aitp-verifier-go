// Package jws parses and verifies AITP compact JWS (RFC-AITP-0001 §5.4.5).
//
// Parse applies the profile's strict-parsing rules: exactly three non-empty
// segments of strict unpadded base64url; a protected header that is a JSON
// object with exactly the string members "alg" and "typ"; a payload that is
// a JSON object without duplicate member names. Verification covers the
// transmitted bytes; nothing is re-serialized.
package jws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// Errors. The verifiers map them to registry codes per artifact.
var (
	ErrMalformed   = errors.New("jws: malformed compact JWS")
	ErrHeader      = errors.New("jws: protected header must have exactly alg and typ")
	ErrPayload     = errors.New("jws: payload is not a strict JSON object")
	ErrTypMismatch = errors.New("jws: typ mismatch")
	ErrAlgMismatch = errors.New("jws: alg mismatch")
)

// Token is a parsed compact JWS.
type Token struct {
	Alg          string
	Typ          string
	Payload      *strictjson.Value // a JSON object
	PayloadBytes []byte
	SigningInput []byte // ASCII(header "." payload), as transmitted
	Signature    []byte
}

// Parse parses s strictly. It does not verify anything cryptographic.
func Parse(s string) (*Token, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: %d segments", ErrMalformed, len(parts))
	}
	raw := make([][]byte, 3)
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("%w: empty segment", ErrMalformed)
		}
		b, err := b64.Decode(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		raw[i] = b
	}
	hdr, err := strictjson.Parse(raw[0])
	if err != nil || hdr.Kind != strictjson.Object || len(hdr.Obj) != 2 {
		return nil, ErrHeader
	}
	alg, okA := hdr.Get("alg")
	typ, okT := hdr.Get("typ")
	if !okA || !okT || alg.Kind != strictjson.String || typ.Kind != strictjson.String {
		return nil, ErrHeader
	}
	payload, err := strictjson.Parse(raw[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPayload, err)
	}
	if payload.Kind != strictjson.Object {
		return nil, ErrPayload
	}
	return &Token{
		Alg:          alg.Str,
		Typ:          typ.Str,
		Payload:      payload,
		PayloadBytes: raw[1],
		SigningInput: []byte(parts[0] + "." + parts[1]),
		Signature:    raw[2],
	}, nil
}

// CheckTyp requires the header typ to be exactly want (RFC 8725 §3.11).
func (t *Token) CheckTyp(want string) error {
	if t.Typ != want {
		return fmt.Errorf("%w: got %q, want %q", ErrTypMismatch, t.Typ, want)
	}
	return nil
}

// CheckAlg requires the header alg to be the sole value the signer's key
// permits: EdDSA for Ed25519, ES256 for P-256. "none" never matches.
func (t *Token) CheckAlg(k *keys.PublicKey) error {
	if t.Alg != k.Alg().JWSAlg() {
		return fmt.Errorf("%w: got %q, want %q", ErrAlgMismatch, t.Alg, k.Alg().JWSAlg())
	}
	return nil
}

// VerifySignature checks the alg pin and then the signature under k.
func (t *Token) VerifySignature(k *keys.PublicKey) error {
	if err := t.CheckAlg(k); err != nil {
		return err
	}
	return k.VerifyJWS(t.SigningInput, t.Signature)
}
