// Package b64 is strict unpadded base64url (RFC 4648 §5), the only binary
// encoding AITP uses (RFC-AITP-0001 §5.4).
//
// Decode rejects '=' padding, characters outside [A-Za-z0-9_-] (including
// the CR and LF that encoding/base64 silently skips), and non-zero trailing
// bits, so every byte string has exactly one accepted encoding.
package b64

import (
	"encoding/base64"
	"errors"
	"fmt"
)

var enc = base64.RawURLEncoding.Strict()

// Errors returned by Decode and DecodeLen.
var (
	ErrAlphabet = errors.New("b64: character outside the unpadded base64url alphabet")
	ErrEncoding = errors.New("b64: malformed base64url")
	ErrLength   = errors.New("b64: wrong decoded length")
)

// InAlphabet reports whether every byte of s is in [A-Za-z0-9_-].
func InAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Decode decodes strict unpadded base64url.
func Decode(s string) ([]byte, error) {
	if !InAlphabet(s) {
		return nil, ErrAlphabet
	}
	b, err := enc.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return b, nil
}

// DecodeLen decodes s and requires exactly n raw bytes.
func DecodeLen(s string, n int) ([]byte, error) {
	if len(s) != enc.EncodedLen(n) {
		return nil, fmt.Errorf("%w: %d chars, want %d", ErrLength, len(s), enc.EncodedLen(n))
	}
	b, err := Decode(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, ErrLength
	}
	return b, nil
}

// Encode encodes b as unpadded base64url.
func Encode(b []byte) string { return enc.EncodeToString(b) }
