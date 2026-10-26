// Package aid parses Agent IDs (RFC-AITP-0001 §5.3):
//
//	aid:pubkey:<43 chars>           legacy, Ed25519
//	aid:pubkey:ed25519:<43 chars>   tagged Ed25519
//	aid:pubkey:p256:<44 chars>      tagged P-256, SEC1 compressed
//
// The identifier is strict unpadded base64url of the raw key. The two
// Ed25519 spellings name the same key but are different strings, so an AID
// keeps the string it was parsed from.
package aid

import (
	"errors"
	"fmt"
	"strings"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
)

// Errors returned by Parse; all wrap ErrInvalid.
var (
	ErrInvalid    = errors.New("aid: invalid AID")
	ErrUnknownAlg = errors.New("aid: unregistered algorithm tag")
)

// AID is a parsed Agent ID.
type AID struct {
	str    string
	tagged bool
	key    *keys.PublicKey
}

const prefix = "aid:pubkey:"

// Parse parses and validates s, including the key it encodes.
func Parse(s string) (*AID, error) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return nil, fmt.Errorf("%w: not an aid:pubkey: identifier", ErrInvalid)
	}
	alg, tagged := keys.Ed25519, false
	if tag, id, found := strings.Cut(rest, ":"); found {
		a, known := keys.AlgFromTag(tag)
		if !known {
			return nil, fmt.Errorf("%w: %w %q", ErrInvalid, ErrUnknownAlg, tag)
		}
		alg, tagged, rest = a, true, id
	}
	raw, err := b64.DecodeLen(rest, alg.RawLen())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	k, err := keys.Parse(alg, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return &AID{str: s, tagged: tagged, key: k}, nil
}

// FromKey returns the AID of k: tagged for P-256; for Ed25519 tagged or the
// legacy untagged form as asked.
func FromKey(k *keys.PublicKey, tagged bool) string {
	id := b64.Encode(k.Raw())
	if k.Alg() == keys.Ed25519 && !tagged {
		return prefix + id
	}
	return prefix + k.Alg().Tag() + ":" + id
}

// String returns the AID exactly as parsed.
func (a *AID) String() string { return a.str }

// Tagged reports whether the AID carries an algorithm tag.
func (a *AID) Tagged() bool { return a.tagged }

// Key returns the public key the AID encodes.
func (a *AID) Key() *keys.PublicKey { return a.key }

// Alg returns the key algorithm.
func (a *AID) Alg() keys.Alg { return a.key.Alg() }

// SameKey reports whether two AIDs name the same key, treating the legacy
// and tagged Ed25519 spellings as equivalent for trust decisions.
func (a *AID) SameKey(b *AID) bool {
	return a.Alg() == b.Alg() && string(a.key.Raw()) == string(b.key.Raw())
}
