package verify

import (
	"net/url"
	"regexp"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/timeutil"
)

// Grammars shared by the JSON Schemas under schemas/json/.
var (
	reAID       = regexp.MustCompile(`^aid:pubkey:([A-Za-z0-9_-]{43}|ed25519:[A-Za-z0-9_-]{43}|p256:[A-Za-z0-9_-]{44})$`)
	reUUIDv4    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	reSig       = regexp.MustCompile(`^((ed25519|p256)\.)?[A-Za-z0-9_-]{86}$`)
	reNonce     = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	reJKT       = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	rePublicKey = regexp.MustCompile(`^[A-Za-z0-9_-]{43,44}$`)
	reCompact   = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	reNoSpace   = regexp.MustCompile(`^[^\s]+$`)
	reSPIFFE    = regexp.MustCompile(`^spiffe://[a-z0-9._-]{1,255}(/([A-Za-z0-9._-]*[A-Za-z0-9_-][A-Za-z0-9._-]*|\.{3,}))+$`)
)

// fields is a read-only view of a JSON object for schema checks.
type fields struct{ v *strictjson.Value }

func asObject(v *strictjson.Value) (fields, bool) {
	if v == nil || v.Kind != strictjson.Object {
		return fields{}, false
	}
	return fields{v}, true
}

func (f fields) has(key string) bool {
	_, ok := f.v.Get(key)
	return ok
}

func (f fields) get(key string) (*strictjson.Value, bool) { return f.v.Get(key) }

// str returns a string member; ok is false when absent or not a string.
func (f fields) str(key string) (string, bool) {
	m, ok := f.v.Get(key)
	if !ok || m.Kind != strictjson.String {
		return "", false
	}
	return m.Str, true
}

// match returns a string member that matches re.
func (f fields) match(key string, re *regexp.Regexp) (string, bool) {
	s, ok := f.str(key)
	if !ok || !re.MatchString(s) {
		return "", false
	}
	return s, true
}

// integer returns a non-negative integer member no smaller than min.
func (f fields) integer(key string, min int64) (int64, bool) {
	m, ok := f.v.Get(key)
	if !ok || m.Kind != strictjson.Number {
		return 0, false
	}
	n, err := timeutil.Seconds(m)
	if err != nil || n < min {
		return 0, false
	}
	return n, true
}

// object returns an object member.
func (f fields) object(key string) (fields, bool) {
	m, ok := f.v.Get(key)
	if !ok {
		return fields{}, false
	}
	return asObject(m)
}

// strings returns an array-of-strings member whose items all match item
// (nil: any string), with unique items and at least minItems entries.
func (f fields) strings(key string, item *regexp.Regexp, minItems int) ([]string, bool) {
	m, ok := f.v.Get(key)
	if !ok {
		return nil, false
	}
	return stringArray(m, item, minItems)
}

func stringArray(m *strictjson.Value, item *regexp.Regexp, minItems int) ([]string, bool) {
	if m.Kind != strictjson.Array || len(m.Arr) < minItems {
		return nil, false
	}
	out := make([]string, 0, len(m.Arr))
	seen := make(map[string]bool, len(m.Arr))
	for _, e := range m.Arr {
		if e.Kind != strictjson.String || seen[e.Str] {
			return nil, false
		}
		if item != nil && !item.MatchString(e.Str) {
			return nil, false
		}
		seen[e.Str] = true
		out = append(out, e.Str)
	}
	return out, true
}

// unknown returns the first member that is not in allowed.
func (f fields) unknown(allowed ...string) (string, bool) {
outer:
	for _, m := range f.v.Obj {
		for _, a := range allowed {
			if m.Key == a {
				continue outer
			}
		}
		return m.Key, true
	}
	return "", false
}

// isURI reports whether s is an absolute URI (JSON Schema "format": "uri").
func isURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Opaque+u.Host+u.Path != ""
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// subset reports the first element of a that is not in b.
func subset(a, b []string) (string, bool) {
	for _, e := range a {
		if !contains(b, e) {
			return e, false
		}
	}
	return "", true
}
