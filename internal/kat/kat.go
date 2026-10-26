// Package kat loads the spec's known-answer vectors from the pinned copy
// under testdata/spec for tests. It parses them with strictjson, so every
// test also exercises the parser on the real corpus.
package kat

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// Root returns the module root (the directory holding go.mod).
func Root(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("kat: go.mod not found")
		}
		dir = parent
	}
}

// Path returns a path under testdata/spec/schemas/conformance/known-answer.
func Path(t testing.TB, rel string) string {
	return filepath.Join(Root(t), "testdata", "spec", "schemas", "conformance", "known-answer", rel)
}

// Load reads and strictly parses a known-answer file.
func Load(t testing.TB, rel string) *strictjson.Value {
	t.Helper()
	data, err := os.ReadFile(Path(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictjson.Parse(data)
	if err != nil {
		t.Fatalf("kat: %s: %v", rel, err)
	}
	return v
}

// Vectors returns the "vectors" array of a known-answer file.
func Vectors(t testing.TB, rel string) []*strictjson.Value {
	t.Helper()
	v, ok := Load(t, rel).Get("vectors")
	if !ok || v.Kind != strictjson.Array || len(v.Arr) == 0 {
		t.Fatalf("kat: %s has no vectors", rel)
	}
	return v.Arr
}

// Has reports whether the object v has member key.
func Has(v *strictjson.Value, key string) bool {
	_, ok := v.Get(key)
	return ok
}

// Str returns the string member key of v.
func Str(t testing.TB, v *strictjson.Value, key string) string {
	t.Helper()
	m, ok := v.Get(key)
	if !ok || m.Kind != strictjson.String {
		t.Fatalf("kat: member %q is not a string", key)
	}
	return m.Str
}

// Hex returns the hex-decoded string member key of v.
func Hex(t testing.TB, v *strictjson.Value, key string) []byte {
	t.Helper()
	b, err := hex.DecodeString(Str(t, v, key))
	if err != nil {
		t.Fatalf("kat: member %q: %v", key, err)
	}
	return b
}

// Keypairs returns keypairs.json indexed by vector id.
func Keypairs(t testing.TB) map[string]*strictjson.Value {
	t.Helper()
	out := map[string]*strictjson.Value{}
	for _, v := range Vectors(t, "keypairs.json") {
		out[Str(t, v, "id")] = v
	}
	return out
}
