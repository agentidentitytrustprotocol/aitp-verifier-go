package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestErrorsGoUpToDate is the CI check that errors.go matches the pinned
// registry: run `go generate ./...` when it fails.
func TestErrorsGoUpToDate(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	md, err := os.ReadFile(filepath.Join(root, registryPath))
	if err != nil {
		t.Fatal(err)
	}
	want, err := Generate(md)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, outputPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("errors.go is stale: run `go generate ./...`")
	}
	codes, _ := Parse(md)
	if len(codes) < 50 {
		t.Fatalf("only %d codes parsed", len(codes))
	}
}

func TestParseRejects(t *testing.T) {
	for name, md := range map[string]string{
		"empty":           "no tables here\n",
		"bad status":      "| Code | Meaning | spec_status |\n|---|---|---|\n| `X` | m | final |\n",
		"bad retry":       "| Code | Retryable | spec_status |\n|---|---|---|\n| `X` | maybe | core |\n",
		"bad name":        "| Code | Meaning | spec_status |\n|---|---|---|\n| `x-y` | m | core |\n",
		"unquoted":        "| Code | Meaning | spec_status |\n|---|---|---|\n| X | m | core |\n",
		"status conflict": "| Code | Meaning | spec_status |\n|---|---|---|\n| `X` | m | core |\n| `X` | m | draft |\n",
		"retry conflict":  "| Code | Retryable | spec_status |\n|---|---|---|\n| `X` | true | core |\n| `X` | false | core |\n",
	} {
		if _, err := Generate([]byte(md)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseMerges(t *testing.T) {
	md := "| Code | Meaning | spec_status |\n|---|---|---|\n| `A_B` | m | core |\n\n" +
		"| Code | Retryable | spec_status |\n|---|---|---|\n| `A_B` | true | core |\n"
	src, err := Generate([]byte(md))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `CodeAB ErrorCode = "A_B"`) || !strings.Contains(string(src), "Retryable: true, RetryableStated: true") {
		t.Fatalf("unexpected output:\n%s", src)
	}
}
