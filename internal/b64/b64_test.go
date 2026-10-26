package b64

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for n := 0; n < 70; n++ {
		b := bytes.Repeat([]byte{0xfb}, n)
		s := Encode(b)
		got, err := DecodeLen(s, n)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"AAAAAA==", ErrAlphabet},   // padding
		{"AAAAAAA=", ErrAlphabet},   // padding
		{"AA AA", ErrAlphabet},      // space
		{"AAAA\nAAAA", ErrAlphabet}, // newline, which encoding/base64 skips
		{"AAAA\rAAAA", ErrAlphabet}, // CR
		{"AA+/", ErrAlphabet},       // standard alphabet
		{"AAAAA", ErrEncoding},      // impossible length
		{"AB", ErrEncoding},         // non-zero trailing bits
		{"AAB", ErrEncoding},        // non-zero trailing bits
	}
	for _, c := range cases {
		if _, err := Decode(c.in); !errors.Is(err, c.want) {
			t.Errorf("%q: got %v, want %v", c.in, err, c.want)
		}
	}
	if _, err := DecodeLen("AAAA", 2); !errors.Is(err, ErrLength) {
		t.Error("length 3 accepted as 2")
	}
	if _, err := DecodeLen("AA=A", 3); !errors.Is(err, ErrAlphabet) {
		t.Error("padding inside fixed length")
	}
	if !InAlphabet("azAZ09-_") || InAlphabet("=") || InAlphabet("é") {
		t.Error("InAlphabet")
	}
}
