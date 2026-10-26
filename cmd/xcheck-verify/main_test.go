package main

import (
	"io"
	"testing"
)

func TestRejectsForeignInput(t *testing.T) {
	for _, in := range []string{"", "{}", `{"minted_by":"someone-else"}`, "not json"} {
		if rc := run([]byte(in), io.Discard); rc != 2 {
			t.Errorf("run(%q) = %d, want 2", in, rc)
		}
	}
}

func TestHighSTwin(t *testing.T) {
	sig := make([]byte, 64)
	sig[63] = 1
	twin, err := highS(sig)
	if err != nil {
		t.Fatal(err)
	}
	back, err := highS(twin)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(sig) {
		t.Fatal("highS is not an involution")
	}
}
