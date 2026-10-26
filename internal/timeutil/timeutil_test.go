package timeutil

import (
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

func num(s string) *strictjson.Value { return &strictjson.Value{Kind: strictjson.Number, Num: s} }

func TestSeconds(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "1711900000": 1711900000, "1.7119e9": 1711900000, "9007199254740991": MaxSafeInteger} {
		if got, err := Seconds(num(in)); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"-1", "1.5", "9007199254740992", "9007199254740993", "1e300"} {
		if _, err := Seconds(num(in)); err != ErrNotTimestamp {
			t.Errorf("%s accepted", in)
		}
	}
	if _, err := Seconds(&strictjson.Value{Kind: strictjson.String, Str: "1"}); err != ErrNotTimestamp {
		t.Error("string accepted")
	}
}

func TestClock(t *testing.T) {
	var c Clock = Fixed(100)
	if c.Now() != 100 {
		t.Fatal("Fixed")
	}
	if !Within(100, 400, 300) || !Within(400, 100, 300) || Within(100, 401, 300) || Within(401, 100, 300) {
		t.Fatal("Within")
	}
}
