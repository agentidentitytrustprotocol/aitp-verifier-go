package jcs

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/kat"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestKnownAnswerJCS recomputes every canonical byte sequence pinned in
// jcs-sha256.json byte for byte, and its digest.
func TestKnownAnswerJCS(t *testing.T) {
	checked := 0
	for _, v := range kat.Vectors(t, "jcs-sha256.json") {
		id := kat.Str(t, v, "id")
		var obj *strictjson.Value
		var wantHex string
		switch {
		case kat.Has(v, "object"):
			obj, _ = v.Get("object")
			wantHex = kat.Str(t, v, "jcs_canonical_hex")
			if kat.Str(t, v, "signing_input") != "body" {
				t.Errorf("%s: signing_input is not body", id)
			}
		case kat.Has(v, "preimage_json"):
			obj, _ = v.Get("preimage_json")
			wantHex = kat.Str(t, v, "preimage_hex")
		case kat.Has(v, "digest_array_jcs"):
			// Multi-hop chain hash: JCS of the array of per-entry digests.
			chain, _ := v.Get("chain")
			arr := &strictjson.Value{Kind: strictjson.Array}
			for _, e := range chain.Arr {
				h := sha256.Sum256([]byte(e.Str))
				arr.Arr = append(arr.Arr, &strictjson.Value{Kind: strictjson.String, Str: b64(h[:])})
			}
			got, err := Canonicalize(arr)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != kat.Str(t, v, "digest_array_jcs") {
				t.Errorf("%s: digest array %s", id, got)
			}
			h := sha256.Sum256(got)
			if b64(h[:]) != kat.Str(t, v, "chain_hash") {
				t.Errorf("%s: chain_hash mismatch", id)
			}
			checked++
			continue
		case kat.Has(v, "chain_truncated"):
			chain, _ := v.Get("chain_truncated")
			got, err := Canonicalize(chain)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(got)
			if b64(h[:]) != kat.Str(t, v, "chain_hash_truncated") || b64(h[:]) == kat.Str(t, v, "chain_hash_full") {
				t.Errorf("%s: truncated chain hash mismatch", id)
			}
			checked++
			continue
		case kat.Has(v, "domain_tag"):
			// Derived identifier (RFC-AITP-0005 §2.2): SHA-256(tag || 0x00 || input) -> UUIDv4 bits.
			pre := append(append([]byte(kat.Str(t, v, "domain_tag")), 0), kat.Hex(t, v, "input_hex")...)
			h := sha256.Sum256(pre)
			u := append([]byte(nil), h[:16]...)
			u[6] = u[6]&0x0f | 0x40
			u[8] = u[8]&0x3f | 0x80
			x := hex.EncodeToString(u)
			uuid := x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
			if hex.EncodeToString(pre) != kat.Str(t, v, "preimage_hex") || hex.EncodeToString(h[:]) != kat.Str(t, v, "sha256_hex") || uuid != kat.Str(t, v, "uuid") {
				t.Errorf("%s: derived identifier differs", id)
			}
			checked++
			continue
		default:
			continue // a signature vector without JCS input (sigfield tests)
		}
		got, err := Canonicalize(obj)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if hex.EncodeToString(got) != wantHex {
			t.Errorf("%s: canonical bytes differ\n got %s", id, got)
			continue
		}
		if kat.Has(v, "sha256_hex") {
			h := sha256.Sum256(got)
			if hex.EncodeToString(h[:]) != kat.Str(t, v, "sha256_hex") || b64(h[:]) != kat.Str(t, v, "sha256_b64url") {
				t.Errorf("%s: digest differs", id)
			}
		}
		checked++
	}
	if checked != 7 {
		t.Fatalf("only %d JCS vectors checked", checked)
	}
	t.Logf("%d JCS/digest vectors recomputed byte-exactly", checked)
}

// TestKnownAnswerJWKCanonical: every pinned canonical JWK is a JCS fixpoint.
func TestKnownAnswerJWKCanonical(t *testing.T) {
	for _, v := range kat.Vectors(t, "jwk-thumbprints.json") {
		in := kat.Str(t, v, "jwk_canonical")
		got, err := Transform([]byte(in))
		if err != nil || string(got) != in {
			t.Errorf("%s: %s %v", kat.Str(t, v, "id"), got, err)
		}
	}
}

func TestRFC8785Example(t *testing.T) {
	// RFC 8785 §3.2.2 / Appendix: the canonicalization sample.
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// TestUTF16Sort is the RFC 8785 §3.2.3 sorting example plus the U+FFFF /
// U+10000 boundary, where UTF-16 order and UTF-8 byte order disagree.
func TestUTF16Sort(t *testing.T) {
	in := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	got, err = Transform([]byte(`{"\uffff":1,"\ud800\udc00":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"\U00010000\":2,\"\uffff\":1}"; string(got) != want {
		t.Fatalf("U+10000 must sort before U+FFFF: got %q", got)
	}
	if CompareUTF16("\uffff", "\U00010000") <= 0 || CompareUTF16("a", "a") != 0 || CompareUTF16("a", "b") >= 0 {
		t.Fatal("CompareUTF16")
	}
}

// TestNumberEdgeCases holds the plan's edge-case table and RFC 8785
// Appendix B's IEEE 754 sample values.
func TestNumberEdgeCases(t *testing.T) {
	lits := []struct{ in, want string }{
		{"-0", "0"},
		{"0", "0"},
		{"-0.0", "0"},
		{"1e21", "1e+21"},
		{"1e20", "100000000000000000000"},
		{"123456789012345678901", "123456789012345680000"},
		{"5e-324", "5e-324"},
		{"9007199254740993", "9007199254740992"}, // above 2^53: nearest double
		{"18446744073709551616", "18446744073709552000"},
		{"0.000001", "0.000001"},
		{"1e-7", "1e-7"},
		{"1E-7", "1e-7"},
		{"-1.5e-10", "-1.5e-10"},
		{"100", "100"},
		{"1.0", "1"},
		{"0.1", "0.1"},
		{"1e400", ""},   // overflows: rejected by the parser
		{"1e-400", "0"}, // underflows to zero
	}
	for _, c := range lits {
		got, err := Transform([]byte(c.in))
		if c.want == "" {
			if err == nil {
				t.Errorf("%s: accepted as %s", c.in, got)
			}
			continue
		}
		if err != nil || string(got) != c.want {
			t.Errorf("%s: got %s %v, want %s", c.in, got, err, c.want)
		}
	}
	bits := []struct {
		hex  string
		want string
	}{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	}
	for _, c := range bits {
		u, _ := strconv.ParseUint(c.hex, 16, 64)
		got, err := FormatNumber(math.Float64frombits(u))
		if err != nil || got != c.want {
			t.Errorf("%s: got %s %v, want %s", c.hex, got, err, c.want)
		}
	}
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := FormatNumber(f); !errors.Is(err, ErrNumber) {
			t.Errorf("%v: %v", f, err)
		}
	}
}

func TestStrings(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"\u0000"`, `"\u0000"`},
		{`"\u001f\u0007"`, `"\u001f\u0007"`},
		{`"\b\f\n\r\t"`, `"\b\f\n\r\t"`},
		{`"\u007f"`, "\"\x7f\""},
		{`"\/"`, `"/"`},
		{`"\u00e9"`, `"é"`},
		{`"\u2028"`, "\"\u2028\""},
		{`"a\"b\\c"`, `"a\"b\\c"`},
		{`"\ud83d\ude00"`, `"😀"`},
	}
	for _, c := range cases {
		got, err := Transform([]byte(c.in))
		if err != nil || string(got) != c.want {
			t.Errorf("%s: got %q %v, want %q", c.in, got, err, c.want)
		}
	}
}

func TestStructures(t *testing.T) {
	cases := []struct{ in, want string }{
		{` { "b" : [ 1 , { "d":true, "c":null } ] , "a" : {} , "e": [] } `, `{"a":{},"b":[1,{"c":null,"d":true}],"e":[]}`},
		{`[false]`, `[false]`},
		{`"x"`, `"x"`},
	}
	for _, c := range cases {
		got, err := Transform([]byte(c.in))
		if err != nil || string(got) != c.want {
			t.Errorf("%s: got %s %v, want %s", c.in, got, err, c.want)
		}
	}
}

func TestTransformRejects(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `[1,]`, "\xef\xbb\xbf{}", `{} x`, `"\ud800"`} {
		if _, err := Transform([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := Canonicalize(&strictjson.Value{Kind: strictjson.Kind(99)}); err == nil {
		t.Error("invalid kind accepted")
	}
	bad := &strictjson.Value{Kind: strictjson.Number, Num: "x"}
	for _, v := range []*strictjson.Value{
		bad,
		{Kind: strictjson.Array, Arr: []*strictjson.Value{bad}},
		{Kind: strictjson.Object, Obj: []strictjson.Member{{Key: "k", Value: bad}}},
	} {
		if _, err := Canonicalize(v); err == nil {
			t.Error("bad number accepted")
		}
	}
}

// FuzzTransform: canonical output is valid strict JSON, and canonicalizing
// it again is the identity.
func FuzzTransform(f *testing.F) {
	for _, s := range []string{`{"a":[1,2.5,-0,1e21]}`, `"\u0000"`, `{"\uffff":1,"\ud800\udc00":2}`, `[null,true,false]`} {
		f.Add([]byte(s))
	}
	for _, name := range []string{"jcs-sha256.json", "jwk-thumbprints.json", "keypairs.json", "signature-strictness.json"} {
		if data, err := os.ReadFile(kat.Path(f, name)); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Transform(data)
		if err != nil {
			return
		}
		again, err := Transform(out)
		if err != nil {
			t.Fatalf("canonical output does not reparse: %q: %v", out, err)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("not idempotent: %q -> %q", out, again)
		}
	})
}
