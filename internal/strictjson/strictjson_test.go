package strictjson

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccepts(t *testing.T) {
	for _, in := range []string{
		`{}`, `[]`, `""`, `0`, `-0`, `1.5e+10`, `1E-2`, `true`, `false`, `null`,
		" \t\r\n{\"a\" : [ 1 , 2 ] } \n",
		`{"a":{"b":{"c":{"d":1}}}}`,
		`"\u0000"`, `"😀"`, `"é"`, `"\"\\\/\b\f\n\r\t"`,
		`{"a":1,"b":{"a":1}}`, // same name at different levels is fine
	} {
		if _, err := Parse([]byte(in)); err != nil {
			t.Errorf("%q rejected: %v", in, err)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := []struct {
		in    string
		cause error
	}{
		{`{"a":1,"a":2}`, ErrDuplicateKey},
		{`{"a":{"b":{"c":{"x":1,"x":2}}}}`, ErrDuplicateKey}, // depth 4
		{`[{"a":[{"k":1,"k":1}]}]`, ErrDuplicateKey},         // depth 4, through arrays
		{`{"a":1,"a":2}`, ErrDuplicateKey},                   // equal after unescaping
		{`"\ud800"`, ErrLoneSurrogate},
		{`"\udc00"`, ErrLoneSurrogate},
		{`"\ud800A"`, ErrLoneSurrogate},
		{`"\ud800x"`, ErrLoneSurrogate},
		{`{"\udfff":1}`, ErrLoneSurrogate},
		{"\"\xff\"", ErrInvalidUTF8},
		{"\"\xc3\x28\"", ErrInvalidUTF8},
		{"\"\xed\xa0\x80\"", ErrInvalidUTF8}, // UTF-8-encoded surrogate
		{"\"\xc0\xaf\"", ErrInvalidUTF8},     // overlong
		{"\xe9", ErrInvalidUTF8},
		{"\xef\xbb\xbf{}", ErrBOM},
		{`{} {}`, ErrTrailingData},
		{`1 2`, ErrTrailingData},
		{`[1]x`, ErrTrailingData},
		{strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1), ErrTooDeep},
		{strings.Repeat(`{"a":`, MaxDepth+1) + "1" + strings.Repeat("}", MaxDepth+1), ErrTooDeep},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.in))
		if !errors.Is(err, c.cause) || !errors.Is(err, ErrSyntax) {
			t.Errorf("%q: got %v, want %v", c.in, err, c.cause)
		}
	}
	for _, in := range []string{
		``, ` `, `{`, `[`, `}`, `{"a"}`, `{"a":}`, `{"a":1,}`, `[1,]`, `{,}`, `{1:2}`,
		`{"a" 1}`, `{"a":1 "b":2}`, `[1 2]`, `"abc`, `"\x"`, `"\u12"`, `"\u12G4"`, `"\`,
		"\"a\nb\"", "\"\x01\"", `01`, `-`, `-a`, `1.`, `1.e5`, `1e`, `1e+`, `.5`, `+1`,
		`tru`, `nul`, `falsy`, `NaN`, `Infinity`, `'a'`, `1e400`, `-1e400`, "\x00",
		`{"a":1`, `[1`, `{"a"`, `"\ud800\u`, `"\ud800\uzzzz"`,
	} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrSyntax) {
			t.Errorf("%q: accepted or wrong error (%v)", in, err)
		}
	}
}

func TestValues(t *testing.T) {
	v, err := Parse([]byte(`{"s":"aé","n":-1.25e2,"b":true,"z":null,"a":[1,"x"],"o":{"k":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != Object || len(v.Obj) != 6 || v.Obj[0].Key != "s" || v.Obj[5].Key != "o" {
		t.Fatal("member order not kept")
	}
	s, _ := v.Get("s")
	n, _ := v.Get("n")
	b, _ := v.Get("b")
	z, _ := v.Get("z")
	a, _ := v.Get("a")
	if s.Str != "aé" || n.Num != "-1.25e2" || !b.Bool || z.Kind != Null || len(a.Arr) != 2 {
		t.Fatal("values")
	}
	if f, err := n.Float(); err != nil || f != -125 {
		t.Fatal("Float", f, err)
	}
	if _, err := s.Float(); err == nil {
		t.Fatal("Float on a string")
	}
	if _, err := (&Value{Kind: Number, Num: "1e999"}).Float(); err == nil {
		t.Fatal("Float overflow")
	}
	if _, err := (&Value{Kind: Number, Num: "x"}).Float(); err == nil {
		t.Fatal("Float garbage")
	}
	if _, ok := v.Get("missing"); ok {
		t.Fatal("Get missing")
	}
	if _, ok := s.Get("x"); ok {
		t.Fatal("Get on a string")
	}
	w := v.Without("s", "o")
	if len(w.Obj) != 4 || len(v.Obj) != 6 {
		t.Fatal("Without")
	}
	if s.Without("x") != s {
		t.Fatal("Without on a string")
	}
	for k, want := range map[Kind]string{Null: "null", Bool: "boolean", Number: "number", String: "string", Array: "array", Object: "object", Kind(42): "invalid"} {
		if k.String() != want {
			t.Errorf("Kind %d: %s", k, k.String())
		}
	}
	_, err = Parse([]byte(`{"a":1,"a":2}`))
	var se *SyntaxError
	if !errors.As(err, &se) || se.Offset != 7 || !strings.Contains(se.Error(), "offset 7") {
		t.Fatalf("SyntaxError offset: %v", err)
	}
}

func knownAnswerFiles(tb testing.TB) []string {
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "spec", "schemas", "conformance", "known-answer", "*.json"))
	more, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "spec", "schemas", "conformance", "*.json"))
	return append(files, more...)
}

// TestSpecCorpus: every known-answer file and conformance fixture in the
// pinned spec parses.
func TestSpecCorpus(t *testing.T) {
	files := knownAnswerFiles(t)
	if len(files) < 50 {
		t.Fatalf("only %d corpus files", len(files))
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{`{"a":[1,{"b":"😀"}]}`, `"\u0000"`, `{"a":1,"a":2}`, `[1e400]`} {
		f.Add([]byte(s))
	}
	files := knownAnswerFiles(f)
	for i, file := range files {
		if i >= 8 {
			break
		}
		if data, err := os.ReadFile(file); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrSyntax) {
				t.Fatalf("error does not wrap ErrSyntax: %v", err)
			}
			return
		}
		if v == nil {
			t.Fatal("nil value without error")
		}
	})
}
