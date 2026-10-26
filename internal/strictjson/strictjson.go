// Package strictjson is a strict RFC 8259 JSON parser.
//
// It accepts exactly the RFC 8259 grammar and additionally rejects, at any
// depth: duplicate object member names (compared after unescaping),
// invalid UTF-8, escaped lone surrogates, a leading byte-order mark, and any
// data after the top-level value. These are the inputs on which two JSON
// libraries can disagree about what a signed object says (RFC-AITP-0001
// §5.4.5 "Strict parsing"; RFC 8785 §3.1 requires I-JSON input).
//
// Values keep object member order and the literal text of numbers, so a
// caller can both canonicalize (package jcs) and inspect the input as sent.
package strictjson

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth bounds nesting so hostile input cannot exhaust the stack.
const MaxDepth = 128

// Kind is the JSON type of a Value.
type Kind int

// The JSON value kinds.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

func (k Kind) String() string {
	switch k {
	case Null:
		return "null"
	case Bool:
		return "boolean"
	case Number:
		return "number"
	case String:
		return "string"
	case Array:
		return "array"
	case Object:
		return "object"
	}
	return "invalid"
}

// Member is one object member, in input order.
type Member struct {
	Key   string
	Value *Value
}

// Value is a parsed JSON value.
type Value struct {
	Kind Kind
	Bool bool     // Kind == Bool
	Str  string   // Kind == String: the unescaped string (valid UTF-8)
	Num  string   // Kind == Number: the literal as written
	Arr  []*Value // Kind == Array
	Obj  []Member // Kind == Object, in input order, names unique
}

// Errors returned by Parse. Every parse error wraps ErrSyntax; the more
// specific causes below also wrap their own sentinel.
var (
	ErrSyntax        = errors.New("strictjson: invalid JSON")
	ErrDuplicateKey  = errors.New("strictjson: duplicate object member name")
	ErrInvalidUTF8   = errors.New("strictjson: invalid UTF-8")
	ErrLoneSurrogate = errors.New("strictjson: lone surrogate escape")
	ErrTrailingData  = errors.New("strictjson: data after the JSON value")
	ErrTooDeep       = errors.New("strictjson: nesting too deep")
	ErrBOM           = errors.New("strictjson: byte-order mark")
)

// SyntaxError reports where parsing failed.
type SyntaxError struct {
	Offset int
	Msg    string
	cause  error
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("strictjson: %s at offset %d", e.Msg, e.Offset)
}

// Is makes every SyntaxError match ErrSyntax and its specific cause.
func (e *SyntaxError) Is(target error) bool {
	return target == ErrSyntax || (e.cause != nil && target == e.cause)
}

type parser struct {
	data []byte
	pos  int
}

func (p *parser) fail(cause error, format string, args ...any) error {
	return &SyntaxError{Offset: p.pos, Msg: fmt.Sprintf(format, args...), cause: cause}
}

// Parse parses exactly one JSON value from data.
func Parse(data []byte) (*Value, error) {
	p := &parser{data: data}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return nil, p.fail(ErrBOM, "leading byte-order mark")
	}
	p.skipWS()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, p.fail(ErrTrailingData, "unexpected data after value")
	}
	return v, nil
}

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*Value, error) {
	if p.pos >= len(p.data) {
		return nil, p.fail(nil, "unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: String, Str: s}, nil
	case c == 't':
		return p.literal("true", &Value{Kind: Bool, Bool: true})
	case c == 'f':
		return p.literal("false", &Value{Kind: Bool})
	case c == 'n':
		return p.literal("null", &Value{Kind: Null})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		if c >= 0x80 && !utf8.Valid(p.data[p.pos:min(p.pos+4, len(p.data))]) {
			return nil, p.fail(ErrInvalidUTF8, "invalid UTF-8")
		}
		return nil, p.fail(nil, "unexpected character %q", c)
	}
}

func (p *parser) literal(word string, v *Value) (*Value, error) {
	if len(p.data)-p.pos < len(word) || string(p.data[p.pos:p.pos+len(word)]) != word {
		return nil, p.fail(nil, "invalid literal")
	}
	p.pos += len(word)
	return v, nil
}

func (p *parser) object(depth int) (*Value, error) {
	if depth > MaxDepth {
		return nil, p.fail(ErrTooDeep, "nesting deeper than %d", MaxDepth)
	}
	p.pos++ // '{'
	v := &Value{Kind: Object, Obj: []Member{}}
	seen := map[string]struct{}{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return v, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.fail(nil, "expected member name")
		}
		keyAt := p.pos
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[k]; dup {
			p.pos = keyAt
			return nil, p.fail(ErrDuplicateKey, "duplicate member name %q", k)
		}
		seen[k] = struct{}{}
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.fail(nil, "expected ':'")
		}
		p.pos++
		p.skipWS()
		mv, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		v.Obj = append(v.Obj, Member{Key: k, Value: mv})
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail(nil, "unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return v, nil
		default:
			return nil, p.fail(nil, "expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (*Value, error) {
	if depth > MaxDepth {
		return nil, p.fail(ErrTooDeep, "nesting deeper than %d", MaxDepth)
	}
	p.pos++ // '['
	v := &Value{Kind: Array, Arr: []*Value{}}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return v, nil
	}
	for {
		p.skipWS()
		ev, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		v.Arr = append(v.Arr, ev)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.fail(nil, "unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return nil, p.fail(nil, "expected ',' or ']'")
		}
	}
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

// hex4 reads the four hex digits after "\u" at p.pos.
func (p *parser) hex4() (rune, error) {
	if len(p.data)-p.pos < 4 {
		return 0, p.fail(nil, "short \\u escape")
	}
	var r rune
	for i := 0; i < 4; i++ {
		h, ok := hexVal(p.data[p.pos+i])
		if !ok {
			return 0, p.fail(nil, "invalid \\u escape")
		}
		r = r<<4 | h
	}
	p.pos += 4
	return r, nil
}

func (p *parser) str() (string, error) {
	p.pos++ // opening quote
	var out []byte
	start := p.pos
	for {
		if p.pos >= len(p.data) {
			return "", p.fail(nil, "unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			out = append(out, p.data[start:p.pos]...)
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", p.fail(nil, "unescaped control character in string")
		case c == '\\':
			out = append(out, p.data[start:p.pos]...)
			if err := p.escape(&out); err != nil {
				return "", err
			}
			start = p.pos
		case c < 0x80:
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.fail(ErrInvalidUTF8, "invalid UTF-8 in string")
			}
			p.pos += size
		}
	}
}

func (p *parser) escape(out *[]byte) error {
	p.pos++ // backslash
	if p.pos >= len(p.data) {
		return p.fail(nil, "unterminated escape")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		*out = append(*out, c)
	case 'b':
		*out = append(*out, '\b')
	case 'f':
		*out = append(*out, '\f')
	case 'n':
		*out = append(*out, '\n')
	case 'r':
		*out = append(*out, '\r')
	case 't':
		*out = append(*out, '\t')
	case 'u':
		r, err := p.hex4()
		if err != nil {
			return err
		}
		switch {
		case utf16.IsSurrogate(r) && r < 0xDC00:
			// A high surrogate must be followed by an escaped low surrogate.
			if len(p.data)-p.pos < 2 || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
				return p.fail(ErrLoneSurrogate, "high surrogate without low surrogate")
			}
			p.pos += 2
			lo, err := p.hex4()
			if err != nil {
				return err
			}
			if lo < 0xDC00 || lo > 0xDFFF {
				return p.fail(ErrLoneSurrogate, "high surrogate without low surrogate")
			}
			r = utf16.DecodeRune(r, lo)
		case utf16.IsSurrogate(r):
			return p.fail(ErrLoneSurrogate, "lone low surrogate")
		}
		*out = utf8.AppendRune(*out, r)
	default:
		return p.fail(nil, "invalid escape \\%c", c)
	}
	return nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *parser) number() (*Value, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.data) || !isDigit(p.data[p.pos]) {
		return nil, p.fail(nil, "invalid number")
	}
	if p.data[p.pos] == '0' {
		p.pos++
		if p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			return nil, p.fail(nil, "leading zero in number")
		}
	} else {
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.pos >= len(p.data) || !isDigit(p.data[p.pos]) {
			return nil, p.fail(nil, "digit expected after '.'")
		}
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || !isDigit(p.data[p.pos]) {
			return nil, p.fail(nil, "digit expected in exponent")
		}
		for p.pos < len(p.data) && isDigit(p.data[p.pos]) {
			p.pos++
		}
	}
	lit := string(p.data[start:p.pos])
	// I-JSON (RFC 7493 §2.2): a number must be representable as an IEEE 754
	// double. Overflow to infinity is rejected; JCS cannot serialize it.
	if f, err := strconv.ParseFloat(lit, 64); math.IsInf(f, 0) || (err != nil && !errors.Is(err, strconv.ErrRange)) {
		p.pos = start
		return nil, p.fail(nil, "number out of range")
	}
	return &Value{Kind: Number, Num: lit}, nil
}

// Float returns the number's IEEE 754 double value.
func (v *Value) Float() (float64, error) {
	if v == nil || v.Kind != Number {
		return 0, errors.New("strictjson: not a number")
	}
	f, err := strconv.ParseFloat(v.Num, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, err
	}
	if math.IsInf(f, 0) {
		return 0, errors.New("strictjson: number out of range")
	}
	return f, nil
}

// Get returns the member named key of an object.
func (v *Value) Get(key string) (*Value, bool) {
	if v == nil || v.Kind != Object {
		return nil, false
	}
	for _, m := range v.Obj {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// Without returns a shallow copy of an object with the named members removed.
func (v *Value) Without(keys ...string) *Value {
	if v == nil || v.Kind != Object {
		return v
	}
	out := &Value{Kind: Object, Obj: make([]Member, 0, len(v.Obj))}
	for _, m := range v.Obj {
		drop := false
		for _, k := range keys {
			if m.Key == k {
				drop = true
				break
			}
		}
		if !drop {
			out.Obj = append(out.Obj, m)
		}
	}
	return out
}
