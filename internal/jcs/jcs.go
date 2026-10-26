// Package jcs implements the JSON Canonicalization Scheme, RFC 8785.
//
// AITP signs the JCS form of its protocol-internal artifacts
// (RFC-AITP-0001 §5.4.1). Three rules carry the interop risk and are
// implemented here rather than borrowed from encoding/json:
//
//   - object members are sorted by their names as UTF-16 code-unit
//     sequences (RFC 8785 §3.2.3), which differs from Go's byte order for
//     names containing characters above U+FFFF;
//   - numbers are serialized as ECMAScript Number::toString does for an
//     IEEE 754 double (RFC 8785 §3.2.2.3);
//   - strings escape only '"', '\\' and the C0 controls, using the short
//     forms where JSON has them and lowercase \u00xx otherwise
//     (RFC 8785 §3.2.2.2).
package jcs

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// ErrNumber reports a number JCS cannot serialize (NaN or infinity).
var ErrNumber = errors.New("jcs: number is not finite")

// Transform parses data strictly and returns its canonical form.
func Transform(data []byte) ([]byte, error) {
	v, err := strictjson.Parse(data)
	if err != nil {
		return nil, err
	}
	return Canonicalize(v)
}

// Canonicalize returns the RFC 8785 canonical form of v.
func Canonicalize(v *strictjson.Value) ([]byte, error) {
	var b []byte
	return appendValue(b, v)
}

func appendValue(b []byte, v *strictjson.Value) ([]byte, error) {
	switch v.Kind {
	case strictjson.Null:
		return append(b, "null"...), nil
	case strictjson.Bool:
		if v.Bool {
			return append(b, "true"...), nil
		}
		return append(b, "false"...), nil
	case strictjson.Number:
		f, err := v.Float()
		if err != nil {
			return nil, ErrNumber
		}
		s, err := FormatNumber(f)
		if err != nil {
			return nil, err
		}
		return append(b, s...), nil
	case strictjson.String:
		return AppendString(b, v.Str), nil
	case strictjson.Array:
		b = append(b, '[')
		for i, e := range v.Arr {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendValue(b, e); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case strictjson.Object:
		members := slices.Clone(v.Obj)
		slices.SortFunc(members, func(x, y strictjson.Member) int { return CompareUTF16(x.Key, y.Key) })
		b = append(b, '{')
		for i, m := range members {
			if i > 0 {
				b = append(b, ',')
			}
			b = AppendString(b, m.Key)
			b = append(b, ':')
			var err error
			if b, err = appendValue(b, m.Value); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	}
	return nil, errors.New("jcs: invalid value")
}

// CompareUTF16 orders two strings by their UTF-16 code units.
func CompareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

const hexDigits = "0123456789abcdef"

// AppendString appends the RFC 8785 serialization of s (valid UTF-8).
func AppendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		b = append(b, s[start:i]...)
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\t':
			b = append(b, '\\', 't')
		case '\n':
			b = append(b, '\\', 'n')
		case '\f':
			b = append(b, '\\', 'f')
		case '\r':
			b = append(b, '\\', 'r')
		default:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
		}
		start = i + 1
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// FormatNumber serializes f as ECMAScript Number::toString (ECMA-262
// §6.1.6.1.20) does, which RFC 8785 §3.2.2.3 adopts.
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", ErrNumber
	}
	if f == 0 {
		return "0", nil // covers -0
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest round-trip digits: "d.ddde±XX" -> digits "dddd", exponent.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expPart, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, err := strconv.Atoi(expPart)
	if err != nil {
		return "", err
	}
	k := len(digits)
	n := exp + 1 // value = 0.digits × 10^n
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		ev := strconv.Itoa(abs(n - 1))
		if k == 1 {
			out = digits + "e" + es + ev
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es + ev
		}
	}
	return sign + out, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
