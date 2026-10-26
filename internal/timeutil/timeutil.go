// Package timeutil holds the verifier's notion of time. Verifiers never read
// the wall clock: the time comes from a Clock the caller supplies.
package timeutil

import (
	"errors"
	"math"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// Clock returns the current time as Unix seconds.
type Clock interface {
	Now() int64
}

// Fixed is a Clock that always returns the same instant.
type Fixed int64

// Now returns the fixed instant.
func (f Fixed) Now() int64 { return int64(f) }

// MaxSafeInteger is 2^53 - 1, the largest integer every JSON implementation
// reads exactly (RFC 7493 §2.2).
const MaxSafeInteger = 1<<53 - 1

// ErrNotTimestamp reports a value that is not an integer Unix timestamp.
var ErrNotTimestamp = errors.New("timeutil: not an integer timestamp in [0, 2^53-1]")

// Seconds reads a JSON number as an integer Unix timestamp (a JWT
// NumericDate or an AITP timestamp field). Fractions, exponents that do not
// yield an integer, negatives and values above 2^53-1 are rejected.
func Seconds(v *strictjson.Value) (int64, error) {
	f, err := v.Float()
	if err != nil {
		return 0, ErrNotTimestamp
	}
	if f < 0 || f > MaxSafeInteger || f != math.Trunc(f) {
		return 0, ErrNotTimestamp
	}
	return int64(f), nil
}

// Within reports whether |now - t| <= tolerance.
func Within(now, t, tolerance int64) bool {
	d := now - t
	if d < 0 {
		d = -d
	}
	return d <= tolerance
}
