// Package curves holds the signature-strictness checks of RFC-AITP-0001
// §5.4.7 on top of the standard library's Ed25519 and ECDSA.
//
// Ed25519: crypto/ed25519 already uses the cofactorless equation and
// rejects S ≥ L, but its point decoder accepts non-canonical encodings and
// small-order points. Ed25519CheckPoint adds the canonical-encoding check
// (y < p, and no "negative zero" x) and a blocklist of the eight canonical
// small-order encodings, applied to the public key A and to R.
//
// P-256: crypto/ecdsa accepts high-S signatures. P256VerifyDigest adds the
// range and low-S checks, and P256Decompress decodes SEC1 compressed
// points with math/big (elliptic.UnmarshalCompressed is deprecated).
package curves

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"math/big"
)

// Errors. Every verification failure wraps ErrSignature.
var (
	ErrSignature    = errors.New("curves: signature verification failed")
	ErrNonCanonical = errors.New("curves: non-canonical encoding")
	ErrSmallOrder   = errors.New("curves: small-order point")
	ErrHighS        = errors.New("curves: ECDSA S above n/2")
	ErrRange        = errors.New("curves: scalar out of range")
	ErrLength       = errors.New("curves: wrong length")
	ErrNotOnCurve   = errors.New("curves: point not on curve")
)

type sigError struct{ cause error }

func (e sigError) Error() string { return e.cause.Error() }
func (e sigError) Unwrap() []error {
	return []error{ErrSignature, e.cause}
}

func fail(cause error) error { return sigError{cause} }

// ── Ed25519 ─────────────────────────────────────────────────────────────────

// ed25519P is 2^255 - 19.
var ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// ed25519L is the prime order of the base point, 2^252 + 27742317777372353535851937790883648493.
var ed25519L, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// smallOrder lists the canonical encodings of the eight points of order
// dividing 8. With the canonical-encoding check in front of it, no other
// encoding of these points gets through.
var smallOrder = [8][32]byte{
	// identity (0, 1): order 1
	{0x01},
	// (0, -1): order 2
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	// (±sqrt(-1), 0): order 4
	{},
	{31: 0x80},
	// order 8
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85},
}

// SmallOrderEncodings returns the blocklist (for tests).
func SmallOrderEncodings() [8][32]byte { return smallOrder }

// leInt reads a little-endian integer.
func leInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// Ed25519CheckPoint rejects a non-canonical or small-order encoding of an
// Ed25519 point (a public key A, or a signature's R).
func Ed25519CheckPoint(enc []byte) error {
	if len(enc) != 32 {
		return ErrLength
	}
	var yb [32]byte
	copy(yb[:], enc)
	signBit := yb[31] >> 7
	yb[31] &= 0x7f
	y := leInt(yb[:])
	if y.Cmp(ed25519P) >= 0 {
		return ErrNonCanonical
	}
	// x = 0 exactly when y = ±1; its encoding must have the sign bit clear.
	pm1 := new(big.Int).Sub(ed25519P, big.NewInt(1))
	if signBit == 1 && (y.Cmp(big.NewInt(1)) == 0 || y.Cmp(pm1) == 0) {
		return ErrNonCanonical
	}
	for _, so := range smallOrder {
		if bytes.Equal(enc, so[:]) {
			return ErrSmallOrder
		}
	}
	return nil
}

// Ed25519Verify verifies sig over msg under pub with the §5.4.7 rules:
// canonical, non-small-order A and R; S < L; cofactorless equation.
func Ed25519Verify(pub, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return fail(ErrLength)
	}
	if err := Ed25519CheckPoint(pub); err != nil {
		return fail(err)
	}
	if err := Ed25519CheckPoint(sig[:32]); err != nil {
		return fail(err)
	}
	if leInt(sig[32:]).Cmp(ed25519L) >= 0 {
		return fail(ErrRange)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fail(errors.New("curves: Ed25519 equation does not hold"))
	}
	return nil
}

// ── P-256 ───────────────────────────────────────────────────────────────────

var (
	p256      = elliptic.P256().Params()
	p256HalfN = new(big.Int).Rsh(p256.N, 1)
)

// P256Decompress decodes a 33-byte SEC1 compressed point (SEC 1 §2.3.4).
func P256Decompress(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 33 {
		return nil, ErrLength
	}
	if b[0] != 0x02 && b[0] != 0x03 {
		return nil, ErrNonCanonical
	}
	x := new(big.Int).SetBytes(b[1:])
	if x.Cmp(p256.P) >= 0 {
		return nil, ErrNonCanonical
	}
	// y² = x³ - 3x + b (mod p)
	rhs := new(big.Int).Exp(x, big.NewInt(3), p256.P)
	rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
	rhs.Add(rhs, p256.B)
	rhs.Mod(rhs, p256.P)
	// p ≡ 3 (mod 4), so a square root is rhs^((p+1)/4).
	exp := new(big.Int).Rsh(new(big.Int).Add(p256.P, big.NewInt(1)), 2)
	y := new(big.Int).Exp(rhs, exp, p256.P)
	if new(big.Int).Exp(y, big.NewInt(2), p256.P).Cmp(rhs) != 0 {
		return nil, ErrNotOnCurve
	}
	if y.Bit(0) != uint(b[0]&1) {
		y.Sub(p256.P, y)
	}
	unc := make([]byte, 65)
	unc[0] = 0x04
	x.FillBytes(unc[1:33])
	y.FillBytes(unc[33:])
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), unc)
	if err != nil {
		return nil, ErrNotOnCurve
	}
	return pub, nil
}

// P256Coordinates returns the 32-byte big-endian affine coordinates of pub.
func P256Coordinates(pub *ecdsa.PublicKey) (x, y []byte, err error) {
	unc, err := pub.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return unc[1:33], unc[33:], nil
}

// P256Compress returns the 33-byte SEC1 compressed encoding of pub.
func P256Compress(pub *ecdsa.PublicKey) ([]byte, error) {
	x, y, err := P256Coordinates(pub)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 33)
	out[0] = 0x02 | (y[31] & 1)
	copy(out[1:], x)
	return out, nil
}

// P256VerifyDigest verifies a 64-byte r||s ECDSA signature with the hash
// step already performed: digest is used as e directly (RFC-AITP-0001
// §5.4.6). It rejects r or s outside [1, n-1] and s > n/2 (§5.4.7).
func P256VerifyDigest(pub *ecdsa.PublicKey, digest, sig []byte) error {
	if pub == nil || len(sig) != 64 {
		return fail(ErrLength)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(p256.N) >= 0 || s.Cmp(p256.N) >= 0 {
		return fail(ErrRange)
	}
	if s.Cmp(p256HalfN) > 0 {
		return fail(ErrHighS)
	}
	if !ecdsa.Verify(pub, digest, r, s) {
		return fail(errors.New("curves: ECDSA equation does not hold"))
	}
	return nil
}
