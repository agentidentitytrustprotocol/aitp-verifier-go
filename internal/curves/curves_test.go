package curves

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/kat"
)

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	s = s[strings.IndexByte(s, '.')+1:] // drop an algorithm tag
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vector(t *testing.T, file, id string) map[string]string {
	t.Helper()
	for _, v := range kat.Vectors(t, file) {
		if kat.Str(t, v, "id") == id {
			out := map[string]string{}
			for _, m := range v.Obj {
				out[m.Key] = m.Value.Str
			}
			return out
		}
	}
	t.Fatalf("%s: no vector %s", file, id)
	return nil
}

// ── Independent Edwards arithmetic, used only to check the blocklist ───────

var edD = func() *big.Int {
	p := ed25519P
	num := big.NewInt(-121665)
	den := new(big.Int).ModInverse(big.NewInt(121666), p)
	return num.Mul(num, den).Mod(num, p)
}()

type pt struct{ x, y *big.Int }

func edAdd(a, b pt) pt {
	p := ed25519P
	x1y2 := new(big.Int).Mul(a.x, b.y)
	y1x2 := new(big.Int).Mul(a.y, b.x)
	y1y2 := new(big.Int).Mul(a.y, b.y)
	x1x2 := new(big.Int).Mul(a.x, b.x)
	dxy := new(big.Int).Mul(edD, new(big.Int).Mul(x1x2, y1y2))
	dxy.Mod(dxy, p)
	x3 := new(big.Int).Add(x1y2, y1x2)
	x3.Mul(x3, new(big.Int).ModInverse(new(big.Int).Add(big.NewInt(1), dxy), p)).Mod(x3, p)
	y3 := new(big.Int).Add(y1y2, x1x2)
	y3.Mul(y3, new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), dxy), p), p)).Mod(y3, p)
	return pt{x3, y3}
}

// edDecode is RFC 8032 §5.1.3 decoding (strict).
func edDecode(enc [32]byte) (pt, bool) {
	p := ed25519P
	sign := enc[31] >> 7
	enc[31] &= 0x7f
	y := leInt(enc[:])
	if y.Cmp(p) >= 0 {
		return pt{}, false
	}
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, p)
	v := new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1))
	v.Mod(v, p)
	x2 := new(big.Int).Mul(u, new(big.Int).ModInverse(v, p))
	x2.Mod(x2, p)
	x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(3)), 3), p)
	if new(big.Int).Exp(x, big.NewInt(2), p).Cmp(x2) != 0 {
		i := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2), p)
		x.Mul(x, i).Mod(x, p)
		if new(big.Int).Exp(x, big.NewInt(2), p).Cmp(x2) != 0 {
			return pt{}, false
		}
	}
	if x.Sign() == 0 && sign == 1 {
		return pt{}, false
	}
	if x.Bit(0) != uint(sign) {
		x.Sub(p, x)
	}
	return pt{x, y}, true
}

// TestSmallOrderBlocklist proves each blocklisted encoding decodes to a
// distinct point P with [8]P = identity: the blocklist is the whole
// 8-element torsion subgroup.
func TestSmallOrderBlocklist(t *testing.T) {
	seen := map[string]bool{}
	for i, enc := range SmallOrderEncodings() {
		P, ok := edDecode(enc)
		if !ok {
			t.Fatalf("entry %d does not decode", i)
		}
		Q := P
		for j := 0; j < 3; j++ {
			Q = edAdd(Q, Q)
		}
		if Q.x.Sign() != 0 || Q.y.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("entry %d: [8]P is not the identity", i)
		}
		key := P.x.String() + "," + P.y.String()
		if seen[key] {
			t.Fatalf("entry %d duplicates another point", i)
		}
		seen[key] = true
		if err := Ed25519CheckPoint(enc[:]); !errors.Is(err, ErrSmallOrder) {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
}

func TestEd25519CheckPoint(t *testing.T) {
	// y = p (non-canonical encoding of y = 0).
	nonCanon := make([]byte, 32)
	copy(nonCanon, []byte{0xed})
	for i := 1; i < 31; i++ {
		nonCanon[i] = 0xff
	}
	nonCanon[31] = 0x7f
	// y = p + 1: a non-canonical encoding of the identity.
	idPlusP := append([]byte(nil), nonCanon...)
	idPlusP[0] = 0xee
	// identity with the sign bit set ("negative zero" x).
	negZero := make([]byte, 32)
	negZero[0], negZero[31] = 0x01, 0x80
	// (0, -1) with the sign bit set.
	so := SmallOrderEncodings()
	negZero2 := append([]byte(nil), so[1][:]...)
	negZero2[31] |= 0x80
	for name, c := range map[string]struct {
		enc  []byte
		want error
	}{
		"y = p":           {nonCanon, ErrNonCanonical},
		"y = p+1":         {idPlusP, ErrNonCanonical},
		"-0 identity":     {negZero, ErrNonCanonical},
		"-0 order 2":      {negZero2, ErrNonCanonical},
		"short":           {make([]byte, 31), ErrLength},
		"kat-keypair-001": {unb64(t, "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"), nil},
	} {
		if err := Ed25519CheckPoint(c.enc); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// TestSignatureStrictness: sig-001..sig-003 are rejected for the stated
// reason, a lax (stock) check accepts them, and the valid siblings verify.
func TestSignatureStrictness(t *testing.T) {
	const file = "signature-strictness.json"

	v := vector(t, file, "sig-001-ed25519-small-order-key-rejected")
	pub, msg, sig := unb64(t, v["public_key_b64url"]), mustHex(t, v["message_hex"]), unb64(t, v["signature_b64url"])
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("sig-001: stock Ed25519 should accept (else the vector tests nothing)")
	}
	if err := Ed25519Verify(pub, msg, sig); !errors.Is(err, ErrSmallOrder) || !errors.Is(err, ErrSignature) {
		t.Errorf("sig-001: got %v", err)
	}

	v = vector(t, file, "sig-002-ed25519-noncanonical-s-rejected")
	pub = unb64(t, strings.TrimPrefix(v["signer_aid"], "aid:pubkey:"))
	msg = mustHex(t, v["message_hex"])
	if err := Ed25519Verify(pub, msg, unb64(t, v["valid_signature_b64url"])); err != nil {
		t.Errorf("sig-002 valid sibling: %v", err)
	}
	if err := Ed25519Verify(pub, msg, unb64(t, v["signature_b64url"])); !errors.Is(err, ErrRange) {
		t.Errorf("sig-002: got %v", err)
	}

	v = vector(t, file, "sig-003-p256-high-s-rejected")
	ec, err := P256Decompress(unb64(t, strings.TrimPrefix(v["signer_aid"], "aid:pubkey:p256:")))
	if err != nil {
		t.Fatal(err)
	}
	d := mustHex(t, v["sha256_hex"])
	if err := P256VerifyDigest(ec, d, unb64(t, v["low_s_signature"])); err != nil {
		t.Errorf("sig-003 low-S sibling: %v", err)
	}
	high := unb64(t, v["signature"])
	r, s := new(big.Int).SetBytes(high[:32]), new(big.Int).SetBytes(high[32:])
	if !ecdsa.Verify(ec, d, r, s) {
		t.Error("sig-003: stock ECDSA should accept")
	}
	if err := P256VerifyDigest(ec, d, high); !errors.Is(err, ErrHighS) || !errors.Is(err, ErrSignature) {
		t.Errorf("sig-003: got %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEd25519VerifyRejects(t *testing.T) {
	seed := make([]byte, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("m")
	sig := ed25519.Sign(priv, msg)
	if err := Ed25519Verify(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := Ed25519Verify(pub, []byte("x"), sig); !errors.Is(err, ErrSignature) {
		t.Error("wrong message accepted")
	}
	if err := Ed25519Verify(pub[:31], msg, sig); !errors.Is(err, ErrLength) {
		t.Error("short key")
	}
	if err := Ed25519Verify(pub, msg, sig[:63]); !errors.Is(err, ErrLength) {
		t.Error("short sig")
	}
	smallR := append([]byte(nil), sig...)
	copy(smallR, []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err := Ed25519Verify(pub, msg, smallR); !errors.Is(err, ErrSmallOrder) {
		t.Errorf("small-order R: %v", err)
	}
}

func TestP256(t *testing.T) {
	kp := kat.Keypairs(t)["kat-keypair-005-p256"]
	scalar := kat.Hex(t, kp, "private_scalar_hex")
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	unc := priv.PublicKey().Bytes()
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), unc)
	if err != nil {
		t.Fatal(err)
	}
	comp, err := P256Compress(pub)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(comp) != kat.Str(t, kp, "pubkey_compressed_hex") {
		t.Fatal("compressed key differs from kat-keypair-005-p256")
	}
	back, err := P256Decompress(comp)
	if err != nil || !back.Equal(pub) {
		t.Fatalf("decompress round-trip: %v", err)
	}
	// Both parities decompress to the two points with this x.
	other := append([]byte(nil), comp...)
	other[0] ^= 1
	neg, err := P256Decompress(other)
	if err != nil || neg.Equal(pub) {
		t.Fatalf("other parity: %v", err)
	}

	// Malformed encodings.
	uncompressed := append([]byte{}, unc...)
	xGEp := append([]byte{0x02}, p256.P.FillBytes(make([]byte, 32))...)
	for name, c := range map[string]struct {
		enc  []byte
		want error
	}{
		"uncompressed (id-012)": {uncompressed, ErrLength},
		"prefix 04":             {append([]byte{0x04}, comp[1:]...), ErrNonCanonical},
		"prefix 00":             {append([]byte{0x00}, comp[1:]...), ErrNonCanonical},
		"x = p":                 {xGEp, ErrNonCanonical},
		"x not on curve":        {append([]byte{0x02}, make([]byte, 31)...), ErrLength},
	} {
		if _, err := P256Decompress(c.enc); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	// Find an x with no point and check it is refused.
	found := false
	for i := 0; i < 64 && !found; i++ {
		x := make([]byte, 33)
		x[0], x[32] = 0x02, byte(i)
		if _, err := P256Decompress(x); errors.Is(err, ErrNotOnCurve) {
			found = true
		}
	}
	if !found {
		t.Error("no off-curve x found in 64 tries")
	}

	d := sha256.Sum256([]byte("m"))
	n := p256.N
	enc := func(r, s *big.Int) []byte {
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
	one := big.NewInt(1)
	nm1 := new(big.Int).Sub(n, one)
	for name, c := range map[string]struct {
		sig  []byte
		want error
	}{
		"r = 0":   {enc(big.NewInt(0), one), ErrRange},
		"s = 0":   {enc(one, big.NewInt(0)), ErrRange},
		"r = n":   {enc(n, one), ErrRange},
		"s = n":   {enc(one, n), ErrRange},
		"s = n-1": {enc(one, nm1), ErrHighS},
		"short":   {make([]byte, 63), ErrLength},
		"bad eq":  {enc(one, one), ErrSignature},
	} {
		if err := P256VerifyDigest(pub, d[:], c.sig); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if err := P256VerifyDigest(nil, d[:], make([]byte, 64)); !errors.Is(err, ErrLength) {
		t.Error("nil key")
	}
	if _, err := P256Compress(&ecdsa.PublicKey{}); err == nil {
		t.Error("compress of an empty key")
	}
}
