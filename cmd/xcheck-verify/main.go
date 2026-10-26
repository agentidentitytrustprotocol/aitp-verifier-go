// Command xcheck-verify is the cross-implementation check: it reads the
// JSON that aitp-rs's xcheck-mint tool writes and verifies every artifact
// with package verify, byte for byte. Nothing is re-signed. Each negative
// either changes exactly one thing in a positive artifact (the high-S twin
// of a P-256 signature, a stripped "p256." tag, a withheld or rewritten
// key) or is a negative aitp-rs minted itself.
//
//	xcheck-mint | go run ./cmd/xcheck-verify
//
// It exits 1 if any check fails and 2 if the input is not xcheck-mint
// output.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/verify"
)

// p256N is the order of the P-256 base point.
var p256N, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

type minted struct {
	MintedBy               string          `json:"minted_by"`
	Now                    int64           `json:"now"`
	ExpectedIssuer         string          `json:"expected_issuer"`
	Snapshot               json.RawMessage `json:"snapshot"`
	SnapshotWithExtensions json.RawMessage `json:"snapshot_with_extensions"`
	ManifestNoExtensions   json.RawMessage `json:"manifest_no_extensions"`
	ManifestWithExtensions json.RawMessage `json:"manifest_with_extensions"`
	OIDCIdentity           struct {
		Now   int64      `json:"now"`
		EdDSA oidcVector `json:"eddsa"`
		ES256 oidcVector `json:"es256"`
	} `json:"oidc_identity"`
	P256 struct {
		AID                string          `json:"aid"`
		VerifierAID        string          `json:"verifier_aid"`
		ParticipantAID     string          `json:"participant_aid"`
		Snapshot           json.RawMessage `json:"snapshot"`
		Manifest           json.RawMessage `json:"manifest"`
		Envelope           json.RawMessage `json:"envelope"`
		EnvelopeDoubleHash json.RawMessage `json:"envelope_double_hash"`
		PinnedKey          struct {
			Identity      json.RawMessage `json:"identity"`
			Envelope      json.RawMessage `json:"envelope"`
			ProofInputHex string          `json:"proof_input_hex"`
		} `json:"pinned_key"`
		TCT         string `json:"tct"`
		Attestation string `json:"attestation"`
	} `json:"p256"`
}

type oidcVector struct {
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	Proof     string `json:"proof"`
	IssuerJWK struct {
		Kty, Crv, X, Y string
	} `json:"issuer_jwk"`
	SelfAID  string `json:"self_aid"`
	Envelope struct {
		Sender struct {
			AgentID string `json:"agent_id"`
		} `json:"sender"`
		Payload struct {
			PopNonce string `json:"pop_nonce"`
		} `json:"payload"`
	} `json:"envelope"`
}

// envelopeHead is the part of an envelope a pinned-key proof is bound to.
type envelopeHead struct {
	MessageID string `json:"message_id"`
	Timestamp int64  `json:"timestamp"`
	Sender    struct {
		AgentID string `json:"agent_id"`
	} `json:"sender"`
	Payload struct {
		PopNonce string `json:"pop_nonce"`
	} `json:"payload"`
	Signature string `json:"signature"`
}

type checker struct {
	out    io.Writer
	failed int
}

func (c *checker) ok(name string, fn func() error) {
	if err := fn(); err != nil {
		c.failed++
		fmt.Fprintf(c.out, "  FAIL  %s\n          %v\n", name, err)
		return
	}
	fmt.Fprintf(c.out, "  ok    %s\n", name)
}

// rejects passes when fn fails with a registry code (a *verify.Error).
func (c *checker) rejects(name string, fn func() error) {
	err := fn()
	var ve *verify.Error
	switch {
	case err == nil:
		c.failed++
		fmt.Fprintf(c.out, "  FAIL  %s\n          accepted\n", name)
	case errors.As(err, &ve):
		fmt.Fprintf(c.out, "  ok    %s (%s)\n", name, verify.CodeOf(err))
	default:
		c.failed++
		fmt.Fprintf(c.out, "  FAIL  %s\n          not a registry error: %v\n", name, err)
	}
}

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xcheck-verify:", err)
		os.Exit(2)
	}
	os.Exit(run(in, os.Stdout))
}

func run(in []byte, out io.Writer) int {
	var m minted
	if err := json.Unmarshal(in, &m); err != nil || m.MintedBy != "aitp-rs" {
		fmt.Fprintln(out, "stdin is not xcheck-mint output")
		return 2
	}
	c := &checker{out: out}
	// Inside every artifact's validity window.
	now := m.Now + 100

	fmt.Fprintln(out, "Minted by aitp-rs, verified by aitp-verifier-go:")
	c.ok("revocation snapshot", func() error { return snapshot(m.Snapshot, m.ExpectedIssuer, now) })
	c.ok("revocation snapshot with populated extensions", func() error {
		return snapshot(m.SnapshotWithExtensions, m.ExpectedIssuer, now)
	})
	c.ok("manifest (no extensions)", func() error { return manifest(m.ManifestNoExtensions, now) })
	c.ok("manifest with populated extensions", func() error { return manifest(m.ManifestWithExtensions, now) })

	oidcNow := m.OIDCIdentity.Now + 100
	for _, l := range []struct {
		name string
		vec  oidcVector
	}{{"eddsa", m.OIDCIdentity.EdDSA}, {"es256", m.OIDCIdentity.ES256}} {
		vec := l.vec
		key, kerr := jwkKey(vec.IssuerJWK.Kty, vec.IssuerJWK.Crv, vec.IssuerJWK.X, vec.IssuerJWK.Y)
		c.ok("oidc identity binding ("+l.name+")", func() error {
			if kerr != nil {
				return kerr
			}
			return oidc(vec, vec.Proof, []*keys.PublicKey{key}, oidcNow)
		})
		c.rejects("oidc identity binding ("+l.name+") -- withheld issuer key is rejected", func() error {
			return oidc(vec, vec.Proof, nil, oidcNow)
		})
		c.rejects("oidc identity binding ("+l.name+") -- alg-confusion header rewrite is rejected", func() error {
			if kerr != nil {
				return kerr
			}
			return oidc(vec, swapAlg(vec.Proof), []*keys.PublicKey{key}, oidcNow)
		})
	}

	p := m.P256
	fmt.Fprintln(out, "\nP-256 legs (kat-keypair-005-p256):")
	c.ok("p256 revocation snapshot", func() error { return snapshot(p.Snapshot, p.AID, now) })
	c.ok("p256 manifest (44-char pinned_key identity_hint)", func() error { return manifest(p.Manifest, now) })
	c.ok("p256 envelope (single-hash JCS primitive)", func() error { return envelope(p.Envelope, now) })

	var head envelopeHead
	headErr := json.Unmarshal(p.PinnedKey.Envelope, &head)
	bound := verify.BoundMessage{Sender: head.Sender.AgentID, MessageID: head.MessageID, Timestamp: head.Timestamp, PopNonce: head.Payload.PopNonce}
	pinned := func(identity json.RawMessage, trusted ...string) error {
		if headErr != nil {
			return headErr
		}
		_, err := verify.VerifyIdentity(identity, nil, bound, verify.IdentityOptions{
			Now: now, SelfAID: p.VerifierAID, PinnedKeys: trusted,
		})
		return err
	}
	c.ok("p256 pinned-key five-field proof input is byte-identical", func() error {
		if headErr != nil {
			return headErr
		}
		ours, err := verify.PinnedKeyProofInput(bound, p.VerifierAID)
		if err != nil {
			return err
		}
		if got := hex.EncodeToString(ours); got != p.PinnedKey.ProofInputHex {
			return fmt.Errorf("proof input differs:\n  rs %s\n  go %s", p.PinnedKey.ProofInputHex, got)
		}
		return nil
	})
	c.ok("p256 pinned-key identity (tagged proof, pinned_keys store)", func() error {
		return pinned(p.PinnedKey.Identity, p.AID)
	})
	tct := func(token, audience string) (*verify.TCT, error) {
		a, err := aid.Parse(p.AID)
		if err != nil {
			return nil, err
		}
		return verify.VerifyTCT(token, verify.TCTOptions{
			Now:              now,
			ExpectedAudience: audience,
			IssuerKey:        a.Key().Raw(),
			Revocation:       verify.StaticSnapshot(p.Snapshot),
			RevocationPolicy: verify.RevocationPolicy{Mode: verify.FailClosed, MaxStalenessSecs: 86400},
		})
	}
	c.ok("p256 TCT (ES256)", func() error {
		t, err := tct(p.TCT, p.ParticipantAID)
		if err != nil {
			return err
		}
		if len(t.Grants) != 1 || t.Grants[0] != "session.participate" {
			return fmt.Errorf("unexpected grants %q", t.Grants)
		}
		return nil
	})
	c.rejects("p256 self-attestation is rejected in a grant context", func() error {
		_, err := tct(p.Attestation, p.AID)
		return err
	})

	c.rejects("p256 envelope -- double-hashed digest is rejected", func() error {
		return envelope(p.EnvelopeDoubleHash, now)
	})
	c.rejects("p256 envelope -- high-S twin is rejected", func() error {
		return withSig(p.Envelope, highSTagged, func(b []byte) error { return envelope(b, now) })
	})
	c.rejects("p256 envelope -- untagged signature under a p256 AID is rejected", func() error {
		return withSig(p.Envelope, untagged, func(b []byte) error { return envelope(b, now) })
	})
	c.rejects("p256 manifest -- high-S twin is rejected", func() error {
		return withSig(p.Manifest, highSTagged, func(b []byte) error { return manifest(b, now) })
	})
	c.rejects("p256 revocation snapshot -- high-S twin is rejected", func() error {
		return withSig(p.Snapshot, highSTagged, func(b []byte) error { return snapshot(b, p.AID, now) })
	})
	c.rejects("p256 TCT -- high-S ES256 twin is rejected", func() error {
		twin, err := highSJWS(p.TCT)
		if err != nil {
			return err
		}
		_, err = tct(twin, p.ParticipantAID)
		return err
	})
	c.rejects("p256 pinned-key -- high-S proof is rejected", func() error {
		return withField(p.PinnedKey.Identity, "proof", highSTagged, func(b []byte) error { return pinned(b, p.AID) })
	})
	c.rejects("p256 pinned-key -- untagged proof is rejected", func() error {
		return withField(p.PinnedKey.Identity, "proof", untagged, func(b []byte) error { return pinned(b, p.AID) })
	})
	c.rejects("p256 pinned-key -- key outside the pinned_keys store is rejected", func() error {
		return pinned(p.PinnedKey.Identity, m.ExpectedIssuer)
	})

	// Session trust bundles are an experimental extension this verifier
	// does not implement; say so rather than pass silently.
	fmt.Fprintln(out, "\n  skip  session trust bundles (experimental-session-bundle is not implemented)")

	if c.failed > 0 {
		fmt.Fprintf(out, "\n%d cross-implementation check(s) FAILED: aitp-rs and aitp-verifier-go disagree on the wire.\n", c.failed)
		return 1
	}
	fmt.Fprintln(out, "\nCross-implementation acceptance PASSED (no re-signing).")
	return 0
}

// snapshot verifies a snapshot from issuer and checks that every entry
// reads back as revoked under a fail_closed policy.
func snapshot(data json.RawMessage, issuer string, now int64) error {
	s, err := verify.VerifySnapshot(data, verify.SnapshotOptions{Now: now, ExpectedIssuer: issuer, MaxStalenessSecs: 86400})
	if err != nil {
		return err
	}
	if s.Issuer != issuer {
		return fmt.Errorf("snapshot issuer %s, want %s", s.Issuer, issuer)
	}
	var doc struct {
		RevocationList struct {
			Entries []struct {
				JTI string `json:"jti"`
			} `json:"entries"`
		} `json:"revocation_list"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if len(doc.RevocationList.Entries) == 0 {
		return errors.New("snapshot has no entries to read back")
	}
	policy := verify.RevocationPolicy{Mode: verify.FailClosed, MaxStalenessSecs: 86400}
	for _, e := range doc.RevocationList.Entries {
		st := verify.CheckRevocation(verify.StaticSnapshot(data), policy, issuer, e.JTI, now)
		if !st.Revoked || st.Absent {
			return fmt.Errorf("%s does not read back as revoked: %+v", e.JTI, st)
		}
	}
	return nil
}

func manifest(data []byte, now int64) error {
	_, err := verify.VerifyManifest(data, verify.ManifestOptions{Now: now})
	return err
}

func envelope(data []byte, now int64) error {
	_, err := verify.VerifyEnvelope(data, verify.EnvelopeOptions{Now: now})
	return err
}

func oidc(vec oidcVector, proof string, ks []*keys.PublicKey, now int64) error {
	desc, err := json.Marshal(map[string]string{"type": "oidc", "issuer": vec.Issuer, "subject": vec.Subject, "proof": proof})
	if err != nil {
		return err
	}
	hint := &verify.IdentityHint{Type: "oidc", Issuer: vec.Issuer, Subject: vec.Subject}
	m := verify.BoundMessage{Sender: vec.Envelope.Sender.AgentID, PopNonce: vec.Envelope.Payload.PopNonce}
	_, err = verify.VerifyIdentity(desc, hint, m, verify.IdentityOptions{
		Now:          now,
		SelfAID:      vec.SelfAID,
		TrustAnchors: []string{vec.Issuer},
		IssuerKeys:   func(string) []*keys.PublicKey { return ks },
	})
	return err
}

// jwkKey turns an OKP/Ed25519 or EC/P-256 public JWK into a key.
func jwkKey(kty, crv, x, y string) (*keys.PublicKey, error) {
	switch {
	case kty == "OKP" && crv == "Ed25519":
		raw, err := b64.DecodeLen(x, 32)
		if err != nil {
			return nil, err
		}
		return keys.Parse(keys.Ed25519, raw)
	case kty == "EC" && crv == "P-256":
		xb, err := b64.DecodeLen(x, 32)
		if err != nil {
			return nil, err
		}
		yb, err := b64.DecodeLen(y, 32)
		if err != nil {
			return nil, err
		}
		// SEC1 compressed form: 0x02 for an even y, 0x03 for odd.
		return keys.Parse(keys.P256, append([]byte{0x02 | yb[31]&1}, xb...))
	}
	return nil, fmt.Errorf("unsupported JWK %s/%s", kty, crv)
}

// swapAlg rewrites a JWS header's alg to the other algorithm, keeping the
// payload and signature.
func swapAlg(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return token
	}
	raw, err := b64.Decode(parts[0])
	if err != nil {
		return token
	}
	var h map[string]any
	if json.Unmarshal(raw, &h) != nil {
		return token
	}
	if h["alg"] == "EdDSA" {
		h["alg"] = "ES256"
	} else {
		h["alg"] = "EdDSA"
	}
	enc, _ := json.Marshal(h)
	return b64.Encode(enc) + "." + parts[1] + "." + parts[2]
}

// highS returns the (r, n - s) twin of a raw 64-byte P-256 signature,
// which raw ECDSA accepts and RFC-AITP-0001 §5.4.7 does not.
func highS(sig []byte) ([]byte, error) {
	if len(sig) != 64 {
		return nil, fmt.Errorf("not a raw P-256 signature (%d bytes)", len(sig))
	}
	s := new(big.Int).SetBytes(sig[32:])
	twin := make([]byte, 64)
	copy(twin, sig[:32])
	new(big.Int).Sub(p256N, s).FillBytes(twin[32:])
	return twin, nil
}

func p256Raw(field string) ([]byte, error) {
	rest, ok := strings.CutPrefix(field, "p256.")
	if !ok {
		return nil, fmt.Errorf("expected a p256-tagged signature, got %.12s", field)
	}
	return b64.DecodeLen(rest, 64)
}

func highSTagged(field string) (string, error) {
	raw, err := p256Raw(field)
	if err != nil {
		return "", err
	}
	twin, err := highS(raw)
	if err != nil {
		return "", err
	}
	return "p256." + b64.Encode(twin), nil
}

func untagged(field string) (string, error) {
	raw, err := p256Raw(field)
	if err != nil {
		return "", err
	}
	return b64.Encode(raw), nil
}

func highSJWS(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("not a compact JWS")
	}
	sig, err := b64.DecodeLen(parts[2], 64)
	if err != nil {
		return "", err
	}
	twin, err := highS(sig)
	if err != nil {
		return "", err
	}
	return parts[0] + "." + parts[1] + "." + b64.Encode(twin), nil
}

// withSig runs fn on data with its top-level "signature" rewritten.
func withSig(data []byte, rewrite func(string) (string, error), fn func([]byte) error) error {
	return withField(data, "signature", rewrite, fn)
}

// withField runs fn on the JSON object data with one top-level string
// member rewritten. Only that member's value changes: every other byte is
// kept, so the rest of the signing input is what aitp-rs signed.
func withField(data []byte, name string, rewrite func(string) (string, error), fn func([]byte) error) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	var old string
	if err := json.Unmarshal(obj[name], &old); err != nil {
		return fmt.Errorf("%s is not a string: %w", name, err)
	}
	repl, err := rewrite(old)
	if err != nil {
		return err
	}
	oldEnc, _ := json.Marshal(old)
	newEnc, _ := json.Marshal(repl)
	if bytes.Count(data, oldEnc) != 1 {
		return fmt.Errorf("%s value is not unique in the artifact", name)
	}
	return fn(bytes.Replace(data, oldEnc, newEnc, 1))
}
