package verify

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jcs"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/sigfield"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// RevocationMode is revocation_policy.mode (RFC-AITP-0008 §3.1).
type RevocationMode string

// The revocation modes. The zero value means FailClosed, the schema
// default.
const (
	FailClosed RevocationMode = "fail_closed"
	FailOpen   RevocationMode = "fail_open"
	SoftFail   RevocationMode = "soft_fail"
)

// DefaultMaxStaleness is the RFC-AITP-0008 §3 example max_staleness_secs.
const DefaultMaxStaleness = 300

// RevocationPolicy is a verifier's revocation_policy (RFC-AITP-0008 §3).
type RevocationPolicy struct {
	Mode             RevocationMode
	MaxStalenessSecs int64
}

func (p RevocationPolicy) mode() RevocationMode {
	if p.Mode == "" {
		return FailClosed
	}
	return p.Mode
}

func (p RevocationPolicy) maxStaleness() int64 {
	if p.MaxStalenessSecs <= 0 {
		return DefaultMaxStaleness
	}
	return p.MaxStalenessSecs
}

// ErrRevocationUnavailable is what a RevocationSource returns when it has
// no snapshot for the issuer at all.
var ErrRevocationUnavailable = errors.New("verify: no revocation source for the issuer")

// ErrSnapshotDiscarded wraps the reasons RFC-AITP-0008 §1.5 discards a
// well-formed, correctly signed snapshot: expired, stale, or signed by an
// issuer other than the one whose token is checked. A discarded snapshot is
// absent.
var ErrSnapshotDiscarded = errors.New("verify: revocation snapshot discarded")

// RevocationSource returns an issuer's signed revocation snapshot (the
// {"revocation_list": …, "signature": …} wire form). It is called only
// after a token's signature and claims have verified (RFC-AITP-0008 §3.3).
type RevocationSource interface {
	Snapshot(issuer string) ([]byte, error)
}

// StaticSnapshot is a RevocationSource that returns one snapshot it holds.
type StaticSnapshot []byte

// Snapshot returns s.
func (s StaticSnapshot) Snapshot(string) ([]byte, error) { return s, nil }

// Unavailable is a RevocationSource with no snapshot for any issuer.
type Unavailable struct{}

// Snapshot returns ErrRevocationUnavailable.
func (Unavailable) Snapshot(string) ([]byte, error) { return nil, ErrRevocationUnavailable }

// HTTPRevocationSource fetches ListRevoked snapshots (RFC-AITP-0008 §1.4)
// through an injected transport. The verifier never dials on its own.
type HTTPRevocationSource struct {
	// Transport performs every request. It is required.
	Transport http.RoundTripper
	// URL maps an issuer AID to its revocation-list URL, typically from
	// the issuer Manifest's rfc-aitp-0008.revocation_list_uri extension.
	URL func(issuer string) (string, error)
	// MaxBytes bounds the response body; 0 means 1 MiB.
	MaxBytes int64
}

// Snapshot fetches the issuer's snapshot. Any failure is reported as
// ErrRevocationUnavailable, which the policy then decides.
func (h HTTPRevocationSource) Snapshot(issuer string) ([]byte, error) {
	if h.Transport == nil || h.URL == nil {
		return nil, fmt.Errorf("%w: no transport configured", ErrRevocationUnavailable)
	}
	u, err := h.URL(issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRevocationUnavailable, err)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRevocationUnavailable, err)
	}
	resp, err := h.Transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRevocationUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrRevocationUnavailable, resp.StatusCode)
	}
	limit := h.MaxBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: unreadable or oversized body", ErrRevocationUnavailable)
	}
	return body, nil
}

// Snapshot is a verified revocation snapshot.
type Snapshot struct {
	Issuer                 string
	PublishedAt, ExpiresAt int64
	revoked                map[string]bool
}

// Revoked reports whether jti is listed.
func (s *Snapshot) Revoked(jti string) bool { return s.revoked[jti] }

// SnapshotOptions configures [VerifySnapshot].
type SnapshotOptions struct {
	// Now is the verifier's current time in Unix seconds.
	Now int64
	// ExpectedIssuer is the AID of the issuing peer whose tokens the
	// snapshot is to speak for; its key verifies the signature.
	ExpectedIssuer string
	// MaxStalenessSecs bounds now - published_at; 0 means
	// DefaultMaxStaleness. Negative disables the bound (for a peer's own,
	// local deny list).
	MaxStalenessSecs int64
}

// VerifySnapshot runs the RFC-AITP-0008 §1.5 checks: structure
// (REVOCATION_SNAPSHOT_INVALID), member set (UNKNOWN_FIELD), issuer, then
// signature (REVOCATION_SNAPSHOT_SIGNATURE_INVALID), expiry and staleness.
// A wrong issuer, expiry or staleness returns an error wrapping
// ErrSnapshotDiscarded.
func VerifySnapshot(data []byte, opts SnapshotOptions) (*Snapshot, error) {
	v, err := strictjson.Parse(data)
	if err != nil {
		return nil, fail(aitpverifier.CodeRevocationSnapshotInvalid, "snapshot is not strict JSON: %v", err)
	}
	return verifySnapshot(v, opts)
}

func verifySnapshot(v *strictjson.Value, opts SnapshotOptions) (*Snapshot, error) {
	bad := func(what string) error {
		return fail(aitpverifier.CodeRevocationSnapshotInvalid, "snapshot %s", what)
	}
	w, ok := asObject(v)
	if !ok {
		return nil, bad("is not a JSON object")
	}
	bodyV, ok := w.get("revocation_list")
	if !ok {
		return nil, bad("has no revocation_list")
	}
	body, ok := asObject(bodyV)
	if !ok {
		return nil, bad("revocation_list is not an object")
	}
	sig, ok := w.match("signature", reSig)
	if !ok {
		return nil, bad("signature is missing or malformed")
	}
	if ver, ok := body.str("version"); !ok || ver != Version {
		return nil, bad("version is not " + Version)
	}
	s := &Snapshot{revoked: map[string]bool{}}
	if s.Issuer, ok = body.match("issuer", reAID); !ok {
		return nil, bad("issuer is not an AID")
	}
	if s.PublishedAt, ok = body.integer("published_at", 0); !ok {
		return nil, bad("published_at is missing or not a non-negative integer")
	}
	if s.ExpiresAt, ok = body.integer("expires_at", 1); !ok {
		return nil, bad("expires_at is missing or not a positive integer")
	}
	entries, ok := body.get("entries")
	if !ok || entries.Kind != strictjson.Array {
		return nil, bad("entries is missing or not an array")
	}
	for _, e := range entries.Arr {
		ef, ok := asObject(e)
		if !ok {
			return nil, bad("entry is not an object")
		}
		jti, ok := ef.match("jti", reUUIDv4)
		if !ok {
			return nil, bad("entry jti is not a UUIDv4")
		}
		if _, ok := ef.integer("revoked_at", 0); !ok {
			return nil, bad("entry revoked_at is not a non-negative integer")
		}
		if r, ok := ef.get("reason"); ok && r.Kind != strictjson.String {
			return nil, bad("entry reason is not a string")
		}
		s.revoked[jti] = true
	}
	if x, ok := body.get("extensions"); ok && x.Kind != strictjson.Object {
		return nil, bad("extensions is not an object")
	}
	for _, e := range entries.Arr {
		if k, ok := (fields{e}).unknown("jti", "revoked_at", "reason"); ok {
			return nil, fail(aitpverifier.CodeUnknownField, "snapshot entry member %q is not defined", k)
		}
	}
	if k, ok := w.unknown("revocation_list", "signature"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "snapshot wrapper member %q is not defined", k)
	}
	if k, ok := body.unknown("version", "issuer", "published_at", "expires_at", "entries", "extensions"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "revocation_list member %q is not defined", k)
	}
	signer := s.Issuer
	if opts.ExpectedIssuer != "" {
		if s.Issuer != opts.ExpectedIssuer {
			return nil, fmt.Errorf("%w: signed issuer %s is not %s", ErrSnapshotDiscarded, s.Issuer, opts.ExpectedIssuer)
		}
		signer = opts.ExpectedIssuer
	}
	a, err := aid.Parse(signer)
	if err != nil {
		return nil, bad("issuer does not encode a valid key")
	}
	canon, err := jcs.Canonicalize(bodyV)
	if err != nil {
		return nil, bad("cannot be canonicalized")
	}
	if err := sigfield.Verify(sig, a.Key(), canon); err != nil {
		return nil, fail(aitpverifier.CodeRevocationSnapshotSignatureInvalid, "snapshot signature: %v", err)
	}
	if s.ExpiresAt <= opts.Now {
		return nil, fmt.Errorf("%w: expired at %d", ErrSnapshotDiscarded, s.ExpiresAt)
	}
	maxAge := opts.MaxStalenessSecs
	if maxAge == 0 {
		maxAge = DefaultMaxStaleness
	}
	if maxAge > 0 && opts.Now-s.PublishedAt > maxAge {
		return nil, fmt.Errorf("%w: %d s old, policy maximum %d s", ErrSnapshotDiscarded, opts.Now-s.PublishedAt, maxAge)
	}
	return s, nil
}

// RevocationStatus is the outcome of a token revocation check.
type RevocationStatus struct {
	// Revoked is true when the jti is listed, or when the snapshot is
	// absent and the mode is fail_closed.
	Revoked bool
	// Absent is true when no usable snapshot was available.
	Absent bool
	// Degraded is true when the snapshot was absent under soft_fail.
	Degraded bool
}

// CheckRevocation looks jti up in issuer's snapshot from src and applies
// policy to an absent or discarded snapshot (RFC-AITP-0008 §1.5, §3.1).
func CheckRevocation(src RevocationSource, policy RevocationPolicy, issuer, jti string, now int64) RevocationStatus {
	data, err := src.Snapshot(issuer)
	var snap *Snapshot
	if err == nil {
		snap, err = VerifySnapshot(data, SnapshotOptions{Now: now, ExpectedIssuer: issuer, MaxStalenessSecs: policy.maxStaleness()})
	}
	if err != nil {
		return absentStatus(policy)
	}
	return RevocationStatus{Revoked: snap.Revoked(jti)}
}

func absentStatus(policy RevocationPolicy) RevocationStatus {
	switch policy.mode() {
	case FailOpen:
		return RevocationStatus{Absent: true}
	case SoftFail:
		return RevocationStatus{Absent: true, Degraded: true}
	default:
		return RevocationStatus{Absent: true, Revoked: true}
	}
}

// ApplySnapshotPolicy is the verify_revocation_snapshot decision: it
// verifies a snapshot and, when the queried jti is non-empty, looks it up.
// A structural, member-set or signature failure is reported with its own
// code; a discarded snapshot is absent and the policy decides, with
// TCT_REVOKED under fail_closed.
func ApplySnapshotPolicy(data []byte, policy RevocationPolicy, opts SnapshotOptions, jti string) (RevocationStatus, error) {
	opts.MaxStalenessSecs = policy.maxStaleness()
	snap, err := VerifySnapshot(data, opts)
	if err != nil {
		if !errors.Is(err, ErrSnapshotDiscarded) {
			return RevocationStatus{}, err
		}
		st := absentStatus(policy)
		if st.Revoked {
			return st, fail(aitpverifier.CodeTctRevoked, "revocation status unknown under fail_closed: %v", err)
		}
		return st, nil
	}
	if jti != "" && snap.Revoked(jti) {
		return RevocationStatus{Revoked: true}, fail(aitpverifier.CodeTctRevoked, "jti %s is revoked", jti)
	}
	return RevocationStatus{}, nil
}
