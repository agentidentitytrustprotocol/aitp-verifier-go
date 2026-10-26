package verify

import (
	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/b64"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jcs"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/sigfield"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
)

// Identity types (RFC-AITP-0002).
const (
	IdentityOIDC      = "oidc"
	IdentityPinnedKey = "pinned_key"
	IdentitySPIFFE    = "spiffe"
)

var identityTypes = []string{IdentityOIDC, IdentityPinnedKey, IdentitySPIFFE}

// DefaultAcceptedIdentityTypes applies when a peer states no
// accepted_identity_types (RFC-AITP-0003 §3.2).
var DefaultAcceptedIdentityTypes = []string{IdentityOIDC}

// IdentityHint is a Manifest's identity_hint (RFC-AITP-0003 §3.1).
type IdentityHint struct {
	Type, Issuer, Subject, PublicKey string
}

// Manifest is a verified Agent Manifest (RFC-AITP-0003).
type Manifest struct {
	AID                      string
	IdentityHint             IdentityHint
	HandshakeEndpoint        string
	AcceptedTrustAnchors     []string
	OfferedCapabilities      []string
	RequiredPeerCapabilities []string
	AcceptedIdentityTypes    []string
	PublishedAt, ExpiresAt   int64
	aid                      *aid.AID
}

// ManifestOptions configures [VerifyManifest].
type ManifestOptions struct {
	// Now is the verifier's current time in Unix seconds.
	Now int64
	// SupportedVersions lists the Manifest versions the verifier
	// implements; nil means {Version}. A version outside it, or other than
	// Version, is MANIFEST_VERSION_UNKNOWN.
	SupportedVersions []string
	// AcceptedIdentityTypes and TrustAnchors, when non-nil, run the
	// RFC-AITP-0003 §5 step 6 compatibility check against the verifier's
	// own policy.
	AcceptedIdentityTypes []string
	TrustAnchors          []string
}

// VerifyManifest runs RFC-AITP-0003 §5: version, schema, member set,
// expiry, proof-of-possession, signature and, when configured,
// compatibility.
func VerifyManifest(data []byte, opts ManifestOptions) (*Manifest, error) {
	v, err := strictjson.Parse(data)
	if err != nil {
		return nil, fail(aitpverifier.CodeManifestInvalid, "Manifest is not strict JSON: %v", err)
	}
	return verifyManifest(v, opts)
}

func verifyManifest(v *strictjson.Value, opts ManifestOptions) (*Manifest, error) {
	f, ok := asObject(v)
	if !ok {
		return nil, fail(aitpverifier.CodeManifestInvalid, "Manifest is not a JSON object")
	}
	supported := opts.SupportedVersions
	if supported == nil {
		supported = []string{Version}
	}
	if ver, ok := f.str("version"); !ok || ver != Version || !contains(supported, ver) {
		return nil, fail(aitpverifier.CodeManifestVersionUnknown, "Manifest version is not one this verifier implements")
	}
	m, err := manifestSchema(f)
	if err != nil {
		return nil, err
	}
	if m.ExpiresAt <= opts.Now {
		return nil, fail(aitpverifier.CodeManifestExpired, "Manifest expired at %d (now %d)", m.ExpiresAt, opts.Now)
	}
	pop, _ := f.object("proof_of_possession")
	challenge, _ := pop.str("challenge")
	popSig, _ := pop.str("signature")
	raw, err := b64.DecodeLen(challenge, 16)
	if err != nil {
		return nil, fail(aitpverifier.CodeManifestInvalid, "proof_of_possession.challenge: %v", err)
	}
	if err := sigfield.Verify(popSig, m.aid.Key(), raw); err != nil {
		return nil, fail(aitpverifier.CodeManifestPopFailed, "proof_of_possession: %v", err)
	}
	body, err := jcs.Canonicalize(v.Without("signature"))
	if err != nil {
		return nil, fail(aitpverifier.CodeManifestInvalid, "Manifest cannot be canonicalized: %v", err)
	}
	sig, _ := f.str("signature")
	if err := sigfield.Verify(sig, m.aid.Key(), body); err != nil {
		return nil, fail(aitpverifier.CodeManifestSignatureInvalid, "Manifest signature: %v", err)
	}
	if opts.AcceptedIdentityTypes != nil && !contains(opts.AcceptedIdentityTypes, m.IdentityHint.Type) {
		return nil, fail(aitpverifier.CodeIncompatibleIdentityType, "identity type %s is not accepted", m.IdentityHint.Type)
	}
	if opts.TrustAnchors != nil && m.IdentityHint.Type == IdentityOIDC && !contains(opts.TrustAnchors, m.IdentityHint.Issuer) {
		return nil, fail(aitpverifier.CodeIncompatibleTrustAnchors, "issuer %s is not a trust anchor", m.IdentityHint.Issuer)
	}
	return m, nil
}

// manifestSchema validates aitp-manifest.schema.json's manifest body:
// every structural defect is MANIFEST_INVALID, and a member outside the
// schema (and outside extensions) is UNKNOWN_FIELD once the rest is valid.
func manifestSchema(f fields) (*Manifest, error) {
	bad := func(what string) error {
		return fail(aitpverifier.CodeManifestInvalid, "Manifest %s", what)
	}
	m := &Manifest{}
	var ok bool
	if m.AID, ok = f.match("aid", reAID); !ok {
		return nil, bad("aid is missing or malformed")
	}
	var err error
	if m.aid, err = aid.Parse(m.AID); err != nil {
		return nil, bad("aid does not encode a valid key")
	}
	if s, ok := f.get("display_name"); ok && (s.Kind != strictjson.String || len([]rune(s.Str)) > 128) {
		return nil, bad("display_name is not a string of at most 128 characters")
	}
	hint, ok := f.object("identity_hint")
	if !ok {
		return nil, bad("identity_hint is missing or not an object")
	}
	if m.IdentityHint, err = identityHint(hint); err != nil {
		return nil, err
	}
	if m.HandshakeEndpoint, ok = f.str("handshake_endpoint"); !ok || !isURI(m.HandshakeEndpoint) || len(m.HandshakeEndpoint) < 8 || m.HandshakeEndpoint[:8] != "https://" {
		return nil, bad("handshake_endpoint is missing or not an https URI")
	}
	if m.AcceptedTrustAnchors, ok = f.strings("accepted_trust_anchors", nil, 0); !ok {
		return nil, bad("accepted_trust_anchors is missing or not a unique string array")
	}
	for _, a := range m.AcceptedTrustAnchors {
		if !isURI(a) {
			return nil, bad("accepted_trust_anchors holds a non-URI")
		}
	}
	if m.OfferedCapabilities, ok = f.strings("offered_capabilities", reNoSpace, 0); !ok {
		return nil, bad("offered_capabilities is missing or malformed")
	}
	if f.has("required_peer_capabilities") {
		if m.RequiredPeerCapabilities, ok = f.strings("required_peer_capabilities", reNoSpace, 0); !ok {
			return nil, bad("required_peer_capabilities is malformed")
		}
	}
	if f.has("accepted_identity_types") {
		if m.AcceptedIdentityTypes, ok = f.strings("accepted_identity_types", nil, 0); !ok {
			return nil, bad("accepted_identity_types is malformed")
		}
		for _, t := range m.AcceptedIdentityTypes {
			if !contains(identityTypes, t) {
				return nil, bad("accepted_identity_types holds an unknown type")
			}
		}
	}
	if f.has("accepted_signature_algorithms") {
		algs, ok := f.strings("accepted_signature_algorithms", nil, 0)
		if !ok {
			return nil, bad("accepted_signature_algorithms is malformed")
		}
		for _, a := range algs {
			if a != "ed25519" && a != "p256" {
				return nil, bad("accepted_signature_algorithms holds an unknown algorithm")
			}
		}
	}
	pop, ok := f.object("proof_of_possession")
	if !ok {
		return nil, bad("proof_of_possession is missing or not an object")
	}
	if _, ok := pop.match("challenge", reNonce); !ok {
		return nil, bad("proof_of_possession.challenge is malformed")
	}
	if _, ok := pop.match("signature", reSig); !ok {
		return nil, bad("proof_of_possession.signature is malformed")
	}
	if m.PublishedAt, ok = f.integer("published_at", 0); !ok {
		return nil, bad("published_at is missing or not a non-negative integer")
	}
	if m.ExpiresAt, ok = f.integer("expires_at", 1); !ok {
		return nil, bad("expires_at is missing or not a positive integer")
	}
	if x, ok := f.get("extensions"); ok && x.Kind != strictjson.Object {
		return nil, bad("extensions is not an object")
	}
	if _, ok := f.match("signature", reSig); !ok {
		return nil, bad("signature is missing or malformed")
	}
	if k, ok := pop.unknown("challenge", "signature"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "proof_of_possession member %q is not defined", k)
	}
	if k, ok := hint.unknown("type", "issuer", "subject", "public_key"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "identity_hint member %q is not defined", k)
	}
	if k, ok := f.unknown("version", "aid", "display_name", "identity_hint", "handshake_endpoint",
		"accepted_trust_anchors", "offered_capabilities", "required_peer_capabilities",
		"accepted_identity_types", "accepted_signature_algorithms", "proof_of_possession",
		"published_at", "expires_at", "extensions", "signature"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "Manifest member %q is not defined", k)
	}
	return m, nil
}

func identityHint(h fields) (IdentityHint, error) {
	bad := func(what string) (IdentityHint, error) {
		return IdentityHint{}, fail(aitpverifier.CodeManifestInvalid, "identity_hint %s", what)
	}
	var out IdentityHint
	var ok bool
	if out.Type, ok = h.str("type"); !ok || !contains(identityTypes, out.Type) {
		return bad("type is missing or unknown")
	}
	if out.Subject, ok = h.str("subject"); !ok || out.Subject == "" {
		return bad("subject is missing or empty")
	}
	if h.has("issuer") {
		if out.Issuer, ok = h.str("issuer"); !ok || !isURI(out.Issuer) {
			return bad("issuer is not a URI")
		}
	}
	if h.has("public_key") {
		if out.PublicKey, ok = h.match("public_key", rePublicKey); !ok {
			return bad("public_key is malformed")
		}
	}
	switch out.Type {
	case IdentityOIDC:
		if !h.has("issuer") || h.has("public_key") {
			return bad("of type oidc needs issuer and forbids public_key")
		}
	case IdentityPinnedKey:
		if !h.has("public_key") {
			return bad("of type pinned_key needs public_key")
		}
	case IdentitySPIFFE:
		if h.has("issuer") || h.has("public_key") || len(out.Subject) > 2048 || !reSPIFFE.MatchString(out.Subject) {
			return bad("of type spiffe needs a SPIFFE ID subject and no issuer or public_key")
		}
	}
	return out, nil
}
