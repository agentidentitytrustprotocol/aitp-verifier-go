package verify

import (
	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/aid"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/jcs"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/keys"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/sigfield"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/strictjson"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/internal/timeutil"
)

// Version is the protocol revision this verifier implements.
const Version = "aitp/0.3"

// DefaultTolerance is the envelope timestamp tolerance in seconds
// (RFC-AITP-0001 §5.5).
const DefaultTolerance = 300

// envelopeTag is the RFC-AITP-0001 §5.4 domain tag, NUL included.
const envelopeTag = "aitp-envelope-v2\x00"

// Registered envelope message types (aitp-envelope.schema.json).
var messageTypes = []string{
	"mutual_hello", "mutual_hello_ack", "mutual_commit", "mutual_commit_ack",
	"tct", "pop_challenge", "pop_response", "identity_presentation", "error",
}

// Envelope is a parsed AITP envelope (RFC-AITP-0001 §5).
type Envelope struct {
	MessageType string
	MessageID   string
	Timestamp   int64
	Sender      string
	senderAID   *aid.AID
	raw         *strictjson.Value
	payload     *strictjson.Value
	signature   string
}

// Payload returns the envelope payload as canonical JSON.
func (e *Envelope) Payload() []byte {
	b, _ := jcs.Canonicalize(e.payload)
	return b
}

// EnvelopeOptions configures envelope checks.
type EnvelopeOptions struct {
	// Now is the verifier's current time in Unix seconds.
	Now int64
	// Tolerance is the timestamp tolerance in seconds; 0 means
	// DefaultTolerance.
	Tolerance int64
	// Replay, when set, is the message_id deny list (RFC-AITP-0001 §5.5).
	// A verified envelope's id is added to it.
	Replay *ReplayCache
	// ExtraMessageTypes admits message types outside the registry.
	ExtraMessageTypes []string
}

// ParseEnvelope runs the unauthenticated envelope checks in the
// RFC-AITP-0009 §3.1 endpoint order: replay and timestamp, then the
// RFC-AITP-0001 §5.4 version and member-set checks. It does not verify the
// signature; see [Envelope.VerifySignature] and [VerifyEnvelope].
func ParseEnvelope(data []byte, opts EnvelopeOptions) (*Envelope, error) {
	v, err := strictjson.Parse(data)
	if err != nil {
		return nil, fail(aitpverifier.CodeInvalidEnvelope, "envelope is not strict JSON: %v", err)
	}
	return parseEnvelope(v, opts)
}

func parseEnvelope(v *strictjson.Value, opts EnvelopeOptions) (*Envelope, error) {
	f, ok := asObject(v)
	if !ok {
		return nil, fail(aitpverifier.CodeInvalidEnvelope, "envelope is not a JSON object")
	}
	tol := opts.Tolerance
	if tol == 0 {
		tol = DefaultTolerance
	}
	// RFC-AITP-0009 §3.1: replay, then timestamp, before the structure.
	if id, ok := f.str("message_id"); ok && opts.Replay != nil && opts.Replay.Seen(id, opts.Now) {
		return nil, fail(aitpverifier.CodeReplayDetected, "message_id %s already seen", id)
	}
	if ts, ok := f.integer("timestamp", 0); ok && !timeutil.Within(opts.Now, ts, tol) {
		return nil, fail(aitpverifier.CodeTimestampExpired, "timestamp %d outside ±%d s of %d", ts, tol, opts.Now)
	}
	// RFC-AITP-0001 §5.4 check order, steps 1 and 2.
	if ver, ok := f.str("version"); !ok || ver != Version {
		return nil, fail(aitpverifier.CodeUnknownVersion, "envelope version is not %s", Version)
	}
	e := &Envelope{raw: v}
	bad := func(what string) error {
		return fail(aitpverifier.CodeInvalidEnvelope, "envelope %s", what)
	}
	if e.MessageType, ok = f.str("message_type"); !ok {
		return nil, bad("message_type missing or not a string")
	}
	if !contains(messageTypes, e.MessageType) && !contains(opts.ExtraMessageTypes, e.MessageType) {
		return nil, bad("message_type " + e.MessageType + " is not registered")
	}
	if e.MessageID, ok = f.match("message_id", reUUIDv4); !ok {
		return nil, bad("message_id is not a lowercase UUIDv4")
	}
	if e.Timestamp, ok = f.integer("timestamp", 0); !ok {
		return nil, bad("timestamp is not a non-negative integer")
	}
	sender, ok := f.object("sender")
	if !ok {
		return nil, bad("sender missing or not an object")
	}
	if e.Sender, ok = sender.match("agent_id", reAID); !ok {
		return nil, bad("sender.agent_id is not an AID")
	}
	if e.payload, ok = f.get("payload"); !ok || e.payload.Kind != strictjson.Object {
		return nil, bad("payload missing or not an object")
	}
	if e.signature, ok = f.match("signature", reSig); !ok {
		return nil, bad("signature missing or malformed")
	}
	if x, ok := f.get("extensions"); ok && x.Kind != strictjson.Object {
		return nil, bad("extensions is not an object")
	}
	if k, ok := sender.unknown("agent_id"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "sender member %q is not defined", k)
	}
	if k, ok := f.unknown("version", "message_type", "message_id", "timestamp", "sender", "payload", "signature", "extensions"); ok {
		return nil, fail(aitpverifier.CodeUnknownField, "envelope member %q is not defined", k)
	}
	var err error
	if e.senderAID, err = aid.Parse(e.Sender); err != nil {
		return nil, bad("sender.agent_id does not encode a valid key")
	}
	return e, nil
}

// SenderKey returns the public key that the sender AID encodes.
func (e *Envelope) senderKey() *keys.PublicKey { return e.senderAID.Key() }

// VerifySignature checks the envelope signature (RFC-AITP-0001 §5.4) under
// the sender AID's key. Failure is INVALID_SIGNATURE.
func (e *Envelope) VerifySignature() error { return e.verifySignature(e.senderKey()) }

func (e *Envelope) verifySignature(k *keys.PublicKey) error {
	body, err := jcs.Canonicalize(e.raw.Without("signature"))
	if err != nil {
		return fail(aitpverifier.CodeInvalidEnvelope, "envelope cannot be canonicalized: %v", err)
	}
	input := append([]byte(envelopeTag), body...)
	if err := sigfield.Verify(e.signature, k, input); err != nil {
		return fail(aitpverifier.CodeInvalidSignature, "envelope signature: %v", err)
	}
	return nil
}

// VerifyEnvelope runs every envelope check in order and, on success,
// records the message_id in opts.Replay.
func VerifyEnvelope(data []byte, opts EnvelopeOptions) (*Envelope, error) {
	e, err := ParseEnvelope(data, opts)
	if err != nil {
		return nil, err
	}
	if err := e.VerifySignature(); err != nil {
		return nil, err
	}
	opts.Replay.Add(e.MessageID, opts.Now)
	return e, nil
}
