package verify

import aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"

// ReplayCache is an in-memory message_id deny list (RFC-AITP-0001 §5.5).
// An id stays in it for Window seconds after it was recorded. The zero
// value is not usable; call [NewReplayCache]. A nil *ReplayCache records
// nothing and reports nothing as seen.
type ReplayCache struct {
	Window int64
	seen   map[string]int64
}

// NewReplayCache returns an empty cache. window ≤ 0 means
// DefaultTolerance, the minimum RFC-AITP-0001 §5.5 allows.
func NewReplayCache(window int64) *ReplayCache {
	if window <= 0 {
		window = DefaultTolerance
	}
	return &ReplayCache{Window: window, seen: map[string]int64{}}
}

// Seen reports whether id was recorded within the window before now.
func (c *ReplayCache) Seen(id string, now int64) bool {
	if c == nil {
		return false
	}
	at, ok := c.seen[id]
	return ok && now-at <= c.Window
}

// Add records id at time now.
func (c *ReplayCache) Add(id string, now int64) {
	if c == nil {
		return
	}
	c.seen[id] = now
}

// Check records id and fails with REPLAY_DETECTED when it was already seen.
func (c *ReplayCache) Check(id string, now int64) error {
	if c.Seen(id, now) {
		return fail(aitpverifier.CodeReplayDetected, "message_id %s already seen", id)
	}
	c.Add(id, now)
	return nil
}
