package main

import (
	"bytes"
	"encoding/json"
	"errors"
)

// params is a request's params object, member by member. Members stay raw
// so that artifacts reach the verifiers as the bytes the runner sent.
type params map[string]json.RawMessage

func parseParams(raw json.RawMessage) (params, error) {
	p := params{}
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return p, nil
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errors.New("params is not a JSON object")
	}
	return p, nil
}

func (p params) has(key string) bool {
	v, ok := p[key]
	return ok && string(v) != "null"
}

// raw returns a member's bytes, or nil when it is absent.
func (p params) raw(key string) []byte {
	if !p.has(key) {
		return nil
	}
	return p[key]
}

func (p params) str(key string) string {
	var s string
	if v := p.raw(key); v != nil {
		_ = json.Unmarshal(v, &s)
	}
	return s
}

func (p params) int(key string) (int64, bool) {
	var n int64
	v := p.raw(key)
	if v == nil || json.Unmarshal(v, &n) != nil {
		return 0, false
	}
	return n, true
}

func (p params) bool(key string) bool {
	var b bool
	if v := p.raw(key); v != nil {
		_ = json.Unmarshal(v, &b)
	}
	return b
}

// strings returns a string-array member; nil when absent, non-nil (maybe
// empty) when present.
func (p params) strings(key string) []string {
	v := p.raw(key)
	if v == nil {
		return nil
	}
	out := []string{}
	_ = json.Unmarshal(v, &out)
	return out
}

func (p params) object(key string) params {
	v := p.raw(key)
	if v == nil {
		return nil
	}
	o, err := parseParams(v)
	if err != nil {
		return nil
	}
	return o
}

func (p params) objects(key string) []params {
	v := p.raw(key)
	if v == nil {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(v, &list) != nil {
		return nil
	}
	out := make([]params, 0, len(list))
	for _, item := range list {
		if o, err := parseParams(item); err == nil {
			out = append(out, o)
		}
	}
	return out
}

func (p params) rawList(key string) [][]byte {
	v := p.raw(key)
	if v == nil {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(v, &list) != nil {
		return nil
	}
	out := make([][]byte, len(list))
	for i, item := range list {
		out[i] = item
	}
	return out
}
