// Command aitp-verifier-adapter is the conformance adapter for this
// verifier: an NDJSON request/response loop on stdin and stdout, as
// schemas/conformance/ADAPTER.md in the spec describes, that maps each
// fixture operation onto package verify.
//
// It never touches the network or the wall clock. Its revocation source
// fetches through a transport that refuses every request, and its clock is
// the one the runner sets with set_clock.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
	"github.com/agentidentitytrustprotocol/aitp-verifier-go/verify"
)

const (
	implementation = "aitp-verifier-go"
	repository     = "https://github.com/agentidentitytrustprotocol/aitp-verifier-go"
	// codeOpNotSupported is the adapter-protocol refusal code. It is not
	// a registry code.
	codeOpNotSupported = "OP_NOT_SUPPORTED"
	maxLine            = 16 << 20
)

type request struct {
	ID     string          `json:"id"`
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params"`
}

type response struct {
	ID        string `json:"id"`
	OK        bool   `json:"ok"`
	Result    any    `json:"result,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
}

func main() {
	if err := serve(os.Stdin, os.Stdout, newAdapter()); err != nil {
		fmt.Fprintln(os.Stderr, "aitp-verifier-adapter:", err)
		os.Exit(1)
	}
}

// serve runs the request loop until shutdown or end of input.
func serve(in io.Reader, out io.Writer, a *adapter) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		var resp response
		if err := json.Unmarshal(line, &req); err != nil {
			resp = response{ID: req.ID, ErrorCode: string(aitpverifier.CodeInvalidEnvelope), Message: "request is not JSON: " + err.Error()}
		} else {
			resp = a.handle(req)
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if req.Op == "shutdown" {
			return nil
		}
	}
	return sc.Err()
}

// opFunc answers one operation: a result object or an error.
type opFunc func(a *adapter, p params) (map[string]any, error)

// errNotSupported refuses one input of a declared op.
var errNotSupported = errors.New("not supported")

func (a *adapter) handle(req request) response {
	fn, ok := ops[req.Op]
	if !ok {
		return response{ID: req.ID, ErrorCode: codeOpNotSupported, Message: "unknown op " + req.Op}
	}
	p, err := parseParams(req.Params)
	if err != nil {
		return response{ID: req.ID, ErrorCode: string(aitpverifier.CodeInvalidEnvelope), Message: err.Error()}
	}
	result, err := fn(a, p)
	if err != nil {
		var re *refusal
		switch {
		case errors.As(err, &re):
			return response{ID: req.ID, ErrorCode: string(re.code), Message: re.msg}
		case errors.Is(err, errNotSupported):
			return response{ID: req.ID, ErrorCode: codeOpNotSupported, Message: err.Error()}
		}
		code := verify.CodeOf(err)
		if code == "" {
			return response{ID: req.ID, ErrorCode: codeOpNotSupported, Message: "adapter: " + err.Error()}
		}
		return response{ID: req.ID, ErrorCode: string(code), Message: err.Error()}
	}
	if result == nil {
		result = map[string]any{}
	}
	return response{ID: req.ID, OK: true, Result: result}
}

// refusal is an adapter-level rejection with a registry code.
type refusal struct {
	code aitpverifier.ErrorCode
	msg  string
}

func (r *refusal) Error() string { return string(r.code) + ": " + r.msg }

func refuse(code aitpverifier.ErrorCode, format string, args ...any) error {
	return &refusal{code: code, msg: fmt.Sprintf(format, args...)}
}

// commit is the VCS revision the binary was built from.
func commit() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return s.Value
			}
		}
	}
	return "unknown"
}
