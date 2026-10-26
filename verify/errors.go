// Package verify holds the AITP verifiers: envelope, Manifest, identity
// binding, mutual handshake, TCT (consumer and issuer side), downstream
// proof-of-possession, revocation snapshot, grant voucher, delegation token
// and replay control.
//
// Every verifier is a pure function of its inputs. None reads the wall
// clock: the caller passes the current time. None opens a network
// connection on its own: the only network-adjacent hook is a
// [RevocationSource], and [HTTPRevocationSource] uses the
// [net/http.RoundTripper] the caller injects.
//
// A failure is an [*Error] carrying the registry code
// ([aitpverifier.ErrorCode]) that RFC text or the conformance fixtures pin
// for it; [CodeOf] extracts it.
package verify

import (
	"errors"
	"fmt"

	aitpverifier "github.com/agentidentitytrustprotocol/aitp-verifier-go"
)

// Error is a verification failure with its AITP registry code.
type Error struct {
	Code   aitpverifier.ErrorCode
	Reason string
}

func (e *Error) Error() string {
	if e.Reason == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Reason
}

// CodeOf returns the registry code of err, or "" when err is not an *Error.
func CodeOf(err error) aitpverifier.ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func fail(code aitpverifier.ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// recode rewrites the code of a verification error, keeping its reason.
func recode(err error, code aitpverifier.ErrorCode) *Error {
	var e *Error
	if errors.As(err, &e) {
		return &Error{Code: code, Reason: e.Reason}
	}
	return &Error{Code: code, Reason: err.Error()}
}
