// Package aitpverifier is a Go verifier for the Agent Identity & Trust
// Protocol (AITP), written from the RFCs, schemas and conformance fixtures
// alone and depending only on the standard library.
//
// The root package carries the registry's error codes and the module
// version. The verifiers are in package verify; the conformance adapter is
// cmd/aitp-verifier-adapter.
package aitpverifier

//go:generate go run ./internal/gen/errorcodes
