// Package aitpverifier is a Go verifier for the Agent Identity & Trust
// Protocol (AITP), written from the RFCs, schemas and conformance fixtures
// alone and depending only on the standard library.
//
// This release carries the primitives (strict JSON, JCS, base64url, JWS,
// JWK thumbprints, AIDs and the RFC-AITP-0001 §5.4.7 signature checks)
// under internal/ and the registry's error codes; the verifiers follow.
package aitpverifier

//go:generate go run ./internal/gen/errorcodes
