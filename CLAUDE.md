# CLAUDE.md: aitp-verifier-go

Guidance for agent sessions working in this repository.

## Independence rule (load-bearing)

This verifier is written from the AITP RFCs, JSON Schemas, registries and
conformance fixtures **only**. Do not open, read, search or paste source code
from `aitp-rs`, `aitp-verifier-ts` or `aitp-verifier-py`. Their READMEs and
published conformance reports are fine; their code is not. The README's
Independence section states this as a provenance claim, and breaking it
makes the claim false.

When the spec is ambiguous, cite the RFC section (`RFC-AITP-NNNN §x.y`) and
open a `spec-bug` issue on the spec repository rather than copying what
another implementation does.

## Hard constraints

- **Zero dependencies.** `go list -m all` prints only this module. JCS, the
  strict JSON tokenizer, JWS, base64url and the curve checks are written
  here on top of the standard library.
- **Go 1.26 floor** (`go.mod`), CI on 1.26 and 1.27.
- **No network, no wall clock** in verifiers. Time comes from the caller.
- Module path `github.com/agentidentitytrustprotocol/aitp-verifier-go`; the
  library is the root package `aitpverifier`, binaries live under `cmd/`.

## Spec pin

`SPEC_VERSION` holds the spec commit this code is tested against. Test data
(known-answer vectors, fixtures, schemas, the error-code registry) is
vendored from that commit under `vendor/spec/`; never edit it by hand.

## Before every commit

```sh
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

## Git

Branch, open a PR, merge on green CI. No force-push to main.
