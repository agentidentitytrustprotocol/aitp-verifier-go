# aitp-verifier-go

A Go verifier for the [Agent Identity & Trust Protocol (AITP)](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol), written from the RFCs alone. It depends on nothing outside the Go standard library and checks itself against the spec's known-answer vectors and conformance fixtures.

> **Status: pre-release.** The primitives come first; the verifiers and the conformance adapter follow. Nothing is tagged yet.

## Install

Not yet released. The module path will be `github.com/agentidentitytrustprotocol/aitp-verifier-go`.

## Verifiers

To come.

## Conformance adapter

To come: `cmd/aitp-verifier-adapter`, driven by `aitp-conformance`.

## CI

To come.

## Primitives

To come.

## Non-goals

- Signing production artifacts. Test-only signing with the published known-answer keys lives in the conformance adapter alone.
- Network fetches. Verifiers take an injected transport and never read the wall clock.

## Independence

Written from the RFCs, schemas and conformance expectations only. Shares no code with aitp-rs, aitp-verifier-py or aitp-verifier-ts and meets them only at the known-answer vectors. **Same author** as the other implementations: independent in code, not in authorship. It does not satisfy the v1.0 different-authorship criterion.

## Development

Go 1.26 or newer. `gofmt -l .`, `go vet ./...` and `go test ./...` must be clean. The pinned spec commit is in `SPEC_VERSION`.

## License

Apache-2.0. See [LICENSE](LICENSE).
