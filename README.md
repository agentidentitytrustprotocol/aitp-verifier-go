# aitp-verifier-go

A Go verifier for the [Agent Identity & Trust Protocol (AITP)](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol), written from the RFCs alone. It depends on nothing outside the Go standard library and checks itself against the spec's known-answer vectors and conformance fixtures.

> **Status: pre-release.** The primitives are in (`internal/`); the verifiers and the conformance adapter follow. Nothing is tagged yet.

## Install

Not yet released. The module path will be `github.com/agentidentitytrustprotocol/aitp-verifier-go`.

## Verifiers

To come.

## Conformance adapter

To come: `cmd/aitp-verifier-adapter`, driven by `aitp-conformance`.

## CI

`.github/workflows/ci.yml` runs on every push and pull request: the spec pin and generated-file check, `gofmt`, `go vet`, staticcheck, govulncheck, tests on Go 1.26 and 1.27 with a coverage gate of 85% on `internal/`, and 60-second fuzz runs of the JSON parser and JCS.

## Primitives

All under `internal/`, written on the standard library alone:

| Package | What it does |
|---|---|
| `strictjson` | RFC 8259 parser that rejects duplicate member names at any depth, invalid UTF-8, lone surrogate escapes, a BOM and trailing data |
| `jcs` | RFC 8785 canonicalization: UTF-16 code-unit key order, ECMAScript number formatting |
| `b64` | Strict unpadded base64url: no padding, no line breaks, no non-zero trailing bits |
| `curves` | RFC-AITP-0001 §5.4.7: Ed25519 canonical-point and small-order checks, S < L; P-256 low-S and range checks, SEC1 point decompression |
| `keys`, `aid` | Ed25519 and P-256 keys, and `aid:pubkey:` identifiers in the legacy and tagged forms |
| `sigfield` | JCS-profile signature fields (`ed25519.` / `p256.` tags), verified over SHA-256 of the signing input |
| `jws` | Compact JWS with the AITP strict-parsing, `typ` and `alg` pinning rules |
| `jwk` | RFC 7638 thumbprints (`cnf.jkt`) |
| `timeutil` | Caller-supplied clock and integer timestamps |

`errors.go` holds the registry's error codes and is generated from the pinned spec (`go generate ./...`).

## Non-goals

- Signing production artifacts. Test-only signing with the published known-answer keys lives in the conformance adapter alone.
- Network fetches. Verifiers take an injected transport and never read the wall clock.

## Independence

Written from the RFCs, schemas and conformance expectations only. Shares no code with aitp-rs, aitp-verifier-py or aitp-verifier-ts and meets them only at the known-answer vectors. **Same author** as the other implementations: independent in code, not in authorship. It does not satisfy the v1.0 different-authorship criterion.

## Development

Go 1.26 or newer. `gofmt -l .`, `go vet ./...` and `go test ./...` must be clean.

The pinned spec commit is in `SPEC_VERSION`. The spec files the tests read (known-answer vectors, conformance fixtures, JSON Schemas, the error-code registry) are copied from that commit into `testdata/spec/` by `scripts/sync-spec.sh`; `scripts/sync-spec.sh --check` fails when the copy drifts. After a pin bump, run the sync script and `go generate ./...`.

## License

Apache-2.0. See [LICENSE](LICENSE).
