# aitp-verifier-go

A Go verifier for the [Agent Identity & Trust Protocol (AITP)](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol), written from the spec: the RFCs, JSON Schemas, conformance fixtures and the adapter contract. It depends on nothing outside the Go standard library and checks itself against the spec's known-answer vectors and conformance fixtures.

> **Status: v0.1.1.** It passes every core conformance fixture, and verifies aitp-rs-minted artifacts in CI. See [CHANGELOG.md](CHANGELOG.md).

## Install

```sh
go get github.com/agentidentitytrustprotocol/aitp-verifier-go@v0.1.1
go install github.com/agentidentitytrustprotocol/aitp-verifier-go/cmd/aitp-verifier-adapter@v0.1.1
```

## Verifiers

Package `verify` (`github.com/agentidentitytrustprotocol/aitp-verifier-go/verify`) covers envelopes, Manifests, handshake messages, identity descriptors (OIDC and pinned key), TCTs (grant context and issuer side), revocation snapshots and policy, grant vouchers, delegation tokens, PoP challenges and responses, and the replay cache. Every failure is a `*verify.Error` carrying its registry code (`verify.CodeOf`). Time is a parameter, and revocation lists are fetched only through a transport the caller supplies.

## Conformance adapter

`cmd/aitp-verifier-adapter` is the NDJSON adapter that the spec's `schemas/conformance/ADAPTER.md` describes, for aitp-rs's `aitp-conformance` runner:

```sh
aitp-conformance run --target "$(go env GOPATH)/bin/aitp-verifier-adapter" \
  --fixtures-dir <spec>/schemas/conformance --profile core --report conformance.json
```

Every release has the `conformance.json` from its tag attached.

## CI

`.github/workflows/ci.yml` runs on every push and pull request: the spec pin and generated-file check, `gofmt`, `go vet`, staticcheck, govulncheck, tests on Go 1.26 and 1.27 with a coverage gate of 85% on `internal/`, and 60-second fuzz runs of the JSON parser and JCS.

It also builds aitp-rs's `aitp-conformance` runner and `xcheck-mint` minter from the commit in `AITP_RS_COMMIT`, and then runs two cross-implementation jobs:

- `conformance (aitp-conformance)` runs the adapter against the pinned spec fixtures with `--profile core`. It fails on any failed gate or any failed or skipped core fixture, then validates the report against the spec's schema and report checker. The report is uploaded as the `conformance-report` artifact (`conformance.json`).
- `mint (aitp-rs) -> verify` pipes freshly minted aitp-rs artifacts into `cmd/xcheck-verify`. That command verifies the positives and rejects the one-change negatives (high-S twins, stripped algorithm tags, withheld keys) without re-signing anything.

Main's branch protection requires six checks: `spec pin + generated files`, `tests (go 1.26)`, `tests (go 1.27)`, `build aitp-rs tools`, `conformance (aitp-conformance)` and `mint (aitp-rs) -> verify`.

Other workflows:

- `bump-spec.yml` takes the spec repo's `spec-released` dispatch, or a manual run, and opens a held PR that moves `SPEC_VERSION` and regenerates `testdata/spec`, `errors.go` and the adapter test transcript (`scripts/post-spec-bump.sh`).
- `bump-aitp-rs.yml` runs daily, on aitp-rs's `aitp-released` dispatch, or by hand, and opens a held PR that moves `AITP_RS_COMMIT` to aitp-rs main.
- `spec-canary.yml` runs conformance daily against spec main and keeps one tracking issue open while it fails.
- `auto-merge.yml` arms auto-merge for Dependabot patch and minor bumps.
- `release.yml` runs on a `v*` tag. It checks that the tag equals `version.go`, runs the full CI, and waits for proxy.golang.org and sum.golang.org to serve the version. It then runs the core gate against the adapter that `go install …@<tag>` builds from an empty module cache, and publishes a GitHub release with that `conformance.json` attached. Proxy versions are immutable, so a bad release is fixed forward with a new tag and a `retract` directive.

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

What that covers, precisely:

- **The verifier code** (the `verify` package, `internal/` and `cmd/aitp-verifier-adapter`) was written from the RFCs, the JSON Schemas, the conformance fixtures and known-answer vectors, and the spec's `schemas/conformance/ADAPTER.md` only.
- **The CI cross-check tooling** was not. `cmd/xcheck-verify` and the layout of the cross-implementation CI jobs were modelled after reading aitp-verifier-ts's CI workflow files and its `xcheck-verify.mjs`. That tooling feeds aitp-rs-minted artifacts to this verifier; it is not part of the verification logic.

## Development

Go 1.26 or newer. `gofmt -l .`, `go vet ./...` and `go test ./...` must be clean.

The pinned spec commit is in `SPEC_VERSION`. The spec files the tests read (known-answer vectors, conformance fixtures, JSON Schemas, the error-code registry) are copied from that commit into `testdata/spec/` by `scripts/sync-spec.sh`; `scripts/sync-spec.sh --check` fails when the copy drifts. After a pin bump, run the sync script and `go generate ./...`.

## License

Apache-2.0. See [LICENSE](LICENSE).
