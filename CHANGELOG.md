# Changelog

All notable changes to this module. Versions follow [Semantic Versioning](https://semver.org/). Released versions are immutable on the Go module proxy, so a bad release is fixed with a new version and a `retract` directive, never by moving a tag.

## [Unreleased]

### Changed

- CI builds the conformance runner and minter from aitp-rs v0.24.0 (tag `aitp-v0.24.0`, commit `29cb348`). The adapter and `cmd/xcheck-verify` needed no changes: core conformance is 96 passed, 0 failed, 0 skipped, and the mint-and-verify check passes.

## [0.1.1] - 2026-10-27

Tested against spec `v0.3.4-draft`.

### Security

- `VerifyHello` on a `mutual_hello_ack` now checks that the ack comes from the peer the receiver addressed (RFC-AITP-0004 §5.2 step 3). The new `HelloOptions.PeerAID` is the AID you sent `mutual_hello` to, taken from the Manifest you fetched. It is required for an ack, and a different envelope sender fails with the new code `PEER_MISMATCH`. Callers verifying acks must now set `PeerAID`.

### Changed

- The adapter passes the fixture's `peer_aid` input as `PeerAID`, and passes core fixture `mh-015`.
- `errors.go` gains `CodePeerMismatch`, generated from the pinned registry.

## [0.1.0] - 2026-10-26

The first release. Tested against spec commit `dbe63bf` and aitp-rs `052f27e`.

### Added

- Package `verify`, with verifiers for envelopes, Manifests, handshake messages (`mutual_hello`, `mutual_commit` and their acks), identity descriptors (OIDC and pinned key), TCTs (grant context and the issuer side), revocation snapshots and policy, grant vouchers, delegation tokens, PoP challenges and responses, and a replay cache. Each failure carries its registry error code. Verifiers take an injected transport and caller-supplied time, and never touch the network or the wall clock on their own.
- The registry error codes, generated from the pinned spec (`errors.go`).
- Standard-library-only primitives: a strict JSON parser, RFC 8785 JCS, strict base64url, compact JWS, RFC 7638 thumbprints, and Ed25519 and P-256 checks (canonical points, the small-order blocklist, low-S).
- `cmd/aitp-verifier-adapter`, the conformance adapter. It passes all 95 core fixtures under `aitp-conformance --profile core`, with none skipped.
- `cmd/xcheck-verify`, which verifies artifacts minted by aitp-rs byte for byte, negatives included.
- CI covering the spec pin, Go 1.26 and 1.27, lint, fuzzing, conformance and the aitp-rs mint-and-verify check, plus held bump PRs for the spec and aitp-rs pins.

[0.1.1]: https://github.com/agentidentitytrustprotocol/aitp-verifier-go/releases/tag/v0.1.1
[0.1.0]: https://github.com/agentidentitytrustprotocol/aitp-verifier-go/releases/tag/v0.1.0
