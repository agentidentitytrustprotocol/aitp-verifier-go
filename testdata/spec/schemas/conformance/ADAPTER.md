# Conformance Adapter Protocol

- **Document type:** informative. Nothing here adds a protocol requirement.
- **Version:** `adapter-protocol: 1`. A runner sends it as `params.version`
  in the `init` request.

A conformance runner runs the fixtures in this directory against an
implementation through an *adapter*. The adapter is a small program that
translates each request into calls on the implementation and reports the
outcome. This document describes the adapter protocol, so that an adapter
written for one runner works with another, and an implementer does not need
to read one implementation's source to write one.

The fixtures, their metadata and the [runner enforcement
rules](README.md#conformance-runner-enforcement-rules) are normative and are
defined in [README.md](README.md). The per-prefix operation inputs are in
[PLACEHOLDERS.md, "Operation key"](PLACEHOLDERS.md#operation-key). The
conformance report and its claims are in
[`docs/conformance-badge.md`](../../docs/conformance-badge.md). Where this
document and those disagree, they win.

The protocol was first written down for the `aitp-conformance` runner in
[aitp-rs](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/conformance.md).
The behaviour described here was checked against that runner
(`crates/aitp-conformance`); notes marked **aitp-rs** describe what that
runner does where the protocol leaves a choice.

---

## Transport

The adapter is a child process. The runner writes requests to its stdin and
reads responses from its stdout, as NDJSON: one JSON object per line, each
line ending in `\n`.

- **One request at a time.** The runner writes one request and waits for its
  response before it writes the next. An adapter never sees two outstanding
  requests and needs no concurrency.
- **Stdout is the protocol channel.** Anything else an adapter writes there
  breaks the stream. Logs go to stderr, which the runner passes through.
- **Timeout.** A request that gets no response line within 30 seconds fails
  the fixture step that sent it.

  **aitp-rs:** the 30-second default is per request
  (`SubprocessAdapter::with_timeout` overrides it). The runner does not kill
  the adapter on a timeout. It kills the process only at shutdown, so a late
  response to the timed-out request is read as the answer to the next one and
  fails that request on the `id` check.

## Lifecycle

1. The runner starts the adapter.
2. The runner sends `init`. The adapter declares what it supports.
3. The runner sends operations, one at a time.
4. The runner sends `shutdown`.
5. The adapter exits.

**aitp-rs:** after `shutdown` the runner waits about 500 ms for the process
to exit, then kills it.

## Messages

### Request

```json
{"id": "req-7", "op": "verify_tct", "params": {"tct_token": "eyJ...", "...": "..."}}
```

| Field | Meaning |
|---|---|
| `id` | Opaque correlation string. The adapter echoes it unchanged. |
| `op` | Operation name from the [vocabulary](#operations) below. |
| `params` | Operation input, a JSON object. |

For a fixture step, `params` is the fixture's `input` object (or, in the
`sequence` form, the step merged over the sibling context fields, step values
winning) with `operation` removed and every placeholder already substituted.
No `*_claims` minting companion ever reaches the adapter: the runner strips
them at every depth (see
[PLACEHOLDERS.md](PLACEHOLDERS.md#compact-jws-token-placeholders-portable-trust-artifacts)).

The runner adds one input. For an `mh-*` fixture whose operation is
`verify_handshake_payload`, it sets `self_accepted_identity_types` to
`["oidc"]` when the fixture does not state it, so the adapter always receives
the receiver's accepted types for that family and runs RFC-AITP-0004 §5.1
step 8 with them. An `id-*` fixture gets no such default
([README.md, "Receiver policy inputs"](README.md#receiver-policy-inputs-self_accepted_identity_types-self_trust_anchors)).

**aitp-rs:** ids are `req-1`, `req-2`, ... numbered over the whole run,
`init` included.

### Response: success

```json
{"id": "req-7", "ok": true, "result": {}}
```

`result` is a JSON object, `{}` when the operation has nothing to return.
A fixture whose `expected.outcome` is `success` passes on this response
unless it also asserts values in `result` (for example `presenter_aid` and
`grants` for `verify_tct_as_issuer`).

### Side effects

A step whose `expected` block carries `side_effects`
([README.md, "Side-effect assertions"](README.md#side-effect-assertions)) is
checked against the `side_effects` member of the success response's `result`.
It is an object whose keys are the README's side-effect keys and whose values
are booleans:

```json
{"id": "req-12", "ok": true, "result": {"side_effects": {"pop_challenge_issued": true}}}
```

The adapter reports the keys it instruments. A key it leaves out is
un-instrumented, and the README's rule for an un-instrumented assertion
applies. A failure response has no `result`, so under `adapter-protocol: 1` it
carries no side effects: the assertions on a failure step (`tct-007` and
`tct-026` step 3, `rev-004`) are un-instrumented through this protocol.

### Response: failure

```json
{"id": "req-7", "ok": false, "error_code": "AUDIENCE_MISMATCH", "message": "aud does not match"}
```

- `error_code` is a code from the [error-code
  registry](../../registries/error-codes.md), spelled exactly. The runner
  compares it with `expected.error_code`.
- `message` is human-readable and required. The runner never uses it to
  decide a result.

A refusal made below the protocol layer carries no AITP code. The adapter
reports the HTTP status the transport would answer with, in `http_status`,
instead of `error_code`. The presentation rate limit of
[RFC-AITP-0009 §3.1](../../rfcs/RFC-AITP-0009-security.md#31-rate-limiting)
is one (`id-022`):

```json
{"id": "req-9", "ok": false, "http_status": 429, "message": "rate limited"}
```

A fixture that expects this sets `expected.http_status` and no
`expected.error_code`. The step fails if the adapter also returns an
`error_code`.

A response whose `id` differs from the request's, or that is not one of the
two shapes above, fails the step.

### `init`

```json
{"id": "req-1", "op": "init", "params": {"version": "1"}}
```

```json
{
  "id": "req-1",
  "ok": true,
  "result": {
    "implementation": "example-impl",
    "version": "1.2.3",
    "repository": "https://example.com/example-impl",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "supported_ops": ["verify_envelope", "verify_manifest", "verify_tct", "set_clock", "begin_fixture"],
    "supported_features": []
  }
}
```

| Field | Meaning |
|---|---|
| `supported_ops` | Required. Every operation the adapter answers, housekeeping ops included. |
| `supported_features` | Required, may be empty. Informational. |
| `implementation`, `version` | Optional. Copied into the report; `"unknown"` when absent. |
| `repository`, `commit` | Optional. Copied into the report's `implementation` object. A report needs a repository, from here or from the runner's command line. |

**aitp-rs:** the runner decides SKIPs from `supported_ops` only. It does not
read `supported_features`; which opt-in fixtures run is chosen by the
runner's `--feature` flags.

### `shutdown`

```json
{"id": "req-212", "op": "shutdown", "params": {}}
```

The runner ignores the response. The adapter exits after answering.

## Operations

The list is the set of `input.operation` values (and per-step `operation`
values in the `sequence` form) that fixtures in this directory use, plus the
housekeeping ops a runner sends around them. `scripts/check-adapter-ops.py`
(run by `make validate`) fails when a fixture uses an operation this section
does not name. The inputs of each operation are in
[PLACEHOLDERS.md, "Operation key"](PLACEHOLDERS.md#operation-key) and in the
fixture's own `input`.

### Housekeeping ops

The runner sends these itself; no fixture names them. Each is optional. The
runner sends one only when the adapter lists it in `supported_ops`, and it
ignores the response, error or not.

| Op | Params | When the runner sends it | What the adapter does |
|---|---|---|---|
| `set_features` | `{"features": [...]}` | Once, before the first fixture that runs. | Turns on the named opt-in features (the `feature` values of the fixtures the run enables). |
| `set_clock` | `{"now_unix_secs": 1711900000, "now": 1711900000}` | Before each fixture that runs. | Sets its notion of "now" to the [reference clock](PLACEHOLDERS.md#reference-clock-for-byte-stable-minting). An adapter without it runs on wall time, and fixtures that depend on the reference clock can then fail. |
| `begin_fixture` | `{}` | Before each fixture that runs, after `set_clock`. | Drops all per-fixture state: replay deny list, consumed and outstanding nonces, rate-limit counters, sessions, seeded challenges. |

State carries across the steps of one `sequence` fixture and never into the
next fixture ([README.md, "Multi-step `sequence`
form"](README.md#multi-step-sequence-form)). `begin_fixture` is how an
adapter that keeps one implementation instance for the run meets that rule.

**aitp-rs:** the runner sends `set_clock` twice per fixture, the second time
with `now_unix_secs` only. A fixture's `preconditions` object, when present,
is sent between the two as one request per key (the key is the op); a
precondition that fails SKIPs the fixture. No fixture in this directory uses
`preconditions`.

### Fixture operations

| Op | Fixtures | Required for core |
|---|---|---|
| `verify_envelope` | `env-*` | yes |
| `verify_manifest` | `man-*` | yes |
| `verify_handshake_payload` | `id-*` (handshake form), `mh-*` | yes (`id-024` to `id-030`: no, `experimental-spiffe-identity`) |
| `process_handshake_message` | `mh-001` | yes |
| `verify_tct` | `tct-*` (verifier side), `rev-004`, `rev-011` | yes |
| `verify_tct_as_issuer` | `tct-027`, `tct-028`, `tct-029` | yes |
| `verify_grant_voucher` | `vch-*` | yes |
| `verify_delegation_token` | `del-*`, `del-mh-*` | yes (`del-mh-*`: no) |
| `verify_revocation_snapshot` | `rev-*` | yes |
| `issue_pop_challenge` | `tct-006` | yes |
| `produce_pop_response` | `tct-006` | yes |
| `verify_pop_response` | `tct-006` | yes |
| `authorize_capability_invocation` | `tct-007`, `tct-026` | yes |
| `expect_pop_challenge_issued` | `tct-007`, `tct-026` | yes |
| `withhold_pop_response` | `tct-007`, `tct-026` | yes |
| `verify_identity_presentation` | `id-013` to `id-016`, `id-019` to `id-022` | no, `aitp-pinned-admission` |
| `issue_presentation_challenge` | `id-016` | no, `aitp-pinned-admission` |
| `verify_attestation` | `tct-019`, `tct-020`, `tct-021` | no, `aitp-self-attestation` |
| `verify_session_bundle` | `bundle-*` | no, `experimental-session-bundle` |
| `verify_a2a_agent_card_binding` | `a2a-*` | no, `aitp-a2a-agent-card` |
| `renew_tct` | `ren-001` to `ren-009`, `ren-012` | no, `experimental-renewal` |
| `verify_renewal_response` | `ren-010`, `ren-011` | no, `experimental-renewal` |

The "Fixtures" column is a guide. The fixture's own `input.operation` is the
authority.

In an `issue_presentation_challenge` step, the runner reads `result.pop_nonce`
from a success response and substitutes it for `__ISSUED_NONCE_<n>__` in
later steps, numbered from 1 within the sequence. A success response without
`result.pop_nonce` fails the step.

An adapter may answer more operations than this list (aitp-rs also answers
issuance ops such as `issue_tct` and helpers such as `verify_jcs`). No
fixture uses them, so they are outside this protocol.

## SKIP

A fixture step is **SKIP**, not FAIL, when:

- its op is not in the adapter's `supported_ops` (the runner does not send
  it); or
- the adapter answers with `"error_code": "OP_NOT_SUPPORTED"`, which lets a
  declared op refuse one input it does not implement.

A runner also SKIPs, before sending anything, every fixture whose metadata
says so: `draft` and `extension` fixtures whose `feature` the run did not
enable, as the [enforcement
rules](README.md#conformance-runner-enforcement-rules) require.

SKIP is not a pass. A `required_for_core` fixture that is SKIPped for any
reason blocks the core claim, `OP_NOT_SUPPORTED` included. A partial
implementation can run the corpus and get a useful report, but it cannot
claim `AITP v0.3` with skips.

**aitp-rs:** when an enabled draft feature negates a core assertion (for
example `del-007` expects `DELEGATION_MULTIHOP_NOT_SUPPORTED`, and
`experimental-multihop-delegation` is on), the runner SKIPs that fixture. The
exit code exempts such a skip and lists it; the report's `AITP v0.3` gate
still counts it as blocking.

## Gating: claims, not pass counts

A run's result is the gate for each claim, not the number of fixtures that
passed. "180 passed, 0 failed" says nothing about conformance if the
`required_for_core` fixtures were among the skips.

The conformance report (`aitp-conformance-report.schema.json`, `report_version`
`"1"`) carries one result per non-`reserved` fixture and a `gates` array. The
claims and their rules are in [`docs/conformance-badge.md`,
"Claims"](../../docs/conformance-badge.md#claims):

- `AITP v0.3` passes only when every `status: core` fixture with
  `required_for_core: true` has outcome `pass`.
- An extension claim (`AITP v0.3 pinned-admission`,
  `AITP v0.3 self-attestation`) passes only when its feature is enabled and
  every fixture with that feature has outcome `pass`.

A report covers the whole corpus, so a runner writing one does not filter
fixtures. [`scripts/check-conformance-report.py`](../../scripts/check-conformance-report.py)
recomputes the totals, the gates and the fixture digest from a report.

**aitp-rs:** the runner exits non-zero when any fixture FAILs or the core
gate fails, and refuses `--report` together with `--filter`, `--tag` or
`--fail-fast`.

## Invoking a runner

How a runner is invoked is implementation-defined. For the aitp-rs runner:

```sh
aitp-conformance run \
  --target ./my-adapter \
  --fixtures-dir path/to/agentidentitytrustprotocol/schemas/conformance \
  --feature aitp-pinned-admission --feature aitp-self-attestation \
  --report conformance-report.json
```

- `--target` is one executable path. The runner spawns it directly, with no
  shell and no arguments, so a script adapter needs a shebang line and the
  executable bit. `--target "python3 adapter.py"` fails to spawn.
- `--fixtures-dir` points at this directory.
- `--feature` enables one opt-in feature; repeat it for more.
- `--filter` is a plain substring match on fixture ids, not a glob.

A starting point for a new adapter is the
[Python template](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/adapters/README.md)
in aitp-rs. It answers `init` and `shutdown`, stubs a few handlers, and
returns `OP_NOT_SUPPORTED` for any op it has no handler for.

## Versioning

This is `adapter-protocol: 1`. A change that breaks an existing adapter (a
renamed op, a changed message shape, a new required `init` field) bumps the
number, and the runner sends the new value in `init`. Adding an op that new
fixtures use does not.
