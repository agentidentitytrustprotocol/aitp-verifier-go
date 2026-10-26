# Conformance Test Fixtures

AITP conformance fixtures are JSON files that describe a scenario, the input,
and the expected agent behavior. Any compliant implementation MUST produce the
specified outcome for each fixture.

---

## Structure

The prefix list below is generated from the fixture files actually present
(`ls schemas/conformance/*.json`), not hand-transcribed — regenerate it the
same way if fixtures are added or renamed:

```
conformance/
├── README.md
├── env-*.json      Envelope-level checks (RFC-AITP-0001, RFC-AITP-0007)
├── man-*.json      Manifest verification (RFC-AITP-0003)
├── mh-*.json       Mutual Handshake scenarios (RFC-AITP-0004; includes mh-success-*)
├── id-*.json       Identity binding and pinned-admission (RFC-AITP-0002)
├── tct-*.json      Trust Context Token verification (RFC-AITP-0005, RFC-AITP-0008)
├── vch-*.json      Grant voucher verification (RFC-AITP-0005 §8)
├── rev-*.json      Revocation checks (RFC-AITP-0008)
├── del-*.json      Single-hop delegation (RFC-AITP-0006)
├── del-mh-*.json   Multi-hop delegation, opt-in (RFC-AITP-0011)
├── bundle-*.json   Session Trust Bundle, opt-in (RFC-AITP-0010)
├── a2a-*.json      A2A Agent Card binding, opt-in (RFC-AITP-0014)
├── known-answer/   Pinned canonical bytes, keys and signatures (not fixtures)
└── reports/        Sample conformance reports (not fixtures; docs/conformance-badge.md)
```

---

## Fixture Format

Every fixture MUST carry the following metadata block as its leading
fields. The block exists so a conformance runner can know — without
parsing scenario content — whether a fixture is required for its
protocol version, an opt-in draft feature, or out of scope entirely.

```json
{
  "id": "unique-fixture-id",
  "rfc": "RFC-AITP-NNNN",
  "status": "core | draft | extension | reserved",
  "required_for_v0_1": false,
  "required_for_core": true,
  "feature": null,
  "description": "Human-readable description of the scenario",
  "tags": ["happy-path | failure | security | edge-case"],
  "input": { ... },
  "expected": {
    "outcome": "success | failure",
    "error_code": "ERROR_CODE (if failure)",
    "grants": ["capability (if success)"]
  }
}
```

### Metadata fields

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Fixture id (e.g. `mh-success-001`). |
| `rfc` | string | Most-specific RFC the fixture exercises (e.g. `RFC-AITP-0006`). |
| `status` | enum | One of `core`, `draft`, `extension`, `reserved`. See enforcement rules below. |
| `required_for_v0_1` | bool | Whether a v0.1 implementation MUST pass this fixture. `false` for fixtures minted in the v0.2 JWS token shape (a v0.1 implementation cannot parse them); `true` only for fixtures frozen in the v0.1 shape (currently only `del-004`). Always `false` for `draft` / `extension` fixtures. |
| `required_for_core` | bool | Whether a v0.2 implementation MUST pass this fixture. `false` for v0.1-frozen fixtures and all `draft` / `extension` fixtures. |
| `feature` | string \| null | When `status != "core"`, the named opt-in feature flag a runner uses to enable this fixture (e.g. `experimental-session-bundle`). `null` for core fixtures. |

### Conformance runner enforcement rules

A conformance runner selects fixtures by the implementation's protocol
version (`required_for_core` for a v0.2 runner, `required_for_v0_1` for
a v0.1 runner) and MUST apply the following rules to the metadata block
before executing a fixture:

- `status: "core"` + the matching `required_for_v0_N: true` → **MUST
  execute.** A `OP_NOT_SUPPORTED` result or runner SKIP MUST be
  reported as a failure for this fixture.
- `status: "draft"` → **MUST SKIP** unless the runner has explicitly
  opted into the named `feature` (and, by extension, draft conformance
  for the cited RFC). Failing an implementation for not implementing
  a draft fixture is non-conformant runner behavior.
- `status: "extension"` → **MUST SKIP** in the default runner. May
  be exercised only when the runner is explicitly testing the named
  extension feature.
- `status: "reserved"` → MUST be ignored by every runner; reserved status
  exists only so a fixture id slot can be claimed before the underlying
  RFC normative text lands.

Any fixture missing the metadata block, or carrying invalid values for
these fields, MUST cause the runner to fail loudly rather than silently
skip — the metadata is a load-bearing input to interop testing.

### Multi-step `sequence` form

Fixtures that exercise stateful behavior (e.g. replay detection across two sends, or a downstream PoP exchange across challenge/response) use a `sequence` array inside `input` instead of a single `expected` block. Each entry is one step:

```json
{
  "input": {
    "sequence": [
      { "step": 1, "operation": "...", "message_id": "...", "expected": { "outcome": "success" } },
      { "step": 2, "operation": "...", "message_id": "...", "expected": { "outcome": "failure", "error_code": "REPLAY_DETECTED" } }
    ]
  }
}
```

The runner MUST execute each step in order against the same implementation instance and assert the per-step `expected` outcome. Each step carries its own `operation` field — see PLACEHOLDERS.md "Operation key" for the per-prefix operation registry.

Verifier state persists only across the steps of one fixture's `sequence`. The runner MUST execute each fixture, sequence or not, against fresh verifier state: no `message_id` deny-list entry, consumed or outstanding nonce, or rate-limit counter carries in from another fixture. Fixtures are independent and reuse values; `id-019` and `id-013` present the same `pop_nonce` under the same `message_id`, so a runner that keeps one verifier across fixtures fails whichever runs second. How the state is reset (a new instance per fixture, or an explicit reset) is left to the harness.

Sequence fixtures MAY also carry sibling fields inside `input` that provide context shared across all steps. For example, `tct-006-pop-challenge-response.json` carries `input.tct_token` alongside `input.sequence` because every step in the sequence operates against the same TCT (the consuming peer issues a challenge for it; the holder produces a response with the subject key bound via `cnf.jkt`; the verifier checks both). Sibling context fields are part of the fixture input and the runner MUST make them available to every step.

`mh-001` (replay detection) and `tct-006` (downstream PoP) are the fixtures using this form.

### Side-effect assertions

A fixture's `expected` block (or any step's per-step `expected` within a `sequence`) MAY carry an optional `side_effects` object. The conformance runner MUST instrument the listed effects and assert the actual values match. Existing fixtures that omit `side_effects` are unaffected — it is an additive field.

Currently defined side-effect keys:

| Key | Meaning |
|---|---|
| `revocation_lookup_called` | Whether the implementation called the network revocation source. Used by `rev-004` to pin RFC-AITP-0008 §3.3 (signature-before-revocation ordering). |
| `network_fetch_called` | Whether the implementation made any outbound network fetch. Broader than `revocation_lookup_called`; used for DoS-amplification assertions. |
| `pop_challenge_issued` | Whether the verifier issued a `pop_challenge` during fixture evaluation. Used by `tct-007` for PoP-enforcement conformance and by `tct-026` for the issuer-side check. |
| `capability_authorized` | Whether the verifier authorized a capability invocation. Used by `tct-007` to assert PoP-required grants are rejected without a valid `pop_response`, and by `tct-026` to `tct-029` for the issuer-side check (RFC-AITP-0005 §10.5). |

A runner that cannot instrument a listed side effect MUST report SKIP for that assertion (NOT silent pass). The schema (`schemas/json/aitp-conformance-fixture.schema.json`) lists the keys above; additional keys are permitted (`additionalProperties: true`) so new fixtures can add side-effect surfaces without a schema bump, but the registered keys are the only ones a runner is required to recognize.

### Trust-store input (`trust_store`)

A pinned-key fixture states the verifier's `pinned_keys` store (RFC-AITP-0002 §3.2 step 3, §4) as `input.trust_store`:

- It is an array of AID strings. Each entry's algorithm comes from its AID tag (`aid:pubkey:p256:…` is `p256`; an untagged or `aid:pubkey:ed25519:` AID is `ed25519`), and the runner seeds the store with the `(algorithm, public_key)` pairs those AIDs encode.
- When `trust_store` is absent, the store is empty. The runner MUST NOT invent trust: it MUST NOT pre-load the sender's key, a KAT keypair, or any default, and an implementation's possession-only behavior is not a substitute (RFC-AITP-0002 §3.2 forbids such a mode in every deployment mode).
- Every pinned-key failure fixture except `id-007` carries a `trust_store` that contains the sender, so steps 1–3 pass and the failure comes only from the defect the fixture names. `id-007` alone omits the sender, because its defect is the untrusted key.

### Receiver policy inputs (`self_accepted_identity_types`, `self_trust_anchors`)

An `mh-*` fixture that receives a MUTUAL_HELLO runs RFC-AITP-0004 §5.1 through step 8, the policy step. It states the receiver's own policy in two keys:

- `input.self_accepted_identity_types` is the receiver's own `accepted_identity_types` (RFC-AITP-0003 §3.2). Step 8 checks the payload `identity.type` against it, and a type not in it fails with `INCOMPATIBLE_IDENTITY_TYPE`.
- `input.self_trust_anchors` is the receiver's OIDC `trust_anchors`. For an `oidc` peer, step 8 requires the identity `issuer` to be in it, else `INCOMPATIBLE_TRUST_ANCHORS` (`mh-004`).
- When `self_trust_anchors` is absent, as in every `id-*` fixture and the earlier `mh-*` fixtures, the receiver's `trust_anchors` hold exactly the runner-minted OIDC test issuer listed in PLACEHOLDERS.md ("Identity-issuer keys"), `https://auth.openai.com`. No other issuer counts as trusted, and the runner MUST NOT add one. This applies to an `id-*` fixture too: it does not run step 8, but a verifier may run the trust-anchor check inside step 6 (RFC-AITP-0004 §5.1 step 6, check 2).
- **Authoring rule: an untrusted OIDC issuer is a fixture's only late failure.** RFC-AITP-0004 §5.1 step 6 lets a verifier check the issuer against `trust_anchors` before it fetches key material, so when the issuer is untrusted and key resolution or proof verification (check 3), step 7 or step 8 also fails, either `INCOMPATIBLE_TRUST_ANCHORS` or the strict-order code is conformant. A fixture MUST NOT combine an untrusted OIDC issuer with any of those failures, because its single `expected.error_code` could not be right for every conformant verifier. Combining one with a failure that runs earlier under either order (steps 1–5, or the descriptor-shape and hint checks of step 6 check 1) is allowed, because the code is fixed: `id-011b` pairs the untrusted issuer `https://auth.example.com` with a forbidden `public_key` and expects `IDENTITY_FAILED`. `mh-004` is the fixture for an untrusted issuer alone.
- When `self_accepted_identity_types` is absent, the receiver runs with the default `["oidc"]`. The runner MUST NOT configure accepted types of its own, and MUST NOT add the type the payload presents (`mh-011` tests exactly this).
- The sender's Manifest may carry its own `accepted_identity_types`. That is the sender's policy for its peers, and step 8 does not read it.
- `mh-010` to `mh-014` use these keys. The earlier `mh-*` fixtures that reach step 8 present `oidc`, which the default accepts, and `mh-009` presents `pinned_key` but fails at step 6. So the default changes none of their outcomes.

An `id-*` fixture with `verify_handshake_payload` checks the identity binding, which is §5.1 step 6, and does not run step 8 (PLACEHOLDERS.md, "Operation key"). The pinned-key successes `id-010` and `id-017` and the `spiffe` successes state no receiver types for that reason. A runner whose implementation always runs step 8 configures the receiver to accept the fixture's identity type for an `id-*` fixture, as the `spiffe` rule already says.

### Revocation inputs (`issuer_revocation_list`, `revocation_snapshots`)

A fixture states the revocation state it tests through `input.issuer_revocation_list` (TCT verification) or `input.revocation_snapshots` (delegation, single-hop and multi-hop):

- A fixture that supplies neither key is **not testing revocation**. Its expected outcome assumes every lookup it would make returns "not revoked", and the runner MUST evaluate it that way: it MUST NOT apply `revocation_policy.mode` to the missing snapshot, and it MUST NOT fail the fixture for an unreachable revocation endpoint. `del-001` and `del-mh-001` are examples.
- The convention is per issuer. When a fixture supplies `revocation_snapshots` for some issuers but not others, every issuer it supplies no entry for is likewise not under test, and its lookups read "not revoked". Only the supplied entries are evaluated, including discarding them under RFC-AITP-0008 §1.5. So `del-mh-004` and `del-mh-006` fail only because of the one hop issuer whose snapshot they supply.
- This is a fixture convention, not protocol behaviour. In a deployment an absent, unobtainable or discarded snapshot is handled by `revocation_policy.mode` (RFC-AITP-0008 §1.5, §3.1; RFC-AITP-0011 §6), and under `fail_closed` the token is rejected.
- That behaviour is covered by the dedicated revocation fixtures: `rev-*`, `tct-004`, `tct-022` to `tct-025`, `del-002`, `del-008`, `del-mh-004` and `del-mh-006`. Each supplies the revocation input it tests.

`issuer_revocation_list` has these members:

| Member | Meaning |
|---|---|
| `issuer` | The AID of the issuer whose revocation state the entry describes: the TCT's `iss`. |
| `snapshot` | The issuer's signed revocation snapshot (`{"revocation_list": …, "signature": …}`, RFC-AITP-0008 §1.5), as the verifier obtained it. It is verified and, if it fails, discarded under §1.5. |
| `available` | Boolean, default `true`. `false` states that the verifier has **no revocation source** for the issuer: no snapshot can be obtained at all, as for an issuer Manifest without `rfc-aitp-0008.revocation_list_uri` (RFC-AITP-0008 §1.4) or an unreachable endpoint. It is not an empty list. An entry with `available: false` MUST NOT carry `snapshot`. |
| `fail_mode` | The verifier's `revocation_policy.mode` (RFC-AITP-0008 §3.1). When absent, the runner MUST run the verifier with its default revocation policy and MUST NOT set a mode; the expected outcome assumes the schema default, `fail_closed`. |

`available: false` is the one way a fixture says "the source is unavailable". A missing key still means "not tested" (above), so a runner MUST NOT apply that convention when the key is present, and MUST NOT turn `available: false` into an empty snapshot. `tct-024` (no `fail_mode`, so the default: `TCT_REVOKED`) and `tct-025` (`fail_open`: success) use it. An implementation that reads an unavailable source as "nothing is revoked" passes `tct-025` and fails `tct-024`.

### Manifest inputs (`issuer_manifests`, `coordinator_manifest`)

A delegation or session-bundle fixture states the Manifests the verifier holds for its peers. Each one is a complete, signed Manifest body (RFC-AITP-0003 §2) that the runner mints the same way it mints a `man-*` fixture's `input.manifest`: `__VALID_POP_SIG__` and `__VALID_MANIFEST_SIG__` are produced with the key of the Manifest's own `aid` (see `PLACEHOLDERS.md`).

- `del-*` and `del-mh-*` fixtures carry `input.issuer_manifests`, an array of Manifest bodies. The verifier resolves each hop issuer's key from the Manifest whose `aid` equals that hop's `iss` (RFC-AITP-0006 §4 step 1, RFC-AITP-0011 §3 step 1). The voucher needs no entry, because the verifier checks it against its own key (RFC-AITP-0006 §4 step 3).
- `bundle-*` fixtures carry `input.coordinator_manifest`, one Manifest body. The verifier checks the bundle signature against the key that this Manifest designates for the coordinator's AID (RFC-AITP-0010 §5 step 5).
- These inputs are the verifier's whole Manifest source. The runner MUST supply exactly the Manifests the fixture lists. It MUST NOT derive a key from the AID string in place of a missing Manifest, synthesize a stand-in Manifest, or fetch one over the network. When no supplied Manifest designates the key an issuer or coordinator needs, verification fails with `KEY_RESOLUTION_FAILED` (RFC-AITP-0007 §1). `del-mh-005` and `bundle-007` test exactly this.
- A fixture that is rejected before any key is resolved (`del-007`, `bundle-004-signature-sibling-rejected`, `bundle-006-unknown-field-rejected`, `bundle-008`) still carries the field, so every fixture in a family has the same input shape. The verifier never reads it.
- `del-004` is frozen in the v0.1 shape and carries no Manifest input.
- `a2a-*` fixtures carry `input.manifest`, the Manifest fetched from the Agent Card's `params.manifestUrl`, or `input.manifest_fetch`, the outcome of a failed fetch (`a2a-004`, which maps to `MANIFEST_NOT_FOUND`). The runner MUST NOT fetch the Manifest or the Card (RFC-AITP-0014 §4.2).

### Dynamic fixtures

A fixture MAY carry an optional `dynamic` boolean in its metadata
block. Fixtures marked `"dynamic": true` carry placeholder values in
time-sensitive fields because they exercise a live protocol exchange
that cannot be statically minted. The companion `dynamic_fields` array
names the fields the runner MUST regenerate.

A conformance runner MUST generate fresh artifacts for every field
listed in `dynamic_fields`, using the pinned KAT keypairs (see
[`PLACEHOLDERS.md`](PLACEHOLDERS.md)), before invoking the
implementation under test. It MUST NOT feed the placeholder tokens
through verbatim.

`tct-006` and `tct-007` carry this flag: each drives a multi-step
`sequence` whose nonces, timestamps, and signatures must be fresh for
the downstream PoP challenge/response to verify. `id-016` carries it too:
its nonces are chosen by the verifier during the run, so the proofs and
envelope signatures over them can only be minted then. Fixtures without the
flag are statically mintable — their placeholders can be substituted
once and reused.

### Structural-rejection fixtures

Some fixtures carry intentionally invalid or placeholder signatures
and test that the implementation rejects on an early **structural**
check, before reaching the cryptographic layer. The placeholder
signature is never verified; the fixture passes by *not* reaching the
signature verifier.

`del-004` (frozen in the v0.1 wire shape, for v0.1 runners) and
`del-007` (its v0.2 sibling, claim-shaped) are the structural-rejection
fixtures: a delegation token carrying a `chain` MUST be rejected with
`DELEGATION_MULTIHOP_NOT_SUPPORTED` before any per-hop signature work,
so their chain-entry, chain-hash, and (for del-004) outer-signature
placeholders are deliberately never resolved.

The new v0.2 token-format fixtures `tct-008` (`alg: none`) and
`tct-009` (algorithm confusion) are also pre-crypto rejections: the
AID-derived `alg` pin fails before any signature bytes are examined
(RFC-AITP-0001 §5.4.5). `tct-010` (`typ` confusion) carries a
*cryptographically valid* grant voucher presented as a TCT — the
signature would verify; the explicit-typing check is what rejects.
`tct-013` (a UUID v7 `jti`) and `tct-014` (a v4 `jti` with wrong
variant bits) are validly signed too: the `jti` layout check of
RFC-AITP-0005 §2.2 runs before signature verification and rejects with
`TCT_SIGNATURE_INVALID`, the TCT's structural-rejection code
([`registries/error-codes.md`](../../registries/error-codes.md#structural-rejection)).

`tct-017` (ES256 high-S) carries a literal committed token, not a
placeholder: a placeholder would be minted afresh by the runner's own
signer, which normalizes S and so would produce a token that passes.
The token is kat-keypair-005-p256's low-S signature over valid claims
with S replaced by n − S. It verifies under RFC 7518 alone; the
RFC-AITP-0001 §5.4.7 low-S rule is what rejects it, and
`make kat-verify` asserts both halves.

`env-007` to `env-011` carry literal committed envelope signatures for the
same reason. `env-007` carries `kat-envelope-002-ed25519`, kat-keypair-001's
signature over its envelope (RFC-AITP-0001 §5.4, `extensions` included).
`env-008`, `env-009` and `env-010` carry the same signature over env-007's
envelope with one member changed after signing: an `extensions` key,
`message_type`, and `version`. A runner that minted a fresh signature would
sign the changed envelope and the negatives would pass. `make kat-verify`
asserts that the signature verifies over env-007's envelope and over none of
the three changed ones. `env-010` also pins the RFC-AITP-0001 §5.4 check
order: the unknown `version` is reported as `UNKNOWN_VERSION` although the
signature fails too. `env-011` pins the strict cutover between revisions: it
is env-007's envelope with `version` set to the previous revision `aitp/0.2`
and a fresh `message_id`, and its committed signature is kat-keypair-001's
valid signature over those exact bytes. Nothing is tampered, so the only
reason to reject is the revision literal: `UNKNOWN_VERSION`.

`rev-010` and `bundle-008` apply the `env-010` pattern to the other two
JCS-profile artifacts whose unknown-version code is not `UNKNOWN_VERSION`
([`VERSIONING.md`](../../VERSIONING.md)). Each carries the committed signed
example (`kat-keypair-001-snapshot.json`, `kat-keypair-001-bundle.json` under
[`known-answer/signed-examples/`](known-answer/signed-examples/)) with `version`
changed to `aitp/9.9` after signing, and the example's literal signature, which
a runner MUST NOT re-mint. The signature therefore fails too, and the fixture
proves the version check runs first: RFC-AITP-0008 §1.5 rejects the snapshot
structurally with `REVOCATION_SNAPSHOT_INVALID` before any signature work, and
RFC-AITP-0010 §5 step 1 rejects the bundle with `BUNDLE_VERSION_MISMATCH` before
the step 6 signature check. `bundle-008`'s `coordinator_manifest` is the committed
`kat-keypair-001-manifest.json`, so the fixture has no placeholder at all.
`make kat-verify` asserts that each signature verifies over the signed example and
not over the fixture.

`tct-015`, `tct-016` and `tct-018` are validly signed and schema-valid:
`verify_tct` is a grant context, and RFC-AITP-0005 §5.3 rejects a self-issued
TCT, or any TCT carrying the `aitp.attestation` marker (alone, with a distinct
`iss`, or beside an ordinary grant), there. They stay `core`: the
grant-context rejection binds every verifier. The committed
self-attestations themselves are known-answer vectors, not fixtures:
`kat-tct-002` and `kat-tct-003` under
[`known-answer/signed-examples/tct/`](known-answer/signed-examples/tct/).

The pinned-admission fixtures (`id-013` to `id-016`, `id-019` to `id-022`)
exercise the OPTIONAL profile of RFC-AITP-0002 §3.4 through the
`verify_identity_presentation` and `issue_presentation_challenge` operations
([`PLACEHOLDERS.md`](PLACEHOLDERS.md#operation-key)). Because the profile is
OPTIONAL, they are extension-gated: `status: extension`, `required_for_core:
false`, `feature: aitp-pinned-admission`. The default runner MUST SKIP them, so
an implementation that does not claim the profile is not failed. A runner
testing an implementation that claims "AITP v0.3 pinned-admission" conformance
opts into the feature, and that implementation MUST pass them (RFC-AITP-0001 §10
item 9). The proofs in `id-013`, `id-014`, `id-015`, `id-019`, `id-020`,
`id-021` and `id-022` are real Ed25519 signatures by kat-keypair-003, which
`make kat-verify` re-verifies (Node) and re-signs (Python) against each
fixture's tuple. `id-016` is dynamic, because the verifier chooses its nonces at
run time.

`tct-019`, `tct-020` and `tct-021` exercise relying-party verification of a
self-attestation (RFC-AITP-0005 §5.3, "Verification") through the
`verify_attestation` operation. That is not a grant context, and consuming
attestations is a role RFC-AITP-0001 §10 does not require, so all three are
`status: extension` under `feature: aitp-self-attestation`; an implementation
that claims "AITP v0.3 self-attestation" conformance MUST pass them. `tct-020` carries
the committed known answer `kat-tct-002` verbatim and expects success for a
third-party relying party whose AID is not the token's `aud`; `tct-019` is an
otherwise valid attestation whose `ext` lacks the key the relying party expects;
`tct-021` presents `kat-tct-002` again, with every input as in `tct-020` except
`trust_store`, the relying party's record of issuer keys trusted at `iat`, which
does not list the issuer (RFC-AITP-0005 §5.3 "Lifetime" and the §7.3 exception).
No new input field is needed: `trust_store` already carries the relying party's
records.
The §5.3 "Verification is not a grant context" bullet is also pinned by
`make kat-verify`: `checkSelfAttestations()` in
[`scripts/verify-known-answer.mjs`](../../scripts/verify-known-answer.mjs) and
the self-attestation section of
[`scripts/recompute-known-answer-independent.py`](../../scripts/recompute-known-answer-independent.py)
verify `kat-tct-002` and `kat-tct-003` as attestations (`iss == sub == aud`,
`grants` exactly `["aitp.attestation"]`, `cnf.jkt` the issuer's own thumbprint,
the `ext` statement present), and both stacks check that `tct-020` and `tct-021`
carry `kat-tct-002` byte for byte.

**Not expressible as a fixture.** RFC-AITP-0002 §3.4 requires the nonce lookup
and consumption to be one atomic step, so that two presentations racing on one
nonce cannot both succeed. A fixture runs its steps in order against one
instance, so it cannot produce the race; `id-013` pins only the sequential
half (a consumed nonce is never accepted again). Atomicity under concurrency is
left to implementation tests.

`rev-004` is **not** a structural-rejection fixture, despite also
carrying a tampered-signature placeholder. It tests the opposite
ordering: signature verification MUST be reached and MUST fail
(`TCT_SIGNATURE_INVALID`), and the network revocation lookup MUST NOT
run afterward. Its `__TAMPERED_SIG__` placeholder is minted (per
[`PLACEHOLDERS.md`](PLACEHOLDERS.md) — sign properly, then flip the
least-significant bit of the last raw signature byte) into a
syntactically valid base64url signature that fails Ed25519
verification, so the crypto layer is genuinely exercised. A runner
that rejects `rev-004` at base64url decode — rather than at signature
verification — is testing the wrong code path.

---

## Fixture-input validation

The metadata block described above (`id`, `rfc`, `status`, …) is checked
against `aitp-conformance-fixture.schema.json` for every fixture. That check
never looks inside `input`, which is where the actual artifacts — the
session bundle, the TCT claims, the manifest — live. `make json-validate`
(`scripts/validate-json.sh`) closes that gap with a second, map-driven stage
that validates each embedded artifact against the schema it claims to
satisfy.

**If you add a fixture, you MUST add a matching entry to
[`scripts/fixture-validation-map.json`](../../scripts/fixture-validation-map.json),
keyed by the fixture's `id`.** This is fail-closed: an unmapped fixture is a
build error, never a silently-skipped one — see the check's own error text
for what it demands.

Each artifact entry names:

- `pointer` — the RFC 6901 JSON pointer to the artifact inside the fixture
  (e.g. `/input/session_bundle`).
- `schema` — the schema filename under `schemas/json/` the artifact must
  satisfy.
- `expect` — `valid`, `invalid`, or `invalid_known_defect`.
- `reason` — required whenever `expect` is not `valid`, naming why the
  artifact is expected to fail.
- `wrap` — optional; re-wraps the artifact as `{KEY: artifact}` for a schema
  that describes the wrapped transport form rather than the bare body.

`expect` is checked **bidirectionally**: a fixture whose artifact is declared
`invalid` and starts validating fails the build exactly as loudly as one
declared `valid` that stops validating — a negative expectation that
silently starts passing is the vacuous-pass failure mode this stage exists
to prevent. If you fix the underlying defect a fixture was demonstrating,
update its map entry in the same commit, or the build will fail there
instead.

A fixture with no artifacts to validate MUST say so explicitly with a
`no_artifacts` entry naming a reason, rather than being left out of the map.

Fixture `input` values carry placeholder tokens (`__VALID_A_SIG__`,
`__NOW_PLUS_3600__`, …) rather than minted values, because minting needs key
material this repository deliberately does not use at validation time.
[`scripts/normalize-fixture-input.py`](../../scripts/normalize-fixture-input.py)
substitutes a shape-conformant dummy per placeholder family before an
artifact is handed to the schema validator; an unrecognized placeholder is a
hard error there too, for the same reason an unmapped fixture is a hard
error here. See [`PLACEHOLDERS.md`](PLACEHOLDERS.md) for the placeholder
registry.

---

## Running Conformance Tests

Implementations MUST provide a conformance runner that:

1. Accepts a fixture directory path.
2. Executes each fixture against the implementation.
3. Emits a conformance report: one JSON document, valid against
   [`aitp-conformance-report.schema.json`](../json/aitp-conformance-report.schema.json),
   with one result per non-`reserved` fixture ID (`pass`, `fail`, `skip` or
   `excluded_by_role`) and the gate for each RFC-AITP-0001 §10 claim it
   evaluated.

The runner interface (how it is invoked, its flags, its human-readable
output) is implementation-defined. The report format is not. The fields, the
fixture digest and the per-claim badge rules are in
[`docs/conformance-badge.md`](../../docs/conformance-badge.md); sample reports,
valid and invalid, are in [`reports/`](reports/).

---

## Fixture summary

| Tier | Count | Required for v0.3 |
|---|---|---|
| `core` (`required_for_core`) | 94 | ✅ Yes |
| `core` (frozen in the v0.1 shape: `del-004`) | 1 | ❌ No (v0.1 runners only) |
| `extension` — pinned-admission profile (RFC-AITP-0002 §3.4, `feature: aitp-pinned-admission`) | 8 | ❌ No (required of an implementation claiming the profile) |
| `extension` — attestation verification (RFC-AITP-0005 §5.3, `feature: aitp-self-attestation`) | 3 | ❌ No (required of an implementation claiming the role) |
| `draft` — session bundle (RFC-AITP-0010, `feature: experimental-session-bundle`) | 8 | ❌ No |
| `draft` — multi-hop delegation (RFC-AITP-0011, `feature: experimental-multihop-delegation`) | 6 | ❌ No |
| `draft` — A2A Agent Card binding (RFC-AITP-0014, `feature: aitp-a2a-agent-card`) | 6 | ❌ No |
| `draft` — `spiffe` identity type (RFC-AITP-0002 §6, `feature: experimental-spiffe-identity`) | 7 | ❌ No |
| **Total** | **133** | |

Counts are sourced from the `status` / `required_for_v0_N` / `feature` metadata block on each fixture file. A conformance runner for the current revision, `aitp/0.3`, MUST execute every `required_for_core` core fixture (the key keeps its v0.2 name so existing runners keep working; for `aitp/0.3` it marks the core tier); `draft` and `extension` fixtures MUST be SKIPped unless the runner has been explicitly opted into the named `feature` (see the enforcement rules above).

---

## Fixture Index

### Envelope and key resolution (RFC-AITP-0001, RFC-AITP-0007)

| ID | Description | Outcome |
|---|---|---|
| `env-001` | Envelope timestamp older than tolerance window | failure: TIMESTAMP_EXPIRED |
| `env-002` | Caller invokes a capability not present in the active TCT | failure: POLICY_VIOLATION |
| `env-003` | Issuer key cannot be resolved (Manifest unreachable, OIDC offline) | failure: KEY_RESOLUTION_FAILED |
| `env-004` | Replayed envelope `message_id` rejected by deny list | failure: REPLAY_DETECTED |
| `env-005` | P-256 sender (`aid:pubkey:p256:`) envelope with algorithm-tagged signature verifies (RFC-AITP-0001 §5.4.3) | success |
| `env-006` | Envelope carries an unknown top-level member (`trace_id`) outside `extensions` | failure: UNKNOWN_FIELD |
| `env-007` | Envelope carries an unrecognized, vendor-namespaced key inside `extensions` — ignored; committed signature `kat-envelope-002-ed25519` | success |
| `env-008` | env-007's signed envelope with an `extensions` key renamed after signing | failure: INVALID_SIGNATURE |
| `env-009` | env-007's signed envelope with `message_type` changed to `mutual_hello_ack` after signing | failure: INVALID_SIGNATURE |
| `env-010` | env-007's signed envelope with `version` changed to an unknown value after signing; the version check runs before the signature check | failure: UNKNOWN_VERSION |
| `env-011` | A correctly signed envelope from the previous revision (`version` `aitp/0.2`); strict cutover, no dual-accept | failure: UNKNOWN_VERSION |

### Manifest (RFC-AITP-0003)

| ID | Description | Outcome |
|---|---|---|
| `man-001` | Manifest `expires_at` is in the past at fetch time | failure: MANIFEST_EXPIRED |
| `man-002` | Manifest declares an unsupported `version` | failure: MANIFEST_VERSION_UNKNOWN |
| `man-003` | Cached Manifest past `expires_at` is rejected even if otherwise valid | failure: MANIFEST_EXPIRED |
| `man-004` | Manifest body carries an unknown member (`deployment_region`) outside `extensions` | failure: UNKNOWN_FIELD |
| `man-005` | Manifest body carries an unrecognized, vendor-namespaced key inside `extensions` — ignored | success |
| `man-006` | Manifest missing the REQUIRED `handshake_endpoint` — structural rejection, not a signature failure | failure: MANIFEST_INVALID |
| `man-007` | Manifest `identity_hint` has `type: "oidc"` and also carries `public_key`, which RFC-AITP-0003 §3.1 forbids | failure: MANIFEST_INVALID |

### Mutual Handshake (RFC-AITP-0004)

| ID | Description | Outcome |
|---|---|---|
| `mh-success-001` | Both peers complete MUTUAL_COMMIT with valid TCTs | success |
| `mh-001` | Replayed MUTUAL_HELLO (duplicate message_id) rejected | failure: REPLAY_DETECTED |
| `mh-002` | Manifest signature invalid → rejected | failure: MANIFEST_SIGNATURE_INVALID |
| `mh-003` | Manifest PoP failed → rejected | failure: MANIFEST_POP_FAILED |
| `mh-004` | Peer issuer not in accepted_trust_anchors | failure: INCOMPATIBLE_TRUST_ANCHORS |
| `mh-005` | pop_nonce_echo mismatch | failure: NONCE_MISMATCH |
| `mh-006` | Peer-issued TCT audience ≠ self AID | failure: AUDIENCE_MISMATCH |
| `mh-007` | Peer-issued TCT grants exceed offered_capabilities | failure: GRANT_OVERFLOW |
| `mh-008` | Peer PoP signature invalid | failure: POP_VERIFICATION_FAILED |
| `mh-009` | Peer's `manifest.identity_hint.type` ≠ payload `identity.type` (type-confusion within the peer's own message; RFC-AITP-0004 §5.1 step 6) | failure: IDENTITY_FAILED |
| `mh-010` | Receiver accepts `["oidc"]`; valid `pinned_key` identity (id-017's envelope, sender trusted) (§5.1 step 8) | failure: INCOMPATIBLE_IDENTITY_TYPE |
| `mh-011` | Receiver states no `accepted_identity_types`, so the default `["oidc"]` applies; same valid `pinned_key` identity | failure: INCOMPATIBLE_IDENTITY_TYPE |
| `mh-012` | Receiver accepts `["pinned_key"]`; valid `oidc` identity from an issuer in its trust anchors | failure: INCOMPATIBLE_IDENTITY_TYPE |
| `mh-013` | Receiver accepts `["oidc", "pinned_key"]`; same valid `pinned_key` identity: the positive control for `mh-010` and `mh-011` | success |
| `mh-014` | Receiver accepts `["oidc"]`; `pinned_key` proof over the wrong `pop_nonce` (id-006's envelope). Step 6 runs before step 8 | failure: IDENTITY_FAILED |

### Identity Binding (RFC-AITP-0002)

| ID | Description | Outcome |
|---|---|---|
| `id-001` | OIDC JWT missing `aud` claim | failure: IDENTITY_FAILED |
| `id-002` | OIDC JWT `aud` targets a different peer's AID | failure: IDENTITY_FAILED |
| `id-003` | OIDC JWT missing `cnf.jkt` claim | failure: IDENTITY_FAILED |
| `id-004` | Pinned-key proof captured from one handshake replayed against a different receiver/message/nonce | failure: IDENTITY_FAILED |
| `id-005` | Pinned-key legacy proof (pre-rc.3 binding) rejected | failure: IDENTITY_FAILED |
| `id-006` | Pinned-key proof signed over the wrong `pop_nonce` rejected (sender trusted; fails at §3.2 step 5) | failure: IDENTITY_FAILED |
| `id-007` | Pinned-key proof from an untrusted public key rejected (§3.2 step 3) | failure: IDENTITY_FAILED |
| `id-008` | OIDC identity descriptor also carries `public_key`, which RFC-AITP-0002 §1 forbids | failure: IDENTITY_FAILED |
| `id-009` | Identity descriptor carries an unrecognized, vendor-namespaced key inside `extensions` — ignored | success |
| `id-010` | P-256 pinned-key identity: 44-char compressed key, `p256.`-tagged proof (`kat-pinned-key-proof-002-p256`), sender trusted | success |
| `id-011` | The id-010 proof with its `p256.` tag stripped: read as Ed25519, an algorithm mismatch (RFC-AITP-0002 §3.1) | failure: IDENTITY_FAILED |
| `id-011b` | `oidc`-typed descriptor carrying `public_key` and a valid pinned proof: pinned verification MUST NOT run (§3.2 step 1; schema-invalid) | failure: IDENTITY_FAILED |
| `id-012` | P-256 `public_key` in the 87-char uncompressed form (§3.3; schema-invalid) | failure: IDENTITY_FAILED |
| `id-017` | Ed25519 pinned-key identity, sender trusted: the positive counterpart of `id-007` | success |
| `id-018` | `pinned_key` descriptor carrying `issuer`, which RFC-AITP-0002 §1 forbids (schema-invalid) | failure: IDENTITY_FAILED |
| `id-023` | OIDC identity from a P-256 sender: `cnf.jkt` is the RFC 7638 thumbprint of the EC JWK (`kat-jwk-thumb-005-p256`), per RFC-AITP-0002 §2.2.1 | success |
| `id-024` | *SPIFFE*: valid JWT-SVID from trust domain `prod.example.com` (RFC-AITP-0002 §6.3) | success |
| `id-025` | *SPIFFE*: valid X509-SVID; the leaf key (kat-keypair-003) is not the sender's AID key, and `proof` is `kat-spiffe-x509-proof-001` (§6.4) | success |
| `id-026` | *SPIFFE*: subject in `staging.example.com`, no bundle for it; the JWT-SVID is signed by the prod key (§6.2, §6.5 step 3) | failure: IDENTITY_FAILED |
| `id-027` | *SPIFFE*: JWT-SVID `nonce` is not the payload `pop_nonce` | failure: IDENTITY_FAILED |
| `id-028` | *SPIFFE*: JWT-SVID expired | failure: IDENTITY_FAILED |
| `id-029` | *SPIFFE*: JWT-SVID `aud` is another peer's AID (`agentD`) | failure: IDENTITY_FAILED |
| `id-030` | *SPIFFE*: X509-SVID leaf with two URI SANs, one matching (§6.4 step 2) | failure: IDENTITY_FAILED |
| `id-019` | Pinned-admission (RFC-AITP-0002 §3.4): `identity_presentation` answering an outstanding challenge, real proof, sender trusted | success |
| `id-013` | Pinned-admission: a consumed `pop_nonce` presented again under a fresh `message_id`, all signatures valid (sequence) | failure: IDENTITY_FAILED |
| `id-014` | Pinned-admission: a 15-byte `pop_nonce` with a proof valid over it, rejected before signature verification | failure: IDENTITY_FAILED |
| `id-015` | Pinned-admission: `id-019`'s presentation with `message_type` `mutual_hello`; the proof still verifies | failure: INVALID_ENVELOPE |
| `id-016` | Pinned-admission: outstanding-nonce bound 2; the third challenge is refused, not evicted, and both earlier nonces still present (dynamic sequence) | failure: CHALLENGE_REFUSED (step 3) |
| `id-020` | Pinned-admission: the nonce expired before `now`; fresh timestamp, real proof, sender trusted | failure: IDENTITY_FAILED |
| `id-021` | Pinned-admission: the nonce is outstanding but its challenge named another `verifier_aid`; real proof bound to `self_aid` | failure: IDENTITY_FAILED |
| `id-022` | Pinned-admission: a replay from a source that has used its rate-limit slot gets the deny-list outcome first; then HTTP 429, then the consumed nonce from a new source (sequence) | failure: REPLAY_DETECTED (step 2) |

The rows marked *Pinned-admission* are `status: extension` under `feature: aitp-pinned-admission`; a default runner SKIPs them. The rows marked *SPIFFE* are `status: draft` under `feature: experimental-spiffe-identity` (the `spiffe` type is at registry status Proposed); a default runner SKIPs them too.

### Trust Context Token (RFC-AITP-0005, RFC-AITP-0008)

| ID | Description | Outcome |
|---|---|---|
| `tct-002` | Expired peer-issued TCT rejected | failure: TCT_EXPIRED |
| `tct-003` | TCT JWS signature does not validate under the issuer's key | failure: TCT_SIGNATURE_INVALID |
| `tct-004` | TCT `jti` listed in the issuing peer's revocation list | failure: TCT_REVOKED |
| `tct-005` | TCT `exp` is after the issuing peer's Manifest `expires_at` (TCT itself not yet expired) | failure: TCT_EXPIRES_AFTER_MANIFEST |
| `tct-006` | Downstream PoP `pop_challenge` / `pop_response` exchange round-trips successfully | success |
| `tct-007` | A grant marked as requiring PoP MUST NOT be authorized without a valid `pop_response`; verifiers that silently skip PoP for a marked grant fail this fixture | failure: POP_RESPONSE_INVALID |
| `tct-008` | JWS header `alg: none` rejected before any signature work (RFC-AITP-0001 §5.4.5) | failure: TOKEN_ALG_MISMATCH |
| `tct-009` | ES256-signed token presented for an Ed25519 AID — AID-derived `alg` pin rejects | failure: TOKEN_ALG_MISMATCH |
| `tct-010` | Cryptographically valid grant voucher (`typ: aitp-grant+jwt`) presented as a TCT — explicit typing rejects | failure: TOKEN_TYP_MISMATCH |
| `tct-011` | TCT claims carry an unknown claim (`device_id`) outside `ext` | failure: UNKNOWN_FIELD |
| `tct-012` | TCT claims carry an unrecognized, vendor-namespaced key inside `ext` — ignored | success |
| `tct-013` | TCT `jti` is a UUID v7, not the UUID v4 layout (RFC-AITP-0005 §2.2) — rejected before signature verification | failure: TCT_SIGNATURE_INVALID |
| `tct-014` | TCT `jti` has version nibble `4` but wrong variant bits (`c`, not `8`–`b`) — rejected before signature verification | failure: TCT_SIGNATURE_INVALID |
| `tct-015` | Self-issued TCT (`iss == sub`) in a grant context (RFC-AITP-0005 §5.3) | failure: TCT_SIGNATURE_INVALID |
| `tct-016` | TCT with the `aitp.attestation` marker grant and `iss ≠ sub`, in a grant context (RFC-AITP-0005 §5.3) | failure: TCT_SIGNATURE_INVALID |
| `tct-018` | TCT with the `aitp.attestation` marker beside, and after, an ordinary grant (`iss ≠ sub`), in a grant context (RFC-AITP-0005 §5.3) | failure: TCT_SIGNATURE_INVALID |
| `tct-019` | Extension (`aitp-self-attestation`): otherwise valid self-attestation whose `ext` lacks the relying party's expected key (`verify_attestation`) | failure: TCT_SIGNATURE_INVALID |
| `tct-020` | Extension (`aitp-self-attestation`): `kat-tct-002` verified as an attestation by a third-party relying party; not a grant context (`verify_attestation`) | success |
| `tct-021` | Extension (`aitp-self-attestation`): `kat-tct-002` presented to a relying party whose records do not show the issuer key as trusted at `iat` (`verify_attestation`) | failure: TCT_SIGNATURE_INVALID |
| `tct-022` | Valid TCT checked against its issuer's snapshot, whose signature does not validate and which does not list the `jti`, under `fail_closed`: the snapshot is discarded and counts as absent (RFC-AITP-0008 §1.5, aitp-rs#271). Committed signed example and snapshot, signature bit flipped; nothing minted | failure: TCT_REVOKED |
| `tct-023` | Same as `tct-022` under `fail_open`: the discarded snapshot counts as absent, the token is allowed and the condition logged | success |
| `tct-024` | Valid TCT whose issuer has no revocation source (`issuer_revocation_list.available: false`), with no `fail_mode`, so the schema default `fail_closed` applies (RFC-AITP-0008 §1.4, §3.1). Committed signed example; nothing minted | failure: TCT_REVOKED |
| `tct-025` | Same as `tct-024` with an explicit `fail_open`: the token is allowed and the condition logged | success |
| `tct-026` | Committed TCT presented back to its issuer (`self_aid` = `iss`) with no `pop_response`, under an enforce-for-all PoP posture: a challenge is issued and the invocation is not authorized (RFC-AITP-0005 §10.5) | failure: POP_RESPONSE_INVALID |
| `tct-027` | Issuer-side check: the subject's valid `pop_response` answers a challenge that has expired (`verify_tct_as_issuer`) | failure: POP_CHALLENGE_INVALID |
| `tct-028` | Issuer-side check: a valid `pop_signature` by a key that is not the key in `sub` (`verify_tct_as_issuer`) | failure: POP_RESPONSE_INVALID |
| `tct-029` | Issuer-side success: `iss` is the verifier and `aud` = `sub` = the PoP-proven presenter AID; no expected audience is taken from the token (`verify_tct_as_issuer`) | success |
| `tct-017` | ES256 TCT whose signature is high-S (`S > n/2`): a stock JOSE verifier accepts it, an AITP verifier rejects it (RFC-AITP-0001 §5.4.7) | failure: TCT_SIGNATURE_INVALID |

### Grant voucher (RFC-AITP-0005 §8)

| ID | Description | Outcome |
|---|---|---|
| `vch-001` | Valid grant voucher verifies under the issuer's own key (typ, AID-pinned alg, signature, claims) | success |
| `vch-002` | Expired grant voucher rejected (surfaces as the delegation-context code per RFC-AITP-0006 §4 step 5) | failure: DELEGATION_EXPIRED |

### Revocation (RFC-AITP-0008)

| ID | Description | Outcome |
|---|---|---|
| `rev-001` | Stale revocation snapshot under `fail_closed` mode rejects the request | failure: TCT_REVOKED |
| `rev-002` | Stale revocation snapshot under `soft_fail` mode allows a configured safe-subset of grants | success (degraded) |
| `rev-003` | Fresh signed snapshot, JTI not in entries → not revoked | success |
| `rev-004` | TCT signature invalid → revocation source MUST NOT be consulted (asserts `side_effects.revocation_lookup_called == false`) | failure: TCT_SIGNATURE_INVALID |
| `rev-005` | Snapshot's `revocation_list` body carries an unknown member (`list_owner`) outside `extensions` | failure: UNKNOWN_FIELD |
| `rev-006` | Snapshot's `revocation_list` body carries an unrecognized, vendor-namespaced key inside `extensions` — ignored | success |
| `rev-007` | Snapshot's `revocation_list` body missing the REQUIRED `published_at` — structural rejection | failure: REVOCATION_SNAPSHOT_INVALID |
| `rev-008` | Snapshot signature does not validate under the issuing peer's key — the snapshot failed, not any token it lists | failure: REVOCATION_SNAPSHOT_SIGNATURE_INVALID |
| `rev-009` | Same stale snapshot as `rev-001`/`rev-002`, but under `fail_open` mode — allows the request, grants un-narrowed | success |
| `rev-010` | Committed signed snapshot with `version` changed to an unknown value after signing; structural validation runs before the signature check, and this is the snapshot's unknown-version code | failure: REVOCATION_SNAPSHOT_INVALID |
| `rev-011` | Fresh, correctly signed snapshot obtained for the TCT's issuer, but signed by a different AID (the committed kat-keypair-005-p256 snapshot); the TCT's `jti` is not listed. A snapshot is valid only for tokens its signer issued (RFC-AITP-0008 §1.5): it is discarded, and `fail_closed` applies. There is no third-party revocation authority in `aitp/0.3` | failure: TCT_REVOKED |

### Delegation (RFC-AITP-0006)

| ID | Description | Outcome |
|---|---|---|
| `del-001` | Single-hop happy path — A→B→C with scope ⊆ voucher.grants | success |
| `del-002` | Single-hop, otherwise identical to del-001, but `voucher.src_jti` is in A's own deny list (RFC-AITP-0006 §4 step 7, core path) | failure: DELEGATION_SOURCE_TCT_REVOKED |
| `del-003` | Scope exceeds the embedded voucher's grants | failure: DELEGATION_SCOPE_EXCEEDED |
| `del-004` | **Frozen in the v0.1 wire shape** (v0.1 runners only): a delegation token with a non-empty `chain` field MUST be rejected structurally, before any per-hop signature work | failure: DELEGATION_MULTIHOP_NOT_SUPPORTED |
| `del-005` | Embedded voucher signed by a third party (`voucher.iss` ≠ verifier's AID) | failure: DELEGATION_INVALID_VOUCHER |
| `del-006` | Voucher issued to a different subject (`voucher.sub` ≠ outer `iss`) | failure: DELEGATION_INVALID_VOUCHER |
| `del-007` | v0.2 sibling of del-004: claim-shaped token carrying a `chain` rejected structurally by core implementations | failure: DELEGATION_MULTIHOP_NOT_SUPPORTED |
| `del-008` | Same token as `del-002`, but A's own deny list, supplied as a signed snapshot, fails signature verification and does not list `src_jti`. A's own list is local state, so the mode does not apply and it is never treated as absent (RFC-AITP-0006 §4 step 7) | failure: REVOCATION_SNAPSHOT_SIGNATURE_INVALID |

### Multi-hop Delegation (RFC-AITP-0011, opt-in)

These fixtures exercise the multi-hop delegation extension. Core implementations MUST reject any token carrying a `chain` claim with `DELEGATION_MULTIHOP_NOT_SUPPORTED` (RFC-AITP-0006 §4); implementations that opt in follow RFC-AITP-0011 verification rules (chain of verbatim delegation JWS strings, digest-array `chain_hash`, per-hop `jti` revocation).

| ID | Description | Outcome |
|---|---|---|
| `del-mh-001` | 3-hop chain (A→B→C→D) — all JWS signatures, voucher on `chain[0]`, transitive scope, expiry monotonicity, and `chain_hash` valid | success |
| `del-mh-002` | Chain hop's scope exceeds the voucher boundary — transitive scope check rejects | failure: DELEGATION_SCOPE_EXCEEDED |
| `del-mh-003` | Chain with wrong `chain_hash` claim (signed over, so the outer signature is valid) — recomputation mismatches | failure: DELEGATION_CHAIN_HASH_MISMATCH |
| `del-mh-004` | A hop's `jti` is in that hop issuer's deny list (RFC-AITP-0011 §6 per-hop revocation) | failure: DELEGATION_SOURCE_TCT_REVOKED |
| `del-mh-005` | Same chain as del-mh-001, but `issuer_manifests` lists B and D and omits C, the issuer of `chain[1]`, so no supplied Manifest designates that hop's key (RFC-AITP-0011 §3 step 1) | failure: KEY_RESOLUTION_FAILED |
| `del-mh-006` | Same chain as del-mh-004, but B's snapshot no longer lists `chain[0].jti` and its signature does not validate: the snapshot is discarded and absent, and under the default `fail_closed` the hop counts as revoked (RFC-AITP-0011 §6, RFC-AITP-0008 §1.5) | failure: DELEGATION_SOURCE_TCT_REVOKED |

### Session Trust Bundle (RFC-AITP-0010, opt-in)

Bundle fixtures use the same opt-in posture as multi-hop. Core implementations are not required to support session bundles. Participant TCTs are embedded as opaque compact JWS strings.

| ID | Description | Outcome |
|---|---|---|
| `bundle-001` | 2-participant bundle, fresh, valid coordinator signature, receiver is in participants | success |
| `bundle-002` | Bundle is byte-valid but receiver's AID is not in `participants[*].aid` | failure: BUNDLE_NOT_MEMBER |
| `bundle-003` | Bundle's `expires_at` is in the past (with consistent embedded TCT expiry) | failure: BUNDLE_EXPIRED |
| `bundle-004-signature-sibling-rejected` | Old, now-invalid shape: `signature` is a sibling of the `session_bundle` wrapper instead of a member of the inner body | failure: SESSION_BUNDLE_INVALID |
| `bundle-005-extensions-accepted` | Bundle body carries an optional `extensions.tee` member (RFC-AITP-0010 §3 field table, RFC-AITP-0012) alongside a correctly-placed signature | success |
| `bundle-006-unknown-field-rejected` | Bundle's inner `session_bundle` body carries an unknown member (`coordinator_note`) outside `extensions` | failure: UNKNOWN_FIELD |
| `bundle-007` | Same bundle as bundle-001, but `coordinator_manifest` is a valid Manifest for a different AID, so no supplied Manifest designates the coordinator's key (RFC-AITP-0010 §5 step 5) | failure: KEY_RESOLUTION_FAILED |
| `bundle-008` | Committed signed bundle with `version` changed to an unknown value after signing; the step 1 version check runs before the step 6 signature check | failure: BUNDLE_VERSION_MISMATCH |

### A2A Agent Card binding (RFC-AITP-0014, opt-in)

These fixtures run the client-side binding of an A2A Agent Card to the agent's Manifest (`verify_a2a_agent_card_binding`, [`PLACEHOLDERS.md`](PLACEHOLDERS.md#operation-key)). Core implementations are not required to support it.

| ID | Description | Outcome |
|---|---|---|
| `a2a-001` | Unsigned Card naming B's AID and Manifest; the Manifest verifies and lists the selected interface | success |
| `a2a-002` | Card `params.aid` names C; the Manifest is B's (RFC-AITP-0014 §4.2 step 4) | failure: IDENTITY_FAILED |
| `a2a-003` | Card identity types, skills and description disagree with the Manifest; the Manifest's values are the effective ones (§4.3) | success |
| `a2a-004` | Card signature stipulated valid, Manifest unreachable; a Card signature does not replace the Manifest (§4.4) | failure: MANIFEST_NOT_FOUND |
| `a2a-005` | Card shadowing: the selected interface URL is not in the Manifest's `rfc-aitp-0014.a2a_interfaces` (§4.2 step 5) | failure: IDENTITY_FAILED |
| `a2a-006` | Card names the `ed25519:`-tagged form of the Manifest's legacy AID; the forms are equal (RFC-AITP-0001 §5.3) | success |

Additions and edge-case fixtures (replay during MUTUAL_COMMIT, identity-issuer key rotation, partial chain verification, etc.) are welcome via PR.

---

## Pre-v0.1 fixture renames

Earlier drafts of AITP used `hs-*` (handshake) fixture IDs. The Mutual Handshake restructure (RFC-AITP-0004) renamed them to `mh-*` and split a single happy-path into a dedicated success fixture. External citations of the old IDs map as follows:

| Old ID | New ID | Notes |
|---|---|---|
| `hs-001-oidc-direct-tct` | `mh-success-001` | Happy-path mutual handshake; OIDC identity is one of several success paths covered by `id-*` fixtures. |
| `hs-004-replay-rejected` | `mh-001` | Replayed `MUTUAL_HELLO` rejected via `REPLAY_DETECTED`. |

No `hs-*` IDs are reserved.

---

## Placeholder convention

Many fixtures contain string tokens of the form `__UPPER_SNAKE__`
(e.g. `__VALID_ENVELOPE_SIG__`, `__NOW__`,
`__JWT_MISSING_AUD_CLAIM__`). These are not literal values: they mark
positions where a minting tool must substitute real data
(signatures, timestamps, JWTs, captured-proof bytes) before the
fixture is fed to a conformance runner. Every placeholder used in this
directory is defined normatively in [`PLACEHOLDERS.md`](PLACEHOLDERS.md),
which also pins:

- The mapping from fixture role names (`agentA`, `agentB`, `agentC`,
  …) to the [pinned KAT keypairs](known-answer/keypairs.json).
- The reference clock for `__NOW__` (`1711900000`) so re-mints are
  byte-stable.
- The runner-facing `input.operation` registry per fixture id prefix.
- The pinned tamper recipe for `__TAMPERED_*__` (sign-then-flip-LSB
  of the last raw signature byte) so failure-injection placeholders
  reproduce.

The portable trust artifacts (TCT, grant voucher, delegation
token) are placeheld as **whole compact-JWS tokens** (`__JWS_*__`)
with decoded-claims companion fields per the claims-sibling convention
in PLACEHOLDERS.md. Real-signature reference artifacts (minted from
the pinned seeds, off-the-shelf JOSE-verifiable) live under
[`known-answer/signed-examples/`](known-answer/signed-examples/);
the fixture surface itself stays in placeholder form until the
implementation minting pass re-materializes it.
