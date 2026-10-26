# Conformance Fixture Placeholder Convention

The fixtures under `schemas/conformance/*.json` use string placeholders
of the form `__UPPER_SNAKE__` for values that a runner or minting tool
must materialize at execution time. This file is the normative
specification for those placeholders.

A minting tool (e.g. `aitp-rs`'s `mint-conformance-fixtures` script)
walks each fixture, identifies placeholders by name, substitutes real
values per the rules below, and writes the result. A conformance
runner that consumes already-minted fixtures MUST NOT see any of these
tokens — if it does, the fixture is not yet migrated.

## Naming rule

Placeholders MUST match the regex `^__[A-Z][A-Z0-9_]+__$`. The
double-underscore boundaries make placeholders trivially greppable and
unambiguous against any base64url, hex, or UUID alphabet.

A runner that cannot mint a placeholder MUST report that fixture as FAIL,
or as SKIP where the fixture's operation is one it legitimately does not
claim. It MUST NOT substitute a sentinel or dummy value and score the
result. A negative fixture that "passes" on an unminted value proves
nothing: the verifier rejected garbage, not the one defect the fixture
isolates. Every minted value is a real artifact that is one property away
from valid.

## Time placeholders

| Token | Meaning | Substitution |
|---|---|---|
| `__NOW__` | The runner's reference clock at execution time. | Unix seconds (integer). |
| `__NOW_MINUS_3600__` | One hour before `__NOW__`. | `__NOW__ - 3600` (integer). |
| `__NOW_PLUS_3600__` | One hour after `__NOW__`. | `__NOW__ + 3600` (integer). |
| `__NOW_PLUS_7200__` | Two hours after `__NOW__`. | `__NOW__ + 7200` (integer). Used by `tct-005` to put `tct.expires_at` past the issuer's `issuer_manifest.expires_at` (`__NOW_PLUS_3600__`) while keeping the TCT itself in the future. |

Additional `__NOW_MINUS_<seconds>__` and `__NOW_PLUS_<seconds>__`
tokens MAY be introduced as new fixtures need them; minting tools MUST
parse the trailing integer literally and substitute `__NOW__ ±
<seconds>`.

### Reference clock for byte-stable minting

Minting tools MUST anchor `__NOW__` to **`1711900000`** (the same
clock used by the rc.2 known-answer test vectors in
[`known-answer/jcs-sha256.json`](known-answer/jcs-sha256.json)).
Using the wall clock would produce different canonical bytes on every
mint; pinning `__NOW__` lets a re-mint be byte-stable across runs and
across implementations. Runners that consume already-minted fixtures
MUST treat the integer in the fixture as authoritative; they do not
compare it to wall time.

## AID role mapping

Most fixtures use placeholder AIDs of the form
`aid:pubkey:agent<X>_pubkey_AID_v01_placeholder_<X>...`. The minting
tool MUST replace these with the real AIDs derived from the pinned
known-answer keypairs. Fixtures keep the legacy untagged
`aid:pubkey:<43-char>` AID form (still valid in v0.3 per
RFC-AITP-0001 §5.3, implying Ed25519/`EdDSA`); P-256 fixtures use the
`aid:pubkey:p256:` form. The mapping is normative:

| Fixture role | KAT keypair | AID |
|---|---|---|
| `agentP256` (P-256 signer in `env-005`, the P-256 OIDC sender in `id-023`, and other ES256 fixtures) | [`kat-keypair-005-p256`](known-answer/keypairs.json) | `aid:pubkey:p256:<44-char identifier pinned in keypairs.json>` |
| `agentA` (initiator / TCT issuer in most fixtures) | [`kat-keypair-001`](known-answer/keypairs.json) | `aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik` |
| `agentB` (target / TCT subject) | [`kat-keypair-002`](known-answer/keypairs.json) | `aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg` |
| `agentC` (delegatee in single-hop, intermediate in multi-hop) | [`kat-keypair-003`](known-answer/keypairs.json) | `aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU` |
| `agentD` (final delegatee in multi-hop chains) | [`kat-keypair-004`](known-answer/keypairs.json) | `aid:pubkey:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w` |
| `issuingPeer` (alias of `agentA` in delegation fixtures) | `kat-keypair-001` | same as `agentA` |
| `worker_pubkey_AID_v01_placeholder_wwwwwwwww` (Manifest example) | `kat-keypair-002` | same as `agentB` |
| `verifier_pubkey_AID_v01_placeholder_vvvvvvv` / `victim_pubkey_AID_v01_placeholder_vvvvvvvvv` (verifier in `id-*`) | `kat-keypair-001` | same as `agentA` |
| `attacker_pubkey_AID_v01_placeholder_XXXXXXX` (`mh-002`) | [`kat-keypair-006-attacker`](known-answer/keypairs.json) — seed `0xAA` × 32 (**not** `0xff` × 32; that pattern is `kat-keypair-003`, a different, trusted-role AID — an earlier revision of this hint was wrong and unrecoverable, see issue #17). An UNTRUSTED non-role key published specifically so `mh-002` is independently re-mintable: RFC-AITP-0003 §5 verifies PoP before the signature, so reaching `mh-002`'s expected `MANIFEST_SIGNATURE_INVALID` requires a *valid* attacker PoP, which requires the attacker's private key. Tests trust-anchor + signature checks against an unknown peer. MUST NOT be added to any `trust_anchors` / `pinned_keys` fixture. | `aid:pubkey:5zTqbCtiV95yNV5HKqBaTEh-a0Y8Ap7TBt8vAbVja1g` |

Identity-issuer keys (the OIDC issuers used by `__VALID_JWT__` and
`__VALID_JWT_FROM_UNKNOWN_ISSUER__`) are NOT drawn from
`keypairs.json`, because they are issuer signing keys, not AIDs. They
are pinned in
[`known-answer/oidc-test-issuers.json`](known-answer/oidc-test-issuers.json).
The runner signs each OIDC JWT with the pinned seed and sends no issuer
key in the request. A fixture's `accepted_trust_anchors` / local
`trust_anchors` name issuers by URL only. An adapter's identity-issuer
resolver therefore maps `https://auth.openai.com` to
`kat-oidc-issuer-001`, reading the key from that file, and resolves no
other issuer. It MUST NOT copy the key from another implementation's
source.

The runner-minted OIDC test issuer is `https://auth.openai.com`, the
issuer of every `__VALID_JWT__` and OIDC `__JWT_*__` proof in the corpus
(the SPIFFE `__JWT_SVID_*__` proofs are not OIDC). When
a fixture states no `self_trust_anchors`, it is the only issuer the
verifier trusts (conformance README, "Receiver policy inputs").

The SPIFFE test authorities of the `spiffe` fixtures are minted at runtime
the same way: one P-256 JWT-SVID signing key (`ES256`, `kid`
`aitp-test-spiffe-jwt-1`) and one P-256 X.509 CA, self-signed, with
`cA` true and `keyCertSign`, both for trust domain `prod.example.com`.
`__TEST_SPIFFE_JWT_AUTHORITY_JWK__` and `__TEST_SPIFFE_X509_CA_JWK__` are
their public JWKs, with `use` `jwt-svid` and `x509-svid`, the CA JWK
carrying the CA certificate as its one `x5c` entry (SPIFFE Trust Domain
and Bundle §4, X509-SVID §6.1, JWT-SVID §6.1).

The exception is `__VALID_JWT_FROM_UNKNOWN_ISSUER__`. Its issuer key is
pinned so that minting is byte-stable across runners:
`kat-oidc-issuer-002-unknown` in
[`known-answer/oidc-test-issuers.json`](known-answer/oidc-test-issuers.json)
(seed `0x55` × 32, used by no entry in `keypairs.json`).
The key MUST NOT appear in any fixture's `accepted_trust_anchors` or
`trust_anchors`.

## Operation key

Every fixture carries a top-level `input.operation` string telling
the conformance runner which conformance op to invoke against the
implementation under test. The operation registry:

| Fixture id prefix | `input.operation` | Notes |
|---|---|---|
| `env-*` | `verify_envelope` | Single envelope verification. |
| `man-*` | `verify_manifest` | Standalone Manifest verification (RFC-AITP-0003 §5). |
| `tct-*` | `verify_tct` | Standalone TCT verification (RFC-AITP-0005 §7.2/§10). The `tct_token` input is a compact JWS string. MAY accept an `input.issuer_manifest` object (at minimum `{aid, expires_at}`) — when present, the runner supplies it to the verifier as the resolved issuing-peer Manifest so the §10.4 conditional Manifest-expiry bound check fires. When absent, the §10.4 check is skipped (per the RFC's "MAY be skipped when the issuer Manifest is unavailable" clause). `tct-005` exercises the present-Manifest path; other `tct-*` fixtures rely on §7.2/§10.1–§10.3 alone. `verify_tct` is a **grant context** (RFC-AITP-0005 §5.3): it evaluates the token as a capability grant to `expected_audience`. A self-issued TCT (`iss == sub`, `tct-015`) or one carrying the `aitp.attestation` marker grant (`tct-016`, and `tct-018` beside an ordinary grant) MUST fail it with `TCT_SIGNATURE_INVALID`. Verifying a self-attestation as an attestation is not a `verify_tct` operation; it is `verify_attestation`, below. |
| `tct-*` (attestation) | `verify_attestation` | Relying-party verification of a self-attestation (RFC-AITP-0005 §5.3, "Verification"), used by `tct-019`, `tct-020` and `tct-021`. This is **not** a grant context: `aud` need not equal the relying party's AID, and `iss == sub == aud` is the required shape. Inputs: `tct_token` (a placeholder minted by the `iss` key, or in `tct-020` and `tct-021` the committed `kat-tct-002` token), `tct_token_claims`, `self_aid` (the relying party), `expected_ext_key` (the `ext` key the relying party consumes), `trust_store` (the relying party's own record of issuer keys trusted at `iat`, per the RFC-AITP-0005 §7.3 exception; an issuer absent from it is not established as trusted at `iat`, and the attestation is rejected with `TCT_SIGNATURE_INVALID`, as in `tct-021`) and `waive_manifest_cap` (`true`: the relying party has decided explicitly to waive the Manifest cap, as §5.3 "Lifetime" requires when the issuer publishes no Manifest). The fixtures are `status: extension` under `feature: aitp-self-attestation`; a default runner SKIPs them, and an implementation that does not consume attestations reports SKIP. |
| `tct-*` (issuer side) | `verify_tct_as_issuer` | The issuer-side check of RFC-AITP-0005 §10.5, used by `tct-027`, `tct-028` and `tct-029`: the verifier receives back a TCT it issued, with one `pop_response` envelope answering a challenge it issued. Inputs: `self_aid` (the verifier, which is the token's `iss`), `tct_token` (the committed signed example `kat-keypair-001-issues-002`), `tct_token_claims`, `issuer_policy` (`pop_posture: "enforce-for-all"`, the posture that requires PoP for every grant, and `pop_required_grants`, which lists every grant in the token for a runner that configures PoP only per grant), `outstanding_pop_challenges`, an array of challenges the verifier has issued, each `{tct_jti, nonce, expires_at}`, which the runner MUST seed before the step, and `envelope`, the `pop_response`. The input carries no `expected_audience`: the verifier takes the expected audience only from the PoP-proven presenter AID (§10.5 item 5), and a runner MUST NOT supply one. The verifier runs §10.5 items 1 to 6. On success, `expected.presenter_aid` is the established presenter AID and `expected.grants` the authorized grants. `tct-026` uses the `tct-007` sequence operations below with the same `self_aid` and `issuer_policy` inputs. |
| `vch-*` | `verify_grant_voucher` | Standalone grant-voucher verification (RFC-AITP-0005 §8 / RFC-AITP-0006 §4 step 3): typ enforcement, AID-pinned alg, signature under the issuer's own key, claims checks. Inputs include `verifier_aid` (the voucher issuer's own AID). Voucher expiry surfaces as `DELEGATION_EXPIRED` (the voucher is only ever consumed in delegation context). |
| `del-*` | `verify_delegation_token` | Single-hop delegation verification (RFC-AITP-0006 §4). Inputs may include a `revocation_snapshots` array of `{issuer_aid, snapshot}` records — the same shape `del-mh-*` uses — that the runner MUST populate the deny list from before checking `voucher.src_jti` (RFC-AITP-0006 §4 step 7). Unlike `del-mh-*`, core §4 names exactly this one lookup: no per-hop sweep (there are no hops) and no independent voucher revocation handle (RFC-AITP-0008 §1.1). Inputs (except the frozen `del-004`) include `issuer_manifests`, an array of signed Manifest bodies from which the verifier resolves each hop issuer's key; it is the verifier's whole Manifest source (README, "Manifest inputs"). |
| `rev-*` | `verify_revocation_snapshot` or `verify_tct` | Revocation-layer fixtures. `rev-001`/`002`/`003` use `verify_revocation_snapshot` (RFC-AITP-0008 §1.5) to exercise the snapshot freshness / signature / lookup path directly. `rev-004` uses `verify_tct` (the standard TCT op) with `input.revocation_instrumented: true` and `expected.side_effects.revocation_lookup_called: false` to pin the RFC-AITP-0008 §3.3 ordering requirement — TCT signature verification MUST precede any network revocation lookup. Runners that cannot instrument the revocation source MUST SKIP the side-effect assertion (and thus the fixture, since it is core/required). |
| `id-*` | `verify_handshake_payload` | Verify a single inline-handshake `payload` (i.e. the result of step 6 in RFC-AITP-0004 §5.1). A pinned-key fixture's `input.trust_store` is the verifier's `pinned_keys` store, as an array of AID strings (the algorithm comes from each AID's tag); when absent the store is empty, and the runner MUST NOT seed trust of its own. See the conformance README's trust-store rule. A `spiffe` fixture (`id-024` to `id-030`, draft, `feature: experimental-spiffe-identity`) carries `input.trust_anchors_config`, whose `spiffe_bundles` is the verifier's whole SPIFFE bundle store (RFC-AITP-0002 §6.2); the runner configures the verifier to accept `spiffe` and MUST NOT add bundles of its own. An `id-*` fixture does not run the step 8 policy checks, so the pinned-key successes `id-010` and `id-017` state no receiver identity types; a runner whose implementation always runs step 8 configures the receiver to accept the fixture's identity type, as for `spiffe`. |
| `id-*` (pinned-admission, single envelope) | `verify_identity_presentation` | One-way pinned-key admission (OPTIONAL profile `pinned-admission`, RFC-AITP-0002 §3.4), used by `id-014`, `id-015`, `id-019`, `id-020` and `id-021`. The verifier checks one `identity_presentation` envelope in the §3.4 check order. Inputs: `self_aid` (the verifier, which is also the proof's `receiver`), `trust_store` (as above), `outstanding_challenges`, an array of challenges the verifier has issued and not yet consumed, each `{pop_nonce, verifier_aid, expires_at}` (the informative challenge format of §3.4), and optionally `now` (the verifier's clock; when absent, the reference clock `__NOW__`). The runner MUST seed the verifier's outstanding-nonce store from `outstanding_challenges` before the step, including an entry whose `verifier_aid` is not `self_aid` (`id-021`: a deployment operating several verifier AIDs over one store). Every pinned-admission fixture is `status: extension` under `feature: aitp-pinned-admission`: a default runner SKIPs it, and an implementation that does not claim the profile reports SKIP. |
| `id-*` (pinned-admission, multi-step `sequence`) | per-step in the sequence | Used by `id-013` (nonce reuse), `id-016` (outstanding-nonce bound) and `id-022` (deny list before rate limit). `verify_identity_presentation` is as above, with state carried across steps: a nonce consumed in one step stays consumed. State carries only across the steps of one fixture: each fixture starts from fresh verifier state, with no deny-list, nonce-store or rate-limit state from another fixture ([README, Multi-step `sequence` form](README.md#multi-step-sequence-form)). `issue_presentation_challenge` asks the verifier for a new challenge on behalf of the client at the step's `source` address. On success the runner records the issued nonce as `__ISSUED_NONCE_<n>__`, where `n` counts successful issues in the fixture (1, 2, …). Fixture-level `max_outstanding_nonces` is the verifier's bound on outstanding nonces, and the runner MUST configure it. In `id-016` the per-source rate limit MUST NOT trigger: every issuing step uses a distinct `source`. A `verify_identity_presentation` step MAY also carry `source`, the client address the presentation arrives from. Fixture-level `presentation_rate_limit` (`{per_source, window_seconds}`) is the verifier's per-source limit on presentations (RFC-AITP-0009 §3.1), and the runner MUST configure it when present; when absent, the fixture assumes a limit it never reaches. A step refused by the rate limit expects `{"outcome": "failure", "http_status": 429}` with no `error_code`, because a rate-limited request never reaches the protocol layer and gets no AITP error envelope. Within the pinned-admission profile the status is exactly 429: RFC-AITP-0002 §3.4 makes it a MUST, tightening the SHOULD of RFC-AITP-0009 §3.1. |
| `mh-*` (single-message) | `verify_handshake_payload` | As above, except that the runner runs the step the fixture's `step` names through its policy step: RFC-AITP-0004 §5.1 step 8 for a received MUTUAL_HELLO, which an `id-*` fixture stops short of. The receiver's policy comes from `input.self_accepted_identity_types` (when absent, the default `["oidc"]`, and the runner MUST NOT add types of its own) and `input.self_trust_anchors` (README, "Receiver policy inputs"). `trust_store` is as above. || `mh-*` (multi-step `sequence`) | per-step in the sequence | Each `sequence[i]` carries its own `operation`; typical values are `start_handshake` and `process_handshake_message`. |
| `tct-*` (multi-step `sequence`) | per-step in the sequence | Used by `tct-006` (downstream PoP exchange), `tct-007` (PoP enforcement) and `tct-026` (PoP enforcement by the issuer, RFC-AITP-0005 §10.5). Operations for `tct-006`: `issue_pop_challenge` (verifier produces a `pop_challenge` envelope), `produce_pop_response` (holder signs `sha256(base64url_decode(nonce))` with the subject key bound via `cnf.jkt` and emits a `pop_response` envelope), `verify_pop_response` (verifier checks envelope signature, `nonce_echo`, and `pop_signature` per RFC-AITP-0005 §6.2). Operations for `tct-007`: `authorize_capability_invocation` (verifier receives a capability invocation against a grant the issuing peer marks as PoP-required; verifier SHOULD respond by issuing a `pop_challenge`), `expect_pop_challenge_issued` (no-op step that asserts the verifier instrumentation observed a `pop_challenge` envelope being emitted; uses the `side_effects.pop_challenge_issued` assertion), `withhold_pop_response` (test harness deliberately does NOT return a `pop_response`; verifier MUST reject the original invocation with `POP_RESPONSE_INVALID` and MUST NOT authorize the capability — asserted via `side_effects.capability_authorized: false`). |
| `del-mh-*` | `verify_delegation_token` | Multi-hop delegation verification (RFC-AITP-0011 §3-§6). Inputs may include a `revocation_snapshots` array of `{issuer_aid, snapshot}` records that the runner MUST populate per-hop deny lists from before checking `voucher.src_jti` (and per-hop `jti`) revocation. Implementations that do not opt into RFC-AITP-0011 MUST return `DELEGATION_MULTIHOP_NOT_SUPPORTED` for any token carrying a `chain` claim. Inputs include `issuer_manifests`, an array of signed Manifest bodies, one per hop issuer the fixture means to resolve; a hop issuer with no matching Manifest fails with `KEY_RESOLUTION_FAILED` (README, "Manifest inputs"). |
| `bundle-*` | `verify_session_bundle` | Session Trust Bundle verification (RFC-AITP-0010 §5). Inputs include `self_aid` (the receiving participant), `now` (reference clock) and `coordinator_manifest`, the signed Manifest from which the verifier resolves the coordinator's key (README, "Manifest inputs"). Core (non-opted-in) implementations report `SKIP` rather than `FAIL` when this operation is encountered. |
| `a2a-*` | `verify_a2a_agent_card_binding` | A2A Agent Card binding (RFC-AITP-0014 §4.2 steps 1–5). Inputs: `self_aid` (the A2A client), `now`, `agent_card` (an A2A 1.0.0 AgentCard as fetched), `selected_interface_url` (the AgentInterface `url` the client intends to call), and either `manifest` (the Manifest body fetched from the Card's `params.manifestUrl`, minted as for `man-*`) or `manifest_fetch` (`{url, status}`, a fetch outcome such as `network_error`). `card_signature_valid: true` stipulates that the A2A card-signature check passes; the runner does not verify the illustrative `signatures` value. On success, `expected.effective` lists the values the client must use (RFC-AITP-0014 §4.3). The runner MUST NOT fetch anything. The fixtures are `status: draft` under `feature: aitp-a2a-agent-card`; core implementations report `SKIP`. |

A runner that encounters an unknown `operation` MUST return SKIP
rather than FAIL — that lets an implementation under test
self-document which conformance ops it does and does not support
without breaking the rest of the run.

## Signature placeholders (JCS-profile artifacts)

The minting tool produces real signatures using the
[known-answer keypairs](known-answer/keypairs.json). Every signature
placeholder in this table is replaced with the unpadded base64url
encoding of the signature over the appropriate canonical input
(RFC-AITP-0001 §5.4.1). Every signature hashes its input once
(RFC-AITP-0001 §5.4.6): a P-256 signature is ECDSA with `e = sha256(input)`,
never `sha256(sha256(input))`, and is emitted low-S (§5.4.7). These tokens apply to **JCS-profile**
artifacts only (envelopes, Manifests, revocation snapshots, handshake
payloads); the compact-JWS artifacts use the whole-token family in
the next section.

| Token | Signing key | Signing input |
|---|---|---|
| `__VALID_ENVELOPE_SIG__` | Sender's pinned signing key | Envelope signing input per RFC-AITP-0001 §5.4: `sig_input_v2` = `aitp-envelope-v2` ‖ `0x00` ‖ JCS(envelope without `signature`), so the signature covers every other member, `extensions` included, exactly as the fixture carries them after substitution. In `env-005` (P-256 sender) the value is committed rather than minted: substitute the `signature` of [`signed-examples/envelope/kat-keypair-005-envelope.json`](known-answer/signed-examples/envelope/kat-keypair-005-envelope.json) (`kat-envelope-001-p256`), whose envelope is otherwise identical to the fixture's. `env-007` carries no placeholder: its literal `signature` is that of [`signed-examples/envelope/kat-keypair-001-envelope.json`](known-answer/signed-examples/envelope/kat-keypair-001-envelope.json) (`kat-envelope-002-ed25519`, signed by kat-keypair-001), and `env-008`, `env-009` and `env-010` carry the same literal signature over an envelope changed after signing. `env-011` carries its own literal signature, kat-keypair-001's valid signature over its `aitp/0.2` envelope. A runner MUST NOT re-mint any of these five. |
| `__VALID_MANIFEST_SIG__` | Manifest agent's signing key | JCS canonical **inner** Manifest body excluding `signature` — never the `{"manifest": …}` wrapper (RFC-AITP-0003 §6.1) |
| `__VALID_POP_SIG__` | Manifest agent's signing key | `sha256(decoded_bytes(challenge))` (RFC-AITP-0003 §3.1) |
| `__VALID_A_SIG__` | Initiating peer (A)'s signing key | Resolved from the enclosing artifact, per the table below — **never** "whatever the minting tool decides". |
| `__VALID_B_SIG__` | Target peer (B)'s signing key | Same resolution table, signed by B. |
| `__LEGACY_PINNED_PROOF__` | Pinned-key holder's signing key (legacy two-field input) | Pre-v0.1 pinned-key proof signed over the two-field input `message_id`, a literal pipe, then `timestamp` (no domain prefix, no receiver, no `pop_nonce`). Used by `id-005` to assert rejection when the verifier replays the five-field reconstruction (RFC-AITP-0002 §3.1). The signing form is pinned to [RFC-AITP-0001 §5.4.6](../../rfcs/RFC-AITP-0001-core.md#546-signing-primitive-per-algorithm-jcs-profile-and-proofs): `base64url(Ed25519(SHA-256(input)))`, encoded as [RFC-AITP-0002 §3.1](../../rfcs/RFC-AITP-0002-identity.md) encodes any pinned-key proof, where `input` is the ASCII bytes of `message_id`, `\|`, then `timestamp` in decimal. The signer is the pinned key the fixture presents (`kat-keypair-003` in `id-005`). The legacy input is then the only defect, so the failure surfaces only at the input-reconstruction step, not at base64url decode or at the hash step. |
| `__VALID_JWT__` | Identity issuer's key | Compact JWT serialization with claims pinned by the surrounding fixture context: `iss`/`sub` from the `identity` descriptor, `aud` = fixture `self_aid`, `nonce` = the sibling payload `pop_nonce`, and `cnf.jkt` = the RFC 7638 thumbprint of the presenting agent's AID key (`manifest.aid`, which equals the envelope sender) in that AID's own algorithm form (RFC-AITP-0002 §2.2.1): the OKP JWK for an Ed25519 AID, the EC JWK with the decompressed point's `x`/`y` for a P-256 AID. There is no separate P-256 variant of the token; `id-023` (`agentP256` sender, expected `cnf.jkt` = `kat-jwk-thumb-005-p256`) is minted by the same recipe. The `__JWT_*__` failure variants below use the same derivation for every claim they do not break. |
| `__VALID_JWT_FROM_UNKNOWN_ISSUER__` | Untrusted issuer's key | Same shape as `__VALID_JWT__` but signed by an issuer NOT in the verifier's `trust_anchors`. The signature is cryptographically valid; the policy check is what fails. |
| `__VALID_NONCE__` | n/a | Random 128-bit base64url string (22 chars, unpadded). The minting tool MAY use a per-fixture deterministic seed for reproducibility. |
| `__VALID_NONCE_ECHO__` | n/a | The exact `__VALID_NONCE__` value from the corresponding earlier message in the same handshake. |
| `__ISSUED_NONCE_1__`, `__ISSUED_NONCE_2__` | n/a | The `pop_nonce` the verifier returned from the first and second successful `issue_presentation_challenge` steps of the same fixture (`id-016`). The verifier chooses the nonce, so the value is never minted ahead of time: the runner captures it at the issuing step and substitutes it into the later `verify_identity_presentation` step that carries the token. |
| `__VALID_PINNED_PROOF__` | Pinned-key holder's signing key (the key in the presenter's AID) | The pinned-key proof of RFC-AITP-0002 §3.1 over the step's own envelope: `sender` = envelope `sender.agent_id`, `receiver` = fixture `self_aid`, the envelope's `message_id` and `timestamp`, and the decoded payload `pop_nonce` after substitution. It cannot be minted before the run, because the nonce is issued at run time. |
| `__VALID_JWT_SVID__` | The SPIFFE test JWT-SVID authority (`ES256`, `kid` `aitp-test-spiffe-jwt-1`) | A JWT-SVID (RFC-AITP-0002 §6.3) with protected header exactly `{"alg":"ES256","kid":"aitp-test-spiffe-jwt-1","typ":"JWT"}`, `sub` = `identity.subject`, `aud` = fixture `self_aid` as a one-element array, `iat` = `__NOW__`, `exp` = `__NOW_PLUS_300__`, `nonce` = the payload `pop_nonce`, and `cnf.jkt` = the RFC 7638 thumbprint of the sender AID key (RFC-AITP-0002 §2.2.1). The `__JWT_SVID_*__` failure variants below use the same recipe for everything they do not break. |
| `__X509_SVID_LEAF__` | The SPIFFE test X.509 CA | A DER X509-SVID in standard base64: issued by the test CA, one URI SAN = `identity.subject`, `cA` false, key usage `digitalSignature` only, validity `__NOW_MINUS_60__` to `__NOW_PLUS_3600__`, subject public key kat-keypair-003's Ed25519 key (the leaf key of `kat-spiffe-x509-proof-001`). |
| `__VALID_X509_SVID_PROOF__` | The X509-SVID leaf key (kat-keypair-003) | The RFC-AITP-0002 §6.4.1 proof over the fixture's own envelope: `sender` = envelope `sender.agent_id`, `receiver` = fixture `self_aid`, the envelope's `message_id` and `timestamp`, and the decoded payload `pop_nonce`. Untagged Ed25519, single hash. |
| `__VALID_DOWNSTREAM_POP_SIG__` | TCT subject's signing key (the holder; the key encoded in the TCT's `sub` AID) | `sha256(base64url_decode(nonce))` where `nonce` is the `__VALID_NONCE__` issued by the verifier in the matching `pop_challenge` (RFC-AITP-0005 §6.1). Same convention as `__VALID_POP_SIG__`; named separately to disambiguate the downstream PoP exchange from Manifest PoP in fixtures that include both. |

### Resolving `__VALID_A_SIG__` / `__VALID_B_SIG__`

These two placeholders appear in more than one kind of artifact, so the signing
input depends on which artifact encloses them. It is **fully determined** by that
artifact — it is not a minting-tool choice. An earlier revision of this file
described them as "context-dependent … minting tool resolves from surrounding
fixture shape," which licensed two minting tools to pick different conventions.
Both then verified their own output and passed, while their wire formats
disagreed. That is exactly how the revocation and session-bundle signing inputs
diverged between implementations (see the signing-input entry in
[`CHANGELOG.md`](../../CHANGELOG.md)).

| Enclosing artifact | Signing input |
|---|---|
| `snapshot` (a `{"revocation_list": …, "signature": …}` object) | JCS canonical form of the **inner `revocation_list` body**. The `signature` is a sibling of the body, not a member of it, so nothing is removed before canonicalizing. RFC-AITP-0008 §1.5. |
| `session_bundle` (a `{"session_bundle": …}` object) | JCS canonical form of the **inner `session_bundle` body**, excluding its `signature` member. RFC-AITP-0010 §3. |
| an envelope | The envelope signing input of RFC-AITP-0001 §5.4: the 16 ASCII bytes `aitp-envelope-v2`, one `0x00` byte, then JCS of the whole envelope minus `signature` (`extensions` included). Not the bare JCS form, and not the retired pipe-composed string. |

**General rule for every JCS-profile artifact carried inside an artifact-name
wrapper** (`{"manifest": …}`, `{"revocation_list": …}`, `{"session_bundle": …}`):
the wrapper key is transport routing metadata and is never part of the signing
bytes (RFC-AITP-0001 §5.4.1). Sign the inner body; add the wrapper only when
transmitting. A minting tool that canonicalizes the wrapper produces artifacts
that verify only against itself.

Pinned signing inputs for all three live in
[`known-answer/jcs-sha256.json`](known-answer/jcs-sha256.json), each declaring
`signing_input: "body"`, and are executed by `make kat-verify`.

`tct-022` and `tct-023` carry no placeholder either. Their snapshot is the body of
[`signed-examples/revocation/kat-keypair-001-snapshot.json`](known-answer/signed-examples/revocation/kat-keypair-001-snapshot.json)
with that example's committed signature after the `__TAMPERED_SIGNATURE__` bit flip,
and their `tct_token` is the committed `signed-examples/tct/kat-keypair-001-issues-002.json` token. A runner MUST NOT re-mint either.

`rev-010` and `bundle-008` carry no `__VALID_A_SIG__`: their literal `signature`
is that of the committed signed example
([`signed-examples/revocation/kat-keypair-001-snapshot.json`](known-answer/signed-examples/revocation/kat-keypair-001-snapshot.json),
[`signed-examples/session-bundle/kat-keypair-001-bundle.json`](known-answer/signed-examples/session-bundle/kat-keypair-001-bundle.json)),
over a body whose `version` was changed after signing. A runner MUST NOT
re-mint either: a fresh signature would cover the changed `version`, and the
fixture would no longer show that the version check runs before the signature
check.

**Retired in v0.2** (used only by fixtures frozen in the v0.1 token
shape, e.g. `del-004`): `__VALID_TCT_SIG__`,
`__VALID_ISSUING_PEER_SIG__`, `__VALID_GRANT_PROOF_SIG__`. The v0.2
TCT and delegation token are compact JWS strings — there is no
embedded signature field to substitute. Minting tools MUST still
recognize these tokens when minting the frozen v0.1 fixtures.

## Compact-JWS token placeholders (portable trust artifacts)

The TCT, grant voucher, and delegation token are opaque compact
JWS strings (RFC-AITP-0001 §5.4.5). They are placeheld as **whole
tokens**, not per-field signatures.

**Claims-sibling convention.** A string field `X` whose value is a
`__JWS_*__` token MUST have a sibling field `X_claims` (same JSON
object level) carrying the decoded payload claims to mint. The minter:

1. resolves `__JWS_*__` tokens **innermost-first** (a delegation's
   claims may contain `"voucher": "__JWS_GRANT_VOUCHER__"` with its own
   `voucher_claims` sibling inside the claims object);
2. removes each `*_claims` companion from the claims object before
   serializing the payload (the companions are minting inputs, never
   wire bytes);
3. builds the protected header as exactly `{"alg": <derived from the
   claims' iss AID per RFC-AITP-0001 §5.4.5>, "typ": <per the token
   kind below>}` unless the token variant says otherwise;
4. signs with the keypair mapped to the `iss` AID (AID role table
   above);
5. substitutes the compact string and leaves the **top-level**
   `X_claims` sibling in place in the fixture for auditability —
   runners MUST ignore `*_claims` fields when present at the fixture
   `input` level.

| Token | `typ` | Recipe |
|---|---|---|
| `__JWS_TCT__` | `aitp-tct+jwt` | Standard mint from the claims sibling. |
| `__JWS_GRANT_VOUCHER__` | `aitp-grant+jwt` | Standard mint. When this token is placed in a field a verifier treats as a TCT (e.g. `tct-010`), the expected outcome is `TOKEN_TYP_MISMATCH`. |
| `__JWS_DELEGATION__` | `aitp-delegation+jwt` | Standard mint; resolves a nested `voucher` placeholder first. |
| `__JWS_TCT_TAMPERED_SIG__` | `aitp-tct+jwt` | Mint normally, then flip the **least-significant bit of the last raw signature byte** before base64url-encoding the third segment (same recipe as `__TAMPERED_SIGNATURE__`). Expected: `TCT_SIGNATURE_INVALID`. |
| `__JWS_DELEGATION_TAMPERED_SIG__` | `aitp-delegation+jwt` | Same tamper recipe on the outer delegation JWS. Expected: `DELEGATION_INVALID_SIGNATURE`. |
| `__JWS_VOUCHER_TAMPERED_SIG__` | `aitp-grant+jwt` | Same tamper recipe on the embedded voucher JWS. Expected: `DELEGATION_INVALID_VOUCHER`. |
| `__JWS_TCT_ALG_NONE__` | `aitp-tct+jwt` | Header `{"alg":"none","typ":"aitp-tct+jwt"}`; payload from the claims sibling; third segment = base64url of 64 zero bytes (86 chars, so the failure is the `alg` check, not segment syntax). Expected: `TOKEN_ALG_MISMATCH`. |
| `__JWS_TCT_WRONG_ALG__` | `aitp-tct+jwt` | Header `{"alg":"ES256","typ":"aitp-tct+jwt"}` while the `iss` AID is Ed25519; sign with the `iss` Ed25519 key over the signing input (deterministic bytes; the signature is never checked because the `alg` pin rejects first). Expected: `TOKEN_ALG_MISMATCH`. |
| `__ANY_JWS__` | n/a | Any syntactically valid three-segment compact JWS; used for fields a fixture never verifies because rejection happens earlier (e.g. `chain` entries in the core multi-hop structural rejection). RECOMMENDED: a real `__JWS_DELEGATION__` mint so cross-fixture minter paths stay uniform. |
| `__COMPUTED_CHAIN_HASH__` | n/a | The correct RFC-AITP-0011 §5 digest-array `chain_hash` over the minted `chain` JWS strings. Cannot be pinned in the fixture (it depends on the minted bytes); the minter MUST compute it after resolving every chain entry. Distinct from the ignored-value `__ANY_CHAIN_HASH__`, which marks a hash no verifier checks. Used by `del-mh-001/002/004`. |

**Array extension of the claims-sibling rule.** A `chain` claim is an
array of `__JWS_DELEGATION__` tokens with an equal-length sibling
`chain_claims` array at the same level inside the outer token's claims
object; `chain_claims[i]` is the decoded claims for `chain[i]` and may
itself contain a nested `voucher`/`voucher_claims` pair (resolved
innermost-first). Likewise, a session-bundle participant entry carries
`"tct": "__JWS_TCT__"` with a `tct_claims` sibling inside the same
participant object. The minter strips every `*_claims` companion before
serializing/signing wire bytes — note the session-bundle schema's
`additionalProperties: false` on participant entries makes this
mandatory, not just conventional. In handshake fixtures,
`__VALID_NONCE_ECHO__` inside a received payload resolves to the
`__VALID_NONCE__` minted for the same peer block's `self_pop_nonce_*`
field.

## Failure-injection placeholders

These represent values that look well-formed but trigger a specific
failure path. The minting tool produces them by manipulating a
known-good signed object — the surrounding fixture documents which
property should be broken.

| Token | What's broken | Expected error path |
|---|---|---|
| `__TAMPERED_SIGNATURE__` | Sign properly, then flip the **least-significant bit of the last raw signature byte** before base64url-encoding. | `MANIFEST_SIGNATURE_INVALID` (manifest), `INVALID_SIGNATURE` (envelope), `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` (revocation snapshot — `rev-008`, and `del-008` for A's own deny list). The expected code is per-artifact: the snapshot's own code, not the `TCT_SIGNATURE_INVALID` implementations previously borrowed for it (issue #39). Where the tampered snapshot is a hop issuer's fetched snapshot inside a larger decision (`del-mh-006`), it is discarded and the fixture expects the policy outcome instead (RFC-AITP-0008 §1.5). |
| `__TAMPERED_SIG__` | Same recipe; shorter alias used by older fixtures. | `TCT_SIGNATURE_INVALID`. |

The tamper recipe is pinned so re-mints reproduce byte-for-byte. Any
implementation that mutates a different bit will produce a different
signature string and break cross-mint determinism.
| `__INVALID_POP_SIG__` | PoP signature over the wrong input (e.g. the wrong challenge). | `MANIFEST_POP_FAILED`. |
| `__INVALID_POP_SIG_OVER_WRONG_NONCE__` | PoP signature whose input used a different `pop_nonce` than the receiving peer expects. | `POP_VERIFICATION_FAILED`. |
| `__PINNED_PROOF_OVER_WRONG_NONCE__` | Ed25519 RFC-AITP-0002 §3.1 pinned-key proof over a `pop_nonce` other than the envelope's, every other proof-input field matching the fixture. Signed by the sender's pinned key, which the fixture's `trust_store` contains, so §3.2 steps 1–3 pass and only step 5 fails. Used by `id-006`. | `IDENTITY_FAILED`. |
| `__JWT_MISSING_AUD_CLAIM__` | Otherwise-valid OIDC JWT with the `aud` claim removed. | `IDENTITY_FAILED`. |
| `__JWT_AUD_TARGETS_DIFFERENT_PEER__` | OIDC JWT whose `aud` is some other peer's AID: pinned to `kat-keypair-004`'s AID (`agentD`), so minting is byte-stable across runners. | `IDENTITY_FAILED`. |
| `__JWT_MISSING_CNF_JKT_CLAIM__` | OIDC JWT with `cnf.jkt` removed. | `IDENTITY_FAILED`. |
| `__JWT_SVID_WRONG_NONCE__` | `__VALID_JWT_SVID__` with `nonce` = `YWl0cC1zcGlmZmUtand0OQ` (the 16 bytes `aitp-spiffe-jwt9`), not the payload `pop_nonce`. Used by `id-027`. | `IDENTITY_FAILED`. |
| `__JWT_SVID_EXPIRED__` | `__VALID_JWT_SVID__` with `iat` = `__NOW_MINUS_360__` and `exp` = `__NOW_MINUS_60__`. Used by `id-028`. | `IDENTITY_FAILED`. |
| `__JWT_SVID_AUD_DIFFERENT_PEER__` | `__VALID_JWT_SVID__` with `aud` = `[` `kat-keypair-004`'s AID (`agentD`) `]`. Used by `id-029`. | `IDENTITY_FAILED`. |
| `__JWT_SVID_STAGING_SUBJECT_PROD_KEY__` | `__VALID_JWT_SVID__` with `sub` = `identity.subject` (in trust domain `staging.example.com`), still signed by the `prod.example.com` authority key under its `kid`. Used by `id-026`: the verifier has no bundle for the subject's trust domain. | `IDENTITY_FAILED`. |
| `__X509_SVID_LEAF_TWO_URI_SANS__` | `__X509_SVID_LEAF__` with a second URI SAN, `spiffe://prod.example.com/ns/payments/sa/other`, after the first. Used by `id-030`. | `IDENTITY_FAILED`. |
| `__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__` | A pinned-key proof signed over a *different* (sender, receiver, message_id, timestamp, pop_nonce) tuple than the one in this fixture. Tests cross-peer replay (RFC-AITP-0002 §3.1). | `IDENTITY_FAILED`. |

## Ignored-value placeholders (structural-rejection fixtures)

A small set of placeholders mark fields whose value is never inspected
by a v0.1 implementation because the fixture rejects on an earlier
structural check. The minting tool MUST still emit a syntactically
valid value (so the fixture passes JSON-schema and length validation),
but the bytes are not required to be cryptographically meaningful —
no signature is verified against them.

| Token | Field | Why it's ignored | Minter substitution |
|---|---|---|---|
| `__ANY_CHAIN_STEP_SIG__` | `delegation.chain[i].signature` (v0.1 shape) | v0.1-frozen fixture only (`del-004`): v0.1 implementations reject any delegation token with a non-empty `chain` field at the structural check before any per-hop signature work. | Any 86-char unpadded base64url string. RECOMMENDED: a real Ed25519 signature under `kat-keypair-001` over the JCS-canonical chain-step body, so the same minter path produces it. |
| `__ANY_CHAIN_HASH__` | `chain_hash` | `chain_hash` is recomputed during multi-hop verification, which a core (non-opted-in) implementation never reaches. Used by `del-004` (v0.1 shape) and the v0.2 structural-rejection sibling. | Any 43-char unpadded base64url (32 bytes); RECOMMENDED: the correctly computed hash so the value is internally consistent even though no verifier checks it. |
| `__ANY_DELEGATION_SIG__` | outer `delegation.signature` (v0.1 shape) | v0.1-frozen fixture only (`del-004`): the outer signature is not verified before the structural rejection. | Any 86-char unpadded base64url string; RECOMMENDED: a real Ed25519 signature so cross-fixture minter paths stay uniform. |
| `__ANY_JWS__` | `chain[i]` entries (v0.2 and later shape) | Core v0.3 implementations reject any delegation token carrying a `chain` claim with `DELEGATION_MULTIHOP_NOT_SUPPORTED` before processing entries. | See the compact-JWS table above. |

A runner that exercises the multi-hop opt-in (`feature:
experimental-multihop-delegation`) does verify these fields and uses
the `del-mh-*` fixture set, where the equivalent fields are real
minted compact JWS strings rather than the `__ANY_*__` ignored
variants.

## Adding new placeholders

A new placeholder requires:

1. A row in this file (table above + a one-line description of what it
   represents).
2. A minting-tool implementation that materializes it.
3. A test in the runner that asserts the substituted value still
   triggers the documented expected outcome.

Placeholders MUST NOT shadow real protocol values. Specifically, no
fixture field whose schema requires a fixed-length base64url or UUID
may be filled with an `__UPPER_SNAKE__` token at runtime — minting MUST
happen before validation.

## Stability

The placeholder table is **versioned with the protocol**. The v0.1
names remain frozen for the fixtures that stay in the v0.1 token shape
(`del-004` and the historical record); they are never renamed, only
retired. The v0.2 additions are the compact-JWS token family above.
Renaming any active placeholder requires the RFC process; new names
can be added freely. A minting tool that does not recognize a
placeholder MUST fail fast rather than emit the literal string, since
unsubstituted placeholders would slip past schema validation only to
produce confusing runtime failures.
