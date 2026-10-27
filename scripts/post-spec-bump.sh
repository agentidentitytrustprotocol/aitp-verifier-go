#!/usr/bin/env bash
#
# post-spec-bump.sh: everything a SPEC_VERSION bump PR must regenerate,
# run by bump-spec.yml after the pin is rewritten.
#
#   1. testdata/spec from the new pin (scripts/sync-spec.sh);
#   2. errors.go from its registry (go generate);
#   3. the adapter test transcript, which records the runner's concrete
#      requests at the pin. That needs aitp-conformance, built here from
#      AITP_RS_COMMIT with the runner's cargo.
#
# Step 3 is best effort: when the runner cannot be built, or the adapter
# fails the new fixtures, the PR still opens (its CI then shows the
# failure to the reviewer) with the old transcript and a warning.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

scripts/sync-spec.sh
go generate ./...

RS="$(tr -d '[:space:]' < AITP_RS_COMMIT)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if git -C "$WORK" init -q rs &&
    git -C "$WORK/rs" fetch -q --depth 1 https://github.com/agentidentitytrustprotocol/aitp-rs.git "$RS" &&
    git -C "$WORK/rs" checkout -q FETCH_HEAD &&
    cargo build --quiet --locked --release --manifest-path "$WORK/rs/Cargo.toml" -p aitp-conformance --bin aitp-conformance &&
    python3 scripts/record-transcript.py "$WORK/rs/target/release/aitp-conformance"; then
    echo "transcript re-recorded at the new pin"
else
    echo "::warning::adapter transcript not re-recorded; TestTranscript fails until scripts/record-transcript.py is run"
fi
