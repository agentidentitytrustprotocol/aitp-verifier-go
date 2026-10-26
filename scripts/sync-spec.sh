#!/usr/bin/env bash
#
# sync-spec.sh: copy the spec files this module tests against into
# testdata/spec/, from the spec commit named in SPEC_VERSION.
#
# Usage:
#   scripts/sync-spec.sh           rewrite testdata/spec/ from the pinned commit
#   scripts/sync-spec.sh --check   exit 1 if testdata/spec/ differs from it
#
# Env: AITP_SPEC_DIR=<path> uses a local spec checkout (its git object store)
# instead of fetching from GitHub. Either way the files come from the pinned
# commit, never from a working tree.
#
# What is copied: registries/error-codes.md, schemas/json/, and
# schemas/conformance/ without reports/.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/testdata/spec"
SPEC_URL="https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol.git"
PATHS="registries/error-codes.md schemas/json schemas/conformance"

MODE="sync"
case "${1:-}" in
    "") ;;
    --check) MODE="check" ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

SHA="$(tr -d '[:space:]' < "$ROOT/SPEC_VERSION")"
case "$SHA" in
    *[!0-9a-f]*|"") echo "SPEC_VERSION is not a commit SHA: $SHA" >&2; exit 2 ;;
esac
[ "${#SHA}" -eq 40 ] || { echo "SPEC_VERSION must be a full 40-char SHA" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "${AITP_SPEC_DIR:-}" ]; then
    git -C "$AITP_SPEC_DIR" cat-file -e "$SHA^{commit}" || { echo "$SHA not in $AITP_SPEC_DIR" >&2; exit 2; }
    # shellcheck disable=SC2086
    git -C "$AITP_SPEC_DIR" archive "$SHA" $PATHS | tar -x -C "$WORK"
else
    git -C "$WORK" init -q repo
    git -C "$WORK/repo" fetch -q --depth 1 "$SPEC_URL" "$SHA"
    # shellcheck disable=SC2086
    git -C "$WORK/repo" archive FETCH_HEAD $PATHS | tar -x -C "$WORK"
    rm -rf "$WORK/repo"
fi
rm -rf "$WORK/schemas/conformance/reports"
printf '%s\n' "$SHA" > "$WORK/SPEC_COMMIT"

if [ "$MODE" = "check" ]; then
    if diff -r "$WORK" "$DEST" > "$WORK.diff" 2>&1; then
        echo "testdata/spec matches spec $SHA"
        rm -f "$WORK.diff"
        exit 0
    fi
    head -40 "$WORK.diff" >&2
    rm -f "$WORK.diff"
    echo "testdata/spec is out of sync with SPEC_VERSION ($SHA); run scripts/sync-spec.sh" >&2
    exit 1
fi

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -R "$WORK" "$DEST"
echo "testdata/spec synced from spec $SHA"
