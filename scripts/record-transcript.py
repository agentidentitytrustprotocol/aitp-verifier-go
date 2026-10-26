#!/usr/bin/env python3
"""Record the adapter transcript that cmd/aitp-verifier-adapter's tests replay.

Runs aitp-conformance (the spec's reference runner, built from aitp-rs) on
the pinned fixtures against a pass-through target that logs every request
line. The runner substitutes the fixtures' placeholders, so the logged
params are the concrete artifacts. Each fixture step is then paired with
the outcome its fixture expects, read from testdata/spec, and written to
cmd/aitp-verifier-adapter/testdata/transcript.json.

The adapter's own responses are not recorded: the test checks the adapter
against the fixtures' expectations, not against a previous run of itself.

Usage: scripts/record-transcript.py <path to aitp-conformance> [adapter binary]
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "testdata/spec/schemas/conformance"
OUT = ROOT / "cmd/aitp-verifier-adapter/testdata/transcript.json"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    runner = sys.argv[1]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        adapter = sys.argv[2] if len(sys.argv) > 2 else None
        if adapter is None:
            adapter = str(tmp / "adapter")
            subprocess.run(["go", "build", "-o", adapter, "./cmd/aitp-verifier-adapter"], cwd=ROOT, check=True)
        log, report = tmp / "in.log", tmp / "report.json"
        target = tmp / "target.sh"
        target.write_text(f"#!/bin/sh\ntee -a '{log}' | '{adapter}'\n")
        target.chmod(0o755)
        spec = (ROOT / "SPEC_VERSION").read_text().strip()
        subprocess.run([runner, "run", "--target", str(target), "--fixtures-dir", str(FIXTURES),
                        "--profile", "core", "--report", str(report), "--spec-commit", spec,
                        "--spec-version", "pinned", "--implementation-repository",
                        "https://github.com/agentidentitytrustprotocol/aitp-verifier-go"],
                       check=True, stdout=subprocess.DEVNULL)
        requests = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        ran = [r["id"] for r in json.loads(report.read_text())["results"] if r["outcome"] != "skip"]

    fixtures = {}
    for f in FIXTURES.glob("*.json"):
        d = json.loads(f.read_text())
        if "id" in d:
            fixtures[d["id"]] = d

    # Split the request stream at begin_fixture; each fixture's steps follow it.
    groups, current = [], None
    for r in requests:
        if r["op"] == "begin_fixture":
            current = []
            groups.append(current)
        elif current is not None and r["op"] not in ("set_clock", "shutdown"):
            current.append(r)
    clocks = [r["params"] for r in requests if r["op"] == "set_clock" and "now" in r["params"]]
    if len(groups) != len(ran) or len(clocks) != len(ran):
        sys.exit(f"{len(groups)} fixture groups, {len(clocks)} clocks, {len(ran)} fixtures run")

    out = []
    for fid, steps, clock in zip(ran, groups, clocks):
        d = fixtures[fid]
        seq = d["input"].get("sequence")
        expected = [s.get("expected", {}) for s in seq] if seq else [d.get("expected", {})]
        if len(expected) != len(steps):
            sys.exit(f"{fid}: {len(steps)} requests for {len(expected)} steps")
        out.append({
            "fixture": fid,
            "now": clock["now_unix_secs"],
            "steps": [{
                "op": r["op"],
                "params": r["params"],
                "outcome": e.get("outcome"),
                "error_code": e.get("error_code"),
            } for r, e in zip(steps, expected)],
        })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"spec_commit": spec, "fixtures": out}, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(out)} fixtures")


if __name__ == "__main__":
    main()
