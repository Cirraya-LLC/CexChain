# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The conformance suite (testvectors/evidence-v1.json) against the command
line: each case's evidence through `cexchain verify --json` (a record's) or
`cexchain contract verify --json` (an instance's contract evidence), with its
options as flags. The verdict must be the suite's (exit 0 verified, 3 not),
and a verified report must hold the case's facts: a fact object matches when
each of its keys is in the report with a matching value, a fact list matches
a list of the same length element by element, and anything else only an
equal value.

Usage: python3 conformance.py CEXCHAIN SUITE
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile


def matches(fact, value) -> bool:
    if isinstance(fact, dict):
        return isinstance(value, dict) and all(k in value and matches(v, value[k]) for k, v in fact.items())
    if isinstance(fact, list):
        return isinstance(value, list) and len(fact) == len(value) and all(map(matches, fact, value))
    return type(fact) is type(value) and fact == value


def flags(options: dict, work: str) -> list[str]:
    def file(name: str, data: bytes) -> str:
        path = os.path.join(work, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    out = []
    if "ledger_id" in options:
        out += ["--ledger-id", options["ledger_id"]]
    for i, key in enumerate(options.get("witnesses", [])):
        out += ["--witness", file(f"witness-{i}.pub", bytes.fromhex(key))]
    if options.get("min_witnesses"):
        out += ["--min-witnesses", str(options["min_witnesses"])]
    for i, pem in enumerate(options.get("tsa_roots", [])):
        out += ["--tsa-root", file(f"root-{i}.pem", pem.encode())]
    if options.get("min_timestamps"):
        out += ["--min-timestamps", str(options["min_timestamps"])]
    for i, (name, content) in enumerate(options.get("attachments", {}).items()):
        out += ["--attachment", f"{name}={file(f'attachment-{i}', bytes.fromhex(content))}"]
    if options.get("require_presence"):
        out.append("--require-presence")
    if options.get("require_answered"):
        out.append("--require-answered")
    return out


def run_case(cexchain: str, case: dict) -> str | None:
    """Nothing if the command line agrees with the case; else why not."""
    with tempfile.TemporaryDirectory() as work:
        evidence = os.path.join(work, "evidence.cbor")
        with open(evidence, "wb") as f:
            f.write(bytes.fromhex(case["evidence"]))
        command = [cexchain] + (["contract", "verify"] if case["kind"] == "contract" else ["verify"])
        command += [evidence, "--json"] + flags(case.get("options", {}), work)
        done = subprocess.run(command, capture_output=True, text=True)
    if done.returncode not in (0, 3):
        return f"exit {done.returncode}: {done.stderr.strip()[:300]}"
    verified = done.returncode == 0
    if verified != case["verified"]:
        try:
            said = json.loads(done.stdout).get("error", "")
        except ValueError:
            said = done.stdout.strip()[:300]
        return f"{'verified' if verified else 'not verified'}, the suite says otherwise ({said})"
    if verified:
        report = json.loads(done.stdout)
        if not matches(case.get("facts", {}), report):
            return "the report does not hold the case's facts"
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 1
    cexchain, path = sys.argv[1], sys.argv[2]
    with open(path) as f:
        suite = json.load(f)
    if suite.get("format") != 1:
        print(f"{path}: not a suite of format 1", file=sys.stderr)
        return 1
    failures = 0
    for case in suite["cases"]:
        problem = run_case(cexchain, case)
        if problem is not None:
            failures += 1
            print(f"FAIL {case['name']}: {problem}")
    print(f"conformance: {len(suite['cases']) - failures} of {len(suite['cases'])} cases as the suite says")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
