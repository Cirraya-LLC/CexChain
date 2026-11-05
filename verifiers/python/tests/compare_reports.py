# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Compares the Python verifier's JSON report with `cexchain verify --json`
or `cexchain contract verify --json`.

Usage: python3 compare_reports.py PYTHON_JSON PYTHON_EXIT BLACKBOX_JSON BLACKBOX_EXIT [--expect verified|failed]
                                  [--known REGEX]

The verdicts (and exit codes) must agree. When both verified, every field
must agree, except a summary (events[].summary, calls[].summary), a sentence
for people: a difference there is only reported. So is a known difference:
one at a field whose path (as .calls[6].consents[0].witnesses.trusted)
matches REGEX, which a test names when the verifiers are known to differ
there and the difference is reported.

Exit status 0 if they agree, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys


def _load(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _walk(a, b, path: str, out: list, soft: list):
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            sub = f"{path}.{key}"
            if key not in a:
                out.append(f"{sub}: only cexchain verify has it ({json.dumps(b[key])[:120]})")
            elif key not in b:
                out.append(f"{sub}: only the Python verifier has it ({json.dumps(a[key])[:120]})")
            elif key == "summary":
                if a[key] != b[key]:
                    soft.append(f"{sub}: python {a[key]!r} / cexchain {b[key]!r}")
            else:
                _walk(a[key], b[key], sub, out, soft)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: {len(a)} items in python, {len(b)} in cexchain verify")
            return
        for i, (x, y) in enumerate(zip(a, b)):
            _walk(x, y, f"{path}[{i}]", out, soft)
    elif a != b or type(a) is not type(b):
        out.append(f"{path}: python {json.dumps(a)[:120]} / cexchain {json.dumps(b)[:120]}")


def compare(py, py_exit: int, bb, bb_exit: int, expect: str | None = None,
            known: str | None = None) -> tuple[list, list]:
    problems, soft = [], []
    if py_exit != bb_exit:
        problems.append(f"exit codes differ: python {py_exit}, cexchain verify {bb_exit}")
    py_ok = bool(py and py.get("verified"))
    bb_ok = bool(bb and bb.get("verified"))
    if py_ok != bb_ok:
        problems.append(f"verdicts differ: python {py_ok} ({(py or {}).get('error')}), "
                        f"cexchain verify {bb_ok} ({(bb or {}).get('error')})")
    if expect == "verified" and not (py_ok and bb_ok):
        problems.append("expected both to verify")
    if expect == "failed" and (py_ok or bb_ok):
        problems.append("expected both to fail")
    # A full report also comes with a failure the verifier was asked to
    # check beside the bundle (an attachment, too few witnesses).
    if (py_ok and bb_ok) or (py and bb and any(k in py and k in bb for k in ("record", "instance"))):
        fields = []
        _walk(py, bb, "", fields, soft)
        for line in fields:
            path = line.split(":", 1)[0]
            if known is not None and re.search(known, path):
                soft.append(f"{line} (a known difference)")
            else:
                problems.append(line)
    return problems, soft


def main(argv: list[str]) -> int:
    options = dict(zip(argv[5::2], argv[6::2]))
    if len(argv) < 5 or len(argv) % 2 == 0 or not set(options) <= {"--expect", "--known"}:
        print(__doc__, file=sys.stderr)
        return 2
    py, bb = _load(argv[1]), _load(argv[3])
    problems, soft = compare(py, int(argv[2]), bb, int(argv[4]), options.get("--expect"), options.get("--known"))
    for line in soft:
        print(f"    note: {'differs' if line.endswith('(a known difference)') else 'wording differs'} at {line}")
    if problems:
        for line in problems:
            print(f"    DISAGREE: {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
