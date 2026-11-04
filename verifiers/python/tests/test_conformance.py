# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The verifier against the conformance suite testvectors/evidence-v1.json:
every case's evidence, verified as the command line does with the case's
options, must reach the case's verdict, and a verified report must match
the case's facts.

A fact object matches a report object when every key of the fact is in the
report and its value matches; a fact list matches a report list of the same
length, element by element; any other value matches only an equal value
(true, false, null, numbers, and strings exactly).

Run from verifiers/python: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from cexchain_verify import cli  # noqa: E402

SUITE = HERE.parents[2] / "testvectors" / "evidence-v1.json"
OPTIONS = {"ledger_id", "witnesses", "min_witnesses", "tsa_roots", "min_timestamps", "attachments",
           "require_presence", "require_answered"}


def mismatches(fact, value, path: str = "") -> list[str]:
    """Where `value` (a report) does not match `fact`, as paths."""
    if isinstance(fact, dict):
        if not isinstance(value, dict):
            return [f"{path or '.'}: an object in the facts, {json.dumps(value)[:80]} in the report"]
        out = []
        for key, sub in fact.items():
            if key not in value:
                out.append(f"{path}.{key}: not in the report")
            else:
                out += mismatches(sub, value[key], f"{path}.{key}")
        return out
    if isinstance(fact, list):
        if not isinstance(value, list) or len(value) != len(fact):
            return [f"{path}: {len(fact)} items in the facts, {json.dumps(value)[:80]} in the report"]
        return [m for i, (a, b) in enumerate(zip(fact, value)) for m in mismatches(a, b, f"{path}[{i}]")]
    same = (fact is None and value is None) or (
        isinstance(fact, bool) == isinstance(value, bool) and isinstance(fact, (bool, int, str))
        and isinstance(value, type(fact)) and fact == value)
    return [] if same else [f"{path}: {json.dumps(fact)} in the facts, {json.dumps(value)} in the report"]


def run(case: dict, work: pathlib.Path) -> tuple[int, dict]:
    """Verifies the case's evidence with the command line, as its options say:
    (exit code, JSON report)."""
    evidence = work / "evidence.cbor"
    evidence.write_bytes(bytes.fromhex(case["evidence"]))
    argv = (["contract"] if case["kind"] == "contract" else []) + [str(evidence), "--json"]
    options = case["options"]
    if "ledger_id" in options:
        argv += ["--ledger-id", options["ledger_id"]]
    for i, key in enumerate(options.get("witnesses", [])):
        path = work / f"witness-{i}.pub"
        path.write_bytes(bytes.fromhex(key))
        argv += ["--witness", str(path)]
    if "min_witnesses" in options:
        argv += ["--min-witnesses", str(options["min_witnesses"])]
    for i, pem in enumerate(options.get("tsa_roots", [])):
        path = work / f"tsa-root-{i}.pem"
        path.write_text(pem)
        argv += ["--tsa-root", str(path)]
    if "min_timestamps" in options:
        argv += ["--min-timestamps", str(options["min_timestamps"])]
    for i, (name, content) in enumerate(sorted(options.get("attachments", {}).items())):
        path = work / f"attachment-{i}"
        path.write_bytes(bytes.fromhex(content))
        argv += ["--attachment", f"{name}={path}"]
    if options.get("require_presence"):
        argv.append("--require-presence")
    if options.get("require_answered"):
        argv.append("--require-answered")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, json.loads(out.getvalue())


class Conformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = json.loads(SUITE.read_text())

    def test_suite_is_well_formed(self):
        self.assertEqual(self.suite["format"], 1)
        names = [case["name"] for case in self.suite["cases"]]
        self.assertEqual(len(names), len(set(names)))
        for case in self.suite["cases"]:
            with self.subTest(case["name"]):
                self.assertIn(case["kind"], ("record", "contract"))
                self.assertLessEqual(set(case["options"]), OPTIONS)
                if case["verified"]:
                    self.assertNotIn("rule", case)
                else:
                    self.assertTrue(case["rule"])
                    self.assertEqual(case["facts"], {})

    def test_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            for case in self.suite["cases"]:
                with self.subTest(case["name"]):
                    code, report = run(case, work)
                    self.assertIn(code, (cli.EXIT_VERIFIED, cli.EXIT_NOT_VERIFIED), report)
                    self.assertEqual(report.get("verified"), code == cli.EXIT_VERIFIED)
                    self.assertEqual(code == cli.EXIT_VERIFIED, case["verified"],
                                     f"{case['description']} ({report.get('error')})")
                    if case["verified"]:
                        self.assertEqual(mismatches(case["facts"], report), [])


if __name__ == "__main__":
    unittest.main()
