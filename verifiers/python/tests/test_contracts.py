# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The verifier's contract parts against the independent test vectors
(testvectors/, spec section 18): the WebAssembly profile (vm-v1.json),
contracts, children, requests and answers (protocol-v0.6, v0.7, and v0.8),
and Bo's calls (bo-v1.json).

Run from verifiers/python: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from cexchain_verify import cbor, contracts, cose, evidence, protocol, rules, statetree, wasm  # noqa: E402
from cexchain_verify.contract_evidence import verify_contract_evidence  # noqa: E402
from cexchain_verify.contract_report import diagnostic  # noqa: E402
from cexchain_verify.errors import VerifyError  # noqa: E402

VECTORS = HERE.parents[2] / "testvectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


def entries_of(lg: dict, t0: int | None = None) -> list:
    """The log: as the vectors hold it, or (v0.6) each statement registered
    at t0 + 1000 + its index."""
    if "log_entries" in lg:
        return [protocol.parse_log_entry(hx(e)) for e in lg["log_entries"]]
    return [protocol.LogEntry(encoded=b"", id=hx(st["statement_id"]), registered_at=t0 + 1000 + i,
                              statement=hx(st["encoded"]), commitment=None) for i, st in enumerate(lg["statements"])]


def snapshot(ledger: rules.Ledger) -> rules.Ledger:
    """A copy of the replayed state; contracts' loaded modules are shared,
    since runs never change them."""
    return copy.deepcopy(ledger, {id(c.module): c.module for c in ledger.contracts.values()})


def replay(entries: list, stops=()) -> tuple[rules.Ledger, dict]:
    """The state after every entry, and a snapshot of it after the first n
    entries for each n in `stops`."""
    ledger = rules.Ledger(entries[0], 0)
    snapshots = {}
    for i, entry in enumerate(entries):
        if i in stops:
            snapshots[i] = snapshot(ledger)
        if i == 0:
            continue
        if entry.commitment is not None:
            ledger.apply_commitment(entry, i)
        else:
            ledger.apply(entry, i)
    if len(entries) in stops:
        snapshots[len(entries)] = snapshot(ledger)
    return ledger, snapshots


def run_verdict(ledger: rules.Ledger, statement: protocol.Statement, at: int, index: int):
    """What the home's run of a call at `at` gives: (input, outcome, output,
    fuel, verdict)."""
    if statement.presence is not None:
        raise AssertionError("the vectors' calls carry no proof of presence")
    applied = rules.Applied(index=index, registered_at=at, statement=statement,
                            id=ledger.h(statement.sign1.to_be_signed()), signer=statement.actor, chain=[],
                            presence=None)
    data = ledger.call_input(applied)
    f = statement.fields
    contract_id = f["contract"] if f["contract"] is not None else ledger.instances[f["instance"]].contract
    outcome, output, fuel, _ = wasm.run(ledger.contracts[contract_id].module, data,
                                        contracts.HASH_NAMES[ledger.hash_alg])
    verdict = outcome
    if outcome == "ok":
        try:
            verdict = contracts.parse_output(output, ledger.id)[0]
        except VerifyError:
            verdict = "malformed"
    return data, outcome, output, fuel, verdict


class ContractVectors(unittest.TestCase):
    """Shared checks of protocol-v0.6, v0.7, and v0.8."""

    def check_log(self, lg: dict, entries: list, at):
        """Every statement replays; every contract run and every refused
        statement is as the vectors say. `at(after, item)` is the time a
        refused statement or a run is tried at."""
        stops = {item["after"] for item in lg["refused"] + lg["runs"]}
        ledger, states = replay(entries, stops)
        by_name = {st["name"]: protocol.parse_statement(hx(st["encoded"])) for st in lg["statements"]}
        refused = {r["name"]: r for r in lg["refused"]}
        for run in lg["runs"]:
            with self.subTest(run=run["name"]):
                statement = by_name.get(run["name"])
                if statement is None:
                    statement = protocol.parse_statement(hx(refused[run["name"]]["encoded"]))
                data, outcome, output, fuel, verdict = run_verdict(states[run["after"]], statement,
                                                                   at(run["after"], run), run["after"])
                self.assertEqual(data.hex(), run["input"])
                self.assertEqual((outcome, output.hex(), fuel, verdict),
                                 (run["outcome"], run["output"], run["fuel"], run["verdict"]))
        for r in lg["refused"]:
            with self.subTest(refused=r["name"]):
                signed = hx(r["encoded"])
                if r["malformed"]:
                    with self.assertRaises(VerifyError):
                        protocol.parse_statement(signed)
                    continue
                statement = protocol.parse_statement(signed)
                state = snapshot(states[r["after"]])
                entry = protocol.LogEntry(encoded=b"", id=state.h(statement.sign1.to_be_signed()),
                                          registered_at=at(r["after"], r), statement=signed, commitment=None)
                with self.assertRaises(VerifyError):
                    state.apply(entry, r["after"])
        return ledger

    def check_instances(self, ledger: rules.Ledger, lg: dict):
        for x in lg["instances"]:
            with self.subTest(instance=x["id"]):
                i = ledger.instances[hx(x["id"])]
                self.assertEqual((i.contract.hex(), i.head, cbor.encode(i.state).hex(), i.status, i.final),
                                 (x["contract"], x["head"], x["state"], x["status"], x["final"]))
                self.assertEqual({role: v.hex() for role, v in i.parties.items()}, x["parties"])
                if "history" in x:
                    self.assertEqual((i.history, i.depth, i.parent.hex() if i.parent else None),
                                     (x["history"], x["depth"], x["parent"]))
                    if x["created_by"] is not None:
                        self.assertEqual((i.created_by, i.position), (x["created_by"], x["position"]))
                if "open" in x:
                    self.assertEqual([r.hex() for r in i.open], x["open"])
        for c in lg.get("contracts", []):
            contract = ledger.contracts[hx(c["id"])]
            self.assertEqual(contract.retired, c["retired"])
            if "history" in c:
                self.assertEqual(contract.history, c["history"])
        for child in lg.get("children", []):
            h = ledger.h
            self.assertEqual(contracts.child_id(h, hx(child["call"]), child["position"]).hex(), child["id"])
            self.assertIn(hx(child["id"]), ledger.instances)

    def check_state(self, ledger: rules.Ledger, lg: dict):
        ids = [*ledger.actors, *ledger.delegations, *ledger.records, *ledger.contracts, *ledger.instances]
        leaves = sorted((ledger.leaf(i) for i in ids), key=lambda leaf: leaf[1])
        self.assertEqual(leaves, [[x["kind"], hx(x["id"]), x["history"]] for x in lg["state_leaves"]])
        self.assertEqual(statetree.root_of(ledger.h, leaves).hex(), lg["state_root"])
        self.assertEqual(ledger.commitments[lg["state_commitment"]["index"]].root.hex(), lg["state_root"])

    def check_evidence(self, lg: dict, name: str, e: dict):
        data = hx(e["contract_evidence"])
        result = verify_contract_evidence(data, ledger_id=hx(lg["ledger_id"]))
        ledger, instance = result.ledger, result.instance
        self.assertEqual(instance.id.hex(), e["subject"])
        self.assertEqual(instance.depth, e["depth"])
        generations = ledger.ancestors(instance) + [instance]
        self.assertEqual([{"id": a.id.hex(), "until": b.created_by} for a, b in zip(generations, generations[1:])],
                         e["ancestors"])
        self.assertEqual([a.index for a in result.calls], e["events"])
        inner, _ = protocol.parse_contract_evidence(data)
        indices = [cose.parse_receipt(receipt).leaf_index for _, receipt in protocol.parse_bundle(inner).entries]
        self.assertEqual(indices, e["entries"])
        self.assertEqual([i.hex() for i in evidence.involved_objects(ledger, instance)], e["involved"])
        pins = []
        for applied in result.calls:
            for ref in applied.statement.fields["consents"]:
                if ref.bundle.hex() not in pins:
                    pins.append(ref.bundle.hex())
        self.assertEqual(pins, e["pins"])
        self.assertTrue(result.bundle.complete)
        return result


class ProtocolV06(ContractVectors):
    def test_ledgers(self):
        d = load("protocol-v0.6.json")
        for lg in d["ledgers"]:
            with self.subTest(hash=lg["hash"]):
                ledger = self.check_log(lg, entries_of(lg, d["t0"]), lambda after, _: d["t0"] + 1000 + after)
                self.check_instances(ledger, lg)
                self.assertEqual(ledger.contracts[hx(lg["contracts"][0]["id"])].code.hex(), d["contract"])
                # The contract evidence holds opaque bundles here: its pins
                # are those of the calls on the instance.
                inner, consents = protocol.parse_contract_evidence(hx(lg["contract_evidence"]["encoded"]))
                self.assertEqual(inner.hex(), lg["contract_evidence"]["instance_bundle"])
                self.assertEqual([ledger.h(b).hex() for b in consents], lg["contract_evidence"]["pins"])
                for c in lg["consents"]:
                    self.assertEqual(ledger.h(hx(c["bundle"])).hex(), c["bundle_hash"])
                    protocol.parse_signer(cbor.decode(hx(c["signer"])), "a signer")


class ProtocolV07(ContractVectors):
    def test_ledgers(self):
        d = load("protocol-v0.7.json")
        for lg in d["ledgers"]:
            with self.subTest(hash=lg["hash"]):
                ledger = self.check_log(lg, entries_of(lg), lambda after, _: d["t0"] + 1000 + after)
                self.check_instances(ledger, lg)
                self.check_state(ledger, lg)
                for name, e in lg["evidence"].items():
                    with self.subTest(evidence=name):
                        self.check_evidence(lg, name, e)


class ProtocolV08(ContractVectors):
    def test_ledgers(self):
        d = load("protocol-v0.8.json")
        for lg in d["ledgers"]:
            with self.subTest(hash=lg["hash"]):
                ledger = self.check_log(lg, entries_of(lg), lambda after, item: item["at"])
                self.check_instances(ledger, lg)
                self.check_state(ledger, lg)
                when = lg["checkpoint_time"]
                for x in lg["requests"]:
                    q = ledger.requests[hx(x["id"])]
                    late = max(0, q.answered_at - q.deadline) if q.answered_at is not None else None
                    overdue = q.status is None and when >= q.deadline
                    self.assertEqual(
                        (q.instance.hex(), q.call, q.position, q.kind, cbor.encode(q.params).hex(), q.deadline,
                         q.reply, q.asked_at, q.status, q.answered_by, q.answered_at, late, overdue),
                        (x["instance"], x["call"], x["position"], x["kind"], x["params"], x["deadline"], x["reply"],
                         x["asked_at"], x["status"], x["answered_by"], x["answered_at"], x["late_by"], x["overdue"]))
                    self.assertEqual(contracts.request_id(ledger.h, hx(x["call_id"]), x["position"]).hex(), x["id"])
                for name, e in lg["evidence"].items():
                    with self.subTest(evidence=name):
                        result = self.check_evidence(lg, name, e)
                        self.check_requests(result, e)

    def check_requests(self, result, e: dict):
        ledger = result.ledger
        for call in e["calls"]:
            run = ledger.runs[call["index"]]
            self.assertEqual((run.instance.hex(), [r.hex() for r in run.requests]),
                             (call["instance"], call["requests"]))
            applied = ledger.applied[call["index"]]
            answer = applied.statement.fields["answer"]
            if call["answer"] is None:
                self.assertIsNone(answer)
                continue
            a = call["answer"]
            q = ledger.requests[answer[0]]
            self.assertEqual((answer[0].hex(), answer[1], max(0, applied.registered_at - q.deadline),
                              applied.signer.hex(), cbor.encode(contracts.applied_signer(ledger, applied)).hex(),
                              applied.chain[0].hex() if applied.chain else None),
                             (a["request"], a["status"], a["late_by"], a["actor"], a["signer"], a["delegation"]))
        self.assertEqual([q.id.hex() for q in result.own_requests()], e["requests"])
        self.assertEqual([q.id.hex() for q in result.open_requests()], e["open"])
        self.assertEqual([q.id.hex() for q in result.open_requests() if result.overdue(q)], e["overdue"])


class Damaged(unittest.TestCase):
    """The vectors' signed contract evidence fails whenever a byte flips."""

    def test_flips(self):
        lg = load("protocol-v0.7.json")["ledgers"][0]
        data = hx(lg["evidence"]["tier-3 part"]["contract_evidence"])
        for position in range(0, len(data), max(1, len(data) // 23)):
            damaged = bytearray(data)
            damaged[position] ^= 0x01
            with self.subTest(position=position), self.assertRaises(VerifyError):
                verify_contract_evidence(bytes(damaged), ledger_id=hx(lg["ledger_id"]))

    def test_consents(self):
        lg = load("protocol-v0.7.json")["ledgers"][0]
        e = lg["evidence"]["tier-3 part"]
        inner, consents = protocol.parse_contract_evidence(hx(e["contract_evidence"]))
        for why, bundles in (("a consent left out", consents[1:]), ("a consent twice", consents + consents[:1]),
                             ("a consent no call cites", consents + [hx(lg["consents"][-1]["bundle"])])):
            with self.subTest(why), self.assertRaises(VerifyError):
                verify_contract_evidence(cbor.encode({0: 1, 1: inner, 2: bundles}), ledger_id=hx(lg["ledger_id"]))
        with self.assertRaises(VerifyError):  # the wrong home
            verify_contract_evidence(hx(e["contract_evidence"]), ledger_id=hx(lg["parties"]["Supplier"]))


class VmProfile(unittest.TestCase):
    """vm-v1.json: modules in and out of the profile, and runs with their
    outcomes, outputs, fuel, and abort reasons. The two runs that use all
    10,000,000 fuel take minutes here; CEXCHAIN_VM_FULL=1 runs them too."""

    def test_modules_and_runs(self):
        import os
        d = load("vm-v1.json")
        modules = {}
        for m in d["modules"]:
            with self.subTest(module=m["name"]):
                try:
                    modules[m["name"]] = wasm.load(hx(m["wasm"]))
                    loaded = True
                except wasm.Refused:
                    loaded = False
                self.assertEqual(loaded, m["valid"])
        full = os.environ.get("CEXCHAIN_VM_FULL") == "1"
        for r in d["runs"]:
            if r["fuel"] >= d["fuel"] and not full:
                continue
            with self.subTest(run=r["name"]):
                outcome, output, fuel, reason = wasm.run(modules[r["module"]], hx(r["input"]), r["hash"])
                self.assertEqual((outcome, output.hex(), fuel, reason.hex()),
                                 (r["outcome"], r["output"], r["fuel"], r.get("reason", "")))


def jsonish(value):
    """A decoded CBOR value as bo-v1.json writes results: byte strings in
    hex, map keys as text."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [jsonish(v) for v in value]
    if isinstance(value, dict):
        return {str(jsonish(k)): jsonish(v) for k, v in value.items()}
    return value


class BoCalls(unittest.TestCase):
    """bo-v1.json: each call's input as the ledger encodes it, and its
    outcome on the deployed code, read as a contract output."""

    def test_runs(self):
        d = load("bo-v1.json")
        count = 0
        for c in d["contracts"]:
            module = wasm.load(hx(c["code"]))
            for r in c["runs"]:
                with self.subTest(contract=c["name"], run=r["label"]):
                    if r["call"] is not None:
                        self.assertEqual(self.input_of(r["call"]).hex(), r["input"])
                    outcome, output, fuel, reason = wasm.run(module, hx(r["input"]))
                    self.assertEqual((outcome, output.hex(), fuel, reason.hex()),
                                     (r["outcome"], r["output"], r["fuel"], r["reason"]))
                    home = hx(r["call"]["home"]) if r["call"] else None
                    self.check_result(outcome, output, reason, r["result"], home)
                    count += 1
        self.assertGreater(count, 700)

    def input_of(self, call: dict) -> bytes:
        def signer(s):
            return contracts.signer_map(s["kind"], s["presence"], s["model"])
        data = {1: call["function"], 2: cbor.decode(hx(call["arguments"])), 3: hx(call["home"]),
                4: hx(call["contract"]), 6: [hx(call["caller"]), signer(call["signer"])], 7: call["time"]}
        i = call["instance"]
        if i is not None:
            instance = contracts.Instance(id=hx(i["id"]), contract=b"", head=i["head"], created_by=0,
                                          state=cbor.decode(hx(i["state"])), status=i["status"],
                                          parties={k: hx(v) for k, v in (i["parties"] or {}).items()})
            if i.get("parent") is not None:
                instance.parent, instance.depth = hx(i["parent"]), i["depth"]
            data[5] = contracts.instance_view(instance)
        if call["consents"]:
            data[8] = [[hx(ledger), signer(s)] for ledger, s in call["consents"]]
        q = call.get("request")
        if q is not None:
            request = contracts.Request(id=hx(q["id"]), instance=b"", call=0, position=0, kind=q["kind"],
                                        params=cbor.decode(hx(q["params"])), deadline=q["deadline"], reply="",
                                        asked_at=q["asked_at"])
            data[9] = contracts.request_view(request, q["status"])
        return cbor.encode(data)

    def check_result(self, outcome, output, reason, result, home):
        if "refused" in result:
            self.assertEqual((outcome, reason.decode()), ("aborted", result["refused"]))
            return
        verdict, value = contracts.parse_output(output, home if home is not None else bytes(32))
        if "needs" in result:
            self.assertEqual((verdict, [x.hex() for x in value]), ("needs", result["needs"]))
            return
        expected = result["accept"]
        self.assertEqual(verdict, "accept")
        self.assertEqual((jsonish(value.state), value.status, jsonish(value.parties), value.final),
                         (expected["state"], expected.get("status"), expected.get("parties"),
                          expected.get("final", False)))
        self.assertEqual([[n, jsonish(v)] for n, v in value.events], expected.get("events", []))
        self.assertEqual(len(value.children), len(expected.get("children", [])))
        self.assertEqual(len(value.requests), len(expected.get("requests", [])))


class Diagnostic(unittest.TestCase):
    """CBOR diagnostic notation, as reports show values."""

    def test_values(self):
        cases = [
            (0, "0"), (-25, "-25"), (2**64 - 1, "18446744073709551615"), (-2**64, "-18446744073709551616"),
            ("q\"uo\\te", '"q\\"uo\\\\te"'), ("nl\n\x01\x7f中😀", '"nl\\u000a\\u0001\x7f中😀"'), (b"\x00\xff", "h'00ff'"),
            ([], "[]"), ({}, "{}"), ([1, [2, []]], "[1, [2, []]]"), (True, "true"), (None, "null"),
            ({1: "a", -1: "b", "k": 2, b"bk": 3}, '{1: "a", -1: "b", h\'626b\': 3, "k": 2}'),
            ({"b": 1, "a": 2, "aa": 3}, '{"a": 2, "b": 1, "aa": 3}'),
            (cbor.Map([(True, 1), (None, 2), (False, 3)]), "{false: 3, true: 1, null: 2}"),
            (cbor.Tag(1, 1700000000), "1(1700000000)"), (cbor.Tag(24, b"\x01"), "24(h'01')"),
        ]
        for value, text in cases:
            with self.subTest(text):
                self.assertEqual(diagnostic(cbor.decode(cbor.encode(value))), text)


class Outputs(unittest.TestCase):
    """contract-output: what is well formed, and what is not."""

    def test_outputs(self):
        home = bytes([7]) * 32
        ok = [[1, {1: 0}], [1, {1: None, 2: "s", 3: {"r": home[:31] + b"\x08"}, 4: [["e", None]], 5: True}],
              [1, {1: 0, 6: [{1: 0}], 7: [{1: "kind.x-y_z", 2: None, 3: 5, 4: "f"}]}], [2, [bytes(32), b"\x01" * 32]]]
        for value in ok:
            contracts.parse_output(cbor.encode(value), home)
        bad = [b"", b"\xff", cbor.encode([3, 0]), cbor.encode([True, {1: 0}]), cbor.encode([1, {2: "s"}]),
               cbor.encode([1, {1: 0, 5: False}]), cbor.encode([1, {1: 0, 8: 1}]), cbor.encode([1, {1: 0, 2: ""}]),
               cbor.encode([1, {1: 0, 3: {}}]), cbor.encode([1, {1: 0, 4: []}]), cbor.encode([2, []]),
               cbor.encode([2, [home]]), cbor.encode([2, [b"\x02" * 32, b"\x01" * 32]]),
               cbor.encode([1, {1: 0, 6: [{1: 0}] * 17}]), cbor.encode([1, {1: 0, 6: [{1: 0, 5: True}]}]),
               cbor.encode([1, {1: 0, 7: [{1: "Kind", 2: None, 3: 5, 4: "f"}]}]),
               cbor.encode([1, {1: 0, 7: [{1: "k", 2: b"x" * 4094, 3: 5, 4: "f"}]}]),
               cbor.encode([1, {1: b"x" * 65_534}]), cbor.encode([1, {1: 0}]) + b"\x00"]
        for data in bad:
            with self.subTest(data=data[:16].hex()), self.assertRaises(VerifyError):
                contracts.parse_output(data, home)


if __name__ == "__main__":
    unittest.main()
