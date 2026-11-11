# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The verifier against the protocol's independent test vectors
(testvectors/, spec section 18).

Run from verifiers/python: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from kanhe_verify import cbor, claims, cose, crypto, merkle, presence, protocol, rules, statetree  # noqa: E402
from kanhe_verify import access, cli, memberships, timestamps, evidence, report  # noqa: E402
from kanhe_verify.errors import VerifyError  # noqa: E402

import vector_bundles  # noqa: E402

VECTORS = HERE.parents[2] / "testvectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


class Cbor(unittest.TestCase):
    def test_round_trip_and_profile(self):
        for value in (0, 23, 24, 255, 256, 2**64 - 1, -1, -2**64, b"", b"x", "", "中", [], {}, [1, [2]],
                      {1: 2, "a": b"b"}, False, True, None, cbor.Tag(18, [1])):
            self.assertEqual(cbor.decode(cbor.encode(value)), value)

    def test_refusals(self):
        bad = {
            "non-shortest integer": "1817",
            "non-shortest length": "5801ff",
            "indefinite array": "9f01ff",
            "float": "f93c00",
            "undefined": "f7",
            "simple value": "f0",
            "bignum": "c240",
            "unsorted map": "a2020101 01".replace(" ", ""),
            "duplicate key": "a201010101",
            "length-first order is not bytewise": "a2" "6161" "01" "01" "02",
            "invalid UTF-8": "62c328",
            "trailing bytes": "0101",
            "truncated": "5802ff",
        }
        for why, data in bad.items():
            with self.subTest(why), self.assertRaises(cbor.CborError):
                cbor.decode(hx(data))

    def test_depth_and_items(self):
        nested = b"\x81" * 32 + b"\x00"
        cbor.decode(nested)
        with self.assertRaises(cbor.CborError):
            cbor.decode(b"\x81" * 33 + b"\x00")
        with self.assertRaises(cbor.CborError):
            cbor.decode(cbor.encode(list(range(10))), max_items=10)
        cbor.decode(cbor.encode(list(range(10))), max_items=11)


class Hashes(unittest.TestCase):
    def test_vectors(self):
        for v in load("hashes.json")["vectors"]:
            if v["algorithm"] not in (crypto.SHA256, crypto.SM3):
                continue  # only the ledger hashes (section 3)
            with self.subTest(v["name"]):
                self.assertEqual(crypto.hash_function(v["algorithm"])(hx(v["message"])).hex(), v["digest"])


class Signatures(unittest.TestCase):
    def test_vectors(self):
        for i, v in enumerate(load("signatures.json")["vectors"]):
            with self.subTest(i=i, name=v["name"], source=v["source"]):
                try:
                    key = crypto.parse_public_key([v["algorithm"], hx(v["public_key"])])
                except VerifyError:
                    self.assertFalse(v["valid"])
                    continue
                if v.get("expected_error") == "invalid_argument":
                    self.assertTrue(crypto.is_weak(key))
                self.assertEqual(crypto.verify_signature(key, hx(v["message"]), hx(v["signature"])), v["valid"])


class Merkle(unittest.TestCase):
    def test_vectors(self):
        for name in ("merkle-sha256.json", "merkle-sm3.json"):
            d = load(name)
            h = crypto.hash_function(d["algorithm"])
            entries = [hx(e) for e in d["entries"]]
            for n, root in enumerate(d["roots"]):
                self.assertEqual(merkle.tree_hash(h, entries[:n]).hex(), root)
            for v in d["inclusion"]:
                n, m = v["tree_size"], v["index"]
                path = [hx(p) for p in v["proof"]]
                leaf = merkle.leaf_hash(h, entries[m])
                self.assertTrue(merkle.verify_inclusion(h, m, n, leaf, path, hx(d["roots"][n])))
                if path:
                    self.assertFalse(merkle.verify_inclusion(h, m, n, leaf, path[:-1], hx(d["roots"][n])))
            for v in d["consistency"]:
                m, n = v["old_size"], v["new_size"]
                proof = [hx(p) for p in v["proof"]]
                self.assertTrue(merkle.verify_consistency(h, m, n, hx(d["roots"][m]), hx(d["roots"][n]), proof))
                if m < n:
                    self.assertFalse(merkle.verify_consistency(h, m, n, hx(d["roots"][m]), hx(d["roots"][n - 1])
                                                               if n - 1 > m else b"\x00" * 32, proof))


class CoseSign1(unittest.TestCase):
    def test_vectors(self):
        for v in load("cose-sign1.json")["vectors"]:
            with self.subTest(v["name"]):
                message = cbor.decode(hx(v["message"]))
                self.assertIsInstance(message, cbor.Tag)
                protected, unprotected, payload, signature = message.value
                self.assertEqual(unprotected, {})
                body = hx(v["payload"]) if v["detached"] else payload
                tbs = cbor.encode(["Signature1", protected, hx(v["external_aad"]), body])
                key = crypto.parse_public_key([v["algorithm"], hx(v["public_key"])])
                self.assertTrue(crypto.verify_signature(key, tbs, signature))


class ProtocolV01(unittest.TestCase):
    """Encodings: statements, log entries, a checkpoint, receipts, a field
    disclosure, an attachment commitment."""

    def test_objects(self):
        d = load("protocol-v0.1.json")
        for lg in d["ledgers"]:
            h = crypto.hash_function(lg["hash"])
            for st in lg["statements"]:
                s = protocol.parse_statement(hx(st["encoded"]))
                self.assertEqual(h(s.sign1.to_be_signed()).hex(), st["statement_id"])
                self.assertEqual(cbor.encode(s.payload).hex(), st["payload"])
            entries = [hx(e) for e in lg["log_entries"]]
            for e in entries:
                protocol.parse_log_entry(e)
            self.assertEqual(merkle.tree_hash(h, entries).hex(), lg["root"])
            head = protocol.parse_tree_head(hx(lg["checkpoint"]), cose.CHECKPOINT_TYPE, "the checkpoint")
            log_key = protocol.parse_statement(hx(lg["statements"][0]["encoded"])).fields["log_key"]
            self.assertTrue(crypto.verify_signature(log_key, head.sign1.to_be_signed(), head.sign1.signature))
            for r in lg["receipts"]:
                receipt = cose.parse_receipt(hx(r["encoded"]))
                self.assertEqual(receipt.leaf_index, r["index"])
                leaf = merkle.leaf_hash(h, entries[r["index"]])
                self.assertTrue(merkle.verify_inclusion(h, receipt.leaf_index, receipt.tree_size, leaf, receipt.path,
                                                        head.root))
                self.assertTrue(crypto.verify_signature(log_key, receipt.to_be_signed(head.root), receipt.signature))
            cosig = cose.parse_sign1(hx(lg["cosignature"]), cose.COSIGNATURE_TYPE, "a cosignature")
            self.assertEqual(cosig.payload, head.sign1.payload)
            disclosure = lg["disclosure"]
            leaf = hx(disclosure["leaf"])
            name, _, value = protocol.parse_field_leaf(leaf)
            self.assertEqual(name, disclosure["name"])
            self.assertTrue(merkle.verify_inclusion(h, disclosure["index"], len(lg["record_fields"]),
                                                    merkle.leaf_hash(h, leaf), [hx(p) for p in disclosure["path"]],
                                                    hx(lg["field_root"])))
            a = lg["attachment"]
            self.assertEqual(h(hx(a["salt"]) + hx(a["content"])).hex(), a["commitment"])


def replay(lg: dict, upto: int | None = None) -> rules.Ledger:
    entries = [protocol.parse_log_entry(hx(e)) for e in lg["log_entries"]]
    ledger = rules.Ledger(entries[0], 0)
    for i, entry in enumerate(entries[1:upto], start=1):
        if entry.commitment is not None:
            ledger.apply_commitment(entry, i)
        else:
            ledger.apply(entry, i)
    return ledger


class ProtocolV02(unittest.TestCase):
    """Presence (passkey and hardware key), the state tree, commitments."""

    def test_presence_and_state(self):
        for lg in load("protocol-v0.2.json")["ledgers"]:
            ledger = replay(lg)
            h = ledger.h
            passkey = ledger.applied[lg["presence"]["statement_index"]]
            self.assertEqual(presence.challenge(h, passkey.statement).hex(), lg["presence"]["challenge"])
            self.assertEqual(passkey.presence.method, "webauthn")
            self.assertTrue(passkey.presence.user_verified)
            ukey = ledger.applied[lg["hardware_presence"]["statement_index"]]
            self.assertEqual(presence.challenge(h, ukey.statement).hex(), lg["hardware_presence"]["challenge"])
            self.assertEqual(ukey.presence.method, "hardware-key")
            leaves = sorted([ledger.leaf(i) for i in list(ledger.actors) + list(ledger.delegations)
                             + list(ledger.records)], key=lambda leaf: leaf[1])
            self.assertEqual(statetree.root_of(h, leaves).hex(), lg["state_root"])
            for p in lg["state_proofs"]:
                leaf = [p["kind"], hx(p["id"]), p["history"]]
                self.assertEqual(ledger.leaf(hx(p["id"])), leaf)
                self.assertEqual(statetree.root_from_proof(h, leaf, [hx(s) for s in p["siblings"]]).hex(),
                                 lg["state_root"])
            self.assertEqual(ledger.commitments[lg["state_commitment"]["index"]].root.hex(), lg["state_root"])

    def test_presence_tampering(self):
        lg = load("protocol-v0.2.json")["ledgers"][0]
        entries = [hx(e) for e in lg["log_entries"]]
        index = lg["presence"]["statement_index"]
        entry = cbor.decode(entries[index])
        sign1 = cbor.decode(entry[3])
        payload = cbor.decode(sign1.value[2])
        # Changing the client data's origin to another site breaks the proof.
        client = payload[8][3].replace(b"http://localhost:43210", b"https://evil.example")
        self.assertNotEqual(client, payload[8][3])
        with self.assertRaises(VerifyError):
            expected = presence.challenge(crypto.hash_function(lg["hash"]), protocol.parse_statement(entry[3]))
            presence._check_client_data(client, expected, "localhost")
        self.assertTrue(presence.origin_belongs("http://localhost:43210", "localhost"))
        self.assertTrue(presence.origin_belongs("https://a.example.org", "example.org"))
        self.assertFalse(presence.origin_belongs("http://example.org", "example.org"))
        self.assertFalse(presence.origin_belongs("https://badexample.org", "example.org"))


class ProtocolV04(unittest.TestCase):
    """Key rotation: the log key in effect by tree size."""

    def test_rotation(self):
        for lg in load("protocol-v0.4.json")["ledgers"]:
            ledger = replay(lg)
            self.assertEqual(ledger.root_rotations, 1)
            self.assertEqual(len(ledger.log_keys), 2)
            before = protocol.parse_tree_head(hx(lg["checkpoint_before"]), cose.CHECKPOINT_TYPE, "a checkpoint")
            ledger.check_signed_head(before, ledger.log_key_for_size(before.tree_size), "the old checkpoint")
            after = protocol.parse_tree_head(hx(lg["checkpoint"]), cose.CHECKPOINT_TYPE, "a checkpoint")
            ledger.check_signed_head(after, ledger.log_key_for_size(after.tree_size), "the new checkpoint")
            with self.assertRaises(VerifyError):
                ledger.check_signed_head(after, ledger.log_key_for_size(before.tree_size), "the new checkpoint")
            for p in lg["state_proofs"]:
                self.assertEqual(ledger.leaf(hx(p["id"])), [p["kind"], hx(p["id"]), p["history"]])


class GenericCoreAndVersions(unittest.TestCase):
    """v0.9 and v0.10: whole logs replay; every refused statement is refused
    for its reason; the replayed state equals the committed one."""

    def check(self, name: str):
        for lg in load(name)["ledgers"]:
            ledger = replay(lg)
            h = ledger.h
            leaves = sorted([ledger.leaf(i) for i in list(ledger.actors) + list(ledger.delegations)
                             + list(ledger.records)], key=lambda leaf: leaf[1])
            expected = [[x["kind"], hx(x["id"]), x["history"]] for x in lg["state_leaves"]]
            self.assertEqual(leaves, expected)
            self.assertEqual(statetree.root_of(h, leaves).hex(), lg["state_root"])
            self.assertEqual(ledger.commitments[lg["state_commitment"]["index"]].root.hex(), lg["state_root"])
            for r in lg["records"]:
                record = ledger.records[hx(r["id"])]
                self.assertEqual((record.type, record.state, record.revoked, record.history),
                                 (r["type"], r["state"], r["revoked"], r["history"]))
                if "superseded_by" in r:
                    self.assertEqual(record.superseded_by.hex() if record.superseded_by else None, r["superseded_by"])
            for refused in lg["refused"]:
                if refused["why"] == "no such record":
                    # A verifier holds only part of a log: a registration that
                    # supersedes a record the bundle does not hold is checked
                    # under every other rule (section 11, step 3).
                    continue
                with self.subTest(refused["name"]):
                    state = replay(lg, refused["after"])
                    statement = protocol.parse_statement if refused["malformed"] else None
                    signed = hx(refused["encoded"])
                    with self.assertRaises(VerifyError):
                        if statement is not None:
                            protocol.parse_statement(signed)
                        else:
                            s = protocol.parse_statement(signed)
                            sid = h(s.sign1.to_be_signed())
                            entry = protocol.LogEntry(encoded=b"", id=sid, registered_at=refused["at"],
                                                      statement=signed, commitment=None)
                            copy.deepcopy(state).apply(entry, refused["after"])

    def test_v09(self):
        self.check("protocol-v0.9.json")

    def test_v10(self):
        self.check("protocol-v0.10.json")


class Claims(unittest.TestCase):
    """v0.14: claim metadata, valid with its words and refused; a whole log
    with claims replays, every refused statement is refused, and each
    claim's report facts are the vectors'."""

    def test_metadata(self):
        d = load("protocol-v0.14.json")["claim_metadata"]
        for case in d["valid"]:
            with self.subTest(case["name"]):
                metadata = cbor.decode(hx(case["metadata"]))
                claim = claims.parse(metadata)
                self.assertEqual(claims.words(claim.condition), case["text"])
                self.assertEqual([[t.field, t.op, t.type, t.value] for t in claim.condition], case["condition"])
                self.assertEqual(cbor.encode(metadata).hex(), case["metadata"])
        for case in d["refused"]:
            with self.subTest(case["name"]), self.assertRaises(VerifyError):
                claims.parse(cbor.decode(hx(case["metadata"])))

    def test_log(self):
        for lg in load("protocol-v0.14.json")["ledgers"]:
            ledger = replay(lg)
            h = ledger.h
            leaves = sorted([ledger.leaf(i) for i in list(ledger.actors) + list(ledger.delegations)
                             + list(ledger.records)], key=lambda leaf: leaf[1])
            expected = [[x["kind"], hx(x["id"]), x["history"]] for x in lg["state_leaves"]]
            self.assertEqual(leaves, expected)
            self.assertEqual(statetree.root_of(h, leaves).hex(), lg["state_root"])
            self.assertEqual(ledger.commitments[lg["state_commitment"]["index"]].root.hex(), lg["state_root"])
            checkpoint = protocol.parse_tree_head(hx(lg["checkpoint"]), cose.CHECKPOINT_TYPE, "a checkpoint")
            self.assertEqual(checkpoint.timestamp, lg["checkpoint_time"])
            for r in lg["records"]:
                record = ledger.records[hx(r["id"])]
                self.assertEqual((record.type, record.state, record.revoked, record.history),
                                 (r["type"], r["state"], r["revoked"], r["history"]))
                if r["claim"] is None:
                    self.assertIsNone(record.claim)
                    continue
                c, want = record.claim, r["claim"]
                self.assertEqual(c.source.hex(), want["source"])
                self.assertEqual(ledger.records[c.source].type, want["source_type"])
                self.assertEqual(report.source_status(ledger, c), want["source_status"])
                self.assertEqual(claims.words(c.condition), want["text"])
                self.assertEqual((c.holds, c.as_of, c.until, c.subject), (want["holds"], want["as_of"],
                                                                         want["until"], want["subject"]))
                self.assertEqual([x.hex() for x in c.for_] if c.for_ else None, want["for"])
                self.assertEqual(c.until is not None and lg["checkpoint_time"] > c.until, want["lapsed"])
            self.assertEqual(sorted(r["id"] for r in lg["records"] if r["claim"]), sorted(lg["claims"]))
            for refused in lg["refused"]:
                with self.subTest(refused["name"]), self.assertRaises(VerifyError):
                    state = replay(lg, refused["after"])
                    signed = hx(refused["encoded"])
                    s = protocol.parse_statement(signed)
                    entry = protocol.LogEntry(encoded=b"", id=h(s.sign1.to_be_signed()), registered_at=refused["at"],
                                              statement=signed, commitment=None)
                    state.apply(entry, refused["after"])


class AskingAboutACondition(unittest.TestCase):
    """v0.15: access requests of both forms decode to their values, and each
    refused one is refused for its rule; claims answer requests about a
    condition, or are refused for the one acceptance check they fail."""

    def test_requests(self):
        d = load("protocol-v0.15.json")["access_requests"]
        for case in d["valid"]:
            with self.subTest(case["name"]):
                metadata = hx(case["metadata"])
                r = access.decode_access_request(metadata)
                self.assertEqual((r.ledger.hex(), r.record.hex(), r.purpose, r.until),
                                 (case["ledger"], case["record"], case["purpose"], case["until"]))
                self.assertEqual(r.recipient.hex() if r.recipient is not None else None, case["recipient"])
                self.assertEqual(list(r.fields) if r.fields is not None else None, case["fields"])
                self.assertEqual(list(r.attachments) if r.attachments is not None else None, case["attachments"])
                if case["condition"] is None:
                    self.assertIsNone(r.condition)
                    self.assertIsNone(case["text"])
                else:
                    terms = [[t.field, t.op, t.type, t.value] for t in r.condition]
                    self.assertEqual(cbor.encode(terms).hex(), case["condition"])
                    self.assertEqual(claims.words(r.condition), case["text"])
                # The decoded map, as a record's key 5 holds it, reads the same.
                self.assertEqual(access.decode_access_request(cbor.decode(metadata)), r)
        for case in d["refused"]:
            with self.subTest(case["name"]):
                with self.assertRaises(access.AccessError) as caught:
                    access.decode_access_request(hx(case["metadata"]))
                self.assertEqual(caught.exception.why, case["why"])

    def test_answers(self):
        for case in load("protocol-v0.15.json")["answers"]:
            with self.subTest(case["name"]):
                claim = claims.parse(cbor.decode(hx(case["claim"])))
                request = access.decode_access_request(hx(case["request"]))
                ledger, request_id = hx(case["requester_ledger"]), hx(case["request_id"])
                if case["accepted"]:
                    self.assertIsNone(case["why"])
                    access.claim_answers(claim, ledger, request_id, request)
                    # The metadata, undecoded, is checked the same way.
                    access.claim_answers(hx(case["claim"]), ledger, request_id, hx(case["request"]))
                    continue
                with self.assertRaises(access.AccessError) as caught:
                    access.claim_answers(claim, ledger, request_id, request)
                self.assertEqual(caught.exception.why, case["why"])


class TrustNodes(unittest.TestCase):
    """v0.16: the mechanism types; membership metadata, valid with its values
    and refused for its rule; where memberships stood at given times; a trust
    node's log replayed, every refused statement refused; and member ledgers'
    bundles with membership proofs, verified with their reports under the
    trust list, or refused whatever the list."""

    METADATA_RULES = {"no metadata", "unknown key", "missing key", "member", "kind", "name", "verified",
                      "registration", "jurisdiction", "until"}

    @classmethod
    def setUpClass(cls):
        cls.d = load("protocol-v0.16.json")

    def test_mechanism_types(self):
        types = self.d["mechanism_types"]
        self.assertEqual([t["type"] for t in types], list(rules.MECHANISM_TYPES))
        for t in types:
            initial, transitions = rules.MECHANISM_TYPES[t["type"]]
            self.assertEqual(initial, t["initial"])
            self.assertEqual(transitions, {tuple(x) for x in t["transitions"]})
            self.assertEqual(len(transitions), len(t["transitions"]))
        self.assertEqual(types[-1]["type"], memberships.MEMBERSHIP_TYPE)

    def test_metadata(self):
        d = self.d["membership_metadata"]
        for case in d["valid"]:
            with self.subTest(case["name"]):
                data = hx(case["metadata"])
                m = memberships.parse(data)
                want = case["membership"]
                self.assertEqual((m.member.hex(), m.kind, m.name, m.verified),
                                 (want["member"], want["kind"], want["name"], want["verified"]))
                self.assertEqual((m.registration, m.jurisdiction, m.until),
                                 (want.get("registration"), want.get("jurisdiction"), want.get("until")))
                self.assertEqual(cbor.encode(cbor.decode(data)).hex(), case["metadata"])
                # The decoded map, as a record's key 5 holds it, reads the same.
                self.assertEqual(memberships.parse(cbor.decode(data)), m)
        self.assertEqual({c["why"] for c in d["refused"]}, self.METADATA_RULES)
        for case in d["refused"]:
            with self.subTest(case["name"]):
                with self.assertRaises(memberships.MembershipError) as caught:
                    memberships.parse(hx(case["metadata"]))
                self.assertEqual(caught.exception.why, case["why"])

    def test_standings(self):
        seen = set()
        for case in self.d["standings"]:
            changes = [(c["at"], c["to"] or None) for c in case["changes"]]
            for t in case["cases"]:
                with self.subTest(case["name"], t=t["t"] - case["registered_at"]):
                    self.assertEqual(memberships.standing(case["registered_at"], case["until"], changes, t["t"]),
                                     t["standing"])
                    seen.add(t["standing"])
        self.assertEqual(seen, {"not_yet", "active", "suspended", "ended", "revoked", "lapsed"})

    def test_replay(self):
        for lg in self.d["replay"]["ledgers"]:
            ledger = replay(lg)
            h = ledger.h
            leaves = sorted([ledger.leaf(i) for i in list(ledger.actors) + list(ledger.delegations)
                             + list(ledger.records)], key=lambda leaf: leaf[1])
            self.assertEqual(leaves, [[x["kind"], hx(x["id"]), x["history"]] for x in lg["state_leaves"]])
            self.assertEqual(statetree.root_of(h, leaves).hex(), lg["state_root"])
            self.assertEqual(ledger.commitments[lg["state_commitment"]["index"]].root.hex(), lg["state_root"])
            checkpoint = protocol.parse_tree_head(hx(lg["checkpoint"]), cose.CHECKPOINT_TYPE, "a checkpoint")
            self.assertEqual(checkpoint.timestamp, lg["checkpoint_time"])
            for r in lg["records"]:
                record = ledger.records[hx(r["id"])]
                self.assertEqual((record.type, record.state, record.revoked, record.history, record.registrant.hex()),
                                 (r["type"], r["state"], r["revoked"], r["history"], r["registrant"]))
                if r["membership"] is None:
                    self.assertIsNone(record.membership)
                    continue
                m, want = record.membership, r["membership"]
                self.assertEqual((m.member.hex(), m.kind, m.name, m.verified, m.registration, m.jurisdiction,
                                  m.until),
                                 (want["member"], want["kind"], want["name"], want["verified"], want["registration"],
                                  want["jurisdiction"], want["until"]))
                registered_at, changes = memberships.history(ledger, record)
                self.assertEqual(registered_at, want["registered_at"])
                self.assertEqual(memberships.standing(registered_at, m.until, changes, lg["checkpoint_time"]),
                                 want["at_checkpoint"])
            self.assertEqual(sorted(r["id"] for r in lg["records"] if r["membership"]), sorted(lg["memberships"]))
            for refused in lg["refused"]:
                with self.subTest(refused["name"]):
                    state = replay(lg, refused["after"])
                    signed = hx(refused["encoded"])
                    s = protocol.parse_statement(signed)
                    entry = protocol.LogEntry(encoded=b"", id=h(s.sign1.to_be_signed()), registered_at=refused["at"],
                                              statement=signed, commitment=None)
                    with self.assertRaises(VerifyError) as caught:
                        state.apply(entry, refused["after"])
                    if refused["why"] in self.METADATA_RULES:
                        self.assertIsInstance(caught.exception, memberships.MembershipError)
                        self.assertEqual(caught.exception.why, refused["why"])

    @staticmethod
    def _expected(m) -> dict:
        v = m.values
        return {"trust_node": m.trust_node.hex(), "trusted": m.trusted, "trust_node_name": m.trust_node_name,
                "membership": m.membership.hex(), "kind": v.kind, "name": v.name, "verified": v.verified,
                "registration": v.registration, "jurisdiction": v.jurisdiction, "until": v.until,
                "registered_at": m.registered_at, "record_time": m.record_time, "at_record": m.at_record,
                "checkpoint_time": m.checkpoint_time, "at_checkpoint": m.at_checkpoint}

    def test_bundles(self):
        everyone = {}
        for case in self.d["bundles"]["valid"]:
            with self.subTest(case["name"]):
                nodes = {hx(t["ledger"]): t["name"] for t in case["trust_nodes"]}
                everyone.update(nodes)
                data = hx(case["bundle"])
                result = evidence.verify_bundle(data, ledger_id=hx(case["ledger"]), trust_nodes=nodes)
                self.assertTrue(result.complete)
                self.assertEqual([self._expected(m) for m in result.memberships], case["memberships"])
                for m in result.memberships:
                    self.assertTrue(m.report.complete)
                    # Never a name from the evidence: the trust node's own
                    # organization name is not the list's.
                    self.assertNotEqual(m.trust_node_name, m.report.ledger.name)
                # The report's JSON gives the same facts, its times in ISO 8601.
                j = report.to_json(result)["memberships"]
                self.assertEqual([list(x) for x in j], [list(x) for x in case["memberships"]])
                for x, want in zip(j, case["memberships"]):
                    for key in ("registered_at", "record_time", "checkpoint_time", "until"):
                        self.assertEqual(x[key], report.iso_time(want[key]))
                    self.assertEqual({k: x[k] for k in ("trusted", "trust_node_name", "at_record", "at_checkpoint")},
                                     {k: want[k] for k in ("trusted", "trust_node_name", "at_record", "at_checkpoint")})
                self.assertIn("Member ", report.to_text(result))
                # The trust list decides trust and names only.
                untrusted = evidence.verify_bundle(data, ledger_id=hx(case["ledger"]))
                self.assertTrue(all(not m.trusted and m.trust_node_name is None for m in untrusted.memberships))
                self.assertEqual([(m.at_record, m.at_checkpoint) for m in untrusted.memberships],
                                 [(m["at_record"], m["at_checkpoint"]) for m in case["memberships"]])
        reasons = set()
        for case in self.d["bundles"]["refused"]:
            reasons.add(case["why"])
            with self.subTest(case["name"]):
                for nodes in ({}, everyone):
                    with self.assertRaises(VerifyError):
                        evidence.verify_bundle(hx(case["bundle"]), ledger_id=hx(case["ledger"]), trust_nodes=nodes)
        self.assertEqual(reasons, {"another member", "nested", "twice", "incomplete", "not a membership",
                                   "does not verify", "metadata", "own ledger", "too many", "empty", "not bytes"})

    def test_bundles_without_proofs(self):
        """A bundle without key 9 reports no memberships, whatever the list."""
        case = self.d["bundles"]["valid"][0]
        bundle = cbor.decode(hx(case["bundle"]))
        del bundle[9]
        result = evidence.verify_bundle(cbor.encode(bundle), ledger_id=hx(case["ledger"]),
                                        trust_nodes={hx(t["ledger"]): t["name"] for t in case["trust_nodes"]})
        self.assertEqual(result.memberships, [])
        self.assertEqual(report.to_json(result)["memberships"], [])

    def _cli(self, argv) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(argv)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def test_command_line(self):
        case = self.d["bundles"]["valid"][0]
        node = case["trust_nodes"][0]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "bundle.cbor"
            path.write_bytes(hx(case["bundle"]))
            code, out = self._cli([str(path), "--ledger-id", case["ledger"], "--trust-node",
                                   f"{node['ledger']}={node['name']}", "--json"])
            self.assertEqual(code, cli.EXIT_VERIFIED)
            m = json.loads(out)["memberships"][0]
            self.assertEqual((m["trusted"], m["trust_node_name"], m["name"], m["at_record"]),
                             (True, node["name"], case["memberships"][0]["name"], "active"))
            code, out = self._cli([str(path), "--trust-node", f"{node['ledger']}={node['name']}"])
            self.assertEqual(code, cli.EXIT_VERIFIED)
            self.assertIn(f"Member       per {node['name']} (trust node {node['ledger'][:12]}), which you trust", out)
            code, out = self._cli([str(path), "--json"])
            self.assertEqual(code, cli.EXIT_VERIFIED)
            m = json.loads(out)["memberships"][0]
            self.assertEqual((m["trusted"], m["trust_node_name"]), (False, None))
            for bad in (node["ledger"], f"{node['ledger'][:12]}=HK Trust", f"{node['ledger']}=", "xyz=HK Trust"):
                with self.subTest(bad):
                    self.assertEqual(self._cli([str(path), "--trust-node", bad])[0], cli.EXIT_USAGE)
            twice = ["--trust-node", f"{node['ledger']}=A", "--trust-node", f"{node['ledger']}=B"]
            self.assertEqual(self._cli([str(path)] + twice)[0], cli.EXIT_USAGE)
            refused = self.d["bundles"]["refused"][0]
            path.write_bytes(hx(refused["bundle"]))
            self.assertEqual(self._cli([str(path), "--json"])[0], cli.EXIT_NOT_VERIFIED)


class TimeStampTokens(unittest.TestCase):
    """v0.11: RFC 3161 tokens by OpenSSL's responder."""

    def test_tokens(self):
        d = load("protocol-v0.11.json")
        roots = d["root"].encode()
        for case in d["cases"]:
            checkpoint = protocol.parse_tree_head(hx(case["checkpoint"]), cose.CHECKPOINT_TYPE, "a checkpoint")
            h = crypto.hash_function(case["hash"])
            imprint = h(checkpoint.sign1.payload)
            self.assertEqual(imprint.hex(), case["imprint"])
            info = timestamps.check_token(hx(case["token"]), imprint, case["hash"], roots)
            self.assertTrue(info.trusted)
            self.assertEqual((info.time_ms, info.accuracy_ms, info.authority),
                             (case["time"], case["accuracy"], case["authority"]))
            untrusted = timestamps.check_token(hx(case["token"]), imprint, case["hash"], b"")
            self.assertFalse(untrusted.trusted)
            # The certificate of the authority is no root: not trusted.
            self.assertFalse(timestamps.check_token(hx(case["token"]), imprint, case["hash"],
                                                    d["certificate"].encode()).trusted)
            with self.assertRaises(VerifyError):
                timestamps.check_token(hx(case["token"]), h(b"another checkpoint"), case["hash"], roots)


class VectorBundles(unittest.TestCase):
    """Bundles packed from the vectors' logs verify, completely."""

    def test_bundles(self):
        count = 0
        for name, ledger_id, record, data in vector_bundles.all_bundles():
            with self.subTest(name):
                result = evidence.verify_bundle(data, ledger_id=hx(ledger_id))
                self.assertTrue(result.complete)
                self.assertEqual(result.record.id.hex(), record)
                count += 1
                # Any flipped byte of the bundle fails.
                for position in range(0, len(data), max(1, len(data) // 25)):
                    damaged = bytearray(data)
                    damaged[position] ^= 0x01
                    with self.assertRaises(VerifyError):
                        evidence.verify_bundle(bytes(damaged), ledger_id=hx(ledger_id))
        self.assertGreater(count, 20)


if __name__ == "__main__":
    unittest.main()
