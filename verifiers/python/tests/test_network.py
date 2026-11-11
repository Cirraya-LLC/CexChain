# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Open witness networks (spec section 10.2, v0.13) against
testvectors/protocol-v0.13.json: the origin, the checkpoint note, the note
key's signed note, verifier keys and key IDs, every case's cosignature with
its verdict and time, the evidence anchor, and signed-note's own example;
then the anchor in evidence bundles, as section 11 verifies it.

Run from verifiers/python: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import struct
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from kanhe_verify import cbor, cose, crypto, evidence, network, protocol, report  # noqa: E402
from kanhe_verify.errors import VerifyError  # noqa: E402

import vector_bundles  # noqa: E402

VECTORS = HERE.parents[2] / "testvectors"
DASH = "—"  # a note signature line starts with an em dash and a space


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


def signature_lines(signed: str) -> tuple[str, list]:
    """A signed note (c2sp.org/signed-note): its text, ending with a
    newline, then a blank line, then lines "— <name> <base64>"."""
    text, blank, rest = signed.partition("\n\n")
    assert blank and rest.endswith("\n")
    lines = []
    for line in rest[:-1].split("\n"):
        assert line.startswith(DASH + " ")
        name, _, encoded = line[2:].partition(" ")
        lines.append((name, base64.b64decode(encoded, validate=True)))
    return text + "\n", lines


class OpenWitnessNetworks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = json.loads((VECTORS / "protocol-v0.13.json").read_text())
        cls.head = protocol.parse_tree_head(hx(cls.d["checkpoint"]), cose.CHECKPOINT_TYPE, "the checkpoint")

    def test_origin(self):
        self.assertEqual(self.head.ledger_id.hex(), self.d["ledger_id"])
        self.assertEqual(self.head.hash, crypto.SHA256)
        self.assertEqual(network.origin(hx(self.d["ledger_id"])), self.d["origin"])
        self.assertEqual(self.d["origin"], "cirraya.com/kanhe/" + self.d["ledger_id"])

    def test_note(self):
        note = network.checkpoint_note(self.d["origin"], self.head.tree_size, self.head.root)
        self.assertEqual(note, self.d["note"])
        lines = note.split("\n")
        self.assertEqual(lines[1:], [str(self.head.tree_size), base64.b64encode(self.head.root).decode(), ""])

    def test_signed_note(self):
        """The note key: Ed25519, seed SHA-256("Kanhe test key: note"),
        signature type 0x01, key name the origin."""
        origin, note = self.d["origin"], self.d["note"]
        key = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"Kanhe test key: note").digest())
        public = key.public_key().public_bytes_raw()
        vkey = network.parse_verifier_key(self.d["note_vkey"])
        self.assertEqual((vkey.name, vkey.kind, vkey.public.key), (origin, network.NOTE_ED25519, public))
        self.assertEqual(vkey.key_id, network.key_id(origin, 0x01, public))
        self.assertEqual(vkey.text, self.d["note_vkey"])
        text, lines = signature_lines(self.d["signed_note"])
        self.assertEqual(text, note)
        self.assertEqual([name for name, _ in lines], [origin])
        self.assertTrue(network.verify_note_signature(vkey, note, lines[0][1]))
        self.assertFalse(network.verify_note_signature(vkey, note.replace("\n15\n", "\n16\n"), lines[0][1]))
        # Ed25519 is deterministic: the signed note, byte for byte.
        line = f"{DASH} {origin} {base64.b64encode(vkey.key_id + key.sign(note.encode())).decode()}\n"
        self.assertEqual(self.d["signed_note"], note + "\n" + line)
        self.assertEqual(self.d["add_checkpoint"], "old 0\n\n" + self.d["signed_note"])
        # A log's key cosigns nothing: it is no network witness's key.
        with self.assertRaises(VerifyError):
            network.parse_witness_key(self.d["note_vkey"])

    def test_cases(self):
        origin = self.d["origin"]
        for case in self.d["cases"]:
            with self.subTest(case["name"]):
                vkey = network.parse_witness_key(case["vkey"])
                self.assertEqual(vkey.text, case["vkey"])
                self.assertEqual(vkey.name, case["cosigner"])
                data = hx(case["bytes"])
                self.assertEqual(data[:4], vkey.key_id)
                self.assertEqual(network.cosignature_time(data), case["time"])
                ok = network.verify_cosignature(vkey, origin, self.head.tree_size, self.head.root, data)
                self.assertEqual(ok, case["valid"])
                if not case["valid"]:
                    continue
                # Any other size, root, origin, or time, or a flipped bit of
                # the signature, fails.
                size, root = self.head.tree_size, self.head.root
                for args in ((origin, size + 1, root), (origin, size, bytes(32)), (origin[:-1] + "x", size, root)):
                    self.assertFalse(network.verify_cosignature(vkey, *args, data))
                later = data[:4] + struct.pack(">Q", case["time"] + 1) + data[12:]
                self.assertFalse(network.verify_cosignature(vkey, origin, size, root, later))
                flipped = data[:-1] + bytes([data[-1] ^ 1])
                self.assertFalse(network.verify_cosignature(vkey, origin, size, root, flipped))
                self.assertFalse(network.verify_cosignature(vkey, origin, size, root, data + b"\0"))

    def test_kinds(self):
        kinds = {case["name"]: network.parse_witness_key(case["vkey"]).kind for case in self.d["cases"]}
        self.assertEqual(kinds["ed25519"], network.COSIGNATURE_ED25519)
        self.assertEqual(kinds["ml-dsa-44"], network.COSIGNATURE_MLDSA44)
        ml = next(case for case in self.d["cases"] if case["name"] == "ml-dsa-44")
        self.assertEqual(len(hx(ml["bytes"])), 12 + 2420)
        # The base64 of a key holds '+' too: a verifier key splits at its
        # first two.
        self.assertTrue(any("+" in case["vkey"].split("+", 2)[2] for case in self.d["cases"]))

    def test_anchor(self):
        anchor = protocol.parse_anchor(cbor.decode(hx(self.d["anchor"])))
        self.assertEqual(anchor.checkpoint, hx(self.d["checkpoint"]))
        self.assertEqual((anchor.tokens, anchor.consistency), ([], None))
        valid = {case["cosigner"]: case for case in self.d["cases"] if case["valid"]}
        self.assertEqual([name for name, _ in anchor.cosignatures], list(valid))
        for name, data in anchor.cosignatures:
            case = valid[name]
            self.assertEqual(data.hex(), case["bytes"])
            vkey = network.parse_witness_key(case["vkey"])
            self.assertTrue(network.verify_cosignature(vkey, self.d["origin"], self.head.tree_size, self.head.root,
                                                       data))

    def test_c2sp_example(self):
        """signed-note's own example: its verifier key verifies its note."""
        example = self.d["c2sp_example"]
        vkey = network.parse_verifier_key(example["vkey"])
        self.assertEqual((vkey.name, vkey.kind), ("example.com/foo", network.NOTE_ED25519))
        signature = base64.b64decode(example["signature"])
        self.assertTrue(network.verify_note_signature(vkey, example["note"], signature))
        self.assertFalse(network.verify_note_signature(vkey, example["note"] + "\n", signature))

    def test_verifier_keys_refused(self):
        good = next(case["vkey"] for case in self.d["cases"] if case["name"] == "ml-dsa-44")
        name, hex_id, encoded = good.split("+", 2)
        body = encoded.rstrip("=")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        unused = body[:-1] + alphabet[alphabet.index(body[-1]) ^ 1] + encoded[len(body):]
        self.assertNotEqual(len(body), len(encoded), "the ML-DSA-44 key's base64 has padding")
        public = base64.b64decode(encoded)[1:]
        bad = {
            "two parts": f"{name}+{hex_id}",
            "an upper-case key ID": f"{name}+{hex_id.upper()}+{encoded}" if hex_id != hex_id.upper() else "x",
            "a key ID of another key": f"{name}+00000000+{encoded}",
            "a seven-digit key ID": f"{name}+{hex_id[:7]}+{encoded}",
            "base64 without its padding": f"{name}+{hex_id}+{body}",
            "base64 with extra padding": f"{name}+{hex_id}+{encoded}=",
            "base64 with unused bits set": f"{name}+{hex_id}+{unused}",
            "base64 with a space": f"{name}+{hex_id}+{encoded[:10]} {encoded[10:]}",
            "a trailing newline": good + "\n",
            "an empty name": f"+{network.key_id('', 6, public).hex()}+{encoded}",
            "a name with a space": f"a b+{network.key_id('a b', 6, public).hex()}+{encoded}",
            "a name of 256 bytes": f"{'a' * 256}+{network.key_id('a' * 256, 6, public).hex()}+{encoded}",
            "a key one byte short": (f"{name}+{network.key_id(name, 6, public[:-1]).hex()}+"
                                     f"{base64.b64encode(bytes([6]) + public[:-1]).decode()}"),
            "signature type 0x05": (f"{name}+{network.key_id(name, 5, public).hex()}+"
                                    f"{base64.b64encode(bytes([5]) + public).decode()}"),
            "no key": f"{name}+{network.key_id(name, 6, b'').hex()}+",
        }
        self.assertEqual(network.parse_witness_key(good).text, good)
        for why, text in bad.items():
            with self.subTest(why), self.assertRaises(VerifyError):
                network.parse_witness_key(text)

    def test_names(self):
        for name in ("witness.example/a", "a" * 255, "wé", "w\x7f", "w​"):
            self.assertTrue(network.valid_name(name), repr(name))
        for name in ("", "a" * 256, "a b", "a+b", "a\tb", "a\nb", "a\x01b", "a\x1fb", "a b", "a b",
                     "a　b", "a\udc80b", b"ab", None):
            self.assertFalse(network.valid_name(name), repr(name))


class NetworkEvidence(unittest.TestCase):
    """The v0.13 anchor in bundles of the v0.10 SHA-256 ledger (section 11,
    steps 6 and 8)."""

    @classmethod
    def setUpClass(cls):
        cls.bundles = list(vector_bundles.network_bundles())
        cls.d = json.loads((VECTORS / "protocol-v0.13.json").read_text())

    def verify(self, data: bytes, ledger_id: str, vkeys=()):
        keys = [network.parse_witness_key(v) for v in vkeys]
        return evidence.verify_bundle(data, ledger_id=hx(ledger_id), network_witnesses=keys)

    def test_trusted_and_not(self):
        self.assertGreater(len(self.bundles), 0)
        for name, ledger_id, record, data, vkeys in self.bundles:
            with self.subTest(name):
                both = self.verify(data, ledger_id, vkeys)
                self.assertEqual(both.record.id.hex(), record)
                self.assertTrue(both.complete)
                self.assertEqual((both.witnesses_trusted, both.witnesses_untrusted), (2, 0))
                self.assertEqual(report.to_json(both)["witnesses"], {
                    "trusted": 2, "untrusted": 0,
                    "network": [{"witness": case["cosigner"], "size": 15, "time": "2026-11-06T21:20:00.000Z",
                                 "trusted": True} for case in self.d["cases"] if case["valid"]]})
                none = self.verify(data, ledger_id)
                self.assertEqual((none.witnesses_trusted, none.witnesses_untrusted), (0, 2))
                self.assertEqual([n.trusted for n in none.network], [False, False])
                one = self.verify(data, ledger_id, vkeys[:1])
                self.assertEqual((one.witnesses_trusted, one.witnesses_untrusted), (1, 1))
                self.assertEqual([n.trusted for n in one.network], [True, False])
                # Each witness once, whatever times its cosignature is given.
                twice = cbor.decode(data)
                twice[8].append(twice[8][0])
                again = self.verify(cbor.encode(twice), ledger_id, vkeys)
                self.assertEqual((again.witnesses_trusted, len(again.network)), (2, 4))

    def test_damaged(self):
        _, ledger_id, _, data, vkeys = self.bundles[0]
        bundle = cbor.decode(data)
        for i in range(2):
            damaged = cbor.decode(data)
            name, sig = damaged[8][0][4][i]
            damaged[8][0][4][i] = [name, sig[:-1] + bytes([sig[-1] ^ 1])]
            encoded = cbor.encode(damaged)
            with self.subTest(f"cosignature {i} damaged"):
                with self.assertRaises(VerifyError):
                    self.verify(encoded, ledger_id, vkeys)
                # Not trusted: counted, and relied on for nothing.
                self.assertEqual(self.verify(encoded, ledger_id).witnesses_untrusted, 2)
        refused = {
            "an anchor with neither key 2 nor key 4": {1: bundle[3]},
            "an empty list of network cosignatures": {1: bundle[3], 4: []},
            "a cosignature of 11 bytes": {1: bundle[3], 4: [["witness.example/a", bytes(11)]]},
            "a cosignature of 8,193 bytes": {1: bundle[3], 4: [["witness.example/a", bytes(8193)]]},
            "a name with a space": {1: bundle[3], 4: [["witness example", bytes(12)]]},
            "a name of 256 bytes": {1: bundle[3], 4: [["a" * 256, bytes(12)]]},
            "an unknown anchor key": {1: bundle[3], 4: [["witness.example/a", bytes(12)]], 5: 0},
        }
        for why, anchor in refused.items():
            with self.subTest(why):
                damaged = cbor.decode(data)
                damaged[8] = [anchor]
                with self.assertRaises(VerifyError):
                    self.verify(cbor.encode(damaged), ledger_id)
        # Twelve bytes are a key ID and a time: an untrusted witness's is
        # counted; a trusted one's does not verify.
        short = cbor.decode(data)
        short[8] = [{1: bundle[3], 4: [["witness.example/a", bytes(12)]]}]
        self.assertEqual(self.verify(cbor.encode(short), ledger_id).witnesses_untrusted, 1)
        key = network.VerifierKey(name="witness.example/a", key_id=bytes(4), kind=network.COSIGNATURE_ED25519,
                                  public=network.parse_witness_key(vkeys[0]).public)
        with self.assertRaises(VerifyError):
            evidence.verify_bundle(cbor.encode(short), ledger_id=hx(ledger_id), network_witnesses=[key])

    def test_sm3_ledger_carries_none(self):
        anchor = cbor.decode(hx(self.d["anchor"]))
        for name, ledger_id, record, data in vector_bundles.all_bundles():
            bundle = cbor.decode(data)
            genesis = cbor.decode(cbor.decode(cbor.decode(bundle[2][0][0])[3]).value[2])
            if genesis[7][1] != crypto.SM3:
                continue
            bundle[8] = [{1: bundle[3], 4: anchor[4]}]
            with self.subTest(name), self.assertRaises(VerifyError):
                evidence.verify_bundle(cbor.encode(bundle), ledger_id=hx(ledger_id))
            break
        else:
            self.fail("no SM3 bundle among the vectors")


class Times(unittest.TestCase):
    def test_iso_time(self):
        import datetime
        epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        for ms in (0, 1, 999, 86_399_999, 951_782_400_000, 1_794_000_000_000, 4_107_542_400_000,
                   253_402_300_799_999, *range(0, 10**13, 7_777_777_777)):
            t = epoch + datetime.timedelta(milliseconds=ms)
            self.assertEqual(report.iso_time(ms), t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z")
            self.assertEqual(report.human_time(ms), t.strftime("%Y-%m-%d %H:%M:%S UTC"))
        # Beyond datetime's years: a network witness's time is 8 bytes.
        self.assertEqual(report.iso_time(253_402_300_800_000), "10000-01-01T00:00:00.000Z")
        self.assertEqual(report.iso_time(10**15), "33658-09-27T01:46:40.000Z")
        self.assertTrue(report.iso_time((2**64 - 1) * 1000).endswith("Z"))


if __name__ == "__main__":
    unittest.main()
