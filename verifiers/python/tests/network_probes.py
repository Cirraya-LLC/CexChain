# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Probes of open witness networks (spec v0.13, sections 10.2 and 11):
bundles forged here whose anchors carry network witnesses' cosignatures of
their checkpoint's note, of both kinds (Ed25519, cosignature/v1; ML-DSA-44,
a CosignedSubtree), each verified by both verifiers with the options it
names (the witnesses' verifier keys, a ledger witness, --min-witnesses).

A probe has the verdict the specification decides, and both verifiers must
reach it and, when they report, agree field by field; or it is open (the
specification does not say), and the probe prints what each verifier does.
A probe may also name a difference that is known and reported: it is
printed, and does not fail.

The cosignatures are made here from c2sp.org's texts with Python's
`cryptography`, apart from the verifier's own code (cexchain_verify/network.py).

Usage: python3 network_probes.py CEXCHAIN
Exit status 1 if a decided probe fails in either verifier, or the
verifiers' reports differ where no difference is known.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402

from cexchain_verify import cbor, crypto  # noqa: E402
from compare_reports import compare  # noqa: E402
from probes import Forge  # noqa: E402

T = 1_794_000_000  # the witnesses' time, POSIX seconds
COSIGNATURE_TYPE = "application/cexchain-cosignature+cbor"


def _seed(name: str) -> bytes:
    return hashlib.sha256(f"CexChain probe key: {name}".encode()).digest()


def _key_id(name: str, kind: int, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([kind]) + public).digest()[:4]


class Witness:
    """An open network's witness: Ed25519 (type 0x04) or ML-DSA-44 (0x06)."""

    def __init__(self, name: str, kind: int = 0x04, seed: str | None = None):
        self.name, self.kind = name, kind
        if kind == 0x04:
            self.key = ed25519.Ed25519PrivateKey.from_private_bytes(_seed(seed or name))
        else:
            self.key = mldsa.MLDSA44PrivateKey.from_seed_bytes(_seed(seed or name))
        self.public = self.key.public_key().public_bytes_raw()
        self.key_id = _key_id(name, kind, self.public)
        self.vkey = f"{name}+{self.key_id.hex()}+{base64.b64encode(bytes([kind]) + self.public).decode()}"

    def cosign(self, origin: str, size: int, root: bytes, at: int = T, signed_name: str | None = None,
               start: int = 0) -> bytes:
        if self.kind == 0x04:
            note = f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"
            message = f"cosignature/v1\ntime {at}\n{note}".encode()
        else:
            who = (signed_name or self.name).encode()
            message = (b"subtree/v1\n\0" + bytes([len(who)]) + who + struct.pack(">Q", at)
                       + bytes([len(origin.encode())]) + origin.encode() + struct.pack(">QQ", start, size) + root)
        return self.key_id + struct.pack(">Q", at) + self.key.sign(message)


def note_of(bundle: dict) -> tuple[str, int, bytes]:
    """(origin, size, root) of the bundle's checkpoint."""
    payload = cbor.decode(cbor.decode(bundle[3]).value[2])
    return "cirraya.com/cexchain/" + payload[1].hex(), payload[3], payload[4]


def forged(cosignatures=None, anchors=None, hash_alg: int = crypto.SHA256, ledger_witness: Witness | None = None):
    """A record's bundle whose anchor of its own checkpoint carries
    cosignatures(origin, size, root); or whose anchors are
    anchors(bundle, origin, size, root)."""
    f = Forge(hash_alg=hash_alg, name="Network Probe Org")
    record = f.record("root", f.ledger_id)

    def mutate(bundle):
        origin, size, root = note_of(bundle)
        if anchors is not None:
            bundle[8] = anchors(bundle, origin, size, root)
        else:
            bundle[8] = [{1: bundle[3], 4: cosignatures(origin, size, root)}]
        if ledger_witness is not None:
            # A ledger witness's COSE cosignature of the checkpoint, by the
            # same kind of key (section 10).
            payload = cbor.decode(bundle[3]).value[2]
            kid = f.h(cbor.encode([crypto.ED25519, ledger_witness.public]))
            protected = cbor.encode({1: crypto.ED25519, 3: COSIGNATURE_TYPE, 4: kid})
            signature = ledger_witness.key.sign(cbor.encode(["Signature1", protected, b"", payload]))
            bundle[4] = [cbor.encode(cbor.Tag(18, [protected, {}, payload, signature]))]
    return f.bundle(record, mutate=mutate)


def cases(tmp: str):
    out = []
    ed, ed2, ml = Witness("witness.example/ed"), Witness("witness.example/ed2"), Witness("witness.example/ml", 0x06)
    other = Witness("witness.example/ed", seed="another key")  # the same name, another key
    weak_public = (1).to_bytes(32, "little")  # the identity point: a small-order Ed25519 key
    weak_id = _key_id("witness.example/weak", 0x04, weak_public)
    weak_vkey = f"witness.example/weak+{weak_id.hex()}+{base64.b64encode(bytes([4]) + weak_public).decode()}"
    ledger_witness_file = os.path.join(tmp, "ledger-witness.pub")
    with open(ledger_witness_file, "wb") as f:
        f.write(cbor.encode([crypto.ED25519, ed.public]))

    def case(name, expect, build, *options, differs=None):
        out.append((name, expect, build, list(options), differs))

    def one(witness, **kw):
        return lambda: forged(lambda o, s, r: [[witness.name, witness.cosign(o, s, r, **kw)]])

    def raw(name, data):
        return lambda: forged(lambda o, s, r: [[name, data(o, s, r)]])

    # Section 11, step 8: trusted cosignatures verify, and count in step 6.
    case("an Ed25519 witness, trusted", True, one(ed), "--witness-vkey", ed.vkey, "--min-witnesses", "1")
    case("an Ed25519 witness, not trusted", True, one(ed))
    case("an ML-DSA-44 witness, trusted", True, one(ml), "--witness-vkey", ml.vkey, "--min-witnesses", "1")
    case("an ML-DSA-44 witness, not trusted", True, one(ml))
    case("an ML-DSA-44 witness, not trusted, one required", False, one(ml), "--min-witnesses", "1")

    def both():
        return forged(lambda o, s, r: [[ml.name, ml.cosign(o, s, r)], [ed.name, ed.cosign(o, s, r, at=T + 9)]])
    case("witnesses of both kinds, trusted, two required", True, both, "--witness-vkey", ed.vkey,
         "--witness-vkey", ml.vkey, "--min-witnesses", "2")
    case("witnesses of both kinds, trusted, three required", False, both, "--witness-vkey", ed.vkey,
         "--witness-vkey", ml.vkey, "--min-witnesses", "3")
    case("witnesses of both kinds, one trusted", True, both, "--witness-vkey", ml.vkey)
    case("a trusted witness's key given twice", True, one(ed), "--witness-vkey", ed.vkey, "--witness-vkey", ed.vkey)

    def twice():
        return forged(lambda o, s, r: [[ed.name, ed.cosign(o, s, r)], [ed.name, ed.cosign(o, s, r, at=T + 1)]])
    case("one witness's two cosignatures count once", False, twice, "--witness-vkey", ed.vkey, "--min-witnesses", "2")
    case("one untrusted witness's two cosignatures", True, twice)
    case("the same cosignature in two anchors of one checkpoint", True,
         lambda: forged(anchors=lambda b, o, s, r: [{1: b[3], 4: [[ed.name, ed.cosign(o, s, r)]]}] * 2),
         "--witness-vkey", ed.vkey)
    case("a ledger witness and a network witness, both trusted, two required", True,
         lambda: forged(lambda o, s, r: [[ed2.name, ed2.cosign(o, s, r)]], ledger_witness=ed),
         "--witness", ledger_witness_file, "--witness-vkey", ed2.vkey, "--min-witnesses", "2")
    case("one key as a ledger witness and as a network witness, two required", None,
         lambda: forged(lambda o, s, r: [[ed.name, ed.cosign(o, s, r)]], ledger_witness=ed),
         "--witness", ledger_witness_file, "--witness-vkey", ed.vkey, "--min-witnesses", "2")
    case("one key as a ledger witness and as a network witness, neither trusted", None,
         lambda: forged(lambda o, s, r: [[ed.name, ed.cosign(o, s, r)]], ledger_witness=ed))

    # A trusted witness's cosignature that does not verify fails the evidence.
    def broken(witness, change):
        return raw(witness.name, lambda o, s, r: change(witness.cosign(o, s, r)))

    def flip(c):
        return c[:-1] + bytes([c[-1] ^ 1])
    for witness in (ed, ml):
        kind = "Ed25519" if witness is ed else "ML-DSA-44"
        case(f"{kind}: a trusted witness's signature damaged", False, broken(witness, flip),
             "--witness-vkey", witness.vkey)
        case(f"{kind}: an untrusted witness's signature damaged", True, broken(witness, flip))
        case(f"{kind}: a trusted witness's time changed", False,
             broken(witness, lambda c: c[:4] + struct.pack(">Q", T + 1) + c[12:]), "--witness-vkey", witness.vkey)
        case(f"{kind}: a trusted witness's cosignature of another size", False,
             raw(witness.name, lambda o, s, r, w=witness: w.cosign(o, s + 1, r)), "--witness-vkey", witness.vkey)
        case(f"{kind}: a trusted witness's cosignature of another root", False,
             raw(witness.name, lambda o, s, r, w=witness: w.cosign(o, s, bytes(32))), "--witness-vkey", witness.vkey)
        case(f"{kind}: a trusted witness's cosignature under another origin", False,
             raw(witness.name, lambda o, s, r, w=witness: w.cosign(o[:-1] + "x", s, r)), "--witness-vkey",
             witness.vkey)
        case(f"{kind}: a trusted witness's cosignature with a byte more", False,
             broken(witness, lambda c: c + b"\0"), "--witness-vkey", witness.vkey)
        case(f"{kind}: a trusted witness's twelve bytes, no signature", False,
             broken(witness, lambda c: c[:12]), "--witness-vkey", witness.vkey)
    case("ML-DSA-44: the subtree signed under another witness's name", False,
         raw(ml.name, lambda o, s, r: ml.cosign(o, s, r, signed_name="witness.example/other")),
         "--witness-vkey", ml.vkey)
    case("ML-DSA-44: a subtree from 1, not from 0", False,
         raw(ml.name, lambda o, s, r: ml.cosign(o, s, r, start=1)), "--witness-vkey", ml.vkey)
    case("ML-DSA-44: an Ed25519 signature under its name and key ID", False,
         raw(ml.name, lambda o, s, r: ml.key_id + ed.cosign(o, s, r)[4:]), "--witness-vkey", ml.vkey)
    case("a weak Ed25519 key, trusted: its cosignature never verifies", False,
         raw("witness.example/weak", lambda o, s, r: weak_id + struct.pack(">Q", T) + weak_public + bytes(32)),
         "--witness-vkey", weak_vkey)

    # Others are counted, by name and key ID, and relied on for nothing.
    case("a trusted witness's name with another key: counted as another", True,
         lambda: forged(lambda o, s, r: [[ed.name, ed.cosign(o, s, r)], [other.name, other.cosign(o, s, r)]]),
         "--witness-vkey", ed.vkey)
    case("one key under two names, not trusted: two witnesses", True,
         lambda: forged(lambda o, s, r: [[ed.name, ed.cosign(o, s, r)], ["witness.example/zz", ed.cosign(o, s, r)]]))
    case("an untrusted witness's twelve bytes", True, raw("witness.example/a", lambda o, s, r: bytes(12)))
    case("8,192 bytes, not trusted", True, raw("witness.example/a", lambda o, s, r: bytes(8192)))

    # The CDDL (anchor, note-cosignature).
    case("eleven bytes", False, raw("witness.example/a", lambda o, s, r: bytes(11)))
    case("8,193 bytes", False, raw("witness.example/a", lambda o, s, r: bytes(8193)))
    case("an empty name", False, raw("", lambda o, s, r: ed.cosign(o, s, r)))
    case("a name of 256 bytes", False, raw("a" * 256, lambda o, s, r: ed.cosign(o, s, r)))
    case("a name of 255 bytes", True, raw("a" * 255, lambda o, s, r: ed.cosign(o, s, r)))
    case("a name of bytes, not text", False, raw(b"witness.example/a", lambda o, s, r: ed.cosign(o, s, r)))
    for label, name in (("a space", "witness example"), ("'+'", "witness+example"), ("a tab", "witness\texample"),
                        ("a control character", "witness\x01example"), ("a no-break space", "witness x")):
        case(f"a name with {label}", None, raw(name, lambda o, s, r: ed.cosign(o, s, r)))
    case("a name with a non-ASCII letter", True, raw("témoin.example", lambda o, s, r: ed.cosign(o, s, r)))
    case("an anchor with neither tokens nor network cosignatures", False, lambda: forged(anchors=lambda b, o, s, r: [
        {1: b[3]}]))
    case("an empty list of network cosignatures", False, lambda: forged(anchors=lambda b, o, s, r: [{1: b[3], 4: []}]))
    case("a cosignature of three items", False, lambda: forged(anchors=lambda b, o, s, r: [
        {1: b[3], 4: [[ed.name, ed.cosign(o, s, r), 0]]}]))
    case("an unknown anchor key", False, lambda: forged(anchors=lambda b, o, s, r: [
        {1: b[3], 4: [[ed.name, ed.cosign(o, s, r)]], 5: 0}]))
    case("an SM3 ledger's anchor with network cosignatures (section 10.2)", False,
         lambda: forged(lambda o, s, r: [[ed.name, ed.cosign(o, s, r)]], hash_alg=crypto.SM3))

    # T is reported, and not put to the clock rule.
    case("a witness's time long before the checkpoint", True, one(ed, at=0), "--witness-vkey", ed.vkey)
    case("a witness's time in the year 10000", True, one(ed, at=253_402_300_800), "--witness-vkey", ed.vkey)
    case("a witness's time in the year 33658", True, one(ed, at=10**12), "--witness-vkey", ed.vkey)
    case("a witness's time of 2^64 - 1 seconds", True, one(ed, at=2**64 - 1), "--witness-vkey", ed.vkey)
    return out


def _run(args: list, env=None) -> tuple[int, dict | None]:
    done = subprocess.run(args, capture_output=True, text=True, env=env)
    try:
        return done.returncode, json.loads(done.stdout)
    except ValueError:
        return done.returncode, {"verified": False, "error": (done.stderr or done.stdout).strip()[-200:]}


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cexchain = argv[1]
    env = dict(os.environ, PYTHONPATH=str(HERE.parent))
    failures = open_differ = known = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, expect, build, options, differs in cases(tmp):
            path = os.path.join(tmp, "probe.cbor")
            with open(path, "wb") as f:
                f.write(build())
            pe, py = _run([sys.executable, "-m", "cexchain_verify", path, "--json", *options], env)
            be, bb = _run([cexchain, "verify", path, "--json", *options])
            problems, _ = compare(py, pe, bb, be)
            py_ok, bb_ok = pe == 0, be == 0

            def verdict(ok, report):
                return "verified" if ok else f"refused ({(report or {}).get('error', '?')})"
            if expect is None:
                tag = "open, both agree" if not problems else "OPEN, THEY DIFFER"
                open_differ += bool(problems)
            elif py_ok != expect or bb_ok != expect:
                tag, failures = "WRONG", failures + 1
            elif problems and differs is not None:
                tag, known = f"as the spec says; a known difference: {differs}", known + 1
            elif problems:
                tag, failures = "THE REPORTS DIFFER", failures + 1
            else:
                tag = "as the spec says, the reports agree"
            print(f"  {tag}: {name}\n      python: {verdict(py_ok, py)}\n      cexchain verify: {verdict(bb_ok, bb)}")
            for line in problems:
                print(f"      differ: {line}")
    print(f"network probes: {failures} failed; {open_differ} open probe(s) on which the verifiers differ; "
          f"{known} known difference(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
