# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Test vectors for proposal and consent files (`exchange-file` in
spec/kanhe.cddl, extension .kanhe), encoded with cbor2 independently of
the C++ code: files a reader takes, each with the fields it reads, and files
it refuses, each with the reason. Writes testvectors/exchange-v1.json.

Usage: python3 tools/testvectors/exchange_vectors.py
"""

from __future__ import annotations

import json
import pathlib

import cbor2

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "testvectors" / "exchange-v1.json"

HOME = bytes([0x11]) * 32
INSTANCE = bytes([0x22]) * 32
FRIEND = bytes([0x33]) * 32
OTHER = bytes([0x44]) * 32
SHA256 = -16
SM3 = -65538


def encode(value) -> bytes:
    # Integer keys 1 to 11 encode as one byte each: RFC 7049 and RFC 8949
    # orderings agree, and cbor2's canonical form is the deterministic one.
    return cbor2.dumps(value, canonical=True)


def proposal(changes: dict | None = None) -> dict:
    file = {
        1: 1,
        2: "proposal",
        3: HOME,
        4: INSTANCE,
        5: 7,
        6: "lend",
        7: {"counterparty": FRIEND},
        8: SHA256,
        9: b"the instance's contract evidence",
        10: [FRIEND],
        11: "Lend it to me, please",
    }
    file.update(changes or {})
    return {k: v for k, v in file.items() if v is not None}


def consent(changes: dict | None = None) -> dict:
    file = {
        1: 1,
        2: "consent",
        3: HOME,
        4: INSTANCE,
        5: 7,
        6: "lend",
        7: {"counterparty": FRIEND},
        8: SHA256,
        9: b"the consent's evidence bundle",
    }
    file.update(changes or {})
    return {k: v for k, v in file.items() if v is not None}


def accepted(name: str, file: dict) -> dict:
    return {
        "name": name,
        "encoded": encode(file).hex(),
        "kind": file[2],
        "home": file[3].hex(),
        "instance": file[4].hex(),
        "head": file[5],
        "function": file[6],
        "arguments": encode(file[7]).hex(),
        "hash": file[8],
        "evidence": file[9].hex(),
        "needs": [n.hex() for n in file.get(10, [])],
        "note": file.get(11),
    }


def refused(name: str, encoded: bytes, reason: str) -> dict:
    return {"name": name, "encoded": encoded.hex(), "reason": reason}


def main() -> None:
    null_arguments = consent({6: "bring_back"})
    null_arguments[7] = None
    accept = [
        accepted("a proposal with a note", proposal()),
        accepted("a proposal without a note, for two ledgers, under SM3",
                 proposal({8: SM3, 10: [FRIEND, OTHER], 11: None})),
        accepted("a consent", consent()),
        accepted("a call with null arguments", null_arguments),
    ]
    # Every key of a consent, written in reverse order: not deterministic CBOR.
    backwards = dict(reversed(list(consent().items())))
    refuse = [
        refused("another format version", encode(proposal({1: 2})), "version"),
        refused("another kind", encode(proposal({2: "offer"})), "kind"),
        refused("a key it does not know", encode(proposal() | {12: 0}), "unknown key"),
        refused("a home of 31 bytes", encode(proposal({3: HOME[:31]})), "home"),
        refused("an instance that is text", encode(proposal({4: "instance"})), "instance"),
        refused("an empty function", encode(proposal({6: ""})), "function"),
        refused("a function of 65 bytes", encode(proposal({6: "f" * 65})), "function"),
        refused("a hash that is neither SHA-256 nor SM3", encode(proposal({8: -43})), "hash"),
        refused("no ledgers in a proposal's list", encode(proposal({10: []})), "needs"),
        refused("17 ledgers", encode(proposal({10: [bytes([n]) * 32 for n in range(17)]})),
                "needs"),
        refused("a proposal without its ledgers", encode(proposal({10: None})), "needs"),
        refused("a consent with a list of ledgers", encode(consent() | {10: [FRIEND]}), "needs"),
        refused("an empty note", encode(proposal({11: ""})), "note"),
        refused("a note of 1001 bytes", encode(proposal({11: "n" * 1001})), "note"),
        refused("no evidence", encode(proposal({9: b""})), "evidence"),
        refused("no arguments key", encode({k: v for k, v in consent().items() if k != 7}),
                "arguments"),
        refused("not a map", encode([1, "proposal"]), "shape"),
        refused("keys out of order", cbor2.dumps(backwards), "encoding"),
    ]
    document = {
        "description": "Proposal and consent files (exchange-file in spec/kanhe.cddl, .kanhe), "
                       "encoded independently with cbor2: files a reader takes, with what it reads, "
                       "and files it refuses, with why.",
        "accepted": accept,
        "refused": refuse,
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {len(accept)} accepted and {len(refuse)} refused files to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
