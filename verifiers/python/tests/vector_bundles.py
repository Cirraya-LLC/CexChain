# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Evidence bundles assembled from the independent test vectors.

The protocol vectors of revisions v0.2, v0.4, v0.9, v0.10, v0.14, and v0.16
(a trust node's log, with memberships) hold whole logs that the ledger rules
accept, each ending with a state commitment, and a checkpoint over them, all
built by tools/testvectors/generate.py (not by the C++ code). Their keys are throwaway test keys with published seeds, so a test
can sign the receipts a bundle needs. This module packs those logs into
evidence bundles, one per record: every entry of the log, its receipt, and
a state proof for every object. Both verifiers must accept them.

protocol-v0.13.json's anchor carries two open-network witnesses'
cosignatures (Ed25519 and ML-DSA-44) of the note of the v0.10 SHA-256
ledger's checkpoint: network_bundles() adds it to that ledger's bundles.

Usage: python3 vector_bundles.py OUT_DIR   (writes OUT_DIR/*.cbor and
OUT_DIR/index.json, which lists each bundle's ledger id and record, and
OUT_DIR/network.json, which lists the bundles with the v0.13 anchor, each
with its ledger id and the witnesses' verifier keys)
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from cexchain_verify import cbor, crypto, merkle, statetree  # noqa: E402

VECTORS = HERE.parents[2] / "testvectors"
VDS = {crypto.SHA256: 1, crypto.SM3: -65537}


def smt_proof(h, leaves: list, identifier: bytes) -> list:
    """Siblings from the root down to the leaf of `identifier`."""
    siblings, current, depth = [], leaves, 0
    while len(current) > 1:
        left = [leaf for leaf in current if statetree.bit(leaf[1], depth) == 0]
        right = [leaf for leaf in current if statetree.bit(leaf[1], depth) == 1]
        if statetree.bit(identifier, depth):
            siblings.append(statetree.root_of(h, left, depth + 1))
            current = right
        else:
            siblings.append(statetree.root_of(h, right, depth + 1))
            current = left
        depth += 1
    return siblings


def inclusion_path(h, index: int, leaves: list) -> list:
    n = len(leaves)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if index < k:
        return inclusion_path(h, index, leaves[:k]) + [merkle.tree_hash(h, leaves[k:])]
    return inclusion_path(h, index - k, leaves[k:]) + [merkle.tree_hash(h, leaves[:k])]


def receipt(h, hash_alg: int, log_key, entries: list, index: int) -> bytes:
    """An RFC 9942 receipt for entry `index` against the tree of all
    `entries`, signed by `log_key` (Ed25519)."""
    root = merkle.tree_hash(h, entries)
    public = [crypto.ED25519, log_key.public_key().public_bytes_raw()]
    protected = cbor.encode({1: crypto.ED25519, 4: h(cbor.encode(public)), 395: VDS[hash_alg]})
    proof = cbor.encode([len(entries), index, inclusion_path(h, index, entries)])
    signature = log_key.sign(cbor.encode(["Signature1", protected, b"", root]))
    return cbor.encode(cbor.Tag(18, [protected, {396: {-1: [proof]}}, None, signature]))


def key(seeds: dict, name: str):
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seeds[name]))


def bundle(ledger: dict, seeds: dict, log_key_name: str, subject: bytes, leaves: list) -> bytes:
    h = crypto.hash_function(ledger["hash"])
    entries = [bytes.fromhex(e) for e in ledger["log_entries"]]
    log_key = key(seeds, log_key_name)
    listed = [[entry, receipt(h, ledger["hash"], log_key, entries, i)] for i, entry in enumerate(entries)]
    proofs = [[leaf, smt_proof(h, leaves, leaf[1])] for leaf in leaves]
    return cbor.encode({0: 1, 1: subject, 2: listed, 3: bytes.fromhex(ledger["checkpoint"]), 7: proofs})


def _leaves(items: list) -> list:
    leaves = [[x["kind"], bytes.fromhex(x["id"]), x["history"]] for x in items]
    return sorted(leaves, key=lambda leaf: leaf[1])


def all_bundles():
    """Yields (name, ledger id, record id, bundle bytes)."""
    for version, log_key_name in (("v0.2", "log"), ("v0.4", "log_2")):
        document = json.loads((VECTORS / f"protocol-{version}.json").read_text())
        for ledger in document["ledgers"]:
            leaves = _leaves(ledger["state_proofs"])
            records = [leaf[1] for leaf in leaves if leaf[0] == statetree.RECORD]
            for record in records:
                name = f"{version}-{'sha256' if ledger['hash'] == crypto.SHA256 else 'sm3'}-{record.hex()[:8]}"
                data = bundle(ledger, document["seeds"], log_key_name, record, leaves)
                yield name, ledger["ledger_id"], record.hex(), data
    for version in ("v0.9", "v0.10", "v0.14", "v0.16"):
        document = json.loads((VECTORS / f"protocol-{version}.json").read_text())
        if version == "v0.16":
            document = document["replay"]
        for ledger in document["ledgers"]:
            leaves = _leaves(ledger["state_leaves"])
            for record in ledger["records"]:
                name = f"{version}-{'sha256' if ledger['hash'] == crypto.SHA256 else 'sm3'}-{record['id'][:8]}"
                data = bundle(ledger, document["seeds"], "log", bytes.fromhex(record["id"]), leaves)
                yield name, ledger["ledger_id"], record["id"], data


def network_bundles():
    """Yields (name, ledger id, record id, bundle bytes, the witnesses'
    verifier keys): the v0.10 SHA-256 ledger's bundles, with the anchor of
    protocol-v0.13.json, whose checkpoint is theirs."""
    document = json.loads((VECTORS / "protocol-v0.13.json").read_text())
    anchor = cbor.decode(bytes.fromhex(document["anchor"]))
    vkeys = [case["vkey"] for case in document["cases"] if case["valid"]]
    for name, ledger_id, record, data in all_bundles():
        if ledger_id != document["ledger_id"]:
            continue
        bundle = cbor.decode(data)
        assert bundle[3] == anchor[1], "the v0.13 anchor is not over the v0.10 checkpoint"
        bundle[8] = [anchor]
        yield f"network-{name}", ledger_id, record, cbor.encode(bundle), vkeys


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(next(line for line in __doc__.splitlines() if line.startswith("Usage:")), file=sys.stderr)
        return 1
    out = pathlib.Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    index = []
    for name, ledger_id, record, data in all_bundles():
        (out / f"{name}.cbor").write_bytes(data)
        index.append({"file": f"{name}.cbor", "ledger_id": ledger_id, "record": record})
    (out / "index.json").write_text(json.dumps(index, indent=1) + "\n")
    network = []
    for name, ledger_id, record, data, vkeys in network_bundles():
        (out / f"{name}.cbor").write_bytes(data)
        network.append({"file": f"{name}.cbor", "ledger_id": ledger_id, "record": record, "vkeys": vkeys})
    (out / "network.json").write_text(json.dumps(network, indent=1) + "\n")
    print(f"wrote {len(index) + len(network)} bundles to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
