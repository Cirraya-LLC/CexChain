#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Writes testvectors/bo-v1.json: the Bo compiler's conformance vectors.

For each contract: its source (in each language it is written in), its name
and interface, the bo-source bundle a deploy records (spec section 15), the
code our compiler builds from it and the code's SHA-256, the code codegen 1
built (informative: another compiler may build other code), each function's
fuel and output bounds (informative), and calls with their outcomes
(normative: any compiler's code must give the same outcomes, outputs, and
refusals; fuel is our code's). Then sources that must not build, with the
codes of their errors and their lines (normative). The C++ codegen tests
write them (tests/bo/codegen_test.cpp, the hidden case
[.codegen-reference]); this script checks each before writing it:
  - the input, encoded again here from the call (cbor2 to read the parts, a
    deterministic encoder written from RFC 8949 section 4.2.1), equals the
    bytes core's protocol::encode_contract_input wrote;
  - the reference interpreter (wasm_ref.py) gives the same outcome, output,
    fuel, and reason;
  - the output decodes as contract-output, which the vectors also show
    decoded;
  - the bundle decodes as a bo-source bundle holding the source as written,
    and its pack digests are the SHA-256 of each official pack's canonical
    CBOR, computed here from bo/packs/*.pack (diagnostic notation read by
    this script) and equal to tests/bo/golden/pack-digests.txt.
The C++ test "the conformance vectors" then rebuilds each source to the same
code, bundle, interface, and bounds, replays each run, and compiles each
source that must not build to the same errors.

Usage (from CexChain/, after a GCC build):
    python3 tools/testvectors/bo_vectors.py [--tests build/gcc-debug/tests/cexchain_bo_tests]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

import cbor2

import wasm_ref as w

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "testvectors" / "bo-v1.json"
PACKS = ROOT / "bo" / "packs"
PACK_DIGESTS = ROOT / "tests" / "bo" / "golden" / "pack-digests.txt"


def read_pack(text: str):
    """A language pack: CBOR diagnostic notation as the packs use it (JSON's
    values, with # comments to the end of a line and / ... / comments),
    read without the C++ code."""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif ch == "#":
            while i < len(text) and text[i] != "\n":
                i += 1
        elif ch == "/":
            i = text.index("/", i + 1) + 1
        else:
            out.append(ch)
            i += 1
    return json.loads("".join(out))


def official_packs() -> dict:
    """Each official pack's id, version, and the SHA-256 of its canonical
    CBOR, checked against the C++ golden."""
    golden = {}
    for line in PACK_DIGESTS.read_text(encoding="utf-8").splitlines():
        pack_id, version, hash_name, digest = line.split()
        if hash_name == "SHA-256":
            golden[pack_id] = (int(version), digest)
    packs = {}
    for path in sorted(PACKS.glob("*.pack")):
        pack = read_pack(path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(dcbor(pack)).hexdigest()
        packs[pack["id"]] = (pack["version"], digest)
        assert golden.get(pack["id"]) == (pack["version"], digest), \
            f"{path.name}: digest {digest}, but the golden says {golden.get(pack['id'])}"
    assert set(packs) == set(golden), "the packs and their goldens differ"
    return packs


def check_bundle(bundle: bytes, source: str, packs: dict) -> None:
    """A bo-source bundle (spec section 15, `bo-source` in the CDDL), decoded
    and checked: {1: 1, 2: edition, 3: source, 4: [+ [id, version, digest]]},
    deterministic, every pack official (none embedded) at its digest."""
    value = cbor2.loads(bundle)
    assert dcbor(value) == bundle, "the bundle is not deterministic CBOR"
    assert set(value) == {1, 2, 3, 4}, f"bundle keys {sorted(value)}"
    assert value[1] == 1 and value[2] == 1, "format 1, edition 1"
    assert value[3] == source, "the bundle holds another source"
    refs = value[4]
    assert refs == sorted(refs, key=lambda r: r[0].encode("utf-8")) and refs, "pack order"
    for pack_id, version, digest in refs:
        assert packs[pack_id] == (version, digest.hex()), f"pack {pack_id} {version}"


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | info]) + n.to_bytes(width, "big")
    raise ValueError("integer too large")


def dcbor(value) -> bytes:
    """Deterministic CBOR (RFC 8949 section 4.2.1): map keys sorted bytewise."""
    if isinstance(value, bool) or value is None:
        return {False: b"\xf4", True: b"\xf5", None: b"\xf6"}[value]
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(dcbor(v) for v in value)
    if isinstance(value, dict):
        items = sorted((dcbor(k), dcbor(v)) for k, v in value.items())
        assert len({k for k, _ in items}) == len(items), "duplicate key"
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(type(value))


def signer(s: dict) -> dict:
    out = {1: s["kind"]}
    if s["presence"] is not None:
        out[2] = s["presence"]
    if s["model"] is not None:
        out[3] = s["model"]
    return out


def contract_input(call: dict) -> bytes:
    """contract-input (spec section 15) from a call's parts."""
    inp = {
        1: call["function"],
        2: cbor2.loads(bytes.fromhex(call["arguments"])),
        3: bytes.fromhex(call["home"]),
        4: bytes.fromhex(call["contract"]),
        6: [bytes.fromhex(call["caller"]), signer(call["signer"])],
        7: call["time"],
    }
    if call["instance"] is not None:
        i = call["instance"]
        view = {1: bytes.fromhex(i["id"]), 2: i["head"], 3: cbor2.loads(bytes.fromhex(i["state"]))}
        if i["status"] is not None:
            view[4] = i["status"]
        if i["parties"]:
            view[5] = {role: bytes.fromhex(v) for role, v in i["parties"].items()}
        if i.get("parent") is not None:
            # A part (spec v0.7): its parent and depth.
            view[6] = [bytes.fromhex(i["parent"]), i["depth"]]
        inp[5] = view
    if call["consents"]:
        inp[8] = [[bytes.fromhex(l), signer(s)] for l, s in call["consents"]]
    return dcbor(inp)


def readable(value):
    """A decoded CBOR value as JSON: byte strings as hex."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [readable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): readable(v) for k, v in value.items()}
    return value


def result(outcome: str, output: bytes, reason: bytes) -> dict:
    """What a run did, decoded: accept, needs, or a refusal."""
    if outcome != "ok":
        return {"refused": reason.decode("utf-8")} if outcome == "aborted" else {"trap": outcome}
    decoded = cbor2.loads(output)
    assert dcbor(decoded) == output, "the output is not deterministic CBOR"
    assert isinstance(decoded, list) and len(decoded) == 2 and decoded[0] in (1, 2), decoded
    if decoded[0] == 2:
        assert decoded[1] == sorted(decoded[1]) and 1 <= len(decoded[1]) <= 16
        return {"needs": [l.hex() for l in decoded[1]]}
    accept = decoded[1]
    out = {"state": readable(accept[1])}
    if 2 in accept:
        out["status"] = accept[2]
    if 3 in accept:
        out["parties"] = readable(accept[3])
    if 4 in accept:
        out["events"] = readable(accept[4])
    if accept.get(5) is True:
        out["final"] = True
    if 6 in accept:
        out["children"] = readable(accept[6])
    return {"accept": out}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tests", default=str(ROOT / "build" / "gcc-debug" / "tests" /
                                              "cexchain_bo_tests"),
                        help="the GCC build's cexchain_bo_tests")
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "runs.json"
        env = dict(os.environ, CEXCHAIN_BO_CODEGEN_REFERENCE=str(path))
        subprocess.run([args.tests, "[.codegen-reference]"], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        doc = json.loads(path.read_text(encoding="utf-8"))

    # The VAT written every way it can be (codegen_test.cpp) is checked on
    # both interpreters and by the Python oracle in CTest bo_codegen_reference
    # each time; its 700-odd runs are left out of these vectors, which keep
    # the tax contract's and the dinner's bills (their test blocks).
    doc["modules"] = {n: c for n, c in doc["modules"].items() if not n.startswith("vat-")}
    doc["runs"] = [r for r in doc["runs"] if not r["module"].startswith("vat-")]
    packs = official_packs()
    contracts = {}
    for name, code_hex in doc["modules"].items():
        code = bytes.fromhex(code_hex)
        deploy = doc["deploys"][name]
        bundle = bytes.fromhex(deploy["bundle"])
        check_bundle(bundle, doc["sources"][name][0]["text"], packs)
        assert deploy["compiler"] == doc["compiler"]
        contracts[name] = {
            "name": name,
            "contract": deploy["contract"],
            "sources": doc["sources"][name],
            "interface": deploy["interface"],
            "compiler": deploy["compiler"],
            "bundle": deploy["bundle"],
            "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
            "code_sha256": hashlib.sha256(code).hexdigest(),
            "code": code_hex,
            "codegen1_sha256": deploy["codegen1_sha256"],
            "bounds": deploy["bounds"],
            "runs": [],
            "_module": w.load(code),
        }
    for run in doc["runs"]:
        c = contracts[run["module"]]
        raw = bytes.fromhex(run["input"])
        if run["call"] is not None:
            again = contract_input(run["call"])
            assert again == raw, f"{run['label']}: the input encodes differently here"
        outcome, output, fuel, reason = w.run(c["_module"], raw)
        recorded = (run["outcome"], bytes.fromhex(run["output"]), run["fuel"],
                    bytes.fromhex(run["reason"]))
        assert (outcome, output, fuel, reason) == recorded, \
            f"{run['label']}: here {outcome} {fuel} {reason!r}, recorded {recorded}"
        c["runs"].append({
            "label": run["label"],
            "call": run["call"],
            "input": run["input"],
            "outcome": outcome,
            "output": output.hex(),
            "fuel": fuel,
            "reason": reason.hex(),
            "result": result(outcome, output, reason),
        })

    out = {
        "format": 1,
        "description": "Bo conformance vectors (spec/bo.md, section 18): for each contract its "
                       "sources (in each language they are written in), name, interface, the "
                       "bo-source bundle a deploy records (official packs, SHA-256 digests), "
                       "and the code cexchain-bo builds, its codegen 1 code's hash, and its "
                       "functions' fuel and output bounds (informative); calls with their "
                       "outcomes (normative; fuel is this code's); and sources that must not "
                       "build, with their errors' codes and lines (normative). Inputs are "
                       "contract-input (spec section 15) as the ledger encodes them; reasons, "
                       "outputs, bundles, and code are hex.",
        "compiler": doc["compiler"],
        "codegen": doc["codegen"],
        "contracts": [{k: v for k, v in c.items() if not k.startswith("_")}
                      for c in contracts.values()],
        "errors": doc["errors"],
    }
    pathlib.Path(args.out).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    runs = sum(len(c["runs"]) for c in contracts.values())
    print(f"{args.out}: {len(contracts)} contracts, {runs} runs, all identical on the reference "
          f"interpreter; {len(doc['errors'])} sources that must not build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
