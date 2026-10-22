#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Writes testvectors/bo-v1.json: the Bo compiler's conformance vectors.

For each contract: its source (in each language it is written in), its name
and interface, the bo-source bundle a deploy records (spec section 15), the
code our compiler builds from it and the code's SHA-256, the hashes of the
code codegens 1 to 3 built (informative: another compiler may build other
code; codegen 2 differs from codegen 3 only where R31 asks a consent, and
codegen 3 from codegen 4 only where a time rule's block does an action), each
function's fuel and output bounds (informative), and calls with their outcomes
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
    this script) and equal to tests/bo/golden/pack-digests.txt; key 6 names
    the vocabulary packs the source's `use` lines name, at the digests of
    their canonical CBOR, computed here from bo/vocab/*.vocab and, carried,
    bo/vocab/history/*.vocab (each equal to the C++ reader's canonical CBOR,
    and the carried versions' terms the beginning of the current ones');
  - each contract's deploys with earlier releases of the official language
    packs (its bundles as the vectors recorded them then: version 1, from
    before vocabulary packs, with no key 6; version 2, from before
    temperatures and field defaults; version 3, from before vocabulary pack
    files, with version 1 of the vocabulary packs in key 6; all in
    bo/packs/history/) are kept as
    "earlier", oldest first, each with the code it deployed, which must be
    the code built today with the codegen its compiler names.
The C++ test "the conformance vectors" then rebuilds each source to the same
code, bundle, interface, and bounds, rebuilds every earlier deploy to the same
code, replays each run, and compiles each source that must not build to the
same errors.

Usage (from CexChain/, after a GCC build):
    python3 tools/testvectors/bo_vectors.py [--tests build/gcc-debug/tests/cexchain_bo_tests]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

import cbor2

import wasm_ref as w

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "testvectors" / "bo-v1.json"
PACKS = ROOT / "bo" / "packs"
VOCAB = ROOT / "bo" / "vocab"
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


def terms_of(pack: dict):
    """A vocabulary pack's terms as one text (a file may give its lines)."""
    terms = pack.get("terms")
    return "".join(line + "\n" for line in terms) if isinstance(terms, list) else terms


def official_packs(vocabulary: list) -> dict:
    """Each official pack's (id, version) and the SHA-256 of its canonical
    CBOR: the language packs from bo/packs/*.pack and, carried so that old
    deploys rebuild, bo/packs/history/*.pack; the vocabulary packs from
    bo/vocab/*.vocab and bo/vocab/history/*.vocab (diagnostic notation read
    by this script), each equal to the canonical CBOR the C++ reader gives,
    a carried version's terms the beginning of its current version's. Each is
    checked against the C++ golden."""
    golden = {}
    for line in PACK_DIGESTS.read_text(encoding="utf-8").splitlines():
        pack_id, version, hash_name, digest = line.split()
        if hash_name == "SHA-256":
            golden[(pack_id, int(version))] = digest
    packs = {}
    for path in sorted(PACKS.glob("*.pack")) + sorted((PACKS / "history").glob("*.pack")):
        pack = read_pack(path.read_text(encoding="utf-8"))
        key = (pack["id"], pack["version"])
        packs[key] = hashlib.sha256(dcbor(pack)).hexdigest()
        assert golden.get(key) == packs[key], \
            f"{path.name}: digest {packs[key]}, but the golden says {golden.get(key)}"
    written = {(e["id"], e["version"]): bytes.fromhex(e["canonical"]) for e in vocabulary}
    terms = {}
    for path in sorted(VOCAB.glob("*.vocab")) + sorted((VOCAB / "history").glob("*.vocab")):
        value = read_pack(path.read_text(encoding="utf-8"))
        key = (value["id"], value["version"])
        canonical = dcbor(value)
        assert written.get(key) == canonical, f"{path.name}: the C++ reader's CBOR differs"
        assert value["format"] == 1 and value["edition"] == 1
        assert isinstance(value["concepts"], dict) and value["concepts"], path.name
        # A carried version's terms begin the current version's (the
        # compiler's library holds one meaning per action, and a later
        # version only adds actions' terms: services version 3).
        if path.parent == VOCAB:
            terms[value["id"]] = terms_of(value)
        else:
            assert terms_of(value) is None or terms[value["id"]].startswith(terms_of(value)), \
                f"{path.name}: terms"
        packs[key] = hashlib.sha256(canonical).hexdigest()
        assert golden.get(key) == packs[key], f"{path.name}: digest differs from the golden"
    assert set(written) == {k for k in packs if k[0] in terms}, "the vocabulary packs differ"
    assert set(packs) == set(golden), "the packs and their goldens differ"
    return packs


def uses(source: str) -> list:
    """The vocabulary packs a source's `use` lines name (`use` in English,
    使用 in Chinese), by id."""
    found = re.findall(r"^(?:use|使用) (\S+)\s*$", source, re.M)
    return sorted(set(found))


def check_bundle(bundle: bytes, source: str, packs: dict, version: int) -> None:
    """A bo-source bundle (spec/bo.md section 16, `bo-source` in the CDDL),
    decoded and checked: {1: 1, 2: edition, 3: source, 4: [+ [id, version,
    digest]], ? 6: [+ [id, version, digest]]}, deterministic, every language
    pack official (none embedded) at `version` and its digest, and key 6
    the vocabulary packs the source's `use` lines name, at their digests."""
    value = cbor2.loads(bundle)
    assert dcbor(value) == bundle, "the bundle is not deterministic CBOR"
    used = uses(source)
    assert set(value) == ({1, 2, 3, 4, 6} if used else {1, 2, 3, 4}), \
        f"bundle keys {sorted(value)}"
    assert value[1] == 1 and value[2] == 1, "format 1, edition 1"
    assert value[3] == source, "the bundle holds another source"
    refs = value[4]
    assert refs == sorted(refs, key=lambda r: r[0].encode("utf-8")) and refs, "pack order"
    for pack_id, pack_version, digest in refs:
        assert pack_version == version, f"pack {pack_id} version {pack_version}"
        assert packs[(pack_id, pack_version)] == digest.hex(), f"pack {pack_id} {pack_version}"
    if used:
        assert [r[0] for r in value[6]] == used, "key 6 is not the source's use lines"
        for pack_id, pack_version, digest in value[6]:
            # The official vocabulary packs' version of the release: 1 with
            # the language packs version 2 and 3, 2 with versions 4 and 5;
            # with version 6, commerce and services 3, finance 2.
            want = 1 if version < 4 else 2 if version < 6 or pack_id == "finance" else 3
            assert pack_version == want, f"vocabulary {pack_id} version"
            assert packs[(pack_id, pack_version)] == digest.hex(), f"vocabulary {pack_id}"


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
    if call.get("request") is not None:
        # An answer (spec v0.8): the request it answers, request-view.
        q = call["request"]
        inp[9] = {1: bytes.fromhex(q["id"]), 2: q["kind"], 3: cbor2.loads(bytes.fromhex(q["params"])),
                  4: q["deadline"], 5: q["asked_at"], 6: q["status"]}
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
    if 7 in accept:
        # Requests (spec v0.8): kind, params (text keys, values with a JSON
        # form), deadline, and reply.
        requests = accept[7]
        assert isinstance(requests, list) and 1 <= len(requests) <= 16, requests
        for q in requests:
            assert set(q) == {1, 2, 3, 4} and isinstance(q[1], str) and isinstance(q[4], str)
            assert isinstance(q[2], dict) and all(isinstance(k, str) for k in q[2])
            assert len(dcbor(q[2])) <= 4096
        out["requests"] = readable(requests)
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
    packs = official_packs(doc["vocabulary"])
    current = max(read_pack(path.read_text(encoding="utf-8"))["version"]
                  for path in PACKS.glob("*.pack"))
    # What each contract's deploys recorded with earlier releases of the
    # official language packs (version 1: no `use` lines, no key 6; version
    # 2: before temperatures and field defaults; version 3: before
    # vocabulary pack files), from the vectors as they were, oldest first:
    # old deploys must still rebuild to the same code.
    earlier = {}
    if pathlib.Path(args.out).exists():
        previous = json.loads(pathlib.Path(args.out).read_text(encoding="utf-8"))
        for c in previous["contracts"]:
            kept = c.get("earlier", [])
            kept = [kept] if isinstance(kept, dict) else list(kept)
            if "bundle" in c:
                old = cbor2.loads(bytes.fromhex(c["bundle"]))
                versions = {r[1] for r in old[4]}
                if versions != {current} and all(e["bundle"] != c["bundle"] for e in kept):
                    kept.append({"compiler": c["compiler"], "bundle": c["bundle"],
                                 "code_sha256": c["code_sha256"]})
            if kept:
                earlier[c["name"]] = kept
    contracts = {}
    for name, code_hex in doc["modules"].items():
        code = bytes.fromhex(code_hex)
        deploy = doc["deploys"][name]
        bundle = bytes.fromhex(deploy["bundle"])
        check_bundle(bundle, doc["sources"][name][0]["text"], packs, current)
        assert deploy["compiler"] == doc["compiler"]
        for old in earlier.get(name, []):
            old_bundle = bytes.fromhex(old["bundle"])
            version = cbor2.loads(old_bundle)[4][0][1]
            assert version < current, f"{name}: an earlier deploy at version {version}"
            check_bundle(old_bundle, cbor2.loads(old_bundle)[3], packs, version)
            if version == 1:
                assert not uses(cbor2.loads(old_bundle)[3]), f"{name}: use lines before packs"
            # The code of the codegen the deploy's compiler names (codegen
            # 4 reads a time rule's block with the actions it does).
            codegen = int(re.search(r"; codegen (\d+);", old["compiler"]).group(1))
            built = (hashlib.sha256(code).hexdigest() if codegen == doc["codegen"]
                     else deploy[f"codegen{codegen}_sha256"])
            assert old["code_sha256"] == built, \
                f"{name}: the code differs from the code deployed with packs version {version}"
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
            "codegen2_sha256": deploy["codegen2_sha256"],
            "codegen3_sha256": deploy["codegen3_sha256"],
            "bounds": deploy["bounds"],
            "runs": [],
            "_module": w.load(code),
        }
        if name in earlier:
            contracts[name]["earlier"] = [{
                "compiler": old["compiler"],
                "bundle": old["bundle"],
                "bundle_sha256": hashlib.sha256(bytes.fromhex(old["bundle"])).hexdigest(),
                "code_sha256": old["code_sha256"],
            } for old in earlier[name]]
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
                       "bo-source bundle a deploy records (official language packs version "
                       f"{current} and the vocabulary packs its use lines name, SHA-256 "
                       "digests), the bundles its deploys recorded with earlier releases of "
                       "the official packs, oldest first (earlier: language packs version 1, "
                       "no use lines; version 2, before temperatures and field defaults; "
                       "version 3, before vocabulary pack files, with version 1 of the "
                       "vocabulary packs; version 4, before requests, and version 5, before "
                       "a service's periods and bills, with version 2 of them; each rebuilds "
                       "to the code its compiler's codegen wrote), "
                       "and the code cexchain-bo builds, the hashes of its codegen 1 to 3 code, and its "
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
