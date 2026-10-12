#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Writes testvectors/test-contracts.json: contracts for tests of the node,
assembled here and checked with the reference interpreter (wasm_ref.py).

The counting contract decides by how many consents a call cites, so a
registrar's dry runs can ask for consents and later accept the same call:
  - arguments that are an array of byte strings [out_0, ..., out_k]: the
    output is the content of out_min(n, k), where n is the number of consents
    the call cites (input key 8);
  - a text string: it aborts, with the text as the reason;
  - anything else (or an element that is not a byte string): it traps.
It walks the input's CBOR (a recursive skip), so it works for any input.

Usage:
    python3 tools/testvectors/test_contracts.py
"""

from __future__ import annotations

import json
import pathlib

import cbor2

import wasm_ref as w

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "testvectors"

# Imports: 0 input_size, 1 input_read, 2 output_write, 3 abort.
IMPORTS = ["input_size", "input_read", "output_write", "abort"]
ARG, HEAD_LENGTH, SKIP = 4, 5, 6


def info(p: int) -> list:
    return [("local.get", p), ("i32.load8_u", 0), ("i32.const", 31), ("i32.and",)]


def major(p: int) -> list:
    return [("local.get", p), ("i32.load8_u", 0), ("i32.const", 5), ("i32.shr_u",)]


def counting_contract() -> bytes:
    # Function 4: the argument of the item head at p (a length, a count, or
    # the low 32 bits of a number).
    arg = {"params": ["i32"], "results": ["i32"], "locals": ["i32"], "body": [
        *info(0), ("local.set", 1),
        ("local.get", 1), ("i32.const", 24), ("i32.lt_u",),
        ("if", None), ("local.get", 1), ("return",), ("end",),
        ("local.get", 1), ("i32.const", 24), ("i32.eq",),
        ("if", None), ("local.get", 0), ("i32.load8_u", 1), ("return",), ("end",),
        ("local.get", 1), ("i32.const", 25), ("i32.eq",),
        ("if", None),
        ("local.get", 0), ("i32.load8_u", 1), ("i32.const", 8), ("i32.shl",),
        ("local.get", 0), ("i32.load8_u", 2), ("i32.or",), ("return",),
        ("end",),
        # 26: four bytes from p + 1; 27: the low four of eight, from p + 5.
        ("local.get", 0),
        ("i32.const", 1), ("i32.const", 5), ("local.get", 1), ("i32.const", 26), ("i32.eq",), ("select",),
        ("i32.add",), ("local.set", 0),
        ("local.get", 0), ("i32.load8_u", 0), ("i32.const", 24), ("i32.shl",),
        ("local.get", 0), ("i32.load8_u", 1), ("i32.const", 16), ("i32.shl",), ("i32.or",),
        ("local.get", 0), ("i32.load8_u", 2), ("i32.const", 8), ("i32.shl",), ("i32.or",),
        ("local.get", 0), ("i32.load8_u", 3), ("i32.or",),
    ]}
    # Function 5: the length of the item head at p.
    head_length = {"params": ["i32"], "results": ["i32"], "locals": ["i32"], "body": [
        *info(0), ("local.set", 1),
        ("local.get", 1), ("i32.const", 24), ("i32.lt_u",),
        ("if", None), ("i32.const", 1), ("return",), ("end",),
        ("local.get", 1), ("i32.const", 24), ("i32.eq",),
        ("if", None), ("i32.const", 2), ("return",), ("end",),
        ("local.get", 1), ("i32.const", 25), ("i32.eq",),
        ("if", None), ("i32.const", 3), ("return",), ("end",),
        ("local.get", 1), ("i32.const", 26), ("i32.eq",),
        ("if", None), ("i32.const", 5), ("return",), ("end",),
        ("i32.const", 9),
    ]}
    # Function 6: where the item at p ends. Locals: major type, items to
    # skip, position.
    skip = {"params": ["i32"], "results": ["i32"], "locals": ["i32", "i32", "i32"], "body": [
        *major(0), ("local.set", 1),
        ("local.get", 0), ("call", ARG), ("local.set", 2),
        ("local.get", 0), ("local.get", 0), ("call", HEAD_LENGTH), ("i32.add",), ("local.set", 3),
        ("local.get", 1), ("i32.const", 2), ("i32.eq",), ("local.get", 1), ("i32.const", 3), ("i32.eq",),
        ("i32.or",),
        ("if", None), ("local.get", 3), ("local.get", 2), ("i32.add",), ("return",), ("end",),
        ("local.get", 1), ("i32.const", 5), ("i32.eq",),
        ("if", None), ("local.get", 2), ("i32.const", 1), ("i32.shl",), ("local.set", 2), ("end",),
        ("local.get", 1), ("i32.const", 6), ("i32.eq",),
        ("if", None), ("i32.const", 1), ("local.set", 2), ("end",),
        ("local.get", 1), ("i32.const", 4), ("i32.ge_u",), ("local.get", 1), ("i32.const", 6), ("i32.le_u",),
        ("i32.and",),
        ("if", None),
        ("block", None), ("loop", None),
        ("local.get", 2), ("i32.eqz",), ("br_if", 1),
        ("local.get", 3), ("call", SKIP), ("local.set", 3),
        ("local.get", 2), ("i32.const", 1), ("i32.sub",), ("local.set", 2),
        ("br", 0),
        ("end",), ("end",),
        ("end",),
        ("local.get", 3),
    ]}
    # Function 7, the entry. Locals: 0 input size, 1 position, 2 unused,
    # 3 entries left, 4 the arguments' position, 5 consents, 6 key,
    # 7 outputs, 8 the output's index.
    entry = {"locals": ["i32"] * 9, "body": [
        ("call", 0), ("local.set", 0),
        ("i32.const", 0), ("call", 1),
        ("i32.const", 0), ("i32.load8_u", 0), ("i32.const", 31), ("i32.and",), ("local.set", 3),
        ("i32.const", 1), ("local.set", 1),
        ("block", None), ("loop", None),
        ("local.get", 3), ("i32.eqz",), ("br_if", 1),
        ("local.get", 1), ("i32.load8_u", 0), ("local.set", 6),
        ("local.get", 1), ("i32.const", 1), ("i32.add",), ("local.set", 1),
        ("local.get", 6), ("i32.const", 2), ("i32.eq",),
        ("if", None), ("local.get", 1), ("local.set", 4), ("end",),
        ("local.get", 6), ("i32.const", 8), ("i32.eq",),
        ("if", None), ("local.get", 1), ("call", ARG), ("local.set", 5), ("end",),
        ("local.get", 1), ("call", SKIP), ("local.set", 1),
        ("local.get", 3), ("i32.const", 1), ("i32.sub",), ("local.set", 3),
        ("br", 0),
        ("end",), ("end",),
        # Text: abort with it.
        *major(4), ("i32.const", 3), ("i32.eq",),
        ("if", None),
        ("local.get", 4), ("local.get", 4), ("call", HEAD_LENGTH), ("i32.add",),
        ("local.get", 4), ("call", ARG),
        ("call", 3), ("return",),
        ("end",),
        # Anything but a non-empty array traps.
        *major(4), ("i32.const", 4), ("i32.ne",),
        ("if", None), ("unreachable",), ("end",),
        ("local.get", 4), ("call", ARG), ("local.set", 7),
        ("local.get", 7), ("i32.eqz",),
        ("if", None), ("unreachable",), ("end",),
        # The output's index: min(consents, outputs - 1).
        ("local.get", 5),
        ("local.get", 7), ("i32.const", 1), ("i32.sub",),
        ("local.get", 5), ("local.get", 7), ("i32.const", 1), ("i32.sub",), ("i32.lt_u",),
        ("select",), ("local.set", 8),
        ("local.get", 4), ("local.get", 4), ("call", HEAD_LENGTH), ("i32.add",), ("local.set", 1),
        ("block", None), ("loop", None),
        ("local.get", 8), ("i32.eqz",), ("br_if", 1),
        ("local.get", 1), ("call", SKIP), ("local.set", 1),
        ("local.get", 8), ("i32.const", 1), ("i32.sub",), ("local.set", 8),
        ("br", 0),
        ("end",), ("end",),
        # It must be a byte string: write its content.
        *major(1), ("i32.const", 2), ("i32.ne",),
        ("if", None), ("unreachable",), ("end",),
        ("local.get", 1), ("local.get", 1), ("call", HEAD_LENGTH), ("i32.add",),
        ("local.get", 1), ("call", ARG),
        ("call", 2),
    ]}
    return w.assemble([arg, head_length, skip, entry], imports=IMPORTS, memory=(4, 4))


def check(code: bytes) -> list[dict]:
    """Runs the contract on inputs shaped like a home's (spec section 15) and
    returns them, with what it did."""
    module = w.load(code)
    home, other = bytes(32 * [1]), bytes(32 * [2])
    outputs = [cbor2.dumps([2, [other]]), cbor2.dumps([1, {1: "done"}]), cbor2.dumps([1, {1: 2}])]
    signer = {1: 0}
    big_state = bytes(70_000)

    def call_input(arguments, consents: int, state=None) -> bytes:
        value = {1: "sign", 2: arguments, 3: home, 4: other,
                 5: {1: other, 2: 7, 3: state if state is not None else {"x": [1, 2, {3: -4}]}},
                 6: [other, signer], 7: 1_791_244_800_000}
        if consents:
            value[8] = [[other, {1: 1, 2: 1}]] * consents
        return cbor2.dumps(value, canonical=True)

    runs = []
    for consents in range(4):
        out = w.run(module, call_input(outputs, consents))
        expected = outputs[min(consents, len(outputs) - 1)]
        assert out[0] == "ok" and out[1] == expected, (consents, out)
        runs.append({"consents": consents, "output": expected.hex()})
    for state in (bytes(300), big_state):  # two- and four-byte lengths
        assert w.run(module, call_input(outputs, 0, state))[1] == outputs[0]
    aborted = w.run(module, call_input("no deal", 1))
    assert aborted[0] == "aborted" and aborted[3] == b"no deal", aborted
    assert w.run(module, call_input(7, 0))[0] == "unreachable"
    assert w.run(module, call_input([], 0))[0] == "unreachable"
    assert w.run(module, call_input(["not bytes"], 0))[0] == "unreachable"
    creation = cbor2.dumps({1: "propose", 2: [outputs[1]], 3: home, 4: other, 6: [other, signer],
                            7: 1_791_244_800_000}, canonical=True)
    assert w.run(module, creation)[1] == outputs[1]
    return runs


def main() -> None:
    code = counting_contract()
    runs = check(code)
    document = {
        "description": "Contracts for tests of the node, assembled by tools/testvectors/test_contracts.py "
                       "and checked with its reference interpreter. counting: arguments [out_0, ..., out_k] "
                       "(byte strings) make it write out_min(n, k), n being the number of consents the call "
                       "cites; a text string makes it abort with that reason; anything else traps.",
        "counting": code.hex(),
        "counting_runs": runs,
    }
    (OUT / "test-contracts.json").write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    main()
