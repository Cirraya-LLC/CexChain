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

The splitting contract (split_contract) is a receivable whose parts are
child instances (spec section 15, v0.7): issue, split, transfer.
protocol-v0.7.json runs it too.

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


def arg_function() -> dict:
    """Function 4: the argument of the item head at p (a length, a count, or
    the low 32 bits of a number)."""
    return {"params": ["i32"], "results": ["i32"], "locals": ["i32"], "body": [
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


def head_length_function() -> dict:
    """Function 5: the length of the item head at p."""
    return {"params": ["i32"], "results": ["i32"], "locals": ["i32"], "body": [
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


def skip_function() -> dict:
    """Function 6: where the item at p ends. Locals: major type, items to
    skip, position."""
    return {"params": ["i32"], "results": ["i32"], "locals": ["i32", "i32", "i32"], "body": [
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


def counting_contract() -> bytes:
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
    return w.assemble([arg_function(), head_length_function(), skip_function(), entry], imports=IMPORTS,
                      memory=(4, 4))


# ---------------------------------------------------------------------------
# The splitting contract (spec section 15, "Instances created by a call")
# ---------------------------------------------------------------------------

U64, PUT, HEAD, EQ32, CONSENTED = 7, 8, 9, 10, 11
SPLIT_IN, SPLIT_OUT = 8192, 1024
SPLIT_FUNCTIONS = {"issue": 1, "split": 2, "transfer": 2}
# Constant pieces of its outputs, and its reasons, at the start of memory.
SPLIT_CONSTANTS = [
    ("accept_issue", b"\x82\x01\xa3\x01\x82"),  # [1, {1: [
    ("accept_split", b"\x82\x01\xa4\x01"),  # [1, {1:
    ("accept_transfer", b"\x82\x01\xa2\x01"),  # [1, {1:
    ("status_active", b"\x02\x66active"),
    ("status_split", b"\x02\x65split"),
    ("final_children", b"\x05\xf5\x06"),  # 5: true, 6:
    ("child", b"\xa3\x01\x82"),  # {1: [
    ("holder", b"\x03\xa1\x66holder\x58\x20"),  # 3: {"holder": h'<32 bytes>'}
    ("needs", b"\x82\x02\x81\x58\x20"),  # [2, [h'<32 bytes>']]
    ("bad_arguments", b"bad arguments"),
    ("no_amount", b"the amount must be positive"),
    ("bad_part", b"a part must be positive and within the amount"),
    ("bad_sum", b"the parts do not add up to the amount"),
]


def _get(i):
    return ("local.get", i)


def _set(i):
    return ("local.set", i)


def _c(v):
    return ("i32.const", v)


def u64_function() -> dict:
    """Function 7 (U64): the unsigned value of the item head at p, all 64
    bits. Locals: additional information, bytes left, value."""
    get, put, c = _get, _set, _c
    return {"params": ["i32"], "results": ["i64"], "locals": ["i32", "i32", "i64"], "body": [
        get(0), ("i32.load8_u", 0), c(31), ("i32.and",), put(1),
        get(1), c(24), ("i32.lt_u",),
        ("if", None), get(1), ("i64.extend_i32_u",), ("return",), ("end",),
        c(1), get(1), c(24), ("i32.sub",), ("i32.shl",), put(2),
        ("block", None), ("loop", None),
        get(2), ("i32.eqz",), ("br_if", 1),
        get(0), c(1), ("i32.add",), put(0),
        get(3), ("i64.const", 8), ("i64.shl",), get(0), ("i64.load8_u", 0), ("i64.or",), put(3),
        get(2), c(1), ("i32.sub",), put(2),
        ("br", 0),
        ("end",), ("end",),
        get(3),
    ]}


def put_function() -> dict:
    """Function 8 (PUT): copies len bytes from src to out; returns out + len."""
    get = _get
    return {"params": ["i32", "i32", "i32"], "results": ["i32"], "body": [
        get(0), get(1), get(2), ("memory.copy",),
        get(0), get(2), ("i32.add",),
    ]}


def head_function() -> dict:
    """Function 9 (HEAD): writes a head of major type mt (shifted) and value v
    at out, in its shortest form; returns where it ends. Locals: bytes after
    the first, additional information, bytes left to write."""
    get, put, c = _get, _set, _c
    return {"params": ["i32", "i32", "i64"], "results": ["i32"], "locals": ["i32", "i32", "i32"], "body": [
        get(2), ("i64.const", 24), ("i64.lt_u",),
        ("if", None),
        get(0), get(1), get(2), ("i32.wrap_i64",), ("i32.or",), ("i32.store8", 0),
        get(0), c(1), ("i32.add",), ("return",),
        ("end",),
        c(1), put(3), c(24), put(4),
        *[x for limit, n, info in ((0xFF, 2, 25), (0xFFFF, 4, 26), (0xFFFF_FFFF, 8, 27))
          for x in (get(2), ("i64.const", limit), ("i64.gt_u",),
                    ("if", None), c(n), put(3), c(info), put(4), ("end",))],
        get(0), get(1), get(4), ("i32.or",), ("i32.store8", 0),
        get(3), put(5),
        ("block", None), ("loop", None),
        get(5), ("i32.eqz",), ("br_if", 1),
        get(0), get(5), ("i32.add",), get(2), ("i32.wrap_i64",), ("i32.store8", 0),
        get(2), ("i64.const", 8), ("i64.shr_u",), put(2),
        get(5), c(1), ("i32.sub",), put(5),
        ("br", 0),
        ("end",), ("end",),
        get(0), c(1), ("i32.add",), get(3), ("i32.add",),
    ]}


def _constants() -> tuple[dict, bytes]:
    where, data = {}, b""
    for name, raw in SPLIT_CONSTANTS:
        where[name] = (len(data), len(raw))
        data += raw
    return where, data


def split_contract() -> bytes:
    """A receivable that splits into parts, each a child instance. Its state is
    [amount, tier] and its parties {"holder": ledger}:
      - issue (creates): arguments [holder, amount], amount >= 1; the state
        [amount, 1], status "active";
      - split: arguments [[ledger, amount], ...], the parts' amounts >= 1 and
        adding up to the amount; the instance ends with status "split", and
        each part becomes a child [amount, tier + 1], "active", held by its
        ledger. It checks no count and no tier: the ledger's limits apply;
      - transfer: arguments a ledger, the new holder.
    Split and transfer need the holder's consent, unless the holder is the
    home ([2, [holder]] otherwise). Malformed arguments abort; so do parts
    that do not add up. Imports: input_size 0, input_read 1, output_write 2,
    abort 3."""
    where, data = _constants()

    def get(i):
        return ("local.get", i)

    def put(i):
        return ("local.set", i)

    def c(v):
        return ("i32.const", v)

    def const(name):
        return [c(where[name][0]), c(where[name][1])]

    def put_const(out, name):
        return [get(out), *const(name), ("call", PUT), put(out)]

    def fail(name):
        return [*const(name), ("call", 3), ("return",)]

    u64, put_fn, head = u64_function(), put_function(), head_function()
    # Function 10: whether the 32 bytes at a equal those at b.
    eq32 = {"params": ["i32", "i32"], "results": ["i32"], "body": [
        get(0), ("i64.load", 0), get(1), ("i64.load", 0), ("i64.eq",),
        *[x for off in (8, 16, 24)
          for x in (get(0), ("i64.load", off), get(1), ("i64.load", off), ("i64.eq",), ("i32.and",))],
    ]}
    # Function 11: whether the holder at h needs no consent: it is the home
    # (at home), or the call cites its consent (the input's key 8 at
    # consents, or 0). Locals: consents left, position.
    consented = {"params": ["i32", "i32", "i32"], "results": ["i32"], "locals": ["i32", "i32"], "body": [
        get(0), get(1), ("call", EQ32),
        ("if", None), c(1), ("return",), ("end",),
        get(2), ("i32.eqz",),
        ("if", None), c(0), ("return",), ("end",),
        get(2), ("call", ARG), put(3),
        get(2), get(2), ("call", HEAD_LENGTH), ("i32.add",), put(4),
        ("block", None), ("loop", None),
        get(3), ("i32.eqz",), ("br_if", 1),
        get(4), c(3), ("i32.add",), get(0), ("call", EQ32),
        ("if", None), c(1), ("return",), ("end",),
        get(4), ("call", SKIP), put(4),
        get(3), c(1), ("i32.sub",), put(3),
        ("br", 0),
        ("end",), ("end",),
        c(0),
    ]}
    # Function 12, the entry. Locals: 0 position, 1 entries left, 2 key,
    # 3 function, 4 arguments, 5 home ledger, 6 instance view, 7 consents,
    # 8 state, 9 holder ledger, 10 output end, 11 parts, 12 part, 13 parts
    # left; 14 amount, 15 sum, 16 a part's amount, 17 tier (i64).
    P, N, KEY, FN, ARGS, HOME, VIEW, CONSENTS, STATE, HOLDER, OUT, K, R, I = range(14)
    AMOUNT, SUM, A, TIER = range(14, 18)

    def walk_map(at, keys):
        """Walks the map at local `at`, running keys[k] at each key k with P
        at its value."""
        out = [get(at), ("call", ARG), put(N), get(at), get(at), ("call", HEAD_LENGTH), ("i32.add",), put(P),
               ("block", None), ("loop", None),
               get(N), ("i32.eqz",), ("br_if", 1),
               get(P), ("i32.load8_u", 0), put(KEY),
               get(P), c(1), ("i32.add",), put(P)]
        for k, then in keys.items():
            out += [get(KEY), c(k), ("i32.eq",), ("if", None), *then, ("end",)]
        return out + [get(P), ("call", SKIP), put(P),
                      get(N), c(1), ("i32.sub",), put(N),
                      ("br", 0), ("end",), ("end",)]

    def not_ledger(at, offset):
        """1 unless the bytes at local `at` + offset are the head of a
        32-byte string."""
        return [get(at), ("i32.load8_u", offset), c(0x58), ("i32.ne",),
                get(at), ("i32.load8_u", offset + 1), c(0x20), ("i32.ne",), ("i32.or",)]

    def not_uint(at, offset):
        return [get(at), ("i32.load8_u", offset), c(5), ("i32.shr_u",)]

    def write():
        return [c(SPLIT_OUT), get(OUT), c(SPLIT_OUT), ("i32.sub",), ("call", 2), ("return",)]

    def ask_holder():
        return [get(HOLDER), get(HOME), get(CONSENTS), ("call", CONSENTED), ("i32.eqz",),
                ("if", None),
                c(SPLIT_OUT), put(OUT), *put_const(OUT, "needs"),
                get(OUT), get(HOLDER), c(32), ("call", PUT), put(OUT),
                *write(),
                ("end",)]

    def copy_state():
        return [get(OUT), get(STATE), get(STATE), ("call", SKIP), get(STATE), ("i32.sub",), ("call", PUT), put(OUT)]

    issue = [
        get(ARGS), ("i32.load8_u", 0), c(0x82), ("i32.ne",), *not_ledger(ARGS, 1), ("i32.or",),
        *not_uint(ARGS, 35), ("i32.or",),
        ("if", None), *fail("bad_arguments"), ("end",),
        get(ARGS), c(35), ("i32.add",), ("call", U64), put(AMOUNT),
        get(AMOUNT), ("i64.eqz",),
        ("if", None), *fail("no_amount"), ("end",),
        *put_const(OUT, "accept_issue"),
        get(OUT), c(0), get(AMOUNT), ("call", HEAD), put(OUT),
        get(OUT), c(1), ("i32.store8", 0), get(OUT), c(1), ("i32.add",), put(OUT),
        *put_const(OUT, "status_active"), *put_const(OUT, "holder"),
        get(OUT), get(ARGS), c(3), ("i32.add",), c(32), ("call", PUT), put(OUT),
        *write(),
    ]

    def each_part(body):
        return [get(ARGS), get(ARGS), ("call", HEAD_LENGTH), ("i32.add",), put(R), get(K), put(I),
                ("block", None), ("loop", None),
                get(I), ("i32.eqz",), ("br_if", 1),
                *body,
                get(R), ("call", SKIP), put(R),
                get(I), c(1), ("i32.sub",), put(I),
                ("br", 0), ("end",), ("end",)]

    split = [
        get(ARGS), ("i32.load8_u", 0), c(5), ("i32.shr_u",), c(4), ("i32.ne",),
        ("if", None), *fail("bad_arguments"), ("end",),
        get(STATE), c(1), ("i32.add",), ("call", U64), put(AMOUNT),
        get(STATE), c(1), ("i32.add",), get(STATE), c(1), ("i32.add",), ("call", HEAD_LENGTH), ("i32.add",),
        ("call", U64), put(TIER),
        get(ARGS), ("call", ARG), put(K),
        ("i64.const", 0), put(SUM),
        *each_part([
            get(R), ("i32.load8_u", 0), c(0x82), ("i32.ne",), *not_ledger(R, 1), ("i32.or",),
            *not_uint(R, 35), ("i32.or",),
            ("if", None), *fail("bad_arguments"), ("end",),
            get(R), c(35), ("i32.add",), ("call", U64), put(A),
            get(A), ("i64.eqz",),
            get(A), get(AMOUNT), get(SUM), ("i64.sub",), ("i64.gt_u",), ("i32.or",),
            ("if", None), *fail("bad_part"), ("end",),
            get(SUM), get(A), ("i64.add",), put(SUM),
        ]),
        get(SUM), get(AMOUNT), ("i64.ne",),
        ("if", None), *fail("bad_sum"), ("end",),
        *ask_holder(),
        *put_const(OUT, "accept_split"), *copy_state(),
        *put_const(OUT, "status_split"), *put_const(OUT, "final_children"),
        get(OUT), c(0x80), get(K), ("i64.extend_i32_u",), ("call", HEAD), put(OUT),
        *each_part([
            *put_const(OUT, "child"),
            get(OUT), c(0), get(R), c(35), ("i32.add",), ("call", U64), ("call", HEAD), put(OUT),
            get(OUT), c(0), get(TIER), ("i64.const", 1), ("i64.add",), ("call", HEAD), put(OUT),
            *put_const(OUT, "status_active"), *put_const(OUT, "holder"),
            get(OUT), get(R), c(3), ("i32.add",), c(32), ("call", PUT), put(OUT),
        ]),
        *write(),
    ]

    transfer = [
        *not_ledger(ARGS, 0),
        ("if", None), *fail("bad_arguments"), ("end",),
        *ask_holder(),
        *put_const(OUT, "accept_transfer"), *copy_state(), *put_const(OUT, "holder"),
        get(OUT), get(ARGS), c(2), ("i32.add",), c(32), ("call", PUT), put(OUT),
        *write(),
    ]

    def on(letter, body):
        return [get(FN), ("i32.load8_u", 1), c(ord(letter)), ("i32.eq",), ("if", None), *body, ("end",)]

    entry = {"locals": ["i32"] * 14 + ["i64"] * 4, "body": [
        c(SPLIT_IN), ("call", 1),
        c(SPLIT_IN), put(VIEW),
        *walk_map(VIEW, {1: [get(P), put(FN)], 2: [get(P), put(ARGS)], 3: [get(P), c(2), ("i32.add",), put(HOME)],
                         8: [get(P), put(CONSENTS)], 5: [get(P), put(STATE)]}),
        # STATE holds the view's position for now.
        get(STATE), put(VIEW), c(0), put(STATE),
        c(SPLIT_OUT), put(OUT),
        *on("i", issue),
        get(VIEW), ("i32.eqz",), ("if", None), ("unreachable",), ("end",),
        *walk_map(VIEW, {3: [get(P), put(STATE)], 5: [get(P), c(10), ("i32.add",), put(HOLDER)]}),
        get(HOLDER), ("i32.eqz",), ("if", None), ("unreachable",), ("end",),
        *on("s", split),
        *on("t", transfer),
        ("unreachable",),
    ]}
    return w.assemble([arg_function(), head_length_function(), skip_function(), u64, put_fn, head, eq32,
                       consented, entry], imports=IMPORTS, memory=(4, 4), data=[(0, data)])


def split_output(function: str, arguments, state=None, holder=None, home=None, consents=()) -> tuple:
    """What the splitting contract does, computed independently: (outcome,
    output or reason)."""
    def ledger(v):
        return isinstance(v, bytes) and len(v) == 32

    if function == "issue":
        if not (isinstance(arguments, list) and len(arguments) == 2 and ledger(arguments[0])
                and isinstance(arguments[1], int) and arguments[1] >= 0):
            return "aborted", b"bad arguments"
        if arguments[1] == 0:
            return "aborted", b"the amount must be positive"
        return "ok", cbor2.dumps([1, {1: [arguments[1], 1], 2: "active", 3: {"holder": arguments[0]}}],
                                 canonical=True)
    needs = holder != home and holder not in consents
    if function == "split":
        if not isinstance(arguments, list):
            return "aborted", b"bad arguments"
        amount, tier = state
        total = 0
        for part in arguments:
            if not (isinstance(part, list) and len(part) == 2 and ledger(part[0]) and isinstance(part[1], int)
                    and part[1] >= 0):
                return "aborted", b"bad arguments"
            if part[1] == 0 or part[1] > amount - total:
                return "aborted", b"a part must be positive and within the amount"
            total += part[1]
        if total != amount:
            return "aborted", b"the parts do not add up to the amount"
        if needs:
            return "ok", cbor2.dumps([2, [holder]], canonical=True)
        children = [{1: [a, tier + 1], 2: "active", 3: {"holder": h}} for h, a in arguments]
        return "ok", cbor2.dumps([1, {1: state, 2: "split", 5: True, 6: children}], canonical=True)
    assert function == "transfer"
    if not ledger(arguments):
        return "aborted", b"bad arguments"
    if needs:
        return "ok", cbor2.dumps([2, [holder]], canonical=True)
    return "ok", cbor2.dumps([1, {1: state, 3: {"holder": arguments}}], canonical=True)


def check_split(code: bytes) -> int:
    """Runs the splitting contract on inputs shaped like a home's, against
    split_output; returns how many runs agreed."""
    module = w.load(code)
    home, contract, instance = bytes(32 * [1]), bytes(32 * [2]), bytes(32 * [3])
    ledgers = [bytes([0x40 + i]) * 32 for i in range(20)]
    holder = ledgers[0]

    def run(function, arguments, state=None, consents=(), status="active", parent=None, of=holder):
        value = {1: function, 2: arguments, 3: home, 4: contract, 6: [ledgers[19], {1: 3}], 7: 1_791_244_800_000}
        if function != "issue":
            view = {1: instance, 2: 41, 3: state, 4: status, 5: {"holder": of}}
            if parent is not None:
                view[6] = parent
            value[5] = view
        if consents:
            value[8] = [[c, {1: 0}] for c in consents]
        outcome, output, _, reason = w.run(module, cbor2.dumps(value, canonical=True))
        expected = split_output(function, arguments, state, of, home, consents)
        got = (outcome, output if outcome == "ok" else reason)
        assert got == expected, (function, arguments, state, got, expected)

    cases = 0
    for amount in (1, 23, 24, 255, 256, 65_535, 65_536, 2**32 - 1, 2**32, 2**63, 2**64 - 1):
        run("issue", [holder, amount])
        cases += 1
    for bad in ([holder, 0], [holder], [b"short", 5], [holder, -5], "x", [holder, "5"]):
        run("issue", bad)
        cases += 1
    for tier in (1, 22, 23, 255, 2**40):
        for parts in ([[ledgers[1], 600], [ledgers[2], 400]], [[ledgers[i + 1], 1] for i in range(16)][:16]):
            amount = sum(a for _, a in parts)
            run("split", parts, [amount, tier], consents=[holder])
            run("split", parts, [amount, tier])
            run("split", parts, [amount, tier], consents=[ledgers[5], ledgers[6]])
            run("split", parts, [amount, tier], of=home)
            run("split", parts, [amount, tier], consents=[holder], parent=[bytes(32 * [9]), 3])
            cases += 5
    big = 2**64 - 1
    for parts, amount in (([[ledgers[1], big - 1], [ledgers[2], 1]], big), ([[ledgers[1], big]], big),
                          ([[ledgers[1], 2**32], [ledgers[2], 2**32]], 2**33),
                          ([[ledgers[i + 1], 1] for i in range(17)], 17), ([], 5),
                          ([[ledgers[1], 3], [ledgers[2], 3]], 5), ([[ledgers[1], 0], [ledgers[2], 5]], 5),
                          ([[ledgers[1], 6]], 5), ([[ledgers[1], 4]], 5), ([[b"short", 5]], 5),
                          ([[ledgers[1], -1]], 5), ([ledgers[1]], 5), ({"a": 1}, 5),
                          ([[ledgers[1], big], [ledgers[2], big]], big)):
        run("split", parts, [amount, 7], consents=[holder])
        cases += 1
    for new, consents in ((ledgers[3], [holder]), (ledgers[3], []), (ledgers[3], [ledgers[4]]),
                          (b"short", [holder]), (5, [holder])):
        run("transfer", new, [700, 3], consents=consents)
        run("transfer", new, [700, 3], consents=consents, of=home)
        cases += 2
    many = sorted(ledgers[1:17])
    run("transfer", ledgers[3], [700, 3], consents=many)
    run("transfer", ledgers[3], [700, 3], consents=many[:15] + [holder])
    return cases + 2


# ---------------------------------------------------------------------------
# The requesting contract (spec section 15, "Requests and answers", v0.8)
# ---------------------------------------------------------------------------

REQUEST_FUNCTIONS = {"ask": 2, "open": 1, "result": 2, "when.due": 2}
REQUEST_IN, REQUEST_OUT = 262_144, 1024
STATUS_NAMES = {1: "done", 2: "failed", 3: "expired"}
# Constant pieces of its outputs, and its reason, at the start of memory.
REQUEST_CONSTANTS = [
    ("events", b"\x04\x81\x82"),  # 4: [[
    ("done", b"\x64done"),
    ("failed", b"\x66failed"),
    ("expired", b"\x67expired"),
    ("reply", b"\x04\x66result"),  # 4: "result"
    ("bad_request", b"bad request"),
]


def request_contract() -> bytes:
    """A contract that makes requests and reacts to answers, with the
    interface REQUEST_FUNCTIONS. Every function behaves alike; its arguments
    decide:
      - a byte string: the output is its content (any output, as the v0.6
        oracle contract writes, so vectors reach every rule);
      - a text string: it aborts, with the text as the reason;
      - an array of specs [kind, params, after] (kind a text string, after an
        unsigned integer): it accepts, making one request per spec, in order,
        {1: kind, 2: params, 3: time + after (mod 2^64), 4: "result"}, time
        being the call's registration time (input key 7). Any other spec
        aborts with "bad request". It checks no kind, size, or count: the
        ledger's limits apply;
      - anything else: it accepts, making no request.
    When it accepts, the state is [status, request id] for an answer (input
    key 9), with the event [name, kind], name being done, failed, or expired;
    for any other call, the instance's state as it was, or null for a
    creation. Imports: input_size 0, input_read 1, output_write 2, abort 3."""
    where, data = {}, b""
    for name, raw in REQUEST_CONSTANTS:
        where[name] = (len(data), len(raw))
        data += raw
    get, put, c = _get, _set, _c
    # Function 10, the entry. Locals: 0 position, 1 entries left, 2 key,
    # 3 arguments, 4 instance view, 5 request view, 6 output end, 7 specs,
    # 8 specs left, 9 spec, 10 item, 11 item end, 12 request id, 13 kind,
    # 14 status, 15 state; 16 time (i64).
    P, N, KEY, ARGS, VIEW, REQ, OUT, K, I, S, Q, E, RID, RKIND, RSTATUS, STATE = range(16)
    TIME = 16

    def const(name):
        return [c(where[name][0]), c(where[name][1])]

    def put_const(name):
        return [get(OUT), *const(name), ("call", PUT), put(OUT)]

    def put_byte(value):
        return [get(OUT), c(value), ("i32.store8", 0), get(OUT), c(1), ("i32.add",), put(OUT)]

    def put_local_byte(local):
        return [get(OUT), get(local), ("i32.store8", 0), get(OUT), c(1), ("i32.add",), put(OUT)]

    def put_item(at):
        """Copies the item at local `at` to the output; E is where it ends."""
        return [get(at), ("call", SKIP), put(E),
                get(OUT), get(at), get(E), get(at), ("i32.sub",), ("call", PUT), put(OUT)]

    def walk_map(at, keys):
        """Walks the map at local `at`, running keys[k] at each key k (one
        byte) with P at its value."""
        out = [get(at), ("call", ARG), put(N), get(at), get(at), ("call", HEAD_LENGTH), ("i32.add",), put(P),
               ("block", None), ("loop", None),
               get(N), ("i32.eqz",), ("br_if", 1),
               get(P), ("i32.load8_u", 0), put(KEY),
               get(P), c(1), ("i32.add",), put(P)]
        for k, then in keys.items():
            out += [get(KEY), c(k), ("i32.eq",), ("if", None), *then, ("end",)]
        return out + [get(P), ("call", SKIP), put(P),
                      get(N), c(1), ("i32.sub",), put(N),
                      ("br", 0), ("end",), ("end",)]

    def each_spec(body):
        return [get(ARGS), get(ARGS), ("call", HEAD_LENGTH), ("i32.add",), put(S), get(K), put(I),
                ("block", None), ("loop", None),
                get(I), ("i32.eqz",), ("br_if", 1),
                *body,
                get(S), ("call", SKIP), put(S),
                get(I), c(1), ("i32.sub",), put(I),
                ("br", 0), ("end",), ("end",)]

    def major(at):
        return [get(at), ("i32.load8_u", 0), c(5), ("i32.shr_u",)]

    def content(at):
        """The content of the string at local `at`: (start, length)."""
        return [get(at), get(at), ("call", HEAD_LENGTH), ("i32.add",), get(at), ("call", ARG)]

    bad = [*const("bad_request"), ("call", 3), ("return",)]
    check_specs = each_spec([
        get(S), ("i32.load8_u", 0), c(0x83), ("i32.ne",),
        ("if", None), *bad, ("end",),
        get(S), c(1), ("i32.add",), put(Q),
        *major(Q), c(3), ("i32.ne",),
        ("if", None), *bad, ("end",),
        get(Q), ("call", SKIP), ("call", SKIP), put(Q),
        *major(Q), ("if", None), *bad, ("end",),
    ])
    write_specs = each_spec([
        *put_byte(0xA4), *put_byte(0x01),
        get(S), c(1), ("i32.add",), put(Q), *put_item(Q),
        *put_byte(0x02), get(E), put(Q), *put_item(Q),
        *put_byte(0x03),
        get(OUT), c(0), get(TIME), get(E), ("call", U64), ("i64.add",), ("call", HEAD), put(OUT),
        *put_const("reply"),
    ])
    answered = [
        *walk_map(REQ, {1: [get(P), put(RID)], 2: [get(P), put(RKIND)], 6: [get(P), ("i32.load8_u", 0), put(RSTATUS)]}),
        get(RSTATUS), c(1), ("i32.lt_u",), get(RSTATUS), c(3), ("i32.gt_u",), ("i32.or",),
        ("if", None), ("unreachable",), ("end",),
        *put_byte(0x82), *put_local_byte(RSTATUS), *put_byte(0x58), *put_byte(0x20),
        get(OUT), get(RID), c(2), ("i32.add",), c(32), ("call", PUT), put(OUT),
    ]
    events = [
        *put_const("events"),
        *[x for status, name in STATUS_NAMES.items()
          for x in (get(RSTATUS), c(status), ("i32.eq",), ("if", None), *put_const(name), ("end",))],
        *put_item(RKIND),
    ]
    entry = {"locals": ["i32"] * 16 + ["i64"], "body": [
        c(REQUEST_IN), ("call", 1),
        c(REQUEST_IN), put(Q),
        *walk_map(Q, {2: [get(P), put(ARGS)], 5: [get(P), put(VIEW)], 7: [get(P), ("call", U64), put(TIME)],
                      9: [get(P), put(REQ)]}),
        *major(ARGS), c(2), ("i32.eq",),
        ("if", None), *content(ARGS), ("call", 2), ("return",), ("end",),
        *major(ARGS), c(3), ("i32.eq",),
        ("if", None), *content(ARGS), ("call", 3), ("return",), ("end",),
        *major(ARGS), c(4), ("i32.eq",),
        ("if", None), get(ARGS), ("call", ARG), put(K), ("end",),
        *check_specs,
        c(REQUEST_OUT), put(OUT),
        *put_byte(0x82), *put_byte(0x01),
        # The accept's map: the state, then events for an answer, then requests.
        get(OUT), c(0xA1), get(REQ), c(0), ("i32.ne",), ("i32.add",), get(K), c(0), ("i32.ne",), ("i32.add",),
        ("i32.store8", 0), get(OUT), c(1), ("i32.add",), put(OUT),
        *put_byte(0x01),
        get(REQ),
        ("if", None),
        *answered,
        ("else",),
        get(VIEW),
        ("if", None),
        *walk_map(VIEW, {3: [get(P), put(STATE)]}),
        *put_item(STATE),
        ("else",),
        *put_byte(0xF6),
        ("end",),
        ("end",),
        get(REQ), ("if", None), *events, ("end",),
        get(K),
        ("if", None),
        *put_byte(0x07),
        get(OUT), c(0x80), get(K), ("i64.extend_i32_u",), ("call", HEAD), put(OUT),
        *write_specs,
        ("end",),
        c(REQUEST_OUT), get(OUT), c(REQUEST_OUT), ("i32.sub",), ("call", 2),
    ]}
    return w.assemble([arg_function(), head_length_function(), skip_function(), u64_function(), put_function(),
                       head_function(), entry], imports=IMPORTS, memory=(8, 8), data=[(0, data)])


def request_output(value: dict) -> tuple[str, bytes]:
    """What the requesting contract does with the input `value` (a decoded
    contract-input), computed independently: (outcome, output or reason)."""
    arguments = value[2]
    if isinstance(arguments, bytes):
        return "ok", arguments
    if isinstance(arguments, str):
        return "aborted", arguments.encode()
    specs = arguments if isinstance(arguments, list) else []
    for spec in specs:
        if not (isinstance(spec, list) and len(spec) == 3 and isinstance(spec[0], str)
                and isinstance(spec[2], int) and not isinstance(spec[2], bool) and 0 <= spec[2] < 2**64):
            return "aborted", b"bad request"
    request = value.get(9)
    if request is not None:
        if request[6] not in STATUS_NAMES:
            return "unreachable", b""
        accept = {1: [request[6], request[1]], 4: [[STATUS_NAMES[request[6]], request[2]]]}
    elif 5 in value:
        accept = {1: value[5][3]}
    else:
        accept = {1: None}
    if specs:
        accept[7] = [{1: kind, 2: params, 3: (value[7] + after) % 2**64, 4: "result"} for kind, params, after in specs]
    return "ok", cbor2.dumps([1, accept], canonical=True)


def check_requests(code: bytes) -> int:
    """Runs the requesting contract on inputs shaped like a home's, against
    request_output; returns how many runs agreed."""
    module = w.load(code)
    home, contract, instance = bytes(32 * [1]), bytes(32 * [2]), bytes(32 * [3])
    request_id, caller = bytes(32 * [4]), bytes(32 * [5])
    now = 1_792_022_400_000
    cases = [0]

    def run(function, arguments, state=..., request=None, time=now, consents=0):
        value = {1: function, 2: arguments, 3: home, 4: contract, 6: [caller, {1: 3}], 7: time}
        if state is not ...:
            value[5] = {1: instance, 2: 17, 3: state, 4: "active"}
        if consents:
            value[8] = [[bytes([0x40 + i]) * 32, {1: 0}] for i in range(consents)]
        if request is not None:
            value[9] = request
        outcome, output, _, reason = w.run(module, cbor2.dumps(value, canonical=True))
        expected = request_output(value)
        got = (outcome, output if outcome == "ok" else reason)
        assert got == expected, (function, arguments, state, request, got, expected)
        cases[0] += 1

    def view(status, kind="invoice", params=None, deadline=now + 86_400_000):
        return {1: request_id, 2: kind, 3: params, 4: deadline, 5: now - 60_000, 6: status}

    states = [..., None, 0, "x", {"k": [1, 2, {3: -4}]}, bytes(23), bytes(24), bytes(300), bytes(70_000),
              [[1, 2], "three"], 2**64 - 1, -2**64]
    afters = [0, 1, 23, 24, 255, 256, 65_535, 65_536, 2**32 - 1, 2**32, 31_622_400_000, 2**63, 2**64 - 1]
    params = [None, 0, -5, "p", b"", bytes(23), bytes(24), bytes(256), bytes(4093), bytes(65_000),
              {"bill": 1, "total": 12_500}, [1, [2, [3]]]]
    kinds = ["a", "x" * 23, "x" * 24, "panel.suspend", "k" * 64, "k" * 300, "Invoice", ""]
    for state in states:
        for arguments in ([], None, 7, {"a": 1}, True, [["notify", None, 0]], b"", b"\x82\x01\xa1\x01\x00",
                          "no such thing", ""):
            run("ask", arguments, state)
    for after in afters:
        run("ask", [["invoice", {"bill": 1}, after]], 0)
        run("open", [["invoice", None, after]], time=2**64 - 2)
    for p in params:
        run("ask", [["notify", p, 86_400_000], ["collect", p, 2]], "s")
    for kind in kinds:
        run("open", [[kind, kind, 5]])
    for n in (1, 2, 15, 16, 17, 23, 24, 64, 65):
        run("ask", [[f"k{i}", i, i] for i in range(n)], [n])
    for spec in (5, "spec", [1, None, 0], ["k", None], ["k", None, 0, 0], ["k", None, -1], ["k", None, "x"],
                 ["k", None, 2**64], ["k", None, True], [b"k", None, 0], {"k": 1}, ["k", None, None]):
        run("ask", [spec], 0)
        run("ask", [["first", None, 1], spec], 0)
    for status in (1, 2, 3):
        for kind, p in (("invoice", None), ("k" * 64, bytes(4093)), ("notify", {"about": "welcome"})):
            for arguments in (None, {"digest": bytes(32), "ref": "INV-1"}, [["retry", p, 60_000]], b"\x82\x01\xa1\x01\x00",
                              "not yet", [5]):
                run("result", arguments, [2, bytes(32)], view(status, kind, p))
        run("result", None, ..., view(status), consents=3)
        run("open", [["a", 1, 1]], request=view(status))
    for status in (0, 4, 23):
        run("result", None, 0, view(status))
    return cases[0]


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
    split = split_contract()
    split_runs = check_split(split)
    request = request_contract()
    request_runs = check_requests(request)
    document = {
        "description": "Contracts for tests of the node, assembled by tools/testvectors/test_contracts.py "
                       "and checked with its reference interpreter. counting: arguments [out_0, ..., out_k] "
                       "(byte strings) make it write out_min(n, k), n being the number of consents the call "
                       "cites; a text string makes it abort with that reason; anything else traps. split: a "
                       "receivable whose parts are child instances (spec section 15, v0.7), with the "
                       "interface in split_interface: issue [holder, amount] (state [amount, 1], status "
                       "active, parties {holder}); split [[ledger, amount], ...] (the parts add up to the "
                       "amount; the instance ends with status split, and each part becomes a child [amount, "
                       "tier + 1], active, held by its ledger); transfer ledger (the new holder). Split and "
                       "transfer need the holder's consent unless the holder is the home. request: the "
                       "requesting contract of protocol-v0.8.json (spec section 15, v0.8), with the interface "
                       "in request_interface: arguments that are a byte string are its output; a text string "
                       "makes it abort with that reason; [[kind, params, after], ...] accepts and makes one "
                       "request per item, due `after` ms after the call, replying to result; an answer sets "
                       "the state to [status, request] with the event [done|failed|expired, kind]; "
                       "request_checks counts the runs that agreed with an independent model.",
        "counting": code.hex(),
        "counting_runs": runs,
        "split": split.hex(),
        "split_interface": SPLIT_FUNCTIONS,
        "split_checks": split_runs,
        "request": request.hex(),
        "request_interface": REQUEST_FUNCTIONS,
        "request_checks": request_runs,
    }
    (OUT / "test-contracts.json").write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    main()
