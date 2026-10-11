# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""A reference interpreter for CexChain's deterministic WebAssembly profile
(spec/README.md, section 14), written independently of the C++ implementation
to produce test vectors. It favours clarity over speed.

    load(wasm_bytes) -> Module        raises Refused for a module outside the profile
    run(module, input, hash_name) -> (outcome, output, fuel)
        outcome is "ok" or the name of a trap

Also an assembler for building test modules (see `assemble`).
"""

from __future__ import annotations

import hashlib

# Limits (spec section 14.1 and 14.3).
MAX_MODULE = 524_288
MAX_TYPES = 1024
MAX_PARAMS = 32
MAX_RESULTS = 16
MAX_FUNCS = 10_000
MAX_LOCALS = 4096
MAX_BODY = 131_072
MAX_GLOBALS = 1024
MAX_TABLE = 1024
MAX_PAGES = 16
MAX_DATA = 1 << 20
MAX_HEIGHT = 65_535
MAX_NESTING = 1024
FUEL = 10_000_000
MAX_DEPTH = 256
STACK_BUDGET = 131_072
MAX_OUTPUT = 1 << 20
MAX_ABORT = 1024
PAGE = 65_536

I32, I64 = 0x7F, 0x7E
VALTYPES = (I32, I64)
MASK32, MASK64 = (1 << 32) - 1, (1 << 64) - 1

HOST = {
    "input_size": ((), (I32,)),
    "input_read": ((I32,), ()),
    "output_write": ((I32, I32), ()),
    "hash": ((I32, I32, I32), ()),
    "abort": ((I32, I32), ()),
}


class Refused(Exception):
    """The module is not in the profile."""


class Trap(Exception):
    def __init__(self, kind: str, reason: bytes = b""):
        super().__init__(kind)
        self.kind = kind
        self.reason = reason


# ---------------------------------------------------------------------------
# Opcodes in the profile: name -> (opcode, immediate kind, [pops], [pushes])
# Immediate kinds: none, block, idx (u32), brtable, memarg, i32, i64, zero
# (a single 0x00 byte), callind (typeidx, tableidx 0), selectt.
# ---------------------------------------------------------------------------

def _num(op, pops, pushes):
    return (op, "none", pops, pushes)


OPS = {
    "unreachable": (0x00, "none", None, None),
    "nop": (0x01, "none", [], []),
    "block": (0x02, "block", None, None),
    "loop": (0x03, "block", None, None),
    "if": (0x04, "block", None, None),
    "else": (0x05, "none", None, None),
    "end": (0x0B, "none", None, None),
    "br": (0x0C, "idx", None, None),
    "br_if": (0x0D, "idx", None, None),
    "br_table": (0x0E, "brtable", None, None),
    "return": (0x0F, "none", None, None),
    "call": (0x10, "idx", None, None),
    "call_indirect": (0x11, "callind", None, None),
    "drop": (0x1A, "none", None, None),
    "select": (0x1B, "none", None, None),
    "select_t": (0x1C, "selectt", None, None),
    "local.get": (0x20, "idx", None, None),
    "local.set": (0x21, "idx", None, None),
    "local.tee": (0x22, "idx", None, None),
    "global.get": (0x23, "idx", None, None),
    "global.set": (0x24, "idx", None, None),
    "i32.load": (0x28, "memarg", [I32], [I32]),
    "i64.load": (0x29, "memarg", [I32], [I64]),
    "i32.load8_s": (0x2C, "memarg", [I32], [I32]),
    "i32.load8_u": (0x2D, "memarg", [I32], [I32]),
    "i32.load16_s": (0x2E, "memarg", [I32], [I32]),
    "i32.load16_u": (0x2F, "memarg", [I32], [I32]),
    "i64.load8_s": (0x30, "memarg", [I32], [I64]),
    "i64.load8_u": (0x31, "memarg", [I32], [I64]),
    "i64.load16_s": (0x32, "memarg", [I32], [I64]),
    "i64.load16_u": (0x33, "memarg", [I32], [I64]),
    "i64.load32_s": (0x34, "memarg", [I32], [I64]),
    "i64.load32_u": (0x35, "memarg", [I32], [I64]),
    "i32.store": (0x36, "memarg", [I32, I32], []),
    "i64.store": (0x37, "memarg", [I32, I64], []),
    "i32.store8": (0x3A, "memarg", [I32, I32], []),
    "i32.store16": (0x3B, "memarg", [I32, I32], []),
    "i64.store8": (0x3C, "memarg", [I32, I64], []),
    "i64.store16": (0x3D, "memarg", [I32, I64], []),
    "i64.store32": (0x3E, "memarg", [I32, I64], []),
    "memory.size": (0x3F, "zero", [], [I32]),
    "memory.grow": (0x40, "zero", [I32], [I32]),
    "i32.const": (0x41, "i32", [], [I32]),
    "i64.const": (0x42, "i64", [], [I64]),
}
_I32_CMP = ["eqz", "eq", "ne", "lt_s", "lt_u", "gt_s", "gt_u", "le_s", "le_u", "ge_s", "ge_u"]
for i, n in enumerate(_I32_CMP):
    OPS["i32." + n] = _num(0x45 + i, [I32] if n == "eqz" else [I32, I32], [I32])
for i, n in enumerate(_I32_CMP):
    OPS["i64." + n] = _num(0x50 + i, [I64] if n == "eqz" else [I64, I64], [I32])
_UN = ["clz", "ctz", "popcnt"]
_BIN = ["add", "sub", "mul", "div_s", "div_u", "rem_s", "rem_u", "and", "or", "xor", "shl", "shr_s",
        "shr_u", "rotl", "rotr"]
for i, n in enumerate(_UN + _BIN):
    OPS["i32." + n] = _num(0x67 + i, [I32] if n in _UN else [I32, I32], [I32])
    OPS["i64." + n] = _num(0x79 + i, [I64] if n in _UN else [I64, I64], [I64])
OPS["i32.wrap_i64"] = _num(0xA7, [I64], [I32])
OPS["i64.extend_i32_s"] = _num(0xAC, [I32], [I64])
OPS["i64.extend_i32_u"] = _num(0xAD, [I32], [I64])
OPS["i32.extend8_s"] = _num(0xC0, [I32], [I32])
OPS["i32.extend16_s"] = _num(0xC1, [I32], [I32])
OPS["i64.extend8_s"] = _num(0xC2, [I64], [I64])
OPS["i64.extend16_s"] = _num(0xC3, [I64], [I64])
OPS["i64.extend32_s"] = _num(0xC4, [I64], [I64])
# 0xFC prefix: (sub-opcode, immediates)
FC = {
    "memory.init": (8, "data_zero"),
    "data.drop": (9, "idx"),
    "memory.copy": (10, "zero_zero"),
    "memory.fill": (11, "zero"),
}

BY_OPCODE = {v[0]: k for k, v in OPS.items()}
# Bytes accessed by each load and store (its natural alignment is log2 of it).
WIDTH = {"i32.load": 4, "i64.load": 8, "i32.load8_s": 1, "i32.load8_u": 1, "i32.load16_s": 2,
         "i32.load16_u": 2, "i64.load8_s": 1, "i64.load8_u": 1, "i64.load16_s": 2, "i64.load16_u": 2,
         "i64.load32_s": 4, "i64.load32_u": 4, "i32.store": 4, "i64.store": 8, "i32.store8": 1,
         "i32.store16": 2, "i64.store8": 1, "i64.store16": 2, "i64.store32": 4}
LOG2 = {1: 0, 2: 1, 4: 2, 8: 3}
FC_BY_SUB = {v[0]: k for k, v in FC.items()}


# ---------------------------------------------------------------------------
# Binary reading
# ---------------------------------------------------------------------------

class Reader:
    def __init__(self, data: bytes, pos: int = 0, end: int | None = None):
        self.data, self.pos = data, pos
        self.end = len(data) if end is None else end

    def u8(self) -> int:
        if self.pos >= self.end:
            raise Refused("unexpected end")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def uleb(self, bits: int) -> int:
        result, shift = 0, 0
        for i in range((bits + 6) // 7):
            b = self.u8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                if i == (bits + 6) // 7 - 1 and (b >> (bits - 7 * i)) != 0:
                    raise Refused("integer too large")
                return result
        raise Refused("integer representation too long")

    def sleb(self, bits: int) -> int:
        result, shift = 0, 0
        n = (bits + 6) // 7
        for i in range(n):
            b = self.u8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                if i == n - 1:
                    # The sign bit and the unused bits of the last byte agree.
                    used = bits - 7 * i
                    upper = (b & 0x7F) >> (used - 1)
                    if upper not in (0, (1 << (8 - used)) - 1):
                        raise Refused("integer too large")
                if b & 0x40:
                    result -= 1 << shift
                return result
        raise Refused("integer representation too long")

    def u32(self) -> int:
        return self.uleb(32)

    def bytes_(self, n: int) -> bytes:
        if self.pos + n > self.end:
            raise Refused("unexpected end")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def name(self) -> str:
        raw = self.bytes_(self.u32())
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Refused("malformed UTF-8")

    def done(self) -> bool:
        return self.pos >= self.end


def _valtype(r: Reader) -> int:
    t = r.u8()
    if t not in VALTYPES:
        raise Refused("value type outside the profile")
    return t


def _limits(r: Reader, cap: int) -> tuple[int, int]:
    flag = r.u8()
    if flag not in (0, 1):
        raise Refused("limits outside the profile")
    lo = r.u32()
    hi = r.u32() if flag == 1 else cap
    if lo > cap or hi > cap or lo > hi:
        raise Refused("limits too large")
    return lo, hi


def _const_expr(r: Reader, t: int) -> int:
    op = r.u8()
    if t == I32 and op == 0x41:
        v = r.sleb(32) & MASK32
    elif t == I64 and op == 0x42:
        v = r.sleb(64) & MASK64
    else:
        raise Refused("constant expression outside the profile")
    if r.u8() != 0x0B:
        raise Refused("constant expression outside the profile")
    return v


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class Func:
    def __init__(self, type_idx: int, host: str | None = None):
        self.type_idx, self.host = type_idx, host
        self.locals: list[int] = []
        self.code = b""
        self.max_height = 0
        self.targets: dict[int, int] = {}  # block, if, or loop start -> its end
        self.elses: dict[int, int] = {}  # if start -> its else
        self.else_ends: dict[int, int] = {}  # else -> where its then-branch continues


class Module:
    def __init__(self):
        self.types: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
        self.funcs: list[Func] = []
        self.imports = 0
        self.table: tuple[int, int] | None = None
        self.memory: tuple[int, int] | None = None
        self.globals: list[tuple[int, bool, int]] = []
        self.exports: dict[str, tuple[int, int]] = {}
        self.elems: list[tuple[int, list[int]]] = []
        self.data: list[tuple[int | None, bytes]] = []  # (offset or None for passive, bytes)
        self.data_count: int | None = None
        self.entry = -1


def load(wasm: bytes) -> Module:
    if len(wasm) > MAX_MODULE:
        raise Refused("module too large")
    r = Reader(wasm)
    if r.bytes_(4) != b"\0asm" or r.bytes_(4) != b"\1\0\0\0":
        raise Refused("not a WebAssembly 1 module")
    m = Module()
    order = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 10, 11]
    last = -1
    func_types: list[int] = []
    codes: list[tuple[list[int], int, int]] = []
    while not r.done():
        sid = r.u8()
        size = r.u32()
        start = r.pos
        if start + size > r.end:
            raise Refused("section size")
        s = Reader(wasm, start, start + size)
        if sid == 0:
            s.name()
            r.pos = start + size
            continue
        if sid not in order:
            raise Refused("unknown section")
        if order.index(sid) <= last:
            raise Refused("section out of order or repeated")
        last = order.index(sid)
        if sid == 1:
            n = s.u32()
            if n > MAX_TYPES:
                raise Refused("too many types")
            for _ in range(n):
                if s.u8() != 0x60:
                    raise Refused("type outside the profile")
                params = tuple(_valtype(s) for _ in range(s.u32()))
                results = tuple(_valtype(s) for _ in range(s.u32()))
                if len(params) > MAX_PARAMS or len(results) > MAX_RESULTS:
                    raise Refused("type too large")
                m.types.append((params, results))
        elif sid == 2:
            for _ in range(s.u32()):
                module, field = s.name(), s.name()
                if s.u8() != 0x00:
                    raise Refused("only function imports")
                t = s.u32()
                if module != "cexchain" or field not in HOST:
                    raise Refused("unknown import")
                if t >= len(m.types) or m.types[t] != HOST[field]:
                    raise Refused("import type mismatch")
                if any(f.host == field for f in m.funcs):
                    raise Refused("repeated import")
                m.funcs.append(Func(t, field))
            m.imports = len(m.funcs)
        elif sid == 3:
            for _ in range(s.u32()):
                t = s.u32()
                if t >= len(m.types):
                    raise Refused("unknown type")
                func_types.append(t)
            if m.imports + len(func_types) > MAX_FUNCS:
                raise Refused("too many functions")
        elif sid == 4:
            n = s.u32()
            if n > 1:
                raise Refused("at most one table")
            if n == 1:
                if s.u8() != 0x70:
                    raise Refused("table type outside the profile")
                m.table = _limits(s, MAX_TABLE)
        elif sid == 5:
            n = s.u32()
            if n > 1:
                raise Refused("at most one memory")
            if n == 1:
                m.memory = _limits(s, MAX_PAGES)
        elif sid == 6:
            n = s.u32()
            if n > MAX_GLOBALS:
                raise Refused("too many globals")
            for _ in range(n):
                t = _valtype(s)
                mut = s.u8()
                if mut not in (0, 1):
                    raise Refused("malformed mutability")
                m.globals.append((t, mut == 1, _const_expr(s, t)))
        elif sid == 7:
            for _ in range(s.u32()):
                name = s.name()
                kind = s.u8()
                idx = s.u32()
                if name in m.exports:
                    raise Refused("duplicate export")
                if kind > 3:
                    raise Refused("unknown export kind")
                m.exports[name] = (kind, idx)
        elif sid == 8:
            raise Refused("start function")
        elif sid == 9:
            for _ in range(s.u32()):
                if s.u32() != 0:
                    raise Refused("element segment outside the profile")
                offset = _const_expr(s, I32)
                idxs = [s.u32() for _ in range(s.u32())]
                m.elems.append((offset, idxs))
        elif sid == 12:
            m.data_count = s.u32()
        elif sid == 10:
            n = s.u32()
            if n != len(func_types):
                raise Refused("function and code counts differ")
            for _ in range(n):
                size_ = s.u32()
                if size_ > MAX_BODY:
                    raise Refused("function body too large")
                b = Reader(wasm, s.pos, s.pos + size_)
                if b.end > s.end:
                    raise Refused("unexpected end")
                locals_: list[int] = []
                for _ in range(b.u32()):
                    count = b.u32()
                    t = _valtype(b)
                    if len(locals_) + count > MAX_LOCALS:
                        raise Refused("too many locals")
                    locals_ += [t] * count
                codes.append((locals_, b.pos, b.end))
                s.pos = b.end
        elif sid == 11:
            n = s.u32()
            if m.data_count is not None and n != m.data_count:
                raise Refused("data count mismatch")
            total = 0
            for _ in range(n):
                flag = s.u32()
                if flag == 0:
                    offset = _const_expr(s, I32)
                elif flag == 1:
                    offset = None
                else:
                    raise Refused("data segment outside the profile")
                raw = s.bytes_(s.u32())
                total += len(raw)
                m.data.append((offset, raw))
            if total > MAX_DATA:
                raise Refused("too much data")
        if s.pos != s.end:
            raise Refused("section size")
        r.pos = start + size
    if len(codes) != len(func_types):
        raise Refused("function and code counts differ")
    if m.data_count is not None and m.data_count != len(m.data):
        raise Refused("data count mismatch")

    for t, (locals_, start, end) in zip(func_types, codes):
        f = Func(t)
        params = m.types[t][0]
        if len(params) + len(locals_) > MAX_LOCALS:
            raise Refused("too many locals")
        f.locals = list(params) + locals_
        f.code = wasm[start:end]
        m.funcs.append(f)

    # Exports, elements, data: in the profile and in bounds.
    if m.exports.get("memory", (None,))[0] != 2 or m.memory is None:
        raise Refused("must export its memory as \"memory\"")
    entry = m.exports.get("cexchain_call")
    if entry is None or entry[0] != 0 or entry[1] >= len(m.funcs) or entry[1] < m.imports:
        raise Refused("must export a function \"cexchain_call\"")
    if m.types[m.funcs[entry[1]].type_idx] != ((), ()):
        raise Refused("cexchain_call must take and return nothing")
    m.entry = entry[1]
    for name, (kind, idx) in m.exports.items():
        if (kind == 0 and idx >= len(m.funcs)) or (kind == 1 and (m.table is None or idx != 0)) \
                or (kind == 2 and idx != 0) or (kind == 3 and idx >= len(m.globals)):
            raise Refused("export of an unknown item")
    for offset, idxs in m.elems:
        if m.table is None or offset + len(idxs) > m.table[0]:
            raise Refused("element segment out of bounds")
        if any(i >= len(m.funcs) for i in idxs):
            raise Refused("unknown function")
    for offset, raw in m.data:
        if offset is not None and offset + len(raw) > m.memory[0] * PAGE:
            raise Refused("data segment out of bounds")

    for f in m.funcs[m.imports:]:
        _validate(m, f)
    return m


# ---------------------------------------------------------------------------
# Validation (the algorithm of the WebAssembly specification's appendix), also
# measuring each function's maximum operand stack height, and recording the
# structure the interpreter needs.
# ---------------------------------------------------------------------------

UNKNOWN = 0


def _block_type(m: Module, r: Reader) -> tuple[tuple[int, ...], tuple[int, ...]]:
    b = r.data[r.pos] if r.pos < r.end else None
    if b == 0x40:
        r.pos += 1
        return (), ()
    if b in VALTYPES:
        r.pos += 1
        return (), (b,)
    idx = r.sleb(33)
    if idx < 0 or idx >= len(m.types):
        raise Refused("block type outside the profile")
    return m.types[idx]


def _validate(m: Module, f: Func) -> None:
    params, results = m.types[f.type_idx]
    vals: list[int] = []
    ctrls: list[dict] = []
    max_h = 0

    def push(t):
        nonlocal max_h
        vals.append(t)
        max_h = max(max_h, len(vals))

    def pop(expect=None):
        c = ctrls[-1]
        if len(vals) == c["height"]:
            if c["unreachable"]:
                return UNKNOWN
            raise Refused("type mismatch")
        t = vals.pop()
        if expect is not None and t != UNKNOWN and t != expect:
            raise Refused("type mismatch")
        return t

    def pops(ts):
        for t in reversed(ts):
            pop(t)

    def pushes(ts):
        for t in ts:
            push(t)

    def push_ctrl(op, ins, outs, start):
        if len(ctrls) >= MAX_NESTING:
            raise Refused("nesting too deep")
        ctrls.append({"op": op, "ins": ins, "outs": outs, "height": len(vals), "unreachable": False,
                      "start": start})
        pushes(ins)

    def pop_ctrl():
        if not ctrls:
            raise Refused("unbalanced end")
        c = ctrls[-1]
        pops(c["outs"])
        if len(vals) != c["height"]:
            raise Refused("type mismatch")
        ctrls.pop()
        return c

    def label_types(c):
        return c["ins"] if c["op"] == "loop" else c["outs"]

    def unreachable():
        c = ctrls[-1]
        del vals[c["height"]:]
        c["unreachable"] = True

    def local(i):
        if i >= len(f.locals):
            raise Refused("unknown local")
        return f.locals[i]

    def need_memory():
        if m.memory is None:
            raise Refused("no memory")

    r = Reader(f.code)
    push_ctrl("func", (), results, -1)
    ctrls[0]["height"] = 0
    while True:
        if r.done():
            raise Refused("function body does not end")
        pos = r.pos
        op = r.u8()
        if op == 0xFC:
            sub = r.u32()
            name = FC_BY_SUB.get(sub)
            if name is None:
                raise Refused("instruction outside the profile")
            need_memory()
            if name == "memory.init":
                idx = r.u32()
                if r.u8() != 0:
                    raise Refused("memory index")
                if m.data_count is None or idx >= m.data_count:
                    raise Refused("unknown data segment")
                pops([I32, I32, I32])
            elif name == "data.drop":
                idx = r.u32()
                if m.data_count is None or idx >= m.data_count:
                    raise Refused("unknown data segment")
            elif name == "memory.copy":
                if r.u8() != 0 or r.u8() != 0:
                    raise Refused("memory index")
                pops([I32, I32, I32])
            elif name == "memory.fill":
                if r.u8() != 0:
                    raise Refused("memory index")
                pops([I32, I32, I32])
            continue
        name = BY_OPCODE.get(op)
        if name is None:
            raise Refused("instruction outside the profile")
        kind, ins, outs = OPS[name][1], OPS[name][2], OPS[name][3]
        if name == "unreachable":
            unreachable()
        elif name == "nop":
            pass
        elif name in ("block", "loop", "if"):
            bt = _block_type(m, r)
            if name == "if":
                pop(I32)
            pops(bt[0])
            push_ctrl(name, bt[0], bt[1], pos)
        elif name == "else":
            c = ctrls[-1]
            if c["op"] != "if":
                raise Refused("else without if")
            pop_ctrl()
            f.elses[c["start"]] = pos
            push_ctrl("else", c["ins"], c["outs"], c["start"])
        elif name == "end":
            c = pop_ctrl()
            if c["op"] == "if" and c["ins"] != c["outs"]:
                raise Refused("if without else must keep its type")
            if c["start"] >= 0:
                f.targets[c["start"]] = pos
            pushes(c["outs"])
            if not ctrls:
                if not r.done():
                    raise Refused("code after the function's end")
                break
        elif name == "br":
            n = r.u32()
            if n >= len(ctrls):
                raise Refused("unknown label")
            pops(label_types(ctrls[-1 - n]))
            unreachable()
        elif name == "br_if":
            n = r.u32()
            if n >= len(ctrls):
                raise Refused("unknown label")
            pop(I32)
            ts = label_types(ctrls[-1 - n])
            pops(ts)
            pushes(ts)
        elif name == "br_table":
            labels = [r.u32() for _ in range(r.u32())]
            default = r.u32()
            if default >= len(ctrls) or any(n >= len(ctrls) for n in labels):
                raise Refused("unknown label")
            pop(I32)
            arity = len(label_types(ctrls[-1 - default]))
            for n in labels:
                ts = label_types(ctrls[-1 - n])
                if len(ts) != arity:
                    raise Refused("type mismatch")
                popped = [pop(t) for t in reversed(ts)]
                for t in reversed(popped):
                    push(t)
            pops(label_types(ctrls[-1 - default]))
            unreachable()
        elif name == "return":
            pops(results)
            unreachable()
        elif name == "call":
            idx = r.u32()
            if idx >= len(m.funcs):
                raise Refused("unknown function")
            p, q = m.types[m.funcs[idx].type_idx]
            pops(p)
            pushes(q)
        elif name == "call_indirect":
            t = r.u32()
            if r.u32() != 0 or m.table is None:
                raise Refused("unknown table")
            if t >= len(m.types):
                raise Refused("unknown type")
            pop(I32)
            pops(m.types[t][0])
            pushes(m.types[t][1])
        elif name == "drop":
            pop()
        elif name == "select":
            pop(I32)
            t1 = pop()
            t2 = pop()
            if t1 != UNKNOWN and t2 != UNKNOWN and t1 != t2:
                raise Refused("type mismatch")
            push(t1 if t1 != UNKNOWN else t2)
        elif name == "select_t":
            n = r.u32()
            if n != 1:
                raise Refused("select arity")
            t = _valtype(r)
            pop(I32)
            pop(t)
            pop(t)
            push(t)
        elif name == "local.get":
            push(local(r.u32()))
        elif name == "local.set":
            pop(local(r.u32()))
        elif name == "local.tee":
            t = local(r.u32())
            pop(t)
            push(t)
        elif name == "global.get":
            i = r.u32()
            if i >= len(m.globals):
                raise Refused("unknown global")
            push(m.globals[i][0])
        elif name == "global.set":
            i = r.u32()
            if i >= len(m.globals):
                raise Refused("unknown global")
            if not m.globals[i][1]:
                raise Refused("global is immutable")
            pop(m.globals[i][0])
        else:
            if kind == "memarg":
                need_memory()
                align = r.u32()
                r.u32()  # offset
                if align > LOG2[WIDTH[name]]:
                    raise Refused("alignment too large")
            elif kind == "zero":
                need_memory()
                if r.u8() != 0:
                    raise Refused("memory index")
            elif kind == "i32":
                r.sleb(32)
            elif kind == "i64":
                r.sleb(64)
            pops(ins)
            pushes(outs)
    if max_h > MAX_HEIGHT:
        raise Refused("operand stack too high")
    f.max_height = max_h
    f.else_ends = {e: f.targets[start] + 1 for start, e in f.elses.items()}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _s32(v):
    v &= MASK32
    return v - (1 << 32) if v & 0x80000000 else v


def _s64(v):
    v &= MASK64
    return v - (1 << 64) if v & (1 << 63) else v


def _ceil64(n):
    return (n + 63) // 64


class Instance:
    def __init__(self, m: Module, input_: bytes, hash_name: str):
        self.m = m
        self.input = input_
        self.hash_name = hash_name
        self.memory = bytearray(m.memory[0] * PAGE)
        self.max_pages = m.memory[1]
        self.globals = [g[2] for g in m.globals]
        self.table: list[int | None] = [None] * (m.table[0] if m.table else 0)
        for offset, idxs in m.elems:
            for i, fi in enumerate(idxs):
                self.table[offset + i] = fi
        self.data: list[bytes | None] = []
        for offset, raw in m.data:
            if offset is not None:
                self.memory[offset:offset + len(raw)] = raw
                self.data.append(b"")  # active segments are dropped after use
            else:
                self.data.append(raw)
        self.fuel = FUEL
        self.depth = 0
        self.budget = 0
        self.output: bytes | None = None

    def charge(self, cost):
        if cost > self.fuel:
            self.fuel = 0
            raise Trap("out of fuel")
        self.fuel -= cost

    def mem(self, addr, n):
        if addr + n > len(self.memory):
            raise Trap("out of bounds")

    def call_host(self, name, args):
        if name == "input_size":
            self.charge(1)
            return [len(self.input)]
        if name == "input_read":
            ptr = args[0]
            self.charge(1 + _ceil64(len(self.input)))
            self.mem(ptr, len(self.input))
            self.memory[ptr:ptr + len(self.input)] = self.input
            return []
        if name == "output_write":
            ptr, n = args
            self.charge(1 + _ceil64(n))
            if self.output is not None:
                raise Trap("output written twice")
            if n > MAX_OUTPUT:
                raise Trap("output too large")
            self.mem(ptr, n)
            self.output = bytes(self.memory[ptr:ptr + n])
            return []
        if name == "hash":
            ptr, n, out = args
            self.charge(64 + _ceil64(n))
            self.mem(ptr, n)
            self.mem(out, 32)
            digest = hashlib.new(self.hash_name, bytes(self.memory[ptr:ptr + n])).digest()
            self.memory[out:out + 32] = digest
            return []
        if name == "abort":
            ptr, n = args
            self.charge(1)
            n = min(n, MAX_ABORT)
            self.mem(ptr, n)
            raise Trap("aborted", bytes(self.memory[ptr:ptr + n]))
        raise AssertionError(name)

    def invoke(self, fi: int, args: list[int]) -> list[int]:
        f = self.m.funcs[fi]
        if f.host is not None:
            return self.call_host(f.host, args)
        if self.depth + 1 > MAX_DEPTH:
            raise Trap("call depth exceeded")
        slots = len(f.locals) + f.max_height
        if self.budget + slots > STACK_BUDGET:
            raise Trap("stack budget exceeded")
        self.depth += 1
        self.budget += slots
        try:
            return self.execute(f, args)
        finally:
            self.depth -= 1
            self.budget -= slots

    def execute(self, f: Func, args: list[int]) -> list[int]:
        m = self.m
        locals_ = list(args) + [0] * (len(f.locals) - len(args))
        results = m.types[f.type_idx][1]
        stack: list[int] = []
        # labels: (arity on branch, continuation, stack height, is a loop)
        labels: list[tuple[int, int, int, bool]] = [(len(results), len(f.code), 0, False)]
        r = Reader(f.code)

        def branch(n):
            arity, cont, height, loop = labels[-1 - n]
            vals = stack[len(stack) - arity:] if arity else []
            del stack[height:]
            stack.extend(vals)
            # A loop's label stays: its body runs again.
            del labels[len(labels) - n if loop else len(labels) - 1 - n:]
            r.pos = cont

        while r.pos < len(f.code):
            pos = r.pos
            op = r.u8()
            if op == 0xFC:
                sub = r.u32()
                name = FC_BY_SUB[sub]
                if name == "memory.init":
                    seg = r.u32()
                    r.u8()
                    n = stack.pop()
                    s = stack.pop()
                    d = stack.pop()
                    self.charge(1 + _ceil64(n))
                    raw = self.data[seg]
                    if s + n > len(raw) or d + n > len(self.memory):
                        raise Trap("out of bounds")
                    self.memory[d:d + n] = raw[s:s + n]
                elif name == "data.drop":
                    seg = r.u32()
                    self.charge(1)
                    self.data[seg] = b""
                elif name == "memory.copy":
                    r.u8()
                    r.u8()
                    n = stack.pop()
                    s = stack.pop()
                    d = stack.pop()
                    self.charge(1 + _ceil64(n))
                    if s + n > len(self.memory) or d + n > len(self.memory):
                        raise Trap("out of bounds")
                    self.memory[d:d + n] = bytes(self.memory[s:s + n])
                elif name == "memory.fill":
                    r.u8()
                    n = stack.pop()
                    val = stack.pop()
                    d = stack.pop()
                    self.charge(1 + _ceil64(n))
                    if d + n > len(self.memory):
                        raise Trap("out of bounds")
                    self.memory[d:d + n] = bytes([val & 0xFF]) * n
                continue
            name = BY_OPCODE[op]
            if name in ("else", "end"):
                # Reaching else ends a then-branch: skip to the end. Both cost nothing.
                if name == "else":
                    labels.pop()
                    r.pos = f.else_ends[pos]
                    continue
                if len(labels) > 1:
                    labels.pop()
                    continue
                break
            if name == "unreachable":
                self.charge(1)
                raise Trap("unreachable")
            self.charge(2 if name in ("call", "call_indirect") else 1 if name != "memory.grow" else 0)
            if name == "nop":
                continue
            if name in ("block", "loop", "if"):
                bt = _block_type(m, r)
                body = r.pos
                if name == "if":
                    cond = stack.pop()
                height = len(stack) - len(bt[0])
                end = f.targets[pos]
                if name == "loop":
                    labels.append((len(bt[0]), body, height, True))
                else:
                    labels.append((len(bt[1]), end + 1, height, False))
                if name == "if" and not cond:
                    if pos in f.elses:
                        r.pos = f.elses[pos] + 1
                    else:
                        labels.pop()
                        r.pos = end + 1
                continue
            if name == "br":
                branch(r.u32())
                continue
            if name == "br_if":
                n = r.u32()
                if stack.pop():
                    branch(n)
                continue
            if name == "br_table":
                targets = [r.u32() for _ in range(r.u32())]
                default = r.u32()
                i = stack.pop()
                branch(targets[i] if i < len(targets) else default)
                continue
            if name == "return":
                return stack[len(stack) - len(results):] if results else []
            if name == "call":
                idx = r.u32()
                p, q = m.types[m.funcs[idx].type_idx]
                args_ = stack[len(stack) - len(p):] if p else []
                del stack[len(stack) - len(p):]
                stack.extend(self.invoke(idx, args_))
                continue
            if name == "call_indirect":
                t = r.u32()
                r.u32()
                i = stack.pop()
                if i >= len(self.table):
                    raise Trap("indirect call out of range")
                fi = self.table[i]
                if fi is None:
                    raise Trap("indirect call to null")
                if m.types[m.funcs[fi].type_idx] != m.types[t]:
                    raise Trap("indirect call type mismatch")
                p = m.types[t][0]
                args_ = stack[len(stack) - len(p):] if p else []
                del stack[len(stack) - len(p):]
                stack.extend(self.invoke(fi, args_))
                continue
            if name == "drop":
                stack.pop()
                continue
            if name in ("select", "select_t"):
                if name == "select_t":
                    r.u32()
                    r.u8()
                c = stack.pop()
                b = stack.pop()
                a = stack.pop()
                stack.append(a if c else b)
                continue
            if name == "local.get":
                stack.append(locals_[r.u32()])
                continue
            if name == "local.set":
                locals_[r.u32()] = stack.pop()
                continue
            if name == "local.tee":
                locals_[r.u32()] = stack[-1]
                continue
            if name == "global.get":
                stack.append(self.globals[r.u32()])
                continue
            if name == "global.set":
                self.globals[r.u32()] = stack.pop()
                continue
            kind = OPS[name][1]
            if kind == "memarg":
                r.u32()
                offset = r.u32()
                self._memory_op(name, offset, stack)
                continue
            if name == "memory.size":
                r.u8()
                stack.append(len(self.memory) // PAGE)
                continue
            if name == "memory.grow":
                r.u8()
                delta = stack.pop()
                pages = len(self.memory) // PAGE
                if pages + delta > self.max_pages:
                    self.charge(1)
                    stack.append(MASK32)
                else:
                    self.charge(1 + 1024 * delta)
                    self.memory.extend(bytes(delta * PAGE))
                    stack.append(pages)
                continue
            if name == "i32.const":
                stack.append(r.sleb(32) & MASK32)
                continue
            if name == "i64.const":
                stack.append(r.sleb(64) & MASK64)
                continue
            self._numeric(name, stack)
        return stack[len(stack) - len(results):] if results else []

    def _memory_op(self, name, offset, stack):
        n = WIDTH[name]
        if ".store" in name:
            v = stack.pop()
            addr = stack.pop() + offset
            self.mem(addr, n)
            self.memory[addr:addr + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
            return
        addr = stack.pop() + offset
        signed = name.endswith("_s")
        self.mem(addr, n)
        v = int.from_bytes(self.memory[addr:addr + n], "little")
        if signed and v & (1 << (8 * n - 1)):
            v -= 1 << (8 * n)
        stack.append(v & (MASK32 if name.startswith("i32") else MASK64))

    @staticmethod
    def _numeric(name, stack):
        ty, op = name.split(".", 1)
        bits = 32 if ty == "i32" else 64
        mask = MASK32 if bits == 32 else MASK64
        signed = _s32 if bits == 32 else _s64
        if op == "wrap_i64":
            stack.append(stack.pop() & MASK32)
            return
        if op == "extend_i32_s":
            stack.append(_s32(stack.pop()) & MASK64)
            return
        if op == "extend_i32_u":
            stack.append(stack.pop() & MASK32)
            return
        if op.startswith("extend") and op.endswith("_s"):
            w = int(op[len("extend"):-2])
            v = stack.pop() & ((1 << w) - 1)
            if v & (1 << (w - 1)):
                v -= 1 << w
            stack.append(v & mask)
            return
        if op == "eqz":
            stack.append(1 if stack.pop() == 0 else 0)
            return
        if op in ("clz", "ctz", "popcnt"):
            v = stack.pop()
            if op == "clz":
                out = bits - v.bit_length()
            elif op == "ctz":
                out = bits if v == 0 else (v & -v).bit_length() - 1
            else:
                out = bin(v).count("1")
            stack.append(out)
            return
        b = stack.pop()
        a = stack.pop()
        sa, sb = signed(a), signed(b)
        cmp = {"eq": a == b, "ne": a != b, "lt_s": sa < sb, "lt_u": a < b, "gt_s": sa > sb,
               "gt_u": a > b, "le_s": sa <= sb, "le_u": a <= b, "ge_s": sa >= sb, "ge_u": a >= b}
        if op in cmp:
            stack.append(1 if cmp[op] else 0)
            return
        if op in ("div_s", "div_u", "rem_s", "rem_u") and b == 0:
            raise Trap("divide by zero")
        if op == "div_s":
            if sa == -(1 << (bits - 1)) and sb == -1:
                raise Trap("integer overflow")
            q = abs(sa) // abs(sb)
            out = q if (sa < 0) == (sb < 0) else -q
        elif op == "div_u":
            out = a // b
        elif op == "rem_s":
            rr = abs(sa) % abs(sb)
            out = -rr if sa < 0 else rr
        elif op == "rem_u":
            out = a % b
        elif op == "add":
            out = a + b
        elif op == "sub":
            out = a - b
        elif op == "mul":
            out = a * b
        elif op == "and":
            out = a & b
        elif op == "or":
            out = a | b
        elif op == "xor":
            out = a ^ b
        elif op == "shl":
            out = a << (b % bits)
        elif op == "shr_s":
            out = sa >> (b % bits)
        elif op == "shr_u":
            out = a >> (b % bits)
        elif op == "rotl":
            k = b % bits
            out = (a << k) | (a >> (bits - k)) if k else a
        elif op == "rotr":
            k = b % bits
            out = (a >> k) | (a << (bits - k)) if k else a
        else:
            raise AssertionError(name)
        stack.append(out & mask)


def run(m: Module, input_: bytes, hash_name: str = "sha256") -> tuple[str, bytes, int, bytes]:
    """Runs cexchain_call: (outcome, output, fuel used, abort reason)."""
    inst = Instance(m, input_, hash_name)
    try:
        inst.invoke(m.entry, [])
    except Trap as t:
        return t.kind, b"", FUEL - inst.fuel, t.reason
    return "ok", inst.output or b"", FUEL - inst.fuel, b""


# ---------------------------------------------------------------------------
# An assembler for test modules
# ---------------------------------------------------------------------------

def uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not b & 0x40) or (v == -1 and b & 0x40):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def vec(items: list[bytes]) -> bytes:
    return uleb(len(items)) + b"".join(items)


def name_(s: str) -> bytes:
    raw = s.encode()
    return uleb(len(raw)) + raw


def instr(ins) -> bytes:
    """One instruction: a name, or (name, immediate...)."""
    if isinstance(ins, str):
        ins = (ins,)
    name, *imm = ins
    if name in FC:
        sub, kind = FC[name]
        out = b"\xfc" + uleb(sub)
        if kind == "data_zero":
            return out + uleb(imm[0]) + b"\0"
        if kind == "idx":
            return out + uleb(imm[0])
        if kind == "zero_zero":
            return out + b"\0\0"
        return out + b"\0"
    if name == "raw":
        return imm[0]
    op, kind = OPS[name][0], OPS[name][1]
    out = bytes([op])
    if kind == "none":
        return out
    if kind == "block":
        bt = imm[0] if imm else None
        if bt is None:
            return out + b"\x40"
        if bt in ("i32", "i64"):
            return out + bytes([I32 if bt == "i32" else I64])
        return out + sleb(bt)  # a type index
    if kind == "idx":
        return out + uleb(imm[0])
    if kind == "brtable":
        return out + vec([uleb(x) for x in imm[0]]) + uleb(imm[1])
    if kind == "memarg":
        align = imm[1] if len(imm) > 1 else 0
        return out + uleb(align) + uleb(imm[0] if imm else 0)
    if kind == "i32":
        v = imm[0]
        return out + sleb(v - (1 << 32) if v >= (1 << 31) else v)
    if kind == "i64":
        v = imm[0]
        return out + sleb(v - (1 << 64) if v >= (1 << 63) else v)
    if kind == "zero":
        return out + b"\0"
    if kind == "callind":
        return out + uleb(imm[0]) + b"\0"
    if kind == "selectt":
        return out + b"\x01" + bytes([I32 if imm[0] == "i32" else I64])
    raise AssertionError(name)


def code(body: list) -> bytes:
    return b"".join(instr(i) for i in body)


def section(sid: int, content: bytes) -> bytes:
    return bytes([sid]) + uleb(len(content)) + content


def assemble(funcs: list[dict], imports: list[str] = (), memory=(1, 1), table=None, globals_=(),
             elems=(), data=(), data_count=False, extra_types=(), exports_extra=(),
             entry_name="cexchain_call", raw_sections=()) -> bytes:
    """Builds a module. Each function: {"params": [...], "results": [...],
    "locals": [...], "body": [...]}; "i32"/"i64" as types. Imports are host
    function names (indices first). The last function is exported as the
    entry unless entry_name is None."""
    t = {"i32": I32, "i64": I64, "f32": 0x7D, "f64": 0x7C}  # floats only to build refused modules
    types: list[bytes] = []
    type_index: dict[bytes, int] = {}

    def type_of(params, results):
        enc = b"\x60" + vec([bytes([t[p]]) for p in params]) + vec([bytes([t[q]]) for q in results])
        if enc not in type_index:
            type_index[enc] = len(types)
            types.append(enc)
        return type_index[enc]

    host_types = {"input_size": ([], ["i32"]), "input_read": (["i32"], []),
                  "output_write": (["i32", "i32"], []), "hash": (["i32", "i32", "i32"], []),
                  "abort": (["i32", "i32"], [])}
    import_entries = [name_("cexchain") + name_(h) + b"\0" + uleb(type_of(*host_types[h])) for h in imports]
    func_entries = [uleb(type_of(f.get("params", []), f.get("results", []))) for f in funcs]
    for p, q in extra_types:
        type_of(p, q)
    bodies = []
    for f in funcs:
        locals_ = f.get("locals", [])
        groups = [uleb(1) + bytes([t[x]]) for x in locals_]
        body = vec(groups) + code(f["body"]) + b"\x0b"
        bodies.append(uleb(len(body)) + body)
    out = b"\0asm\1\0\0\0"
    out += section(1, vec(types))
    if import_entries:
        out += section(2, vec(import_entries))
    out += section(3, vec(func_entries))
    if table is not None:
        out += section(4, b"\x01\x70" + (b"\x00" + uleb(table[0]) if table[1] is None
                                         else b"\x01" + uleb(table[0]) + uleb(table[1])))
    if memory is not None:
        lo, hi = memory
        out += section(5, b"\x01" + (b"\x00" + uleb(lo) if hi is None else b"\x01" + uleb(lo) + uleb(hi)))
    if globals_:
        entries = []
        for ty, mut, value in globals_:
            init = instr(("i32.const" if ty == "i32" else "i64.const", value)) + b"\x0b"
            entries.append(bytes([t[ty], 1 if mut else 0]) + init)
        out += section(6, vec(entries))
    exports = []
    if memory is not None:
        exports.append(name_("memory") + b"\x02\x00")
    if entry_name is not None:
        exports.append(name_(entry_name) + b"\x00" + uleb(len(imports) + len(funcs) - 1))
    exports += list(exports_extra)
    out += section(7, vec(exports))
    for sid, content in raw_sections:
        out += section(sid, content)
    if elems:
        out += section(9, vec([b"\x00" + instr(("i32.const", off)) + b"\x0b" + vec([uleb(i) for i in idxs])
                               for off, idxs in elems]))
    if data_count:
        out += section(12, uleb(len(data)))
    out += section(10, vec(bodies))
    if data:
        segs = []
        for off, raw in data:
            if off is None:
                segs.append(b"\x01" + uleb(len(raw)) + raw)
            else:
                segs.append(b"\x00" + instr(("i32.const", off)) + b"\x0b" + uleb(len(raw)) + raw)
        out += section(11, vec(segs))
    return out
