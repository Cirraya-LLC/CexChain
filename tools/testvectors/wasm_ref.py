# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""A reference interpreter for CexChain's deterministic WebAssembly profile
(spec/README.md, section 14), written independently of the C++ implementation
to produce test vectors. It favours clarity over speed. The interpreter itself
is the independent verifier's (verifiers/python/cexchain_verify/wasm.py),
which needs only the standard library; this tool adds the rest.

    load(wasm_bytes) -> Module        raises Refused for a module outside the profile
    run(module, input, hash_name, fuel) -> (outcome, output, fuel used, reason)
        outcome is "ok" or the name of a trap; fuel is the limit (the spec's
        10,000,000 unless given)

Also an assembler for building test modules (see `assemble`), and a checker
for runs another engine recorded:

    python3 wasm_ref.py --check FILE

FILE is JSON: {"format": 1, "modules": {NAME: HEX}, "runs": [{"module": NAME,
"input": HEX, "outcome": "ok" or a trap, "output": HEX, "fuel": N, "reason":
HEX, ? "oracle": NAME, ? "hash": "sha256" or "sm3", ? "limit": N}]}. Each
run must give here exactly the outcome, output, fuel, and abort reason
recorded; an oracle also checks what the run means (see ORACLES); a limit is
the fuel the run had, if not the spec's. The Bo compiler's runtime tests
write such a file (CTest bo_reference), and so does the interpreter's fuel
sweep (CTest vm_fuel_reference). Exit status 1 if any run differs.
"""

from __future__ import annotations

import calendar
import datetime
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "verifiers" / "python"))
from cexchain_verify.wasm import (  # noqa: E402,F401 (the vector tools use them as wasm_ref's)
    _BIN, _I32_CMP, FC, FUEL, I32, I64, MASK32, MASK64, OPS, Refused, load, run)


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


# ---------------------------------------------------------------------------
# Checking runs another engine recorded (--check)
# ---------------------------------------------------------------------------

class _Refusal(Exception):
    """What a harness of the Bo runtime must abort with."""


def _signed64(v: int) -> int:
    v &= MASK64
    return v - (1 << 64) if v >> 63 else v


def _in_range(v: int) -> int:
    if not -(1 << 63) <= v < (1 << 63):
        raise _Refusal("bo:overflow")
    return v


DAY_MS = 86_400_000
FIRST_LOCAL = -62_135_596_800_000  # 0001-01-01T00:00
LAST_LOCAL = 253_402_300_799_999  # 9999-12-31T23:59:59.999
EPOCH = datetime.date(1970, 1, 1).toordinal()


def _local_day(t: int, offset: int) -> tuple[datetime.date, int]:
    if not -DAY_MS <= offset <= DAY_MS:
        raise _Refusal("bo:date")
    local = _signed64(t + offset)
    if not FIRST_LOCAL <= local <= LAST_LOCAL:
        raise _Refusal("bo:date")
    return datetime.date.fromordinal(local // DAY_MS + EPOCH), local % DAY_MS


def _muldiv(a: int, b: int, c: int, mode: int) -> int:
    """a * b / c rounded: half up (away from zero) unless mode is 1 (half
    even) or 2 (toward zero)."""
    if c == 0:
        raise _Refusal("bo:division-by-zero")
    product = a * b
    q, r = divmod(abs(product), abs(c))
    if mode != 2 and r:
        if 2 * r > abs(c) or (2 * r == abs(c) and (mode != 1 or q & 1)):
            q += 1
    return _in_range(-q if (product < 0) != (c < 0) else q)


def _bo_math(raw: bytes) -> list[int]:
    """What the Bo runtime's math harness (tests/bo/runtime_harness.hpp,
    MathOp) must output for its input, from Python's integers and calendar."""
    op = raw[0]

    def a(i: int) -> int:
        return int.from_bytes(raw[1 + 8 * i:9 + 8 * i], "little", signed=True)

    if op == 0:
        return []
    if op == 1:
        return [_in_range(a(0) + a(1))]
    if op == 2:
        return [_in_range(a(0) - a(1))]
    if op == 3:
        return [_in_range(a(0) * a(1))]
    if op == 4:
        return [_in_range(-a(0))]
    if op == 5:
        return [_muldiv(a(0), a(1), a(2), a(3) & MASK32)]
    if op == 6:
        n = ((a(0) & MASK64) << 64) | (a(1) & MASK64)
        d = a(2) & MASK64
        return [n // d, n % d]
    if op == 7:
        return [datetime.date(a(0), a(1), a(2)).toordinal() - EPOCH]
    if op == 8:
        day = datetime.date.fromordinal(a(0) + EPOCH)
        return [day.year, day.month, day.day]
    if op == 9:
        return [calendar.monthrange(a(0), a(1))[1]]
    if op == 10:
        day, ms = _local_day(a(0), a(2))
        months = a(1)
        if not -120_000 <= months <= 120_000:
            raise _Refusal("bo:date")
        total = day.year * 12 + day.month - 1 + months
        if not 12 <= total < 120_000:
            raise _Refusal("bo:date")
        year, month = total // 12, total % 12 + 1
        moved = datetime.date(year, month, min(day.day, calendar.monthrange(year, month)[1]))
        return [(moved.toordinal() - EPOCH) * DAY_MS + ms - a(2)]
    if op == 11:
        day, _ = _local_day(a(0), a(1))
        return [day.year, day.month, day.day]
    if op == 12:
        y, m, d, offset = a(0), a(1), a(2), a(3)
        if not -DAY_MS <= offset <= DAY_MS or not 1 <= y <= 9999 or not 1 <= m <= 12:
            raise _Refusal("bo:date")
        if not 1 <= d <= calendar.monthrange(y, m)[1]:
            raise _Refusal("bo:date")
        return [(datetime.date(y, m, d).toordinal() - EPOCH) * DAY_MS - offset]
    if op in (13, 14):
        n, m = a(0), a(1)
        x, y = raw[17:17 + n], raw[17 + n:17 + n + m]
        if op == 14:
            return [1 if x == y else 0]
        return [(x > y) - (x < y)]
    raise AssertionError(f"unknown operation {op}")


def _check_math(raw: bytes, outcome: str, output: bytes, reason: bytes) -> str | None:
    try:
        results = _bo_math(raw)
    except _Refusal as refusal:
        want = str(refusal).encode()
        if outcome != "aborted" or reason != want:
            return f"expected an abort with {want!r}, got {outcome} {reason!r}"
        return None
    want = b"".join((v & MASK64).to_bytes(8, "little") for v in results)
    if outcome != "ok" or output != want:
        return f"expected {want.hex()}, got {outcome} {output.hex()}"
    return None


def _check_cbor(written_back: bool):
    def check(raw: bytes, outcome: str, output: bytes, reason: bytes) -> str | None:
        if outcome == "ok":
            want = raw if written_back else b""
            return None if output == want else f"accepted, but wrote {output.hex()}"
        return None if (outcome, reason) == ("aborted", b"bo:input") else \
            f"expected ok or an abort with b'bo:input', got {outcome} {reason!r}"
    return check


def _cbor_decode(data: bytes):
    """A CBOR item (the profile's: integers, strings, arrays, maps, false,
    true, null), decoded with Python's types; maps become dicts."""
    def item(at: int):
        first = data[at]
        major, info = first >> 5, first & 31
        at += 1
        if info < 24:
            arg = info
        elif info <= 27:
            width = 1 << (info - 24)
            arg = int.from_bytes(data[at:at + width], "big")
            at += width
        else:
            raise ValueError("not in the profile")
        if major == 0:
            return arg, at
        if major == 1:
            return -1 - arg, at
        if major in (2, 3):
            raw = data[at:at + arg]
            return (raw if major == 2 else raw.decode("utf-8")), at + arg
        if major == 4:
            out = []
            for _ in range(arg):
                v, at = item(at)
                out.append(v)
            return out, at
        if major == 5:
            out = {}
            for _ in range(arg):
                k, at = item(at)
                v, at = item(at)
                out[k] = v
            return out, at
        if major == 7 and arg in (20, 21, 22):
            return {20: False, 21: True, 22: None}[arg], at
        raise ValueError("not in the profile")
    value, end = item(0)
    if end != len(data):
        raise ValueError("trailing bytes")
    return value


def _bill(spec: dict, lines: list[int], time: int, fields: dict) -> dict:
    """A bill as Bo's charges compute it (R26 to R28), from Python's integers:
    the charges in order, each on the price (each line's, or the whole bill's)
    and the charges it names; added ones times their rate, included ones
    taken out of the price; fixed amounts once per bill or on each line."""
    charges = spec["charges"]
    applies, rates = {}, {}
    for c in charges:
        ok = True
        cond = c.get("condition")
        if cond is not None and "lines_at_least" in cond:
            ok = len(lines) >= cond["lines_at_least"]
        elif cond is not None:
            ok = fields.get(cond["field"]) == cond["equals"]
        if c.get("amount") is None:
            rate = c.get("rate")
            for since, r in c.get("dated", []):
                if time >= since:
                    rate = r
            if rate is None:
                ok = False
            rates[c["name"]] = rate if rate is not None else 0
        applies[c["name"]] = ok
    divisor = 1_000_000 + sum(rates[c["name"]] for c in charges
                              if c["included"] and c.get("amount") is None and applies[c["name"]])

    def charged(c, base):
        if c.get("amount") is not None:
            return c["amount"]
        return _muldiv(base, rates[c["name"]], divisor if c["included"] else 1_000_000, c["mode"])

    price = _in_range(sum(lines))
    per_line = [c for c in charges if not c["per_document"]]
    line_amounts = []
    totals = {c["name"]: 0 for c in charges}
    for p in lines:
        here = {}
        for c in per_line:
            if not applies[c["name"]]:
                here[c["name"]] = 0
                continue
            base = (p if c["on_price"] else 0) + sum(here[o] for o in c["on"])
            here[c["name"]] = charged(c, base)
            totals[c["name"]] = _in_range(totals[c["name"]] + here[c["name"]])
        line_amounts.append({n: a for n, a in here.items() if applies[n]})
    for c in charges:
        if not c["per_document"]:
            continue
        if applies[c["name"]]:
            base = (price if c["on_price"] else 0) + sum(totals[o] for o in c["on"])
            totals[c["name"]] = charged(c, base)
    total = price + sum(totals[c["name"]] for c in charges if not c["included"])
    bill = {"time": time, "price": price, "total": _in_range(total),
            "charges": {c["name"]: ({"amount": totals[c["name"]]} if c.get("amount") is not None
                                    else {"rate": rates[c["name"]], "amount": totals[c["name"]]})
                        for c in charges if applies[c["name"]]}}
    if per_line:
        bill["lines"] = line_amounts
    return bill


def _check_bill(raw: bytes, outcome: str, output: bytes, reason: bytes,
                recorded: dict) -> str | None:
    """A Bo contract's bill: what the run made must be what _bill computes
    from the contract's charges (recorded["bill"]), the lines and fields the
    instance holds, and the call's time."""
    if outcome != "ok":
        return None
    out = _cbor_decode(output)
    if out[0] != 1:
        return None
    state = out[1][1]
    events = out[1].get(4, [])
    spec = recorded["bill"]
    made = [e[1] for e in events if e[0] == spec["document"]]
    if not made:
        return None
    if made[0] != state["bill"]:
        return "the event's bill is not the state's"
    time = _cbor_decode(raw)[7]
    fields = state["fields"]
    want = _bill(spec, fields[spec["document"]], time, fields)
    return None if want == state["bill"] else f"expected the bill {want}, got {state['bill']}"


# What a run means, by the harness that made it (tests/bo/runtime_harness.hpp):
# a CBOR copy writes back exactly what it accepts, a read writes nothing, and
# math agrees with Python's integers and calendar; a Bo contract's bill agrees
# with Python's integers (tests/bo/codegen_test.cpp).
ORACLES = {
    "cbor-copy": _check_cbor(True),
    "cbor-read": _check_cbor(False),
    "math": _check_math,
    "bill": _check_bill,
}


def check(path: str) -> int:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("format") != 1:
        print(f"{path}: not format 1")
        return 1
    modules = {}
    for name, wasm in doc["modules"].items():
        try:
            modules[name] = load(bytes.fromhex(wasm))
        except Refused as refusal:
            print(f"module {name}: refused here ({refusal})")
            return 1
    started = time.monotonic()
    failures = 0
    fuel_total = 0
    for i, recorded in enumerate(doc["runs"]):
        raw = bytes.fromhex(recorded["input"])
        outcome, output, fuel, reason = run(modules[recorded["module"]], raw,
                                            recorded.get("hash", "sha256"),
                                            recorded.get("limit", FUEL))
        fuel_total += fuel
        problems = []
        want = (recorded["outcome"], bytes.fromhex(recorded["output"]), recorded["fuel"],
                bytes.fromhex(recorded["reason"]))
        if (outcome, output, fuel, reason) != want:
            problems.append(f"here {outcome}, fuel {fuel}, output {output.hex()[:64]}, reason "
                            f"{reason!r}; recorded {want[0]}, fuel {want[2]}, output "
                            f"{want[1].hex()[:64]}, reason {want[3]!r}")
        oracle = recorded.get("oracle")
        if oracle:
            check_with = ORACLES[oracle]
            problem = (check_with(raw, outcome, output, reason, recorded) if oracle == "bill"
                       else check_with(raw, outcome, output, reason))
            if problem:
                problems.append(f"{oracle}: {problem}")
        if problems:
            failures += 1
            if failures <= 20:
                print(f"run {i} ({recorded['module']}, input {raw.hex()[:64]}): "
                      + "; ".join(problems))
    runs = len(doc["runs"])
    print(f"{runs} runs of {len(modules)} modules, {fuel_total:,} fuel in "
          f"{time.monotonic() - started:.1f} s: "
          + ("all identical" if not failures else f"{failures} differ"))
    return 1 if failures else 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Check recorded runs against this interpreter.")
    parser.add_argument("--check", metavar="FILE", required=True,
                        help="JSON of modules and runs, as the Bo runtime tests write it")
    sys.exit(check(parser.parse_args().check))
