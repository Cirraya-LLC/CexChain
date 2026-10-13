// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Harness modules for the Bo runtime (tests/bo/runtime_test.cpp): small
// contracts that run one routine on their input, so that each routine can be
// checked on vm::run, on the Python reference (wasm_ref.py --check), and
// against core. Their bytes are goldens in tests/bo/golden/runtime/; the
// fuzz target bo_runtime_fuzz embeds cbor-copy.wasm.

#pragma once

#include <cstdint>
#include <string_view>

#include <cexchain/core/bytes.hpp>

namespace cexchain::test::bo_runtime {

/// Reads the input with `read_input` and writes it back item by item through
/// the `out_*` routines (head by head, strings with `out_raw`), checking
/// each item's end against the index. So its output is its input exactly
/// when the reader accepts it; otherwise it aborts with "bo:input".
[[nodiscard]] Bytes cbor_copy_module();

/// Reads [container, key]: for a map, writes the value under the key
/// (`map_get`); for an array and an unsigned key, the item at that index
/// (`array_get`). Writes nothing when there is none.
[[nodiscard]] Bytes cbor_lookup_module();

/// Writes what its input (not CBOR) says, one command after another, through
/// the `out_*` routines:
///   0 major u8, argument u64      out_head
///   1 value i64                   out_int
///   2 length u32, bytes           out_bytes
///   3 length u32, bytes           out_text
///   4 20, 21, or 22               out_bool (false, true) or out_null
///   5                             remembers a mark (Var::out)
///   6 major u8, count u64         out_close with the last mark
///   7 length u32, bytes           out_raw
/// Numbers are little-endian.
[[nodiscard]] Bytes cbor_write_module();

/// Runs one arithmetic, date, or text routine: the input is an operation
/// (u8) and its arguments (i64, little-endian; for texts, two lengths and
/// then both texts' bytes); the output is the results (i64 each).
enum class MathOp : std::uint8_t {
    nop,
    add,
    sub,
    mul,
    neg,
    muldiv,
    udiv128,
    days_from_civil,
    civil_from_days,
    days_in_month,
    add_months,
    date_parts,
    date_from_parts,
    bytes_cmp,
    bytes_eq,
};
[[nodiscard]] Bytes math_module();

/// Only `read_input`, and then nothing: what reading costs.
[[nodiscard]] Bytes read_only_module();

/// `read_input`, then `map_get` on [map, key] as the lookup harness does,
/// writing nothing: with read_only_module, what a lookup costs.
[[nodiscard]] Bytes lookup_only_module();

/// A typical accepted call's output, written with the `out_*` routines:
/// [1, {1: {"fields": {"amount": 5000000, "holder": h'11..'}, "state":
/// "proposed"}, 2: "proposed", 3: {"bank": h'22..', "supplier": h'11..'},
/// 4: [["proposed", null]]}].
[[nodiscard]] Bytes typical_output_module();

/// Each harness by its golden's name ("cbor-copy").
struct Harness {
    std::string_view name;
    Bytes (*build)();
};
inline constexpr Harness harnesses[] = {
    {"cbor-copy", cbor_copy_module},           {"cbor-lookup", cbor_lookup_module},
    {"cbor-write", cbor_write_module},         {"math", math_module},
    {"read-only", read_only_module},           {"lookup-only", lookup_only_module},
    {"typical-output", typical_output_module},
};

} // namespace cexchain::test::bo_runtime
