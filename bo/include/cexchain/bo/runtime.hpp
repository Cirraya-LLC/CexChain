// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/read_bound.hpp>
#include <cexchain/bo/wasm.hpp>

/// Part of cexchain::bo, the compiler proper (GCC 16). The runtime: routines
/// compiled code calls, emitted as WebAssembly functions into the module that
/// uses them, and only those it uses (with what they call). Everything runs
/// on integers, deterministically, under the contract profile's fuel.
///
/// Values. Bo's numbers are signed 64-bit integers in their smallest unit
/// (money in minor units, rates in millionths, dates in milliseconds since
/// the epoch, durations in milliseconds or months). An item of the input is
/// its address in memory; a text or byte string is an address and a length.
///
/// Refusals. A routine that cannot go on aborts the call (host `abort`) with
/// a reason "bo:CODE" (see Reason), which tools render through the language
/// packs.
namespace cexchain::bo::runtime {

/// Where a compiled contract keeps what, in its 16 pages (1 MiB). The memory
/// is fixed at its maximum from the start: instantiation costs no fuel,
/// growing does.
namespace layout {
inline constexpr std::uint32_t pages = 16;
/// Addresses below this are never items, so 0 can mean "none".
inline constexpr std::uint32_t static_base = 16;
/// Constants (keys, texts, reasons) and scratch space, from static_base.
inline constexpr std::uint32_t static_end = 0x8000;
/// The call's input, copied in by `read_input`.
inline constexpr std::uint32_t input_base = 0x8000;
inline constexpr std::uint32_t input_max = 0x2'8000; // 160 KiB
/// The index: the end of the input item at address p is the i32 at
/// 4 * p + ends_offset.
inline constexpr std::uint32_t ends_offset = 0x1'0000;
/// The output, written by the `out_*` routines.
inline constexpr std::uint32_t output_base = 0xD'0000;
inline constexpr std::uint32_t output_end = 0x10'0000;
} // namespace layout

static_assert(4 * layout::input_base + layout::ends_offset >=
              layout::input_base + layout::input_max);
static_assert(4 * (layout::input_base + layout::input_max) + layout::ends_offset <=
              layout::output_base);
static_assert(layout::output_end == layout::pages * 65'536U);

/// The module plan for compiled contracts.
[[nodiscard]] constexpr wasm::MemoryPlan memory_plan() noexcept {
    return {layout::pages, layout::static_base, layout::static_end};
}

/// The most ledgers a call can need consents from (spec section 15).
inline constexpr std::uint32_t max_needs = 16;
/// The longest text `fail_numbered` takes.
inline constexpr std::uint32_t max_numbered_text = 128;

/// Limits of the input, as core's decoder applies them (spec section 2).
inline constexpr std::uint32_t max_input_items = 131'072;
inline constexpr std::uint32_t max_input_depth = 32;

/// Why the runtime refuses a call. The reason's text is "bo:" and the
/// enumerator's name with dashes: "bo:division-by-zero".
enum class Reason : std::uint8_t {
    input,            ///< the input is not deterministic CBOR within the limits, or too large
    overflow,         ///< a result outside the signed 64-bit range
    division_by_zero, ///< a division by zero
    date,             ///< a date outside the years 1 to 9999, or a bad offset or date
    output,           ///< the output would not fit its region (192 KiB)
    consents,         ///< a call would need the consents of more than 16 ledgers
};
[[nodiscard]] std::string_view text_of(Reason reason) noexcept BO_POST(r, r.starts_with("bo:"));

/// Rounding of a quotient, in the order of the concepts round.half_up,
/// round.half_even, and round.down. Half up rounds halves away from zero;
/// down rounds toward zero.
enum class Rounding : std::uint8_t { half_up, half_even, down };

/// The routines. Types are WebAssembly's; addresses and lengths are i32.
enum class Routine : std::uint8_t {
    // Refusals: [] -> [], abort with the reason.
    fail_input,
    fail_overflow,
    fail_division_by_zero,
    fail_date,
    fail_output,

    // The input (spec section 15), read once and indexed.
    /// [] -> [item]: copies the input to layout::input_base, checks that it is
    /// one item of deterministic CBOR in the profile (what core's
    /// cbor::decode accepts: shortest forms, definite lengths, map keys in
    /// order without duplicates, false, true, and null only, no bignums, at
    /// most 32 levels and 131,072 items; in codegen 1 also valid UTF-8 in
    /// texts), records each item's end, and returns the item. Aborts with
    /// bo:input otherwise, or if the input is longer than layout::input_max.
    /// From codegen 2 on, texts' bytes are not checked: the ledger's input
    /// holds valid UTF-8 only (core's decoder refuses anything else), and
    /// checking cost up to 50 fuel per byte of text that is not ASCII.
    read_input,
    /// [p, depth] -> [end]: reads and indexes the item at p (internal).
    read_item,
    /// [p, end] -> []: aborts with bo:input unless [p, end) is UTF-8 (internal).
    check_utf8,
    /// [item] -> [end]: the address just after an input item.
    item_end,
    /// [item] -> [i64]: the argument of an item's head: an unsigned integer's
    /// value, n of a negative integer -1 - n, a string's length, a
    /// container's count, a tag's number, a simple value's number.
    head_arg,
    /// [item] -> [address]: just after the head: a string's bytes, a
    /// container's first item, a tag's item.
    content,
    /// [map, key, key_length] -> [value]: the value under the key, whose
    /// encoding is at [key, key + key_length), or 0 when it is absent or
    /// the item is no map. The keys are in order, so it stops early.
    map_get,
    /// [array, index] -> [item]: the array's item at the index, or 0.
    array_get,

    // The output: deterministic CBOR, written in order from
    // layout::output_base (the global Var::out is where the next byte goes).
    /// [n] -> [address]: n bytes of output; aborts with bo:output beyond it.
    out_reserve,
    /// [i64 argument] -> [n]: the size of a head with that argument.
    out_head_size,
    /// [major, i64 argument] -> []: a head in its shortest form.
    out_head,
    /// [i64] -> []: an integer.
    out_int,
    /// [flag] -> []: false for 0, true otherwise.
    out_bool,
    /// [] -> []: null.
    out_null,
    /// [address, length] -> []: a byte string.
    out_bytes,
    /// [address, length] -> []: a text string (the bytes must be UTF-8).
    out_text,
    /// [address, length] -> []: bytes as they are (an encoded item).
    out_raw,
    /// [mark, major, i64 count] -> []: puts the head of an array (4), a map
    /// (5), or a tag (6) before what was written since `mark` (the value of
    /// Var::out then), for counts known only at the end.
    out_close,
    /// [] -> []: hands the output to the host (output_write).
    out_finish,

    // Checked arithmetic: a result outside the signed 64-bit range aborts
    // with bo:overflow.
    /// [i64 a, i64 b] -> [i64]
    add,
    sub,
    mul,
    /// [i64 a] -> [i64]: -a.
    neg,
    /// [i64 a, i64 b, i64 c, mode] -> [i64]: a * b / c rounded in the mode
    /// (Rounding), with a 128-bit product. Aborts with bo:division-by-zero if
    /// c is 0, and bo:overflow if the result does not fit.
    muldiv,
    /// [i64 high, i64 low, i64 d] -> [i64 quotient, i64 remainder]: the
    /// unsigned 128-bit (high, low) divided by d, with high < d (internal).
    udiv128,

    // Civil dates: the proleptic Gregorian calendar, at a fixed offset from
    // UTC in milliseconds (east positive; within a day either way), years 1
    // to 9999 (local); bo:date otherwise.
    /// [i64 year, i64 month, i64 day] -> [i64 days since 1970-01-01]: for a
    /// valid date.
    days_from_civil,
    /// [i64 days] -> [i64 year, i64 month, i64 day]
    civil_from_days,
    /// [i64 year, i64 month] -> [i64 days]
    days_in_month,
    /// [i64 time, i64 offset] -> [i64 local days, i64 milliseconds into the
    /// day] (internal).
    local_days,
    /// [i64 time, i64 months, i64 offset] -> [i64 time]: so many calendar
    /// months later (or earlier), the day of the month clamped to the new
    /// month's length (31 January plus a month is 28 or 29 February), the
    /// time of day kept.
    add_months,
    /// [i64 time, i64 offset] -> [i64 year, i64 month, i64 day]: the local date.
    date_parts,
    /// [i64 year, i64 month, i64 day, i64 offset] -> [i64 time]: the local
    /// midnight that starts the date; bo:date for no such date.
    date_from_parts,

    // Texts and bytes.
    /// [p, n, q, m] -> [-1, 0, or 1]: [p, p + n) against [q, q + m), bytewise
    /// (for UTF-8, the order of code points).
    bytes_cmp,
    /// [p, n, q, m] -> [1 or 0]: equal bytes.
    bytes_eq,

    // Contracts (spec section 15): the call's input, consents, and refusals.
    /// [] -> []: aborts with bo:consents.
    fail_consents,
    /// [] -> [root]: `read_input`, then records where the value of each key
    /// 1 to 8 of the root map (contract-input) is, in the call table
    /// (Runtime::call_table; 0 for a key that is absent). Aborts with
    /// bo:input unless the root is a map.
    read_call,
    /// [ledger] -> [signer]: the consent of the ledger (a 32-byte id at that
    /// address) to the call. The home's is the call itself: the caller's
    /// signer. Another ledger's is the signer of its consent among the call's
    /// (key 8); without one, the ledger joins the needs (Var::needs, at most
    /// 16 ledgers, each once; bo:consents beyond) and the result is 0.
    consent,
    /// [signer] -> [flag]: 1 if the signer (a `signer` map) is a person (kind
    /// 1) who proved presence (key 2).
    in_person,
    /// [] -> []: writes the output [2, needs], the needed ledgers in
    /// ascending order.
    out_needs,
    /// [item, reason, reason_length] -> [i64]: an integer item's value, which
    /// must fit 64 bits signed; aborts with the reason for anything else
    /// (also for item 0, "absent").
    expect_int,
    /// [item, reason, reason_length] -> [address, length]: a text item's bytes.
    expect_text,
    /// [item, reason, reason_length] -> [address]: a 32-byte byte string's
    /// bytes (a ledger id).
    expect_ledger,
    /// [item, reason, reason_length] -> [flag]: false or true.
    expect_bool,
    /// [text, text_length, i64 n] -> []: aborts with the text (at most 128
    /// bytes) followed by n in decimal (n at least 0): "bo:requires sign 2".
    fail_numbered,

    /// [start] -> []: hands the output from `start` on to the host
    /// (output_write): a contract that makes requests (E8) writes them
    /// first, at the start of the output region, and its output after them.
    out_finish_at,
};

/// The runtime's globals.
enum class Var : std::uint8_t {
    input_end, ///< i32: just after the input
    items,     ///< i32: items of the input read so far
    out,       ///< i32: where the next byte of output goes
    needs,     ///< i32: the ledgers whose consents the call lacks, so far
};

[[nodiscard]] std::string_view name_of(Routine routine) noexcept BO_POST(r, !r.empty());
/// The number of routines (Routine's enumerators are 0 to this, less one).
[[nodiscard]] std::size_t routine_count() noexcept;
[[nodiscard]] wasm::FuncType type_of(Routine routine);

// read_input_fuel and max_key_size: read_bound.hpp (it is read_input's bound,
// which Runtime sets, since read_item recurses and has no cost tree).

/// The routines of one module, emitted on first use. Emission order follows
/// the order of first use, so the same calls give the same module.
class Runtime {
public:
    /// Writes routines as codegen version `codegen` did (the only routine
    /// that differs is read_item: codegen 1 checks texts' UTF-8).
    explicit Runtime(wasm::ModuleWriter& module, std::uint32_t codegen = wasm::codegen_version)
        BO_PRE(module.plan().pages == layout::pages &&
               module.plan().static_base == layout::static_base &&
               module.plan().static_end == layout::static_end &&
               codegen >= wasm::oldest_codegen_version && codegen <= wasm::codegen_version);

    [[nodiscard]] wasm::ModuleWriter& module() noexcept { return *module_; }
    [[nodiscard]] std::uint32_t codegen() const noexcept { return codegen_; }
    /// The routine's function, emitting it (and what it calls) if needed.
    [[nodiscard]] wasm::Func get(Routine routine);
    [[nodiscard]] wasm::Func fail(Reason reason);
    [[nodiscard]] wasm::Global var(Var var);
    /// The call table `read_call` fills: the address of the value of the
    /// input's key k (1 to 8) is the i32 at call_table() + 4k.
    [[nodiscard]] std::uint32_t call_table();
    /// Where `consent` keeps the needed ledgers (16 addresses).
    [[nodiscard]] std::uint32_t needs_area();
    /// Scratch for `fail_numbered`'s reason.
    [[nodiscard]] std::uint32_t number_buffer();
    /// The routines emitted so far, in order.
    [[nodiscard]] const std::vector<Routine>& emitted() const noexcept { return emitted_; }

private:
    wasm::ModuleWriter* module_;
    std::uint32_t codegen_;
    std::vector<std::optional<wasm::Func>> functions_;
    std::array<std::optional<wasm::Global>, 4> vars_;
    std::vector<Routine> emitted_;
    std::optional<std::uint32_t> call_table_;
    std::optional<std::uint32_t> needs_area_;
    std::optional<std::uint32_t> number_buffer_;
};

} // namespace cexchain::bo::runtime
