// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/cost.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/wasm.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Part of cexchain::bo, the compiler proper (GCC 16). Lowering: a checked model to a contract
/// module in the profile of spec section 14, which reads the call's input and writes its output as
/// spec section 15 says.
///
/// The compiled contract:
///   - has one function per action, named by its concept (`pledge`) or as the
///     contract names it, and one that creates an instance: `issue` for an
///     asset, `create` otherwise. The same names in every language;
///   - takes arguments as a map: a creation's {"fields": {...}, "parties":
///     {role: ledger}}, an action's {input: value} (plus the role it binds, by
///     its name, when it binds one). Money is an integer of cents, a rate of
///     millionths, a quantity of base units, a date of milliseconds since the
///     epoch, a duration of milliseconds (days, weeks) or of months; a party is
///     a 32-byte ledger id; a text, a text; yes or no, false or true. Null
///     stands for a function that takes nothing. Anything else is refused;
///   - keeps the instance's state as {"state": NAME, "fields": {...}} (plus
///     "pending", the proposals AI agents made, "previous", the state before
///     the current one, "fired" and "since" for time rules, and "bill", the
///     bill its document's field holds, when the contract uses them; a list
///     is kept as its CBOR array), and reports the
///     state's name as the status, the parties (the roles bound so far and
///     every field that holds a party; one that holds none, null in the
///     state, is no party), each state change as an event [state, null]
///     (after [propose, ACTION] or [approve, ACTION] for a proposal or an
///     approval), and the instance as final when it reaches a state no action
///     can leave;
///   - asks for the consents an action needs ([2, needs]): of its starter
///     (`by`; a built-in action without one is the home's own word), of the
///     role it binds (R3) or the counterparty each call names (R21), of a
///     party a field it changes held (R8), and of every party a reached
///     `requires consent of` names (nobody, for a field that holds none). The
///     home's own consent is the call itself;
///   - refuses a call with "bo:CODE VALUES" (render_reason in messages.hpp)
///     or with the text of a `reject`. A built-in action is refused first, in
///     a state it cannot start from (bo:state ACTION).
/// It depends only on the model's concepts and names, never on spellings or
/// places, so a contract written in any language gives the same bytes.
///
/// What this version compiles: creation, the
/// contract's own actions with inputs, the vocabulary's actions with the
/// standard library's terms (R19), fields (party fields that may hold none
/// among them), states (and a return to the previous one), `requires` (with
/// a guard), `if` and `otherwise`, `reject`, consents, `in person`, agents'
/// proposals with the function `approve`, `when` rules (R24; those that only
/// state duties, R9, have no code), lists (`each`, `sum of`, `count of`,
/// `in`), bills and the charges computed on them (R26 to R28), and
/// expressions over numbers, money, quantities, rates, dates, durations,
/// texts, yes or no, parties, and lists. Anything else is reported (build.*)
/// and nothing is built: the built-in actions whose terms come later,
/// executors, a service's period due, a list built from values that
/// are not constants, and actions done inside actions.
namespace cexchain::bo {

/// Limits of a compiled contract (spec section 15, and what keeps its
/// globals and locals within the profile).
inline constexpr std::size_t max_build_functions = 256;
inline constexpr std::size_t max_build_name = 64;
inline constexpr std::size_t max_build_parties = 64;
inline constexpr std::size_t max_build_fields = 256;
inline constexpr std::size_t max_build_inputs = 256;
inline constexpr std::size_t max_build_events = 64;
inline constexpr std::size_t max_build_charges = 64;
/// The bytes compiled code has for its output (runtime::layout): beyond them
/// a call is refused with bo:output.
inline constexpr std::uint64_t max_build_output = 196'608;

/// The most a call of one function can use (cost.hpp). It
/// holds for every call whose arguments are of the function's shape (a map
/// of its inputs, each of its type, lists within their bounds; arguments of
/// another shape are refused, and reading very large ones may run out of
/// fuel first), on any state the contract writes, with any other input the
/// ledger gives within the 160 KiB compiled code reads.
struct FunctionBound {
    /// Fuel, all told (spec section 14.3: a call has 10,000,000).
    std::uint64_t fuel = 0;
    /// Of which reading and indexing the input (runtime::read_input_fuel).
    std::uint64_t input = 0;
    /// The input's items and map keys at most, which `input` is for.
    std::uint64_t input_items = 0;
    std::uint64_t input_keys = 0;
    /// Bytes of output, against the max_build_output the code has.
    std::uint64_t output = 0;

    friend bool operator==(const FunctionBound&, const FunctionBound&) = default;
};

struct Build {
    /// The module, which vm::load accepts.
    Bytes code;
    /// Each function and its kind, the deploy's interface.
    std::map<std::string, protocol::FunctionKind> interface;
    /// Each function's bound (from codegen 2 on; empty for code built as
    /// codegen 1, whose input had no useful bound).
    std::map<std::string, FunctionBound> bounds;
};

struct Lowered {
    /// Set if the model compiled.
    std::optional<Build> build;
    /// Why it did not (build.* codes, in the model's order).
    std::vector<Diagnostic> diagnostics;
};

/// Compiles a checked model: one without errors from `check`. `source` is
/// the text it was checked from, which messages quote. `codegen` is the
/// codegen version to write (an earlier one only to rebuild a deploy made
/// with it): codegen 1 checked texts' UTF-8 in the input (runtime.hpp) and
/// took two new locals for each comparison of parties that may be none and
/// each `consent of` a list; codegens 1 and 2 ask no consent by R31 (a
/// counterparty the action makes holder, pledgee, or payee, whose role was
/// bound before), which came with codegen 3.
[[nodiscard]] Lowered lower(std::string_view source, const model::Model& model,
                            std::uint32_t codegen = wasm::codegen_version)
    BO_PRE(codegen >= wasm::oldest_codegen_version && codegen <= wasm::codegen_version);

} // namespace cexchain::bo
