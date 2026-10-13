// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The runtime's registry: each routine's type and body, emitted into a
// module on first use, with the routines it calls.

#include <array>
#include <cstddef>
#include <cstdint>
#include <meta>
#include <string_view>
#include <utility>

#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/wasm.hpp>
#include <cexchain/core/bytes.hpp>

#include "reflection.hpp"
#include "runtime_parts.hpp"

namespace cexchain::bo::runtime {

namespace {

using detail::Define;
using wasm::FuncType;
constexpr auto I32 = wasm::ValType::i32;
constexpr auto I64 = wasm::ValType::i64;

constexpr std::size_t all_routines = bo::detail::enumerator_count<Routine>();
constexpr std::size_t reason_count = bo::detail::enumerator_count<Reason>();

constexpr std::array<std::string_view, reason_count> reason_texts{
    "bo:input", "bo:overflow", "bo:division-by-zero", "bo:date", "bo:output"};

/// Each reason's text is "bo:" and its enumerator's name, with dashes.
consteval bool reason_texts_match() {
    const auto enumerators = std::meta::enumerators_of(^^Reason);
    for (std::size_t i = 0; i < reason_count; ++i) {
        const std::string_view name = std::meta::identifier_of(enumerators[i]);
        const std::string_view text = reason_texts[i].substr(3);
        if (name.size() != text.size()) {
            return false;
        }
        for (std::size_t k = 0; k < name.size(); ++k) {
            if ((name[k] == '_' ? '-' : name[k]) != text[k]) {
                return false;
            }
        }
    }
    return true;
}
static_assert(reason_texts_match(), "reason_texts is out of date");

template <Reason R>
void define_fail(Runtime& rt, wasm::FunctionBuilder& b) {
    wasm::ModuleWriter& m = rt.module();
    const std::string_view text = text_of(R);
    b.u32(m.intern(as_bytes(text))).u32(static_cast<std::uint32_t>(text.size()));
    b.call(m.host(wasm::Host::abort)).unreachable();
}

struct Spec {
    Routine routine;
    FuncType type;
    Define define;
};

/// Every routine, in the order of the enumeration.
const std::array<Spec, all_routines>& specs() {
    using namespace detail;
    using enum Routine;
    static const std::array<Spec, all_routines> table{{
        {fail_input, {}, define_fail<Reason::input>},
        {fail_overflow, {}, define_fail<Reason::overflow>},
        {fail_division_by_zero, {}, define_fail<Reason::division_by_zero>},
        {fail_date, {}, define_fail<Reason::date>},
        {fail_output, {}, define_fail<Reason::output>},
        {read_input, {{}, {I32}}, define_read_input},
        {read_item, {{I32, I32}, {I32}}, define_read_item},
        {check_utf8, {{I32, I32}, {}}, define_check_utf8},
        {item_end, {{I32}, {I32}}, define_item_end},
        {head_arg, {{I32}, {I64}}, define_head_arg},
        {content, {{I32}, {I32}}, define_content},
        {map_get, {{I32, I32, I32}, {I32}}, define_map_get},
        {array_get, {{I32, I32}, {I32}}, define_array_get},
        {out_reserve, {{I32}, {I32}}, define_out_reserve},
        {out_head_size, {{I64}, {I32}}, define_out_head_size},
        {out_head, {{I32, I64}, {}}, define_out_head},
        {out_int, {{I64}, {}}, define_out_int},
        {out_bool, {{I32}, {}}, define_out_bool},
        {out_null, {}, define_out_null},
        {out_bytes, {{I32, I32}, {}}, define_out_bytes},
        {out_text, {{I32, I32}, {}}, define_out_text},
        {out_raw, {{I32, I32}, {}}, define_out_raw},
        {out_close, {{I32, I32, I64}, {}}, define_out_close},
        {out_finish, {}, define_out_finish},
        {add, {{I64, I64}, {I64}}, define_add},
        {sub, {{I64, I64}, {I64}}, define_sub},
        {mul, {{I64, I64}, {I64}}, define_mul},
        {neg, {{I64}, {I64}}, define_neg},
        {muldiv, {{I64, I64, I64, I32}, {I64}}, define_muldiv},
        {udiv128, {{I64, I64, I64}, {I64, I64}}, define_udiv128},
        {days_from_civil, {{I64, I64, I64}, {I64}}, define_days_from_civil},
        {civil_from_days, {{I64}, {I64, I64, I64}}, define_civil_from_days},
        {days_in_month, {{I64, I64}, {I64}}, define_days_in_month},
        {local_days, {{I64, I64}, {I64, I64}}, define_local_days},
        {add_months, {{I64, I64, I64}, {I64}}, define_add_months},
        {date_parts, {{I64, I64}, {I64, I64, I64}}, define_date_parts},
        {date_from_parts, {{I64, I64, I64, I64}, {I64}}, define_date_from_parts},
        {bytes_cmp, {{I32, I32, I32, I32}, {I32}}, define_bytes_cmp},
        {bytes_eq, {{I32, I32, I32, I32}, {I32}}, define_bytes_eq},
    }};
    return table;
}

const Spec& spec(const Routine routine) {
    const Spec& s = specs()[static_cast<std::size_t>(routine)];
    BO_ASSERT(s.routine == routine);
    return s;
}

constexpr std::array<Routine, reason_count> fail_routines{
    Routine::fail_input, Routine::fail_overflow, Routine::fail_division_by_zero, Routine::fail_date,
    Routine::fail_output};

consteval bool fail_routines_match() {
    for (std::size_t i = 0; i < reason_count; ++i) {
        const std::string_view routine = bo::detail::enumerator_name(fail_routines[i]);
        const std::string_view reason = bo::detail::enumerator_name(static_cast<Reason>(i));
        if (!routine.starts_with("fail_") || routine.substr(5) != reason) {
            return false;
        }
    }
    return true;
}
static_assert(fail_routines_match(), "fail_routines is out of date");
static_assert(bo::detail::enumerator_count<Var>() == 3, "Runtime::vars_ is out of date");

} // namespace

std::string_view text_of(const Reason reason) noexcept {
    return reason_texts[static_cast<std::size_t>(reason)];
}

std::size_t routine_count() noexcept {
    return all_routines;
}

std::string_view name_of(const Routine routine) noexcept {
    return bo::detail::enumerator_name(routine);
}

wasm::FuncType type_of(const Routine routine) {
    return spec(routine).type;
}

Runtime::Runtime(wasm::ModuleWriter& module) : module_(&module), functions_(all_routines) {}

wasm::Func Runtime::get(const Routine routine) {
    std::optional<wasm::Func>& slot = functions_[static_cast<std::size_t>(routine)];
    if (slot) {
        return *slot;
    }
    const Spec& s = spec(routine);
    const wasm::Func f = module_->declare(s.type);
    // Recorded before the body, which may call the routine itself.
    slot = f;
    emitted_.push_back(routine);
    wasm::FunctionBuilder b = module_->begin(f);
    s.define(*this, b);
    module_->define(std::move(b));
    return f;
}

wasm::Func Runtime::fail(const Reason reason) {
    return get(fail_routines[static_cast<std::size_t>(reason)]);
}

wasm::Global Runtime::var(const Var var) {
    std::optional<wasm::Global>& slot = vars_.at(static_cast<std::size_t>(var));
    if (!slot) {
        const std::int64_t initial = var == Var::out ? layout::output_base : 0;
        slot = module_->add_global(wasm::ValType::i32, initial);
    }
    return *slot;
}

} // namespace cexchain::bo::runtime
