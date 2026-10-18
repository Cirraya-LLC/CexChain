// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The runtime's routines, one function each that writes its body
// (runtime_cbor.cpp, runtime_math.cpp), and what they share.

#pragma once

#include <cstdint>

#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/wasm.hpp>

namespace cexchain::bo::runtime::detail {

using wasm::FunctionBuilder;

/// Writes a routine's body; `rt` gives the routines it calls.
using Define = void (*)(Runtime& rt, FunctionBuilder& b);

/// Aborts with the reason if the i32 on the stack is not zero.
inline void fail_if(Runtime& rt, FunctionBuilder& b, const Reason reason) {
    const wasm::Label then = b.if_();
    b.call(rt.fail(reason));
    b.end(then);
}

void define_read_input(Runtime& rt, FunctionBuilder& b);
void define_read_item(Runtime& rt, FunctionBuilder& b);
void define_check_utf8(Runtime& rt, FunctionBuilder& b);
void define_item_end(Runtime& rt, FunctionBuilder& b);
void define_head_arg(Runtime& rt, FunctionBuilder& b);
void define_content(Runtime& rt, FunctionBuilder& b);
void define_map_get(Runtime& rt, FunctionBuilder& b);
void define_array_get(Runtime& rt, FunctionBuilder& b);
void define_out_reserve(Runtime& rt, FunctionBuilder& b);
void define_out_head_size(Runtime& rt, FunctionBuilder& b);
void define_out_head(Runtime& rt, FunctionBuilder& b);
void define_out_int(Runtime& rt, FunctionBuilder& b);
void define_out_bool(Runtime& rt, FunctionBuilder& b);
void define_out_null(Runtime& rt, FunctionBuilder& b);
void define_out_bytes(Runtime& rt, FunctionBuilder& b);
void define_out_text(Runtime& rt, FunctionBuilder& b);
void define_out_raw(Runtime& rt, FunctionBuilder& b);
void define_out_close(Runtime& rt, FunctionBuilder& b);
void define_out_finish(Runtime& rt, FunctionBuilder& b);
void define_add(Runtime& rt, FunctionBuilder& b);
void define_sub(Runtime& rt, FunctionBuilder& b);
void define_mul(Runtime& rt, FunctionBuilder& b);
void define_neg(Runtime& rt, FunctionBuilder& b);
void define_muldiv(Runtime& rt, FunctionBuilder& b);
void define_udiv128(Runtime& rt, FunctionBuilder& b);
void define_days_from_civil(Runtime& rt, FunctionBuilder& b);
void define_civil_from_days(Runtime& rt, FunctionBuilder& b);
void define_days_in_month(Runtime& rt, FunctionBuilder& b);
void define_local_days(Runtime& rt, FunctionBuilder& b);
void define_add_months(Runtime& rt, FunctionBuilder& b);
void define_date_parts(Runtime& rt, FunctionBuilder& b);
void define_date_from_parts(Runtime& rt, FunctionBuilder& b);
void define_bytes_cmp(Runtime& rt, FunctionBuilder& b);
void define_bytes_eq(Runtime& rt, FunctionBuilder& b);
void define_read_call(Runtime& rt, FunctionBuilder& b);
void define_consent(Runtime& rt, FunctionBuilder& b);
void define_in_person(Runtime& rt, FunctionBuilder& b);
void define_out_needs(Runtime& rt, FunctionBuilder& b);
void define_expect_int(Runtime& rt, FunctionBuilder& b);
void define_expect_text(Runtime& rt, FunctionBuilder& b);
void define_expect_ledger(Runtime& rt, FunctionBuilder& b);
void define_expect_bool(Runtime& rt, FunctionBuilder& b);
void define_fail_numbered(Runtime& rt, FunctionBuilder& b);
void define_out_finish_at(Runtime& rt, FunctionBuilder& b);

} // namespace cexchain::bo::runtime::detail
