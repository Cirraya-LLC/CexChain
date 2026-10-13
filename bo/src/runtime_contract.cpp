// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The runtime's routines for contracts (spec section 15): reading the call's
// input map, consents and the needs they leave, presence, typed reads of
// arguments and state, and reasons that carry a number.

#include <cstdint>

#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/wasm.hpp>

#include "runtime_parts.hpp"

namespace cexchain::bo::runtime::detail {

namespace {

using enum wasm::Op;
using wasm::Label;
using wasm::Local;
constexpr auto I32 = wasm::ValType::i32;
constexpr auto I64 = wasm::ValType::i64;

/// The input's keys (contract-input), as the call table numbers them.
constexpr std::uint32_t key_home = 3;
constexpr std::uint32_t key_caller = 6;
constexpr std::uint32_t key_consents = 8;
constexpr std::uint32_t ledger_size = 32;

/// Aborts with the reason a typed read was given (its parameters 1 and 2).
void abort_given(Runtime& rt, FunctionBuilder& b) {
    b.get(b.param(1)).get(b.param(2)).call(rt.module().host(wasm::Host::abort)).unreachable();
}

/// Pushes the value of the input's key k from the call table.
void call_item(Runtime& rt, FunctionBuilder& b, const std::uint32_t k) {
    b.i32(0).load(i32_load, rt.call_table() + 4 * k);
}

/// Pushes [address, 32, ledger, 32] and compares: equal ids.
void same_ledger(Runtime& rt, FunctionBuilder& b, const Local ledger) {
    b.i32(static_cast<std::int32_t>(ledger_size)).get(ledger);
    b.i32(static_cast<std::int32_t>(ledger_size)).call(rt.get(Routine::bytes_eq));
}

} // namespace

void define_read_call(Runtime& rt, FunctionBuilder& b) {
    const Local root = b.local(I32);
    const Local n = b.local(I32);
    const Local q = b.local(I32);
    const Local key = b.local(I32);
    const Local value = b.local(I32);
    const wasm::Func item_end = rt.get(Routine::item_end);
    const std::uint32_t table = rt.call_table();

    b.call(rt.get(Routine::read_input)).tee(root);
    b.load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne);
    fail_if(rt, b, Reason::input);
    b.get(root).call(rt.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
    b.get(root).call(rt.get(Routine::content)).set(q);
    const Label done = b.block();
    const Label next = b.loop();
    b.get(n).op(i32_eqz).br_if(done);
    b.get(q).call(item_end).set(value);
    // Keys 1 to 8 are one byte each, 0x01 to 0x08; others are skipped.
    b.get(q).load(i32_load8_u).tee(key).i32(1).op(i32_sub).i32(8).op(i32_lt_u);
    {
        const Label known = b.if_();
        b.get(key).i32(2).op(i32_shl).get(value).store(i32_store, table);
        b.end(known);
    }
    b.get(value).call(item_end).set(q);
    b.get(n).i32(1).op(i32_sub).set(n).br(next);
    b.end(next);
    b.end(done);
    b.get(root);
}

void define_consent(Runtime& rt, FunctionBuilder& b) {
    const Local ledger = b.param(0);
    const Local q = b.local(I32);
    const Local n = b.local(I32);
    const Local id = b.local(I32);
    const Local count = b.local(I32);
    const Local k = b.local(I32);
    const wasm::Func item_end = rt.get(Routine::item_end);
    const wasm::Func content = rt.get(Routine::content);
    const wasm::Func head_arg = rt.get(Routine::head_arg);
    const wasm::Global needs = rt.var(Var::needs);
    const std::uint32_t area = rt.needs_area();

    // The home agrees through the call: the caller's signer, the second
    // item of [actor, signer].
    call_item(rt, b, key_home);
    b.call(content);
    same_ledger(rt, b, ledger);
    {
        const Label home = b.if_();
        call_item(rt, b, key_caller);
        b.call(content).call(item_end).return_();
        b.end(home);
    }
    // A consent among the call's: [ledger, signer] each.
    call_item(rt, b, key_consents);
    b.tee(q);
    {
        const Label some = b.if_();
        b.get(q).call(head_arg).op(i32_wrap_i64).set(n);
        b.get(q).call(content).set(q);
        const Label done = b.block();
        const Label next = b.loop();
        b.get(n).op(i32_eqz).br_if(done);
        b.get(q).call(content).tee(id).call(content);
        b.get(id).call(head_arg).op(i32_wrap_i64).get(ledger);
        b.i32(static_cast<std::int32_t>(ledger_size)).call(rt.get(Routine::bytes_eq));
        {
            const Label found = b.if_();
            b.get(id).call(item_end).return_();
            b.end(found);
        }
        b.get(q).call(item_end).set(q);
        b.get(n).i32(1).op(i32_sub).set(n).br(next);
        b.end(next);
        b.end(done);
        b.end(some);
    }
    // Missing: needed, once.
    b.global_get(needs).set(count);
    {
        const Label done = b.block();
        const Label next = b.loop();
        b.get(k).get(count).op(i32_ge_u).br_if(done);
        b.get(k).i32(2).op(i32_shl).load(i32_load, area);
        same_ledger(rt, b, ledger);
        {
            const Label seen = b.if_();
            b.i32(0).return_();
            b.end(seen);
        }
        b.get(k).i32(1).op(i32_add).set(k).br(next);
        b.end(next);
        b.end(done);
    }
    b.get(count).u32(max_needs).op(i32_ge_u);
    fail_if(rt, b, Reason::consents);
    b.get(count).i32(2).op(i32_shl).get(ledger).store(i32_store, area);
    b.get(count).i32(1).op(i32_add).global_set(needs);
    b.i32(0);
}

void define_in_person(Runtime& rt, FunctionBuilder& b) {
    const Local signer = b.param(0);
    const Local kind = b.local(I32);
    wasm::ModuleWriter& m = rt.module();
    const wasm::Func map_get = rt.get(Routine::map_get);
    const std::uint8_t key_kind[] = {0x01};
    const std::uint8_t key_presence[] = {0x02};
    b.get(signer).op(i32_eqz);
    {
        const Label none = b.if_();
        b.i32(0).return_();
        b.end(none);
    }
    // Kind 1 (a person), encoded 0x01.
    b.get(signer).u32(m.intern(ByteView(key_kind))).i32(1).call(map_get).tee(kind).op(i32_eqz);
    {
        const Label none = b.if_();
        b.i32(0).return_();
        b.end(none);
    }
    b.get(kind).load(i32_load8_u).i32(1).op(i32_ne);
    {
        const Label other = b.if_();
        b.i32(0).return_();
        b.end(other);
    }
    b.get(signer).u32(m.intern(ByteView(key_presence))).i32(1).call(map_get);
    b.op(i32_eqz).op(i32_eqz);
}

void define_out_needs(Runtime& rt, FunctionBuilder& b) {
    const Local n = b.local(I32);
    const Local i = b.local(I32);
    const Local j = b.local(I32);
    const Local x = b.local(I32);
    const Local before = b.local(I32);
    const std::uint32_t area = rt.needs_area();
    b.global_get(rt.var(Var::needs)).set(n);
    // Insertion sort: at most 16 ledgers.
    b.i32(1).set(i);
    {
        const Label done = b.block();
        const Label next = b.loop();
        b.get(i).get(n).op(i32_ge_u).br_if(done);
        b.get(i).i32(2).op(i32_shl).load(i32_load, area).set(x);
        b.get(i).set(j);
        {
            const Label placed = b.block();
            const Label shift = b.loop();
            b.get(j).op(i32_eqz).br_if(placed);
            b.get(j).i32(1).op(i32_sub).i32(2).op(i32_shl).load(i32_load, area).tee(before);
            b.i32(static_cast<std::int32_t>(ledger_size)).get(x);
            b.i32(static_cast<std::int32_t>(ledger_size)).call(rt.get(Routine::bytes_cmp));
            b.i32(0).op(i32_le_s).br_if(placed);
            b.get(j).i32(2).op(i32_shl).get(before).store(i32_store, area);
            b.get(j).i32(1).op(i32_sub).set(j).br(shift);
            b.end(shift);
            b.end(placed);
        }
        b.get(j).i32(2).op(i32_shl).get(x).store(i32_store, area);
        b.get(i).i32(1).op(i32_add).set(i).br(next);
        b.end(next);
        b.end(done);
    }
    const wasm::Func head = rt.get(Routine::out_head);
    b.i32(4).i64(2).call(head);
    b.i64(2).call(rt.get(Routine::out_int));
    b.i32(4).get(n).op(i64_extend_i32_u).call(head);
    b.i32(0).set(i);
    {
        const Label done = b.block();
        const Label next = b.loop();
        b.get(i).get(n).op(i32_ge_u).br_if(done);
        b.get(i).i32(2).op(i32_shl).load(i32_load, area);
        b.i32(static_cast<std::int32_t>(ledger_size)).call(rt.get(Routine::out_bytes));
        b.get(i).i32(1).op(i32_add).set(i).br(next);
        b.end(next);
        b.end(done);
    }
}

void define_expect_int(Runtime& rt, FunctionBuilder& b) {
    const Local item = b.param(0);
    const Local major = b.local(I32);
    const Local arg = b.local(I64);
    const Label bad = b.block();
    b.get(item).op(i32_eqz).br_if(bad);
    b.get(item).load(i32_load8_u).i32(5).op(i32_shr_u).tee(major).i32(1).op(i32_gt_u).br_if(bad);
    // At most 2^63 - 1, or at least -2^63 (-1 - n for n below 2^63).
    b.get(item).call(rt.get(Routine::head_arg)).tee(arg).i64(0).op(i64_lt_s).br_if(bad);
    b.get(major);
    {
        const Label negative = b.if_(I64);
        b.i64(-1).get(arg).op(i64_sub);
        b.else_(negative);
        b.get(arg);
        b.end(negative);
    }
    b.return_();
    b.end(bad);
    abort_given(rt, b);
}

void define_expect_text(Runtime& rt, FunctionBuilder& b) {
    const Local item = b.param(0);
    const Label bad = b.block();
    b.get(item).op(i32_eqz).br_if(bad);
    b.get(item).load(i32_load8_u).i32(5).op(i32_shr_u).i32(3).op(i32_ne).br_if(bad);
    b.get(item).call(rt.get(Routine::content));
    b.get(item).call(rt.get(Routine::head_arg)).op(i32_wrap_i64);
    b.return_();
    b.end(bad);
    abort_given(rt, b);
}

void define_expect_ledger(Runtime& rt, FunctionBuilder& b) {
    const Local item = b.param(0);
    const Label bad = b.block();
    b.get(item).op(i32_eqz).br_if(bad);
    // A byte string of 32 bytes: 0x58 0x20.
    b.get(item).load(i32_load8_u).u32(0x58).op(i32_ne).br_if(bad);
    b.get(item).load(i32_load8_u, 1).u32(ledger_size).op(i32_ne).br_if(bad);
    b.get(item).i32(2).op(i32_add).return_();
    b.end(bad);
    abort_given(rt, b);
}

void define_expect_bool(Runtime& rt, FunctionBuilder& b) {
    const Local item = b.param(0);
    const Local flag = b.local(I32);
    const Label bad = b.block();
    b.get(item).op(i32_eqz).br_if(bad);
    // false 0xF4, true 0xF5.
    b.get(item).load(i32_load8_u).u32(0xF4).op(i32_sub).tee(flag).i32(2).op(i32_ge_u).br_if(bad);
    b.get(flag).return_();
    b.end(bad);
    abort_given(rt, b);
}

void define_fail_numbered(Runtime& rt, FunctionBuilder& b) {
    const Local text = b.param(0);
    const Local length = b.param(1);
    const Local n = b.param(2);
    const Local p = b.local(I32);
    const Local digits = b.local(I32);
    const std::uint32_t buffer = rt.number_buffer();
    const std::uint32_t last = buffer + max_numbered_text + 20;
    // The text, at most max_numbered_text bytes.
    b.get(length).u32(max_numbered_text).get(length).u32(max_numbered_text).op(i32_lt_u);
    b.op(select).set(length);
    b.u32(buffer).get(text).get(length).op(memory_copy);
    // The digits, last first, at the buffer's end; then after the text.
    b.u32(last).set(p);
    {
        const Label next = b.loop();
        b.get(p).i32(1).op(i32_sub).tee(p);
        b.get(n).i64(10).op(i64_rem_u).op(i32_wrap_i64).i32('0').op(i32_add).store(i32_store8);
        b.get(n).i64(10).op(i64_div_u).tee(n).op(i64_eqz).op(i32_eqz).br_if(next);
        b.end(next);
    }
    b.u32(last).get(p).op(i32_sub).set(digits);
    b.u32(buffer).get(length).op(i32_add).get(p).get(digits).op(memory_copy);
    b.u32(buffer).get(length).get(digits).op(i32_add);
    b.call(rt.module().host(wasm::Host::abort)).unreachable();
}

} // namespace cexchain::bo::runtime::detail
