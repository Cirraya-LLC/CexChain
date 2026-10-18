// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The runtime's CBOR: reading and indexing the input, finding items in it,
// and writing the output, all in deterministic CBOR (spec section 2).

#include <array>
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

/// Pushes the remaining input after `q` (an i32 address) as an i64.
void remaining(Runtime& rt, FunctionBuilder& b, const Local q) {
    b.global_get(rt.var(Var::input_end)).get(q).op(i32_sub).op(i64_extend_i32_u);
}

} // namespace

void define_read_input(Runtime& rt, FunctionBuilder& b) {
    wasm::ModuleWriter& m = rt.module();
    // Sizes: the input's items and map keys, at most (its bound is
    // read_input_fuel's, which Runtime sets).
    b.sizes({max_input_items, max_input_items / 2});
    const Local n = b.local(I32);
    const wasm::Global items = rt.var(Var::items);
    b.call(m.host(wasm::Host::input_size)).tee(n).u32(layout::input_max).op(i32_gt_u);
    fail_if(rt, b, Reason::input);
    b.u32(layout::input_base).call(m.host(wasm::Host::input_read), {layout::input_max});
    b.u32(layout::input_base).get(n).op(i32_add).global_set(rt.var(Var::input_end));
    b.i32(0).global_set(items);
    b.u32(layout::input_base).i32(0).call(rt.get(Routine::read_item));
    b.global_get(rt.var(Var::input_end)).op(i32_ne);
    fail_if(rt, b, Reason::input);
    // The items are counted as they are read and checked once: an input
    // has fewer items than bytes, so the count stays bounded either way.
    b.global_get(items).u32(max_input_items).op(i32_gt_u);
    fail_if(rt, b, Reason::input);
    b.u32(layout::input_base);
}

void define_read_item(Runtime& rt, FunctionBuilder& b) {
    const wasm::Func self = b.self();
    const Local p = b.param(0);
    const Local depth = b.param(1);
    const Local head = b.local(I32);
    const Local info = b.local(I32);
    const Local width = b.local(I32);
    const Local q = b.local(I32);
    const Local end = b.local(I32);
    const Local n = b.local(I32);
    const Local key = b.local(I32);
    const Local prev = b.local(I32);
    const Local prev_end = b.local(I32);
    const Local arg = b.local(I64);
    const wasm::Global items = rt.var(Var::items);
    const wasm::Global input_end = rt.var(Var::input_end);

    const Label done = b.block();
    // One more item, within the input.
    b.global_get(items).i32(1).op(i32_add).global_set(items);
    b.get(p).global_get(input_end).op(i32_ge_u);
    fail_if(rt, b, Reason::input);
    // One-byte integers (0 to 23 and -1 to -24), the most common items.
    b.get(p).load(i32_load8_u).tee(head).u32(0xDF).op(i32_and).u32(0x18).op(i32_lt_u);
    {
        const Label small = b.if_();
        b.get(p).i32(1).op(i32_add).set(end).br(done);
        b.end(small);
    }

    // The head: its argument, in its shortest form (simple values aside).
    b.get(head).i32(31).op(i32_and).tee(info);
    b.get(p).i32(1).op(i32_add).set(q);
    b.i32(24).op(i32_lt_u);
    const Label small = b.if_();
    b.get(info).op(i64_extend_i32_u).set(arg);
    b.else_(small);
    {
        // 28 to 30 are reserved, 31 is an indefinite length or a break.
        b.get(info).i32(27).op(i32_gt_u);
        fail_if(rt, b, Reason::input);
        b.i32(1).get(info).i32(24).op(i32_sub).op(i32_shl).set(width);
        b.get(width).global_get(input_end).get(q).op(i32_sub).op(i32_gt_u);
        fail_if(rt, b, Reason::input);
        // 1, 2, 4, or 8 bytes.
        const Label bytes = b.loop({8});
        b.get(arg).i64(8).op(i64_shl).get(q).load(i64_load8_u).op(i64_or).set(arg);
        b.get(q).i32(1).op(i32_add).set(q);
        b.get(width).i32(1).op(i32_sub).tee(width).br_if(bytes);
        b.end(bytes);
        // Shortest form: at least 24, 2^8, 2^16, or 2^32 for 1, 2, 4, or 8
        // bytes. Simple values (major type 7) have their own rule below.
        b.get(head).u32(0xE0).op(i32_lt_u);
        const Label not_simple = b.if_();
        b.get(arg);
        b.i64(24);
        b.i64(1).i32(8).get(info).i32(25).op(i32_sub).op(i32_shl).op(i64_extend_i32_u).op(i64_shl);
        b.get(info).i32(24).op(i32_eq).op(select);
        b.op(i64_lt_u);
        fail_if(rt, b, Reason::input);
        b.end(not_simple);
    }
    b.end(small);

    // By major type.
    const Label simple = b.block();
    const Label tag = b.block();
    const Label map = b.block();
    const Label array = b.block();
    const Label text = b.block();
    const Label bytes = b.block();
    const Label integer = b.block();
    b.get(head).i32(5).op(i32_shr_u);
    const std::array<Label, 7> majors{integer, integer, bytes, text, array, map, tag};
    b.br_table(majors, simple);
    b.end(integer);
    b.get(q).set(end).br(done);

    b.end(bytes);
    b.get(arg);
    remaining(rt, b, q);
    b.op(i64_gt_u);
    fail_if(rt, b, Reason::input);
    b.get(q).get(arg).op(i32_wrap_i64).op(i32_add).set(end).br(done);

    b.end(text);
    b.get(arg);
    remaining(rt, b, q);
    b.op(i64_gt_u);
    fail_if(rt, b, Reason::input);
    b.get(q).get(arg).op(i32_wrap_i64).op(i32_add).set(end);
    if (rt.codegen() < 2) {
        b.get(q).get(end).call(rt.get(Routine::check_utf8), {layout::input_max});
    }
    b.br(done);

    b.end(array);
    b.get(depth).u32(max_input_depth).op(i32_ge_u);
    fail_if(rt, b, Reason::input);
    // Each item takes a byte at least.
    b.get(arg);
    remaining(rt, b, q);
    b.op(i64_gt_u);
    fail_if(rt, b, Reason::input);
    b.get(arg).op(i32_wrap_i64).tee(n);
    {
        const Label some = b.if_();
        b.get(depth).i32(1).op(i32_add).set(depth);
        // As many as the input has items (read_input's bound counts them).
        const Label next = b.loop({max_input_items});
        b.get(q).get(depth).call(self).set(q);
        b.get(n).i32(1).op(i32_sub).tee(n).br_if(next);
        b.end(next);
        b.end(some);
    }
    b.get(q).set(end).br(done);

    b.end(map);
    b.get(depth).u32(max_input_depth).op(i32_ge_u);
    fail_if(rt, b, Reason::input);
    // Each entry takes two bytes at least.
    b.get(arg).global_get(input_end).get(q).op(i32_sub).i32(1).op(i32_shr_u);
    b.op(i64_extend_i32_u).op(i64_gt_u);
    fail_if(rt, b, Reason::input);
    b.get(arg).op(i32_wrap_i64).tee(n);
    {
        const Label some = b.if_();
        b.get(depth).i32(1).op(i32_add).set(depth);
        const Label next = b.loop({max_input_items});
        b.get(q).set(key);
        b.get(q).get(depth).call(self).set(q);
        // Keys in the bytewise order of their encodings, none twice. Their
        // first bytes mostly decide (a text's holds its length).
        b.get(prev_end);
        {
            const Label compare = b.if_();
            b.get(prev).load(i32_load8_u).get(key).load(i32_load8_u).op(i32_lt_u).op(i32_eqz);
            const Label close = b.if_();
            b.get(prev).get(prev_end).get(prev).op(i32_sub);
            b.get(key).get(q).get(key).op(i32_sub);
            b.call(rt.get(Routine::bytes_cmp), {layout::input_max}).i32(0).op(i32_ge_s);
            fail_if(rt, b, Reason::input);
            b.end(close);
            b.end(compare);
        }
        b.get(key).set(prev).get(q).set(prev_end);
        b.get(q).get(depth).call(self).set(q);
        b.get(n).i32(1).op(i32_sub).tee(n).br_if(next);
        b.end(next);
        b.end(some);
    }
    b.get(q).set(end).br(done);

    b.end(tag);
    b.get(depth).u32(max_input_depth).op(i32_ge_u);
    fail_if(rt, b, Reason::input);
    // No bignums (tags 2 and 3).
    b.get(arg).i64(2).op(i64_sub).i64(2).op(i64_lt_u);
    fail_if(rt, b, Reason::input);
    b.get(q).get(depth).i32(1).op(i32_add).call(self).set(end).br(done);

    b.end(simple);
    // false, true, and null only: no other simple value, no floats.
    b.get(info).i32(20).op(i32_sub).i32(3).op(i32_ge_u);
    fail_if(rt, b, Reason::input);
    b.get(q).set(end);
    b.end(done);

    b.get(p).i32(2).op(i32_shl).get(end).store(i32_store, layout::ends_offset);
    b.get(end);
}

void define_check_utf8(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the bytes checked. Each pass takes one byte at least.
    b.sizes({layout::input_max});
    const Local p = b.param(0);
    const Local end = b.param(1);
    const Local c = b.local(I32);
    const Local length = b.local(I32);
    const Local point = b.local(I32);
    const Local least = b.local(I32);
    const Local k = b.local(I32);

    const Label done = b.block();
    const Label next = b.loop({b.size(0) + 1});
    b.get(p).get(end).op(i32_ge_u).br_if(done);
    // Eight ASCII bytes at a time.
    b.get(end).get(p).op(i32_sub).i32(8).op(i32_ge_u);
    {
        const Label room = b.if_();
        b.get(p).load(i64_load).i64(static_cast<std::int64_t>(0x8080'8080'8080'8080ULL));
        b.op(i64_and).op(i64_eqz);
        const Label ascii = b.if_();
        b.get(p).i32(8).op(i32_add).set(p).br(next);
        b.end(ascii);
        b.end(room);
    }
    b.get(p).load(i32_load8_u).tee(c).u32(0x80).op(i32_lt_u);
    {
        const Label ascii = b.if_();
        b.get(p).i32(1).op(i32_add).set(p).br(next);
        b.end(ascii);
    }
    // A lead byte gives the length, its bits, and the least code point of
    // that length (no overlong forms).
    {
        const Label lead = b.block();
        const Label four = b.block();
        const Label three = b.block();
        const Label two = b.block();
        b.get(c).u32(0xE0).op(i32_and).u32(0xC0).op(i32_eq).br_if(two);
        b.get(c).u32(0xF0).op(i32_and).u32(0xE0).op(i32_eq).br_if(three);
        b.get(c).u32(0xF8).op(i32_and).u32(0xF0).op(i32_eq).br_if(four);
        b.call(rt.fail(Reason::input)).unreachable();
        b.end(two);
        b.i32(2).set(length).get(c).i32(0x1F).op(i32_and).set(point).u32(0x80).set(least);
        b.br(lead);
        b.end(three);
        b.i32(3).set(length).get(c).i32(0x0F).op(i32_and).set(point).u32(0x800).set(least);
        b.br(lead);
        b.end(four);
        b.i32(4).set(length).get(c).i32(0x07).op(i32_and).set(point).u32(0x1'0000).set(least);
        b.end(lead);
    }
    b.get(end).get(p).op(i32_sub).get(length).op(i32_lt_u);
    fail_if(rt, b, Reason::input);
    b.i32(1).set(k);
    {
        // The continuation bytes: one to three.
        const Label more = b.loop({3});
        b.get(p).get(k).op(i32_add).load(i32_load8_u).tee(c);
        b.u32(0xC0).op(i32_and).u32(0x80).op(i32_ne);
        fail_if(rt, b, Reason::input);
        b.get(point).i32(6).op(i32_shl).get(c).i32(0x3F).op(i32_and).op(i32_or).set(point);
        b.get(k).i32(1).op(i32_add).tee(k).get(length).op(i32_lt_u).br_if(more);
        b.end(more);
    }
    // Not overlong, not beyond U+10FFFF, not a surrogate.
    b.get(point).get(least).op(i32_lt_u);
    fail_if(rt, b, Reason::input);
    b.get(point).u32(0x10'FFFF).op(i32_gt_u);
    fail_if(rt, b, Reason::input);
    b.get(point).u32(0xD800).op(i32_sub).u32(0x800).op(i32_lt_u);
    fail_if(rt, b, Reason::input);
    b.get(p).get(length).op(i32_add).set(p).br(next);
    b.end(next);
    b.end(done);
}

void define_item_end(Runtime&, FunctionBuilder& b) {
    b.get(b.param(0)).i32(2).op(i32_shl).load(i32_load, layout::ends_offset);
}

void define_head_arg(Runtime&, FunctionBuilder& b) {
    const Local p = b.param(0);
    const Local info = b.local(I32);
    const Local width = b.local(I32);
    const Local arg = b.local(I64);
    b.get(p).load(i32_load8_u).i32(31).op(i32_and).tee(info).i32(24).op(i32_lt_u);
    const Label small = b.if_();
    b.get(info).op(i64_extend_i32_u).return_();
    b.end(small);
    b.i32(1).get(info).i32(24).op(i32_sub).op(i32_shl).set(width);
    // 1, 2, 4, or 8 bytes (info 28 to 31 never reach here: read_input
    // refuses them).
    const Label bytes = b.loop({8});
    b.get(p).i32(1).op(i32_add).set(p);
    b.get(arg).i64(8).op(i64_shl).get(p).load(i64_load8_u).op(i64_or).set(arg);
    b.get(width).i32(1).op(i32_sub).tee(width).br_if(bytes);
    b.end(bytes);
    b.get(arg);
}

void define_content(Runtime&, FunctionBuilder& b) {
    const Local p = b.param(0);
    const Local info = b.local(I32);
    b.get(p).i32(1).op(i32_add);
    b.get(p).load(i32_load8_u).i32(31).op(i32_and).tee(info).i32(24).op(i32_lt_u);
    const Label small = b.if_(I32);
    b.i32(0);
    b.else_(small);
    b.i32(1).get(info).i32(24).op(i32_sub).op(i32_shl);
    b.end(small);
    b.op(i32_add);
}

void define_map_get(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the entries searched at most (the map's); size 1: the key's
    // length, which bounds each comparison.
    b.sizes({layout::input_max / 2, layout::input_max});
    const Local map = b.param(0);
    const Local key = b.param(1);
    const Local key_length = b.param(2);
    const Local n = b.local(I32);
    const Local q = b.local(I32);
    const Local end = b.local(I32);
    const Local order = b.local(I32);
    const wasm::Func item_end = rt.get(Routine::item_end);

    b.get(map).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne);
    {
        const Label no_map = b.if_();
        b.i32(0).return_();
        b.end(no_map);
    }
    b.get(map).call(rt.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
    b.get(map).call(rt.get(Routine::content)).set(q);
    const Label absent = b.block();
    const Label next = b.loop({b.size(0) + 1});
    b.get(n).op(i32_eqz).br_if(absent);
    b.get(q).call(item_end).set(end);
    b.get(q).get(end).get(q).op(i32_sub).get(key).get(key_length);
    b.call(rt.get(Routine::bytes_cmp), {b.size(1)}).tee(order).op(i32_eqz);
    {
        const Label found = b.if_();
        b.get(end).return_();
        b.end(found);
    }
    // Keys are in order: past it, it is absent.
    b.get(order).i32(0).op(i32_gt_s).br_if(absent);
    b.get(end).call(item_end).set(q);
    b.get(n).i32(1).op(i32_sub).set(n).br(next);
    b.end(next);
    b.end(absent);
    b.i32(0);
}

void define_array_get(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the index, at most.
    b.sizes({max_input_items});
    const Local array = b.param(0);
    const Local index = b.param(1);
    const Local q = b.local(I32);
    const wasm::Func item_end = rt.get(Routine::item_end);

    b.get(array).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0x80).op(i32_ne);
    {
        const Label no_array = b.if_();
        b.i32(0).return_();
        b.end(no_array);
    }
    b.get(index).op(i64_extend_i32_u).get(array).call(rt.get(Routine::head_arg)).op(i64_ge_u);
    {
        const Label beyond = b.if_();
        b.i32(0).return_();
        b.end(beyond);
    }
    b.get(array).call(rt.get(Routine::content)).set(q);
    const Label done = b.block();
    const Label next = b.loop({b.size(0) + 1});
    b.get(index).op(i32_eqz).br_if(done);
    b.get(q).call(item_end).set(q);
    b.get(index).i32(1).op(i32_sub).set(index).br(next);
    b.end(next);
    b.end(done);
    b.get(q);
}

void define_out_reserve(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the bytes reserved, the output's whole region at most.
    b.sizes({layout::output_end - layout::output_base});
    b.output(b.size(0));
    const Local n = b.param(0);
    const Local at = b.local(I32);
    const wasm::Global out = rt.var(Var::out);
    b.global_get(out).set(at);
    b.get(n).u32(layout::output_end).get(at).op(i32_sub).op(i32_gt_u);
    fail_if(rt, b, Reason::output);
    b.get(at).get(n).op(i32_add).global_set(out);
    b.get(at);
}

void define_out_head_size(Runtime&, FunctionBuilder& b) {
    const Local arg = b.param(0);
    const std::array<std::pair<std::int64_t, std::int32_t>, 4> sizes{
        {{24, 1}, {0x100, 2}, {0x1'0000, 3}, {0x1'0000'0000, 5}}};
    for (const auto& [below, size] : sizes) {
        b.get(arg).i64(below).op(i64_lt_u);
        const Label fits = b.if_();
        b.i32(size).return_();
        b.end(fits);
    }
    b.i32(9);
}

void define_out_head(Runtime& rt, FunctionBuilder& b) {
    const Local major = b.param(0);
    const Local arg = b.param(1);
    const Local at = b.local(I32);
    const Local n = b.local(I32);
    const Local k = b.local(I32);
    b.get(arg).call(rt.get(Routine::out_head_size)).tee(n);
    b.call(rt.get(Routine::out_reserve), {9}).set(at);
    b.get(n).i32(1).op(i32_eq);
    {
        const Label one = b.if_();
        b.get(at).get(major).i32(5).op(i32_shl).get(arg).op(i32_wrap_i64).op(i32_or);
        b.store(i32_store8).return_();
        b.end(one);
    }
    // Additional information 24 + log2(n - 1), then the argument in n - 1
    // bytes, most significant first.
    b.get(at).get(major).i32(5).op(i32_shl);
    b.get(n).i32(1).op(i32_sub).op(i32_ctz).i32(24).op(i32_add).op(i32_or).store(i32_store8);
    b.get(n).i32(1).op(i32_sub).set(k);
    const Label bytes = b.loop({8});
    b.get(at).get(k).op(i32_add).get(arg).store(i64_store8);
    b.get(arg).i64(8).op(i64_shr_u).set(arg);
    b.get(k).i32(1).op(i32_sub).tee(k).br_if(bytes);
    b.end(bytes);
}

void define_out_int(Runtime& rt, FunctionBuilder& b) {
    const Local v = b.param(0);
    const wasm::Func head = rt.get(Routine::out_head);
    b.get(v).i64(0).op(i64_ge_s);
    const Label positive = b.if_();
    b.i32(0).get(v).call(head);
    b.else_(positive);
    b.i32(1).get(v).i64(-1).op(i64_xor).call(head);
    b.end(positive);
}

void define_out_bool(Runtime& rt, FunctionBuilder& b) {
    b.i32(1).call(rt.get(Routine::out_reserve), {1});
    b.u32(0xF4).get(b.param(0)).op(i32_eqz).op(i32_eqz).op(i32_add).store(i32_store8);
}

void define_out_null(Runtime& rt, FunctionBuilder& b) {
    b.i32(1).call(rt.get(Routine::out_reserve), {1}).u32(0xF6).store(i32_store8);
}

void define_out_raw(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the bytes written, at most.
    b.sizes({layout::output_end - layout::output_base});
    const Local p = b.param(0);
    const Local n = b.param(1);
    b.get(n).call(rt.get(Routine::out_reserve), {b.size(0)}).get(p).get(n);
    b.bulk(memory_copy, b.size(0));
}

void define_out_bytes(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the string's length, at most.
    b.sizes({layout::output_end - layout::output_base});
    b.i32(2).get(b.param(1)).op(i64_extend_i32_u).call(rt.get(Routine::out_head));
    b.get(b.param(0)).get(b.param(1)).call(rt.get(Routine::out_raw), {b.size(0)});
}

void define_out_text(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the text's length, at most.
    b.sizes({layout::output_end - layout::output_base});
    b.i32(3).get(b.param(1)).op(i64_extend_i32_u).call(rt.get(Routine::out_head));
    b.get(b.param(0)).get(b.param(1)).call(rt.get(Routine::out_raw), {b.size(0)});
}

void define_out_close(Runtime& rt, FunctionBuilder& b) {
    // Size 0: the bytes written since the mark, at most.
    b.sizes({layout::output_end - layout::output_base});
    const Local mark = b.param(0);
    const Local major = b.param(1);
    const Local count = b.param(2);
    const Local size = b.local(I32);
    const Local length = b.local(I32);
    const Local end = b.local(I32);
    const wasm::Global out = rt.var(Var::out);
    // Make room for the head, move what follows the mark up, and write the
    // head at the mark.
    b.global_get(out).get(mark).op(i32_sub).set(length);
    b.get(count).call(rt.get(Routine::out_head_size)).tee(size);
    b.call(rt.get(Routine::out_reserve), {9}).get(size).op(i32_add).set(end);
    b.get(mark).get(size).op(i32_add).get(mark).get(length).bulk(memory_copy, b.size(0));
    b.get(mark).global_set(out);
    // The head again, written where it goes: its bytes were reserved above.
    b.get(major).get(count).call(rt.get(Routine::out_head));
    b.get(end).global_set(out);
}

void define_out_finish(Runtime& rt, FunctionBuilder& b) {
    b.u32(layout::output_base).global_get(rt.var(Var::out)).u32(layout::output_base);
    b.op(i32_sub).call(rt.module().host(wasm::Host::output_write),
                       {layout::output_end - layout::output_base});
}

void define_out_finish_at(Runtime& rt, FunctionBuilder& b) {
    const Local start = b.param(0);
    b.get(start).global_get(rt.var(Var::out)).get(start);
    b.op(i32_sub).call(rt.module().host(wasm::Host::output_write),
                       {layout::output_end - layout::output_base});
}

} // namespace cexchain::bo::runtime::detail
