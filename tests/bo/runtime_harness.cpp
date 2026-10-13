// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "runtime_harness.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/wasm.hpp>

namespace cexchain::test::bo_runtime {

namespace {

namespace wasm = bo::wasm;
namespace rt = bo::runtime;
using enum wasm::Op;
using rt::Routine;
using wasm::FunctionBuilder;
using wasm::Label;
using wasm::Local;
constexpr auto I32 = wasm::ValType::i32;
constexpr auto I64 = wasm::ValType::i64;

Bytes finish(const wasm::ModuleWriter& module) {
    auto bytes = module.finish();
    if (!bytes) {
        throw std::runtime_error("a harness module does not load");
    }
    return std::move(*bytes);
}

/// Aborts with `reason` (a harness's own, not the runtime's).
void abort_with(wasm::ModuleWriter& m, FunctionBuilder& b, const std::string_view reason) {
    b.u32(m.intern(as_bytes(reason))).u32(static_cast<std::uint32_t>(reason.size()));
    b.call(m.host(wasm::Host::abort));
}

/// Copies the raw input to layout::input_base and returns its length.
void read_raw(wasm::ModuleWriter& m, rt::Runtime& runtime, FunctionBuilder& b, const Local n) {
    b.call(m.host(wasm::Host::input_size)).tee(n).u32(rt::layout::input_max).op(i32_gt_u);
    const Label large = b.if_();
    b.call(runtime.fail(rt::Reason::input));
    b.end(large);
    b.u32(rt::layout::input_base).call(m.host(wasm::Host::input_read));
}

/// copy_item(p) -> end, recursively.
wasm::Func copy_item(wasm::ModuleWriter& m, rt::Runtime& runtime) {
    const wasm::Func self = m.declare({{I32}, {I32}});
    FunctionBuilder b = m.begin(self);
    const Local p = b.param(0);
    const Local major = b.local(I32);
    const Local c = b.local(I32);
    const Local q = b.local(I32);
    const Local n = b.local(I32);
    const Local arg = b.local(I64);
    b.get(p).load(i32_load8_u).i32(5).op(i32_shr_u).set(major);
    b.get(p).call(runtime.get(Routine::head_arg)).set(arg);
    b.get(p).call(runtime.get(Routine::content)).tee(c).set(q);
    b.get(major).get(arg).call(runtime.get(Routine::out_head));
    // Strings: their bytes.
    b.get(major).i32(2).op(i32_eq).get(major).i32(3).op(i32_eq).op(i32_or);
    {
        const Label string = b.if_();
        b.get(c).get(arg).op(i32_wrap_i64).call(runtime.get(Routine::out_raw));
        b.get(c).get(arg).op(i32_wrap_i64).op(i32_add).set(q);
        b.end(string);
    }
    // Containers: their items (a map's are keys and values), a tag's item.
    b.get(major).i32(4).op(i32_ge_u).get(major).i32(6).op(i32_le_u).op(i32_and);
    {
        const Label container = b.if_();
        b.get(arg).op(i32_wrap_i64).get(major).i32(5).op(i32_eq).op(i32_shl);
        b.i32(1).get(major).i32(6).op(i32_ne).op(select).set(n);
        const Label done = b.block();
        const Label next = b.loop();
        b.get(n).op(i32_eqz).br_if(done);
        b.get(q).call(self).set(q);
        b.get(n).i32(1).op(i32_sub).set(n).br(next);
        b.end(next);
        b.end(done);
        b.end(container);
    }
    b.get(q).get(p).call(runtime.get(Routine::item_end)).op(i32_ne);
    {
        const Label wrong = b.if_();
        abort_with(m, b, "harness: the index disagrees");
        b.end(wrong);
    }
    b.get(q);
    m.define(std::move(b));
    return self;
}

/// Pushes the i64 argument `i` of the math harness's input.
void argument(FunctionBuilder& b, const std::uint32_t i) {
    b.u32(rt::layout::input_base).load(i64_load, 1 + 8 * i);
}

/// The lookup shared by the lookup harness and the lookup-only module:
/// leaves the found item (or 0) in `found`.
void lookup(wasm::ModuleWriter& m, rt::Runtime& runtime, FunctionBuilder& b, const Local found) {
    const Local root = b.local(I32);
    const Local container = b.local(I32);
    const Local key = b.local(I32);
    b.call(runtime.get(Routine::read_input)).tee(root).load(i32_load8_u).u32(0x82).op(i32_ne);
    {
        const Label shape = b.if_();
        abort_with(m, b, "harness: not [container, key]");
        b.end(shape);
    }
    b.get(root).i32(1).op(i32_add).tee(container).call(runtime.get(Routine::item_end)).set(key);
    b.get(container).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_eq);
    const Label is_map = b.if_();
    b.get(container).get(key);
    b.get(key).call(runtime.get(Routine::item_end)).get(key).op(i32_sub);
    b.call(runtime.get(Routine::map_get)).set(found);
    b.else_(is_map);
    b.get(container).get(key).call(runtime.get(Routine::head_arg)).op(i32_wrap_i64);
    b.call(runtime.get(Routine::array_get)).set(found);
    b.end(is_map);
}

} // namespace

Bytes cbor_copy_module() {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func entry = m.declare({});
    FunctionBuilder b = m.begin(entry);
    b.call(runtime.get(Routine::read_input));
    b.call(copy_item(m, runtime)).op(drop);
    b.call(runtime.get(Routine::out_finish));
    m.define(std::move(b));
    m.entry(entry);
    return finish(m);
}

Bytes cbor_lookup_module() {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func entry = m.declare({});
    FunctionBuilder b = m.begin(entry);
    const Local found = b.local(I32);
    lookup(m, runtime, b, found);
    b.get(found);
    {
        const Label some = b.if_();
        b.get(found).get(found).call(runtime.get(Routine::item_end)).get(found).op(i32_sub);
        b.call(runtime.get(Routine::out_raw));
        b.end(some);
    }
    b.call(runtime.get(Routine::out_finish));
    m.define(std::move(b));
    m.entry(entry);
    return finish(m);
}

Bytes cbor_write_module() {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    // Marks for close commands, up to 64 open.
    const std::uint32_t marks = m.reserve(4 * 64, 4);
    const wasm::Func entry = m.declare({});
    FunctionBuilder b = m.begin(entry);
    const Local n = b.local(I32);
    const Local p = b.local(I32);
    const Local end = b.local(I32);
    const Local sp = b.local(I32);
    const Local length = b.local(I32);
    const Local major = b.local(I32);
    const Local value = b.local(I32);
    read_raw(m, runtime, b, n);
    b.u32(rt::layout::input_base).tee(p).get(n).op(i32_add).set(end);

    const Label finished = b.block();
    const Label next = b.loop();
    b.get(p).get(end).op(i32_ge_u).br_if(finished);
    {
        const Label bad = b.block();
        const Label raw = b.block();
        const Label close = b.block();
        const Label mark = b.block();
        const Label simple = b.block();
        const Label text = b.block();
        const Label bytes = b.block();
        const Label integer = b.block();
        const Label head = b.block();
        b.get(p).load(i32_load8_u);
        b.get(p).i32(1).op(i32_add).set(p);
        const std::array<Label, 8> commands{head, integer, bytes, text, simple, mark, close, raw};
        b.br_table(commands, bad);

        b.end(head);
        b.get(p).load(i32_load8_u).get(p).load(i64_load, 1).call(runtime.get(Routine::out_head));
        b.get(p).i32(9).op(i32_add).set(p).br(next);

        b.end(integer);
        b.get(p).load(i64_load).call(runtime.get(Routine::out_int));
        b.get(p).i32(8).op(i32_add).set(p).br(next);

        b.end(bytes);
        b.get(p).load(i32_load).set(length).get(p).i32(4).op(i32_add).set(p);
        b.get(p).get(length).call(runtime.get(Routine::out_bytes));
        b.get(p).get(length).op(i32_add).set(p).br(next);

        b.end(text);
        b.get(p).load(i32_load).set(length).get(p).i32(4).op(i32_add).set(p);
        b.get(p).get(length).call(runtime.get(Routine::out_text));
        b.get(p).get(length).op(i32_add).set(p).br(next);

        b.end(simple);
        b.get(p).load(i32_load8_u).set(value).get(p).i32(1).op(i32_add).set(p);
        b.get(value).i32(22).op(i32_eq);
        {
            const Label null = b.if_();
            b.call(runtime.get(Routine::out_null));
            b.else_(null);
            b.get(value).i32(20).op(i32_sub).call(runtime.get(Routine::out_bool));
            b.end(null);
        }
        b.br(next);

        b.end(mark);
        b.get(sp).i32(2).op(i32_shl).global_get(runtime.var(rt::Var::out)).store(i32_store, marks);
        b.get(sp).i32(1).op(i32_add).set(sp).br(next);

        b.end(close);
        b.get(sp).i32(1).op(i32_sub).set(sp);
        b.get(p).load(i32_load8_u).set(major);
        b.get(sp).i32(2).op(i32_shl).load(i32_load, marks).get(major).get(p).load(i64_load, 1);
        b.call(runtime.get(Routine::out_close));
        b.get(p).i32(9).op(i32_add).set(p).br(next);

        b.end(raw);
        b.get(p).load(i32_load).set(length).get(p).i32(4).op(i32_add).set(p);
        b.get(p).get(length).call(runtime.get(Routine::out_raw));
        b.get(p).get(length).op(i32_add).set(p).br(next);

        b.end(bad);
        abort_with(m, b, "harness: unknown command");
    }
    b.br(next);
    b.end(next);
    b.end(finished);
    b.call(runtime.get(Routine::out_finish));
    m.define(std::move(b));
    m.entry(entry);
    return finish(m);
}

Bytes math_module() {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func entry = m.declare({});
    FunctionBuilder b = m.begin(entry);
    const Local n = b.local(I32);
    const Local count = b.local(I32);
    const Local r0 = b.local(I64);
    const Local r1 = b.local(I64);
    const Local r2 = b.local(I64);
    constexpr std::uint32_t text = rt::layout::input_base + 17;
    read_raw(m, runtime, b, n);

    const Label results = b.block();
    {
        const Label bad = b.block();
        std::vector<Label> ops;
        for (std::uint32_t i = 0; i <= static_cast<std::uint32_t>(MathOp::bytes_eq); ++i) {
            ops.push_back(b.block());
        }
        b.u32(rt::layout::input_base).load(i32_load8_u);
        // ops.back() is the innermost: operation 0.
        std::vector<Label> order(ops.rbegin(), ops.rend());
        b.br_table(order, bad);
        auto op = [&](const MathOp which, const std::uint32_t arguments, const Routine routine,
                      const std::int32_t outputs) {
            b.end(order[static_cast<std::size_t>(which)]);
            for (std::uint32_t i = 0; i < arguments; ++i) {
                argument(b, i);
            }
            if (routine == Routine::muldiv) {
                b.op(i32_wrap_i64);
            }
            b.call(runtime.get(routine));
            const std::array<Local, 3> rs{r0, r1, r2};
            for (std::int32_t i = outputs - 1; i >= 0; --i) {
                b.set(rs[static_cast<std::size_t>(i)]);
            }
            b.i32(outputs).set(count).br(results);
        };
        b.end(order[0]); // nop
        b.br(results);
        op(MathOp::add, 2, Routine::add, 1);
        op(MathOp::sub, 2, Routine::sub, 1);
        op(MathOp::mul, 2, Routine::mul, 1);
        op(MathOp::neg, 1, Routine::neg, 1);
        op(MathOp::muldiv, 4, Routine::muldiv, 1);
        op(MathOp::udiv128, 3, Routine::udiv128, 2);
        op(MathOp::days_from_civil, 3, Routine::days_from_civil, 1);
        op(MathOp::civil_from_days, 1, Routine::civil_from_days, 3);
        op(MathOp::days_in_month, 2, Routine::days_in_month, 1);
        op(MathOp::add_months, 3, Routine::add_months, 1);
        op(MathOp::date_parts, 2, Routine::date_parts, 3);
        op(MathOp::date_from_parts, 4, Routine::date_from_parts, 1);
        for (const auto& [which, routine] : {std::pair{MathOp::bytes_cmp, Routine::bytes_cmp},
                                             std::pair{MathOp::bytes_eq, Routine::bytes_eq}}) {
            b.end(order[static_cast<std::size_t>(which)]);
            // [text, a], [text + a, b], from the two lengths.
            b.u32(text);
            argument(b, 0);
            b.op(i32_wrap_i64);
            b.u32(text);
            argument(b, 0);
            b.op(i32_wrap_i64).op(i32_add);
            argument(b, 1);
            b.op(i32_wrap_i64);
            b.call(runtime.get(routine)).op(i64_extend_i32_s).set(r0);
            b.i32(1).set(count).br(results);
        }
        b.end(bad);
        abort_with(m, b, "harness: unknown operation");
    }
    b.end(results);
    b.get(count);
    {
        const Label some = b.if_();
        const std::array<Local, 3> rs{r0, r1, r2};
        for (std::uint32_t i = 0; i < 3; ++i) {
            b.u32(rt::layout::output_base + 8 * i).get(rs[i]).store(i64_store);
        }
        b.u32(rt::layout::output_base).get(count).i32(3).op(i32_shl);
        b.call(m.host(wasm::Host::output_write));
        b.end(some);
    }
    m.define(std::move(b));
    m.entry(entry);
    return finish(m);
}

Bytes read_only_module() {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func entry = m.declare({});
    FunctionBuilder b = m.begin(entry);
    b.call(runtime.get(Routine::read_input)).op(drop);
    m.define(std::move(b));
    m.entry(entry);
    return finish(m);
}

Bytes lookup_only_module() {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func entry = m.declare({});
    FunctionBuilder b = m.begin(entry);
    const Local found = b.local(I32);
    lookup(m, runtime, b, found);
    m.define(std::move(b));
    m.entry(entry);
    return finish(m);
}

Bytes typical_output_module() {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func entry = m.declare({});
    FunctionBuilder b = m.begin(entry);
    const auto text = [&](const std::string_view t) {
        b.u32(m.intern(as_bytes(t))).u32(static_cast<std::uint32_t>(t.size()));
        b.call(runtime.get(Routine::out_text));
    };
    const auto ledger = [&](const std::uint8_t fill) {
        const std::array<std::uint8_t, 32> id = [&] {
            std::array<std::uint8_t, 32> a{};
            a.fill(fill);
            return a;
        }();
        b.u32(m.intern(id)).u32(32).call(runtime.get(Routine::out_bytes));
    };
    const auto head = [&](const std::int32_t major, const std::int64_t count) {
        b.i32(major).i64(count).call(runtime.get(Routine::out_head));
    };
    head(4, 2);
    b.i64(1).call(runtime.get(Routine::out_int));
    head(5, 4);
    b.i64(1).call(runtime.get(Routine::out_int));
    head(5, 2);
    text("fields");
    head(5, 2);
    text("amount");
    b.i64(5'000'000).call(runtime.get(Routine::out_int));
    text("holder");
    ledger(0x11);
    text("state");
    text("proposed");
    b.i64(2).call(runtime.get(Routine::out_int));
    text("proposed");
    b.i64(3).call(runtime.get(Routine::out_int));
    head(5, 2);
    text("bank");
    ledger(0x22);
    text("supplier");
    ledger(0x11);
    b.i64(4).call(runtime.get(Routine::out_int));
    head(4, 1);
    head(4, 2);
    text("proposed");
    b.call(runtime.get(Routine::out_null));
    b.call(runtime.get(Routine::out_finish));
    m.define(std::move(b));
    m.entry(entry);
    return finish(m);
}

} // namespace cexchain::test::bo_runtime
