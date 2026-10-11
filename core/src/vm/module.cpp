// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/vm.hpp>

#include "internal.hpp"

namespace cexchain::vm {

namespace detail {

namespace {

constexpr std::uint64_t mask32 = 0xFFFF'FFFF;

/// Reads the binary format. The first error sticks: it moves the position to
/// the end, so later reads fail at once and return zero, and callers only
/// check `failed()` before acting on what they read.
class Reader {
public:
    Reader(ByteView data, std::size_t pos, std::size_t end) noexcept
        : data_(data), pos_(pos), end_(end) {}

    [[nodiscard]] bool done() const noexcept { return pos_ >= end_; }
    [[nodiscard]] bool failed() const noexcept { return failed_; }
    [[nodiscard]] Error error() const noexcept { return error_; }
    [[nodiscard]] std::size_t pos() const noexcept { return pos_; }
    [[nodiscard]] std::size_t end() const noexcept { return end_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return end_ - pos_; }
    void seek(std::size_t pos) noexcept { pos_ = pos; }

    void fail(Errc code, std::string_view detail) noexcept { fail(Error{code, detail}); }

    void fail(Error error) noexcept {
        if (!failed_) {
            failed_ = true;
            error_ = error;
        }
        pos_ = end_;
    }

    [[nodiscard]] Status status() const noexcept {
        if (failed_) {
            return std::unexpected(error_);
        }
        return {};
    }

    std::uint8_t byte() noexcept {
        if (pos_ >= end_) {
            fail(Errc::malformed, "unexpected end");
            return 0;
        }
        return data_[pos_++];
    }

    /// The next byte, without reading it (0 at the end).
    [[nodiscard]] std::uint8_t peek() const noexcept { return pos_ < end_ ? data_[pos_] : 0; }

    std::uint32_t u32() noexcept {
        std::uint64_t result = 0;
        for (unsigned i = 0; i < 5; ++i) {
            const std::uint8_t b = byte();
            result |= static_cast<std::uint64_t>(b & 0x7FU) << (7U * i);
            if ((b & 0x80U) == 0) {
                if (i == 4 && (b >> 4U) != 0) {
                    fail(Errc::malformed, "integer too large");
                    return 0;
                }
                return failed_ ? 0 : static_cast<std::uint32_t>(result);
            }
        }
        fail(Errc::malformed, "integer representation too long");
        return 0;
    }

    /// A signed LEB128 integer of `bits` bits (32, 33, or 64), sign-extended.
    std::int64_t sleb(unsigned bits) noexcept {
        std::uint64_t result = 0;
        unsigned shift = 0;
        const unsigned n = (bits + 6) / 7;
        for (unsigned i = 0; i < n; ++i) {
            const std::uint8_t b = byte();
            if (failed_) {
                return 0;
            }
            result |= static_cast<std::uint64_t>(b & 0x7FU) << shift;
            shift += 7;
            if ((b & 0x80U) == 0) {
                if (i == n - 1) {
                    // The sign bit and the unused bits of the last byte agree.
                    const unsigned used = bits - 7 * i;
                    const unsigned upper = (b & 0x7FU) >> (used - 1);
                    if (upper != 0 && upper != (1U << (8 - used)) - 1) {
                        fail(Errc::malformed, "integer too large");
                        return 0;
                    }
                }
                if ((b & 0x40U) != 0 && shift < 64) {
                    result |= ~std::uint64_t{0} << shift;
                }
                return static_cast<std::int64_t>(result);
            }
        }
        fail(Errc::malformed, "integer representation too long");
        return 0;
    }

    ByteView bytes(std::size_t n) noexcept {
        if (n > remaining()) {
            fail(Errc::malformed, "unexpected end");
            return {};
        }
        const ByteView out = data_.subspan(pos_, n);
        pos_ += n;
        return out;
    }

    std::string_view name() noexcept {
        const ByteView raw = bytes(u32());
        const std::string_view text(reinterpret_cast<const char*>(raw.data()), raw.size());
        if (!failed_ && !cbor::is_valid_utf8(text)) {
            fail(Errc::malformed, "malformed UTF-8");
        }
        return text;
    }

    /// Fails unless `count` items of at least a byte each can follow.
    bool fits(std::uint32_t count) noexcept {
        if (count > remaining()) {
            fail(Errc::malformed, "unexpected end");
            return false;
        }
        return !failed_;
    }

private:
    ByteView data_;
    std::size_t pos_;
    std::size_t end_;
    bool failed_ = false;
    Error error_{};
};

std::uint8_t value_type(Reader& r) noexcept {
    const std::uint8_t t = r.byte();
    if (!r.failed() && t != type_i32 && t != type_i64) {
        r.fail(Errc::unsupported, "value type outside the profile");
    }
    return t;
}

void value_types(Reader& r, std::vector<std::uint8_t>& out, std::uint32_t cap) {
    const std::uint32_t n = r.u32();
    if (n > cap) {
        r.fail(Errc::unsupported, "type too large");
        return;
    }
    for (std::uint32_t i = 0; i < n && !r.failed(); ++i) {
        out.push_back(value_type(r));
    }
}

Limits limits(Reader& r, std::uint32_t cap) noexcept {
    const std::uint8_t flag = r.byte();
    if (!r.failed() && flag > 1) {
        r.fail(Errc::unsupported, "limits outside the profile");
    }
    Limits out;
    out.min = r.u32();
    out.max = flag == 1 ? r.u32() : cap;
    if (!r.failed() && (out.min > cap || out.max > cap || out.min > out.max)) {
        r.fail(Errc::unsupported, "limits too large");
    }
    return out;
}

std::uint64_t const_expr(Reader& r, std::uint8_t type) noexcept {
    const std::uint8_t op = r.byte();
    std::uint64_t value = 0;
    if (type == type_i32 && op == 0x41) {
        value = static_cast<std::uint64_t>(r.sleb(32)) & mask32;
    } else if (type == type_i64 && op == 0x42) {
        value = static_cast<std::uint64_t>(r.sleb(64));
    } else {
        r.fail(Errc::unsupported, "constant expression outside the profile");
    }
    if (r.byte() != 0x0B) {
        r.fail(Errc::unsupported, "constant expression outside the profile");
    }
    return value;
}

struct HostSpec {
    std::string_view name;
    Host host;
    std::uint8_t params;
    std::uint8_t results;
};

// Every host function takes and returns only i32 values.
constexpr std::array<HostSpec, 5> host_functions{{
    {"input_size", Host::input_size, 0, 1},
    {"input_read", Host::input_read, 1, 0},
    {"output_write", Host::output_write, 2, 0},
    {"hash", Host::hash, 3, 0},
    {"abort", Host::abort, 2, 0},
}};

bool matches(const FuncType& type, const HostSpec& spec) {
    auto all_i32 = [](const std::vector<std::uint8_t>& ts, std::uint8_t n) {
        return ts.size() == n && std::ranges::all_of(ts, [](auto t) { return t == type_i32; });
    };
    return all_i32(type.params, spec.params) && all_i32(type.results, spec.results);
}

/// Bytes accessed by a load or store in the profile (0x28 to 0x3E, floats
/// excluded), or 0 for any other opcode.
constexpr std::uint32_t access_width(std::uint8_t opcode) noexcept {
    switch (opcode) {
    case 0x2C: // i32.load8_s
    case 0x2D: // i32.load8_u
    case 0x30: // i64.load8_s
    case 0x31: // i64.load8_u
    case 0x3A: // i32.store8
    case 0x3C: // i64.store8
        return 1;
    case 0x2E: // i32.load16_s
    case 0x2F: // i32.load16_u
    case 0x32: // i64.load16_s
    case 0x33: // i64.load16_u
    case 0x3B: // i32.store16
    case 0x3D: // i64.store16
        return 2;
    case 0x28: // i32.load
    case 0x34: // i64.load32_s
    case 0x35: // i64.load32_u
    case 0x36: // i32.store
    case 0x3E: // i64.store32
        return 4;
    case 0x29: // i64.load
    case 0x37: // i64.store
        return 8;
    default:
        return 0;
    }
}

/// The operand types of a numeric instruction in the profile: `pops` values
/// of type `in`, pushing one of type `out`. `pops` is 0 for other opcodes.
struct NumericType {
    std::uint8_t pops = 0;
    std::uint8_t in = 0;
    std::uint8_t out = 0;
};

constexpr NumericType numeric_type(std::uint8_t op) noexcept {
    constexpr std::uint8_t i32 = type_i32;
    constexpr std::uint8_t i64 = type_i64;
    if (op == 0x45) {
        return {1, i32, i32}; // i32.eqz
    }
    if (op >= 0x46 && op <= 0x4F) {
        return {2, i32, i32}; // i32 comparisons
    }
    if (op == 0x50) {
        return {1, i64, i32}; // i64.eqz
    }
    if (op >= 0x51 && op <= 0x5A) {
        return {2, i64, i32}; // i64 comparisons
    }
    if (op >= 0x67 && op <= 0x69) {
        return {1, i32, i32}; // i32.clz, ctz, popcnt
    }
    if (op >= 0x6A && op <= 0x78) {
        return {2, i32, i32}; // i32 arithmetic
    }
    if (op >= 0x79 && op <= 0x7B) {
        return {1, i64, i64}; // i64.clz, ctz, popcnt
    }
    if (op >= 0x7C && op <= 0x8A) {
        return {2, i64, i64}; // i64 arithmetic
    }
    switch (op) {
    case 0xA7:
        return {1, i64, i32}; // i32.wrap_i64
    case 0xAC:
    case 0xAD:
        return {1, i32, i64}; // i64.extend_i32_s, i64.extend_i32_u
    case 0xC0:
    case 0xC1:
        return {1, i32, i32}; // i32.extend8_s, extend16_s
    case 0xC2:
    case 0xC3:
    case 0xC4:
        return {1, i64, i64}; // i64.extend8_s, extend16_s, extend32_s
    default:
        return {};
    }
}

constexpr std::uint8_t unknown = 0;
constexpr std::array<std::uint8_t, 1> single_i32{type_i32};
constexpr std::array<std::uint8_t, 1> single_i64{type_i64};
constexpr std::uint32_t no_instr = 0xFFFF'FFFF;

using Types = std::span<const std::uint8_t>;

enum class Kind : std::uint8_t { function, block, loop, if_, else_ };

struct Ctrl {
    Kind kind = Kind::block;
    Types ins;
    Types outs;
    std::uint32_t height = 0;
    bool unreachable = false;
    /// For a loop: the first instruction of its body.
    std::uint32_t loop_target = 0;
    /// For an if without an else so far: the if instruction.
    std::uint32_t if_instr = no_instr;
    /// Instructions, and branch table entries, that continue after the end.
    std::vector<std::uint32_t> fixups;
    std::vector<std::uint32_t> branch_fixups;

    [[nodiscard]] Types label_types() const noexcept { return kind == Kind::loop ? ins : outs; }
};

/// Validates a function body with the algorithm of the WebAssembly
/// specification's appendix, measuring the operand stack's maximum height,
/// and translates it into the interpreter's form.
class Translator {
public:
    Translator(const ModuleData& m, Function& f, Reader body) : m_(m), f_(f), r_(body) {}

    Status run() {
        const FuncType& type = m_.types[f_.type];
        push_ctrl(Kind::function, {}, type.results);
        while (!r_.failed()) {
            if (r_.done()) {
                r_.fail(Errc::malformed, "function body does not end");
                break;
            }
            if (step()) {
                break;
            }
        }
        if (!r_.failed() && max_height_ > max_stack_height) {
            r_.fail(Errc::unsupported, "operand stack too high");
        }
        f_.max_height = static_cast<std::uint32_t>(max_height_);
        return r_.status();
    }

private:
    void mismatch() { r_.fail(Errc::malformed, "type mismatch"); }

    void push(std::uint8_t t) {
        vals_.push_back(t);
        max_height_ = std::max(max_height_, vals_.size());
    }

    void push(Types ts) {
        for (const std::uint8_t t : ts) {
            push(t);
        }
    }

    std::uint8_t pop() {
        const Ctrl& c = ctrls_.back();
        if (vals_.size() == c.height) {
            if (!c.unreachable) {
                mismatch();
            }
            return unknown;
        }
        const std::uint8_t t = vals_.back();
        vals_.pop_back();
        return t;
    }

    std::uint8_t pop(std::uint8_t expect) {
        const std::uint8_t actual = pop();
        if (actual != expect && actual != unknown && expect != unknown) {
            mismatch();
        }
        return actual;
    }

    void pop(Types ts) {
        for (auto it = ts.rbegin(); it != ts.rend(); ++it) {
            pop(*it);
        }
    }

    void push_ctrl(Kind kind, Types ins, Types outs) {
        if (ctrls_.size() >= max_nesting) {
            r_.fail(Errc::unsupported, "nesting too deep");
            return;
        }
        Ctrl c;
        c.kind = kind;
        c.ins = ins;
        c.outs = outs;
        c.height = static_cast<std::uint32_t>(vals_.size());
        c.loop_target = size();
        ctrls_.push_back(std::move(c));
        push(ins);
    }

    Ctrl pop_ctrl() {
        Ctrl& c = ctrls_.back();
        pop(c.outs);
        if (vals_.size() != c.height) {
            mismatch();
        }
        Ctrl out = std::move(c);
        ctrls_.pop_back();
        return out;
    }

    void unreachable() {
        Ctrl& c = ctrls_.back();
        vals_.resize(c.height);
        c.unreachable = true;
    }

    [[nodiscard]] std::uint32_t size() const noexcept {
        return static_cast<std::uint32_t>(f_.code.size());
    }

    Instr& emit(std::uint16_t op) {
        Instr in;
        in.op = op;
        return f_.code.emplace_back(in);
    }

    /// The label `depth` levels out, or null (after failing) if there is none.
    Ctrl* label(std::uint32_t depth) {
        if (depth >= ctrls_.size()) {
            r_.fail(Errc::malformed, "unknown label");
            return nullptr;
        }
        return &ctrls_[ctrls_.size() - 1 - depth];
    }

    /// Points the instruction at index `at` (br or br_if) at the label.
    void target(Ctrl& c, std::uint32_t at) {
        Instr& in = f_.code[at];
        in.arity = static_cast<std::uint16_t>(c.label_types().size());
        in.b = c.height;
        if (c.kind == Kind::loop) {
            in.a = c.loop_target;
        } else {
            c.fixups.push_back(at);
        }
    }

    void add_branch(Ctrl& c) {
        Branch e;
        e.arity = static_cast<std::uint32_t>(c.label_types().size());
        e.height = c.height;
        if (c.kind == Kind::loop) {
            e.target = c.loop_target;
        } else {
            c.branch_fixups.push_back(static_cast<std::uint32_t>(f_.branches.size()));
        }
        f_.branches.push_back(e);
    }

    std::pair<Types, Types> block_type() {
        const std::uint8_t b = r_.peek();
        if (b == 0x40) {
            r_.byte();
            return {};
        }
        if (b == type_i32) {
            r_.byte();
            return {{}, single_i32};
        }
        if (b == type_i64) {
            r_.byte();
            return {{}, single_i64};
        }
        const std::int64_t idx = r_.sleb(33);
        if (r_.failed()) {
            return {};
        }
        if (idx < 0 || static_cast<std::uint64_t>(idx) >= m_.types.size()) {
            r_.fail(Errc::unsupported, "block type outside the profile");
            return {};
        }
        const FuncType& t = m_.types[static_cast<std::size_t>(idx)];
        return {t.params, t.results};
    }

    std::uint8_t local(std::uint32_t idx) {
        if (idx >= f_.locals.size()) {
            r_.fail(Errc::malformed, "unknown local");
            return unknown;
        }
        return f_.locals[idx];
    }

    const Global* global(std::uint32_t idx) {
        if (idx >= m_.globals.size()) {
            r_.fail(Errc::malformed, "unknown global");
            return nullptr;
        }
        return &m_.globals[idx];
    }

    void zero_byte() {
        if (r_.byte() != 0) {
            r_.fail(Errc::malformed, "memory index");
        }
    }

    void data_index(std::uint32_t idx) {
        if (!m_.data_count || idx >= *m_.data_count) {
            r_.fail(Errc::malformed, "unknown data segment");
        }
    }

    void pop3_i32() {
        pop(type_i32);
        pop(type_i32);
        pop(type_i32);
    }

    /// Validates and translates one instruction; true after the function's end.
    bool step() {
        const std::uint8_t op = r_.byte();
        if (r_.failed()) {
            return false;
        }
        switch (op) {
        case 0x00: // unreachable
            emit(op_unreachable);
            unreachable();
            return false;
        case 0x01: // nop
            emit(op_nop);
            return false;
        case 0x02:   // block
        case 0x03:   // loop
        case 0x04: { // if
            const auto [ins, outs] = block_type();
            if (op == 0x04) {
                pop(type_i32);
            }
            pop(ins);
            const std::uint32_t at = size();
            emit(op == 0x04 ? op_if : op_nop);
            push_ctrl(op == 0x02 ? Kind::block : op == 0x03 ? Kind::loop : Kind::if_, ins, outs);
            if (op == 0x04 && !r_.failed()) {
                ctrls_.back().if_instr = at;
            }
            return false;
        }
        case 0x05: { // else
            if (ctrls_.back().kind != Kind::if_) {
                r_.fail(Errc::malformed, "else without if");
                return false;
            }
            Ctrl c = pop_ctrl();
            const std::uint32_t at = size();
            emit(op_else);
            c.fixups.push_back(at);
            f_.code[c.if_instr].a = size();
            push_ctrl(Kind::else_, c.ins, c.outs);
            if (!r_.failed()) {
                Ctrl& e = ctrls_.back();
                e.fixups = std::move(c.fixups);
                e.branch_fixups = std::move(c.branch_fixups);
            }
            return false;
        }
        case 0x0B: { // end
            Ctrl c = pop_ctrl();
            if (c.kind == Kind::if_ && !std::ranges::equal(c.ins, c.outs)) {
                r_.fail(Errc::malformed, "if without else must keep its type");
                return false;
            }
            const std::uint32_t next = size();
            for (const std::uint32_t at : c.fixups) {
                f_.code[at].a = next;
            }
            for (const std::uint32_t at : c.branch_fixups) {
                f_.branches[at].target = next;
            }
            if (c.if_instr != no_instr) {
                f_.code[c.if_instr].a = next;
            }
            push(c.outs);
            if (!ctrls_.empty()) {
                return false;
            }
            emit(op_end_function).arity = static_cast<std::uint16_t>(c.outs.size());
            if (!r_.done()) {
                r_.fail(Errc::malformed, "code after the function's end");
            }
            return true;
        }
        case 0x0C:   // br
        case 0x0D: { // br_if
            Ctrl* c = label(r_.u32());
            if (c == nullptr) {
                return false;
            }
            if (op == 0x0D) {
                pop(type_i32);
            }
            const Types ts = c->label_types();
            pop(ts);
            const std::uint32_t at = size();
            emit(op == 0x0C ? op_br : op_br_if);
            target(*c, at);
            if (op == 0x0C) {
                unreachable();
            } else {
                push(ts);
            }
            return false;
        }
        case 0x0E: { // br_table
            const std::uint32_t n = r_.u32();
            if (!r_.fits(n)) {
                return false;
            }
            std::vector<std::uint32_t> depths(n);
            for (std::uint32_t& d : depths) {
                d = r_.u32();
            }
            depths.push_back(r_.u32());
            if (r_.failed()) {
                return false;
            }
            for (const std::uint32_t d : depths) {
                if (label(d) == nullptr) {
                    return false;
                }
            }
            pop(type_i32);
            const std::size_t arity = label(depths.back())->label_types().size();
            Instr& in = emit(op_br_table);
            in.a = static_cast<std::uint32_t>(f_.branches.size());
            in.b = n;
            for (std::uint32_t i = 0; i < n; ++i) {
                Ctrl& c = *label(depths[i]);
                const Types ts = c.label_types();
                if (ts.size() != arity) {
                    mismatch();
                    return false;
                }
                // Pops and pushes back what it popped (the appendix's push_vals(pop_vals)).
                std::array<std::uint8_t, max_params> popped{};
                for (std::size_t k = ts.size(); k-- > 0;) {
                    popped[k] = pop(ts[k]);
                }
                for (std::size_t k = 0; k < ts.size(); ++k) {
                    push(popped[k]);
                }
                add_branch(c);
            }
            Ctrl& d = *label(depths.back());
            pop(d.label_types());
            add_branch(d);
            unreachable();
            return false;
        }
        case 0x0F: // return
            pop(ctrls_.front().outs);
            emit(op_return).arity = static_cast<std::uint16_t>(ctrls_.front().outs.size());
            unreachable();
            return false;
        case 0x10: { // call
            const std::uint32_t idx = r_.u32();
            if (r_.failed()) {
                return false;
            }
            if (idx >= m_.functions.size()) {
                r_.fail(Errc::malformed, "unknown function");
                return false;
            }
            const FuncType& t = m_.types[m_.functions[idx].type];
            pop(t.params);
            push(t.results);
            emit(op_call).a = idx;
            return false;
        }
        case 0x11: { // call_indirect
            const std::uint32_t idx = r_.u32();
            const std::uint32_t table = r_.u32();
            if (r_.failed()) {
                return false;
            }
            if (table != 0 || !m_.table) {
                r_.fail(Errc::malformed, "unknown table");
                return false;
            }
            if (idx >= m_.types.size()) {
                r_.fail(Errc::malformed, "unknown type");
                return false;
            }
            pop(type_i32);
            pop(m_.types[idx].params);
            push(m_.types[idx].results);
            emit(op_call_indirect).a = idx;
            return false;
        }
        case 0x1A: // drop
            pop();
            emit(op_drop);
            return false;
        case 0x1B: { // select
            pop(type_i32);
            const std::uint8_t t1 = pop();
            const std::uint8_t t2 = pop();
            if (t1 != unknown && t2 != unknown && t1 != t2) {
                mismatch();
            }
            push(t1 != unknown ? t1 : t2);
            emit(op_select);
            return false;
        }
        case 0x1C: { // select t
            if (r_.u32() != 1) {
                r_.fail(Errc::malformed, "select arity");
                return false;
            }
            const std::uint8_t t = value_type(r_);
            pop(type_i32);
            pop(t);
            pop(t);
            push(t);
            emit(op_select);
            return false;
        }
        case 0x20:   // local.get
        case 0x21:   // local.set
        case 0x22: { // local.tee
            const std::uint32_t idx = r_.u32();
            const std::uint8_t t = local(idx);
            if (op != 0x20) {
                pop(t);
            }
            if (op != 0x21) {
                push(t);
            }
            emit(op).a = idx;
            return false;
        }
        case 0x23:   // global.get
        case 0x24: { // global.set
            const std::uint32_t idx = r_.u32();
            const Global* g = global(idx);
            if (g == nullptr) {
                return false;
            }
            if (op == 0x23) {
                push(g->type);
            } else {
                if (!g->is_mutable) {
                    r_.fail(Errc::malformed, "global is immutable");
                    return false;
                }
                pop(g->type);
            }
            emit(op).a = idx;
            return false;
        }
        case 0x3F:   // memory.size
        case 0x40: { // memory.grow
            zero_byte();
            if (op == 0x40) {
                pop(type_i32);
            }
            push(type_i32);
            emit(op);
            return false;
        }
        case 0x41: // i32.const
            emit(op).b = static_cast<std::uint64_t>(r_.sleb(32)) & mask32;
            push(type_i32);
            return false;
        case 0x42: // i64.const
            emit(op).b = static_cast<std::uint64_t>(r_.sleb(64));
            push(type_i64);
            return false;
        case 0xFC:
            return prefixed();
        default:
            break;
        }
        if (const std::uint32_t width = access_width(op); width != 0) {
            const std::uint32_t align = r_.u32();
            const std::uint32_t offset = r_.u32();
            if (r_.failed()) {
                return false;
            }
            if (align > static_cast<std::uint32_t>(std::countr_zero(width))) {
                r_.fail(Errc::malformed, "alignment too large");
                return false;
            }
            const bool is_store = op >= 0x36;
            // i64 loads are 0x29 and 0x30 to 0x35; i64 stores 0x37 and 0x3C to 0x3E.
            const bool is_i64 =
                op == 0x29 || (op >= 0x30 && op <= 0x35) || op == 0x37 || op >= 0x3C;
            const std::uint8_t t = is_i64 ? type_i64 : type_i32;
            if (is_store) {
                pop(t);
                pop(type_i32);
            } else {
                pop(type_i32);
                push(t);
            }
            emit(op).b = offset;
            return false;
        }
        if (const NumericType n = numeric_type(op); n.pops != 0) {
            for (unsigned i = 0; i < n.pops; ++i) {
                pop(n.in);
            }
            push(n.out);
            emit(op);
            return false;
        }
        r_.fail(Errc::unsupported, "instruction outside the profile");
        return false;
    }

    bool prefixed() {
        const std::uint32_t sub = r_.u32();
        if (r_.failed()) {
            return false;
        }
        switch (sub) {
        case 8: { // memory.init
            const std::uint32_t idx = r_.u32();
            zero_byte();
            if (r_.failed()) {
                return false;
            }
            data_index(idx);
            pop3_i32();
            emit(op_memory_init).a = idx;
            return false;
        }
        case 9: { // data.drop
            const std::uint32_t idx = r_.u32();
            if (r_.failed()) {
                return false;
            }
            data_index(idx);
            emit(op_data_drop).a = idx;
            return false;
        }
        case 10: // memory.copy
            zero_byte();
            zero_byte();
            pop3_i32();
            emit(op_memory_copy);
            return false;
        case 11: // memory.fill
            zero_byte();
            pop3_i32();
            emit(op_memory_fill);
            return false;
        default:
            r_.fail(Errc::unsupported, "instruction outside the profile");
            return false;
        }
    }

    const ModuleData& m_;
    Function& f_;
    Reader r_;
    std::vector<std::uint8_t> vals_;
    std::vector<Ctrl> ctrls_;
    std::size_t max_height_ = 0;
};

struct Body {
    std::vector<std::uint8_t> locals;
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct Export {
    std::uint8_t kind = 0;
    std::uint32_t index = 0;
};

/// Decodes the sections into `m`, checking each against the profile.
class Loader {
public:
    explicit Loader(ModuleData& m) : m_(m) {}

    Status run() {
        const ByteView wasm = m_.bytes;
        if (wasm.size() > max_module_size) {
            return fail(Errc::unsupported, "module too large");
        }
        static constexpr std::array<std::uint8_t, 8> header{0x00, 0x61, 0x73, 0x6D,
                                                            0x01, 0x00, 0x00, 0x00};
        if (wasm.size() < header.size() || !std::ranges::equal(wasm.first(8), header)) {
            return fail(Errc::malformed, "not a WebAssembly 1 module");
        }
        // Section ids in their required order: the data count section (12)
        // comes before the code section (10).
        static constexpr std::array<std::uint8_t, 12> order{1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 10, 11};
        std::ptrdiff_t last = -1;
        Reader r(wasm, header.size(), wasm.size());
        while (!r.done()) {
            const std::uint8_t id = r.byte();
            const std::uint32_t size = r.u32();
            if (r.failed()) {
                return r.status();
            }
            if (size > r.remaining()) {
                return fail(Errc::malformed, "section size");
            }
            Reader s(wasm, r.pos(), r.pos() + size);
            r.seek(r.pos() + size);
            if (id == 0) {
                s.name();
                if (s.failed()) {
                    return s.status();
                }
                continue;
            }
            const auto it = std::ranges::find(order, id);
            if (it == order.end()) {
                return fail(Errc::malformed, "unknown section");
            }
            const std::ptrdiff_t rank = it - order.begin();
            if (rank <= last) {
                return fail(Errc::malformed, "section out of order or repeated");
            }
            last = rank;
            section(id, s);
            if (s.failed()) {
                return s.status();
            }
            if (!s.done()) {
                return fail(Errc::malformed, "section size");
            }
        }
        return finish();
    }

private:
    void section(std::uint8_t id, Reader& s) {
        switch (id) {
        case 1:
            types(s);
            return;
        case 2:
            imports(s);
            return;
        case 3:
            functions(s);
            return;
        case 4:
            tables(s);
            return;
        case 5:
            memories(s);
            return;
        case 6:
            globals(s);
            return;
        case 7:
            exports(s);
            return;
        case 8:
            s.fail(Errc::unsupported, "start function");
            return;
        case 9:
            elements(s);
            return;
        case 12:
            m_.data_count = s.u32();
            return;
        case 10:
            code(s);
            return;
        case 11:
            data(s);
            return;
        default:
            return;
        }
    }

    void types(Reader& s) {
        const std::uint32_t n = s.u32();
        if (n > max_types) {
            s.fail(Errc::unsupported, "too many types");
            return;
        }
        if (!s.fits(n)) {
            return;
        }
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            if (s.byte() != 0x60) {
                s.fail(Errc::malformed, "type outside the profile");
                return;
            }
            FuncType t;
            value_types(s, t.params, max_params);
            value_types(s, t.results, max_results);
            m_.types.push_back(std::move(t));
        }
    }

    void imports(Reader& s) {
        const std::uint32_t n = s.u32();
        if (!s.fits(n)) {
            return;
        }
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            const std::string_view module = s.name();
            const std::string_view field = s.name();
            const std::uint8_t kind = s.byte();
            const std::uint32_t type = s.u32();
            if (s.failed()) {
                return;
            }
            if (kind != 0x00) {
                s.fail(Errc::unsupported, "only function imports");
                return;
            }
            const auto spec = std::ranges::find(host_functions, field, &HostSpec::name);
            if (module != "cexchain" || spec == host_functions.end()) {
                s.fail(Errc::unsupported, "unknown import");
                return;
            }
            if (type >= m_.types.size() || !matches(m_.types[type], *spec)) {
                s.fail(Errc::unsupported, "import type mismatch");
                return;
            }
            if (std::ranges::contains(m_.functions, spec->host, &Function::host)) {
                s.fail(Errc::unsupported, "repeated import");
                return;
            }
            Function f;
            f.type = type;
            f.host = spec->host;
            m_.functions.push_back(std::move(f));
        }
        m_.imports = static_cast<std::uint32_t>(m_.functions.size());
    }

    void functions(Reader& s) {
        const std::uint32_t n = s.u32();
        if (!s.fits(n)) {
            return;
        }
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            const std::uint32_t t = s.u32();
            if (!s.failed() && t >= m_.types.size()) {
                s.fail(Errc::malformed, "unknown type");
                return;
            }
            func_types_.push_back(t);
        }
        if (m_.imports + func_types_.size() > max_functions) {
            s.fail(Errc::unsupported, "too many functions");
        }
    }

    void tables(Reader& s) {
        const std::uint32_t n = s.u32();
        if (n > 1) {
            s.fail(Errc::unsupported, "at most one table");
            return;
        }
        if (n == 1) {
            if (s.byte() != 0x70) {
                s.fail(Errc::unsupported, "table type outside the profile");
                return;
            }
            m_.table = limits(s, max_table);
        }
    }

    void memories(Reader& s) {
        const std::uint32_t n = s.u32();
        if (n > 1) {
            s.fail(Errc::unsupported, "at most one memory");
            return;
        }
        if (n == 1) {
            m_.memory = limits(s, max_pages);
        }
    }

    void globals(Reader& s) {
        const std::uint32_t n = s.u32();
        if (n > max_globals) {
            s.fail(Errc::unsupported, "too many globals");
            return;
        }
        if (!s.fits(n)) {
            return;
        }
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            Global g;
            g.type = value_type(s);
            const std::uint8_t mut = s.byte();
            if (!s.failed() && mut > 1) {
                s.fail(Errc::malformed, "malformed mutability");
                return;
            }
            g.is_mutable = mut == 1;
            g.init = const_expr(s, g.type);
            m_.globals.push_back(g);
        }
    }

    void exports(Reader& s) {
        const std::uint32_t n = s.u32();
        if (!s.fits(n)) {
            return;
        }
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            const std::string_view name = s.name();
            const std::uint8_t kind = s.byte();
            const std::uint32_t index = s.u32();
            if (s.failed()) {
                return;
            }
            if (exports_.contains(name)) {
                s.fail(Errc::malformed, "duplicate export");
                return;
            }
            if (kind > 3) {
                s.fail(Errc::malformed, "unknown export kind");
                return;
            }
            exports_.emplace(name, Export{kind, index});
        }
    }

    void elements(Reader& s) {
        const std::uint32_t n = s.u32();
        if (!s.fits(n)) {
            return;
        }
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            if (s.u32() != 0) {
                s.fail(Errc::unsupported, "element segment outside the profile");
                return;
            }
            ElemSegment e;
            e.offset = static_cast<std::uint32_t>(const_expr(s, type_i32));
            const std::uint32_t count = s.u32();
            if (!s.fits(count)) {
                return;
            }
            e.functions.reserve(count);
            for (std::uint32_t k = 0; k < count; ++k) {
                e.functions.push_back(s.u32());
            }
            m_.elems.push_back(std::move(e));
        }
    }

    void code(Reader& s) {
        const std::uint32_t n = s.u32();
        if (!s.failed() && n != func_types_.size()) {
            s.fail(Errc::malformed, "function and code counts differ");
            return;
        }
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            const std::uint32_t size = s.u32();
            if (s.failed()) {
                return;
            }
            if (size > max_body_size) {
                s.fail(Errc::unsupported, "function body too large");
                return;
            }
            if (size > s.remaining()) {
                s.fail(Errc::malformed, "unexpected end");
                return;
            }
            Reader b(m_.bytes, s.pos(), s.pos() + size);
            s.seek(s.pos() + size);
            Body body;
            const std::uint32_t groups = b.u32();
            if (!b.fits(groups)) {
                s.fail(b.error());
                return;
            }
            for (std::uint32_t g = 0; g < groups && !b.failed(); ++g) {
                const std::uint32_t count = b.u32();
                const std::uint8_t t = value_type(b);
                if (b.failed()) {
                    break;
                }
                if (body.locals.size() + count > max_locals) {
                    b.fail(Errc::unsupported, "too many locals");
                    break;
                }
                body.locals.insert(body.locals.end(), count, t);
            }
            if (b.failed()) {
                s.fail(b.error());
                return;
            }
            body.begin = b.pos();
            body.end = b.end();
            bodies_.push_back(std::move(body));
        }
    }

    void data(Reader& s) {
        const std::uint32_t n = s.u32();
        if (!s.failed() && m_.data_count && n != *m_.data_count) {
            s.fail(Errc::malformed, "data count mismatch");
            return;
        }
        if (!s.fits(n)) {
            return;
        }
        std::uint64_t total = 0;
        for (std::uint32_t i = 0; i < n && !s.failed(); ++i) {
            DataSegment d;
            const std::uint32_t flag = s.u32();
            if (flag == 0) {
                d.offset = static_cast<std::uint32_t>(const_expr(s, type_i32));
            } else if (flag != 1) {
                s.fail(Errc::unsupported, "data segment outside the profile");
                return;
            }
            const std::uint32_t size = s.u32();
            d.begin = static_cast<std::uint32_t>(s.pos());
            s.bytes(size);
            d.size = size;
            total += size;
            m_.data.push_back(d);
        }
        if (total > max_data) {
            s.fail(Errc::unsupported, "too much data");
        }
    }

    [[nodiscard]] std::optional<Export> find_export(std::string_view name) const {
        const auto it = exports_.find(name);
        if (it == exports_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    Status finish() {
        if (bodies_.size() != func_types_.size()) {
            return fail(Errc::malformed, "function and code counts differ");
        }
        if (m_.data_count && *m_.data_count != m_.data.size()) {
            return fail(Errc::malformed, "data count mismatch");
        }
        for (std::size_t i = 0; i < bodies_.size(); ++i) {
            Function f;
            f.type = func_types_[i];
            const auto& params = m_.types[f.type].params;
            if (params.size() + bodies_[i].locals.size() > max_locals) {
                return fail(Errc::unsupported, "too many locals");
            }
            f.locals = params;
            f.locals.insert(f.locals.end(), bodies_[i].locals.begin(), bodies_[i].locals.end());
            m_.functions.push_back(std::move(f));
        }

        const auto memory = find_export("memory");
        if (!memory || memory->kind != 2 || !m_.memory) {
            return fail(Errc::unsupported, "must export its memory as \"memory\"");
        }
        const auto entry = find_export("cexchain_call");
        if (!entry || entry->kind != 0 || entry->index >= m_.functions.size() ||
            entry->index < m_.imports) {
            return fail(Errc::unsupported, "must export a function \"cexchain_call\"");
        }
        const FuncType& entry_type = m_.types[m_.functions[entry->index].type];
        if (!entry_type.params.empty() || !entry_type.results.empty()) {
            return fail(Errc::unsupported, "cexchain_call must take and return nothing");
        }
        m_.entry = entry->index;
        for (const auto& [name, e] : exports_) {
            const bool known = (e.kind == 0 && e.index < m_.functions.size()) ||
                               (e.kind == 1 && m_.table && e.index == 0) ||
                               (e.kind == 2 && e.index == 0) ||
                               (e.kind == 3 && e.index < m_.globals.size());
            if (!known) {
                return fail(Errc::malformed, "export of an unknown item");
            }
        }
        for (const ElemSegment& e : m_.elems) {
            if (!m_.table || std::uint64_t{e.offset} + e.functions.size() > m_.table->min) {
                return fail(Errc::unsupported, "element segment out of bounds");
            }
            for (const std::uint32_t fi : e.functions) {
                if (fi >= m_.functions.size()) {
                    return fail(Errc::malformed, "unknown function");
                }
            }
        }
        for (const DataSegment& d : m_.data) {
            if (d.offset &&
                std::uint64_t{*d.offset} + d.size > std::uint64_t{m_.memory->min} * page_size) {
                return fail(Errc::unsupported, "data segment out of bounds");
            }
        }

        for (std::size_t i = 0; i < bodies_.size(); ++i) {
            Function& f = m_.functions[m_.imports + i];
            Translator t(m_, f, Reader(m_.bytes, bodies_[i].begin, bodies_[i].end));
            if (auto status = t.run(); !status) {
                return status;
            }
        }

        m_.type_ids.resize(m_.types.size());
        for (std::size_t i = 0; i < m_.types.size(); ++i) {
            std::size_t first = 0;
            while (!(m_.types[first] == m_.types[i])) {
                ++first;
            }
            m_.type_ids[i] = static_cast<std::uint32_t>(first);
        }
        if (m_.table) {
            m_.table_functions.assign(m_.table->min, null_function);
            for (const ElemSegment& e : m_.elems) {
                std::ranges::copy(e.functions, m_.table_functions.begin() +
                                                   static_cast<std::ptrdiff_t>(e.offset));
            }
        }
        return {};
    }

    ModuleData& m_;
    std::vector<std::uint32_t> func_types_;
    std::vector<Body> bodies_;
    std::map<std::string_view, Export> exports_;
};

} // namespace

} // namespace detail

ByteView Module::bytes() const noexcept {
    return data_->bytes;
}

Result<Module> load(ByteView wasm) {
    auto data = std::make_shared<detail::ModuleData>();
    data->bytes.assign(wasm.begin(), wasm.end());
    if (auto status = detail::Loader(*data).run(); !status) {
        return std::unexpected(status.error());
    }
    return Module(std::move(data));
}

} // namespace cexchain::vm
