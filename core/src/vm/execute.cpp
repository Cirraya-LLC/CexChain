// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include <cexchain/core/vm.hpp>

#include "internal.hpp"

namespace cexchain::vm {

std::string_view name(Trap trap) noexcept {
    switch (trap) {
    case Trap::unreachable:
        return "unreachable";
    case Trap::divide_by_zero:
        return "divide by zero";
    case Trap::integer_overflow:
        return "integer overflow";
    case Trap::out_of_bounds:
        return "out of bounds";
    case Trap::indirect_call_out_of_range:
        return "indirect call out of range";
    case Trap::indirect_call_to_null:
        return "indirect call to null";
    case Trap::indirect_call_type_mismatch:
        return "indirect call type mismatch";
    case Trap::out_of_fuel:
        return "out of fuel";
    case Trap::call_depth_exceeded:
        return "call depth exceeded";
    case Trap::stack_budget_exceeded:
        return "stack budget exceeded";
    case Trap::output_written_twice:
        return "output written twice";
    case Trap::output_too_large:
        return "output too large";
    case Trap::aborted:
        return "aborted";
    }
    return "unknown trap";
}

namespace {

using detail::Branch;
using detail::Function;
using detail::Host;
using detail::Instr;
using detail::ModuleData;

constexpr std::uint64_t mask32 = 0xFFFF'FFFF;

/// Fuel charged before each translated operation runs (spec section 14.3).
/// The ones at 0 cost nothing (else, the function's end) or charge once they
/// know their size (memory.grow and the bulk memory operations).
constexpr auto base_costs = [] {
    std::array<std::uint8_t, detail::op_memory_fill + 1> costs{};
    costs.fill(1);
    costs[detail::op_else] = 0;
    costs[detail::op_end_function] = 0;
    costs[detail::op_call] = 2;
    costs[detail::op_call_indirect] = 2;
    costs[detail::op_memory_grow] = 0;
    costs[detail::op_memory_init] = 0;
    costs[detail::op_memory_copy] = 0;
    costs[detail::op_memory_fill] = 0;
    return costs;
}();

/// 1 per 64 bytes, rounded up.
constexpr std::uint64_t per64(std::uint64_t n) noexcept {
    return (n + 63) / 64;
}

constexpr std::uint32_t lo32(std::uint64_t v) noexcept {
    return static_cast<std::uint32_t>(v);
}

constexpr std::int32_t s32(std::uint64_t v) noexcept {
    return static_cast<std::int32_t>(static_cast<std::uint32_t>(v));
}

constexpr std::int64_t s64(std::uint64_t v) noexcept {
    return static_cast<std::int64_t>(v);
}

/// An i32 result, kept zero-extended in its 64-bit slot.
constexpr std::uint64_t i32(std::uint32_t v) noexcept {
    return v;
}

constexpr std::uint64_t i32(std::int32_t v) noexcept {
    return static_cast<std::uint32_t>(v);
}

constexpr std::uint64_t i64(std::int64_t v) noexcept {
    return static_cast<std::uint64_t>(v);
}

constexpr std::uint64_t flag(bool b) noexcept {
    return b ? 1 : 0;
}

template <unsigned N>
std::uint64_t load_le(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < N; ++i) {
        v |= std::uint64_t{p[i]} << (8 * i);
    }
    return v;
}

template <unsigned N>
void store_le(std::uint8_t* p, std::uint64_t v) noexcept {
    for (unsigned i = 0; i < N; ++i) {
        p[i] = static_cast<std::uint8_t>(v >> (8 * i));
    }
}

struct Frame {
    const Function* function = nullptr;
    /// Where the function continues after a call returns.
    std::uint32_t pc = 0;
    /// Its locals, parameters first; its results go here on return.
    std::uint64_t* locals = nullptr;
    /// The bottom of its operand stack.
    std::uint64_t* base = nullptr;
    /// Its share of the stack budget: locals and maximum operand stack height.
    std::uint32_t slots = 0;
};

/// One invocation of cexchain_call. Traps are returned, not thrown.
class Machine {
public:
    Machine(const ModuleData& m, ByteView input, const crypto::Provider& provider,
            crypto::HashAlg hash, std::uint64_t fuel)
        : m_(m), input_(input), provider_(provider), hash_(hash), fuel_limit_(fuel), fuel_(fuel),
          globals_(m.globals.size()), stack_(stack_budget) {
        const detail::Limits limits = *m.memory;
        memory_.resize(std::size_t{limits.max} * page_size);
        memory_size_ = std::uint64_t{limits.min} * page_size;
        max_pages_ = limits.max;
        for (std::size_t i = 0; i < m.globals.size(); ++i) {
            globals_[i] = m.globals[i].init;
        }
        // Active segments are copied in, then dropped; passive ones stay.
        segments_.reserve(m.data.size());
        for (const detail::DataSegment& d : m.data) {
            const ByteView bytes = ByteView(m.bytes).subspan(d.begin, d.size);
            if (d.offset) {
                std::ranges::copy(bytes, memory_.begin() + *d.offset);
                segments_.emplace_back();
            } else {
                segments_.push_back(bytes);
            }
        }
    }

    Result<Outcome> run() {
        Outcome out;
        const std::optional<Trap> trap = execute();
        if (error_) {
            return std::unexpected(*error_);
        }
        out.fuel_used = fuel_limit_ - fuel_;
        out.trap = trap;
        if (!trap) {
            out.output = std::move(output_).value_or(Bytes{});
        } else if (*trap == Trap::aborted) {
            out.abort_reason = std::move(abort_reason_);
        }
        return out;
    }

private:
    bool charge(std::uint64_t cost) noexcept {
        if (cost > fuel_) {
            fuel_ = 0;
            return false;
        }
        fuel_ -= cost;
        return true;
    }

    [[nodiscard]] bool in_bounds(std::uint64_t addr, std::uint64_t n) const noexcept {
        return addr + n <= memory_size_;
    }

    /// Enters a function whose arguments are on top of the operand stack.
    std::optional<Trap> enter(const Function& f) {
        if (depth_ + 1 > max_call_depth) {
            return Trap::call_depth_exceeded;
        }
        const auto slots = static_cast<std::uint32_t>(f.locals.size() + f.max_height);
        if (budget_ + slots > stack_budget) {
            return Trap::stack_budget_exceeded;
        }
        const std::size_t params = m_.types[f.type].params.size();
        std::uint64_t* locals = sp_ - params;
        std::uint64_t* base = locals + f.locals.size();
        std::fill(sp_, base, std::uint64_t{0});
        frames_[depth_++] = Frame{&f, 0, locals, base, slots};
        budget_ += slots;
        sp_ = base;
        return std::nullopt;
    }

    std::optional<Trap> call_host(Host host) {
        switch (host) {
        case Host::input_size:
            if (!charge(1)) {
                return Trap::out_of_fuel;
            }
            *sp_++ = input_.size();
            return std::nullopt;
        case Host::input_read: {
            const std::uint64_t ptr = *--sp_;
            if (!charge(1 + per64(input_.size()))) {
                return Trap::out_of_fuel;
            }
            if (!in_bounds(ptr, input_.size())) {
                return Trap::out_of_bounds;
            }
            std::ranges::copy(input_, memory_.begin() + static_cast<std::ptrdiff_t>(ptr));
            return std::nullopt;
        }
        case Host::output_write: {
            const std::uint64_t n = *--sp_;
            const std::uint64_t ptr = *--sp_;
            if (!charge(1 + per64(n))) {
                return Trap::out_of_fuel;
            }
            if (output_) {
                return Trap::output_written_twice;
            }
            if (n > max_output) {
                return Trap::output_too_large;
            }
            if (!in_bounds(ptr, n)) {
                return Trap::out_of_bounds;
            }
            output_ = Bytes(memory_.begin() + static_cast<std::ptrdiff_t>(ptr),
                            memory_.begin() + static_cast<std::ptrdiff_t>(ptr + n));
            return std::nullopt;
        }
        case Host::hash: {
            const std::uint64_t out = *--sp_;
            const std::uint64_t n = *--sp_;
            const std::uint64_t ptr = *--sp_;
            if (!charge(64 + per64(n))) {
                return Trap::out_of_fuel;
            }
            if (!in_bounds(ptr, n) || !in_bounds(out, 32)) {
                return Trap::out_of_bounds;
            }
            const auto digest =
                provider_.digest(hash_, ByteView(memory_).subspan(static_cast<std::size_t>(ptr),
                                                                  static_cast<std::size_t>(n)));
            if (!digest) {
                error_ = digest.error();
                return Trap::aborted;
            }
            std::ranges::copy(digest->bytes(), memory_.begin() + static_cast<std::ptrdiff_t>(out));
            return std::nullopt;
        }
        case Host::abort: {
            const std::uint64_t n = std::min<std::uint64_t>(*--sp_, max_abort_reason);
            const std::uint64_t ptr = *--sp_;
            if (!charge(1)) {
                return Trap::out_of_fuel;
            }
            if (!in_bounds(ptr, n)) {
                return Trap::out_of_bounds;
            }
            abort_reason_.assign(memory_.begin() + static_cast<std::ptrdiff_t>(ptr),
                                 memory_.begin() + static_cast<std::ptrdiff_t>(ptr + n));
            return Trap::aborted;
        }
        case Host::none:
            break;
        }
        return Trap::unreachable;
    }

    /// Calls function `index`: a host function at once, or by entering it.
    std::optional<Trap> call(std::uint32_t index) {
        const Function& f = m_.functions[index];
        if (f.host != Host::none) {
            return call_host(f.host);
        }
        frames_[depth_ - 1].pc = pc_;
        if (auto trap = enter(f)) {
            return trap;
        }
        code_ = f.code.data();
        pc_ = 0;
        return std::nullopt;
    }

    void branch(std::uint32_t target, std::uint32_t arity, std::uint64_t height) noexcept {
        std::uint64_t* dest = frames_[depth_ - 1].base + height;
        std::uint64_t* src = sp_ - arity;
        if (dest != src) {
            for (std::uint32_t i = 0; i < arity; ++i) {
                dest[i] = src[i];
            }
        }
        sp_ = dest + arity;
        pc_ = target;
    }

    /// Returns from the current function; false when it was the entry.
    bool leave(std::uint32_t arity) noexcept {
        Frame& frame = frames_[depth_ - 1];
        std::uint64_t* src = sp_ - arity;
        for (std::uint32_t i = 0; i < arity; ++i) {
            frame.locals[i] = src[i];
        }
        sp_ = frame.locals + arity;
        budget_ -= frame.slots;
        if (--depth_ == 0) {
            return false;
        }
        const Frame& caller = frames_[depth_ - 1];
        code_ = caller.function->code.data();
        pc_ = caller.pc;
        return true;
    }

    std::optional<Trap> execute();

    const ModuleData& m_;
    ByteView input_;
    const crypto::Provider& provider_;
    crypto::HashAlg hash_;

    std::uint64_t fuel_limit_;
    std::uint64_t fuel_;
    std::vector<std::uint8_t> memory_;
    std::uint64_t memory_size_ = 0;
    std::uint32_t max_pages_ = 0;
    std::vector<std::uint64_t> globals_;
    std::vector<ByteView> segments_;

    std::vector<std::uint64_t> stack_;
    std::uint64_t* sp_ = nullptr;
    std::array<Frame, max_call_depth> frames_{};
    std::uint32_t depth_ = 0;
    std::uint32_t budget_ = 0;
    const Instr* code_ = nullptr;
    std::uint32_t pc_ = 0;

    std::optional<Bytes> output_;
    Bytes abort_reason_;
    std::optional<Error> error_;
};

std::optional<Trap> Machine::execute() {
    sp_ = stack_.data();
    const Function& entry = m_.functions[m_.entry];
    if (auto trap = enter(entry)) {
        return trap;
    }
    code_ = entry.code.data();
    pc_ = 0;

    for (;;) {
        const Instr& in = code_[pc_++];
        if (!charge(base_costs[in.op])) {
            return Trap::out_of_fuel;
        }
        std::uint64_t* const sp = sp_;
        switch (in.op) {
        case detail::op_unreachable:
            return Trap::unreachable;
        case detail::op_nop:
            break;
        case detail::op_if:
            sp_ = sp - 1;
            if (sp[-1] == 0) {
                pc_ = in.a;
            }
            break;
        case detail::op_else:
            pc_ = in.a;
            break;
        case detail::op_br:
            branch(in.a, in.arity, in.b);
            break;
        case detail::op_br_if:
            sp_ = sp - 1;
            if (sp[-1] != 0) {
                branch(in.a, in.arity, in.b);
            }
            break;
        case detail::op_br_table: {
            sp_ = sp - 1;
            const std::uint64_t i = sp[-1];
            const Branch& e = frames_[depth_ - 1].function->branches[in.a + std::min(i, in.b)];
            branch(e.target, e.arity, e.height);
            break;
        }
        case detail::op_return:
        case detail::op_end_function:
            if (!leave(in.arity)) {
                return std::nullopt;
            }
            break;
        case detail::op_call:
            if (auto trap = call(in.a)) {
                return trap;
            }
            break;
        case detail::op_call_indirect: {
            sp_ = sp - 1;
            const std::uint64_t i = sp[-1];
            if (i >= m_.table_functions.size()) {
                return Trap::indirect_call_out_of_range;
            }
            const std::uint32_t fi = m_.table_functions[static_cast<std::size_t>(i)];
            if (fi == detail::null_function) {
                return Trap::indirect_call_to_null;
            }
            if (m_.type_ids[m_.functions[fi].type] != m_.type_ids[in.a]) {
                return Trap::indirect_call_type_mismatch;
            }
            if (auto trap = call(fi)) {
                return trap;
            }
            break;
        }
        case detail::op_drop:
            sp_ = sp - 1;
            break;
        case detail::op_select:
            sp_ = sp - 2;
            if (sp[-1] == 0) {
                sp[-3] = sp[-2];
            }
            break;
        case detail::op_local_get:
            *sp = frames_[depth_ - 1].locals[in.a];
            sp_ = sp + 1;
            break;
        case detail::op_local_set:
            frames_[depth_ - 1].locals[in.a] = sp[-1];
            sp_ = sp - 1;
            break;
        case detail::op_local_tee:
            frames_[depth_ - 1].locals[in.a] = sp[-1];
            break;
        case detail::op_global_get:
            *sp = globals_[in.a];
            sp_ = sp + 1;
            break;
        case detail::op_global_set:
            globals_[in.a] = sp[-1];
            sp_ = sp - 1;
            break;

            // Loads: the address is replaced by the value.
#define CEXCHAIN_VM_LOAD(opcode, width, convert)                                                   \
    case opcode: {                                                                                 \
        const std::uint64_t addr = sp[-1] + in.b;                                                  \
        if (!in_bounds(addr, width)) {                                                             \
            return Trap::out_of_bounds;                                                            \
        }                                                                                          \
        const std::uint64_t raw = load_le<width>(memory_.data() + addr);                           \
        sp[-1] = convert;                                                                          \
        break;                                                                                     \
    }
            CEXCHAIN_VM_LOAD(0x28, 4, raw) // i32.load
            CEXCHAIN_VM_LOAD(0x29, 8, raw) // i64.load
            CEXCHAIN_VM_LOAD(0x2C, 1,
                             i32(std::int32_t{static_cast<std::int8_t>(raw)})) // i32.load8_s
            CEXCHAIN_VM_LOAD(0x2D, 1, raw)                                     // i32.load8_u
            CEXCHAIN_VM_LOAD(0x2E, 2,
                             i32(std::int32_t{static_cast<std::int16_t>(raw)})) // i32.load16_s
            CEXCHAIN_VM_LOAD(0x2F, 2, raw)                                      // i32.load16_u
            CEXCHAIN_VM_LOAD(0x30, 1, i64(static_cast<std::int8_t>(raw)))       // i64.load8_s
            CEXCHAIN_VM_LOAD(0x31, 1, raw)                                      // i64.load8_u
            CEXCHAIN_VM_LOAD(0x32, 2, i64(static_cast<std::int16_t>(raw)))      // i64.load16_s
            CEXCHAIN_VM_LOAD(0x33, 2, raw)                                      // i64.load16_u
            CEXCHAIN_VM_LOAD(0x34, 4, i64(static_cast<std::int32_t>(raw)))      // i64.load32_s
            CEXCHAIN_VM_LOAD(0x35, 4, raw)                                      // i64.load32_u
#undef CEXCHAIN_VM_LOAD

            // Stores: address and value are popped.
#define CEXCHAIN_VM_STORE(opcode, width)                                                           \
    case opcode: {                                                                                 \
        const std::uint64_t addr = sp[-2] + in.b;                                                  \
        if (!in_bounds(addr, width)) {                                                             \
            return Trap::out_of_bounds;                                                            \
        }                                                                                          \
        store_le<width>(memory_.data() + addr, sp[-1]);                                            \
        sp_ = sp - 2;                                                                              \
        break;                                                                                     \
    }
            CEXCHAIN_VM_STORE(0x36, 4) // i32.store
            CEXCHAIN_VM_STORE(0x37, 8) // i64.store
            CEXCHAIN_VM_STORE(0x3A, 1) // i32.store8
            CEXCHAIN_VM_STORE(0x3B, 2) // i32.store16
            CEXCHAIN_VM_STORE(0x3C, 1) // i64.store8
            CEXCHAIN_VM_STORE(0x3D, 2) // i64.store16
            CEXCHAIN_VM_STORE(0x3E, 4) // i64.store32
#undef CEXCHAIN_VM_STORE

        case detail::op_memory_size:
            *sp = memory_size_ / page_size;
            sp_ = sp + 1;
            break;
        case detail::op_memory_grow: {
            const std::uint64_t delta = sp[-1];
            const std::uint64_t pages = memory_size_ / page_size;
            if (pages + delta > max_pages_) {
                if (!charge(1)) {
                    return Trap::out_of_fuel;
                }
                sp[-1] = mask32;
            } else {
                if (!charge(1 + 1024 * delta)) {
                    return Trap::out_of_fuel;
                }
                memory_size_ += delta * page_size;
                sp[-1] = pages;
            }
            break;
        }
        case detail::op_i32_const:
        case detail::op_i64_const:
            *sp = in.b;
            sp_ = sp + 1;
            break;

        // i32 comparisons.
        case 0x45: // eqz
            sp[-1] = flag(lo32(sp[-1]) == 0);
            break;
#define CEXCHAIN_VM_BINARY(opcode, expr)                                                           \
    case opcode: {                                                                                 \
        const std::uint64_t a = sp[-2];                                                            \
        const std::uint64_t b = sp[-1];                                                            \
        sp[-2] = (expr);                                                                           \
        sp_ = sp - 1;                                                                              \
        break;                                                                                     \
    }
            CEXCHAIN_VM_BINARY(0x46, flag(lo32(a) == lo32(b))) // eq
            CEXCHAIN_VM_BINARY(0x47, flag(lo32(a) != lo32(b))) // ne
            CEXCHAIN_VM_BINARY(0x48, flag(s32(a) < s32(b)))    // lt_s
            CEXCHAIN_VM_BINARY(0x49, flag(lo32(a) < lo32(b)))  // lt_u
            CEXCHAIN_VM_BINARY(0x4A, flag(s32(a) > s32(b)))    // gt_s
            CEXCHAIN_VM_BINARY(0x4B, flag(lo32(a) > lo32(b)))  // gt_u
            CEXCHAIN_VM_BINARY(0x4C, flag(s32(a) <= s32(b)))   // le_s
            CEXCHAIN_VM_BINARY(0x4D, flag(lo32(a) <= lo32(b))) // le_u
            CEXCHAIN_VM_BINARY(0x4E, flag(s32(a) >= s32(b)))   // ge_s
            CEXCHAIN_VM_BINARY(0x4F, flag(lo32(a) >= lo32(b))) // ge_u

        // i64 comparisons.
        case 0x50: // eqz
            sp[-1] = flag(sp[-1] == 0);
            break;
            CEXCHAIN_VM_BINARY(0x51, flag(a == b))           // eq
            CEXCHAIN_VM_BINARY(0x52, flag(a != b))           // ne
            CEXCHAIN_VM_BINARY(0x53, flag(s64(a) < s64(b)))  // lt_s
            CEXCHAIN_VM_BINARY(0x54, flag(a < b))            // lt_u
            CEXCHAIN_VM_BINARY(0x55, flag(s64(a) > s64(b)))  // gt_s
            CEXCHAIN_VM_BINARY(0x56, flag(a > b))            // gt_u
            CEXCHAIN_VM_BINARY(0x57, flag(s64(a) <= s64(b))) // le_s
            CEXCHAIN_VM_BINARY(0x58, flag(a <= b))           // le_u
            CEXCHAIN_VM_BINARY(0x59, flag(s64(a) >= s64(b))) // ge_s
            CEXCHAIN_VM_BINARY(0x5A, flag(a >= b))           // ge_u

        // i32 arithmetic.
        case 0x67: // clz
            sp[-1] = static_cast<std::uint64_t>(std::countl_zero(lo32(sp[-1])));
            break;
        case 0x68: // ctz
            sp[-1] = static_cast<std::uint64_t>(std::countr_zero(lo32(sp[-1])));
            break;
        case 0x69: // popcnt
            sp[-1] = static_cast<std::uint64_t>(std::popcount(lo32(sp[-1])));
            break;
            CEXCHAIN_VM_BINARY(0x6A, i32(lo32(a + b)))                                   // add
            CEXCHAIN_VM_BINARY(0x6B, i32(lo32(a - b)))                                   // sub
            CEXCHAIN_VM_BINARY(0x6C, i32(lo32(a) * lo32(b)))                             // mul
            CEXCHAIN_VM_BINARY(0x71, i32(lo32(a) & lo32(b)))                             // and
            CEXCHAIN_VM_BINARY(0x72, i32(lo32(a) | lo32(b)))                             // or
            CEXCHAIN_VM_BINARY(0x73, i32(lo32(a) ^ lo32(b)))                             // xor
            CEXCHAIN_VM_BINARY(0x74, i32(lo32(a) << (b & 31U)))                          // shl
            CEXCHAIN_VM_BINARY(0x75, i32(s32(a) >> (b & 31U)))                           // shr_s
            CEXCHAIN_VM_BINARY(0x76, i32(lo32(a) >> (b & 31U)))                          // shr_u
            CEXCHAIN_VM_BINARY(0x77, i32(std::rotl(lo32(a), static_cast<int>(b & 31U)))) // rotl
            CEXCHAIN_VM_BINARY(0x78, i32(std::rotr(lo32(a), static_cast<int>(b & 31U)))) // rotr
        case 0x6D: {                                                                     // div_s
            const std::int32_t b = s32(sp[-1]);
            const std::int32_t a = s32(sp[-2]);
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            if (a == INT32_MIN && b == -1) {
                return Trap::integer_overflow;
            }
            sp[-2] = i32(a / b);
            sp_ = sp - 1;
            break;
        }
        case 0x6E: { // div_u
            const std::uint32_t b = lo32(sp[-1]);
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            sp[-2] = i32(lo32(sp[-2]) / b);
            sp_ = sp - 1;
            break;
        }
        case 0x6F: { // rem_s
            const std::int32_t b = s32(sp[-1]);
            const std::int32_t a = s32(sp[-2]);
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            sp[-2] = b == -1 ? std::uint64_t{0} : i32(a % b);
            sp_ = sp - 1;
            break;
        }
        case 0x70: { // rem_u
            const std::uint32_t b = lo32(sp[-1]);
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            sp[-2] = i32(lo32(sp[-2]) % b);
            sp_ = sp - 1;
            break;
        }

        // i64 arithmetic.
        case 0x79: // clz
            sp[-1] = static_cast<std::uint64_t>(std::countl_zero(sp[-1]));
            break;
        case 0x7A: // ctz
            sp[-1] = static_cast<std::uint64_t>(std::countr_zero(sp[-1]));
            break;
        case 0x7B: // popcnt
            sp[-1] = static_cast<std::uint64_t>(std::popcount(sp[-1]));
            break;
            CEXCHAIN_VM_BINARY(0x7C, a + b)                                   // add
            CEXCHAIN_VM_BINARY(0x7D, a - b)                                   // sub
            CEXCHAIN_VM_BINARY(0x7E, a * b)                                   // mul
            CEXCHAIN_VM_BINARY(0x83, a & b)                                   // and
            CEXCHAIN_VM_BINARY(0x84, a | b)                                   // or
            CEXCHAIN_VM_BINARY(0x85, a ^ b)                                   // xor
            CEXCHAIN_VM_BINARY(0x86, a << (b & 63U))                          // shl
            CEXCHAIN_VM_BINARY(0x87, i64(s64(a) >> (b & 63U)))                // shr_s
            CEXCHAIN_VM_BINARY(0x88, a >> (b & 63U))                          // shr_u
            CEXCHAIN_VM_BINARY(0x89, std::rotl(a, static_cast<int>(b & 63U))) // rotl
            CEXCHAIN_VM_BINARY(0x8A, std::rotr(a, static_cast<int>(b & 63U))) // rotr
#undef CEXCHAIN_VM_BINARY
        case 0x7F: { // div_s
            const std::int64_t b = s64(sp[-1]);
            const std::int64_t a = s64(sp[-2]);
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            if (a == INT64_MIN && b == -1) {
                return Trap::integer_overflow;
            }
            sp[-2] = i64(a / b);
            sp_ = sp - 1;
            break;
        }
        case 0x80: { // div_u
            const std::uint64_t b = sp[-1];
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            sp[-2] /= b;
            sp_ = sp - 1;
            break;
        }
        case 0x81: { // rem_s
            const std::int64_t b = s64(sp[-1]);
            const std::int64_t a = s64(sp[-2]);
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            sp[-2] = b == -1 ? std::uint64_t{0} : i64(a % b);
            sp_ = sp - 1;
            break;
        }
        case 0x82: { // rem_u
            const std::uint64_t b = sp[-1];
            if (b == 0) {
                return Trap::divide_by_zero;
            }
            sp[-2] %= b;
            sp_ = sp - 1;
            break;
        }

        // Conversions and sign extension.
        case 0xA7: // i32.wrap_i64
            sp[-1] &= mask32;
            break;
        case 0xAC: // i64.extend_i32_s
            sp[-1] = i64(s32(sp[-1]));
            break;
        case 0xAD: // i64.extend_i32_u
            sp[-1] &= mask32;
            break;
        case 0xC0: // i32.extend8_s
            sp[-1] = i32(std::int32_t{static_cast<std::int8_t>(sp[-1])});
            break;
        case 0xC1: // i32.extend16_s
            sp[-1] = i32(std::int32_t{static_cast<std::int16_t>(sp[-1])});
            break;
        case 0xC2: // i64.extend8_s
            sp[-1] = i64(static_cast<std::int8_t>(sp[-1]));
            break;
        case 0xC3: // i64.extend16_s
            sp[-1] = i64(static_cast<std::int16_t>(sp[-1]));
            break;
        case 0xC4: // i64.extend32_s
            sp[-1] = i64(static_cast<std::int32_t>(sp[-1]));
            break;

        // Bulk memory: charged by size once the operands are known.
        case detail::op_memory_init: {
            const std::uint64_t n = sp[-1];
            const std::uint64_t s = sp[-2];
            const std::uint64_t d = sp[-3];
            sp_ = sp - 3;
            if (!charge(1 + per64(n))) {
                return Trap::out_of_fuel;
            }
            const ByteView segment = segments_[in.a];
            if (s + n > segment.size() || !in_bounds(d, n)) {
                return Trap::out_of_bounds;
            }
            std::ranges::copy(
                segment.subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(n)),
                memory_.begin() + static_cast<std::ptrdiff_t>(d));
            break;
        }
        case detail::op_data_drop:
            segments_[in.a] = {};
            break;
        case detail::op_memory_copy: {
            const std::uint64_t n = sp[-1];
            const std::uint64_t s = sp[-2];
            const std::uint64_t d = sp[-3];
            sp_ = sp - 3;
            if (!charge(1 + per64(n))) {
                return Trap::out_of_fuel;
            }
            if (!in_bounds(s, n) || !in_bounds(d, n)) {
                return Trap::out_of_bounds;
            }
            const auto first = memory_.begin() + static_cast<std::ptrdiff_t>(s);
            const auto last = first + static_cast<std::ptrdiff_t>(n);
            const auto dest = memory_.begin() + static_cast<std::ptrdiff_t>(d);
            if (d <= s) {
                std::copy(first, last, dest);
            } else {
                std::copy_backward(first, last, dest + static_cast<std::ptrdiff_t>(n));
            }
            break;
        }
        case detail::op_memory_fill: {
            const std::uint64_t n = sp[-1];
            const auto value = static_cast<std::uint8_t>(sp[-2]);
            const std::uint64_t d = sp[-3];
            sp_ = sp - 3;
            if (!charge(1 + per64(n))) {
                return Trap::out_of_fuel;
            }
            if (!in_bounds(d, n)) {
                return Trap::out_of_bounds;
            }
            std::fill_n(memory_.begin() + static_cast<std::ptrdiff_t>(d),
                        static_cast<std::ptrdiff_t>(n), value);
            break;
        }
        default:
            // Validation admits no other operation.
            return Trap::unreachable;
        }
    }
}

} // namespace

namespace detail {

Result<Outcome> run(const Module& module, ByteView input, const crypto::Provider& provider,
                    crypto::HashAlg hash, std::uint64_t fuel) {
    if (crypto::digest_size(hash) != 32) {
        return fail(Errc::unsupported, "contracts need a 32-byte ledger hash");
    }
    if (input.size() > 0xFFFF'FFFF) {
        return fail(Errc::invalid_argument, "contract input too large");
    }
    return Machine(module.data(), input, provider, hash, fuel).run();
}

} // namespace detail

Result<Outcome> run(const Module& module, ByteView input, const crypto::Provider& provider,
                    crypto::HashAlg hash) {
    return detail::run(module, input, provider, hash, fuel_limit);
}

} // namespace cexchain::vm
