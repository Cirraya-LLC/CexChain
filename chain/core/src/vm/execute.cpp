// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
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
using detail::charged;
using detail::Function;
using detail::Host;
using detail::Instr;
using detail::ModuleData;
using detail::Op;

constexpr std::uint64_t mask32 = 0xFFFF'FFFF;

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

/// A branch target: an offset from the branch's own instruction.
constexpr std::ptrdiff_t offset(std::uint32_t a) noexcept {
    return static_cast<std::int32_t>(a);
}

/// The value a load pushes, from the `raw` bytes it read (little-endian,
/// zero-extended).
template <Op O>
constexpr std::uint64_t loaded(std::uint64_t raw) noexcept {
    if constexpr (O == detail::op_i32_load8_s) {
        return i32(std::int32_t{static_cast<std::int8_t>(raw)});
    } else if constexpr (O == detail::op_i32_load16_s) {
        return i32(std::int32_t{static_cast<std::int16_t>(raw)});
    } else if constexpr (O == detail::op_i64_load8_s) {
        return i64(static_cast<std::int8_t>(raw));
    } else if constexpr (O == detail::op_i64_load16_s) {
        return i64(static_cast<std::int16_t>(raw));
    } else if constexpr (O == detail::op_i64_load32_s) {
        return i64(static_cast<std::int32_t>(raw));
    } else {
        return raw;
    }
}

template <Op O>
constexpr std::uint64_t unary(std::uint64_t v) noexcept {
    using namespace detail;
    if constexpr (O == op_i32_eqz) {
        return flag(lo32(v) == 0);
    } else if constexpr (O == op_i64_eqz) {
        return flag(v == 0);
    } else if constexpr (O == op_i32_clz) {
        return static_cast<std::uint64_t>(std::countl_zero(lo32(v)));
    } else if constexpr (O == op_i32_ctz) {
        return static_cast<std::uint64_t>(std::countr_zero(lo32(v)));
    } else if constexpr (O == op_i32_popcnt) {
        return static_cast<std::uint64_t>(std::popcount(lo32(v)));
    } else if constexpr (O == op_i64_clz) {
        return static_cast<std::uint64_t>(std::countl_zero(v));
    } else if constexpr (O == op_i64_ctz) {
        return static_cast<std::uint64_t>(std::countr_zero(v));
    } else if constexpr (O == op_i64_popcnt) {
        return static_cast<std::uint64_t>(std::popcount(v));
    } else if constexpr (O == op_i32_wrap_i64 || O == op_i64_extend_i32_u) {
        return v & mask32;
    } else if constexpr (O == op_i64_extend_i32_s) {
        return i64(s32(v));
    } else if constexpr (O == op_i32_extend8_s) {
        return i32(std::int32_t{static_cast<std::int8_t>(v)});
    } else if constexpr (O == op_i32_extend16_s) {
        return i32(std::int32_t{static_cast<std::int16_t>(v)});
    } else if constexpr (O == op_i64_extend8_s) {
        return i64(static_cast<std::int8_t>(v));
    } else if constexpr (O == op_i64_extend16_s) {
        return i64(static_cast<std::int16_t>(v));
    } else {
        static_assert(O == op_i64_extend32_s);
        return i64(static_cast<std::int32_t>(v));
    }
}

/// The binary operations that cannot trap, on operands `a` (pushed first)
/// and `b`.
template <Op O>
constexpr std::uint64_t binary(std::uint64_t a, std::uint64_t b) noexcept {
    using namespace detail;
    if constexpr (O == op_i32_eq) {
        return flag(lo32(a) == lo32(b));
    } else if constexpr (O == op_i32_ne) {
        return flag(lo32(a) != lo32(b));
    } else if constexpr (O == op_i32_lt_s) {
        return flag(s32(a) < s32(b));
    } else if constexpr (O == op_i32_lt_u) {
        return flag(lo32(a) < lo32(b));
    } else if constexpr (O == op_i32_gt_s) {
        return flag(s32(a) > s32(b));
    } else if constexpr (O == op_i32_gt_u) {
        return flag(lo32(a) > lo32(b));
    } else if constexpr (O == op_i32_le_s) {
        return flag(s32(a) <= s32(b));
    } else if constexpr (O == op_i32_le_u) {
        return flag(lo32(a) <= lo32(b));
    } else if constexpr (O == op_i32_ge_s) {
        return flag(s32(a) >= s32(b));
    } else if constexpr (O == op_i32_ge_u) {
        return flag(lo32(a) >= lo32(b));
    } else if constexpr (O == op_i32_add) {
        return i32(lo32(a + b));
    } else if constexpr (O == op_i32_sub) {
        return i32(lo32(a - b));
    } else if constexpr (O == op_i32_mul) {
        return i32(lo32(a) * lo32(b));
    } else if constexpr (O == op_i32_and) {
        return i32(lo32(a) & lo32(b));
    } else if constexpr (O == op_i32_or) {
        return i32(lo32(a) | lo32(b));
    } else if constexpr (O == op_i32_xor) {
        return i32(lo32(a) ^ lo32(b));
    } else if constexpr (O == op_i32_shl) {
        return i32(lo32(a) << (b & 31U));
    } else if constexpr (O == op_i32_shr_s) {
        return i32(s32(a) >> (b & 31U));
    } else if constexpr (O == op_i32_shr_u) {
        return i32(lo32(a) >> (b & 31U));
    } else if constexpr (O == op_i32_rotl) {
        return i32(std::rotl(lo32(a), static_cast<int>(b & 31U)));
    } else if constexpr (O == op_i32_rotr) {
        return i32(std::rotr(lo32(a), static_cast<int>(b & 31U)));
    } else if constexpr (O == op_i64_eq) {
        return flag(a == b);
    } else if constexpr (O == op_i64_ne) {
        return flag(a != b);
    } else if constexpr (O == op_i64_lt_s) {
        return flag(s64(a) < s64(b));
    } else if constexpr (O == op_i64_lt_u) {
        return flag(a < b);
    } else if constexpr (O == op_i64_gt_s) {
        return flag(s64(a) > s64(b));
    } else if constexpr (O == op_i64_gt_u) {
        return flag(a > b);
    } else if constexpr (O == op_i64_le_s) {
        return flag(s64(a) <= s64(b));
    } else if constexpr (O == op_i64_le_u) {
        return flag(a <= b);
    } else if constexpr (O == op_i64_ge_s) {
        return flag(s64(a) >= s64(b));
    } else if constexpr (O == op_i64_ge_u) {
        return flag(a >= b);
    } else if constexpr (O == op_i64_add) {
        return a + b;
    } else if constexpr (O == op_i64_sub) {
        return a - b;
    } else if constexpr (O == op_i64_mul) {
        return a * b;
    } else if constexpr (O == op_i64_and) {
        return a & b;
    } else if constexpr (O == op_i64_or) {
        return a | b;
    } else if constexpr (O == op_i64_xor) {
        return a ^ b;
    } else if constexpr (O == op_i64_shl) {
        return a << (b & 63U);
    } else if constexpr (O == op_i64_shr_s) {
        return i64(s64(a) >> (b & 63U));
    } else if constexpr (O == op_i64_shr_u) {
        return a >> (b & 63U);
    } else if constexpr (O == op_i64_rotl) {
        return std::rotl(a, static_cast<int>(b & 63U));
    } else {
        static_assert(O == op_i64_rotr);
        return std::rotr(a, static_cast<int>(b & 63U));
    }
}

/// Division and remainder: the quotient or remainder of `a` by `b`, or the
/// trap.
template <Op O>
constexpr std::optional<Trap> divide(std::uint64_t a, std::uint64_t b,
                                     std::uint64_t& out) noexcept {
    using namespace detail;
    if constexpr (O == op_i32_div_s || O == op_i32_rem_s) {
        const std::int32_t x = s32(a);
        const std::int32_t y = s32(b);
        if (y == 0) {
            return Trap::divide_by_zero;
        }
        if constexpr (O == op_i32_div_s) {
            if (x == INT32_MIN && y == -1) {
                return Trap::integer_overflow;
            }
            out = i32(x / y);
        } else {
            out = y == -1 ? std::uint64_t{0} : i32(x % y);
        }
    } else if constexpr (O == op_i32_div_u || O == op_i32_rem_u) {
        const std::uint32_t y = lo32(b);
        if (y == 0) {
            return Trap::divide_by_zero;
        }
        out = O == op_i32_div_u ? i32(lo32(a) / y) : i32(lo32(a) % y);
    } else if constexpr (O == op_i64_div_s || O == op_i64_rem_s) {
        const std::int64_t x = s64(a);
        const std::int64_t y = s64(b);
        if (y == 0) {
            return Trap::divide_by_zero;
        }
        if constexpr (O == op_i64_div_s) {
            if (x == INT64_MIN && y == -1) {
                return Trap::integer_overflow;
            }
            out = i64(x / y);
        } else {
            out = y == -1 ? std::uint64_t{0} : i64(x % y);
        }
    } else {
        static_assert(O == op_i64_div_u || O == op_i64_rem_u);
        if (b == 0) {
            return Trap::divide_by_zero;
        }
        out = O == op_i64_div_u ? a / b : a % b;
    }
    return std::nullopt;
}

} // namespace

namespace detail {

struct Frame {
    const Function* function = nullptr;
    /// Where the function continues after a call returns.
    const Instr* pc = nullptr;
    /// Its locals, parameters first; its results go here on return.
    std::uint64_t* locals = nullptr;
};

/// The space of runs, see Arena. Memory is tracked in chunks: a run marks
/// each chunk it writes (stores, data segments, input_read, hash, the bulk
/// operations), and when it ends those chunks are zeroed and unmarked. The
/// rest of the memory was never written since it was last zeroed, so the
/// whole of it is zero between runs. The operand stack, frames, and globals
/// are not cleared: a run writes every slot before reading it (validation
/// guarantees it for the operand stack; a frame's locals other than its
/// parameters are zeroed on entry; globals are set at instantiation).
struct ArenaData {
    static constexpr unsigned chunk_shift = 10;
    static constexpr std::size_t slack = 8;
    static constexpr std::size_t memory_bytes = std::size_t{max_pages} * page_size;
    static constexpr std::size_t chunks = memory_bytes >> chunk_shift;
    static_assert(chunks % 8 == 0);

    std::unique_ptr<std::uint8_t[]> memory = std::make_unique<std::uint8_t[]>(memory_bytes);
    /// 1 for each chunk the current run has written.
    std::array<std::uint8_t, chunks> dirty{};
    /// The budget's slots, and `slack` more that a call may zero beyond its
    /// locals.
    std::vector<std::uint64_t> stack = std::vector<std::uint64_t>(stack_budget + slack);
    std::array<Frame, max_call_depth> frames{};
    std::vector<std::uint64_t> globals;
    std::vector<ByteView> segments;
    bool busy = false;

    void mark(std::uint64_t first, std::uint64_t n) noexcept {
        if (n == 0) {
            return;
        }
        const std::size_t last = static_cast<std::size_t>((first + n - 1) >> chunk_shift);
        for (auto c = static_cast<std::size_t>(first >> chunk_shift); c <= last; ++c) {
            dirty[c] = 1;
        }
    }

    /// Zeroes the chunks the run wrote.
    void wipe() noexcept {
        for (std::size_t word = 0; word < chunks; word += 8) {
            std::uint64_t flags = 0;
            std::memcpy(&flags, dirty.data() + word, 8);
            if (flags == 0) {
                continue;
            }
            for (std::size_t c = word; c < word + 8; ++c) {
                if (dirty[c] != 0) {
                    std::memset(memory.get() + (c << chunk_shift), 0,
                                std::size_t{1} << chunk_shift);
                    dirty[c] = 0;
                }
            }
        }
    }
};

} // namespace detail

namespace {

using detail::Frame;

/// A run's hold on an arena: wiped and released when the run ends, however
/// it ends.
class Lease {
public:
    explicit Lease(detail::ArenaData& arena) noexcept : arena_(arena) { arena_.busy = true; }
    ~Lease() {
        arena_.wipe();
        arena_.busy = false;
    }
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;

private:
    detail::ArenaData& arena_;
};

// Threaded dispatch needs labels as values, a GNU extension (GCC, Clang);
// other compilers use the switch alone, and so does WebAssembly, which has
// no indirect jumps: Emscripten turns computed gotos into a switch on label
// numbers, which ran Bo's conformance runs 2.7 times slower than the switch
// itself (Node.js, 2026-10-20). Defining CEXCHAIN_VM_THREADED as 0 builds
// the switch alone anywhere.
#if !defined(CEXCHAIN_VM_THREADED)
#if defined(__GNUC__) && !defined(__EMSCRIPTEN__)
#define CEXCHAIN_VM_THREADED 1
#else
#define CEXCHAIN_VM_THREADED 0
#endif
#endif

/// One invocation of cexchain_call. Traps are returned, not thrown.
///
/// Fuel (spec section 14.3) is charged before each WebAssembly instruction
/// runs. The translated code charges a whole run at once, at its first
/// instruction: the run's instructions all execute unless one of them traps,
/// since only the last one can branch, call, or cost more than its fixed
/// fuel. When a run costs more than the fuel left, it is executed again
/// instruction by instruction ("step" mode), each charged before it runs, so
/// the instruction that runs out of fuel, and any trap before it, are the
/// spec's; within a fused instruction only the last part can trap, so the
/// parts before it charging one by one would change nothing. A trap in the
/// middle of a run gives back the fuel of the run's instructions after it.
class Machine {
public:
    Machine(const ModuleData& m, ByteView input, const crypto::Provider& provider,
            crypto::HashAlg hash, std::uint64_t fuel, detail::ArenaData& arena,
            detail::Dispatch dispatch)
        : m_(m), input_(input), provider_(provider), hash_(hash), fuel_limit_(fuel), fuel_(fuel),
          arena_(arena), memory_(arena.memory.get()), dirty_(arena.dirty.data()),
          globals_(arena.globals), segments_(arena.segments), frames_(arena.frames.data()),
          dispatch_(dispatch) {
        const detail::Limits limits = *m.memory;
        memory_size_ = std::uint64_t{limits.min} * page_size;
        max_pages_ = limits.max;
        globals_.resize(m.globals.size());
        for (std::size_t i = 0; i < m.globals.size(); ++i) {
            globals_[i] = m.globals[i].init;
        }
        // Active segments are copied in, then dropped; passive ones stay.
        segments_.clear();
        segments_.reserve(m.data.size());
        for (const detail::DataSegment& d : m.data) {
            const ByteView bytes = ByteView(m.bytes).subspan(d.begin, d.size);
            if (d.offset) {
                std::ranges::copy(bytes, memory_ + *d.offset);
                arena_.mark(*d.offset, bytes.size());
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

    /// The memory at `addr`, which the caller has checked is in bounds.
    [[nodiscard]] std::uint8_t* at(std::uint64_t addr) const noexcept {
        return memory_ + static_cast<std::size_t>(addr);
    }

    [[nodiscard]] bool in_bounds(std::uint64_t addr, std::uint64_t n) const noexcept {
        return addr + n <= memory_size_;
    }

    /// Runs a host function, its arguments on top of the operand stack
    /// (`sp_`), charging `fuel_`.
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
            std::ranges::copy(input_, at(ptr));
            arena_.mark(ptr, input_.size());
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
            output_ = Bytes(at(ptr), at(ptr + n));
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
                provider_.digest(hash_, ByteView(at(ptr), static_cast<std::size_t>(n)));
            if (!digest) {
                error_ = digest.error();
                return Trap::aborted;
            }
            std::ranges::copy(digest->bytes(), at(out));
            arena_.mark(out, 32);
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
            abort_reason_.assign(at(ptr), at(ptr + n));
            return Trap::aborted;
        }
        case Host::none:
            break;
        }
        return Trap::unreachable;
    }

    /// Ends the invocation with `trap`, raised by the instruction before
    /// `next`, with `fuel` left. In fast mode the trapping instruction's run
    /// was charged whole: the fuel of its instructions after this one comes
    /// back.
    template <bool Step>
    std::optional<Trap> stop(Trap trap, const Instr* next, std::uint64_t fuel) noexcept {
        if (trap == Trap::out_of_fuel) {
            fuel_ = 0;
            return trap;
        }
        if constexpr (!Step) {
            const Function& f = *frames_[depth_ - 1].function;
            for (auto i = static_cast<std::size_t>(next - f.code.data());
                 i < f.code.size() && f.code[i].op < charged; ++i) {
                fuel += f.costs[i];
            }
        }
        fuel_ = fuel;
        return trap;
    }

    std::optional<Trap> execute();

    template <bool Threaded, bool Step>
    std::optional<Trap> loop(const Instr* pc, std::uint64_t* sp, std::uint64_t* locals,
                             std::uint64_t fuel);

    const ModuleData& m_;
    ByteView input_;
    const crypto::Provider& provider_;
    crypto::HashAlg hash_;

    std::uint64_t fuel_limit_;
    /// The fuel left, while no loop runs (a loop keeps its own).
    std::uint64_t fuel_;
    detail::ArenaData& arena_;
    std::uint8_t* memory_;
    std::uint8_t* dirty_;
    std::uint64_t memory_size_ = 0;
    std::uint32_t max_pages_ = 0;
    std::vector<std::uint64_t>& globals_;
    std::vector<ByteView>& segments_;

    /// The operand stack's top, for host functions.
    std::uint64_t* sp_ = nullptr;
    Frame* frames_;
    std::uint32_t depth_ = 0;
    std::uint32_t budget_ = 0;
    /// Unused where every dispatch is the switch.
    [[maybe_unused]] detail::Dispatch dispatch_;

    std::optional<Bytes> output_;
    Bytes abort_reason_;
    std::optional<Error> error_;
};

std::optional<Trap> Machine::execute() {
    std::uint64_t* const locals = arena_.stack.data();
    const Function& entry = m_.functions[m_.entry];
    if (entry.slots > stack_budget) {
        return Trap::stack_budget_exceeded;
    }
    // The entry takes no parameters.
    std::uint64_t* const base = locals + entry.locals.size();
    std::fill(locals, base, std::uint64_t{0});
    frames_[0] = Frame{&entry, nullptr, locals};
    depth_ = 1;
    budget_ = entry.slots;
#if CEXCHAIN_VM_THREADED
    if (dispatch_ == detail::Dispatch::threaded) {
        return loop<true, false>(entry.code.data(), base, locals, fuel_);
    }
#endif
    return loop<false, false>(entry.code.data(), base, locals, fuel_);
}

// The interpreter's loop: `Threaded` dispatches through labels (GNU), else
// through the switch; `Step` charges each instruction's own fuel before it
// runs (see Machine) instead of each run's at its first instruction.
//
// Each operation's code is written once, for both dispatches: TARGET(name)
// opens it (a case of the switch, and labels for threaded dispatch: C_name
// charges the run and falls through to L_name), NEXT() goes to the next
// instruction, TRAP(trap) ends the invocation.
#if CEXCHAIN_VM_THREADED
// Labels as values and computed gotos are GNU extensions, used on purpose:
// -Wpedantic would refuse them, here only.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wgnu-label-as-value"
#endif
#define CEXCHAIN_VM_LABEL(prefix, name) prefix##name:
#else
#define CEXCHAIN_VM_LABEL(prefix, name)
#endif

#define TARGET(name)                                                                               \
    case detail::op_##name + charged:                                                              \
        CEXCHAIN_VM_LABEL(C_, name)                                                                \
        if (!Step) {                                                                               \
            if (in->fuel > fuel) {                                                                 \
                goto out_of_run_fuel;                                                              \
            }                                                                                      \
            fuel -= in->fuel;                                                                      \
        }                                                                                          \
        [[fallthrough]];                                                                           \
    case detail::op_##name:                                                                        \
        CEXCHAIN_VM_LABEL(L_, name)

#if CEXCHAIN_VM_THREADED
#define NEXT()                                                                                     \
    do {                                                                                           \
        if constexpr (Threaded) {                                                                  \
            in = pc++;                                                                             \
            goto* labels[in->op];                                                                  \
        } else {                                                                                   \
            goto dispatch;                                                                         \
        }                                                                                          \
    } while (false)
#else
#define NEXT() goto dispatch
#endif

#define TRAP(trap)                                                                                 \
    do {                                                                                           \
        depth_ = static_cast<std::uint32_t>(frame - frames_) + 1;                                  \
        return stop<Step>(trap, pc, fuel);                                                         \
    } while (false)

template <bool Threaded, bool Step>
std::optional<Trap> Machine::loop(const Instr* pc, std::uint64_t* sp, std::uint64_t* locals,
                                  std::uint64_t fuel) {
    static_assert(!(Threaded && Step));
    std::uint8_t* const memory = memory_;
    std::uint8_t* const dirty = dirty_;
    std::uint64_t* const globals = globals_.data();
    const Function* const functions = m_.functions.data();
    std::uint64_t memory_size = memory_size_;
    const Instr* in = nullptr;
    const Function* callee = nullptr;
    // The current function's frame, and the stack budget the active frames
    // take (members again when the loop ends).
    Frame* frame = frames_ + depth_ - 1;
    std::uint32_t budget = budget_;

#if CEXCHAIN_VM_THREADED
#define CEXCHAIN_VM_LABEL_ADDRESS(name, ...) &&L_##name,
#define CEXCHAIN_VM_CHARGED_ADDRESS(name, ...) &&C_##name,
    [[maybe_unused]] static const void* const labels[] = {
        CEXCHAIN_VM_OPS(CEXCHAIN_VM_LABEL_ADDRESS) CEXCHAIN_VM_OPS(CEXCHAIN_VM_CHARGED_ADDRESS)};
#undef CEXCHAIN_VM_LABEL_ADDRESS
#undef CEXCHAIN_VM_CHARGED_ADDRESS
    static_assert(std::size(labels) == 2 * std::size_t{detail::op_count});
#endif

    // The first instruction goes through the switch in either dispatch.
    goto dispatch;
dispatch:
    in = pc++;
    if constexpr (Step) {
        const Function& f = *frame->function;
        const std::uint16_t cost = f.costs[static_cast<std::size_t>(in - f.code.data())];
        if (cost > fuel) {
            TRAP(Trap::out_of_fuel);
        }
        fuel -= cost;
    }
    switch (in->op) {
        TARGET(unreachable) {
            TRAP(Trap::unreachable);
        }
        TARGET(nop) {
            NEXT();
        }
        TARGET(if) {
            if (*--sp == 0) {
                pc = in + offset(in->a);
            }
            NEXT();
        }
        TARGET(jump) {
            pc = in + offset(in->a);
            NEXT();
        }
        TARGET(jump_if) {
            if (*--sp != 0) {
                pc = in + offset(in->a);
            }
            NEXT();
        }
        TARGET(br_if) {
            if (*--sp == 0) {
                NEXT();
            }
            goto branch;
        }
        TARGET(br) {
            goto branch;
        }
        TARGET(br_table) {
            const std::uint64_t i = *--sp;
            const Function& f = *frame->function;
            const Branch& e = f.branches[in->a + static_cast<std::size_t>(std::min(i, in->b))];
            std::uint64_t* const dest = locals + f.locals.size() + e.height;
            std::copy_n(sp - e.arity, e.arity, dest);
            sp = dest + e.arity;
            pc = f.code.data() + e.target;
            NEXT();
        }
        TARGET(return) {
            const auto arity = static_cast<std::uint32_t>(in->b);
            if (arity == 1) {
                locals[0] = sp[-1];
            } else {
                std::copy_n(sp - arity, arity, locals);
            }
            sp = locals + arity;
            goto leave;
        }
        TARGET(call) {
            callee = &functions[in->a];
            goto enter;
        }
        TARGET(call_host) {
            callee = &functions[in->a];
            goto host;
        }
        TARGET(call_indirect) {
            const std::uint64_t i = *--sp;
            if (i >= m_.table_functions.size()) {
                TRAP(Trap::indirect_call_out_of_range);
            }
            const std::uint32_t fi = m_.table_functions[static_cast<std::size_t>(i)];
            if (fi == detail::null_function) {
                TRAP(Trap::indirect_call_to_null);
            }
            if (m_.type_ids[functions[fi].type] != m_.type_ids[in->a]) {
                TRAP(Trap::indirect_call_type_mismatch);
            }
            callee = &functions[fi];
            if (callee->host != Host::none) {
                goto host;
            }
            goto enter;
        }
        TARGET(drop) {
            --sp;
            NEXT();
        }
        TARGET(select) {
            sp -= 2;
            if (sp[1] == 0) {
                sp[-1] = sp[0];
            }
            NEXT();
        }
        TARGET(local_get) {
            *sp++ = locals[in->a];
            NEXT();
        }
        TARGET(local_set) {
            locals[in->a] = *--sp;
            NEXT();
        }
        TARGET(local_tee) {
            locals[in->a] = sp[-1];
            NEXT();
        }
        TARGET(global_get) {
            *sp++ = globals[in->a];
            NEXT();
        }
        TARGET(global_set) {
            globals[in->a] = *--sp;
            NEXT();
        }
        TARGET(const) {
            *sp++ = in->b;
            NEXT();
        }
        TARGET(memory_size) {
            *sp++ = memory_size / page_size;
            NEXT();
        }
        TARGET(memory_grow) {
            const std::uint64_t delta = sp[-1];
            const std::uint64_t pages = memory_size / page_size;
            const bool grows = pages + delta <= max_pages_;
            const std::uint64_t cost = grows ? 1 + 1024 * delta : 1;
            if (cost > fuel) {
                TRAP(Trap::out_of_fuel);
            }
            fuel -= cost;
            if (grows) {
                memory_size += delta * page_size;
                memory_size_ = memory_size;
                sp[-1] = pages;
            } else {
                sp[-1] = mask32;
            }
            NEXT();
        }
        // Bulk memory: charged by size once the operands are known.
        TARGET(memory_init) {
            const std::uint64_t n = sp[-1];
            const std::uint64_t s = sp[-2];
            const std::uint64_t d = sp[-3];
            sp -= 3;
            if (1 + per64(n) > fuel) {
                TRAP(Trap::out_of_fuel);
            }
            fuel -= 1 + per64(n);
            const ByteView segment = segments_[in->a];
            if (s + n > segment.size() || d + n > memory_size) {
                TRAP(Trap::out_of_bounds);
            }
            std::ranges::copy(
                segment.subspan(static_cast<std::size_t>(s), static_cast<std::size_t>(n)),
                memory + d);
            arena_.mark(d, n);
            NEXT();
        }
        TARGET(data_drop) {
            segments_[in->a] = {};
            NEXT();
        }
        TARGET(memory_copy) {
            const std::uint64_t n = sp[-1];
            const std::uint64_t s = sp[-2];
            const std::uint64_t d = sp[-3];
            sp -= 3;
            if (1 + per64(n) > fuel) {
                TRAP(Trap::out_of_fuel);
            }
            fuel -= 1 + per64(n);
            if (s + n > memory_size || d + n > memory_size) {
                TRAP(Trap::out_of_bounds);
            }
            std::memmove(memory + d, memory + s, static_cast<std::size_t>(n));
            arena_.mark(d, n);
            NEXT();
        }
        TARGET(memory_fill) {
            const std::uint64_t n = sp[-1];
            const auto value = static_cast<std::uint8_t>(sp[-2]);
            const std::uint64_t d = sp[-3];
            sp -= 3;
            if (1 + per64(n) > fuel) {
                TRAP(Trap::out_of_fuel);
            }
            fuel -= 1 + per64(n);
            if (d + n > memory_size) {
                TRAP(Trap::out_of_bounds);
            }
            std::memset(memory + d, value, static_cast<std::size_t>(n));
            arena_.mark(d, n);
            NEXT();
        }

        // Loads: the address is replaced by the value.
#define CEXCHAIN_VM_LOAD(name, opcode, width)                                                      \
    TARGET(name) {                                                                                 \
        const std::uint64_t addr = sp[-1] + in->b;                                                 \
        if (addr + (width) > memory_size) {                                                        \
            TRAP(Trap::out_of_bounds);                                                             \
        }                                                                                          \
        sp[-1] = loaded<detail::op_##name>(load_le<width>(memory + addr));                         \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_LOADS(CEXCHAIN_VM_LOAD)
#undef CEXCHAIN_VM_LOAD

        // Stores: address and value are popped.
#define CEXCHAIN_VM_STORE(name, opcode, width)                                                     \
    TARGET(name) {                                                                                 \
        const std::uint64_t addr = sp[-2] + in->b;                                                 \
        if (addr + (width) > memory_size) {                                                        \
            TRAP(Trap::out_of_bounds);                                                             \
        }                                                                                          \
        store_le<width>(memory + addr, sp[-1]);                                                    \
        dirty[static_cast<std::size_t>(addr >> detail::ArenaData::chunk_shift)] = 1;               \
        dirty[static_cast<std::size_t>((addr + ((width) - 1)) >>                                   \
                                       detail::ArenaData::chunk_shift)] = 1;                       \
        sp -= 2;                                                                                   \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_STORES(CEXCHAIN_VM_STORE)
#undef CEXCHAIN_VM_STORE

#define CEXCHAIN_VM_UNARY_OP(name, opcode)                                                         \
    TARGET(name) {                                                                                 \
        sp[-1] = unary<detail::op_##name>(sp[-1]);                                                 \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_UNARY(CEXCHAIN_VM_UNARY_OP)
#undef CEXCHAIN_VM_UNARY_OP

#define CEXCHAIN_VM_DIVISION_OP(name, opcode)                                                      \
    TARGET(name) {                                                                                 \
        if (const auto trap = divide<detail::op_##name>(sp[-2], sp[-1], sp[-2])) {                 \
            TRAP(*trap);                                                                           \
        }                                                                                          \
        --sp;                                                                                      \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_DIVISION(CEXCHAIN_VM_DIVISION_OP)
#undef CEXCHAIN_VM_DIVISION_OP

#define CEXCHAIN_VM_BINARY_OP(name, opcode)                                                        \
    TARGET(name) {                                                                                 \
        sp[-2] = binary<detail::op_##name>(sp[-2], sp[-1]);                                        \
        --sp;                                                                                      \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_BINARY(CEXCHAIN_VM_BINARY_OP)
#undef CEXCHAIN_VM_BINARY_OP

        // Fused instructions (see internal.hpp).
#define CEXCHAIN_VM_FUSED_C(fused, name)                                                           \
    TARGET(fused) {                                                                                \
        sp[-1] = binary<detail::op_##name>(sp[-1], in->b);                                         \
        NEXT();                                                                                    \
    }
#define CEXCHAIN_VM_FUSED_L(fused, name)                                                           \
    TARGET(fused) {                                                                                \
        sp[-1] = binary<detail::op_##name>(sp[-1], locals[in->a]);                                 \
        NEXT();                                                                                    \
    }
#define CEXCHAIN_VM_FUSED_LC(fused, name)                                                          \
    TARGET(fused) {                                                                                \
        *sp++ = binary<detail::op_##name>(locals[in->a], in->b);                                   \
        NEXT();                                                                                    \
    }
#define CEXCHAIN_VM_FUSED_LL(fused, name)                                                          \
    TARGET(fused) {                                                                                \
        *sp++ = binary<detail::op_##name>(locals[in->a], locals[lo32(in->b)]);                     \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_BINARY_LIST(CEXCHAIN_VM_FUSED_C, CEXCHAIN_VM_WITH_C)
        CEXCHAIN_VM_BINARY_LIST(CEXCHAIN_VM_FUSED_L, CEXCHAIN_VM_WITH_L)
        CEXCHAIN_VM_BINARY_LIST(CEXCHAIN_VM_FUSED_LC, CEXCHAIN_VM_WITH_LC)
        CEXCHAIN_VM_BINARY_LIST(CEXCHAIN_VM_FUSED_LL, CEXCHAIN_VM_WITH_LL)
#define CEXCHAIN_VM_FUSED_IF(fused, name)                                                          \
    TARGET(fused) {                                                                                \
        sp -= 2;                                                                                   \
        if (binary<detail::op_##name>(sp[0], sp[1]) == 0) {                                        \
            pc = in + offset(in->a);                                                               \
        }                                                                                          \
        NEXT();                                                                                    \
    }
#define CEXCHAIN_VM_FUSED_JUMP_IF(fused, name)                                                     \
    TARGET(fused) {                                                                                \
        sp -= 2;                                                                                   \
        if (binary<detail::op_##name>(sp[0], sp[1]) != 0) {                                        \
            pc = in + offset(in->a);                                                               \
        }                                                                                          \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_COMPARE_LIST(CEXCHAIN_VM_FUSED_IF, CEXCHAIN_VM_WITH_IF)
        CEXCHAIN_VM_COMPARE_LIST(CEXCHAIN_VM_FUSED_JUMP_IF, CEXCHAIN_VM_WITH_JUMP_IF)
#undef CEXCHAIN_VM_FUSED_IF
#undef CEXCHAIN_VM_FUSED_JUMP_IF
#define CEXCHAIN_VM_FUSED_BRANCH(fused, name, x, y, taken)                                         \
    TARGET(fused) {                                                                                \
        if ((binary<detail::op_##name>(x, y) != 0) == (taken)) {                                   \
            pc = in + offset(in->a);                                                               \
        }                                                                                          \
        NEXT();                                                                                    \
    }
#define CEXCHAIN_VM_FUSED_C_IF(fused, name)                                                        \
    CEXCHAIN_VM_FUSED_BRANCH(fused, name, *--sp, in->b, false)
#define CEXCHAIN_VM_FUSED_C_JUMP_IF(fused, name)                                                   \
    CEXCHAIN_VM_FUSED_BRANCH(fused, name, *--sp, in->b, true)
#define CEXCHAIN_VM_FUSED_LL_IF(fused, name)                                                       \
    CEXCHAIN_VM_FUSED_BRANCH(fused, name, locals[lo32(in->b)], locals[in->b >> 32U], false)
#define CEXCHAIN_VM_FUSED_LL_JUMP_IF(fused, name)                                                  \
    CEXCHAIN_VM_FUSED_BRANCH(fused, name, locals[lo32(in->b)], locals[in->b >> 32U], true)
        CEXCHAIN_VM_COMPARE_LIST(CEXCHAIN_VM_FUSED_C_IF, CEXCHAIN_VM_WITH_C_IF)
        CEXCHAIN_VM_COMPARE_LIST(CEXCHAIN_VM_FUSED_C_JUMP_IF, CEXCHAIN_VM_WITH_C_JUMP_IF)
        CEXCHAIN_VM_COMPARE_LIST(CEXCHAIN_VM_FUSED_LL_IF, CEXCHAIN_VM_WITH_LL_IF)
        CEXCHAIN_VM_COMPARE_LIST(CEXCHAIN_VM_FUSED_LL_JUMP_IF, CEXCHAIN_VM_WITH_LL_JUMP_IF)
#undef CEXCHAIN_VM_FUSED_BRANCH
#undef CEXCHAIN_VM_FUSED_C_IF
#undef CEXCHAIN_VM_FUSED_C_JUMP_IF
#undef CEXCHAIN_VM_FUSED_LL_IF
#undef CEXCHAIN_VM_FUSED_LL_JUMP_IF
#undef CEXCHAIN_VM_FUSED_C
#undef CEXCHAIN_VM_FUSED_L
#undef CEXCHAIN_VM_FUSED_LC
#undef CEXCHAIN_VM_FUSED_LL

#define CEXCHAIN_VM_FUSED_LOAD(fused, name, width)                                                 \
    TARGET(fused) {                                                                                \
        const std::uint64_t addr = locals[in->a] + in->b;                                          \
        if (addr + (width) > memory_size) {                                                        \
            TRAP(Trap::out_of_bounds);                                                             \
        }                                                                                          \
        *sp++ = loaded<detail::op_##name>(load_le<width>(memory + addr));                          \
        NEXT();                                                                                    \
    }
        CEXCHAIN_VM_FUSED_LOADS(CEXCHAIN_VM_FUSED_LOAD)
#undef CEXCHAIN_VM_FUSED_LOAD

        TARGET(set_get) {
            locals[in->a] = sp[-1];
            sp[-1] = locals[lo32(in->b)];
            NEXT();
        }
        TARGET(tee_jump_if) {
            const std::uint64_t v = *--sp;
            locals[lo32(in->b)] = v;
            if (v != 0) {
                pc = in + offset(in->a);
            }
            NEXT();
        }
        TARGET(set_jump) {
            locals[lo32(in->b)] = *--sp;
            pc = in + offset(in->a);
            NEXT();
        }
        TARGET(if_l) {
            if (locals[lo32(in->b)] == 0) {
                pc = in + offset(in->a);
            }
            NEXT();
        }
        TARGET(jump_if_l) {
            if (locals[lo32(in->b)] != 0) {
                pc = in + offset(in->a);
            }
            NEXT();
        }
        TARGET(call_l) {
            *sp++ = locals[lo32(in->b)];
            callee = &functions[in->a];
            goto enter;
        }
        TARGET(call_c) {
            *sp++ = in->b;
            callee = &functions[in->a];
            goto enter;
        }
        TARGET(return_l) {
            locals[0] = locals[in->a];
            sp = locals + 1;
            goto leave;
        }
        TARGET(const2) {
            sp[0] = in->a;
            sp[1] = in->b;
            sp += 2;
            NEXT();
        }

    default:
        // Translation makes no other operation.
        TRAP(Trap::unreachable);
    }

branch:
    // br and br_if: moves the values the label takes down to its height.
    {
        const auto arity = static_cast<std::uint32_t>(in->b >> 32U);
        std::uint64_t* const dest = locals + frame->function->locals.size() + lo32(in->b);
        std::copy_n(sp - arity, arity, dest);
        sp = dest + arity;
        pc = in + offset(in->a);
    }
    NEXT();

    // Calls, after their cost: a host function at once, or by entering it.
host:
    sp_ = sp;
    fuel_ = fuel;
    {
        const std::optional<Trap> trap = call_host(callee->host);
        sp = sp_;
        fuel = fuel_;
        if (trap) {
            TRAP(*trap);
        }
    }
    NEXT();

enter:
    if (frame + 1 == frames_ + max_call_depth) {
        TRAP(Trap::call_depth_exceeded);
    }
    if (budget + callee->slots > stack_budget) {
        TRAP(Trap::stack_budget_exceeded);
    }
    {
        frame->pc = pc;
        // Its declared locals start at zero. Most functions declare a few:
        // the first slots are zeroed without a call (into the callee's
        // operand stack, or the arena's slack, when it declares fewer).
        for (std::size_t i = 0; i < detail::ArenaData::slack; ++i) {
            sp[i] = 0;
        }
        if (callee->declared > detail::ArenaData::slack) {
            std::fill(sp + detail::ArenaData::slack, sp + callee->declared, std::uint64_t{0});
        }
        locals = sp - callee->params;
        sp += callee->declared;
        *++frame = Frame{callee, nullptr, locals};
        budget += callee->slots;
        pc = callee->code.data();
    }
    NEXT();

leave:
    // Returns to the caller, the results in place.
    budget -= frame->function->slots;
    if (frame == frames_) {
        depth_ = 0;
        budget_ = budget;
        fuel_ = fuel;
        return std::nullopt;
    }
    --frame;
    locals = frame->locals;
    pc = frame->pc;
    NEXT();

out_of_run_fuel:
    // The run costs more than the fuel left: step through it.
    if constexpr (!Step) {
        depth_ = static_cast<std::uint32_t>(frame - frames_) + 1;
        budget_ = budget;
        return loop<false, true>(in, sp, locals, fuel);
    } else {
        TRAP(Trap::out_of_fuel);
    }
}

#undef TARGET
#undef NEXT
#undef TRAP
#undef CEXCHAIN_VM_LABEL
#if CEXCHAIN_VM_THREADED
#pragma GCC diagnostic pop
#endif

/// The calling thread's arena. (Portable to wasm32: without threads it is a
/// plain static.)
Arena& thread_arena() noexcept {
    thread_local Arena arena;
    return arena;
}

} // namespace

struct ArenaAccess {
    static detail::ArenaData& data(Arena& arena) {
        if (!arena.data_) {
            arena.data_ = std::make_unique<detail::ArenaData>();
        }
        return *arena.data_;
    }
};

Arena::Arena() noexcept = default;
Arena::~Arena() = default;
Arena::Arena(Arena&& other) noexcept = default;
Arena& Arena::operator=(Arena&& other) noexcept = default;

bool Arena::clean() const noexcept {
    if (!data_) {
        return true;
    }
    if (data_->busy || std::ranges::any_of(data_->dirty, [](std::uint8_t d) { return d != 0; })) {
        return false;
    }
    std::uint64_t any = 0;
    for (std::size_t i = 0; i < detail::ArenaData::memory_bytes; i += 8) {
        std::uint64_t word = 0;
        std::memcpy(&word, data_->memory.get() + i, 8);
        any |= word;
    }
    return any == 0;
}

namespace detail {

Result<Outcome> run(const Module& module, ByteView input, const crypto::Provider& provider,
                    crypto::HashAlg hash, std::uint64_t fuel, Arena& arena, Dispatch dispatch) {
    if (crypto::digest_size(hash) != 32) {
        return fail(Errc::unsupported, "contracts need a 32-byte ledger hash");
    }
    if (input.size() > 0xFFFF'FFFF) {
        return fail(Errc::invalid_argument, "contract input too large");
    }
    ArenaData& data = ArenaAccess::data(arena);
    if (data.busy) {
        Arena fresh;
        return run(module, input, provider, hash, fuel, fresh, dispatch);
    }
    const Lease lease(data);
    return Machine(module.data(), input, provider, hash, fuel, data, dispatch).run();
}

Result<Outcome> run(const Module& module, ByteView input, const crypto::Provider& provider,
                    crypto::HashAlg hash, std::uint64_t fuel) {
    return run(module, input, provider, hash, fuel, thread_arena());
}

} // namespace detail

Result<Outcome> run(const Module& module, ByteView input, const crypto::Provider& provider,
                    crypto::HashAlg hash, Arena& arena) {
    return detail::run(module, input, provider, hash, fuel_limit, arena);
}

Result<Outcome> run(const Module& module, ByteView input, const crypto::Provider& provider,
                    crypto::HashAlg hash) {
    return detail::run(module, input, provider, hash, fuel_limit, thread_arena());
}

} // namespace cexchain::vm
