// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/cost.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>

/// Part of cexchain::bo, the compiler proper (C++26 with static reflection and
/// contracts; GCC 16). The WebAssembly emitter: a module writer and a function
/// builder for modules in the contract profile (spec section 14). The emitter
/// never reads untrusted input; its own invariants (operand types, the
/// operand stack's height, control frames, indices) are contracts, so a bug
/// in code generation stops the compiler instead of producing a module.
///
///   ModuleWriter module(layout);
///   const Func f = module.declare({.params = {ValType::i64}, .results = {ValType::i64}});
///   FunctionBuilder b = module.begin(f);
///   b.get(b.param(0)).i64(1).op(Op::i64_add);
///   module.define(std::move(b));
///
/// Output is deterministic: the same calls give the same bytes. Every module
/// `finish` returns has passed `vm::load`.
///
/// Costs (cost.hpp). The builder also records what each function can cost:
/// every loop says how often its body may start, a call may give the
/// callee's sizes, a bulk memory operation how many bytes it moves at most,
/// and `output` marks bytes of output; `ModuleWriter::bound` then gives the
/// most fuel and output an invocation can use.
namespace cexchain::bo::wasm {

/// It goes up whenever any emitted byte changes.
/// Lowering still writes every version from `oldest_codegen_version` on, so
/// that a deploy built with an earlier one rebuilds. 2: the input's texts
/// are not checked for UTF-8 again, and scratch locals are shared; 3: an
/// action asks the consents of R31; 4: a time rule's block is read with the
/// actions it does for final states (model::Finality).
inline constexpr std::uint32_t codegen_version = 4;
inline constexpr std::uint32_t oldest_codegen_version = 1;

enum class ValType : std::uint8_t { i32 = 0x7F, i64 = 0x7E };

struct FuncType {
    std::vector<ValType> params;
    std::vector<ValType> results;

    friend auto operator<=>(const FuncType&, const FuncType&) = default;
};

/// The host functions (spec section 14.4). Each enumerator's identifier is
/// the import's name, and every module imports all five, in this order, as
/// functions 0 to 4.
enum class Host : std::uint8_t { input_size, input_read, output_write, hash, abort };
inline constexpr std::uint32_t host_count = 5;

/// Instructions with no immediates other than a memory argument: numeric,
/// parametric, and memory instructions of the profile. Each enumerator's
/// value is its encoding (0xFC-prefixed ones as 0xFC00 plus the
/// sub-opcode). Control, variable, call, and constant instructions have
/// their own methods.
enum class Op : std::uint16_t {
    drop = 0x1A,
    select = 0x1B,
    i32_load = 0x28,
    i64_load = 0x29,
    i32_load8_s = 0x2C,
    i32_load8_u = 0x2D,
    i32_load16_s = 0x2E,
    i32_load16_u = 0x2F,
    i64_load8_s = 0x30,
    i64_load8_u = 0x31,
    i64_load16_s = 0x32,
    i64_load16_u = 0x33,
    i64_load32_s = 0x34,
    i64_load32_u = 0x35,
    i32_store = 0x36,
    i64_store = 0x37,
    i32_store8 = 0x3A,
    i32_store16 = 0x3B,
    i64_store8 = 0x3C,
    i64_store16 = 0x3D,
    i64_store32 = 0x3E,
    memory_size = 0x3F,
    memory_grow = 0x40,
    i32_eqz = 0x45,
    i32_eq = 0x46,
    i32_ne = 0x47,
    i32_lt_s = 0x48,
    i32_lt_u = 0x49,
    i32_gt_s = 0x4A,
    i32_gt_u = 0x4B,
    i32_le_s = 0x4C,
    i32_le_u = 0x4D,
    i32_ge_s = 0x4E,
    i32_ge_u = 0x4F,
    i64_eqz = 0x50,
    i64_eq = 0x51,
    i64_ne = 0x52,
    i64_lt_s = 0x53,
    i64_lt_u = 0x54,
    i64_gt_s = 0x55,
    i64_gt_u = 0x56,
    i64_le_s = 0x57,
    i64_le_u = 0x58,
    i64_ge_s = 0x59,
    i64_ge_u = 0x5A,
    i32_clz = 0x67,
    i32_ctz = 0x68,
    i32_popcnt = 0x69,
    i32_add = 0x6A,
    i32_sub = 0x6B,
    i32_mul = 0x6C,
    i32_div_s = 0x6D,
    i32_div_u = 0x6E,
    i32_rem_s = 0x6F,
    i32_rem_u = 0x70,
    i32_and = 0x71,
    i32_or = 0x72,
    i32_xor = 0x73,
    i32_shl = 0x74,
    i32_shr_s = 0x75,
    i32_shr_u = 0x76,
    i32_rotl = 0x77,
    i32_rotr = 0x78,
    i64_clz = 0x79,
    i64_ctz = 0x7A,
    i64_popcnt = 0x7B,
    i64_add = 0x7C,
    i64_sub = 0x7D,
    i64_mul = 0x7E,
    i64_div_s = 0x7F,
    i64_div_u = 0x80,
    i64_rem_s = 0x81,
    i64_rem_u = 0x82,
    i64_and = 0x83,
    i64_or = 0x84,
    i64_xor = 0x85,
    i64_shl = 0x86,
    i64_shr_s = 0x87,
    i64_shr_u = 0x88,
    i64_rotl = 0x89,
    i64_rotr = 0x8A,
    i32_wrap_i64 = 0xA7,
    i64_extend_i32_s = 0xAC,
    i64_extend_i32_u = 0xAD,
    i32_extend8_s = 0xC0,
    i32_extend16_s = 0xC1,
    i64_extend8_s = 0xC2,
    i64_extend16_s = 0xC3,
    i64_extend32_s = 0xC4,
    memory_copy = 0xFC0A,
    memory_fill = 0xFC0B,
};

/// The operand types an instruction pops and pushes; `drop` and `select`
/// (which take any type) have none here.
struct Signature {
    std::vector<ValType> pops;
    std::vector<ValType> pushes;
};
[[nodiscard]] Signature signature(Op op);
[[nodiscard]] bool is_load(Op op) noexcept;
[[nodiscard]] bool is_store(Op op) noexcept;
/// memory.copy and memory.fill, whose fuel depends on their size.
[[nodiscard]] bool is_bulk(Op op) noexcept;
/// The instruction's name in the text format ("i64.add", "memory.copy").
[[nodiscard]] std::string_view name_of(Op op) noexcept BO_POST(r, !r.empty());
/// The import's name ("input_read").
[[nodiscard]] std::string_view name_of(Host host) noexcept BO_POST(r, !r.empty());

/// A function: its index in the module (imports first).
struct Func {
    std::uint32_t index = 0;
    friend bool operator==(Func, Func) = default;
};
struct Local {
    std::uint32_t index = 0;
};
struct Global {
    std::uint32_t index = 0;
};
/// A block, loop, or if, for branches to name. Valid while it is open.
struct Label {
    std::uint32_t frame = 0;
    std::uint32_t serial = 0;
};
/// A block's result: none, or one value.
using BlockType = std::optional<ValType>;

/// Where a module keeps what: its memory's size, and the region the writer
/// fills with constant bytes (`intern`) and scratch space (`reserve`).
struct MemoryPlan {
    std::uint32_t pages = 1;
    std::uint32_t static_base = 0;
    std::uint32_t static_end = 0;
};

class ModuleWriter;

/// One function's body. It tracks the operand stack as the WebAssembly
/// specification's validation algorithm does (its appendix), so it knows
/// the stack's maximum height, and every instruction's operands are checked
/// as it is added.
class FunctionBuilder {
public:
    FunctionBuilder(FunctionBuilder&&) noexcept = default;
    FunctionBuilder& operator=(FunctionBuilder&&) noexcept = default;
    FunctionBuilder(const FunctionBuilder&) = delete;
    FunctionBuilder& operator=(const FunctionBuilder&) = delete;
    ~FunctionBuilder() = default;

    // Queries, also used by the contracts below.
    [[nodiscard]] Func self() const noexcept { return self_; }
    [[nodiscard]] std::uint32_t params() const noexcept;
    [[nodiscard]] std::uint32_t height() const noexcept {
        return static_cast<std::uint32_t>(vals_.size());
    }
    [[nodiscard]] std::uint32_t max_height() const noexcept { return max_height_; }
    /// False after an unconditional branch, a return, or `unreachable`,
    /// until the frame ends.
    [[nodiscard]] bool reachable() const noexcept;
    [[nodiscard]] std::size_t open_frames() const noexcept { return frames_.size(); }
    /// The body's size so far, in bytes.
    [[nodiscard]] std::size_t size() const noexcept { return code_.size(); }
    /// Locals declared so far (parameters not counted).
    [[nodiscard]] std::size_t local_count() const noexcept { return locals_.size(); }
    [[nodiscard]] bool is_open(Label label) const noexcept;
    [[nodiscard]] bool is_innermost(Label label) const noexcept;
    [[nodiscard]] bool can_pop(std::span<const ValType> types) const noexcept;
    [[nodiscard]] bool can_pop(ValType type) const noexcept;
    [[nodiscard]] bool is_local(Local local) const noexcept;
    [[nodiscard]] ValType type_of(Local local) const noexcept BO_PRE(is_local(local));
    [[nodiscard]] bool accepts(Op op) const;
    [[nodiscard]] bool can_call(Func callee) const;
    /// The types a branch to `label` carries.
    [[nodiscard]] std::vector<ValType> label_types(Label label) const BO_PRE(is_open(label));
    [[nodiscard]] bool can_branch(Label label) const BO_PRE(is_open(label));
    /// True when the innermost frame can end: its results are on the stack.
    [[nodiscard]] bool can_end() const;

    [[nodiscard]] Local param(std::uint32_t index) const BO_PRE(index < params());
    /// A new local, zero at entry.
    [[nodiscard]] Local local(ValType type);

    // Costs (cost.hpp).
    /// Declares the function's size parameters and their defaults (the most
    /// each can be), once, before `size` is used.
    void sizes(std::vector<std::uint64_t> defaults) BO_PRE(size_count() == 0);
    [[nodiscard]] std::uint32_t size_count() const noexcept {
        return static_cast<std::uint32_t>(size_defaults_.size());
    }
    /// The size parameter `index`.
    [[nodiscard]] Size size(std::uint32_t index) const BO_PRE(index < size_count());
    /// Inside a loop opened with `LoopBound::items`, the size of the item the
    /// body is at.
    [[nodiscard]] Size item_size(Label loop) const BO_PRE(is_open(loop));
    /// Records that at most `bytes` of output are reserved here.
    FunctionBuilder& output(Size bytes);
    /// Output written from here to `cap_end` counts at most `limit` bytes (the
    /// code refuses the call beyond it).
    FunctionBuilder& cap_begin();
    FunctionBuilder& cap_end(std::uint64_t limit);
    /// Code from here to `region_end` runs only when a call does what `tag`
    /// (one bit) stands for; ModuleWriter::bound may leave it out.
    FunctionBuilder& region_begin(std::uint32_t tag) BO_PRE(std::has_single_bit(tag));
    FunctionBuilder& region_end();

    FunctionBuilder& i32(std::int32_t value);
    FunctionBuilder& i64(std::int64_t value);
    /// An i32 constant written as unsigned (an address, a mask).
    FunctionBuilder& u32(std::uint32_t value) { return i32(static_cast<std::int32_t>(value)); }
    FunctionBuilder& get(Local local) BO_PRE(is_local(local));
    FunctionBuilder& set(Local local) BO_PRE(is_local(local) && can_pop(type_of(local)));
    FunctionBuilder& tee(Local local) BO_PRE(is_local(local) && can_pop(type_of(local)));
    FunctionBuilder& global_get(Global global) BO_PRE(is_global(global));
    FunctionBuilder& global_set(Global global)
        BO_PRE(is_global(global) && is_mutable(global) && can_pop(global_type(global)));
    /// A numeric, parametric, or memory instruction other than a load or a
    /// store.
    FunctionBuilder& op(Op op) BO_PRE(!is_load(op) && !is_store(op) && !is_bulk(op) &&
                                      op != Op::memory_grow && accepts(op));
    /// memory.copy or memory.fill of at most `bytes` bytes.
    FunctionBuilder& bulk(Op op, Size bytes) BO_PRE(is_bulk(op) && accepts(op));
    FunctionBuilder& load(Op op, std::uint32_t offset = 0) BO_PRE(is_load(op) && accepts(op));
    FunctionBuilder& store(Op op, std::uint32_t offset = 0) BO_PRE(is_store(op) && accepts(op));

    [[nodiscard]] Label block(BlockType type = {});
    /// A loop whose body starts at most `bound.starts` times.
    [[nodiscard]] Label loop(LoopBound bound, BlockType type = {});
    [[nodiscard]] Label if_(BlockType type = {}) BO_PRE(can_pop(ValType::i32));
    FunctionBuilder& else_(Label label) BO_PRE(is_innermost(label) && can_end());
    FunctionBuilder& end(Label label) BO_PRE(is_innermost(label) && can_end());
    FunctionBuilder& br(Label label) BO_PRE(is_open(label) && can_branch(label));
    FunctionBuilder& br_if(Label label);
    FunctionBuilder& br_table(std::span<const Label> labels, Label otherwise);
    FunctionBuilder& return_();
    FunctionBuilder& unreachable();
    /// Calls `callee`, giving its size parameters (those left out take their
    /// defaults; a host function's one size is the bytes it handles).
    FunctionBuilder& call(Func callee, std::vector<Size> sizes = {}) BO_PRE(can_call(callee));

    [[nodiscard]] bool is_global(Global global) const noexcept;
    [[nodiscard]] bool is_mutable(Global global) const noexcept;
    [[nodiscard]] ValType global_type(Global global) const noexcept;

private:
    friend class ModuleWriter;
    enum class Kind : std::uint8_t { function, block, loop, if_, else_ };
    struct Frame {
        Kind kind = Kind::block;
        std::vector<ValType> results;
        std::uint32_t height = 0;
        bool unreachable = false;
        std::uint32_t serial = 0;
    };

    /// The cost of an open frame (or of a stretch `cap_begin` opened): its
    /// node, and for an `if`, the arm being written.
    struct CostFrame {
        CostNode node;
        std::size_t arm = 0;
        /// A stretch (cap or region), not a frame of the code.
        bool cap = false;
    };

    FunctionBuilder(const ModuleWriter& module, Func self);
    /// Where plain instructions add their fuel now.
    CostNode& current_cost();
    void charge(std::uint64_t fuel) { current_cost().fuel += fuel; }
    void emit_op(Op op);
    void push(ValType type);
    void push(std::span<const ValType> types);
    void pop(ValType type);
    void pop(std::span<const ValType> types);
    void mark_unreachable();
    void byte(std::uint8_t value) { code_.push_back(value); }
    void uleb(std::uint64_t value);
    void sleb(std::int64_t value);
    Label open(Kind kind, BlockType type, std::uint8_t opcode);
    [[nodiscard]] std::uint32_t depth(Label label) const BO_PRE(is_open(label));
    /// The body as the code section holds it (locals, instructions, the
    /// final end).
    [[nodiscard]] Bytes finish() BO_PRE(open_frames() == 1 && can_end());

    const ModuleWriter* module_;
    Func self_;
    std::vector<ValType> locals_;
    /// The operand stack's types; 0 stands for a value of unknown type
    /// (popped from an empty stack in unreachable code).
    std::vector<std::uint8_t> vals_;
    std::vector<Frame> frames_;
    std::uint32_t max_height_ = 0;
    std::uint32_t next_serial_ = 0;
    Bytes code_;
    std::vector<std::uint64_t> size_defaults_;
    std::vector<CostFrame> costs_;
    /// The item slot of each open loop that walks items, by label serial.
    std::map<std::uint32_t, std::uint32_t> item_slots_;
    std::uint32_t next_item_slot_ = 0;
};

/// A module in the contract profile: the five `cexchain` imports, one
/// memory exported as "memory" (its pages fixed, minimum and maximum),
/// mutable globals, functions, one active data segment holding the static
/// region, and the export "cexchain_call". No tables, no custom sections.
class ModuleWriter {
public:
    explicit ModuleWriter(const MemoryPlan& plan)
        BO_PRE(plan.pages >= 1 && plan.pages <= 16 && plan.static_base <= plan.static_end &&
               plan.static_end <= plan.pages * 65'536U);

    [[nodiscard]] const MemoryPlan& plan() const noexcept { return plan_; }
    [[nodiscard]] Func host(Host host) const noexcept;
    [[nodiscard]] std::uint32_t function_count() const noexcept {
        return static_cast<std::uint32_t>(functions_.size());
    }
    [[nodiscard]] bool is_function(Func f) const noexcept { return f.index < functions_.size(); }
    [[nodiscard]] bool is_defined(Func f) const noexcept BO_PRE(is_function(f));
    [[nodiscard]] const FuncType& type_of(Func f) const noexcept BO_PRE(is_function(f));

    /// A new function of `type`; its body comes later, through `begin` and
    /// `define`.
    [[nodiscard]] Func declare(FuncType type)
        BO_PRE(type.params.size() <= 32 && type.results.size() <= 16);
    [[nodiscard]] FunctionBuilder begin(Func f) const BO_PRE(is_function(f) && !is_defined(f));
    void define(FunctionBuilder&& body)
        BO_PRE(is_function(body.self()) && !is_defined(body.self()) && body.open_frames() == 1 &&
               body.can_end());
    /// The operand stack's maximum height in a defined function, as the
    /// builder measured it.
    [[nodiscard]] std::uint32_t max_height(Func f) const BO_PRE(is_function(f) && is_defined(f));

    /// A bound given by hand for `f`, used in place of its recorded cost: for
    /// a routine whose cost the tree cannot bound (one that recurses). It
    /// takes the function's sizes (its defaults filled in).
    using BoundFormula = std::function<Bound(std::span<const std::uint64_t> sizes)>;
    void set_bound(Func f, BoundFormula formula) BO_PRE(is_function(f) && f.index >= host_count);
    /// The most an invocation of `f` can use with these sizes (the rest take
    /// their defaults), every function it calls being defined. Calls to the
    /// functions in `skip` count only the call itself; regions whose tag is
    /// in `absent` (a set of bits) count nothing. A function that calls
    /// itself, without a bound given by hand, is unbounded.
    [[nodiscard]] Bound bound(Func f, std::span<const std::uint64_t> sizes = {},
                              std::span<const Func> skip = {}, std::uint32_t absent = 0) const
        BO_PRE(is_function(f));
    /// The defaults of a defined function's sizes.
    [[nodiscard]] const std::vector<std::uint64_t>& size_defaults(Func f) const
        BO_PRE(is_function(f) && is_defined(f));

    [[nodiscard]] Global add_global(ValType type, std::int64_t initial);
    [[nodiscard]] std::uint32_t global_count() const noexcept {
        return static_cast<std::uint32_t>(globals_.size());
    }
    [[nodiscard]] ValType global_type(Global global) const BO_PRE(global.index < global_count());

    /// Bytes of the static region not used yet.
    [[nodiscard]] std::uint32_t static_free() const noexcept {
        return plan_.static_end - plan_.static_base - static_cast<std::uint32_t>(statics_.size());
    }
    /// True if `bytes` are interned already.
    [[nodiscard]] bool interned(ByteView bytes) const;
    /// The address of `bytes` in the static region, the same for the same
    /// bytes.
    [[nodiscard]] std::uint32_t intern(const ByteView bytes)
        BO_POST(r, r >= plan().static_base && r + bytes.size() <= plan().static_end);
    /// `size` bytes of the static region, zero at entry, for scratch use.
    [[nodiscard]] std::uint32_t reserve(const std::uint32_t size, const std::uint32_t align)
        BO_PRE(align == 1 || align == 2 || align == 4 || align == 8)
            BO_POST(r, r % align == 0 && r + size <= plan().static_end);

    /// Exports `f` as "cexchain_call".
    void entry(Func f) BO_PRE(is_function(f) && f.index >= host_count && type_of(f) == FuncType{});

    /// The module's bytes. Every function must be defined and the entry set.
    /// Errc::unsupported or Errc::malformed if `vm::load` refuses the module
    /// (a bug in the emitter).
    [[nodiscard]] Result<Bytes> finish() const;

private:
    struct Function {
        FuncType type;
        std::optional<Bytes> body;
        std::uint32_t max_height = 0;
        CostNode cost;
        std::vector<std::uint64_t> size_defaults;
        std::uint32_t slots = 0;
        BoundFormula formula;
    };
    /// What an evaluation leaves out, and the functions it is inside.
    struct Evaluation {
        std::span<const Func> skip;
        std::uint32_t absent = 0;
        std::vector<std::uint32_t> active;
    };
    [[nodiscard]] Bound evaluate(const CostNode& node, std::vector<std::uint64_t>& env,
                                 Evaluation& e) const;
    [[nodiscard]] Bound bound_of(Func f, std::vector<std::uint64_t> sizes, Evaluation& e) const;
    struct GlobalEntry {
        ValType type = ValType::i32;
        std::int64_t initial = 0;
    };

    MemoryPlan plan_;
    std::vector<Function> functions_;
    std::vector<GlobalEntry> globals_;
    std::optional<Func> entry_;
    /// The static region from its base, as far as it is used.
    Bytes statics_;
    std::map<Bytes, std::uint32_t> interned_;
    mutable std::map<std::tuple<std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>, Bound>
        bounds_;
};

} // namespace cexchain::bo::wasm
