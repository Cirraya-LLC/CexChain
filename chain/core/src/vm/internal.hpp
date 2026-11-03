// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/vm.hpp>

/// The loaded form of a module. Validation also translates each function body
/// into a flat array of the interpreter's own instructions: branch targets and
/// operand stack heights resolved, `block` and `loop` markers gone (their fuel
/// moved to the instruction that follows them), frequent sequences fused into
/// one instruction, and the fuel of each straight-line run of instructions
/// charged once, by its first instruction.
namespace cexchain::vm::detail {

inline constexpr std::uint8_t type_i32 = 0x7F;
inline constexpr std::uint8_t type_i64 = 0x7E;

struct FuncType {
    std::vector<std::uint8_t> params;
    std::vector<std::uint8_t> results;

    friend bool operator==(const FuncType&, const FuncType&) = default;
};

enum class Host : std::uint8_t { none, input_size, input_read, output_write, hash, abort };

// Instructions with one WebAssembly opcode each: X(name, opcode, ...).

/// Binary operations that cannot trap, comparisons and arithmetic: Y(X, name,
/// opcode) for each, so that lists of fused instructions can be made from
/// them.
#define CEXCHAIN_VM_I32_COMPARE_LIST(X, Y)                                                         \
    Y(X, i32_eq, 0x46)                                                                             \
    Y(X, i32_ne, 0x47)                                                                             \
    Y(X, i32_lt_s, 0x48)                                                                           \
    Y(X, i32_lt_u, 0x49)                                                                           \
    Y(X, i32_gt_s, 0x4A)                                                                           \
    Y(X, i32_gt_u, 0x4B)                                                                           \
    Y(X, i32_le_s, 0x4C)                                                                           \
    Y(X, i32_le_u, 0x4D)                                                                           \
    Y(X, i32_ge_s, 0x4E)                                                                           \
    Y(X, i32_ge_u, 0x4F)
#define CEXCHAIN_VM_I32_ARITHMETIC_LIST(X, Y)                                                      \
    Y(X, i32_add, 0x6A)                                                                            \
    Y(X, i32_sub, 0x6B)                                                                            \
    Y(X, i32_mul, 0x6C)                                                                            \
    Y(X, i32_and, 0x71)                                                                            \
    Y(X, i32_or, 0x72)                                                                             \
    Y(X, i32_xor, 0x73)                                                                            \
    Y(X, i32_shl, 0x74)                                                                            \
    Y(X, i32_shr_s, 0x75)                                                                          \
    Y(X, i32_shr_u, 0x76)                                                                          \
    Y(X, i32_rotl, 0x77)                                                                           \
    Y(X, i32_rotr, 0x78)
#define CEXCHAIN_VM_I64_COMPARE_LIST(X, Y)                                                         \
    Y(X, i64_eq, 0x51)                                                                             \
    Y(X, i64_ne, 0x52)                                                                             \
    Y(X, i64_lt_s, 0x53)                                                                           \
    Y(X, i64_lt_u, 0x54)                                                                           \
    Y(X, i64_gt_s, 0x55)                                                                           \
    Y(X, i64_gt_u, 0x56)                                                                           \
    Y(X, i64_le_s, 0x57)                                                                           \
    Y(X, i64_le_u, 0x58)                                                                           \
    Y(X, i64_ge_s, 0x59)                                                                           \
    Y(X, i64_ge_u, 0x5A)
#define CEXCHAIN_VM_I64_ARITHMETIC_LIST(X, Y)                                                      \
    Y(X, i64_add, 0x7C)                                                                            \
    Y(X, i64_sub, 0x7D)                                                                            \
    Y(X, i64_mul, 0x7E)                                                                            \
    Y(X, i64_and, 0x83)                                                                            \
    Y(X, i64_or, 0x84)                                                                             \
    Y(X, i64_xor, 0x85)                                                                            \
    Y(X, i64_shl, 0x86)                                                                            \
    Y(X, i64_shr_s, 0x87)                                                                          \
    Y(X, i64_shr_u, 0x88)                                                                          \
    Y(X, i64_rotl, 0x89)                                                                           \
    Y(X, i64_rotr, 0x8A)
#define CEXCHAIN_VM_COMPARE_LIST(X, Y)                                                             \
    CEXCHAIN_VM_I32_COMPARE_LIST(X, Y) CEXCHAIN_VM_I64_COMPARE_LIST(X, Y)
#define CEXCHAIN_VM_BINARY_LIST(X, Y)                                                              \
    CEXCHAIN_VM_I32_COMPARE_LIST(X, Y)                                                             \
    CEXCHAIN_VM_I32_ARITHMETIC_LIST(X, Y)                                                          \
    CEXCHAIN_VM_I64_COMPARE_LIST(X, Y)                                                             \
    CEXCHAIN_VM_I64_ARITHMETIC_LIST(X, Y)
#define CEXCHAIN_VM_AS_IS(X, name, ...) X(name, __VA_ARGS__)
#define CEXCHAIN_VM_BINARY(X) CEXCHAIN_VM_BINARY_LIST(X, CEXCHAIN_VM_AS_IS)

/// Division and remainder, which trap on a zero divisor (and div_s on
/// overflow): X(name, opcode).
#define CEXCHAIN_VM_DIVISION(X)                                                                    \
    X(i32_div_s, 0x6D)                                                                             \
    X(i32_div_u, 0x6E)                                                                             \
    X(i32_rem_s, 0x6F)                                                                             \
    X(i32_rem_u, 0x70)                                                                             \
    X(i64_div_s, 0x7F)                                                                             \
    X(i64_div_u, 0x80)                                                                             \
    X(i64_rem_s, 0x81)                                                                             \
    X(i64_rem_u, 0x82)

/// Operations on one value: X(name, opcode).
#define CEXCHAIN_VM_UNARY(X)                                                                       \
    X(i32_eqz, 0x45)                                                                               \
    X(i64_eqz, 0x50)                                                                               \
    X(i32_clz, 0x67)                                                                               \
    X(i32_ctz, 0x68)                                                                               \
    X(i32_popcnt, 0x69)                                                                            \
    X(i64_clz, 0x79)                                                                               \
    X(i64_ctz, 0x7A)                                                                               \
    X(i64_popcnt, 0x7B)                                                                            \
    X(i32_wrap_i64, 0xA7)                                                                          \
    X(i64_extend_i32_s, 0xAC)                                                                      \
    X(i64_extend_i32_u, 0xAD)                                                                      \
    X(i32_extend8_s, 0xC0)                                                                         \
    X(i32_extend16_s, 0xC1)                                                                        \
    X(i64_extend8_s, 0xC2)                                                                         \
    X(i64_extend16_s, 0xC3)                                                                        \
    X(i64_extend32_s, 0xC4)

/// Loads: X(name, opcode, bytes accessed).
#define CEXCHAIN_VM_LOADS(X)                                                                       \
    X(i32_load, 0x28, 4)                                                                           \
    X(i64_load, 0x29, 8)                                                                           \
    X(i32_load8_s, 0x2C, 1)                                                                        \
    X(i32_load8_u, 0x2D, 1)                                                                        \
    X(i32_load16_s, 0x2E, 2)                                                                       \
    X(i32_load16_u, 0x2F, 2)                                                                       \
    X(i64_load8_s, 0x30, 1)                                                                        \
    X(i64_load8_u, 0x31, 1)                                                                        \
    X(i64_load16_s, 0x32, 2)                                                                       \
    X(i64_load16_u, 0x33, 2)                                                                       \
    X(i64_load32_s, 0x34, 4)                                                                       \
    X(i64_load32_u, 0x35, 4)

/// Stores: X(name, opcode, bytes accessed).
#define CEXCHAIN_VM_STORES(X)                                                                      \
    X(i32_store, 0x36, 4)                                                                          \
    X(i64_store, 0x37, 8)                                                                          \
    X(i32_store8, 0x3A, 1)                                                                         \
    X(i32_store16, 0x3B, 2)                                                                        \
    X(i64_store8, 0x3C, 1)                                                                         \
    X(i64_store16, 0x3D, 2)                                                                        \
    X(i64_store32, 0x3E, 4)

// Fused instructions: one instruction for a frequent sequence (chosen from
// the operations Bo's contracts execute most). Within one, only the last
// WebAssembly instruction can trap, so that charging the parts one by one
// would end no differently than charging them together.

/// A binary operation on the value below and an operand of its own: X(fused,
/// operation). `_c`: const b, then the operation; `_l`: local.get a, then the
/// operation.
#define CEXCHAIN_VM_WITH_C(X, name, ...) X(name##_c, name)
#define CEXCHAIN_VM_WITH_L(X, name, ...) X(name##_l, name)
/// A binary operation on two operands of its own, pushing its result:
/// `_lc`: local.get a, const b, then the operation; `_ll`: local.get a,
/// local.get b, then the operation.
#define CEXCHAIN_VM_WITH_LC(X, name, ...) X(name##_lc, name)
#define CEXCHAIN_VM_WITH_LL(X, name, ...) X(name##_ll, name)
/// A comparison, then a branch on its result to `a`: `_if` an if (taken when
/// false), `_jump_if` a br_if with nothing to move. The comparison's operands
/// are the two values below, or (`_c_`) the value below and const b, or
/// (`_ll_`) local.gets of b's low and high 32 bits.
#define CEXCHAIN_VM_WITH_IF(X, name, ...) X(name##_if, name)
#define CEXCHAIN_VM_WITH_JUMP_IF(X, name, ...) X(name##_jump_if, name)
#define CEXCHAIN_VM_WITH_C_IF(X, name, ...) X(name##_c_if, name)
#define CEXCHAIN_VM_WITH_C_JUMP_IF(X, name, ...) X(name##_c_jump_if, name)
#define CEXCHAIN_VM_WITH_LL_IF(X, name, ...) X(name##_ll_if, name)
#define CEXCHAIN_VM_WITH_LL_JUMP_IF(X, name, ...) X(name##_ll_jump_if, name)
#define CEXCHAIN_VM_FUSED_BINARY(X)                                                                \
    CEXCHAIN_VM_BINARY_LIST(X, CEXCHAIN_VM_WITH_C)                                                 \
    CEXCHAIN_VM_BINARY_LIST(X, CEXCHAIN_VM_WITH_L)                                                 \
    CEXCHAIN_VM_BINARY_LIST(X, CEXCHAIN_VM_WITH_LC)                                                \
    CEXCHAIN_VM_BINARY_LIST(X, CEXCHAIN_VM_WITH_LL)                                                \
    CEXCHAIN_VM_COMPARE_LIST(X, CEXCHAIN_VM_WITH_IF)                                               \
    CEXCHAIN_VM_COMPARE_LIST(X, CEXCHAIN_VM_WITH_JUMP_IF)                                          \
    CEXCHAIN_VM_COMPARE_LIST(X, CEXCHAIN_VM_WITH_C_IF)                                             \
    CEXCHAIN_VM_COMPARE_LIST(X, CEXCHAIN_VM_WITH_C_JUMP_IF)                                        \
    CEXCHAIN_VM_COMPARE_LIST(X, CEXCHAIN_VM_WITH_LL_IF)                                            \
    CEXCHAIN_VM_COMPARE_LIST(X, CEXCHAIN_VM_WITH_LL_JUMP_IF)

/// A load from a local's address: local.get a, then the load (offset b):
/// X(fused, load, bytes accessed).
#define CEXCHAIN_VM_FUSED_LOADS(X)                                                                 \
    X(i32_load_l, i32_load, 4)                                                                     \
    X(i64_load_l, i64_load, 8)                                                                     \
    X(i32_load8_s_l, i32_load8_s, 1)                                                               \
    X(i32_load8_u_l, i32_load8_u, 1)                                                               \
    X(i32_load16_s_l, i32_load16_s, 2)                                                             \
    X(i32_load16_u_l, i32_load16_u, 2)                                                             \
    X(i64_load8_s_l, i64_load8_s, 1)                                                               \
    X(i64_load8_u_l, i64_load8_u, 1)                                                               \
    X(i64_load16_s_l, i64_load16_s, 2)                                                             \
    X(i64_load16_u_l, i64_load16_u, 2)                                                             \
    X(i64_load32_s_l, i64_load32_s, 4)                                                             \
    X(i64_load32_u_l, i64_load32_u, 4)

/// Other pairs:
///   - set_get: local.set a, local.get b;
///   - set_jump: local.set b, br to a with nothing to move;
///   - tee_jump_if: local.tee b, br_if to a with nothing to move;
///   - if_l, jump_if_l: local.get b, then if or br_if to a (as jump_if);
///   - call_l: local.get b, call a; call_c: const b, call a;
///   - return_l: local.get a, return of one value;
///   - const2: const a (a value below 2^32), const b.
#define CEXCHAIN_VM_FUSED_OTHER(X)                                                                 \
    X(set_get)                                                                                     \
    X(set_jump)                                                                                    \
    X(tee_jump_if)                                                                                 \
    X(if_l)                                                                                        \
    X(jump_if_l)                                                                                   \
    X(call_l)                                                                                      \
    X(call_c)                                                                                      \
    X(return_l)                                                                                    \
    X(const2)

/// The interpreter's operations without a single opcode of their own:
///   - if: `a` is where to continue when the condition is zero;
///   - jump, jump_if: `a` is the target (br and br_if with no values to
///     move, and else);
///   - br, br_if: `a` is the target, `b` the operand stack height (from the
///     frame's base) at the target | the values carried << 32;
///   - br_table: `a` is the first of its `b` + 1 entries in the function's
///     branch table, the last one being the default;
///   - return: `b` is the number of results (also the function's final end);
///   - call, call_host (an import): `a` is the function; call_indirect: `a`
///     is the type;
///   - locals and globals: `a` is the index;
///   - const: `b` is the value (an i32 in its low 32 bits; i32.const and
///     i64.const);
///   - nop: also the fuel of `block` and `loop` markers that cannot go to the
///     next instruction (a loop's body starts a run of its own);
///   - memory.init, data.drop: `a` is the data segment.
/// Targets are offsets from the branch's own instruction. Loads and stores
/// keep their offset in `b`.
#define CEXCHAIN_VM_BASIC(X)                                                                       \
    X(unreachable)                                                                                 \
    X(nop)                                                                                         \
    X(if)                                                                                          \
    X(jump)                                                                                        \
    X(jump_if)                                                                                     \
    X(br)                                                                                          \
    X(br_if)                                                                                       \
    X(br_table)                                                                                    \
    X(return)                                                                                      \
    X(call)                                                                                        \
    X(call_host)                                                                                   \
    X(call_indirect)                                                                               \
    X(drop)                                                                                        \
    X(select)                                                                                      \
    X(local_get)                                                                                   \
    X(local_set)                                                                                   \
    X(local_tee)                                                                                   \
    X(global_get)                                                                                  \
    X(global_set)                                                                                  \
    X(const)                                                                                       \
    X(memory_size)                                                                                 \
    X(memory_grow)                                                                                 \
    X(memory_init)                                                                                 \
    X(data_drop)                                                                                   \
    X(memory_copy)                                                                                 \
    X(memory_fill)

/// Every operation, in the order of Op.
#define CEXCHAIN_VM_OPS(X)                                                                         \
    CEXCHAIN_VM_BASIC(X)                                                                           \
    CEXCHAIN_VM_LOADS(X)                                                                           \
    CEXCHAIN_VM_STORES(X)                                                                          \
    CEXCHAIN_VM_UNARY(X)                                                                           \
    CEXCHAIN_VM_DIVISION(X)                                                                        \
    CEXCHAIN_VM_BINARY(X)                                                                          \
    CEXCHAIN_VM_FUSED_BINARY(X)                                                                    \
    CEXCHAIN_VM_FUSED_LOADS(X)                                                                     \
    CEXCHAIN_VM_FUSED_OTHER(X)

/// The interpreter's operations. Each translated instruction stands for one
/// WebAssembly instruction or several (the fused ones). Its fuel is not the
/// operation's but the instruction's own (`Function::costs`), so one
/// operation serves instructions of different costs: `jump` is `br` (1) and
/// `else` (0), `return` is also the function's final `end` (0).
enum Op : std::uint16_t {
#define CEXCHAIN_VM_ENUM(name, ...) op_##name,
    CEXCHAIN_VM_OPS(CEXCHAIN_VM_ENUM)
#undef CEXCHAIN_VM_ENUM
        op_count
};

/// Added to an operation: the same operation at the start of a run, which
/// first charges the run's fuel (`Instr::fuel`).
inline constexpr std::uint16_t charged = op_count;

/// One translated instruction. `a` and `b` depend on the operation (see Op).
struct Instr {
    std::uint16_t op = op_nop;
    /// At the start of a run (`op` + `charged`): the fuel of every
    /// instruction in the run.
    std::uint16_t fuel = 0;
    std::uint32_t a = 0;
    std::uint64_t b = 0;
};

struct Branch {
    std::uint32_t target = 0;
    std::uint32_t arity = 0;
    std::uint32_t height = 0;
};

struct Function {
    std::uint32_t type = 0;
    Host host = Host::none;
    /// Parameters first, then the declared locals.
    std::vector<std::uint8_t> locals;
    std::uint32_t params = 0;
    /// The locals it declares, after its parameters.
    std::uint32_t declared = 0;
    std::uint32_t max_height = 0;
    /// Its share of the stack budget: locals and maximum operand stack height.
    std::uint32_t slots = 0;
    std::vector<Instr> code;
    /// For each instruction, its own fuel: what its WebAssembly instructions
    /// cost, with the `block` and `loop` markers its fuel was moved to. A
    /// run's fuel is the sum of its instructions'.
    std::vector<std::uint16_t> costs;
    std::vector<Branch> branches;
};

struct Global {
    std::uint8_t type = type_i32;
    bool is_mutable = false;
    std::uint64_t init = 0;
};

struct Limits {
    std::uint32_t min = 0;
    std::uint32_t max = 0;
};

struct ElemSegment {
    std::uint32_t offset = 0;
    std::vector<std::uint32_t> functions;
};

struct DataSegment {
    /// Unset for a passive segment.
    std::optional<std::uint32_t> offset;
    /// Where its bytes are in the module.
    std::uint32_t begin = 0;
    std::uint32_t size = 0;
};

inline constexpr std::uint32_t null_function = 0xFFFF'FFFF;

struct ModuleData {
    Bytes bytes;
    std::vector<FuncType> types;
    /// For each type, the first type equal to it, so that call_indirect
    /// compares types with one integer comparison.
    std::vector<std::uint32_t> type_ids;
    std::vector<Function> functions;
    std::uint32_t imports = 0;
    std::optional<Limits> table;
    std::optional<Limits> memory;
    std::vector<Global> globals;
    std::vector<ElemSegment> elems;
    std::vector<DataSegment> data;
    std::optional<std::uint32_t> data_count;
    std::uint32_t entry = 0;
    /// The table after instantiation, which nothing can change later:
    /// function indices, or null_function.
    std::vector<std::uint32_t> table_functions;
};

/// How function bodies are translated. Every choice gives every run the same
/// outcome; tests and fuzzers compare them.
struct Translation {
    /// Fuse frequent sequences into one instruction.
    bool fuse = true;
    /// Charge each straight-line run's fuel at once; else every instruction
    /// is a run of its own, charged before it runs.
    bool runs = true;
};

/// How the interpreter goes from one instruction to the next: `threaded`
/// jumps from each instruction's code straight to the next one's (GCC and
/// Clang, but not for WebAssembly; elsewhere it is `table`), `table` through
/// one switch. Both give every run the same outcome; tests and fuzzers run
/// both.
enum class Dispatch : std::uint8_t { threaded, table };

/// Runs with a fuel limit other than the protocol's, for tests and fuzzing:
/// the public `run` is this with fuel_limit, threaded.
[[nodiscard]] Result<Outcome> run(const Module& module, ByteView input,
                                  const crypto::Provider& provider, crypto::HashAlg hash,
                                  std::uint64_t fuel, Arena& arena,
                                  Dispatch dispatch = Dispatch::threaded);
[[nodiscard]] Result<Outcome> run(const Module& module, ByteView input,
                                  const crypto::Provider& provider, crypto::HashAlg hash,
                                  std::uint64_t fuel);

} // namespace cexchain::vm::detail
