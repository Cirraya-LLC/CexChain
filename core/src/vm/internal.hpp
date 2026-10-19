// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/vm.hpp>

/// The loaded form of a module. Validation also translates each function body
/// into a flat array of instructions with resolved branch targets and operand
/// stack heights, so the interpreter never decodes LEB128 or searches for a
/// block's end at run time.
namespace cexchain::vm::detail {

inline constexpr std::uint8_t type_i32 = 0x7F;
inline constexpr std::uint8_t type_i64 = 0x7E;

struct FuncType {
    std::vector<std::uint8_t> params;
    std::vector<std::uint8_t> results;

    friend bool operator==(const FuncType&, const FuncType&) = default;
};

enum class Host : std::uint8_t { none, input_size, input_read, output_write, hash, abort };

/// Operations of the translated code. Values below 0x100 are the WebAssembly
/// opcodes they come from; the others have no single opcode.
enum Op : std::uint16_t {
    op_unreachable = 0x00,
    op_nop = 0x01, ///< Also block and loop, which cost fuel and do nothing else.
    op_if = 0x04,
    op_br = 0x0C,
    op_br_if = 0x0D,
    op_br_table = 0x0E,
    op_return = 0x0F,
    op_call = 0x10,
    op_call_indirect = 0x11,
    op_drop = 0x1A,
    op_select = 0x1B, ///< Also select with a type.
    op_local_get = 0x20,
    op_local_set = 0x21,
    op_local_tee = 0x22,
    op_global_get = 0x23,
    op_global_set = 0x24,
    // Loads and stores keep their opcodes, 0x28 to 0x3E.
    op_memory_size = 0x3F,
    op_memory_grow = 0x40,
    op_i32_const = 0x41,
    op_i64_const = 0x42,
    // Numeric instructions keep their opcodes, 0x45 to 0xC4.
    op_else = 0x100, ///< The end of a then-branch: jumps to the end, without fuel.
    op_end_function, ///< The function's final end: returns, without fuel.
    op_memory_init,  ///< a: the data segment.
    op_data_drop,    ///< a: the data segment.
    op_memory_copy,
    op_memory_fill,
};

/// One translated instruction. Its fields depend on the operation:
///   - if: `a` is where to continue when the condition is false;
///   - else: `a` is the instruction after the end;
///   - br, br_if: `a` is the target, `arity` the values carried, `b` the
///     operand stack height (from the frame's base) at the target;
///   - br_table: `a` is the first of its `b` + 1 entries in the function's
///     branch table, the last one being the default;
///   - return: `arity` is the number of results;
///   - call: `a` is the function; call_indirect: `a` is the type;
///   - locals and globals: `a` is the index;
///   - loads and stores: `b` is the offset;
///   - constants: `b` is the value (an i32 in its low 32 bits).
struct Instr {
    std::uint16_t op = op_nop;
    std::uint16_t arity = 0;
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
    std::uint32_t max_height = 0;
    std::vector<Instr> code;
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

/// Runs with a fuel limit other than the protocol's, for fuzzing: the public
/// `run` is this with fuel_limit.
[[nodiscard]] Result<Outcome> run(const Module& module, ByteView input,
                                  const crypto::Provider& provider, crypto::HashAlg hash,
                                  std::uint64_t fuel, Arena& arena);
[[nodiscard]] Result<Outcome> run(const Module& module, ByteView input,
                                  const crypto::Provider& provider, crypto::HashAlg hash,
                                  std::uint64_t fuel);

} // namespace cexchain::vm::detail
