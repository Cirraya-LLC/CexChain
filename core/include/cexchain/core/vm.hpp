// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Contract execution (spec section 14): WebAssembly modules restricted to a
/// deterministic, integer-only profile, run with fuel. For a module and an
/// input, every conforming implementation reaches the same outcome (the same
/// output or the same trap) and uses the same fuel, so a contract call that
/// the home ledger ran can be replayed by anyone, in the browser too.
namespace cexchain::vm {

/// Fuel for one invocation of `cexchain_call`.
inline constexpr std::uint64_t fuel_limit = 10'000'000;
inline constexpr std::size_t max_module_size = 524'288;
inline constexpr std::uint32_t max_types = 1024;
inline constexpr std::uint32_t max_params = 32;
inline constexpr std::uint32_t max_results = 16;
inline constexpr std::uint32_t max_functions = 10'000;
inline constexpr std::uint32_t max_locals = 4096;
inline constexpr std::uint32_t max_body_size = 131'072;
inline constexpr std::uint32_t max_globals = 1024;
inline constexpr std::uint32_t max_table = 1024;
inline constexpr std::uint32_t max_pages = 16;
inline constexpr std::uint32_t page_size = 65'536;
inline constexpr std::uint32_t max_data = 1U << 20U;
inline constexpr std::uint32_t max_stack_height = 65'535;
inline constexpr std::uint32_t max_nesting = 1024;
inline constexpr std::uint32_t max_call_depth = 256;
inline constexpr std::uint32_t stack_budget = 131'072;
inline constexpr std::uint32_t max_output = 1U << 20U;
inline constexpr std::uint32_t max_abort_reason = 1024;

enum class Trap : std::uint8_t {
    unreachable = 1,
    divide_by_zero,
    integer_overflow,
    out_of_bounds,
    indirect_call_out_of_range,
    indirect_call_to_null,
    indirect_call_type_mismatch,
    out_of_fuel,
    call_depth_exceeded,
    stack_budget_exceeded,
    output_written_twice,
    output_too_large,
    aborted,
};

/// The trap's name in the spec, e.g. "out of fuel".
[[nodiscard]] std::string_view name(Trap trap) noexcept;

namespace detail {
struct ModuleData;
}

/// A module that is in the profile, decoded and validated, ready to run.
/// Cheap to copy.
class Module {
public:
    /// The module's bytes as loaded.
    [[nodiscard]] ByteView bytes() const noexcept;
    [[nodiscard]] const detail::ModuleData& data() const noexcept { return *data_; }

private:
    explicit Module(std::shared_ptr<const detail::ModuleData> data) : data_(std::move(data)) {}
    std::shared_ptr<const detail::ModuleData> data_;
    friend Result<Module> load(ByteView wasm);
};

/// Decodes and validates a module. Errc::unsupported for a module outside the
/// profile, Errc::malformed for one that is not valid WebAssembly.
[[nodiscard]] Result<Module> load(ByteView wasm);

struct Outcome {
    /// Unset if the invocation returned normally.
    std::optional<Trap> trap;
    /// What `output_write` wrote (empty if nothing, or on a trap).
    Bytes output;
    std::uint64_t fuel_used = 0;
    /// With Trap::aborted: the first bytes of the contract's reason.
    Bytes abort_reason;

    [[nodiscard]] bool ok() const noexcept { return !trap; }
};

/// Runs `cexchain_call` once with `input`; `hash` is the ledger's hash, for
/// the `hash` host function. Fails only if the crypto backend does.
[[nodiscard]] Result<Outcome> run(const Module& module, ByteView input,
                                  const crypto::Provider& provider, crypto::HashAlg hash);

} // namespace cexchain::vm
