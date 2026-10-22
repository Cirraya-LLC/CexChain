// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/lower.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Part of cexchain::bo, the compiler proper (GCC 16). Building a source all
/// the way (lex, parse, check, lower), and rebuilding a deploy from the
/// bo-source bundle it carries to compare it with its code.
namespace cexchain::bo {

/// This compiler: its release (the project's version), codegen version, and
/// edition.
[[nodiscard]] const CompilerId& this_compiler() noexcept;
/// "cexchain-bo RELEASE; codegen N; edition E", what a deploy records.
[[nodiscard]] std::string compiler_string();

struct Compiled {
    /// The source's edition (`bo N`, else 1).
    std::uint64_t edition = 1;
    /// Comment lines, which the deploy publishes with the source.
    std::size_t comments = 0;
    /// From `contract NAME`, if the source checked.
    std::string name;
    /// Every problem, in source order (those without a place last): the
    /// lexer's and the parser's; the checker's on a tree without errors;
    /// lowering's on a model without errors; and, once it builds, a warning
    /// that comments are published.
    std::vector<Diagnostic> diagnostics;
    /// Set if it checked without errors: the checked model (its tests
    /// included, which `bo test` runs on the build).
    std::optional<model::Model> model;
    /// Set if it built: the module (which vm::load accepts) and interface.
    std::optional<Build> build;
};

struct CompileOptions {
    /// The codegen version to write: this compiler's, or an earlier one it
    /// still writes (to rebuild a deploy made with it).
    std::uint32_t codegen = wasm::codegen_version;
    /// Refuse code that a call could run out of fuel in (build.fuel: a
    /// function's bound beyond the 10,000,000 a call has), and warn when a
    /// call's output could exceed what the code has for it (build.output).
    /// A rebuild only compares bytes, so it does not.
    bool check_bounds = true;
};

/// Builds a source read with `packs`. A fragment (no contract line),
/// anything that needs executors, and (with check_bounds) code whose fuel
/// bound exceeds a call's fuel do not build.
[[nodiscard]] Compiled compile(std::string_view source, const PackSet& packs,
                               const CompileOptions& options = {});

/// The fuel bound of one call: the function's bound, with
/// reading counted for this input's own items and map keys instead of the
/// most a call's input can hold, so that a test can check the bound against
/// a call's fuel closely. None if the input does not decode, names no
/// function of the build, or holds a map key longer than
/// runtime::max_key_size (read_input_fuel counts no such key).
[[nodiscard]] std::optional<std::uint64_t> bound_for(const Build& build, ByteView input);

enum class RebuildStatus : std::uint8_t {
    /// The source builds to the deployed code, interface, and name.
    rebuilds,
    /// With the compiler the deploy names, the source does not build to what
    /// was deployed: the source is not the code's.
    differs,
    /// No source, or not a bo-source bundle, or packs in it that do not
    /// check: nothing that could be rebuilt.
    malformed,
    /// Built by another compiler, or another version of this one (its
    /// release, codegen, or official packs), whose output this one does not
    /// reproduce: rebuild with that compiler.
    other_compiler,
};

inline constexpr std::array<std::string_view, 4> rebuild_status_names{
    "rebuilds", "differs", "malformed", "other-compiler"};

struct Rebuild {
    RebuildStatus status = RebuildStatus::malformed;
    /// What was found, for people (English).
    std::string detail;
    /// The compiler the deploy names, if it is cexchain-bo.
    std::optional<CompilerId> deployed;
    /// The source bundle, if it decodes.
    std::optional<SourceBundle> bundle;
    /// What this compiler built from it, if it built.
    std::optional<Build> build;
    /// Why it did not build, if it did not.
    std::vector<Diagnostic> diagnostics;
};

/// Rebuilds a deploy whose language is `bo` from its source, reading the
/// bundle's pack digests with the home's hash, and compares the result with
/// the deploy's code, interface, and name. A deploy that names a codegen
/// version this compiler still writes (wasm::oldest_codegen_version on) is
/// rebuilt as that version. "Differs" only when the deploy names such a
/// codegen and this compiler's edition (and, for the official packs, its
/// release): another version's output is reported as such, never as a
/// forgery.
[[nodiscard]] Rebuild rebuild(const protocol::ContractDeployBody& deploy,
                              const crypto::Provider& provider, crypto::HashAlg home_hash);

} // namespace cexchain::bo
