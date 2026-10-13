// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <cexchain/bo/source.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/statement.hpp>

#include "args.hpp"
#include "output.hpp"

/// Contracts written in Bo (D-053, milestone 7), for the contract commands:
/// building a deploy from a source or a .boc file, and checking a deploy's
/// source against its code. Every build has the second, but only builds
/// with the Bo compiler (GCC 16) can rebuild; the others say so.
namespace cexchain::cli {

/// True if this build has the Bo compiler.
[[nodiscard]] bool have_bo_compiler() noexcept;

/// A deploy's source, checked against its code.
struct SourceCheck {
    /// rebuilds, differs, malformed, other-compiler, or not-rebuilt (this
    /// build has no compiler).
    std::string status;
    /// What was found, for people.
    std::string detail;
    /// The check fails verification: the source is not the code's
    /// (differs), or it cannot be (malformed).
    bool failed = false;
    /// The bundle, if it decodes.
    std::optional<bo::SourceBundle> bundle;
};

/// Checks the source of a deploy whose language is bo, under the home's
/// hash: rebuilds it where the compiler is, else checks what the front end
/// can (the bundle and its packs).
[[nodiscard]] SourceCheck check_bo_source(const protocol::ContractDeployBody& deploy,
                                          const crypto::Provider& provider, crypto::HashAlg hash);

/// The check as JSON: status, detail, the compilers, and the bundle's
/// edition, size, and packs.
[[nodiscard]] Json source_check_json(const SourceCheck& check,
                                     const protocol::ContractDeployBody& deploy);
/// "Bo, edition 1: 812 bytes of source; packs en 1, zh-Hans-CN 1, zh-Hant-HK 1".
[[nodiscard]] std::string bundle_text(const SourceCheck& check);
/// "rebuilds: ...", "DOES NOT REBUILD: ...", "MALFORMED: ...", or
/// "not rebuilt: ...".
[[nodiscard]] std::string source_check_text(const SourceCheck& check);

/// A deploy built from FILE: Bo source (.bo, read with the packs of
/// --pack), or a .boc file that `bo build --out` wrote (which must rebuild
/// here to its code). The bundle's digests use the home's hash. Warnings go
/// to stderr; a source that does not build ends the command.
struct BoDeploy {
    protocol::ContractDeployBody body;
    /// What `bo build --json` shows of the build.
    Json build;
};
[[nodiscard]] BoDeploy bo_deploy_body(const Args& args, const std::string& file,
                                      const crypto::Provider& provider, crypto::HashAlg hash);

} // namespace cexchain::cli
