// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/ledger/environment.hpp>

/// Bearer tokens for the HTTP API. They only gate access: what a statement
/// may do is decided by its signature and the ledger's rules. The ledger
/// directory keeps SHA-256 hashes of tokens, never the tokens themselves.
namespace cexchain::node {

enum class Scope : std::uint8_t {
    read = 1,   ///< The log, proofs, receipts, evidence, sealed vault data, metrics.
    submit = 2, ///< Submitting signed statements.
    admin = 4,  ///< Checkpoints and witness cosignatures.
};
using Scopes = std::uint8_t;

[[nodiscard]] constexpr bool has_scope(Scopes scopes, Scope scope) noexcept {
    return (scopes & static_cast<Scopes>(scope)) != 0;
}

/// Parses "read,submit,admin" (any non-empty subset).
[[nodiscard]] Result<Scopes> parse_scopes(std::string_view list);
[[nodiscard]] std::vector<std::string> scope_names(Scopes scopes);

struct ApiToken {
    /// 1-64 characters: letters, digits, '.', '_', '-'.
    std::string name;
    Scopes scopes = 0;
    /// SHA-256 of the token, in hex.
    std::string sha256;
    protocol::Timestamp created = 0;
};

/// The tokens file in a ledger directory.
inline constexpr std::string_view tokens_file = "api-tokens";

[[nodiscard]] bool valid_token_name(std::string_view name);

/// The tokens in `ledger_directory`; none if the file does not exist.
[[nodiscard]] Result<std::vector<ApiToken>>
load_tokens(const std::filesystem::path& ledger_directory);
/// Replaces the tokens file atomically, readable by the owner only.
[[nodiscard]] Status save_tokens(const std::filesystem::path& ledger_directory,
                                 const std::vector<ApiToken>& tokens);

/// A new token: "cxt_" and 43 base64url characters (256 random bits).
[[nodiscard]] std::string generate_token(ledger::Entropy& entropy);
[[nodiscard]] std::string token_hash(const crypto::Provider& provider, std::string_view token);

/// The token whose hash matches `presented`, compared in constant time.
[[nodiscard]] const ApiToken* find_token(const std::vector<ApiToken>& tokens,
                                         const crypto::Provider& provider,
                                         std::string_view presented);

} // namespace cexchain::node
