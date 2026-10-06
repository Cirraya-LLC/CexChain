// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/storage.hpp>

#include "args.hpp"

namespace cexchain::cli {

/// Unwraps a result or throws a CommandError that names what failed.
template <class T>
T unwrap(Result<T> result, std::string_view what) {
    if (!result) {
        throw CommandError{std::string(what) + ": " + std::string(result.error().detail) + " (" +
                           std::string(to_string(result.error().code)) + ")"};
    }
    return std::move(*result);
}

inline void unwrap(Status status, std::string_view what) {
    if (!status) {
        throw CommandError{std::string(what) + ": " + std::string(status.error().detail) + " (" +
                           std::string(to_string(status.error().code)) + ")"};
    }
}

[[nodiscard]] Bytes read_file(const std::filesystem::path& path);
/// Writes atomically (temporary file, fsync, rename). `private_file` sets
/// permissions to owner-only.
void write_file(const std::filesystem::path& path, ByteView data, bool private_file);

[[nodiscard]] std::string hex_id(const protocol::Id& id);
[[nodiscard]] std::string short_id(const protocol::Id& id);
[[nodiscard]] std::string format_time(protocol::Timestamp ms);
/// Parses "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SSZ" (UTC).
[[nodiscard]] protocol::Timestamp parse_time(std::string_view text);

[[nodiscard]] crypto::openssl::KeyPair load_key(const std::filesystem::path& path);
[[nodiscard]] crypto::SigAlg parse_algorithm(std::string_view name);
[[nodiscard]] crypto::HashAlg parse_hash(std::string_view name);
[[nodiscard]] protocol::StatementType parse_statement_type(std::string_view name);
[[nodiscard]] protocol::ActorKind parse_actor_kind(std::string_view name);
[[nodiscard]] std::string_view kind_name(const std::optional<protocol::ActorKind>& kind);

/// An open ledger directory with the environment needed to act on it.
class Session {
public:
    explicit Session(const std::filesystem::path& directory);

    [[nodiscard]] ledger::Ledger& ledger() { return *ledger_; }
    [[nodiscard]] const protocol::LedgerState& state() const { return ledger_->state(); }
    [[nodiscard]] const crypto::Provider& provider() const { return provider_; }
    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

    /// Resolves a full or abbreviated (8+ hex digits) identifier among actors,
    /// delegations, or records.
    [[nodiscard]] protocol::Id actor_id(std::string_view text) const;
    [[nodiscard]] protocol::Id record_id(std::string_view text) const;
    [[nodiscard]] protocol::Id delegation_id(std::string_view text) const;

    /// The actor holding `key`.
    [[nodiscard]] const protocol::ActorState& actor_for(const crypto::Signer& key) const;

    /// Builds, signs, and submits a statement by the holder of `signer`,
    /// choosing a delegation that covers it unless `delegation` is given, and
    /// filling in provenance for agents. Returns the statement's id.
    protocol::Id submit(const crypto::Signer& signer, protocol::Body body,
                        const std::optional<std::string>& delegation,
                        std::optional<protocol::Provenance> provenance = std::nullopt);

    [[nodiscard]] std::filesystem::path vault_path(const protocol::Id& record) const;

private:
    [[nodiscard]] std::optional<protocol::Id>
    choose_delegation(const protocol::ActorState& actor, protocol::StatementType type,
                      const std::optional<std::string>& record_type) const;

    std::filesystem::path directory_;
    crypto::openssl::Provider provider_;
    ledger::SystemClock clock_;
    ledger::SystemEntropy entropy_;
    std::optional<ledger::PosixFileSystem> fs_;
    std::optional<ledger::Ledger> ledger_;
};

/// Creates a ledger in `directory`.
void create_ledger(const std::filesystem::path& directory, const crypto::Signer& root_key,
                   const crypto::PublicKey& log_key, crypto::HashAlg hash,
                   const std::string& organization);

} // namespace cexchain::cli
