// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/verifier/report.hpp>

#include "args.hpp"

namespace cexchain::cli {

using verifier::format_time;
using verifier::iso_time;
using verifier::kind_label;

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
/// Parses "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SSZ" (UTC).
[[nodiscard]] protocol::Timestamp parse_time(std::string_view text);

/// A key passphrase, for the key file named `purpose`: read from the
/// `file_option` file if given, else from the `env` variable, else asked for
/// on the terminal (twice if `confirm`).
[[nodiscard]] std::string passphrase(const Args& args, const std::string& purpose,
                                     bool confirm = false,
                                     std::string_view file_option = "passphrase-file",
                                     const char* env = "CEXCHAIN_PASSPHRASE");

/// Loads a private key file, asking for its passphrase if it is encrypted.
[[nodiscard]] crypto::openssl::KeyPair load_key(const std::filesystem::path& path,
                                                const Args& args);

/// Writes a private key file (owner-only permissions), encrypted with
/// `secret` if given.
void save_key(const std::filesystem::path& path, const crypto::openssl::KeyPair& key,
              const std::optional<std::string>& secret);

/// A public key file holds the deterministic CBOR encoding of [alg, key].
[[nodiscard]] Bytes encode_public_key_file(const crypto::PublicKey& key);
/// Loads a public key file. Private key files are refused, so that verifiers
/// never need anyone's private key.
[[nodiscard]] crypto::PublicKey load_public_key(const std::filesystem::path& path);
/// The public key in a public key file, or in a private key file (asking for
/// its passphrase if needed).
[[nodiscard]] crypto::PublicKey public_key_of(const std::filesystem::path& path, const Args& args);

[[nodiscard]] Bytes hash_text(const crypto::Provider& provider, crypto::HashAlg hash,
                              std::string_view text);
[[nodiscard]] std::vector<std::string> split(const std::string& text, char separator);
/// Splits NAME=VALUE.
[[nodiscard]] std::pair<std::string, std::string> split_pair(const std::string& text,
                                                             std::string_view what);
[[nodiscard]] std::uint64_t parse_number(std::string_view text, std::string_view what);
[[nodiscard]] crypto::SigAlg parse_algorithm(std::string_view name);
[[nodiscard]] crypto::HashAlg parse_hash(std::string_view name);
[[nodiscard]] protocol::StatementType parse_statement_type(std::string_view name);
[[nodiscard]] protocol::ActorKind parse_actor_kind(std::string_view name);

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
    /// With `presence` set, the signer (a person) first proves presence with
    /// a passkey in the browser; the value says whether to open the browser.
    protocol::Id submit(const crypto::Signer& signer, protocol::Body body,
                        const std::optional<std::string>& delegation,
                        std::optional<protocol::Provenance> provenance = std::nullopt,
                        std::optional<bool> presence = std::nullopt);

    /// Signs and submits as the holder of --as, with --delegation, --model,
    /// --model-version, --inputs, --presence, and --no-browser taken from
    /// `args`.
    protocol::Id submit(const Args& args, protocol::Body body);

    /// AI provenance from --model, --model-version, and --inputs (hashed).
    [[nodiscard]] std::optional<protocol::Provenance> provenance(const Args& args) const;

    /// Resolves an index or (abbreviated) statement id to a log index.
    [[nodiscard]] std::uint64_t entry_index(std::string_view text) const;

    /// The log entry at `index` and its statement, parsed.
    [[nodiscard]] protocol::LogEntry log_entry(std::uint64_t index) const;
    [[nodiscard]] protocol::SignedStatement statement(std::uint64_t index) const;

    /// The actor's display name, or "unknown" for an unknown id.
    [[nodiscard]] std::string actor_name(const protocol::Id& id) const;

    [[nodiscard]] std::filesystem::path vault_path(const protocol::Id& record) const;

private:
    void prove_presence(const protocol::ActorState& actor, protocol::Statement& statement,
                        const crypto::PublicKey& signing_key, bool open_browser) const;

    [[nodiscard]] std::optional<protocol::Id>
    choose_delegation(const protocol::ActorState& actor, protocol::StatementType type,
                      const std::optional<std::string>& record_type) const;

    std::filesystem::path directory_;
    std::optional<ledger::DirectoryLock> lock_;
    crypto::openssl::Provider provider_;
    ledger::SystemClock clock_;
    ledger::SystemEntropy entropy_;
    std::optional<ledger::PosixFileSystem> fs_;
    std::optional<ledger::Ledger> ledger_;
};

/// Finishes or discards an interrupted `vault rekey` (call with the ledger
/// locked).
void recover_vault_swap(const std::filesystem::path& directory);

/// Creates a ledger in `directory`.
void create_ledger(const std::filesystem::path& directory, const crypto::Signer& root_key,
                   const crypto::PublicKey& log_key, crypto::HashAlg hash,
                   const std::string& organization);

} // namespace cexchain::cli
