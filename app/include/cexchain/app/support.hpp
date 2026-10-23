// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/app/errors.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/verify.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/verifier/report.hpp>

/// Helpers every action uses: errors, files, ids, times, keys, and parsing.
namespace cexchain::app {

/// How actions verify evidence: signatures checked ahead on all cores, and
/// remembered for the process (the MCP server verifies again and again).
[[nodiscard]] inline ledger::Verifying on_all_cores() {
    return {true, &ledger::signature_cache()};
}

using verifier::format_time;
using verifier::iso_time;
using verifier::kind_label;

/// Unwraps a result or throws an ActionError that names what failed.
template <class T>
T unwrap(Result<T> result, std::string_view what) {
    if (!result) {
        throw ActionError{std::string(what) + ": " + std::string(result.error().detail) + " (" +
                          std::string(to_string(result.error().code)) + ")"};
    }
    return std::move(*result);
}

inline void unwrap(Status status, std::string_view what) {
    if (!status) {
        throw ActionError{std::string(what) + ": " + std::string(status.error().detail) + " (" +
                          std::string(to_string(status.error().code)) + ")"};
    }
}

[[nodiscard]] Bytes read_file(const std::filesystem::path& path);
/// Writes atomically (temporary file, fsync, rename). `private_file` sets
/// permissions to owner-only.
void write_file(const std::filesystem::path& path, ByteView data, bool private_file);
/// A pkcs11: URI with any pin-value hidden, for printing.
[[nodiscard]] std::string redact_pin(std::string_view uri);

[[nodiscard]] std::string hex_id(const protocol::Id& id);
[[nodiscard]] std::string short_id(const protocol::Id& id);
/// Parses "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SSZ" (UTC).
[[nodiscard]] protocol::Timestamp parse_time(std::string_view text);

/// The provider every key and token in this process uses.
[[nodiscard]] const crypto::openssl::Provider& shared_provider();

/// Asks for a key file's passphrase, when the file is encrypted.
using PassphraseSource = std::function<std::string()>;

/// Loads a private key file, asking `passphrase` only if it is encrypted.
[[nodiscard]] crypto::openssl::KeyPair load_key(const std::filesystem::path& path,
                                                const PassphraseSource& passphrase);

/// Writes a private key file (owner-only permissions), encrypted with
/// `secret` if given.
void save_key(const std::filesystem::path& path, const crypto::openssl::KeyPair& key,
              const std::optional<std::string>& secret);

/// A public key file holds the deterministic CBOR encoding of [alg, key].
[[nodiscard]] Bytes encode_public_key_file(const crypto::PublicKey& key);
/// Loads a public key file. Private key files are refused, so that verifiers
/// never need anyone's private key.
[[nodiscard]] crypto::PublicKey load_public_key(const std::filesystem::path& path);

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

/// A client for the API at `url`, with an API token and, if given, the CA
/// certificates to trust.
[[nodiscard]] node::Client client_for(const std::string& url, std::optional<std::string> token,
                                      const std::optional<std::string>& ca_file);

/// Finishes or discards an interrupted `vault rekey` (call with the ledger
/// locked).
void recover_vault_swap(const std::filesystem::path& directory);

/// Creates a ledger in `directory`.
void create_ledger(const std::filesystem::path& directory, const crypto::Signer& root_key,
                   const crypto::PublicKey& log_key, crypto::HashAlg hash,
                   const std::string& organization);

} // namespace cexchain::app
