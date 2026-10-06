// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record.hpp>

#include "support.hpp"

/// Record operations shared by the command line and the MCP server.
namespace cexchain::cli {

using verifier::display_value;

struct IssueRequest {
    std::string record_type;
    std::vector<std::pair<std::string, std::string>> fields;
    std::vector<std::pair<std::string, std::string>> metadata;
    /// Metadata as a CBOR map, for values that are not text; replaces
    /// `metadata`.
    std::optional<cbor::Value> metadata_value;
    std::vector<std::filesystem::path> attachments;
    std::optional<std::string> delegation;
    std::optional<protocol::Provenance> provenance;
    /// Prove presence first, if set.
    std::optional<PresenceRequest> presence;
};

/// Commits to the fields and attachments, registers the record, and keeps
/// the private data (values and salts) in the ledger directory's vault.
protocol::Id issue_record(Session& session, const crypto::Signer& signer,
                          const IssueRequest& request);

struct VaultAttachment {
    std::string name;
    protocol::Nonce salt{};
};

/// The private data behind a record's commitments.
struct Vault {
    std::vector<protocol::RecordField> fields;
    std::vector<VaultAttachment> attachments;
};

// The vault holds the private data behind each record's commitments: field
// values, salts, and attachment salts. Vault files are sealed with HPKE to the
// ledger's vault public key (<ledger>/vault.pub), so anyone who can issue
// records, AI agents included, can add to the vault, but only holders of the
// vault private key can read it. Each file is bound to its ledger and record.
//
//   sealed file   = {1: 1, 2: [kem, kdf, aead], 3: encapsulated key, 4: ciphertext}
//   vault.pub     = {1: kem, 2: public key}
//
// Vaults written before sealing existed hold the plaintext content directly
// ({1: fields, 2: attachments}); `cexchain vault rekey` seals them.

/// The HPKE `info` for vault files.
inline constexpr std::string_view vault_info = "CexChain record vault v1";

[[nodiscard]] Bytes encode_vault_public_key(ByteView key);
/// The X25519 key in a vault public key file, if it is one.
[[nodiscard]] std::optional<Bytes> decode_vault_public_key(ByteView file);
/// <ledger>/vault: vault.pub, vault.key (unless kept elsewhere), and
/// records/<record id>.cbor. Rekeying swaps in a whole new directory.
[[nodiscard]] std::filesystem::path vault_directory(const Session& session);
[[nodiscard]] std::filesystem::path vault_public_key_path(const Session& session);
[[nodiscard]] std::filesystem::path default_vault_key_path(const Session& session);
/// The ledger's vault public key; throws if the ledger has none.
[[nodiscard]] Bytes vault_public_key(const Session& session);
/// Loads the vault private key from --vault-key (default <ledger>/vault.key)
/// and checks that it matches the ledger's vault public key.
[[nodiscard]] crypto::openssl::HpkeKey load_vault_key(const Session& session, const Args& args);
/// Writes a vault private key file, encrypted with `secret` if given.
void save_hpke_key(const std::filesystem::path& path, const crypto::openssl::HpkeKey& key,
                   const std::optional<std::string>& secret);
/// Loads a vault private key file (asking for its passphrase if needed).
[[nodiscard]] crypto::openssl::HpkeKey load_hpke_key(const std::filesystem::path& path,
                                                     const Args& args);

[[nodiscard]] bool is_sealed_vault(ByteView file);
[[nodiscard]] Bytes seal_vault(const protocol::Id& ledger, const protocol::Id& record,
                               const Vault& vault, ByteView public_key);
/// Seals the record's private data to the ledger's vault public key.
void save_vault(const Session& session, const protocol::Id& record, const Vault& vault);
/// Reads a record's private data; `key` is needed unless the file predates
/// sealing.
[[nodiscard]] Vault load_vault(const Session& session, const protocol::Id& record,
                               const crypto::openssl::HpkeKey* key);
/// Reads a record's private data, loading the vault key (--vault-key) only if
/// the file is sealed.
[[nodiscard]] Vault read_vault(const Session& session, const protocol::Id& record,
                               const Args& args);

} // namespace cexchain::cli
