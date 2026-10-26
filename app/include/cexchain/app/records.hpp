// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/app/session.hpp>
#include <cexchain/app/views.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record.hpp>

/// Record operations: issuing records, and their private data in the vault.
namespace cexchain::app {

using verifier::display_value;

struct IssueRequest {
    std::string record_type;
    std::vector<std::pair<std::string, std::string>> fields;
    std::vector<std::pair<std::string, std::string>> metadata;
    /// Metadata as a CBOR map, for values that are not text; replaces
    /// `metadata`.
    std::optional<cbor::Value> metadata_value;
    std::vector<std::filesystem::path> attachments;
    /// Also keep the attached files, sealed, with the record (each at most
    /// node::max_record_file bytes).
    bool keep_files = false;
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
/// Writes a vault private key file, encrypted with `secret` if given.
void save_hpke_key(const std::filesystem::path& path, const crypto::openssl::HpkeKey& key,
                   const std::optional<std::string>& secret);
/// Loads a vault private key file, asking `passphrase` only if it is
/// encrypted.
[[nodiscard]] crypto::openssl::HpkeKey load_hpke_key(const std::filesystem::path& path,
                                                     const PassphraseSource& passphrase);
/// Provides the ledger's vault private key, when it is needed.
using VaultKeySource = std::function<crypto::openssl::HpkeKey()>;

[[nodiscard]] bool is_sealed_vault(ByteView file);
[[nodiscard]] Bytes seal_vault(const protocol::Id& ledger, const protocol::Id& record,
                               const Vault& vault, ByteView public_key);
/// Reads a record's private data; `key` is needed unless the file predates
/// sealing.
[[nodiscard]] Vault load_vault(const Session& session, const protocol::Id& record,
                               const crypto::openssl::HpkeKey* key);
/// Reads a record's private data (in client mode, fetched from the server),
/// asking `vault_key` only if the file is sealed.
[[nodiscard]] Vault read_vault(const Session& session, const protocol::Id& record,
                               const VaultKeySource& vault_key);
/// The same with the key at hand (to open the record's kept files too).
[[nodiscard]] Vault read_vault(const Session& session, const protocol::Id& record,
                               const crypto::openssl::HpkeKey& key);
/// A record's private data as JSON: the record, its fields' values, and its
/// attachments' names.
[[nodiscard]] Json vault_json(const protocol::Id& record, const Vault& vault);

// Kept files: a record's attached files, sealed to the vault key as its
// private data is, and bound to the ledger, the record, and the attachment's
// name (node/record_files.hpp has the format and where they are kept).

/// The HPKE `info` for kept files.
inline constexpr std::string_view record_file_info = "CexChain record file v1";

[[nodiscard]] Bytes seal_record_file(const protocol::Id& ledger, const protocol::Id& record,
                                     std::string_view name, ByteView content, ByteView public_key);

/// One of a record's attachments, and whether a sealed copy is kept.
struct RecordFile {
    std::uint64_t index = 0;
    protocol::Attachment attachment;
    bool kept = false;
};

/// A record's registration, as the ledger holds it.
[[nodiscard]] protocol::RecordRegisterBody registration_of(const Session& session,
                                                           const protocol::Id& record);
/// Its attachments, and which of them are kept (in client mode, by the
/// server).
[[nodiscard]] std::vector<RecordFile> record_files(const Session& session,
                                                   const protocol::Id& record);
/// The attachment named `name`, or the one at the index `name` spells.
[[nodiscard]] RecordFile record_file(const Session& session, const protocol::Id& record,
                                     std::string_view name);
/// A kept file's content, opened with the vault key and checked against the
/// record's commitment (with the salt in the record's private data).
[[nodiscard]] Bytes open_record_file(const Session& session, const protocol::Id& record,
                                     const RecordFile& file, const Vault& vault,
                                     const crypto::openssl::HpkeKey& key);
/// Keeps `content` as the record's attachment `file`, sealed: it must be
/// that attachment (checked against the commitment with the vault's salt).
/// False if a copy was kept already (nothing changes: remove it first to
/// replace it).
bool keep_record_file(Session& session, const protocol::Id& record, const RecordFile& file,
                      const Vault& vault, ByteView content);
/// Removes a kept file (the ledger still commits to it); false if none was
/// kept.
bool remove_record_file(Session& session, const protocol::Id& record, const RecordFile& file);

/// What one of the protocol's own record types is for, in a few words (the
/// command that registers it in parentheses); empty for any other type.
[[nodiscard]] std::string_view record_type_purpose(std::string_view type);

} // namespace cexchain::app
