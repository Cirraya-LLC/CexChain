// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <functional>
#include <istream>
#include <optional>
#include <ostream>
#include <span>
#include <string>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/ledger/ledger.hpp>

/// Backups: one file holding a ledger's log, checkpoints, witness
/// cosignatures, and chosen files from its directory (the sealed vault). The
/// file is a sequence of items, each [length: u32 big-endian][CBOR]:
///   header        {1: "cexchain-backup", 2: 2, 3: ledger id, 4: hash,
///                  5: created, 6: entries, 7: checkpoints, 8: cosignatures,
///                  9: files}
///   genesis       bstr (log entry 0)
///   checkpoints   bstr each (signed checkpoints, oldest first)
///   entries       bstr each (log entries 1.., as logged)
///   cosignatures  [bstr cosignature, public key] each
///   files         [tstr path, bstr content] each
///   trailer       {1: chain, ? 2: signature}, chain = H_n where H_0 =
///                 SHA-256("CexChain backup v1") and H_i+1 = SHA-256(H_i ||
///                 item i, framed); the signature is the log key's over
///                 "CexChain backup v2 signature" || 0x00 || chain.
/// Restoring re-validates every entry and checkpoint as a replica does, so a
/// backup cannot smuggle in a history the ledger never had; the chain
/// catches truncation and damage. What no checkpoint covers (entries after
/// the last one, and the files: tokens, the vault) is restored only if the
/// log key signed the backup: an unsigned backup restores the signed log
/// and nothing else, and says what it left out.
namespace cexchain::ledger {

struct BackupFile {
    /// Relative to the ledger directory, with '/' separators.
    std::string path;
    Bytes content;
};

struct BackupSummary {
    protocol::Id ledger_id;
    protocol::Timestamp created = 0;
    std::uint64_t entries = 0;
    std::uint64_t checkpoints = 0;
    std::uint64_t cosignatures = 0;
    std::uint64_t files = 0;
    /// Signed by the log key.
    bool is_signed = false;
    /// Restores of unsigned backups leave these out.
    std::uint64_t skipped_entries = 0;
    std::uint64_t skipped_files = 0;
    /// The restored head, to compare out of band (with a witness, say).
    std::uint64_t size = 0;
    std::optional<crypto::Digest> root;
    std::optional<protocol::Checkpoint> checkpoint;
};

/// Writes a backup of `ledger` and `files` to `out`, signed by `log_key`
/// (the ledger's) if given.
[[nodiscard]] Result<BackupSummary> write_backup(const Ledger& ledger,
                                                 const crypto::Provider& provider,
                                                 std::span<const BackupFile> files,
                                                 protocol::Timestamp created, std::ostream& out,
                                                 const crypto::Signer* log_key = nullptr);

/// Restores a backup into `fs`, which must hold no ledger, handing each file
/// to `on_file` (which decides where it goes, or refuses it) if the backup
/// is signed. Reopen the ledger afterwards. Fails with
/// Errc::verification_failed if any entry or checkpoint does not validate,
/// the header is not the ledger's, the chain does not match, or the
/// signature does not verify.
[[nodiscard]] Result<BackupSummary>
restore_backup(std::istream& in, FileSystem& fs, Clock& clock, const crypto::Provider& provider,
               const std::function<Status(const BackupFile&)>& on_file);

} // namespace cexchain::ledger
