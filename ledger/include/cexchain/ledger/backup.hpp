// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <functional>
#include <istream>
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
///   header        {1: "cexchain-backup", 2: 1, 3: ledger id, 4: hash,
///                  5: created, 6: entries, 7: checkpoints, 8: cosignatures,
///                  9: files}
///   entries       bstr each (log entries, as logged)
///   checkpoints   bstr each (signed checkpoints, oldest first)
///   cosignatures  [bstr cosignature, public key] each
///   files         [tstr path, bstr content] each
///   trailer       {1: chain}, chain = H_n where H_0 = SHA-256("CexChain
///                 backup v1") and H_i+1 = SHA-256(H_i || item i, framed)
/// Restoring re-validates every entry and checkpoint as a replica does, so
/// a backup cannot smuggle in a history the ledger never had; the chain
/// catches truncation and damage to the files.
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
};

/// Writes a backup of `ledger` and `files` to `out`.
[[nodiscard]] Result<BackupSummary> write_backup(const Ledger& ledger,
                                                 const crypto::Provider& provider,
                                                 std::span<const BackupFile> files,
                                                 protocol::Timestamp created, std::ostream& out);

/// Restores a backup into `fs`, which must hold no ledger, handing each file
/// to `on_file` (which decides where it goes, or refuses it). Reopen the
/// ledger afterwards. Fails with Errc::verification_failed if any entry or
/// checkpoint does not validate, or the chain does not match.
[[nodiscard]] Result<BackupSummary>
restore_backup(std::istream& in, FileSystem& fs, Clock& clock, const crypto::Provider& provider,
               const std::function<Status(const BackupFile&)>& on_file);

} // namespace cexchain::ledger
