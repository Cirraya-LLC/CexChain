// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/ledger/backup.hpp>
#include <kanhe/ledger/ledger.hpp>

/// The console's backups: the ledger's backup (signed by its log key) with
/// the console's own folder, sealed so that the folder it is kept in (an
/// external disk, a synced folder) learns only the ledger's id and the time.
/// The recovery code opens it, on any computer:
///   {1: "kanhe-sealed-backup", 2: 1, 3: ledger id, 4: created (ms),
///    5: the recovery slot (the console's node key, encrypted with the
///       recovery code), 6: encapsulated key, 7: ciphertext}
/// the backup sealed with HPKE (X25519, HKDF-SHA256, AES-256-GCM) to the
/// node key, `info` "Kanhe sealed backup v1", `aad` the ledger id and the
/// time (8 bytes, big-endian). A console's own format, as its sealed keys
/// are, not the protocol's.
namespace kanhe::console {

inline constexpr std::string_view sealed_backup_extension = ".cexbackup";
/// A backup a day, while the console is unlocked and a folder is set.
inline constexpr protocol::Timestamp backup_interval = 24 * 60 * 60'000;
/// The newest this many are kept, and the newest of each of this many
/// weeks before them.
inline constexpr std::size_t kept_daily = 7;
inline constexpr std::size_t kept_weekly = 4;

struct SealedBackupInfo {
    protocol::Id ledger;
    protocol::Timestamp created = 0;
};

[[nodiscard]] Bytes seal_backup(ByteView plain, const protocol::Id& ledger,
                                protocol::Timestamp created, ByteView node_public,
                                ByteView recovery_slot);
/// What a sealed backup says of itself (nothing opened). Throws
/// std::runtime_error if the file is not one.
[[nodiscard]] SealedBackupInfo sealed_backup_info(ByteView file);
/// The backup inside, opened with the recovery code. Throws
/// std::runtime_error if the file is not one or the code does not open it.
[[nodiscard]] Bytes open_sealed_backup(ByteView file, std::string_view recovery_code);

/// The last backup's result, kept in `<console>/backups.json`.
struct BackupStatus {
    protocol::Timestamp at = 0;
    std::string file;
    std::uint64_t size = 0;
    protocol::Timestamp failed_at = 0;
    std::string problem;
};
[[nodiscard]] BackupStatus load_backup_status(const std::filesystem::path& console);
void save_backup_status(const std::filesystem::path& console, const BackupStatus& status);

/// Writes a sealed backup of `ledger` (served from `ledger_dir`, whose
/// console folder is `ledger_dir/console`) into `folder`, signed with
/// `log_key`, checked by restoring it in memory before it is sealed, then
/// prunes that ledger's older backups there: the file written. Throws
/// std::runtime_error on failure.
std::filesystem::path
write_sealed_backup(const ledger::Ledger& ledger, const crypto::Provider& provider,
                    const std::filesystem::path& ledger_dir, const crypto::Signer& log_key,
                    const std::filesystem::path& folder, protocol::Timestamp now);
/// Removes `ledger`'s backups in `folder` beyond the newest kept_daily and
/// the newest of each of the kept_weekly weeks before: the files removed.
/// Only files named as this console names them are touched.
std::vector<std::filesystem::path> prune_backups(const std::filesystem::path& folder,
                                                 const protocol::Id& ledger);

/// Restores a sealed backup into `dir`, which must hold no ledger: the
/// ledger and its console folder, the peers' token files pointed at their
/// new place. Throws std::runtime_error (the code, the file) or returns the
/// restore's error.
[[nodiscard]] Result<ledger::BackupSummary> restore_sealed_backup(ByteView file,
                                                                  std::string_view recovery_code,
                                                                  const std::filesystem::path& dir);

} // namespace kanhe::console
