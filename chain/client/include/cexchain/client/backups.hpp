// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <istream>
#include <string_view>
#include <vector>

#include <cexchain/core/error.hpp>
#include <cexchain/ledger/backup.hpp>

/// What a backup holds beside a ledger's log, and where a restore may write
/// it, as `backup create|restore` and the console's sealed backups share
/// them.
namespace cexchain::client {

/// Whether a restore may write `path` (relative, '/' separators) into a
/// ledger directory: an allow-list of the files a backup holds, each name
/// of the form it is written in, so that no backup writes anywhere else.
[[nodiscard]] bool backup_path_allowed(std::string_view path);

/// The files of the ledger at `dir` a backup holds: the API tokens, the
/// consents calls cite, the calls a registrar holds; with `vault`, the vault
/// (its public key, its private key if kept there, records' sealed data,
/// kept files); with `console`, the console's own folder (its sealed keys
/// and slots, users, kinds, settings, the witness's state, party tokens,
/// the activity log), the peers, the access boxes, and requests' keys. In a
/// fixed order.
[[nodiscard]] std::vector<ledger::BackupFile> backup_files(const std::filesystem::path& dir,
                                                           bool vault, bool console);

/// Restores a backup into `dir` (made if missing, owner-only), which must
/// hold no ledger: the log re-validated, the files written where they
/// belong. A failure leaves `dir` as it was (removed, if it was made).
[[nodiscard]] Result<ledger::BackupSummary> restore_into(std::istream& in,
                                                         const std::filesystem::path& dir);

} // namespace cexchain::client
