// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>

#include <cexchain/app/records.hpp>

#include "support.hpp"

/// The vault's keys from options and passphrases.
namespace cexchain::cli {

/// Loads the vault private key from --vault-key (default <ledger>/vault.key)
/// and checks that it matches the ledger's vault public key.
[[nodiscard]] crypto::openssl::HpkeKey load_vault_key(const app::Session& session,
                                                      const Args& args);
/// Loads a vault private key file (asking for its passphrase if needed).
[[nodiscard]] crypto::openssl::HpkeKey load_hpke_key(const std::filesystem::path& path,
                                                     const Args& args);
/// Reads a record's private data, loading the vault key (--vault-key) only if
/// the file is sealed.
[[nodiscard]] Vault read_vault(const app::Session& session, const protocol::Id& record,
                               const Args& args);

} // namespace cexchain::cli
