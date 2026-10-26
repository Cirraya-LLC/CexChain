// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include <cexchain/console/keystore.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/ledger/environment.hpp>

/// A first run for one person: a new ledger whose owner is that person,
/// acting in person. The console makes every key and seals it: the root key
/// (used here and for recovery only), the log key, and the owner's own key.
/// The root key registers the owner, the owner's passkey, and the owner's
/// delegation: every statement type but the ledger's own key rotations, may
/// delegate, and requires presence. Then the owner does everything else, one
/// passkey tap per statement.
namespace cexchain::console {

/// The sealed keys' names.
inline constexpr std::string_view root_key_name = "root";
inline constexpr std::string_view log_key_name = "log";
inline constexpr std::string_view owner_key_name = "owner";

struct SetUp {
    /// The ledger directory, which holds no ledger yet.
    std::filesystem::path ledger;
    /// The owner's name, which is also the organization's (a nickname works).
    std::string name;
    /// The owner's passkey.
    protocol::PresenceCredential passkey;
    /// The passkey's PRF output, if it has one: its own slot, so that signing
    /// in with it unlocks the console.
    std::optional<std::string> prf;
    /// An unlock passphrase, for consoles that start unattended.
    std::optional<std::string> passphrase;
};

struct FirstRun {
    /// Shown once: it unlocks the keys if every passkey is lost.
    std::string recovery_code;
    protocol::Id ledger;
    protocol::Id owner;
};

/// The statement types of the owner's delegation.
[[nodiscard]] protocol::Scope owner_scope();

/// Makes the console's keys, the ledger, and its owner, and records the
/// owner as the console's user (owner role, linked to the actor). Leaves
/// `keys` unlocked. Throws if the directory holds a ledger or the console's
/// keys exist.
[[nodiscard]] FirstRun set_up(const SetUp& request, KeyStore& keys, ledger::Entropy& entropy);

/// Whether the directory holds a ledger.
[[nodiscard]] bool has_ledger(const std::filesystem::path& directory);

} // namespace cexchain::console
