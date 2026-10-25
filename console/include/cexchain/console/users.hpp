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

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/ledger/environment.hpp>

/// The console's people: who may sign in, with which passkeys, in which
/// role, and the invitations that let someone register a passkey. Roles gate
/// the console, never the ledger: what a person may do on the ledger stays in
/// their delegations. Kept in the ledger directory's console/ folder, which
/// the console and the command line change only while holding its lock.
namespace cexchain::console {

enum class Role : std::uint8_t { owner, admin, member, viewer };

[[nodiscard]] std::string_view name_of(Role role) noexcept;
[[nodiscard]] std::optional<Role> parse_role(std::string_view name) noexcept;

struct User {
    /// 1 to 64 characters: letters, digits, spaces, '.', '_', '-', not
    /// starting or ending with a space.
    std::string name;
    Role role = Role::viewer;
    protocol::Timestamp created = 0;
    std::vector<protocol::PresenceCredential> passkeys;
    /// The ledger's actor this person acts as, in hex, and the name of the
    /// key the console holds for it (console user link); empty until linked.
    std::string actor;
    std::string key;
};

[[nodiscard]] bool valid_user_name(std::string_view name) noexcept;

/// A one-time code that lets its holder register a passkey: as the user it
/// names, or, for the first owner, as whoever sets the console up (no name).
struct Invitation {
    /// 16 hex digits: the first 8 bytes of the code's hash.
    std::string id;
    /// The code's SHA-256, in hex; the code itself is never kept.
    std::string hash;
    /// Empty for the first owner's: the name is given when registering.
    std::string user;
    Role role = Role::viewer;
    protocol::Timestamp created = 0;
    protocol::Timestamp expires = 0;
};

/// An invitation holds for a day.
inline constexpr protocol::Timestamp invitation_lifetime = 24 * 60 * 60'000;

/// The console's users and invitations, as users.json holds them.
struct People {
    std::vector<User> users;
    std::vector<Invitation> invitations;

    [[nodiscard]] const User* find(std::string_view name) const noexcept;
    [[nodiscard]] User* find(std::string_view name) noexcept;
    [[nodiscard]] bool has_owner() const noexcept;
    /// The user a passkey belongs to, if any.
    [[nodiscard]] const User* owner_of(ByteView credential_id) const noexcept;
};

/// Reads the console's people (none if never written). Throws
/// std::runtime_error if the file is damaged.
[[nodiscard]] People load_people(const std::filesystem::path& directory);
/// Replaces them atomically, readable by the owner only.
void save_people(const std::filesystem::path& directory, const People& people);

/// A new invitation, valid from `now` for a day, and its code ("cxi_" and 43
/// base64url characters), which only the caller ever sees.
[[nodiscard]] std::pair<std::string, Invitation> make_invitation(const crypto::Provider& provider,
                                                                 ledger::Entropy& entropy,
                                                                 std::string user, Role role,
                                                                 protocol::Timestamp now);

/// The SHA-256 of an invitation code, in hex, if it has the code's form.
[[nodiscard]] std::optional<std::string> invitation_hash(const crypto::Provider& provider,
                                                         std::string_view code);

} // namespace cexchain::console
