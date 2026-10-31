// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// What a person may do on the ledger, in the console's plain words, and
/// the delegation scope that says it. A person approved from the console
/// always acts in person (their passkey's tap).
namespace cexchain::console {

struct Permissions {
    /// Register documents: of these kinds' record types, or of any.
    bool register_documents = false;
    std::optional<std::vector<std::string>> kinds;
    bool endorse = false;
    bool revoke = false;
    /// Create things under rules, act on them, consent, and answer requests:
    /// under these contracts, or any.
    bool act = false;
    std::optional<std::vector<protocol::Id>> contracts;
    /// Deploy and retire rules.
    bool rules = false;
    /// Register people, set their passkeys, and grant and revoke what they
    /// may do (only within what the granter may do).
    bool people = false;
    std::optional<protocol::Timestamp> until;

    // As read from a delegation (not chosen in the form):
    bool in_person = true;
    bool may_delegate = false;
    /// Statement types the words above do not cover, by name.
    std::vector<std::string> other;
};

/// The record types the protocol's own mechanisms register (consents and
/// access requests, grants, and receipts): a person who may act or register
/// documents may register them too, whatever kinds are chosen.
[[nodiscard]] std::vector<std::string> mechanism_record_types();

/// The scope for `permissions`: in person, delegating only with `people`.
/// Throws std::invalid_argument if it allows nothing.
[[nodiscard]] protocol::Scope scope_of(const Permissions& permissions);
/// The plain words for a delegation's scope.
[[nodiscard]] Permissions permissions_of(const protocol::Scope& scope);

[[nodiscard]] nlohmann::json permissions_json(const Permissions& permissions);
/// From the page's form; nullopt if it is not one.
[[nodiscard]] std::optional<Permissions> parse_permissions(const nlohmann::json& value);
/// What a role is given by default: an admin everything, a member documents
/// and things under rules, a viewer nothing.
[[nodiscard]] Permissions default_permissions(std::string_view role);

/// A delegation's scope as the page and its checks compare it.
[[nodiscard]] nlohmann::json scope_json(const protocol::Scope& scope);

} // namespace cexchain::console
