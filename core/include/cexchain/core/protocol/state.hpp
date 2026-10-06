// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// The ledger's state: a pure function of its log. Every registered statement
/// is validated against the state built from the statements before it, then
/// applied. Replaying a log therefore re-validates all of it.
namespace cexchain::protocol {

/// Identifiers as map keys.
using IdKey = std::array<std::uint8_t, id_size>;
[[nodiscard]] IdKey key_of(const Id& id) noexcept;

/// Statements may claim an issue time at most this far ahead of the ledger
/// clock.
inline constexpr Timestamp max_clock_skew_ms = 5 * 60 * 1000;

struct ActorState {
    Id id;
    /// nullopt for the organization actor created by genesis.
    std::optional<ActorKind> kind;
    std::string display_name;
    crypto::PublicKey key;
    Id kid;
    std::optional<Id> responsible;
    std::optional<AgentProfile> agent;
    bool revoked = false;
    std::uint64_t registered_at_index = 0;
    std::optional<std::uint64_t> revoked_at_index;
    /// Log indices of the statements that rotated this actor's key.
    std::vector<std::uint64_t> rotations;
    /// People only: the WebAuthn credentials that prove their presence.
    std::vector<PresenceCredential> presence;
    /// Log indices of the statements that set those credentials.
    std::vector<std::uint64_t> presence_updates;

    [[nodiscard]] bool is_organization() const noexcept { return !kind.has_value(); }
};

struct DelegationState {
    Id id;
    Id grantor;
    /// The delegation the grantor acted under; nullopt if the organization
    /// granted it directly.
    std::optional<Id> parent;
    Id grantee;
    Scope scope;
    bool revoked = false;
    std::uint64_t granted_at_index = 0;
    std::optional<std::uint64_t> revoked_at_index;
};

struct Endorsement {
    std::string role;
    Id actor;
    std::uint64_t index = 0;
};

struct RecordState {
    Id id;
    std::string record_type;
    Id registrant;
    std::string state;
    Bytes field_root;
    std::uint64_t field_count = 0;
    std::vector<Endorsement> endorsements;
    bool revoked = false;
    std::uint64_t registered_at_index = 0;
    /// Log indices of every statement about this record, in order.
    std::vector<std::uint64_t> history;
};

class LedgerState {
public:
    /// Builds the initial state from a verified genesis statement.
    [[nodiscard]] static Result<LedgerState> from_genesis(const crypto::Provider& provider,
                                                          const SignedStatement& genesis);

    /// Checks whether `statement` may be registered at ledger time `now`:
    /// identity, signature, authority, and type-specific rules.
    [[nodiscard]] Status validate(const crypto::Provider& provider,
                                  const SignedStatement& statement, Timestamp now) const;

    /// Applies a statement that `validate` accepted. `index` is its log index.
    [[nodiscard]] Status apply(const crypto::Provider& provider, const SignedStatement& statement,
                               std::uint64_t index);

    [[nodiscard]] const Id& ledger_id() const noexcept { return ledger_id_; }
    [[nodiscard]] crypto::HashAlg hash() const noexcept { return hash_; }
    [[nodiscard]] const std::string& organization() const noexcept { return organization_; }
    [[nodiscard]] const crypto::PublicKey& root_key() const noexcept { return root_key_; }
    [[nodiscard]] const crypto::PublicKey& log_key() const noexcept { return log_key_; }

    [[nodiscard]] const ActorState* actor(const Id& id) const;
    [[nodiscard]] const DelegationState* delegation(const Id& id) const;
    [[nodiscard]] const RecordState* record(const Id& id) const;
    /// The log index of a registered statement.
    [[nodiscard]] std::optional<std::uint64_t> statement_index(const Id& id) const;

    [[nodiscard]] const std::map<IdKey, ActorState>& actors() const noexcept { return actors_; }
    [[nodiscard]] const std::map<IdKey, DelegationState>& delegations() const noexcept {
        return delegations_;
    }
    [[nodiscard]] const std::map<IdKey, RecordState>& records() const noexcept { return records_; }

private:
    LedgerState() = default;

    [[nodiscard]] Status check_authority(const Statement& statement, const ActorState& signer,
                                         Timestamp now) const;
    [[nodiscard]] Status check_rules(const crypto::Provider& provider, const Statement& statement,
                                     const ActorState& signer) const;
    [[nodiscard]] Status check_new_key(const crypto::Provider& provider,
                                       const crypto::PublicKey& key) const;
    /// The record type that a record statement acts on, if any.
    [[nodiscard]] std::optional<std::string> record_type_of(const Statement& statement) const;

    Id ledger_id_;
    crypto::HashAlg hash_ = crypto::HashAlg::sha256;
    std::string organization_;
    crypto::PublicKey root_key_;
    crypto::PublicKey log_key_;

    std::map<IdKey, ActorState> actors_;
    std::map<IdKey, IdKey> actors_by_kid_;
    std::map<IdKey, DelegationState> delegations_;
    std::map<IdKey, RecordState> records_;
    std::map<IdKey, std::uint64_t> statements_;
};

} // namespace cexchain::protocol
