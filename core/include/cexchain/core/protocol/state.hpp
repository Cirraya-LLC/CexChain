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
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// The ledger's state: a pure function of its log. Every registered statement
/// is validated against the state built from the statements before it, then
/// applied. Replaying a log therefore re-validates all of it.
namespace cexchain::protocol {

/// Statements may claim an issue time at most this far ahead of the ledger
/// clock.
inline constexpr Timestamp max_clock_skew_ms = 5 * 60 * 1000;

/// A delegation chain (organization -> ... -> actor) has at most this many
/// links.
inline constexpr std::size_t max_delegation_depth = 16;

// Ids in state objects are CompactIds: millions of objects (D-048).
struct ActorState {
    CompactId id;
    /// nullopt for the organization actor created by genesis.
    std::optional<ActorKind> kind;
    std::string display_name;
    crypto::PublicKey key;
    CompactId kid;
    std::optional<CompactId> responsible;
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
    CompactId id;
    CompactId grantor;
    /// The delegation the grantor acted under; nullopt if the organization
    /// granted it directly.
    std::optional<CompactId> parent;
    CompactId grantee;
    Scope scope;
    bool revoked = false;
    std::uint64_t granted_at_index = 0;
    std::optional<std::uint64_t> revoked_at_index;
};

struct Endorsement {
    std::string role;
    CompactId actor;
    std::uint64_t index = 0;
};

struct RecordState {
    CompactId id;
    std::string record_type;
    CompactId registrant;
    std::string state;
    /// A digest under the ledger hash (id-sized).
    std::array<std::uint8_t, id_size> field_root{};
    std::uint64_t field_count = 0;
    std::vector<Endorsement> endorsements;
    bool revoked = false;
    std::uint64_t registered_at_index = 0;
    /// Log indices of every statement about this record, in order.
    IndexList history;
};

class LedgerState {
public:
    /// Builds the initial state from a verified genesis statement.
    [[nodiscard]] static Result<LedgerState> from_genesis(const crypto::Provider& provider,
                                                          const SignedStatement& genesis);

    /// Checks whether `statement` may be registered at ledger time `now`:
    /// identity, signature, authority, and type-specific rules. If the caller
    /// already verified the signature with `verified_key`, the check is
    /// skipped when that is the signer's current key (and done otherwise).
    [[nodiscard]] Status validate(const crypto::Provider& provider,
                                  const SignedStatement& statement, Timestamp now,
                                  const crypto::PublicKey* verified_key = nullptr) const;

    /// Applies a statement that `validate` accepted. `index` is its log index.
    [[nodiscard]] Status apply(const crypto::Provider& provider, const SignedStatement& statement,
                               std::uint64_t index);

    [[nodiscard]] const Id& ledger_id() const noexcept { return ledger_id_; }
    [[nodiscard]] crypto::HashAlg hash() const noexcept { return hash_; }
    [[nodiscard]] const std::string& organization() const noexcept { return organization_; }
    [[nodiscard]] const crypto::PublicKey& root_key() const noexcept { return root_key_; }
    [[nodiscard]] const crypto::PublicKey& log_key() const noexcept { return log_key_; }

    [[nodiscard]] const ActorState* actor(const Id& id) const;
    /// The actor whose current key has this kid, if any.
    [[nodiscard]] const ActorState* actor_by_kid(const Id& kid) const;
    [[nodiscard]] const DelegationState* delegation(const Id& id) const;
    [[nodiscard]] const RecordState* record(const Id& id) const;
    /// The log index of a registered statement.
    [[nodiscard]] std::optional<std::uint64_t> statement_index(const Id& id) const;

    /// Every actor, delegation, and record, in the order the log created
    /// them; each element is {key, value}.
    [[nodiscard]] const IdMap<ActorState>& actors() const noexcept { return actors_; }
    [[nodiscard]] const IdMap<DelegationState>& delegations() const noexcept {
        return delegations_;
    }
    [[nodiscard]] const IdMap<RecordState>& records() const noexcept { return records_; }

    /// The objects created or changed since the last call (possibly
    /// repeated), in order: what an incremental state tree must update.
    [[nodiscard]] std::vector<Id> take_changes();

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

    IdMap<ActorState> actors_;
    /// Kids change with key rotations, and a rotated-away kid is free again:
    /// actors are few, so a plain map.
    std::map<IdKey, IdKey> actors_by_kid_;
    IdMap<DelegationState> delegations_;
    IdMap<RecordState> records_;
    IdMap<std::uint64_t> statements_;
    /// (signer, nonce) of every statement: a payload is never accepted twice,
    /// even re-signed with a rotated key.
    NonceSet nonces_;
    std::vector<IdKey> changes_;
};

} // namespace cexchain::protocol
