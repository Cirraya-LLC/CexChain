// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/core/protocol/keys.hpp>
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
    /// Log indices of the statements that rotated this actor's key; for the
    /// organization, its root key and the ledger's log key.
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

/// A statement's signature checked ahead of time (say, on another thread):
/// the key it was checked with, and the outcome.
struct SignatureCheck {
    crypto::PublicKey key;
    Status result;
};

class LedgerState {
public:
    /// Builds the initial state from a verified genesis statement.
    [[nodiscard]] static Result<LedgerState> from_genesis(const crypto::Provider& provider,
                                                          const SignedStatement& genesis);

    /// Checks whether `statement` may be registered at ledger time `now`:
    /// identity, signature, authority, and type-specific rules. A signature
    /// `checked` ahead of time counts only if it was checked with exactly the
    /// signer's current key, and its outcome then stands (either way: a
    /// failed check is not repeated). Otherwise the signature is checked
    /// here.
    [[nodiscard]] Status validate(const crypto::Provider& provider,
                                  const SignedStatement& statement, Timestamp now,
                                  const SignatureCheck* checked = nullptr) const;

    /// Applies a statement that `validate` accepted at `now`, its
    /// registration time. `index` is its log index.
    [[nodiscard]] Status apply(const crypto::Provider& provider, const SignedStatement& statement,
                               std::uint64_t index, Timestamp now);

    [[nodiscard]] const Id& ledger_id() const noexcept { return ledger_id_; }
    [[nodiscard]] crypto::HashAlg hash() const noexcept { return hash_; }
    [[nodiscard]] const std::string& organization() const noexcept { return organization_; }
    /// The organization's current root key, and every root key with the
    /// index of the statement that set it.
    [[nodiscard]] const crypto::PublicKey& root_key() const noexcept {
        return root_keys_.back().key;
    }
    [[nodiscard]] std::span<const KeyEpoch> root_keys() const noexcept { return root_keys_; }
    /// The newest log key: it signs the next state commitment and checkpoint.
    [[nodiscard]] const crypto::PublicKey& log_key() const noexcept { return log_keys_.back().key; }
    /// Every log key, oldest first, with the index of the statement that set
    /// it (0: genesis).
    [[nodiscard]] std::span<const KeyEpoch> log_keys() const noexcept { return log_keys_; }
    /// The log key in effect for a tree of `tree_size` entries.
    [[nodiscard]] const crypto::PublicKey& log_key_for(std::uint64_t tree_size) const {
        return key_in_effect(log_keys_, tree_size);
    }
    /// The keys, as a party that follows rotations without the state keeps
    /// them.
    [[nodiscard]] LedgerKeys keys() const;

    [[nodiscard]] const ActorState* actor(const Id& id) const;
    /// The actor whose current key has this kid, if any.
    [[nodiscard]] const ActorState* actor_by_kid(const Id& kid) const;
    [[nodiscard]] const DelegationState* delegation(const Id& id) const;
    [[nodiscard]] const RecordState* record(const Id& id) const;
    /// The asset a record is, if it is of an asset type (its status is the
    /// record's state).
    [[nodiscard]] const AssetState* asset(const Id& id) const;
    [[nodiscard]] const ContractState* contract(const Id& id) const;
    [[nodiscard]] const InstanceState* instance(const Id& id) const;

    /// Runs a contract call's contract as the home would register the call at
    /// `now`: the input built from this state, the outcome, and the output.
    /// The call must name a deployed contract or an existing instance; the
    /// other rules are not checked here (see `validate`). A home runs a call
    /// before collecting consents to learn whose it needs.
    [[nodiscard]] Result<ContractRun> run_contract(const crypto::Provider& provider,
                                                   const SignedStatement& call,
                                                   Timestamp now) const;

    /// How a statement's registered signer appears to contracts.
    [[nodiscard]] Result<ContractSigner> contract_signer(const Statement& statement) const;

    /// The log index of a registered statement.
    [[nodiscard]] std::optional<std::uint64_t> statement_index(const Id& id) const;

    /// Every actor, delegation, and record, in the order the log created
    /// them; each element is {key, value}.
    [[nodiscard]] const IdMap<ActorState>& actors() const noexcept { return actors_; }
    [[nodiscard]] const IdMap<DelegationState>& delegations() const noexcept {
        return delegations_;
    }
    [[nodiscard]] const IdMap<RecordState>& records() const noexcept { return records_; }
    [[nodiscard]] const IdMap<AssetState>& assets() const noexcept { return assets_; }
    [[nodiscard]] const IdMap<ContractState>& contracts() const noexcept { return contracts_; }
    [[nodiscard]] const IdMap<InstanceState>& instances() const noexcept { return instances_; }

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
    [[nodiscard]] bool is_log_key(const crypto::PublicKey& key) const;
    /// The record type that a record statement acts on, if any.
    [[nodiscard]] std::optional<std::string> record_type_of(const Statement& statement) const;
    /// The contract that a call or retire acts on, if any.
    [[nodiscard]] std::optional<Id> contract_of(const Statement& statement) const;
    /// Runs a call's contract and requires it to accept.
    [[nodiscard]] Result<ContractRun> accepted_run(const crypto::Provider& provider,
                                                   const SignedStatement& call,
                                                   Timestamp now) const;

    Id ledger_id_;
    crypto::HashAlg hash_ = crypto::HashAlg::sha256;
    std::string organization_;
    std::vector<KeyEpoch> root_keys_;
    std::vector<KeyEpoch> log_keys_;

    IdMap<ActorState> actors_;
    /// Kids change with key rotations, and a rotated-away kid is free again:
    /// actors are few, so a plain map.
    std::map<IdKey, IdKey> actors_by_kid_;
    IdMap<DelegationState> delegations_;
    IdMap<RecordState> records_;
    IdMap<AssetState> assets_;
    IdMap<ContractState> contracts_;
    IdMap<InstanceState> instances_;
    IdMap<std::uint64_t> statements_;
    /// (signer, nonce) of every statement: a payload is never accepted twice,
    /// even re-signed with a rotated key.
    NonceSet nonces_;
    std::vector<IdKey> changes_;
};

} // namespace cexchain::protocol
