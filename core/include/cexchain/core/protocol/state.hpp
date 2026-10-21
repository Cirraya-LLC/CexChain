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

/// A value no other state has had, unless it is a copy: see LedgerState. A
/// copy keeps it (the copy is the same state); a state moved from, and one
/// that changes, takes a new one.
class StateStamp {
public:
    StateStamp() noexcept : value_(next()) {}
    StateStamp(const StateStamp&) noexcept = default;
    StateStamp& operator=(const StateStamp&) noexcept = default;
    StateStamp(StateStamp&& other) noexcept : value_(other.value_) { other.value_ = next(); }
    StateStamp& operator=(StateStamp&& other) noexcept {
        value_ = other.value_;
        other.value_ = next();
        return *this;
    }
    ~StateStamp() = default;

    void renew() noexcept { value_ = next(); }
    [[nodiscard]] std::uint64_t value() const noexcept { return value_; }

private:
    /// Never 0, never the same twice.
    static std::uint64_t next() noexcept;
    std::uint64_t value_;
};

/// What `validate` found that `apply` can use, so that a contract call runs
/// once: the call's accepted run, for that statement, at that time, on that
/// state. `apply` uses it only if all three still hold (the state's stamp
/// is the one `validate` saw: it changes with every apply), else it runs the
/// call again. Debug builds run it again anyway and compare.
///
/// A run made ahead of time (on another thread, on an earlier state: see
/// `offer`) is used by the next `validate` only if the input it builds for
/// the call is byte for byte that run's: a run is a function of its module
/// and its input, and the input names the contract, whose module never
/// changes once deployed.
class Validation {
public:
    /// The accepted run of the contract call `validate` passed: null for
    /// other statements, if it failed, and once `apply` has taken it.
    [[nodiscard]] const ContractRun* run() const noexcept { return run_ ? &*run_ : nullptr; }
    /// Whether the last `apply` given this used its run instead of running
    /// the call again.
    [[nodiscard]] bool reused() const noexcept { return reused_; }

    /// Offers the next `validate` a run of its call made ahead of time
    /// (`LedgerState::run_contract`, say on an earlier state). `validate`
    /// drops it either way.
    void offer(ContractRun run) { offered_ = std::move(run); }
    /// Whether the last `validate` given this took the offered run (its
    /// input was the one it built) instead of running the call.
    [[nodiscard]] bool took_offer() const noexcept { return took_offer_; }

private:
    friend class LedgerState;
    Id statement_;
    Timestamp time_ = 0;
    std::uint64_t stamp_ = 0;
    std::optional<ContractRun> run_;
    std::optional<ContractRun> offered_;
    bool reused_ = false;
    bool took_offer_ = false;
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
    /// here. With `validation`, a contract call's accepted run is kept there
    /// for `apply` (and whatever was there before is dropped).
    [[nodiscard]] Status validate(const crypto::Provider& provider,
                                  const SignedStatement& statement, Timestamp now,
                                  const SignatureCheck* checked = nullptr,
                                  Validation* validation = nullptr) const;

    /// Applies a statement that `validate` accepted at `now`, its
    /// registration time. `index` is its log index. A contract call's run is
    /// taken from `validation` if `validate` left it there for this
    /// statement, at this time, on this state as it still is; otherwise the
    /// call runs again.
    [[nodiscard]] Status apply(const crypto::Provider& provider, const SignedStatement& statement,
                               std::uint64_t index, Timestamp now,
                               Validation* validation = nullptr);

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
    [[nodiscard]] const ContractState* contract(const Id& id) const;
    [[nodiscard]] const InstanceState* instance(const Id& id) const;
    /// A request any call made (v0.8), open or answered.
    [[nodiscard]] const RequestState* request(const Id& id) const;

    /// Runs a contract call's contract as the home would register the call at
    /// `now`: the input built from this state, the outcome, and the output.
    /// The call must name a deployed contract or an existing instance; the
    /// other rules are not checked here (see `validate`). A home runs a call
    /// before collecting consents to learn whose it needs.
    [[nodiscard]] Result<ContractRun> run_contract(const crypto::Provider& provider,
                                                   const SignedStatement& call,
                                                   Timestamp now) const;

    /// The rules for the children an accepted run creates (v0.7): none on a
    /// retired contract, none from an instance at depth 8. `validate` applies
    /// them after the run; a dry run that `run_contract` accepts checks them
    /// here, so that its answer is the ledger's.
    [[nodiscard]] Status check_children(const ContractCallBody& call,
                                        const ContractAccept& accept) const;

    /// The rules for the requests an accepted run makes at `now` (v0.8):
    /// each deadline after `now` and at most 366 days after it, each reply a
    /// function of kind 2 in the contract's interface, at most 64 open
    /// requests after the call (an answer closes its request first), and
    /// none on an instance that was final before the call. Like
    /// `check_children`, `validate` applies them after the run, and a dry run
    /// checks them here.
    [[nodiscard]] Status check_requests(const ContractCallBody& call, const ContractAccept& accept,
                                        Timestamp now) const;

    /// How a statement's registered signer appears to contracts.
    [[nodiscard]] Result<ContractSigner> contract_signer(const Statement& statement) const;

    /// The log index of a registered statement. An instance's id is its
    /// creation's statement id only if no call made it a child (v0.7): find
    /// the call that created an instance by `InstanceState::created_by`.
    [[nodiscard]] std::optional<std::uint64_t> statement_index(const Id& id) const;

    /// Every actor, delegation, and record, in the order the log created
    /// them; each element is {key, value}.
    [[nodiscard]] const IdMap<ActorState>& actors() const noexcept { return actors_; }
    [[nodiscard]] const IdMap<DelegationState>& delegations() const noexcept {
        return delegations_;
    }
    [[nodiscard]] const IdMap<RecordState>& records() const noexcept { return records_; }
    [[nodiscard]] const IdMap<ContractState>& contracts() const noexcept { return contracts_; }
    [[nodiscard]] const IdMap<InstanceState>& instances() const noexcept { return instances_; }
    /// Every request, in the order the log made them (v0.8).
    [[nodiscard]] const IdMap<RequestState>& requests() const noexcept { return requests_; }

    /// The objects created or changed since the last call (possibly
    /// repeated), in order: what an incremental state tree must update.
    [[nodiscard]] std::vector<Id> take_changes();

    /// Contracts' code is loaded through `modules` from now on (this state
    /// and its copies): none by default. It must outlive them.
    void load_modules_with(ModuleCache* modules) noexcept { modules_ = modules; }

private:
    LedgerState() = default;

    /// `vm::load(code)`, asking `modules_` first and telling it.
    [[nodiscard]] Result<vm::Module> load_module(ByteView code) const;

    [[nodiscard]] Status check_authority(const Statement& statement, const ActorState& signer,
                                         Timestamp now) const;
    [[nodiscard]] Status check_rules(const crypto::Provider& provider, const Statement& statement,
                                     const ActorState& signer, Timestamp now) const;
    [[nodiscard]] Status check_new_key(const crypto::Provider& provider,
                                       const crypto::PublicKey& key) const;
    [[nodiscard]] bool is_log_key(const crypto::PublicKey& key) const;
    /// The record type that a record statement acts on, if any.
    [[nodiscard]] std::optional<std::string> record_type_of(const Statement& statement) const;
    /// The contract that a call or retire acts on, if any.
    [[nodiscard]] std::optional<Id> contract_of(const Statement& statement) const;
    /// Runs a call's contract and requires it to accept, and any children it
    /// creates (v0.7: the contract not retired, the instance below the depth
    /// limit) and requests it makes (v0.8) to be allowed. An `offered` run
    /// whose input is the one built here is taken (and reset) instead of
    /// running the contract.
    [[nodiscard]] Result<ContractRun> accepted_run(const crypto::Provider& provider,
                                                   const SignedStatement& signed_call,
                                                   Timestamp now,
                                                   std::optional<ContractRun>* offered = nullptr,
                                                   bool* took_offer = nullptr) const;
    [[nodiscard]] Result<ContractRun> run_contract(const crypto::Provider& provider,
                                                   const SignedStatement& call, Timestamp now,
                                                   std::optional<ContractRun>* offered,
                                                   bool* took_offer) const;

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
    IdMap<ContractState> contracts_;
    IdMap<InstanceState> instances_;
    IdMap<RequestState> requests_;
    IdMap<std::uint64_t> statements_;
    /// (signer, nonce) of every statement: a payload is never accepted twice,
    /// even re-signed with a rotated key.
    NonceSet nonces_;
    std::vector<IdKey> changes_;
    /// Changes with every apply: the states a Validation is good for.
    StateStamp stamp_;
    ModuleCache* modules_ = nullptr;
};

/// An ancestor of a child instance, and the log index of its call that
/// created the next generation (v0.7).
struct InstanceAncestor {
    const InstanceState* instance = nullptr;
    std::uint64_t until = 0;
};

/// The ancestors of `instance` in `state`, oldest first: none unless a call
/// made it a child. Stops at an ancestor `state` lacks, which a state built
/// by the rules never does.
[[nodiscard]] std::vector<InstanceAncestor> instance_ancestors(const LedgerState& state,
                                                               const InstanceState& instance);

/// The log indices of the calls an instance's evidence shows, ascending:
/// each ancestor's calls up to the one that created the next generation,
/// then the instance's own (spec section 15, "Contract evidence"). For an
/// instance without a parent, its history.
[[nodiscard]] std::vector<std::uint64_t> instance_events(const LedgerState& state,
                                                         const InstanceState& instance);

} // namespace cexchain::protocol
