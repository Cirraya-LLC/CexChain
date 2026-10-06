// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <utility>
#include <variant>

#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/record_types.hpp>
#include <cexchain/core/protocol/state.hpp>

namespace cexchain::protocol {

namespace {

template <class... Ts>
struct Overloaded : Ts... {
    using Ts::operator()...;
};

bool in_window(const Scope& scope, Timestamp now) {
    return (!scope.not_before || *scope.not_before <= now) &&
           (!scope.not_after || now <= *scope.not_after);
}

/// A delegated scope may only narrow the scope it was delegated under.
Status check_narrowing(const Scope& parent, const Scope& child) {
    if (!parent.may_delegate) {
        return fail(Errc::rejected, "the grantor's delegation does not allow further delegation");
    }
    for (const StatementType type : child.statement_types) {
        if (!std::ranges::contains(parent.statement_types, type)) {
            return fail(Errc::rejected, "delegated statement types exceed the grantor's scope");
        }
    }
    if (parent.record_types) {
        if (!child.record_types) {
            return fail(Errc::rejected, "delegated record types exceed the grantor's scope");
        }
        for (const std::string& type : *child.record_types) {
            if (!std::ranges::contains(*parent.record_types, type)) {
                return fail(Errc::rejected, "delegated record types exceed the grantor's scope");
            }
        }
    }
    if (parent.not_before && (!child.not_before || *child.not_before < *parent.not_before)) {
        return fail(Errc::rejected, "delegated validity starts before the grantor's");
    }
    if (parent.not_after && (!child.not_after || *child.not_after > *parent.not_after)) {
        return fail(Errc::rejected, "delegated validity ends after the grantor's");
    }
    if (parent.require_presence && !child.require_presence) {
        return fail(Errc::rejected,
                    "the grantor's delegation requires proof of presence, so must this one");
    }
    return {};
}

} // namespace

IdKey key_of(const Id& id) noexcept {
    IdKey key{};
    const ByteView bytes = id.bytes();
    std::copy_n(bytes.begin(), std::min(bytes.size(), key.size()), key.begin());
    return key;
}

Result<LedgerState> LedgerState::from_genesis(const crypto::Provider& provider,
                                              const SignedStatement& genesis) {
    const auto* body = std::get_if<GenesisBody>(&genesis.statement.body);
    if (body == nullptr) {
        return fail(Errc::invalid_argument, "the first statement must be genesis");
    }
    if (crypto::is_weak_public_key(body->root_key.algorithm, body->root_key.bytes) ||
        crypto::is_weak_public_key(body->log_key.algorithm, body->log_key.bytes)) {
        return fail(Errc::rejected, "genesis uses a weak key");
    }
    if (auto s = verify_statement(provider, genesis, body->root_key); !s) {
        return std::unexpected(s.error());
    }
    auto kid = key_id(provider, genesis.hash_alg, body->root_key);
    if (!kid) {
        return std::unexpected(kid.error());
    }

    LedgerState state;
    state.ledger_id_ = genesis.id;
    state.hash_ = genesis.hash_alg;
    state.organization_ = body->organization;
    state.root_key_ = body->root_key;
    state.log_key_ = body->log_key;

    ActorState organization;
    organization.id = genesis.id;
    organization.display_name = body->organization;
    organization.key = body->root_key;
    organization.kid = *kid;
    state.actors_by_kid_[key_of(*kid)] = key_of(genesis.id);
    state.actors_[key_of(genesis.id)] = std::move(organization);
    state.changes_.push_back(key_of(genesis.id));
    state.statements_[key_of(genesis.id)] = 0;
    state.nonces_.insert({key_of(genesis.id), genesis.statement.nonce});
    return state;
}

const ActorState* LedgerState::actor(const Id& id) const {
    const auto it = actors_.find(key_of(id));
    return it == actors_.end() ? nullptr : &it->second;
}

const DelegationState* LedgerState::delegation(const Id& id) const {
    const auto it = delegations_.find(key_of(id));
    return it == delegations_.end() ? nullptr : &it->second;
}

const RecordState* LedgerState::record(const Id& id) const {
    const auto it = records_.find(key_of(id));
    return it == records_.end() ? nullptr : &it->second;
}

std::optional<std::uint64_t> LedgerState::statement_index(const Id& id) const {
    const auto it = statements_.find(key_of(id));
    return it == statements_.end() ? std::nullopt : std::optional(it->second);
}

std::optional<std::string> LedgerState::record_type_of(const Statement& statement) const {
    return std::visit(
        Overloaded{
            [](const RecordRegisterBody& b) -> std::optional<std::string> { return b.record_type; },
            [this](const RecordEndorseBody& b) -> std::optional<std::string> {
                const RecordState* r = record(b.record);
                return r == nullptr ? std::nullopt : std::optional(r->record_type);
            },
            [this](const RecordTransitionBody& b) -> std::optional<std::string> {
                const RecordState* r = record(b.record);
                return r == nullptr ? std::nullopt : std::optional(r->record_type);
            },
            [this](const RecordRevokeBody& b) -> std::optional<std::string> {
                const RecordState* r = record(b.record);
                return r == nullptr ? std::nullopt : std::optional(r->record_type);
            },
            [](const auto&) -> std::optional<std::string> { return std::nullopt; },
        },
        statement.body);
}

Status LedgerState::validate(const crypto::Provider& provider,
                             const SignedStatement& signed_statement, Timestamp now,
                             const crypto::PublicKey* verified_key) const {
    const Statement& statement = signed_statement.statement;
    if (statement.type() == StatementType::genesis) {
        return fail(Errc::rejected, "the ledger already has a genesis statement");
    }
    if (!statement.ledger_id || *statement.ledger_id != ledger_id_ ||
        signed_statement.hash_alg != hash_) {
        return fail(Errc::rejected, "the statement belongs to another ledger");
    }
    if (statements_.contains(key_of(signed_statement.id))) {
        return fail(Errc::rejected, "the statement is already registered");
    }
    if (nonces_.contains({key_of(*statement.actor_id), statement.nonce})) {
        return fail(Errc::rejected, "the statement repeats an earlier one (same signer and nonce)");
    }
    if (statement.issued_at > now + max_clock_skew_ms) {
        return fail(Errc::rejected, "the statement claims to be issued in the future");
    }

    const ActorState* signer = actor(*statement.actor_id);
    if (signer == nullptr) {
        return fail(Errc::not_found, "the signing actor is not registered");
    }
    if (signer->revoked) {
        return fail(Errc::rejected, "the signing actor has been revoked");
    }
    if (signed_statement.kid != signer->kid) {
        return fail(Errc::rejected, "the statement is not signed with the actor's current key");
    }
    // A signature checked ahead of time (say, on another thread) counts only
    // if it was checked with exactly the signer's current key.
    if (verified_key == nullptr || *verified_key != signer->key) {
        if (auto s = verify_statement(provider, signed_statement, signer->key); !s) {
            return s;
        }
    }
    if (signer->kind == ActorKind::agent &&
        (!statement.provenance || !statement.provenance->model)) {
        return fail(Errc::rejected, "statements by agents must name their model in provenance");
    }
    if (auto s = check_authority(statement, *signer, now); !s) {
        return s;
    }
    if (statement.presence) {
        if (signer->kind != ActorKind::person) {
            return fail(Errc::rejected, "only people prove presence");
        }
        if (auto check =
                verify_presence(provider, hash_, statement, signed_statement.kid, signer->presence);
            !check) {
            return std::unexpected(check.error());
        }
    }
    return check_rules(provider, statement, *signer);
}

Status LedgerState::check_authority(const Statement& statement, const ActorState& signer,
                                    Timestamp now) const {
    if (signer.is_organization()) {
        if (statement.delegation_id) {
            return fail(Errc::rejected, "the organization acts without a delegation");
        }
        return {};
    }
    // An actor may always rotate its own key; a person with passkeys must
    // prove presence to do it (checked in validate), so a stolen signing key
    // alone cannot take the identity over.
    if (const auto* rotate = std::get_if<ActorRotateKeyBody>(&statement.body);
        rotate != nullptr && rotate->actor == signer.id && !statement.delegation_id) {
        if (!signer.presence.empty() && !statement.presence) {
            return fail(Errc::rejected,
                        "rotating your own key needs proof of presence with a passkey");
        }
        return {};
    }
    // A person may manage their own presence credentials, proving presence
    // with one already registered (checked in validate). A stolen signing
    // key alone therefore cannot enroll the thief's passkey.
    if (const auto* set = std::get_if<ActorSetPresenceBody>(&statement.body);
        set != nullptr && set->actor == signer.id && statement.presence &&
        !statement.delegation_id) {
        return {};
    }
    if (!statement.delegation_id) {
        return fail(Errc::rejected, "the actor needs a delegation for this statement");
    }
    const DelegationState* delegation = this->delegation(*statement.delegation_id);
    if (delegation == nullptr) {
        return fail(Errc::not_found, "the cited delegation does not exist");
    }
    if (delegation->grantee != signer.id) {
        return fail(Errc::rejected, "the cited delegation was granted to another actor");
    }
    if (!std::ranges::contains(delegation->scope.statement_types, statement.type())) {
        return fail(Errc::rejected, "the delegation does not cover this statement type");
    }
    if (const auto record_type = record_type_of(statement);
        record_type && delegation->scope.record_types &&
        !std::ranges::contains(*delegation->scope.record_types, *record_type)) {
        return fail(Errc::rejected, "the delegation does not cover this record type");
    }
    for (const DelegationState* link = delegation; link != nullptr;
         link = link->parent ? this->delegation(*link->parent) : nullptr) {
        if (link->revoked) {
            return fail(Errc::rejected, "a delegation in the chain has been revoked");
        }
        const ActorState* grantor = actor(link->grantor);
        if (grantor == nullptr || grantor->revoked) {
            return fail(Errc::rejected, "a grantor in the delegation chain has been revoked");
        }
        if (!in_window(link->scope, now)) {
            return fail(Errc::rejected, "a delegation in the chain is not valid at this time");
        }
        if (link->scope.require_presence && !statement.presence) {
            return fail(Errc::rejected, "the delegation requires proof of presence");
        }
    }
    return {};
}

Status LedgerState::check_new_key(const crypto::Provider& provider,
                                  const crypto::PublicKey& key) const {
    if (crypto::is_weak_public_key(key.algorithm, key.bytes)) {
        return fail(Errc::rejected, "the key is weak");
    }
    auto kid = key_id(provider, hash_, key);
    if (!kid) {
        return std::unexpected(kid.error());
    }
    if (actors_by_kid_.contains(key_of(*kid))) {
        return fail(Errc::rejected, "the key already belongs to an actor");
    }
    return {};
}

Status LedgerState::check_rules(const crypto::Provider& provider, const Statement& statement,
                                const ActorState& signer) const {
    auto active_record = [this](const Id& id) -> Result<const RecordState*> {
        const RecordState* r = record(id);
        if (r == nullptr) {
            return fail(Errc::not_found, "the record does not exist");
        }
        if (r->revoked) {
            return fail(Errc::rejected, "the record has been revoked");
        }
        return r;
    };
    auto active_actor = [this](const Id& id) -> Result<const ActorState*> {
        const ActorState* a = actor(id);
        if (a == nullptr) {
            return fail(Errc::not_found, "the actor does not exist");
        }
        if (a->revoked) {
            return fail(Errc::rejected, "the actor has been revoked");
        }
        return a;
    };

    return std::visit(
        Overloaded{
            [](const GenesisBody&) -> Status {
                return fail(Errc::rejected, "the ledger already has a genesis statement");
            },
            [&](const ActorRegisterBody& b) -> Status {
                if (auto s = check_new_key(provider, b.key); !s) {
                    return s;
                }
                if (b.responsible) {
                    auto responsible = active_actor(*b.responsible);
                    if (!responsible) {
                        return std::unexpected(responsible.error());
                    }
                    if ((*responsible)->kind != ActorKind::person) {
                        return fail(Errc::rejected, "the responsible actor must be a person");
                    }
                }
                return {};
            },
            [&](const ActorRotateKeyBody& b) -> Status {
                auto target = active_actor(b.actor);
                if (!target) {
                    return std::unexpected(target.error());
                }
                if ((*target)->is_organization()) {
                    return fail(Errc::rejected,
                                "the organization key cannot be rotated in this protocol version");
                }
                return check_new_key(provider, b.key);
            },
            [&](const ActorRevokeBody& b) -> Status {
                auto target = active_actor(b.actor);
                if (!target) {
                    return std::unexpected(target.error());
                }
                if ((*target)->is_organization()) {
                    return fail(Errc::rejected, "the organization actor cannot be revoked");
                }
                return {};
            },
            [&](const DelegationGrantBody& b) -> Status {
                auto grantee = active_actor(b.grantee);
                if (!grantee) {
                    return std::unexpected(grantee.error());
                }
                if ((*grantee)->is_organization()) {
                    return fail(Errc::rejected, "the organization needs no delegation");
                }
                if (signer.is_organization()) {
                    return {};
                }
                std::size_t depth = 0;
                for (const DelegationState* link = delegation(*statement.delegation_id);
                     link != nullptr; link = link->parent ? delegation(*link->parent) : nullptr) {
                    ++depth;
                }
                if (depth >= max_delegation_depth) {
                    return fail(Errc::rejected, "delegation chains are at most 16 links long");
                }
                return check_narrowing(delegation(*statement.delegation_id)->scope, b.scope);
            },
            [&](const DelegationRevokeBody& b) -> Status {
                const DelegationState* target = delegation(b.delegation);
                if (target == nullptr) {
                    return fail(Errc::not_found, "the delegation does not exist");
                }
                if (target->revoked) {
                    return fail(Errc::rejected, "the delegation has already been revoked");
                }
                if (!signer.is_organization() && target->grantor != signer.id) {
                    return fail(Errc::rejected,
                                "only the grantor or the organization may revoke a delegation");
                }
                return {};
            },
            [&](const ActorSetPresenceBody& b) -> Status {
                auto target = active_actor(b.actor);
                if (!target) {
                    return std::unexpected(target.error());
                }
                if ((*target)->kind != ActorKind::person) {
                    return fail(Errc::rejected, "only people have presence credentials");
                }
                for (const PresenceCredential& c : b.credentials) {
                    if (crypto::is_weak_public_key(c.key.algorithm, c.key.bytes)) {
                        return fail(Errc::rejected, "a presence key is weak");
                    }
                }
                return {};
            },
            [&](const RecordRegisterBody&) -> Status { return {}; },
            [&](const RecordEndorseBody& b) -> Status {
                auto target = active_record(b.record);
                if (!target) {
                    return std::unexpected(target.error());
                }
                const RecordType* type = find_record_type((*target)->record_type);
                if (type != nullptr && !type->has_role(b.role)) {
                    return fail(Errc::rejected, "the role is not defined for this record type");
                }
                const bool repeated =
                    std::ranges::any_of((*target)->endorsements, [&](const Endorsement& e) {
                        return e.role == b.role && e.actor == signer.id;
                    });
                if (repeated) {
                    return fail(Errc::rejected,
                                "the actor already endorsed this record in this role");
                }
                return {};
            },
            [&](const RecordTransitionBody& b) -> Status {
                auto target = active_record(b.record);
                if (!target) {
                    return std::unexpected(target.error());
                }
                if ((*target)->state != b.from_state) {
                    return fail(Errc::rejected, "the record is not in the stated state");
                }
                const RecordType* type = find_record_type((*target)->record_type);
                if (type == nullptr || !type->allows(b.from_state, b.to_state)) {
                    return fail(Errc::rejected, "the record type does not allow this transition");
                }
                return {};
            },
            [&](const RecordRevokeBody& b) -> Status {
                auto target = active_record(b.record);
                if (!target) {
                    return std::unexpected(target.error());
                }
                return {};
            },
        },
        statement.body);
}

Status LedgerState::apply(const crypto::Provider& provider, const SignedStatement& signed_statement,
                          std::uint64_t index) {
    const Statement& statement = signed_statement.statement;
    const Id& id = signed_statement.id;
    statements_[key_of(id)] = index;
    if (statement.actor_id) {
        nonces_.insert({key_of(*statement.actor_id), statement.nonce});
    }

    return std::visit(
        Overloaded{
            [](const GenesisBody&) -> Status {
                return fail(Errc::rejected, "the ledger already has a genesis statement");
            },
            [&](const ActorRegisterBody& b) -> Status {
                auto kid = key_id(provider, hash_, b.key);
                if (!kid) {
                    return std::unexpected(kid.error());
                }
                ActorState actor;
                actor.id = id;
                actor.kind = b.kind;
                actor.display_name = b.display_name;
                actor.key = b.key;
                actor.kid = *kid;
                actor.responsible = b.responsible;
                actor.agent = b.agent;
                actor.registered_at_index = index;
                actors_by_kid_[key_of(*kid)] = key_of(id);
                actors_[key_of(id)] = std::move(actor);
                changes_.push_back(key_of(id));
                return {};
            },
            [&](const ActorRotateKeyBody& b) -> Status {
                auto kid = key_id(provider, hash_, b.key);
                if (!kid) {
                    return std::unexpected(kid.error());
                }
                ActorState& actor = actors_.at(key_of(b.actor));
                actor.rotations.push_back(index);
                actors_by_kid_.erase(key_of(actor.kid));
                actor.key = b.key;
                actor.kid = *kid;
                actors_by_kid_[key_of(*kid)] = key_of(b.actor);
                changes_.push_back(key_of(b.actor));
                return {};
            },
            [&](const ActorRevokeBody& b) -> Status {
                ActorState& actor = actors_.at(key_of(b.actor));
                actor.revoked = true;
                actor.revoked_at_index = index;
                changes_.push_back(key_of(b.actor));
                return {};
            },
            [&](const DelegationGrantBody& b) -> Status {
                DelegationState delegation;
                delegation.id = id;
                delegation.grantor = *statement.actor_id;
                delegation.parent = statement.delegation_id;
                delegation.grantee = b.grantee;
                delegation.scope = b.scope;
                delegation.granted_at_index = index;
                delegations_[key_of(id)] = std::move(delegation);
                changes_.push_back(key_of(id));
                return {};
            },
            [&](const DelegationRevokeBody& b) -> Status {
                DelegationState& delegation = delegations_.at(key_of(b.delegation));
                delegation.revoked = true;
                delegation.revoked_at_index = index;
                changes_.push_back(key_of(b.delegation));
                return {};
            },
            [&](const ActorSetPresenceBody& b) -> Status {
                ActorState& actor = actors_.at(key_of(b.actor));
                actor.presence = b.credentials;
                actor.presence_updates.push_back(index);
                changes_.push_back(key_of(b.actor));
                return {};
            },
            [&](const RecordRegisterBody& b) -> Status {
                const RecordType* type = find_record_type(b.record_type);
                RecordState record;
                record.id = id;
                record.record_type = b.record_type;
                record.registrant = *statement.actor_id;
                record.state =
                    std::string(type != nullptr ? type->initial_state : generic_initial_state);
                record.field_root = b.field_root;
                record.field_count = b.field_count;
                record.registered_at_index = index;
                record.history.push_back(index);
                records_[key_of(id)] = std::move(record);
                changes_.push_back(key_of(id));
                return {};
            },
            [&](const RecordEndorseBody& b) -> Status {
                RecordState& record = records_.at(key_of(b.record));
                record.endorsements.push_back(Endorsement{b.role, *statement.actor_id, index});
                record.history.push_back(index);
                changes_.push_back(key_of(b.record));
                return {};
            },
            [&](const RecordTransitionBody& b) -> Status {
                RecordState& record = records_.at(key_of(b.record));
                record.state = b.to_state;
                record.history.push_back(index);
                changes_.push_back(key_of(b.record));
                return {};
            },
            [&](const RecordRevokeBody& b) -> Status {
                RecordState& record = records_.at(key_of(b.record));
                record.revoked = true;
                record.history.push_back(index);
                changes_.push_back(key_of(b.record));
                return {};
            },
        },
        statement.body);
}

std::vector<Id> LedgerState::take_changes() {
    std::vector<Id> out;
    out.reserve(changes_.size());
    for (const IdKey& key : changes_) {
        if (auto id = to_id(key)) {
            out.push_back(*id);
        }
    }
    changes_.clear();
    return out;
}

const ActorState* LedgerState::actor_by_kid(const Id& kid) const {
    const auto it = actors_by_kid_.find(key_of(kid));
    if (it == actors_by_kid_.end()) {
        return nullptr;
    }
    const auto actor = actors_.find(it->second);
    return actor == actors_.end() ? nullptr : &actor->second;
}

} // namespace cexchain::protocol
