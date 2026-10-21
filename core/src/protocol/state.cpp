// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <atomic>
#include <utility>
#include <variant>

#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/record_types.hpp>
#include <cexchain/core/protocol/state.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

std::uint64_t StateStamp::next() noexcept {
    static std::atomic<std::uint64_t> last{0};
    return last.fetch_add(1, std::memory_order_relaxed) + 1;
}

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
    if (parent.contracts) {
        if (!child.contracts) {
            return fail(Errc::rejected, "delegated contracts exceed the grantor's scope");
        }
        for (const Id& contract : *child.contracts) {
            if (!std::ranges::contains(*parent.contracts, contract)) {
                return fail(Errc::rejected, "delegated contracts exceed the grantor's scope");
            }
        }
    }
    // Keys 8 and 9 (v0.8) narrow like record types: a grantor's list stays,
    // as a subset.
    if (parent.functions &&
        (!child.functions || !std::ranges::all_of(*child.functions, [&](const std::string& f) {
            return std::ranges::contains(*parent.functions, f);
        }))) {
        return fail(Errc::rejected, "delegated functions exceed the grantor's scope");
    }
    if (parent.request_kinds &&
        (!child.request_kinds ||
         !std::ranges::all_of(*child.request_kinds, [&](const std::string& k) {
             return std::ranges::contains(*parent.request_kinds, k);
         }))) {
        return fail(Errc::rejected, "delegated request kinds exceed the grantor's scope");
    }
    return {};
}

} // namespace

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
    state.root_keys_ = {{0, body->root_key}};
    state.log_keys_ = {{0, body->log_key}};

    ActorState organization;
    organization.id = genesis.id;
    organization.display_name = body->organization;
    organization.key = body->root_key;
    organization.kid = *kid;
    state.actors_by_kid_[key_of(*kid)] = key_of(genesis.id);
    state.actors_.insert_or_assign(key_of(genesis.id), std::move(organization));
    state.changes_.push_back(key_of(genesis.id));
    state.statements_.insert_or_assign(key_of(genesis.id), 0);
    state.nonces_.insert(*state.actors_.position(key_of(genesis.id)), genesis.statement.nonce);
    return state;
}

const ActorState* LedgerState::actor(const Id& id) const {
    return actors_.find(key_of(id));
}

const DelegationState* LedgerState::delegation(const Id& id) const {
    return delegations_.find(key_of(id));
}

const RecordState* LedgerState::record(const Id& id) const {
    return records_.find(key_of(id));
}

const ContractState* LedgerState::contract(const Id& id) const {
    return contracts_.find(key_of(id));
}

const InstanceState* LedgerState::instance(const Id& id) const {
    return instances_.find(key_of(id));
}

const RequestState* LedgerState::request(const Id& id) const {
    return requests_.find(key_of(id));
}

Result<ContractSigner> LedgerState::contract_signer(const Statement& statement) const {
    const ActorState* signer = statement.actor_id ? actor(*statement.actor_id) : nullptr;
    if (signer == nullptr) {
        return fail(Errc::not_found, "the signing actor is not registered");
    }
    ContractSigner out;
    out.kind = signer->kind ? static_cast<std::uint8_t>(*signer->kind) : std::uint8_t{0};
    if (statement.presence) {
        for (const PresenceCredential& c : signer->presence) {
            if (c.credential_id == statement.presence->credential_id) {
                out.presence = c.method;
            }
        }
    }
    if (statement.provenance) {
        out.model = statement.provenance->model;
    }
    return out;
}

Result<ContractRun> LedgerState::run_contract(const crypto::Provider& provider,
                                              const SignedStatement& signed_statement,
                                              Timestamp now) const {
    return run_contract(provider, signed_statement, now, nullptr, nullptr);
}

Result<ContractRun> LedgerState::run_contract(const crypto::Provider& provider,
                                              const SignedStatement& signed_statement,
                                              Timestamp now, std::optional<ContractRun>* offered,
                                              bool* took_offer) const {
    const Statement& statement = signed_statement.statement;
    const auto* call = std::get_if<ContractCallBody>(&statement.body);
    if (call == nullptr || !statement.actor_id) {
        return fail(Errc::invalid_argument, "not a contract call");
    }
    ContractInput input;
    input.function = call->function;
    input.arguments = call->arguments;
    input.home = ledger_id_;
    const ContractState* contract = nullptr;
    if (call->instance) {
        const InstanceState* instance = this->instance(*call->instance);
        if (instance == nullptr) {
            return fail(Errc::not_found, "the instance does not exist");
        }
        contract = this->contract(instance->contract);
        input.instance = ContractInstanceView{
            .id = *call->instance,
            .head = instance->head,
            .state = instance->state,
            .status = instance->status,
            .parties = instance->parties,
            .parent = instance->parent ? std::optional<Id>(instance->parent->id()) : std::nullopt,
            .depth = instance->depth,
        };
    } else if (call->contract) {
        contract = this->contract(*call->contract);
    }
    if (contract == nullptr || !contract->module) {
        return fail(Errc::not_found, "the contract does not exist");
    }
    input.contract = contract->id;
    input.caller = *statement.actor_id;
    CEXCHAIN_TRY(input.caller_signer, contract_signer(statement));
    input.time = now;
    for (const ContractConsentRef& c : call->consents) {
        input.consents.emplace_back(c.ledger, c.signer);
    }
    // An answer (v0.8) shows its request, with the answer's status.
    if (call->answer) {
        const RequestState* request = this->request(call->answer->request);
        if (request == nullptr) {
            return fail(Errc::not_found, "the request does not exist");
        }
        input.request = ContractRequestView{
            .id = request->id,
            .kind = request->kind,
            .params = request->params,
            .deadline = request->deadline,
            .asked_at = request->asked_at,
            .status = call->answer->status,
        };
    }
    ContractRun run;
    CEXCHAIN_TRY(run.input, encode_contract_input(input));
    // A run made ahead of time on this very input is this run: the input
    // names the contract, whose module never changes.
    if (offered != nullptr && *offered && (*offered)->input == run.input) {
        run = std::move(**offered);
        offered->reset();
        if (took_offer != nullptr) {
            *took_offer = true;
        }
        return run;
    }
    CEXCHAIN_TRY(run.outcome, vm::run(*contract->module, run.input, provider, hash_));
    if (!run.outcome.trap) {
        if (auto output = decode_contract_output(run.outcome.output, ledger_id_)) {
            run.output = std::move(*output);
        } else {
            run.malformed = output.error();
        }
    }
    return run;
}

Result<ContractRun> LedgerState::accepted_run(const crypto::Provider& provider,
                                              const SignedStatement& signed_call, Timestamp now,
                                              std::optional<ContractRun>* offered,
                                              bool* took_offer) const {
    CEXCHAIN_TRY(ContractRun run, run_contract(provider, signed_call, now, offered, took_offer));
    if (run.outcome.trap == vm::Trap::aborted) {
        return fail(Errc::rejected, "the contract rejected the call");
    }
    if (run.outcome.trap) {
        return fail(Errc::rejected, "the contract trapped on the call");
    }
    if (run.malformed) {
        return fail(Errc::rejected, "the contract's output is not well formed");
    }
    const ContractAccept* accept = run.accepted();
    if (accept == nullptr) {
        return fail(Errc::rejected, "the contract needs more consents for the call");
    }
    const auto& call = std::get<ContractCallBody>(signed_call.statement.body);
    CEXCHAIN_CHECK(check_children(call, *accept));
    CEXCHAIN_CHECK(check_requests(call, *accept, now));
    return run;
}

Status LedgerState::check_children(const ContractCallBody& call,
                                   const ContractAccept& accept) const {
    // Children (v0.7): only a contract that is not retired creates them, and
    // only below the depth limit. A creation's instance has depth 0.
    if (accept.children.empty()) {
        return {};
    }
    const InstanceState* instance = call.instance ? this->instance(*call.instance) : nullptr;
    const ContractState* contract =
        instance != nullptr ? this->contract(instance->contract)
                            : (call.contract ? this->contract(*call.contract) : nullptr);
    if (contract == nullptr || contract->retired) {
        return fail(Errc::rejected, "a retired contract creates no more instances, children "
                                    "included");
    }
    if (instance != nullptr && instance->depth >= max_instance_depth) {
        return fail(Errc::rejected, "an instance at depth 8 creates no children");
    }
    // Only answers reach a final instance (v0.8), and they create none.
    if (instance != nullptr && instance->final) {
        return fail(Errc::rejected, "an answer on a final instance creates no children");
    }
    return {};
}

Status LedgerState::check_requests(const ContractCallBody& call, const ContractAccept& accept,
                                   Timestamp now) const {
    // Requests (v0.8) belong to the instance the call acts on, or creates.
    if (accept.requests.empty()) {
        return {};
    }
    const InstanceState* instance = call.instance ? this->instance(*call.instance) : nullptr;
    const ContractState* contract =
        instance != nullptr ? this->contract(instance->contract)
                            : (call.contract ? this->contract(*call.contract) : nullptr);
    if (contract == nullptr) {
        return fail(Errc::not_found, "the contract does not exist");
    }
    if (instance != nullptr && instance->final) {
        return fail(Errc::rejected, "an answer on a final instance makes no requests");
    }
    for (const ContractRequest& request : accept.requests) {
        if (request.deadline <= now || request.deadline - now > max_request_deadline) {
            return fail(Errc::rejected, "a request's deadline is after the call and at most 366 "
                                        "days after it");
        }
        const auto reply = contract->interface.find(request.reply);
        if (reply == contract->interface.end() || reply->second != FunctionKind::call) {
            return fail(Errc::rejected, "a request's reply is a function of the contract that "
                                        "acts on instances");
        }
    }
    // An answer closes its request before the accept opens new ones.
    std::size_t open = instance == nullptr ? 0 : instance->open_requests.size();
    if (instance != nullptr && call.answer &&
        std::ranges::contains(instance->open_requests, CompactId(call.answer->request))) {
        --open;
    }
    if (open + accept.requests.size() > max_open_requests) {
        return fail(Errc::rejected, "an instance has at most 64 open requests");
    }
    return {};
}

std::optional<Id> LedgerState::contract_of(const Statement& statement) const {
    if (const auto* call = std::get_if<ContractCallBody>(&statement.body)) {
        if (call->contract) {
            return *call->contract;
        }
        const InstanceState* instance = call->instance ? this->instance(*call->instance) : nullptr;
        return instance == nullptr ? std::nullopt : std::optional<Id>(instance->contract);
    }
    if (const auto* retire = std::get_if<ContractRetireBody>(&statement.body)) {
        return retire->contract;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> LedgerState::statement_index(const Id& id) const {
    const std::uint64_t* index = statements_.find(key_of(id));
    return index == nullptr ? std::nullopt : std::optional(*index);
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

Result<vm::Module> LedgerState::load_module(ByteView code) const {
    if (modules_ == nullptr) {
        return vm::load(code);
    }
    if (std::optional<vm::Module> known = modules_->find(code)) {
        return std::move(*known);
    }
    CEXCHAIN_TRY(vm::Module module, vm::load(code));
    modules_->loaded(module);
    return module;
}

Status LedgerState::validate(const crypto::Provider& provider,
                             const SignedStatement& signed_statement, Timestamp now,
                             const SignatureCheck* checked, Validation* validation) const {
    // The offered run is this call's to take, or dropped.
    std::optional<ContractRun> offered;
    if (validation != nullptr) {
        validation->run_.reset();
        validation->took_offer_ = false;
        offered = std::move(validation->offered_);
        validation->offered_.reset();
    }
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
    // Only registered actors have used nonces.
    if (const auto signer_at = actors_.position(key_of(*statement.actor_id));
        signer_at && nonces_.contains(*signer_at, statement.nonce)) {
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
    // if it was checked with exactly the signer's current key; verification
    // is a pure function of the statement and the key, so its outcome stands.
    if (checked != nullptr && checked->key == signer->key) {
        if (!checked->result) {
            return checked->result;
        }
    } else if (auto s = verify_statement(provider, signed_statement, signer->key); !s) {
        return s;
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
        auto check =
            verify_presence(provider, hash_, statement, signed_statement.kid, signer->presence);
        if (!check) {
            return std::unexpected(check.error());
        }
        // Changing your own key or credentials takes the person verified (a
        // PIN or biometric), not only present: a touch alone, perhaps
        // tricked, must not hand the identity over (spec v0.4).
        const auto* rotate = std::get_if<ActorRotateKeyBody>(&statement.body);
        const auto* set = std::get_if<ActorSetPresenceBody>(&statement.body);
        const bool own =
            !statement.delegation_id && ((rotate != nullptr && rotate->actor == signer->id) ||
                                         (set != nullptr && set->actor == signer->id));
        if (own && !check->user_verified && check->method != PresenceMethod::hardware_key) {
            return fail(Errc::rejected, "changing your own key or passkeys needs a passkey that "
                                        "verifies you (PIN or biometric), not only a touch");
        }
    }
    if (auto s = check_rules(provider, statement, *signer, now); !s) {
        return s;
    }
    // A call is registered only if its contract accepts it (spec section 15).
    if (std::holds_alternative<ContractCallBody>(statement.body)) {
        auto run = accepted_run(provider, signed_statement, now, &offered,
                                validation != nullptr ? &validation->took_offer_ : nullptr);
        if (!run) {
            return std::unexpected(run.error());
        }
        if (validation != nullptr) {
            validation->statement_ = signed_statement.id;
            validation->time_ = now;
            validation->stamp_ = stamp_.value();
            validation->run_ = std::move(*run);
        }
    }
    return {};
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
    if (const auto contract = contract_of(statement);
        contract && delegation->scope.contracts &&
        !std::ranges::contains(*delegation->scope.contracts, *contract)) {
        return fail(Errc::rejected, "the delegation does not cover this contract");
    }
    // Keys 8 and 9 (v0.8) restrict contract calls only: the function they
    // name (a creation's too), and that they answer requests of the kinds.
    if (const auto* call = std::get_if<ContractCallBody>(&statement.body)) {
        if (delegation->scope.functions &&
            !std::ranges::contains(*delegation->scope.functions, call->function)) {
            return fail(Errc::rejected, "the delegation does not cover this function");
        }
        if (delegation->scope.request_kinds) {
            const RequestState* request =
                call->answer ? this->request(call->answer->request) : nullptr;
            if (request == nullptr ||
                !std::ranges::contains(*delegation->scope.request_kinds, request->kind)) {
                return fail(Errc::rejected, "the delegation covers only answers to requests of "
                                            "its kinds");
            }
        }
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
    if (is_log_key(key)) {
        return fail(Errc::rejected, "the key is (or was) the ledger's log key");
    }
    return {};
}

bool LedgerState::is_log_key(const crypto::PublicKey& key) const {
    return std::ranges::any_of(log_keys_, [&](const KeyEpoch& e) { return e.key == key; });
}

LedgerKeys LedgerState::keys() const {
    LedgerKeys out{ledger_id_, hash_, root_key(), log_keys_, 0};
    if (const ActorState* organization = actor(ledger_id_);
        organization != nullptr && !organization->rotations.empty()) {
        out.last_rotation = organization->rotations.back();
    }
    return out;
}

Status LedgerState::check_rules(const crypto::Provider& provider, const Statement& statement,
                                const ActorState& signer, Timestamp now) const {
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
                // The root key: only the organization itself replaces it.
                if ((*target)->is_organization() && !signer.is_organization()) {
                    return fail(Errc::rejected,
                                "only the organization rotates its root key, with that key");
                }
                // A presence key is a second factor: it never becomes the
                // signing key.
                const bool presence_key =
                    std::ranges::any_of((*target)->presence, [&](const PresenceCredential& c) {
                        return c.key == b.key;
                    });
                if (presence_key) {
                    return fail(Errc::rejected, "the new key is one of the actor's presence keys");
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
                    // A second factor must be a second key: not the person's
                    // signing key, nor any actor's, nor a log key.
                    auto kid = key_id(provider, hash_, c.key);
                    if (!kid) {
                        return std::unexpected(kid.error());
                    }
                    if (c.key == (*target)->key || actors_by_kid_.contains(key_of(*kid)) ||
                        is_log_key(c.key)) {
                        return fail(Errc::rejected,
                                    "a presence key must not be a signing key or a log key");
                    }
                }
                return {};
            },
            [&](const LedgerRotateLogKeyBody& b) -> Status {
                if (!signer.is_organization()) {
                    return fail(Errc::rejected,
                                "only the organization rotates the log key, with its root key");
                }
                if (crypto::is_weak_public_key(b.key.algorithm, b.key.bytes)) {
                    return fail(Errc::rejected, "the key is weak");
                }
                if (is_log_key(b.key)) {
                    return fail(Errc::rejected, "the key is (or was) the ledger's log key");
                }
                auto kid = key_id(provider, hash_, b.key);
                if (!kid) {
                    return std::unexpected(kid.error());
                }
                if (actors_by_kid_.contains(key_of(*kid))) {
                    return fail(Errc::rejected, "the key belongs to an actor");
                }
                return {};
            },
            [&](const RecordRegisterBody& b) -> Status {
                // Spec v0.9: only the protocol registers its own types.
                if (is_reserved_record_type(b.record_type)) {
                    return fail(Errc::rejected,
                                "the record type is reserved: types beginning with \"cexchain.\" "
                                "are the protocol's own");
                }
                return {};
            },
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
            [&](const ContractDeployBody& b) -> Status {
                if (auto module = load_module(b.code); !module) {
                    return fail(Errc::rejected,
                                "the contract's code is not a module in the profile");
                }
                return {};
            },
            [&](const ContractCallBody& b) -> Status {
                const ContractState* contract = nullptr;
                FunctionKind kind = FunctionKind::create;
                if (b.contract) {
                    contract = this->contract(*b.contract);
                    if (contract == nullptr) {
                        return fail(Errc::not_found, "the contract does not exist");
                    }
                    if (contract->retired) {
                        return fail(Errc::rejected, "the contract is retired");
                    }
                    if (!b.consents.empty()) {
                        return fail(Errc::rejected, "creating an instance takes no consents");
                    }
                } else {
                    const InstanceState* instance = this->instance(*b.instance);
                    if (instance == nullptr) {
                        return fail(Errc::not_found, "the instance does not exist");
                    }
                    // A final instance takes only answers to its open
                    // requests (v0.8).
                    if (instance->final && !b.answer) {
                        return fail(Errc::rejected, "the instance is final");
                    }
                    if (*b.head != instance->head) {
                        return fail(Errc::rejected, "the call does not follow the instance's head");
                    }
                    contract = this->contract(instance->contract);
                    kind = FunctionKind::call;
                }
                if (b.answer) {
                    // An answer (v0.8): to an open request of this instance,
                    // at most once, calling its reply, expiring it only at
                    // its deadline, and citing no consents.
                    const RequestState* request = this->request(b.answer->request);
                    if (request == nullptr) {
                        return fail(Errc::not_found, "the request does not exist");
                    }
                    if (!(request->instance == *b.instance)) {
                        return fail(Errc::rejected, "the request belongs to another instance");
                    }
                    if (!request->open()) {
                        return fail(Errc::rejected, "the request is already answered");
                    }
                    if (b.function != request->reply) {
                        return fail(Errc::rejected, "an answer calls its request's reply");
                    }
                    if (b.answer->status == AnswerStatus::expired && now < request->deadline) {
                        return fail(Errc::rejected,
                                    "a request expires only once its deadline is reached");
                    }
                    if (!b.consents.empty()) {
                        return fail(Errc::rejected, "an answer cites no consents");
                    }
                }
                const auto function = contract->interface.find(b.function);
                if (function == contract->interface.end()) {
                    return fail(Errc::rejected, "the function is not in the contract's interface");
                }
                if (function->second != kind) {
                    return fail(Errc::rejected,
                                kind == FunctionKind::create
                                    ? "the function acts on instances; it does not create one"
                                    : "the function creates instances; it does not act on one");
                }
                for (const ContractConsentRef& c : b.consents) {
                    if (c.ledger == ledger_id_) {
                        return fail(Errc::rejected, "the home never consents to its own calls");
                    }
                }
                return {};
            },
            [&](const ContractRetireBody& b) -> Status {
                const ContractState* contract = this->contract(b.contract);
                if (contract == nullptr) {
                    return fail(Errc::not_found, "the contract does not exist");
                }
                if (contract->retired) {
                    return fail(Errc::rejected, "the contract is already retired");
                }
                return {};
            },
        },
        statement.body);
}

Status LedgerState::apply(const crypto::Provider& provider, const SignedStatement& signed_statement,
                          std::uint64_t index, Timestamp now, Validation* validation) {
    const Statement& statement = signed_statement.statement;
    const Id& id = signed_statement.id;
    // A contract call's run from validate(), if it was made for this
    // statement at this time on this state as it is (and so is this call's
    // run: a run is a function of the module and its input, and the input
    // and the checks after the run are functions of the state, the
    // statement, and the time).
    std::optional<ContractRun> validated;
    if (validation != nullptr) {
        if (validation->run_ && validation->stamp_ == stamp_.value() && validation->time_ == now &&
            validation->statement_ == id) {
            validated = std::move(validation->run_);
        }
        validation->run_.reset();
        validation->reused_ = validated.has_value();
    }
    // The state changes from here on.
    stamp_.renew();
    statements_.insert_or_assign(key_of(id), index);
    if (statement.actor_id) {
        // validate() found the signer.
        if (const auto signer_at = actors_.position(key_of(*statement.actor_id))) {
            nonces_.insert(*signer_at, statement.nonce);
        }
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
                actors_.insert_or_assign(key_of(id), std::move(actor));
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
                if (actor.is_organization()) {
                    root_keys_.push_back({index, b.key});
                }
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
                delegations_.insert_or_assign(key_of(id), std::move(delegation));
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
            [&](const LedgerRotateLogKeyBody& b) -> Status {
                log_keys_.push_back({index, b.key});
                // In the organization's history, so a complete bundle shows
                // every rotation.
                actors_.at(key_of(ledger_id_)).rotations.push_back(index);
                changes_.push_back(key_of(ledger_id_));
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
                // parse_statement holds it to the id size.
                std::ranges::copy_n(b.field_root.begin(),
                                    static_cast<std::ptrdiff_t>(
                                        std::min(b.field_root.size(), record.field_root.size())),
                                    record.field_root.begin());
                record.field_count = b.field_count;
                record.registered_at_index = index;
                record.history.push_back(index);
                records_.insert_or_assign(key_of(id), std::move(record));
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
            [&](const ContractDeployBody& b) -> Status {
                CEXCHAIN_TRY(vm::Module module, load_module(b.code));
                ContractState contract;
                contract.id = id;
                contract.deployer = *statement.actor_id;
                contract.interface = b.interface;
                contract.language = b.language;
                contract.compiler = b.compiler;
                contract.name = b.name;
                contract.module = std::move(module);
                contract.deployed_at_index = index;
                contracts_.insert_or_assign(key_of(id), std::move(contract));
                changes_.push_back(key_of(id));
                return {};
            },
            [&](const ContractCallBody& b) -> Status {
                // validate() ran it on this state at this time: the same run.
                std::optional<ContractRun> run = std::move(validated);
#ifndef NDEBUG
                // Debug builds check the reuse: a fresh run must equal it.
                if (run) {
                    CEXCHAIN_TRY(const ContractRun fresh,
                                 accepted_run(provider, signed_statement, now));
                    if (fresh.input != run->input || fresh.outcome.trap != run->outcome.trap ||
                        fresh.outcome.output != run->outcome.output ||
                        fresh.outcome.fuel_used != run->outcome.fuel_used) {
                        return fail(Errc::verification_failed,
                                    "a contract run kept from validation differs from a new one");
                    }
                }
#endif
                if (!run) {
                    CEXCHAIN_TRY(run, accepted_run(provider, signed_statement, now));
                }
                // accepted_run() checked that the output is an accept.
                ContractAccept accept = std::get<ContractAccept>(std::move(*run->output));
                const Id& target = b.instance ? *b.instance : id;
                if (!b.instance) {
                    InstanceState instance;
                    instance.id = id;
                    instance.contract = *b.contract;
                    instance.created_by = index;
                    instances_.insert_or_assign(key_of(id), std::move(instance));
                }
                InstanceState& instance = instances_.at(key_of(target));
                // An answer (v0.8) first closes its request.
                if (b.answer) {
                    RequestState& request = requests_.at(key_of(b.answer->request));
                    request.status = b.answer->status;
                    request.answered_by = index;
                    request.answered_at = now;
                    std::erase(instance.open_requests, CompactId(b.answer->request));
                }
                instance.head = index;
                instance.state = std::move(accept.state);
                if (accept.status) {
                    instance.status = std::move(accept.status);
                }
                if (accept.parties) {
                    instance.parties = std::move(*accept.parties);
                }
                // Finality is permanent: an answer on a final instance
                // leaves it final, whatever its accept says (v0.8).
                instance.final = instance.final || accept.final;
                instance.history.push_back(index);
                changes_.push_back(key_of(target));
                // Then its children, in order (v0.7): the parent's contract,
                // this call as their creation and head.
                const CompactId contract = instance.contract;
                const std::uint32_t depth = instance.depth + 1;
                for (std::size_t position = 0; position < accept.children.size(); ++position) {
                    CEXCHAIN_TRY(const Id child_id,
                                 child_instance_id(provider, hash_, id, position));
                    ContractChild& from = accept.children[position];
                    InstanceState child;
                    child.id = child_id;
                    child.contract = contract;
                    child.head = index;
                    child.state = std::move(from.state);
                    child.status = std::move(from.status);
                    child.parties = std::move(from.parties);
                    child.history.push_back(index);
                    child.created_by = index;
                    child.parent = CompactId(target);
                    child.position = static_cast<std::uint32_t>(position);
                    child.depth = depth;
                    instances_.insert_or_assign(key_of(child_id), std::move(child));
                    changes_.push_back(key_of(child_id));
                }
                // Then its requests, in order (v0.8): the instance's, open.
                // They have no state leaf, so nothing changes for the tree.
                // `instance` stays valid: instances never move (D-048).
                for (std::size_t position = 0; position < accept.requests.size(); ++position) {
                    CEXCHAIN_TRY(const Id made, request_id(provider, hash_, id, position));
                    ContractRequest& from = accept.requests[position];
                    RequestState request;
                    request.id = made;
                    request.instance = CompactId(target);
                    request.call = index;
                    request.position = static_cast<std::uint32_t>(position);
                    request.kind = std::move(from.kind);
                    request.params = std::move(from.params);
                    request.deadline = from.deadline;
                    request.reply = std::move(from.reply);
                    request.asked_at = now;
                    instance.open_requests.push_back(request.id);
                    requests_.insert_or_assign(key_of(made), std::move(request));
                }
                return {};
            },
            [&](const ContractRetireBody& b) -> Status {
                ContractState& contract = contracts_.at(key_of(b.contract));
                contract.retired = true;
                contract.retired_at_index = index;
                changes_.push_back(key_of(b.contract));
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

std::vector<InstanceAncestor> instance_ancestors(const LedgerState& state,
                                                 const InstanceState& instance) {
    std::vector<InstanceAncestor> out;
    const InstanceState* node = &instance;
    // A depth beyond the limit, or a cycle, is impossible under the rules.
    while (node->parent && out.size() < max_instance_depth) {
        const InstanceState* parent = state.instance(node->parent->id());
        if (parent == nullptr) {
            break;
        }
        out.push_back({parent, node->created_by});
        node = parent;
    }
    std::ranges::reverse(out);
    return out;
}

std::vector<std::uint64_t> instance_events(const LedgerState& state,
                                           const InstanceState& instance) {
    std::vector<std::uint64_t> out;
    for (const InstanceAncestor& a : instance_ancestors(state, instance)) {
        for (const std::uint64_t index : a.instance->history) {
            if (index <= a.until) {
                out.push_back(index);
            }
        }
    }
    out.insert(out.end(), instance.history.begin(), instance.history.end());
    // Each generation's creating call is also the last of its parent's.
    std::ranges::sort(out);
    const auto repeated = std::ranges::unique(out);
    out.erase(repeated.begin(), repeated.end());
    return out;
}

const ActorState* LedgerState::actor_by_kid(const Id& kid) const {
    const auto it = actors_by_kid_.find(key_of(kid));
    if (it == actors_by_kid_.end()) {
        return nullptr;
    }
    return actors_.find(it->second);
}

} // namespace cexchain::protocol
