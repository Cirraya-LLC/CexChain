// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// JSON views of contracts and their instances.

#include <format>
#include <variant>

#include <cexchain/app/contracts.hpp>
#include <cexchain/app/requests.hpp>
#include <cexchain/app/views.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>

namespace cexchain::app {

namespace {

Json optional_text(const std::optional<std::string>& text) {
    return text ? Json(*text) : Json(nullptr);
}

std::string encoded_hex(const cbor::Value& value) {
    return to_hex(unwrap(cbor::encode(value), "encoding a value"));
}

std::string encoded_hex(const cbor::Encoded& value) {
    return to_hex(value.bytes());
}

std::string_view kind_name(protocol::FunctionKind kind) {
    return kind == protocol::FunctionKind::create ? "create" : "call";
}

Json signer_json(const protocol::ContractSigner& signer) {
    Json presence = nullptr;
    if (signer.presence) {
        presence = *signer.presence == protocol::PresenceMethod::hardware_key ? "hardware-key"
                                                                              : "webauthn";
    }
    return {{"kind", kind_text(signer_kind(signer))},
            {"presence", std::move(presence)},
            {"model", optional_text(signer.model)}};
}

Json call_json(const Session& session, std::uint64_t index, const protocol::SignedStatement& s,
               const protocol::ContractCallBody& call,
               std::span<const protocol::RequestState* const> requests) {
    // The requests it made on this instance (v0.8), and the one it answers.
    Json made = Json::array();
    for (const protocol::RequestState* r : requests) {
        if (r->call == index) {
            made.push_back(id_json(r->id));
        }
    }
    Json answer = nullptr;
    if (call.answer) {
        answer = {{"request", id_json(call.answer->request)},
                  {"status", std::string(protocol::name(call.answer->status))}};
        if (const protocol::RequestState* r = session.state().request(call.answer->request)) {
            answer["kind"] = r->kind;
            answer["late_by_ms"] = r->late_by();
        }
    }
    Json consents = Json::array();
    for (const protocol::ContractConsentRef& c : call.consents) {
        consents.push_back({{"ledger", id_json(c.ledger)},
                            {"record", id_json(c.record)},
                            {"bundle", id_json(c.bundle)},
                            {"signer", signer_json(c.signer)}});
    }
    return {{"index", index},
            {"statement_id", id_json(s.id)},
            {"registered_at", iso_time(session.log_entry(index).registered_at)},
            {"function", call.function},
            {"creates", !call.instance.has_value()},
            {"arguments", cbor::diagnostic(call.arguments)},
            {"arguments_cbor", encoded_hex(call.arguments)},
            {"reference", optional_text(call.reference)},
            {"by", actor_ref(session, *s.statement.actor_id)},
            {"consents", std::move(consents)},
            {"requests", std::move(made)},
            {"answer", std::move(answer)}};
}

} // namespace

std::optional<protocol::ActorKind> signer_kind(const protocol::ContractSigner& signer) {
    if (signer.kind == 0) {
        return std::nullopt;
    }
    return static_cast<protocol::ActorKind>(signer.kind);
}

/// The deploy statement's body: the code, the source, the interface.
protocol::ContractDeployBody deploy_of(const Session& session, const protocol::ContractState& c) {
    const protocol::SignedStatement deploy = session.statement(c.deployed_at_index);
    return std::get<protocol::ContractDeployBody>(deploy.statement.body);
}

std::optional<std::string> retire_reason(const Session& session, const protocol::ContractState& c) {
    if (!c.retired_at_index) {
        return std::nullopt;
    }
    const protocol::SignedStatement retire = session.statement(*c.retired_at_index);
    return std::get<protocol::ContractRetireBody>(retire.statement.body).reason;
}

Json contract_json(const Session& session, const protocol::ContractState& c) {
    const protocol::ContractDeployBody deploy = deploy_of(session, c);
    Json functions = Json::object();
    for (const auto& [name, kind] : c.interface) {
        functions[name] = kind_name(kind);
    }
    std::size_t instances = 0;
    std::size_t open = 0;
    for (const auto& [key, i] : session.state().instances()) {
        if (i.contract == c.id) {
            ++instances;
            open += i.final ? 0U : 1U;
        }
    }
    const auto code_hash =
        unwrap(session.provider().digest(session.state().hash(), deploy.code), "hashing the code");
    return {{"id", id_json(c.id)},
            {"name", optional_text(c.name)},
            {"language", c.language},
            {"compiler", c.compiler},
            {"functions", std::move(functions)},
            {"deployer", actor_ref(session, c.deployer)},
            {"deployed_at", iso_time(session.log_entry(c.deployed_at_index).registered_at)},
            {"deployed_at_index", c.deployed_at_index},
            {"retired", c.retired},
            {"retired_at_index", c.retired_at_index ? Json(*c.retired_at_index) : Json(nullptr)},
            {"retire_reason", optional_text(retire_reason(session, c))},
            {"code_size", deploy.code.size()},
            {"code_hash", to_hex(code_hash.bytes())},
            {"source_size", deploy.source ? Json(deploy.source->size()) : Json(nullptr)},
            {"instances", instances},
            {"open_instances", open}};
}

RequestsByInstance requests_by_instance(const protocol::LedgerState& state) {
    RequestsByInstance out;
    for (const auto& [key, r] : state.requests()) {
        out[r.instance.key()].push_back(&r);
    }
    return out;
}

std::span<const protocol::RequestState* const> requests_of(const RequestsByInstance& requests,
                                                           const protocol::Id& instance) {
    const auto it = requests.find(protocol::key_of(instance));
    return it == requests.end() ? std::span<const protocol::RequestState* const>()
                                : std::span<const protocol::RequestState* const>(it->second);
}

InstanceChildren children_by_parent(const protocol::LedgerState& state) {
    InstanceChildren out;
    for (const auto& [key, i] : state.instances()) {
        if (i.parent) {
            out[i.parent->key()].push_back(&i);
        }
    }
    return out;
}

std::span<const protocol::InstanceState* const> children_of(const InstanceChildren& children,
                                                            const protocol::Id& parent) {
    const auto it = children.find(protocol::key_of(parent));
    return it == children.end() ? std::span<const protocol::InstanceState* const>()
                                : std::span<const protocol::InstanceState* const>(it->second);
}

Json instance_json(const Session& session, const protocol::InstanceState& i) {
    return instance_json_with(session, i, children_by_parent(session.state()),
                              requests_by_instance(session.state()));
}

Json instance_json_with(const Session& session, const protocol::InstanceState& i,
                        const InstanceChildren& all_children,
                        const RequestsByInstance& all_requests) {
    const auto requests = requests_of(all_requests, i.id);
    Json calls = Json::array();
    for (const std::uint64_t index : i.history) {
        const protocol::SignedStatement s = session.statement(index);
        if (const auto* call = std::get_if<protocol::ContractCallBody>(&s.statement.body)) {
            calls.push_back(call_json(session, index, s, *call, requests));
        }
    }
    // Its requests (v0.8): each with its answer, and which are open.
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    Json request_list = Json::array();
    for (const protocol::RequestState* r : requests) {
        request_list.push_back(request_json(session, *r, now));
    }
    Json open = Json::array();
    for (const protocol::CompactId& id : i.open_requests) {
        open.push_back(id_json(id));
    }
    // Its place among instances created by a call (v0.7): its ancestors,
    // oldest first, and the instances its calls created.
    Json ancestors = Json::array();
    for (const protocol::InstanceAncestor& a : protocol::instance_ancestors(session.state(), i)) {
        ancestors.push_back(id_json(a.instance->id));
    }
    Json children = Json::array();
    for (const protocol::InstanceState* child : children_of(all_children, i.id)) {
        children.push_back({{"id", id_json(child->id)},
                            {"position", child->position},
                            {"created_by", child->created_by},
                            {"status", optional_text(child->status)},
                            {"parties", parties_json(child->parties)},
                            {"final", child->final}});
    }
    const protocol::ContractState* c = session.state().contract(i.contract);
    return {{"id", id_json(i.id)},
            {"contract", id_json(i.contract)},
            {"contract_name", c != nullptr ? optional_text(c->name) : Json(nullptr)},
            {"status", optional_text(i.status)},
            {"parties", parties_json(i.parties)},
            {"final", i.final},
            {"head", i.head},
            {"state", cbor::diagnostic(i.state)},
            {"state_cbor", encoded_hex(i.state)},
            {"calls", std::move(calls)},
            {"parent", i.parent ? id_json(i.parent->id()) : Json(nullptr)},
            {"position", i.position},
            {"depth", i.depth},
            {"created_by", i.created_by},
            {"ancestors", std::move(ancestors)},
            {"children", std::move(children)},
            {"requests", std::move(request_list)},
            {"open_requests", std::move(open)}};
}

} // namespace cexchain::app
