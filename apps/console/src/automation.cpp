// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Automation: the machines that act on the ledger without a person's tap
// (devices, and AI agents answerable to a person), the requests waiting for
// executors, and what the keeper fires next. Owners and admins add an
// executor or an AI agent with two taps (its actor, with a key made here;
// a delegation as narrow as its work, never in person) and take its key
// once, with an API token and its setup: the console never keeps a
// machine's key, since machines run elsewhere.

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/console/console.hpp>
#include <cexchain/console/people.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/node/executor.hpp>
#include <cexchain/node/keeper.hpp>
#include <cexchain/node/tokens.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::optional<protocol::Id> id_of(std::string_view hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

/// A machine's name on the ledger, and the token's name it is given.
bool valid_machine_name(std::string_view name) {
    return node::valid_token_name(name);
}

std::vector<std::string> text_list(const nlohmann::json& value) {
    std::vector<std::string> out;
    if (value.is_array()) {
        for (const auto& v : value) {
            if (v.is_string() && !v.get<std::string>().empty() &&
                !std::ranges::contains(out, v.get<std::string>())) {
                out.push_back(v.get<std::string>());
            }
        }
    }
    std::ranges::sort(out);
    return out;
}

} // namespace

http::Response Console::automation_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    const bool may_change = signer.role == Role::owner || signer.role == Role::admin;
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const protocol::Timestamp now = services_.clock->now();
    if (request.path == "/console/api/automation" && request.method == "GET") {
        nlohmann::json machines = nlohmann::json::array();
        nlohmann::json requests = nlohmann::json::array();
        nlohmann::json contracts = nlohmann::json::array();
        nlohmann::json people = nlohmann::json::array();
        nlohmann::json due = nlohmann::json::array();
        const People users = load_people(services_.directory);
        served->read_state([&](const protocol::LedgerState& state) {
            auto name_of_contract = [&](const protocol::Id& id) {
                const auto* c = state.contract(id);
                return c != nullptr && c->name ? nlohmann::json(*c->name) : nlohmann::json();
            };
            for (const auto& [key, a] : state.actors()) {
                if (a.is_organization() || a.kind == protocol::ActorKind::person || a.revoked) {
                    continue;
                }
                const protocol::Id id(a.id);
                nlohmann::json delegations = nlohmann::json::array();
                for (const auto& [dk, d] : state.delegations()) {
                    if (protocol::Id(d.grantee) != id) {
                        continue;
                    }
                    nlohmann::json on = nlohmann::json::array();
                    for (const protocol::Id& c :
                         d.scope.contracts.value_or(std::vector<protocol::Id>{})) {
                        on.push_back({{"id", hex_of(c)}, {"name", name_of_contract(c)}});
                    }
                    delegations.push_back(
                        {{"id", hex_of(protocol::Id(d.id))},
                         {"revoked", d.revoked},
                         {"may", permissions_json(permissions_of(d.scope))},
                         {"contracts", d.scope.contracts ? on : nlohmann::json()},
                         {"functions", d.scope.functions ? nlohmann::json(*d.scope.functions)
                                                         : nlohmann::json()},
                         {"request_kinds", d.scope.request_kinds
                                               ? nlohmann::json(*d.scope.request_kinds)
                                               : nlohmann::json()}});
                }
                nlohmann::json responsible;
                if (a.responsible) {
                    if (const auto* r = state.actor(protocol::Id(*a.responsible))) {
                        responsible = r->display_name;
                    }
                }
                machines.push_back(
                    {{"id", hex_of(id)},
                     {"name", a.display_name},
                     {"kind", a.kind == protocol::ActorKind::agent ? "agent" : "device"},
                     {"responsible", responsible},
                     {"model", a.agent && a.agent->model ? nlohmann::json(*a.agent->model)
                                                         : nlohmann::json()},
                     {"delegations", delegations}});
            }
            for (const auto& [key, r] : state.requests()) {
                if (r.status) {
                    continue;
                }
                requests.push_back({{"id", hex_of(protocol::Id(r.id))},
                                    {"kind", r.kind},
                                    {"instance", hex_of(protocol::Id(r.instance))},
                                    {"deadline", r.deadline},
                                    {"overdue", now >= r.deadline}});
            }
            for (const auto& [key, c] : state.contracts()) {
                if (c.retired) {
                    continue;
                }
                nlohmann::json functions = nlohmann::json::array();
                for (const auto& [name, kind] : c.interface) {
                    functions.push_back(name);
                }
                contracts.push_back({{"id", hex_of(protocol::Id(c.id))},
                                     {"name", c.name ? nlohmann::json(*c.name) : nlohmann::json()},
                                     {"functions", functions}});
            }
            for (const User& u : users.users) {
                if (const auto actor = id_of(u.actor)) {
                    if (const auto* p = state.actor(*actor); p != nullptr && !p->revoked) {
                        people.push_back({{"name", u.name}, {"actor", u.actor}});
                    }
                }
            }
            // What the keeper (the console's machine) would do now.
            node::DueOptions options;
            options.now = now;
            options.parallel = false;
            if (auto work = node::find_due(*services_.provider, state, options)) {
                for (const node::DueRule& rule : work->rules) {
                    due.push_back({{"kind", "rule"},
                                   {"instance", hex_of(rule.instance)},
                                   {"function", rule.function}});
                }
                for (const node::DueExpiry& expiry : work->expiries) {
                    due.push_back({{"kind", "expiry"},
                                   {"instance", hex_of(expiry.instance)},
                                   {"request", hex_of(expiry.request)}});
                }
            }
        });
        std::vector<nlohmann::json> by_deadline(requests.begin(), requests.end());
        std::ranges::sort(by_deadline, {}, [](const nlohmann::json& r) {
            return r["deadline"].get<protocol::Timestamp>();
        });
        requests = by_deadline;
        return json(200, {{"machines", may_change ? machines : nlohmann::json::array()},
                          {"requests", requests},
                          {"contracts", contracts},
                          {"people", people},
                          {"due", due},
                          {"locked", services_.keys == nullptr || !services_.keys->unlocked()},
                          {"may_change", may_change}});
    }
    if (request.path == "/console/api/automation/setup" && request.method == "POST") {
        // A machine's key, once, after its two taps: encrypted with the
        // passphrase typed on the page; with a token and its setup.
        if (!may_change) {
            return error(403, "forbidden", "only an owner or an admin sets machines up");
        }
        const auto body =
            nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
        const auto actor = body.is_object() ? id_of(body.value("actor", "")) : std::nullopt;
        const auto delegation =
            body.is_object() ? id_of(body.value("delegation", "")) : std::nullopt;
        const std::string passphrase = body.is_object() ? body.value("passphrase", "") : "";
        if (!actor || !delegation) {
            return error(400, "invalid_argument", "name the machine and its delegation (hex)");
        }
        if (passphrase.size() < 8 || passphrase.size() > 1024) {
            return error(400, "invalid_argument", "a passphrase of 8 characters or more");
        }
        std::optional<Handed> handed;
        {
            const std::lock_guard lock(mutex_);
            std::erase_if(handed_, [&](const auto& e) { return e.second.expires <= now; });
            if (const auto it = handed_.find(hex_of(*actor));
                it != handed_.end() && it->second.user == signer.user) {
                handed = std::move(it->second);
                handed_.erase(it);
            }
        }
        if (!handed) {
            return error(404, "not_found",
                         "that machine's key is no longer here: it is handed out once, within ten "
                         "minutes of its registration");
        }
        bool covered = false;
        std::string ledger_url = api_url();
        node::executor::Config config;
        served->read_state([&](const protocol::LedgerState& state) {
            const auto* d = state.delegation(*delegation);
            covered = d != nullptr && protocol::Id(d->grantee) == *actor && !d->revoked;
            config.ledger = state.ledger_id();
        });
        if (!covered) {
            return error(409, "conflict", "that delegation is not the machine's");
        }
        const auto encrypted = handed->key->to_encrypted_pkcs8(passphrase);
        if (!encrypted) {
            return error(500, "internal", "the key could not be encrypted");
        }
        // Its API token: an executor's to answer requests, an agent's to read
        // and submit through the MCP server.
        const std::filesystem::path dir = services_.directory.parent_path();
        auto tokens = node::load_tokens(dir);
        if (!tokens) {
            return error(503, "unavailable", "the API tokens cannot be read");
        }
        std::string token_name = handed->name;
        for (int n = 2;
             std::ranges::any_of(*tokens, [&](const auto& t) { return t.name == token_name; });
             ++n) {
            token_name = handed->name + "-" + std::to_string(n);
        }
        const auto scopes = static_cast<node::Scopes>(
            handed->agent ? (static_cast<node::Scopes>(node::Scope::read) |
                             static_cast<node::Scopes>(node::Scope::submit))
                          : static_cast<node::Scopes>(node::Scope::executor));
        const std::string token = node::generate_token(*services_.entropy);
        tokens->push_back({token_name, scopes, node::token_hash(*services_.provider, token), now});
        if (!node::save_tokens(dir, *tokens)) {
            return error(503, "unavailable", "the API tokens cannot be saved");
        }
        log_activity(signer.user, "automation.setup",
                     {{"name", handed->name}, {"token", token_name}});
        config.actor = *actor;
        config.delegation = *delegation;
        config.model = handed->model;
        config.model_version = handed->model_version;
        const std::string key_file = handed->name + ".key";
        nlohmann::json out{
            {"name", handed->name},     {"key_file", key_file}, {"key", to_base64url(*encrypted)},
            {"token_name", token_name}, {"token", token},       {"server", ledger_url}};
        if (handed->agent) {
            const nlohmann::json args = nlohmann::json::array(
                {"mcp", "--server", ledger_url, "--token-file", handed->name + ".token", "--as",
                 key_file, "--passphrase-file", handed->name + ".passphrase"});
            nlohmann::json server = nlohmann::json::object();
            server["command"] = "cexchain";
            server["args"] = args;
            nlohmann::json servers = nlohmann::json::object();
            servers["cexchain"] = server;
            out["mcp"] = nlohmann::json::object();
            out["mcp"]["mcpServers"] = servers;
        } else {
            out["config"] = node::executor::config_text(config);
            out["command"] = "cexchain executor run --config " + handed->name + ".json --state " +
                             handed->name + "-state --server " + ledger_url + " --token-file " +
                             handed->name + ".token --as " + key_file;
        }
        return json(200, out);
    }
    return error(404, "not_found", "no such console route");
}

std::variant<Console::PersonStep, http::Response>
Console::machine_step(const Signed& who, const nlohmann::json& intent) const {
    if (who.role != Role::owner && who.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin adds machines");
    }
    const ledger::Ledger* const served = ledger();
    const std::string action = intent.value("action", "");
    if (action == "machine.register") {
        const std::string name = intent.value("name", "");
        if (!valid_machine_name(name)) {
            return error(400, "invalid_argument",
                         "a machine's name is 1-64 letters, digits, '.', '_', or '-'");
        }
        const bool agent = intent.value("agent", false);
        std::optional<protocol::Id> responsible;
        protocol::AgentProfile profile;
        if (agent) {
            const People users = load_people(services_.directory);
            const User* person = users.find(intent.value("responsible", ""));
            responsible = person != nullptr ? id_of(person->actor) : std::nullopt;
            if (!responsible) {
                return error(400, "invalid_argument",
                             "an AI agent answers to a person of the ledger: choose who");
            }
            const std::string model = intent.value("model", "");
            const std::string version = intent.value("model_version", "");
            if (model.empty() || model.size() > 128 || version.size() > 128) {
                return error(400, "invalid_argument", "name the agent's model (1-128 bytes)");
            }
            profile.model = model;
            if (!version.empty()) {
                profile.model_version = version;
            }
            profile.runtime = "cexchain-mcp";
        }
        auto key = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
        if (!key) {
            return error(500, "internal", "making its key failed");
        }
        auto held = std::make_shared<crypto::openssl::KeyPair>(std::move(*key));
        PersonStep step{
            protocol::Body{protocol::ActorRegisterBody{
                agent ? protocol::ActorKind::agent : protocol::ActorKind::device, name,
                held->public_key(), responsible, agent ? std::optional(profile) : std::nullopt}},
            std::move(held), name, "automation.register"};
        step.hand_out = true;
        step.agent = agent;
        step.model = profile.model;
        step.model_version = profile.model_version;
        return step;
    }
    if (action == "machine.delegate") {
        // What a machine may do needs no presence, so the organization
        // grants it, with its root key: an owner's to approve.
        if (who.role != Role::owner) {
            return error(
                403, "forbidden",
                "only an owner grants a machine what it may do (the organization signs it)");
        }
        const auto actor = id_of(intent.value("actor", ""));
        bool is_agent = false;
        bool found = false;
        served->read_state([&](const protocol::LedgerState& state) {
            if (const auto* a = actor ? state.actor(*actor) : nullptr;
                a != nullptr && !a->revoked && a->kind != protocol::ActorKind::person) {
                found = true;
                is_agent = a->kind == protocol::ActorKind::agent;
            }
        });
        if (!found) {
            return error(404, "not_found", "no such machine on the ledger");
        }
        protocol::Scope scope;
        if (const auto may = intent.find("may"); may != intent.end() && !may->is_null()) {
            // An AI agent working as a person would, in the People
            // screen's words, but never in person and never delegating.
            const auto permissions = parse_permissions(*may);
            if (!permissions || permissions->people) {
                return error(400, "invalid_argument", "say what it may do (managing people: no)");
            }
            try {
                scope = scope_of(*permissions);
            } catch (const std::invalid_argument& e) {
                return error(400, "invalid_argument", e.what());
            }
        } else {
            // An executor: calls on one contract, answering these requests.
            const auto contract = id_of(intent.value("contract", ""));
            const auto kinds = text_list(intent.value("kinds", nlohmann::json::array()));
            const auto functions = text_list(intent.value("functions", nlohmann::json::array()));
            if (!contract || kinds.empty()) {
                return error(400, "invalid_argument",
                             "an executor answers requests of some kinds under one contract");
            }
            if (!std::ranges::all_of(
                    kinds, [](const std::string& k) { return protocol::is_request_kind(k); })) {
                return error(400, "invalid_argument",
                             "a request kind is lowercase letters, digits, '.', '_', '-'");
            }
            scope.statement_types = {protocol::StatementType::contract_call};
            scope.contracts = std::vector<protocol::Id>{*contract};
            scope.request_kinds = kinds;
            if (!functions.empty()) {
                scope.functions = functions;
            }
        }
        if (const auto until = intent.find("until");
            until != intent.end() && until->is_number_unsigned()) {
            scope.not_after = until->get<protocol::Timestamp>();
        }
        scope.may_delegate = false;
        scope.require_presence = false;
        static_cast<void>(is_agent);
        PersonStep step{protocol::Body{protocol::DelegationGrantBody{*actor, std::move(scope)}},
                        nullptr, intent.value("name", ""), "automation.delegate"};
        step.as_organization = true;
        return step;
    }
    return error(400, "invalid_argument", "the console cannot prepare this action");
}

} // namespace cexchain::console
