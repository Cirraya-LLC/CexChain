// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// People: who uses the console, with which role, and what each may do on
// the ledger. Owners and admins invite people (a link to register a passkey
// on their own device), approve them with three taps (their actor, with a
// key the console holds; their passkeys as that actor's presence; a
// delegation of what they may do, chosen in plain words), change roles, and
// remove them. Roles gate the console; delegations, which the ledger
// enforces, gate the ledger.

#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/console/activity.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/console/people.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/node/tokens.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

using protocol::StatementType;

constexpr std::array people_types{StatementType::actor_register, StatementType::actor_revoke,
                                  StatementType::delegation_grant, StatementType::delegation_revoke,
                                  StatementType::actor_set_presence};

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

bool has(const protocol::Scope& scope, StatementType type) {
    return std::ranges::contains(scope.statement_types, type);
}

} // namespace

std::vector<std::string> mechanism_record_types() {
    return {std::string(protocol::access_grant_type), std::string(protocol::access_receipt_type),
            std::string(protocol::access_request_type),
            std::string(protocol::contract_consent_type)};
}

protocol::Scope scope_of(const Permissions& p) {
    protocol::Scope scope;
    auto add = [&](StatementType t) {
        if (!std::ranges::contains(scope.statement_types, t)) {
            scope.statement_types.push_back(t);
        }
    };
    if (p.register_documents || p.act) {
        add(StatementType::record_register);
    }
    if (p.endorse) {
        add(StatementType::record_endorse);
    }
    if (p.revoke) {
        add(StatementType::record_revoke);
    }
    if (p.act) {
        add(StatementType::contract_call);
    }
    if (p.rules) {
        add(StatementType::contract_deploy);
        add(StatementType::contract_retire);
    }
    if (p.people) {
        for (const StatementType t : people_types) {
            add(t);
        }
    }
    if (scope.statement_types.empty()) {
        throw std::invalid_argument("choose at least one thing they may do");
    }
    std::ranges::sort(scope.statement_types);
    // Documents of the chosen kinds (or any), and always the mechanisms'
    // own records: consents, and access requests, grants, and receipts.
    if (!p.register_documents || p.kinds) {
        std::vector<std::string> types =
            p.register_documents && p.kinds ? *p.kinds : std::vector<std::string>{};
        for (std::string& t : mechanism_record_types()) {
            if (!std::ranges::contains(types, t)) {
                types.push_back(std::move(t));
            }
        }
        std::ranges::sort(types);
        scope.record_types = std::move(types);
    }
    if (p.contracts && (p.act || p.rules)) {
        std::vector<protocol::Id> contracts = *p.contracts;
        std::ranges::sort(contracts, {}, [](const protocol::Id& id) { return to_hex(id.bytes()); });
        contracts.erase(std::ranges::unique(contracts).begin(), contracts.end());
        if (contracts.empty()) {
            throw std::invalid_argument("choose at least one set of rules, or all");
        }
        scope.contracts = std::move(contracts);
    }
    scope.not_after = p.until;
    scope.may_delegate = p.people;
    scope.require_presence = true;
    return scope;
}

Permissions permissions_of(const protocol::Scope& scope) {
    Permissions p;
    const auto mechanisms = mechanism_record_types();
    if (scope.record_types) {
        std::vector<std::string> kinds;
        for (const std::string& t : *scope.record_types) {
            if (!std::ranges::contains(mechanisms, t)) {
                kinds.push_back(t);
            }
        }
        p.kinds = kinds;
        p.register_documents = has(scope, StatementType::record_register) && !kinds.empty();
    } else {
        p.register_documents = has(scope, StatementType::record_register);
    }
    p.endorse = has(scope, StatementType::record_endorse);
    p.revoke = has(scope, StatementType::record_revoke);
    p.act = has(scope, StatementType::contract_call);
    p.contracts = scope.contracts;
    p.rules =
        has(scope, StatementType::contract_deploy) || has(scope, StatementType::contract_retire);
    p.people = std::ranges::any_of(people_types, [&](StatementType t) { return has(scope, t); });
    p.until = scope.not_after;
    p.in_person = scope.require_presence;
    p.may_delegate = scope.may_delegate;
    for (const StatementType t : scope.statement_types) {
        const bool covered =
            t == StatementType::record_register || t == StatementType::record_endorse ||
            t == StatementType::record_revoke || t == StatementType::contract_call ||
            t == StatementType::contract_deploy || t == StatementType::contract_retire ||
            std::ranges::contains(people_types, t);
        if (!covered) {
            p.other.emplace_back(protocol::name(t));
        }
    }
    return p;
}

nlohmann::json permissions_json(const Permissions& p) {
    nlohmann::json contracts;
    if (p.contracts) {
        contracts = nlohmann::json::array();
        for (const protocol::Id& c : *p.contracts) {
            contracts.push_back(hex_of(c));
        }
    }
    return {{"register", p.register_documents},
            {"kinds", p.kinds ? nlohmann::json(*p.kinds) : nlohmann::json()},
            {"endorse", p.endorse},
            {"revoke", p.revoke},
            {"act", p.act},
            {"contracts", contracts},
            {"rules", p.rules},
            {"people", p.people},
            {"until", p.until ? nlohmann::json(*p.until) : nlohmann::json()},
            {"in_person", p.in_person},
            {"may_delegate", p.may_delegate},
            {"other", p.other}};
}

std::optional<Permissions> parse_permissions(const nlohmann::json& v) {
    if (!v.is_object()) {
        return std::nullopt;
    }
    Permissions p;
    auto flag = [&](std::string_view key, bool& into) {
        const auto it = v.find(key);
        if (it == v.end() || it->is_null()) {
            return true;
        }
        if (!it->is_boolean()) {
            return false;
        }
        into = it->get<bool>();
        return true;
    };
    if (!flag("register", p.register_documents) || !flag("endorse", p.endorse) ||
        !flag("revoke", p.revoke) || !flag("act", p.act) || !flag("rules", p.rules) ||
        !flag("people", p.people)) {
        return std::nullopt;
    }
    if (const auto it = v.find("kinds"); it != v.end() && !it->is_null()) {
        if (!it->is_array() || it->empty() || it->size() > 64 ||
            !std::ranges::all_of(*it, [](const auto& k) { return k.is_string(); })) {
            return std::nullopt;
        }
        p.kinds = it->get<std::vector<std::string>>();
    }
    if (const auto it = v.find("contracts"); it != v.end() && !it->is_null()) {
        if (!it->is_array() || it->size() > 64) {
            return std::nullopt;
        }
        std::vector<protocol::Id> ids;
        for (const auto& c : *it) {
            const auto id = c.is_string() ? id_of(c.get<std::string>()) : std::nullopt;
            if (!id) {
                return std::nullopt;
            }
            ids.push_back(*id);
        }
        p.contracts = std::move(ids);
    }
    if (const auto it = v.find("until"); it != v.end() && !it->is_null()) {
        if (!it->is_number_unsigned()) {
            return std::nullopt;
        }
        p.until = it->get<protocol::Timestamp>();
    }
    return p;
}

Permissions default_permissions(std::string_view role) {
    Permissions p;
    if (role == "owner" || role == "admin") {
        p.register_documents = p.endorse = p.revoke = p.act = p.rules = p.people = true;
    } else if (role == "member") {
        p.register_documents = p.endorse = p.revoke = p.act = true;
    }
    return p;
}

nlohmann::json scope_json(const protocol::Scope& scope) {
    nlohmann::json types = nlohmann::json::array();
    for (const StatementType t : scope.statement_types) {
        types.push_back(std::string(protocol::name(t)));
    }
    nlohmann::json contracts;
    if (scope.contracts) {
        contracts = nlohmann::json::array();
        for (const protocol::Id& c : *scope.contracts) {
            contracts.push_back(hex_of(c));
        }
    }
    auto optional_list = [](const std::optional<std::vector<std::string>>& list) {
        return list ? nlohmann::json(*list) : nlohmann::json();
    };
    return {{"types", types},
            {"record_types", optional_list(scope.record_types)},
            {"contracts", contracts},
            {"functions", optional_list(scope.functions)},
            {"request_kinds", optional_list(scope.request_kinds)},
            {"not_before", scope.not_before ? nlohmann::json(*scope.not_before) : nlohmann::json()},
            {"not_after", scope.not_after ? nlohmann::json(*scope.not_after) : nlohmann::json()},
            {"may_delegate", scope.may_delegate},
            {"require_presence", scope.require_presence}};
}

// --- The People screen ---------------------------------------------------------

void Console::change_people(const std::function<void(People&)>& change) const {
    const auto lock = ledger::DirectoryLock::acquire(services_.directory, 2000);
    if (!lock) {
        throw std::runtime_error("the console's users are busy; try again");
    }
    People people = load_people(services_.directory);
    change(people);
    save_people(services_.directory, people);
}

void Console::log_activity(const std::string& user, std::string action,
                           nlohmann::json detail) const {
    record_activity(services_.directory,
                    {services_.clock->now(), user, std::move(action), std::move(detail)});
}

http::Response Console::people_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    const bool may_change = signer.role == Role::owner || signer.role == Role::admin;
    const ledger::Ledger* const served = ledger();
    const protocol::Timestamp now = services_.clock->now();
    if (request.method == "GET") {
        const People people = load_people(services_.directory);
        nlohmann::json users = nlohmann::json::array();
        nlohmann::json contracts = nlohmann::json::array();
        auto describe_user = [&](const User& u, const protocol::LedgerState* state) {
            nlohmann::json passkeys = nlohmann::json::array();
            for (const protocol::PresenceCredential& p : u.passkeys) {
                passkeys.push_back(
                    {{"label", p.label ? nlohmann::json(*p.label) : nlohmann::json()},
                     {"rp_id", p.rp_id}});
            }
            nlohmann::json delegations = nlohmann::json::array();
            bool on_ledger = false;
            std::size_t presence = 0;
            if (const auto actor = id_of(u.actor); actor && state != nullptr) {
                if (const protocol::ActorState* a = state->actor(*actor); a && !a->revoked) {
                    on_ledger = true;
                    for (const auto& p : u.passkeys) {
                        presence +=
                            std::ranges::any_of(
                                a->presence,
                                [&](const auto& c) { return c.credential_id == p.credential_id; })
                                ? 1U
                                : 0U;
                    }
                }
                for (const auto& [key, d] : state->delegations()) {
                    if (protocol::Id(d.grantee) == *actor) {
                        nlohmann::json item = permissions_json(permissions_of(d.scope));
                        item["id"] = to_hex(protocol::Id(d.id).bytes());
                        item["revoked"] = d.revoked;
                        delegations.push_back(std::move(item));
                    }
                }
            }
            // Waiting: a passkey, but no actor yet, or its passkeys or
            // delegation still to come.
            const bool acts = u.role != Role::viewer;
            const std::string step =
                !acts                          ? "active"
                : !on_ledger                   ? "actor"
                : presence < u.passkeys.size() ? "presence"
                : std::ranges::none_of(
                      delegations,
                      [](const nlohmann::json& d) { return !d.value("revoked", false); })
                    ? "delegation"
                    : "active";
            users.push_back(
                {{"name", u.name},
                 {"role", std::string(name_of(u.role))},
                 {"passkeys", passkeys},
                 {"actor", u.actor.empty() ? nlohmann::json() : nlohmann::json(u.actor)},
                 {"step", step},
                 {"delegations", delegations},
                 {"me", u.name == signer.user}});
        };
        if (served != nullptr) {
            served->read_state([&](const protocol::LedgerState& state) {
                for (const User& u : people.users) {
                    describe_user(u, &state);
                }
                for (const auto& [key, c] : state.contracts()) {
                    if (!c.retired) {
                        contracts.push_back(
                            {{"id", to_hex(protocol::Id(c.id).bytes())},
                             {"name", c.name ? nlohmann::json(*c.name) : nlohmann::json()}});
                    }
                }
            });
        } else {
            for (const User& u : people.users) {
                describe_user(u, nullptr);
            }
        }
        nlohmann::json invitations = nlohmann::json::array();
        for (const Invitation& i : people.invitations) {
            if (i.expires > now && !i.user.empty()) {
                invitations.push_back({{"user", i.user},
                                       {"role", std::string(name_of(i.role))},
                                       {"expires", i.expires}});
            }
        }
        nlohmann::json kinds = nlohmann::json::array();
        for (const Kind& k : load_kinds(services_.directory)) {
            kinds.push_back({{"type", k.type}, {"name", k.name}});
        }
        nlohmann::json defaults = nlohmann::json::object();
        for (const std::string_view role : {"admin", "member"}) {
            defaults[std::string(role)] = permissions_json(default_permissions(role));
        }
        return json(200, {{"users", users},
                          {"invitations", invitations},
                          {"kinds", kinds},
                          {"contracts", contracts},
                          {"defaults", defaults},
                          {"may_change", may_change}});
    }
    if (request.method != "POST") {
        return error(405, "unsupported", "method not allowed");
    }
    if (!may_change) {
        return error(403, "forbidden", "only an owner or an admin manages people");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const auto owners = [](const People& people) {
        return std::ranges::count(people.users, Role::owner, &User::role);
    };
    try {
        if (const auto name = body.find("invite"); name != body.end() && name->is_string()) {
            const std::string user = name->get<std::string>();
            const auto role = parse_role(body.value("role", "member"));
            if (!valid_user_name(user) || !role) {
                return error(400, "invalid_argument",
                             "a name is 1 to 64 letters, digits, spaces, '.', '_', or '-'; a "
                             "role is owner, admin, member, or viewer");
            }
            if (*role == Role::owner && signer.role != Role::owner) {
                return error(403, "forbidden", "only an owner makes another owner");
            }
            auto [code, invitation] =
                make_invitation(*services_.provider, *services_.entropy, user, *role, now);
            std::optional<http::Response> refused;
            change_people([&](People& people) {
                if (const User* existing = people.find(user);
                    existing != nullptr && existing->role != *role) {
                    refused = error(409, "conflict",
                                    user + " uses the console already: change the role instead");
                    return;
                }
                people.invitations.push_back(invitation);
            });
            if (refused) {
                return std::move(*refused);
            }
            log_activity(signer.user, "people.invite",
                         {{"user", user}, {"role", std::string(name_of(*role))}});
            const std::string origin = std::string(*request.header("origin"));
            return json(200, {{"user", user},
                              {"role", std::string(name_of(*role))},
                              {"link", origin + "/console/#/enroll/" + code},
                              {"expires", invitation.expires}});
        }
        if (const auto name = body.find("role"); name != body.end() && name->is_string()) {
            const std::string user = name->get<std::string>();
            const auto role = parse_role(body.value("to", ""));
            if (!role) {
                return error(400, "invalid_argument", "a role is owner, admin, member, or viewer");
            }
            std::optional<http::Response> refused;
            change_people([&](People& people) {
                User* u = people.find(user);
                if (u == nullptr) {
                    refused = error(404, "not_found", "no console user named " + user);
                } else if ((u->role == Role::owner || *role == Role::owner) &&
                           signer.role != Role::owner) {
                    refused = error(403, "forbidden", "only an owner changes who is an owner");
                } else if (u->role == Role::owner && *role != Role::owner && owners(people) == 1) {
                    refused = error(409, "conflict", user + " is the console's only owner");
                } else {
                    u->role = *role;
                }
            });
            if (refused) {
                return std::move(*refused);
            }
            log_activity(signer.user, "people.role",
                         {{"user", user}, {"role", std::string(name_of(*role))}});
            return json(200, {{"user", user}, {"role", std::string(name_of(*role))}});
        }
        if (const auto name = body.find("remove"); name != body.end() && name->is_string()) {
            const std::string user = name->get<std::string>();
            std::optional<http::Response> refused;
            change_people([&](People& people) {
                const User* u = people.find(user);
                if (u != nullptr && u->role == Role::owner &&
                    (signer.role != Role::owner || owners(people) == 1)) {
                    refused = error(409, "conflict",
                                    owners(people) == 1 ? user + " is the console's only owner"
                                                        : "only an owner removes an owner");
                    return;
                }
                const bool was =
                    std::erase_if(people.users, [&](const User& x) { return x.name == user; }) > 0;
                const bool invited = std::erase_if(people.invitations, [&](const Invitation& i) {
                                         return i.user == user;
                                     }) > 0;
                if (!was && !invited) {
                    refused =
                        error(404, "not_found", "no console user or invitation named " + user);
                }
            });
            if (refused) {
                return std::move(*refused);
            }
            log_activity(signer.user, "people.remove", {{"user", user}});
            return json(200, {{"removed", user}});
        }
    } catch (const std::exception& e) {
        return error(503, "unavailable", e.what());
    }
    return error(400, "invalid_argument", "invite, change a role, or remove someone");
}

http::Response Console::tokens_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin sees and makes API tokens");
    }
    const std::filesystem::path dir = services_.directory.parent_path();
    if (request.method == "GET") {
        nlohmann::json tokens = nlohmann::json::array();
        if (const auto loaded = node::load_tokens(dir)) {
            for (const node::ApiToken& t : *loaded) {
                tokens.push_back({{"name", t.name},
                                  {"scopes", node::scope_names(t.scopes)},
                                  {"created", t.created}});
            }
        }
        return json(200, {{"tokens", tokens}});
    }
    if (request.method != "POST") {
        return error(405, "unsupported", "method not allowed");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    auto tokens = node::load_tokens(dir);
    if (!tokens) {
        return error(503, "unavailable", "the API tokens cannot be read");
    }
    if (const auto name = body.find("create"); name != body.end() && name->is_string()) {
        const std::string token_name = name->get<std::string>();
        std::string list;
        for (const auto& scope : body.value("scopes", nlohmann::json::array())) {
            if (scope.is_string()) {
                list += (list.empty() ? "" : ",") + scope.get<std::string>();
            }
        }
        const auto scopes = node::parse_scopes(list);
        if (!node::valid_token_name(token_name) || !scopes) {
            return error(400, "invalid_argument",
                         "a token's name is 1-64 letters, digits, '.', '_', or '-'; its scopes "
                         "are read, submit, admin, peer, executor");
        }
        if (std::ranges::any_of(*tokens, [&](const auto& t) { return t.name == token_name; })) {
            return error(409, "conflict", "a token named " + token_name + " exists");
        }
        const std::string token = node::generate_token(*services_.entropy);
        tokens->push_back({token_name, *scopes, node::token_hash(*services_.provider, token),
                           services_.clock->now()});
        if (!node::save_tokens(dir, *tokens)) {
            return error(503, "unavailable", "the API tokens cannot be saved");
        }
        log_activity(signer.user, "tokens.create",
                     {{"name", token_name}, {"scopes", node::scope_names(*scopes)}});
        return json(
            200, {{"name", token_name}, {"scopes", node::scope_names(*scopes)}, {"token", token}});
    }
    if (const auto name = body.find("revoke"); name != body.end() && name->is_string()) {
        const std::string token_name = name->get<std::string>();
        if (std::erase_if(*tokens, [&](const auto& t) { return t.name == token_name; }) == 0) {
            return error(404, "not_found", "no token named " + token_name);
        }
        if (!node::save_tokens(dir, *tokens)) {
            return error(503, "unavailable", "the API tokens cannot be saved");
        }
        log_activity(signer.user, "tokens.revoke", {{"name", token_name}});
        return json(200, {{"revoked", token_name}});
    }
    return error(400, "invalid_argument", "create or revoke a token");
}

http::Response Console::activity_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin reads the console's activity");
    }
    if (request.method != "GET") {
        return error(405, "unsupported", "method not allowed");
    }
    nlohmann::json out = nlohmann::json::array();
    for (const Activity& a : read_activity(services_.directory, 200)) {
        out.push_back(activity_json(a));
    }
    return json(200, {{"activity", out}});
}

std::variant<Console::PersonStep, http::Response>
Console::person_step(const Signed& who, const nlohmann::json& intent) const {
    if (who.role != Role::owner && who.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin approves people");
    }
    const std::string action = intent.value("action", "");
    if (action == "delegation.revoke") {
        const auto delegation = id_of(intent.value("delegation", ""));
        if (!delegation) {
            return error(400, "invalid_argument", "name the delegation by its full id (hex)");
        }
        const std::string reason = intent.value("reason", "");
        return PersonStep{protocol::Body{protocol::DelegationRevokeBody{
                              *delegation, reason.empty() ? std::nullopt : std::optional(reason)}},
                          nullptr,
                          {},
                          "people.revoke"};
    }
    const People people = load_people(services_.directory);
    const std::string name = intent.value("user", "");
    const User* user = people.find(name);
    if (user == nullptr) {
        return error(404, "not_found", "no console user named " + name);
    }
    if (user->role == Role::viewer) {
        return error(409, "conflict", "a viewer reads and verifies: they act as no one");
    }
    if (action == "person.register") {
        if (!user->actor.empty()) {
            return error(409, "conflict", name + " acts as someone on the ledger already");
        }
        auto key = crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519);
        if (!key) {
            return error(500, "internal", "making their key failed");
        }
        auto held = std::make_shared<crypto::openssl::KeyPair>(std::move(*key));
        return PersonStep{protocol::Body{protocol::ActorRegisterBody{protocol::ActorKind::person,
                                                                     user->name, held->public_key(),
                                                                     std::nullopt, std::nullopt}},
                          std::move(held), name, "people.register"};
    }
    const auto actor = id_of(user->actor);
    if (!actor) {
        return error(409, "conflict", name + " acts as no one on the ledger yet");
    }
    if (action == "person.presence") {
        if (user->passkeys.empty() || user->passkeys.size() > 16) {
            return error(409, "conflict", name + " has no passkey to register (or too many)");
        }
        return PersonStep{protocol::Body{protocol::ActorSetPresenceBody{*actor, user->passkeys}},
                          nullptr, name, "people.presence"};
    }
    if (action == "person.delegate") {
        const auto permissions = parse_permissions(intent.value("may", nlohmann::json()));
        if (!permissions) {
            return error(400, "invalid_argument", "say what they may do");
        }
        if (permissions->people && user->role != Role::owner && user->role != Role::admin) {
            return error(409, "conflict", "only owners and admins manage people");
        }
        try {
            return PersonStep{
                protocol::Body{protocol::DelegationGrantBody{*actor, scope_of(*permissions)}},
                nullptr, name, "people.delegate"};
        } catch (const std::invalid_argument& e) {
            return error(400, "invalid_argument", e.what());
        }
    }
    return error(400, "invalid_argument", "the console cannot prepare this action");
}

} // namespace cexchain::console
