// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <print>

#include "commands.hpp"
#include "contracts.hpp"
#include "output.hpp"
#include "requests.hpp"

namespace cexchain::cli {

namespace {

void print_actor_line(const protocol::ActorState& actor) {
    std::string line =
        std::format("{}  {:<13} {}", short_id(actor.id), kind_text(actor.kind), actor.display_name);
    if (actor.agent && actor.agent->model) {
        line += "  (model " + *actor.agent->model + ")";
    }
    if (actor.revoked) {
        line += "  [revoked]";
    }
    std::println("{}", line);
}

void print_delegation_line(const Session& session, const protocol::DelegationState& d,
                           protocol::Timestamp now) {
    std::string status = d.revoked                   ? "  [revoked]"
                         : delegation_active(d, now) ? ""
                                                     : "  [not valid now]";
    std::println("{}  {} -> {}: {}{}", short_id(d.id), session.actor_name(d.grantor),
                 session.actor_name(d.grantee), scope_text(d.scope), status);
}

} // namespace

// ---------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------

int cmd_actor_add(const Args& args) {
    Session session(args);
    protocol::ActorRegisterBody body{parse_actor_kind(args.need("kind")), args.need("name"),
                                     public_key_of(args.need("key"), args), std::nullopt,
                                     std::nullopt};
    if (const auto responsible = args.get("responsible")) {
        body.responsible = session.actor_id(*responsible);
    }
    if (body.kind == protocol::ActorKind::agent) {
        if (!args.has("model")) {
            throw UsageError{"agents need --model (the model they run)"};
        }
        if (!body.responsible) {
            throw UsageError{"agents need --responsible (the person accountable for them)"};
        }
        body.agent = protocol::AgentProfile{args.get("model"), args.get("model-version"),
                                            args.get("runtime")};
    } else if (args.has("runtime")) {
        throw UsageError{"--runtime applies only to agents"};
    }
    // For an agent, --model describes the new agent, not the signer.
    const protocol::Id id =
        body.kind == protocol::ActorKind::agent
            ? session.submit(*load_signer(args.need("as"), args), body, args.get("delegation"),
                             std::nullopt, presence_request(args))
            : session.submit(args, body);
    return report_submitted(args, session, id,
                            {{"actor", actor_json(session, *session.state().actor(id))}},
                            std::format("registered {} \"{}\" as {}", kind_text(body.kind),
                                        body.display_name, hex_id(id)));
}

int cmd_actor_list(const Args& args) {
    Session session(args);
    const std::optional<std::string> kind = args.get("kind");
    if (kind && *kind != "organization") {
        static_cast<void>(parse_actor_kind(*kind));
    }
    Json out = Json::array();
    for (const auto& [key, actor] : session.state().actors()) {
        if ((actor.revoked && !args.has("all")) || (kind && kind_text(actor.kind) != *kind)) {
            continue;
        }
        if (args.json()) {
            out.push_back(actor_json(session, actor));
        } else {
            print_actor_line(actor);
        }
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_actor_show(const Args& args) {
    Session session(args);
    const protocol::ActorState& actor =
        *session.state().actor(session.actor_id(args.positional().front()));
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    std::vector<const protocol::DelegationState*> granted_to;
    std::vector<const protocol::DelegationState*> granted_by;
    for (const auto& [key, d] : session.state().delegations()) {
        if (d.grantee == actor.id) {
            granted_to.push_back(&d);
        }
        if (d.grantor == actor.id) {
            granted_by.push_back(&d);
        }
    }
    std::size_t records = 0;
    for (const auto& [key, r] : session.state().records()) {
        records += r.registrant == actor.id ? 1U : 0U;
    }
    if (args.json()) {
        Json out = actor_json(session, actor);
        Json to = Json::array();
        for (const auto* d : granted_to) {
            to.push_back(delegation_json(session, *d));
        }
        Json by = Json::array();
        for (const auto* d : granted_by) {
            by.push_back(delegation_json(session, *d));
        }
        out["delegations_received"] = std::move(to);
        out["delegations_granted"] = std::move(by);
        out["records_issued"] = records;
        print_json(out);
        return exit_ok;
    }
    std::println("actor:         {}", hex_id(actor.id));
    std::println("name:          {}", actor.display_name);
    std::println("kind:          {}", kind_text(actor.kind));
    std::println("status:        {}", actor.revoked ? "REVOKED" : "active");
    if (actor.responsible) {
        std::println("responsible:   {} ({})", session.actor_name(*actor.responsible),
                     short_id(*actor.responsible));
    }
    if (actor.agent) {
        std::println("model:         {}{}", actor.agent->model.value_or("-"),
                     actor.agent->model_version ? " " + *actor.agent->model_version : "");
        if (actor.agent->runtime) {
            std::println("runtime:       {}", *actor.agent->runtime);
        }
    }
    std::println("key:           {} {}", crypto::name(actor.key.algorithm),
                 to_hex(actor.key.bytes));
    std::println("key id:        {}", hex_id(actor.kid));
    std::println("registered:    entry #{}", actor.registered_at_index);
    if (!actor.rotations.empty()) {
        std::string list;
        for (const std::uint64_t i : actor.rotations) {
            list += (list.empty() ? "#" : ", #") + std::to_string(i);
        }
        std::println("key rotations: {}", list);
    }
    if (actor.kind == protocol::ActorKind::person) {
        if (actor.presence.empty()) {
            std::println("presence:      none registered (cannot prove presence)");
        }
        for (const protocol::PresenceCredential& c : actor.presence) {
            const std::string label = c.label ? " (" + *c.label + ")" : "";
            const std::string id = to_base64url(c.credential_id).substr(0, 16);
            if (c.method == protocol::PresenceMethod::hardware_key) {
                std::println("hardware key:  {} {}{}", crypto::name(c.key.algorithm), id, label);
            } else {
                std::println("passkey:       {} {} for {}{}", crypto::name(c.key.algorithm), id,
                             c.rp_id, label);
            }
        }
    }
    std::println("records:       {} issued", records);
    if (!granted_to.empty()) {
        std::println("\ndelegations received:");
        for (const auto* d : granted_to) {
            print_delegation_line(session, *d, now);
        }
    }
    if (!granted_by.empty()) {
        std::println("\ndelegations granted:");
        for (const auto* d : granted_by) {
            print_delegation_line(session, *d, now);
        }
    }
    return exit_ok;
}

int cmd_actor_revoke(const Args& args) {
    Session session(args);
    const protocol::ActorRevokeBody body{session.actor_id(args.positional().front()),
                                         args.get("reason")};
    const protocol::Id id = session.submit(args, body);
    return report_submitted(args, session, id, {{"actor", id_json(body.actor)}},
                            "revoked actor \"" + session.actor_name(body.actor) + "\" " +
                                hex_id(body.actor));
}

int cmd_actor_rotate_key(const Args& args) {
    Session session(args);
    const protocol::ActorRotateKeyBody body{session.actor_id(args.positional().front()),
                                            public_key_of(args.need("new-key"), args)};
    const protocol::Id id = session.submit(args, body);
    return report_submitted(args, session, id,
                            {{"actor", id_json(body.actor)}, {"key", public_key_json(body.key)}},
                            "rotated the key of \"" + session.actor_name(body.actor) +
                                "\"; the old key no "
                                "longer signs for it");
}

// ---------------------------------------------------------------------------
// Delegations
// ---------------------------------------------------------------------------

int cmd_delegation_grant(const Args& args) {
    Session session(args);
    protocol::Scope scope;
    for (const std::string& name : split(args.need("allow"), ',')) {
        scope.statement_types.push_back(parse_statement_type(name));
    }
    if (const auto types = args.get("record-types")) {
        scope.record_types = split(*types, ',');
    }
    if (const auto from = args.get("from-date")) {
        scope.not_before = parse_time(*from);
    }
    if (args.has("until") && args.has("days")) {
        throw UsageError{"give --until or --days, not both"};
    }
    if (const auto until = args.get("until")) {
        scope.not_after = parse_time(*until);
    } else if (const auto days = args.get("days")) {
        scope.not_after = scope.not_before.value_or(ledger::SystemClock{}.now()) +
                          parse_number(*days, "--days") * day_ms;
    }
    scope.may_delegate = args.has("may-delegate");
    scope.require_presence = args.has("require-presence");
    if (const auto contracts = args.get("contracts")) {
        std::vector<protocol::Id> ids;
        for (const std::string& text : split(*contracts, ',')) {
            const protocol::Id id = session.contract_id(text);
            if (!std::ranges::contains(ids, id)) {
                ids.push_back(id);
            }
        }
        if (ids.empty()) {
            throw UsageError{"--contracts names at least one contract"};
        }
        // Strictly ascending, as scope key 7 requires.
        std::ranges::sort(ids, [](const protocol::Id& a, const protocol::Id& b) {
            return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
        });
        scope.contracts = std::move(ids);
    }
    // Scope keys 8 and 9 (v0.8): the functions its calls may name, and the
    // kinds of request it may answer (then it only answers).
    if (const auto functions = args.get("functions")) {
        std::vector<std::string> names = split(*functions, ',');
        for (const std::string& name : names) {
            if (name.empty() || name.size() > protocol::max_function_name) {
                throw UsageError{"--functions: a function name is 1 to 64 bytes"};
            }
        }
        std::ranges::sort(names);
        names.erase(std::ranges::unique(names).begin(), names.end());
        if (names.empty()) {
            throw UsageError{"--functions names at least one function"};
        }
        scope.functions = std::move(names);
    }
    if (const auto kinds = args.get("request-kinds")) {
        scope.request_kinds = parse_request_kinds(*kinds, "--request-kinds");
    }
    if ((scope.functions || scope.request_kinds) &&
        !std::ranges::contains(scope.statement_types, protocol::StatementType::contract_call)) {
        throw UsageError{"--functions and --request-kinds limit contract calls: --allow "
                         "contract-call too"};
    }
    const protocol::DelegationGrantBody body{session.actor_id(args.need("to")), scope};
    const protocol::Id id = session.submit(args, body);
    return report_submitted(
        args, session, id,
        {{"delegation", delegation_json(session, *session.state().delegation(id))}},
        std::format("granted delegation {} to \"{}\"", hex_id(id),
                    session.actor_name(body.grantee)));
}

int cmd_delegation_list(const Args& args) {
    Session session(args);
    const std::optional<protocol::Id> actor =
        args.has("actor") ? std::optional(session.actor_id(*args.get("actor"))) : std::nullopt;
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    Json out = Json::array();
    for (const auto& [key, d] : session.state().delegations()) {
        if ((d.revoked && !args.has("all")) ||
            (actor && d.grantee != *actor && d.grantor != *actor)) {
            continue;
        }
        if (args.json()) {
            out.push_back(delegation_json(session, d));
        } else {
            print_delegation_line(session, d, now);
        }
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_delegation_show(const Args& args) {
    Session session(args);
    const protocol::DelegationState& d =
        *session.state().delegation(session.delegation_id(args.positional().front()));
    if (args.json()) {
        print_json(delegation_json(session, d));
        return exit_ok;
    }
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    std::println("delegation:    {}", hex_id(d.id));
    std::println("status:        {}", d.revoked                   ? "REVOKED"
                                      : delegation_active(d, now) ? "active"
                                                                  : "not valid now");
    std::println("grantee:       {} ({})", session.actor_name(d.grantee), short_id(d.grantee));
    std::println("grantor:       {} ({})", session.actor_name(d.grantor), short_id(d.grantor));
    std::string types;
    for (const protocol::StatementType t : d.scope.statement_types) {
        types += (types.empty() ? "" : ", ") + std::string(protocol::name(t));
    }
    std::println("may submit:    {}", types);
    if (d.scope.record_types) {
        std::string list;
        for (const std::string& t : *d.scope.record_types) {
            list += (list.empty() ? "" : ", ") + t;
        }
        std::println("record types:  {}", list);
    } else {
        std::println("record types:  any");
    }
    if (d.scope.contracts) {
        std::string list;
        for (const protocol::Id& c : *d.scope.contracts) {
            list += (list.empty() ? "" : ", ") + contract_label(session, c);
        }
        std::println("contracts:     {}", list);
    } else {
        std::println("contracts:     any");
    }
    auto names = [](const std::optional<std::vector<std::string>>& list, std::string_view none) {
        if (!list) {
            return std::string(none);
        }
        std::string out;
        for (const std::string& item : *list) {
            out += (out.empty() ? "" : ", ") + item;
        }
        return out;
    };
    std::println("functions:     {}", names(d.scope.functions, "any"));
    std::println("answers:       {}",
                 d.scope.request_kinds ? "requests of kinds " + names(d.scope.request_kinds, "") +
                                             " (its contract calls are answers to those only)"
                                       : std::string("any request (no limit on kinds)"));
    std::println("valid from:    {}",
                 d.scope.not_before ? format_time(*d.scope.not_before) : "when granted");
    std::println("valid until:   {}",
                 d.scope.not_after ? format_time(*d.scope.not_after) : "until revoked");
    std::println("may delegate:  {}", d.scope.may_delegate ? "yes (only narrower)" : "no");
    std::println("presence:      {}",
                 d.scope.require_presence ? "required (passkey)" : "not required");
    std::println("granted:       entry #{}", d.granted_at_index);
    std::string chain;
    for (const protocol::Id& id : authority_chain(session, d.id)) {
        chain += (chain.empty() ? "" : " <- ") + session.actor_name(id);
    }
    std::println("authority:     {}", chain);
    return exit_ok;
}

int cmd_delegation_revoke(const Args& args) {
    Session session(args);
    const protocol::DelegationRevokeBody body{session.delegation_id(args.positional().front()),
                                              args.get("reason")};
    const protocol::Id id = session.submit(args, body);
    return report_submitted(args, session, id, {{"delegation", id_json(body.delegation)}},
                            "revoked delegation " + hex_id(body.delegation));
}

} // namespace cexchain::cli
