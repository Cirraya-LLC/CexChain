// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <print>

#include <cexchain/core/protocol/record_types.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

const protocol::RecordState& find_record(const Session& session, const Args& args) {
    return *session.state().record(session.record_id(args.positional().front()));
}

std::string join(const std::vector<std::string>& items, std::string_view separator) {
    std::string out;
    for (const std::string& item : items) {
        out += (out.empty() ? "" : std::string(separator)) + item;
    }
    return out;
}

} // namespace

int cmd_record_issue(const Args& args) {
    Session session(args);
    IssueRequest request;
    request.record_type = args.need("type");
    for (const std::string& field : args.all("field")) {
        request.fields.push_back(split_pair(field, "--field"));
    }
    for (const std::string& item : args.all("meta")) {
        request.metadata.push_back(split_pair(item, "--meta"));
    }
    for (const std::string& path : args.all("attach")) {
        request.attachments.emplace_back(path);
    }
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id id = issue_record(session, *load_signer(args.need("as"), args), request);
    const protocol::RecordState& record = *session.state().record(id);
    return report_submitted(
        args, session, id, {{"record", record_json(session, record)}},
        std::format("issued {} {}\nstate: {}", record.record_type, hex_id(id), record.state));
}

int cmd_record_list(const Args& args) {
    Session session(args);
    const auto type = args.get("type");
    const auto state = args.get("state");
    Json out = Json::array();
    for (const auto& [key, record] : session.state().records()) {
        if ((record.revoked && !args.has("all")) || (type && record.record_type != *type) ||
            (state && record.state != *state)) {
            continue;
        }
        if (args.json()) {
            out.push_back(record_json(session, record));
            continue;
        }
        const protocol::LogEntry entry = session.log_entry(record.registered_at_index);
        std::println("{}  {:<24} {:<12} {}  by {}{}", short_id(record.id), record.record_type,
                     record.state, format_time(entry.registered_at),
                     session.actor_name(record.registrant), record.revoked ? "  [revoked]" : "");
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_record_show(const Args& args) {
    Session session(args);
    const protocol::RecordState& record = find_record(session, args);
    const Json r = record_json(session, record);
    if (args.json()) {
        print_json(r);
        return exit_ok;
    }
    std::println("record:     {}", hex_id(record.id));
    std::println("type:       {}", record.record_type);
    std::println("state:      {}{}", record.state, record.revoked ? " (REVOKED)" : "");
    std::println("issued by:  {} at {}", session.actor_name(record.registrant),
                 format_time(session.log_entry(record.registered_at_index).registered_at));
    std::println("fields:     {} committed (values are private; see cexchain record fields)",
                 record.field_count);
    if (r["metadata"].is_object()) {
        for (const auto& [name, value] : r["metadata"].items()) {
            std::println("metadata:   {} = {}", name,
                         value.is_string() ? value.get<std::string>() : value.dump());
        }
    }
    for (const auto& a : r["attachments"]) {
        std::println("attachment: {} ({}, {} bytes)", a["name"].get<std::string>(),
                     a["media_type"].get<std::string>(), a["size"].get<std::uint64_t>());
    }
    if (!record.revoked) {
        const std::vector<std::string> next = next_states(record);
        std::println("next:       {}", next.empty() ? "(no transitions)" : join(next, ", "));
    }
    for (const protocol::Endorsement& e : record.endorsements) {
        std::println("endorsed:   as {} by {} (entry #{})", e.role, session.actor_name(e.actor),
                     e.index);
    }
    std::println("history:    {} statements (cexchain record history {})", record.history.size(),
                 short_id(record.id));
    return exit_ok;
}

int cmd_record_history(const Args& args) {
    Session session(args);
    const protocol::RecordState& record = find_record(session, args);
    Json out = Json::array();
    for (const std::uint64_t index : record.history) {
        if (args.json()) {
            out.push_back(entry_json(session, index));
            continue;
        }
        const protocol::SignedStatement statement = session.statement(index);
        const protocol::Statement& s = statement.statement;
        const protocol::ActorState* actor =
            s.actor_id ? session.state().actor(*s.actor_id) : nullptr;
        std::string who = actor == nullptr
                              ? session.state().organization()
                              : actor->display_name + " [" + kind_text(actor->kind) + "]";
        std::println("#{:<5} {}  {}  by {}", index,
                     format_time(session.log_entry(index).registered_at),
                     statement_summary(session, statement), who);
        if (s.provenance) {
            std::string line = "model " + s.provenance->model.value_or("-");
            if (s.provenance->model_version) {
                line += " " + *s.provenance->model_version;
            }
            for (const protocol::ToolPin& tool : s.provenance->tools) {
                line += ", via " + tool.name;
            }
            if (s.provenance->input_commitment) {
                line += ", inputs committed";
            }
            std::println("       AI provenance: {}", line);
        }
        if (actor != nullptr && actor->kind == protocol::ActorKind::person) {
            std::println("       {}",
                         s.presence ? "presence proven with a passkey" : "presence not proven");
        }
        if (actor != nullptr && actor->responsible) {
            std::println("       responsible: {}", session.actor_name(*actor->responsible));
        }
        if (s.delegation_id) {
            std::vector<std::string> names;
            for (const protocol::Id& id : authority_chain(session, s.delegation_id)) {
                names.push_back(session.actor_name(id));
            }
            std::println("       authorized by {}", join(names, " <- "));
        }
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_record_fields(const Args& args) {
    Session session(args);
    const protocol::RecordState& record = find_record(session, args);
    const Vault vault = read_vault(session, record.id, args);
    if (args.json()) {
        Json fields = Json::object();
        for (const protocol::RecordField& f : vault.fields) {
            fields[f.name] = cbor_json(f.value);
        }
        Json attachments = Json::array();
        for (const VaultAttachment& a : vault.attachments) {
            attachments.push_back(a.name);
        }
        print_json(
            {{"record", id_json(record.id)}, {"fields", fields}, {"attachments", attachments}});
        return exit_ok;
    }
    for (const protocol::RecordField& f : vault.fields) {
        std::println("{} = {}", f.name, display_value(f.value));
    }
    return exit_ok;
}

int cmd_record_endorse(const Args& args) {
    Session session(args);
    const protocol::RecordEndorseBody body{session.record_id(args.positional().front()),
                                           args.need("role")};
    const protocol::Id id = session.submit(args, body);
    return report_submitted(args, session, id,
                            {{"record", id_json(body.record)}, {"role", body.role}},
                            "endorsed " + short_id(body.record) + " as " + body.role);
}

int cmd_record_transition(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    const std::string from = session.state().record(record)->state;
    const protocol::RecordTransitionBody body{record, from, args.need("to")};
    const protocol::Id id = session.submit(args, body);
    return report_submitted(args, session, id,
                            {{"record", id_json(record)}, {"from", from}, {"to", body.to_state}},
                            short_id(record) + ": " + from + " -> " + body.to_state);
}

int cmd_record_revoke(const Args& args) {
    Session session(args);
    const protocol::RecordRevokeBody body{session.record_id(args.positional().front()),
                                          args.get("reason")};
    const protocol::Id id = session.submit(args, body);
    return report_submitted(args, session, id, {{"record", id_json(body.record)}},
                            "revoked record " + hex_id(body.record));
}

int cmd_record_types(const Args& args) {
    Json out = Json::array();
    for (const protocol::RecordType& type : protocol::builtin_record_types()) {
        Json transitions = Json::array();
        for (const protocol::Transition& t : type.transitions) {
            transitions.push_back({{"from", t.from}, {"to", t.to}});
        }
        Json roles = Json::array();
        for (const std::string_view role : type.roles) {
            roles.push_back(role);
        }
        out.push_back({{"name", type.name},
                       {"purpose", record_type_purpose(type.name)},
                       {"initial_state", type.initial_state},
                       {"transitions", std::move(transitions)},
                       {"roles", std::move(roles)}});
    }
    if (args.json()) {
        print_json(out);
        return exit_ok;
    }
    std::println("A record is a document of any kind, and its type is a name its registrant\n"
                 "chooses, such as example.org.photo/1 (by convention: your domain, a name, and\n"
                 "a version). Every such type has the generic lifecycle: a record starts in\n"
                 "\"{}\", has no transitions, may be endorsed in any role (once per actor and\n"
                 "role), and may be revoked. Rules beyond that belong in a contract.\n\n"
                 "The protocol's own types carry its mechanisms. Other names beginning with\n"
                 "\"{}\" are reserved for the protocol.\n",
                 protocol::generic_initial_state, protocol::reserved_type_prefix);
    const auto list_or_none = [](const std::string& text) {
        return text.empty() ? std::string("none") : text;
    };
    for (const auto& type : out) {
        std::println("{}", type["name"].get<std::string>());
        std::println("  for:         {}", type["purpose"].get<std::string>());
        std::println("  starts in:   {}", type["initial_state"].get<std::string>());
        std::string transitions;
        for (const auto& t : type["transitions"]) {
            transitions += (transitions.empty() ? "" : ", ") + t["from"].get<std::string>() +
                           " -> " + t["to"].get<std::string>();
        }
        std::println("  transitions: {}", list_or_none(transitions));
        std::string roles;
        for (const auto& role : type["roles"]) {
            roles += (roles.empty() ? "" : ", ") + role.get<std::string>();
        }
        std::println("  endorsed in: {}", roles.empty() ? std::string("no role") : roles);
    }
    return exit_ok;
}

} // namespace cexchain::cli
