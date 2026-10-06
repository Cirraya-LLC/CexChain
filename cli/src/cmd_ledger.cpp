// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <print>

#include <cexchain/core/cbor.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

constexpr std::uint64_t default_list_limit = 100;

Json status_json(Session& session) {
    const auto& state = session.state();
    const std::uint64_t size = session.ledger().size();
    Json out{{"ledger_id", id_json(state.ledger_id())},
             {"organization", state.organization()},
             {"hash", crypto::name(state.hash())},
             {"directory", session.directory().string()},
             {"root_key", public_key_json(state.root_key())},
             {"log_key", public_key_json(state.log_key())},
             {"entries", size},
             {"root", hex_json(unwrap(session.ledger().root(size), "computing the root").bytes())},
             {"actors", state.actors().size()},
             {"delegations", state.delegations().size()},
             {"records", state.records().size()}};
    if (const auto& checkpoint = session.ledger().latest_checkpoint()) {
        out["checkpoint"] = checkpoint_json(checkpoint->checkpoint);
        out["unchecked_entries"] = size - checkpoint->checkpoint.tree_size;
    } else {
        out["checkpoint"] = nullptr;
        out["unchecked_entries"] = size;
    }
    return out;
}

} // namespace

int cmd_init(const Args& args) {
    const std::filesystem::path directory = args.ledger();
    if (std::filesystem::exists(directory) && !std::filesystem::is_empty(directory)) {
        throw CommandError{directory.string() + " exists and is not empty"};
    }
    const auto root = load_key(args.need("root-key"), args);
    const auto log = load_key(args.need("log-key"), args);
    if (root.public_key() == log.public_key()) {
        throw UsageError{"the root key and the log key must differ"};
    }
    create_ledger(directory, root, log.public_key(),
                  parse_hash(args.get("hash").value_or("sha256")), args.need("org"));
    Session session(directory);
    if (args.json()) {
        print_json(status_json(session));
        return exit_ok;
    }
    std::println("created ledger {}", hex_id(session.state().ledger_id()));
    std::println("organization:  {}", session.state().organization());
    std::println("hash:          {}", crypto::name(session.state().hash()));
    std::println("directory:     {}", directory.string());
    std::println("\nShare the ledger id with the parties who will verify your evidence.");
    return exit_ok;
}

int cmd_status(const Args& args) {
    Session session(args.ledger());
    const Json s = status_json(session);
    if (args.json()) {
        print_json(s);
        return exit_ok;
    }
    std::println("ledger:        {}", s["ledger_id"].get<std::string>());
    std::println("organization:  {}", s["organization"].get<std::string>());
    std::println("hash:          {}", s["hash"].get<std::string>());
    std::println("entries:       {}", s["entries"].get<std::uint64_t>());
    std::println("root:          {}", s["root"].get<std::string>());
    if (const auto& checkpoint = session.ledger().latest_checkpoint()) {
        std::println("checkpoint:    size {} at {}{}", checkpoint->checkpoint.tree_size,
                     format_time(checkpoint->checkpoint.timestamp),
                     s["unchecked_entries"].get<std::uint64_t>() == 0
                         ? ""
                         : std::format(" ({} newer entries not yet checkpointed)",
                                       s["unchecked_entries"].get<std::uint64_t>()));
    } else {
        std::println("checkpoint:    none yet (cexchain checkpoint create)");
    }
    std::println("actors:        {}", s["actors"].get<std::size_t>());
    std::println("delegations:   {}", s["delegations"].get<std::size_t>());
    std::println("records:       {}", s["records"].get<std::size_t>());
    return exit_ok;
}

int cmd_audit(const Args& args) {
    // Opening the session replays and re-validates every statement.
    Session session(args.ledger());
    const auto report = session.ledger().audit();
    if (!report) {
        if (args.json()) {
            print_json({{"ok", false}, {"error", report.error().detail}});
        } else {
            std::println("AUDIT FAILED: {}", report.error().detail);
        }
        return exit_not_verified;
    }
    if (args.json()) {
        print_json({{"ok", true},
                    {"entries", report->entries},
                    {"checkpoints", report->checkpoints},
                    {"actors", report->actors},
                    {"delegations", report->delegations},
                    {"records", report->records},
                    {"unchecked_entries", report->unchecked_entries}});
        return exit_ok;
    }
    std::println("audit passed");
    std::println("  {} entries replayed and re-validated under the ledger rules", report->entries);
    std::println("  {} checkpoints verified against the log", report->checkpoints);
    std::println("  {} actors, {} delegations, {} records", report->actors, report->delegations,
                 report->records);
    if (report->unchecked_entries > 0) {
        std::println("  note: {} entries are newer than the latest checkpoint",
                     report->unchecked_entries);
    }
    return exit_ok;
}

int cmd_log_list(const Args& args) {
    Session session(args.ledger());
    const std::uint64_t size = session.ledger().size();
    const std::uint64_t from = args.has("from") ? parse_number(*args.get("from"), "--from") : 0;
    const std::uint64_t limit =
        args.has("limit") ? parse_number(*args.get("limit"), "--limit") : default_list_limit;
    const std::optional<protocol::StatementType> type =
        args.has("type") ? std::optional(parse_statement_type(*args.get("type"))) : std::nullopt;
    Json out = Json::array();
    std::uint64_t shown = 0;
    for (std::uint64_t i = from; i < size && shown < limit; ++i) {
        const protocol::SignedStatement statement = session.statement(i);
        if (type && statement.statement.type() != *type) {
            continue;
        }
        ++shown;
        if (args.json()) {
            out.push_back(entry_json(session, i));
            continue;
        }
        const protocol::LogEntry entry = session.log_entry(i);
        const std::string signer = statement.statement.actor_id
                                       ? session.actor_name(*statement.statement.actor_id)
                                       : session.state().organization();
        std::println("#{:<5} {}  {:<20} {}", i, format_time(entry.registered_at), signer,
                     statement_summary(session, statement));
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_log_show(const Args& args) {
    Session session(args.ledger());
    const std::uint64_t index = session.entry_index(args.positional().front());
    const protocol::SignedStatement statement = session.statement(index);
    const protocol::LogEntry entry = session.log_entry(index);
    if (args.json()) {
        Json out = entry_json(session, index);
        if (args.has("raw")) {
            out["raw"] = cbor::diagnostic(unwrap(cbor::decode(entry.statement), "decoding"));
        }
        print_json(out);
        return exit_ok;
    }
    const protocol::Statement& s = statement.statement;
    std::println("entry:         #{}", index);
    std::println("statement id:  {}", hex_id(entry.statement_id));
    std::println("type:          {}", protocol::name(s.type()));
    std::println("summary:       {}", statement_summary(session, statement));
    std::println("registered:    {}", format_time(entry.registered_at));
    std::println("issued:        {}", format_time(s.issued_at));
    if (s.actor_id) {
        const protocol::ActorState* actor = session.state().actor(*s.actor_id);
        std::println("signer:        {} [{}] {}", session.actor_name(*s.actor_id),
                     actor == nullptr ? "unknown" : kind_text(actor->kind), hex_id(*s.actor_id));
    } else {
        std::println("signer:        {} [organization root key]", session.state().organization());
    }
    std::println("signature:     {}, key id {}", crypto::name(statement.envelope.algorithm),
                 short_id(statement.kid));
    if (s.delegation_id) {
        std::string chain;
        for (const protocol::Id& id : authority_chain(session, s.delegation_id)) {
            chain += (chain.empty() ? "" : " <- ") + session.actor_name(id);
        }
        std::println("delegation:    {} (authorized by {})", short_id(*s.delegation_id),
                     chain.empty() ? "unknown" : chain);
    }
    if (s.provenance) {
        const protocol::Provenance& p = *s.provenance;
        std::println("provenance:    model {}{}", p.model.value_or("-"),
                     p.model_version ? " " + *p.model_version : "");
        if (p.input_commitment) {
            std::println("               inputs committed as {}", to_hex(*p.input_commitment));
        }
        for (const protocol::ToolPin& tool : p.tools) {
            std::println("               tool {} ({})", tool.name,
                         to_hex(tool.digest).substr(0, 16));
        }
    }
    std::println("body:\n{}", body_json(s.body).dump(2));
    if (args.has("raw")) {
        std::println("raw COSE_Sign1:\n{}",
                     cbor::diagnostic(unwrap(cbor::decode(entry.statement), "decoding")));
    }
    return exit_ok;
}

int cmd_log_export(const Args& args) {
    Session session(args.ledger());
    const std::uint64_t size = session.ledger().size();
    const std::uint64_t from = args.has("from") ? parse_number(*args.get("from"), "--from") : 0;
    const std::uint64_t to = args.has("to") ? parse_number(*args.get("to"), "--to") : size - 1;
    if (from > to || to >= size) {
        throw UsageError{std::format("the range must lie within 0..{}", size - 1)};
    }
    cbor::Array entries;
    for (std::uint64_t i = from; i <= to; ++i) {
        entries.push_back(cbor::Value::bytes(unwrap(session.ledger().entry(i), "reading the log")));
    }
    const std::filesystem::path out = args.need("out");
    write_file(out, unwrap(cbor::encode(cbor::Value::array(std::move(entries))), "encoding"),
               false);
    if (args.json()) {
        print_json(
            {{"file", out.string()}, {"from", from}, {"to", to}, {"entries", to - from + 1}});
    } else {
        std::println("wrote entries {}..{} ({} entries) to {}", from, to, to - from + 1,
                     out.string());
    }
    return exit_ok;
}

} // namespace cexchain::cli
