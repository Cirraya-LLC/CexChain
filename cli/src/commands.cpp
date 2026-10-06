// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "commands.hpp"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <map>
#include <print>
#include <string>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/record_types.hpp>

#include "records.hpp"
#include "support.hpp"

namespace cexchain::cli {

namespace {

constexpr protocol::Timestamp day_ms = 86'400'000;

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = std::min(text.find(separator, start), text.size());
        if (end > start) {
            parts.push_back(text.substr(start, end - start));
        }
        start = end + 1;
    }
    return parts;
}

std::pair<std::string, std::string> split_pair(const std::string& text, std::string_view what) {
    const auto eq = text.find('=');
    if (eq == std::string::npos || eq == 0) {
        throw UsageError{std::string(what) + " must be NAME=VALUE: " + text};
    }
    return {text.substr(0, eq), text.substr(eq + 1)};
}

std::optional<protocol::Provenance> provenance_from(const Args& args) {
    const auto model = args.get("model");
    const auto version = args.get("model-version");
    if (!model && !version) {
        return std::nullopt;
    }
    return protocol::Provenance{model, version, std::nullopt, {}};
}

} // namespace

// ---------------------------------------------------------------------------
// Keys and ledgers
// ---------------------------------------------------------------------------

int key_generate(const Args& args) {
    const crypto::SigAlg alg = parse_algorithm(args.get("alg").value_or("ed25519"));
    const std::filesystem::path out = args.need("out");
    if (std::filesystem::exists(out)) {
        throw CommandError{out.string() + " already exists"};
    }
    const auto key = unwrap(crypto::openssl::KeyPair::generate(alg), "generating the key");
    const auto der = unwrap(key.to_pkcs8(), "encoding the key");
    write_file(out, der.view(), true);
    std::println("{} key written to {}", crypto::name(alg), out.string());
    std::println("public key: {}", to_hex(key.public_key().bytes));
    return 0;
}

int key_show(const Args& args) {
    if (args.positional().size() != 3) {
        throw UsageError{"usage: cexchain key show FILE"};
    }
    const auto key = load_key(args.positional()[2]);
    std::println("algorithm:  {}", crypto::name(key.algorithm()));
    std::println("public key: {}", to_hex(key.public_key().bytes));
    return 0;
}

int init(const Args& args) {
    const std::filesystem::path directory = args.need("ledger");
    const auto root = load_key(args.need("root-key"));
    const auto log = load_key(args.need("log-key"));
    create_ledger(directory, root, log.public_key(),
                  parse_hash(args.get("hash").value_or("sha256")), args.need("org"));
    Session session(directory);
    std::println("created ledger {}", hex_id(session.state().ledger_id()));
    std::println("organization:  {}", session.state().organization());
    std::println("hash:          {}", crypto::name(session.state().hash()));
    return 0;
}

int status(const Args& args) {
    Session session(args.need("ledger"));
    const auto& state = session.state();
    std::println("ledger:        {}", hex_id(state.ledger_id()));
    std::println("organization:  {}", state.organization());
    std::println("hash:          {}", crypto::name(state.hash()));
    std::println("entries:       {}", session.ledger().size());
    std::println("root:          {}",
                 to_hex(unwrap(session.ledger().root(session.ledger().size()), "root").bytes()));
    if (const auto& checkpoint = session.ledger().latest_checkpoint()) {
        std::println("checkpoint:    size {} at {}", checkpoint->checkpoint.tree_size,
                     format_time(checkpoint->checkpoint.timestamp));
    } else {
        std::println("checkpoint:    none yet");
    }
    std::println("actors:        {}", state.actors().size());
    std::println("delegations:   {}", state.delegations().size());
    std::println("records:       {}", state.records().size());
    return 0;
}

// ---------------------------------------------------------------------------
// Actors and delegations
// ---------------------------------------------------------------------------

int actor_add(const Args& args) {
    Session session(args.need("ledger"));
    const auto signer = load_key(args.need("as"));
    const auto key = load_key(args.need("key"));
    protocol::ActorRegisterBody body{parse_actor_kind(args.need("kind")), args.need("name"),
                                     key.public_key(), std::nullopt, std::nullopt};
    if (const auto responsible = args.get("responsible")) {
        body.responsible = session.actor_id(*responsible);
    }
    if (body.kind == protocol::ActorKind::agent) {
        body.agent = protocol::AgentProfile{args.get("model"), args.get("model-version"),
                                            args.get("runtime")};
        if (!body.agent->model) {
            throw UsageError{"agents need --model (the model they run)"};
        }
    }
    const auto id = session.submit(signer, body, args.get("delegation"));
    std::println("registered {} \"{}\" as {}", kind_name(body.kind), body.display_name, hex_id(id));
    return 0;
}

int actor_list(const Args& args) {
    Session session(args.need("ledger"));
    for (const auto& [key, actor] : session.state().actors()) {
        std::string line = std::format("{}  {:<12} {}", short_id(actor.id), kind_name(actor.kind),
                                       actor.display_name);
        if (actor.agent && actor.agent->model) {
            line += "  (model " + *actor.agent->model + ")";
        }
        if (actor.revoked) {
            line += "  [revoked]";
        }
        std::println("{}", line);
    }
    return 0;
}

int delegate(const Args& args) {
    Session session(args.need("ledger"));
    const auto signer = load_key(args.need("as"));
    protocol::Scope scope;
    for (const std::string& name : split(args.need("allow"), ',')) {
        scope.statement_types.push_back(parse_statement_type(name));
    }
    if (const auto types = args.get("record-types")) {
        scope.record_types = split(*types, ',');
    }
    if (const auto until = args.get("until")) {
        scope.not_after = parse_time(*until);
    } else if (const auto days = args.get("days")) {
        scope.not_after = ledger::SystemClock{}.now() + std::stoull(*days) * day_ms;
    }
    scope.may_delegate = args.has("may-delegate");
    const protocol::DelegationGrantBody body{session.actor_id(args.need("to")), scope};
    const auto id = session.submit(signer, body, args.get("delegation"), provenance_from(args));
    std::println("granted delegation {}", hex_id(id));
    return 0;
}

int revoke_delegation(const Args& args) {
    Session session(args.need("ledger"));
    const auto signer = load_key(args.need("as"));
    const protocol::DelegationRevokeBody body{session.delegation_id(args.need("id")),
                                              args.get("reason")};
    session.submit(signer, body, args.get("delegation"), provenance_from(args));
    std::println("revoked delegation {}", hex_id(body.delegation));
    return 0;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

int issue(const Args& args) {
    Session session(args.need("ledger"));
    const auto signer = load_key(args.need("as"));
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
    request.provenance = provenance_from(args);
    const protocol::Id id = issue_record(session, signer, request);
    std::println("issued {} {}", request.record_type, hex_id(id));
    std::println("state: {}", session.state().record(id)->state);
    return 0;
}

int endorse(const Args& args) {
    Session session(args.need("ledger"));
    const auto signer = load_key(args.need("as"));
    const protocol::RecordEndorseBody body{session.record_id(args.need("record")),
                                           args.need("role")};
    session.submit(signer, body, args.get("delegation"), provenance_from(args));
    std::println("endorsed {} as {}", short_id(body.record), body.role);
    return 0;
}

int transition(const Args& args) {
    Session session(args.need("ledger"));
    const auto signer = load_key(args.need("as"));
    const protocol::Id record = session.record_id(args.need("record"));
    const std::string from = session.state().record(record)->state;
    const protocol::RecordTransitionBody body{record, from, args.need("to")};
    session.submit(signer, body, args.get("delegation"), provenance_from(args));
    std::println("{}: {} -> {}", short_id(record), from, body.to_state);
    return 0;
}

int revoke_record(const Args& args) {
    Session session(args.need("ledger"));
    const auto signer = load_key(args.need("as"));
    const protocol::RecordRevokeBody body{session.record_id(args.need("record")),
                                          args.get("reason")};
    session.submit(signer, body, args.get("delegation"), provenance_from(args));
    std::println("revoked record {}", short_id(body.record));
    return 0;
}

int record_show(const Args& args) {
    Session session(args.need("ledger"));
    const protocol::Id id = session.record_id(args.need("record"));
    const protocol::RecordState& record = *session.state().record(id);
    std::println("record:  {}", hex_id(id));
    std::println("type:    {}", record.record_type);
    std::println("state:   {}{}", record.state, record.revoked ? " (revoked)" : "");
    std::println("fields:  {} committed", record.field_count);
    if (const protocol::RecordType* type = protocol::find_record_type(record.record_type)) {
        std::string next;
        for (const protocol::Transition& t : type->transitions) {
            if (t.from == record.state) {
                next += (next.empty() ? "" : ", ") + std::string(t.to);
            }
        }
        std::println("next:    {}", next.empty() ? "(final state)" : next);
    }
    for (const protocol::Endorsement& e : record.endorsements) {
        std::println("endorsed as {} by {}", e.role, session.state().actor(e.actor)->display_name);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Checkpoints and evidence
// ---------------------------------------------------------------------------

int checkpoint(const Args& args) {
    Session session(args.need("ledger"));
    const auto log_key = load_key(args.need("log-key"));
    const auto signed_checkpoint = unwrap(session.ledger().checkpoint(log_key), "checkpointing");
    std::println("checkpoint: size {}, root {}", signed_checkpoint.checkpoint.tree_size,
                 to_hex(signed_checkpoint.checkpoint.root.bytes()));
    return 0;
}

int export_bundle(const Args& args) {
    Session session(args.need("ledger"));
    const auto log_key = load_key(args.need("log-key"));
    const protocol::Id record = session.record_id(args.need("record"));
    auto bundle = unwrap(session.ledger().export_evidence(log_key, record), "exporting evidence");

    const Vault vault = load_vault(session, record);
    const auto commitment =
        unwrap(protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
               "fields");
    for (const std::string& name : split(args.get("disclose").value_or(""), ',')) {
        bundle.disclosures.push_back(unwrap(
            protocol::disclose_field(session.provider(), session.state().hash(), commitment, name),
            "disclosing " + name));
    }
    if (args.has("with-attachments")) {
        for (const VaultAttachment& a : vault.attachments) {
            bundle.attachments.push_back({a.name, a.salt});
        }
    }
    const std::filesystem::path out = args.need("out");
    write_file(out, unwrap(protocol::encode_bundle(bundle), "encoding the bundle"), false);
    std::println("wrote evidence for {} ({} entries, {} disclosed fields) to {}", short_id(record),
                 bundle.entries.size(), bundle.disclosures.size(), out.string());
    return 0;
}

int verify(const Args& args) {
    if (args.positional().size() != 2) {
        throw UsageError{"usage: cexchain verify BUNDLE [options]"};
    }
    const crypto::openssl::Provider provider;
    protocol::VerifyOptions options;
    if (const auto ledger_id = args.get("ledger-id")) {
        options.expected_ledger =
            unwrap(protocol::to_id(unwrap(from_hex(*ledger_id), "ledger id")), "ledger id");
    }
    for (const std::string& path : args.all("witness")) {
        options.trusted_witnesses.push_back(load_key(path).public_key());
    }
    for (const std::string& item : args.all("attachment")) {
        auto [name, path] = split_pair(item, "--attachment");
        options.attachment_contents[name] = read_file(path);
    }

    const Bytes bundle = read_file(args.positional()[1]);
    const auto result = protocol::verify_bundle(provider, bundle, options);
    if (!result) {
        std::println("VERIFICATION FAILED: {}", result.error().detail);
        return 2;
    }
    std::print("{}", format_report(*result, options.expected_ledger.has_value()));
    const bool mismatch =
        std::ranges::any_of(result->attachments, [](const protocol::AttachmentCheck& a) {
            return a.status == protocol::AttachmentStatus::mismatch;
        });
    return mismatch ? 2 : 0;
}

} // namespace cexchain::cli
