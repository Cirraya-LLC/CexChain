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

std::string display_value(const cbor::Value& value) {
    if (const std::string* text = value.as_text()) {
        return *text;
    }
    return cbor::diagnostic(value);
}

// ---------------------------------------------------------------------------
// Record vault: the private data behind a record's commitments.
// ---------------------------------------------------------------------------

struct VaultAttachment {
    std::string name;
    protocol::Nonce salt{};
};

struct Vault {
    std::vector<protocol::RecordField> fields;
    std::vector<VaultAttachment> attachments;
};

void save_vault(const Session& session, const protocol::Id& record, const Vault& vault) {
    cbor::Array fields;
    for (const protocol::RecordField& f : vault.fields) {
        fields.push_back(
            cbor::Value::array({cbor::Value::text(f.name), cbor::Value::bytes(f.salt), f.value}));
    }
    cbor::Array attachments;
    for (const VaultAttachment& a : vault.attachments) {
        attachments.push_back(
            cbor::Value::array({cbor::Value::text(a.name), cbor::Value::bytes(a.salt)}));
    }
    const auto bytes =
        unwrap(cbor::encode(cbor::Value::map(
                   {{cbor::Value::integer(1), cbor::Value::array(std::move(fields))},
                    {cbor::Value::integer(2), cbor::Value::array(std::move(attachments))}})),
               "encoding the vault");
    std::filesystem::create_directories(session.vault_path(record).parent_path());
    write_file(session.vault_path(record), bytes, true);
}

Vault load_vault(const Session& session, const protocol::Id& record) {
    const auto value =
        unwrap(cbor::decode(read_file(session.vault_path(record))), "reading the vault");
    Vault vault;
    auto salt_of = [](const cbor::Value& v) {
        protocol::Nonce salt{};
        if (const Bytes* bytes = v.as_bytes(); bytes != nullptr && bytes->size() == salt.size()) {
            std::ranges::copy(*bytes, salt.begin());
            return salt;
        }
        throw CommandError{"the record vault is corrupted"};
    };
    for (const cbor::Value& item : *value.find(1)->as_array()) {
        const cbor::Array& parts = *item.as_array();
        vault.fields.push_back({*parts[0].as_text(), salt_of(parts[1]), parts[2]});
    }
    for (const cbor::Value& item : *value.find(2)->as_array()) {
        const cbor::Array& parts = *item.as_array();
        vault.attachments.push_back({*parts[0].as_text(), salt_of(parts[1])});
    }
    return vault;
}

std::string event_line(const protocol::RecordEvent& event) {
    std::string actor = "\"" + event.actor.name + "\" [" + std::string(kind_name(event.actor.kind));
    if (event.actor.kind == protocol::ActorKind::agent) {
        if (event.provenance && event.provenance->model) {
            actor += ": " + *event.provenance->model;
        }
        if (event.actor.responsible) {
            actor += "; responsible: " + *event.actor.responsible;
        }
    }
    actor += "]";
    switch (event.type) {
    case protocol::StatementType::record_register:
        return "registered by " + actor;
    case protocol::StatementType::record_endorse:
        return "endorsed as " + event.detail + " by " + actor;
    case protocol::StatementType::record_transition:
        return "moved " + event.detail + " by " + actor;
    case protocol::StatementType::record_revoke:
        return "revoked by " + actor + (event.detail.empty() ? "" : " (" + event.detail + ")");
    default:
        return std::string(protocol::name(event.type)) + " by " + actor;
    }
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
    ledger::SystemEntropy entropy;

    Vault vault;
    for (const std::string& field : args.all("field")) {
        auto [name, value] = split_pair(field, "--field");
        vault.fields.push_back({name, entropy.bytes<16>(), cbor::Value::text(value)});
    }
    if (vault.fields.empty()) {
        throw UsageError{"a record needs at least one --field NAME=VALUE"};
    }
    const auto commitment =
        unwrap(protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
               "committing to the fields");
    vault.fields = commitment.fields;

    protocol::RecordRegisterBody body;
    body.record_type = args.need("type");
    body.field_root = Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end());
    body.field_count = commitment.leaves.size();
    for (const std::string& path_text : args.all("attach")) {
        const std::filesystem::path path = path_text;
        const Bytes content = read_file(path);
        const VaultAttachment attachment{path.filename().string(), entropy.bytes<16>()};
        const auto digest =
            unwrap(protocol::attachment_commitment(session.provider(), session.state().hash(),
                                                   attachment.salt, content),
                   "committing to an attachment");
        std::string media_type = "application/octet-stream";
        if (path.extension() == ".pdf") {
            media_type = "application/pdf";
        } else if (path.extension() == ".ofd") {
            media_type = "application/ofd";
        } else if (path.extension() == ".json") {
            media_type = "application/json";
        } else if (path.extension() == ".png") {
            media_type = "image/png";
        } else if (path.extension() == ".jpg" || path.extension() == ".jpeg") {
            media_type = "image/jpeg";
        }
        body.attachments.push_back({attachment.name, media_type, content.size(),
                                    Bytes(digest.bytes().begin(), digest.bytes().end())});
        vault.attachments.push_back(attachment);
    }
    cbor::Map metadata;
    for (const std::string& item : args.all("meta")) {
        auto [name, value] = split_pair(item, "--meta");
        metadata.push_back({cbor::Value::text(name), cbor::Value::text(value)});
    }
    if (!metadata.empty()) {
        body.metadata = cbor::Value::map(std::move(metadata));
    }

    const auto id = session.submit(signer, body, args.get("delegation"), provenance_from(args));
    save_vault(session, id, vault);
    const protocol::RecordState* record = session.state().record(id);
    std::println("issued {} {}", body.record_type, hex_id(id));
    std::println("state: {}", record->state);
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
    const protocol::EvidenceReport& r = *result;
    std::println("CexChain evidence report\n");
    std::println("  Ledger       {} (id {}, {})", r.organization, short_id(r.ledger_id),
                 crypto::name(r.hash));
    if (!options.expected_ledger) {
        std::println("               ! not compared with an expected ledger id (--ledger-id)");
    }
    std::println("  Checkpoint   size {}, signed {} by the ledger's log key",
                 r.checkpoint.tree_size, format_time(r.checkpoint.timestamp));
    std::println("  Witnesses    {} trusted, {} other", r.trusted_cosignatures,
                 r.untrusted_cosignatures);
    std::println("  Record       {} (id {})", r.record_type, short_id(r.record));
    std::println("  State        {}{}", r.state, r.revoked ? " — REVOKED" : "");
    if (r.metadata) {
        for (const cbor::MapEntry& m : *r.metadata->as_map()) {
            std::println("  Metadata     {} = {}", display_value(m.key), display_value(m.value));
        }
    }
    std::println("\n  History");
    for (const protocol::RecordEvent& event : r.events) {
        std::println("    #{:<4} {}  {}", event.index, format_time(event.registered_at),
                     event_line(event));
        if (!event.authority.empty()) {
            std::string chain;
            for (const protocol::ActorSummary& link : event.authority) {
                chain += (chain.empty() ? "" : " <- ") + link.name;
            }
            std::println("           authorized by {}", chain);
        }
    }
    if (!r.disclosed_fields.empty()) {
        std::println("\n  Disclosed fields (each proven against the record's commitment)");
        for (const protocol::RecordField& f : r.disclosed_fields) {
            std::println("    {} = {}", f.name, display_value(f.value));
        }
    }
    if (!r.attachments.empty()) {
        std::println("\n  Attachments");
        for (const protocol::AttachmentCheck& a : r.attachments) {
            const char* status = a.status == protocol::AttachmentStatus::verified ? "matches"
                                 : a.status == protocol::AttachmentStatus::mismatch
                                     ? "DOES NOT MATCH"
                                     : "not checked (pass --attachment NAME=PATH)";
            std::println("    {} ({}, {} bytes): {}", a.name, a.media_type, a.size, status);
        }
    }
    std::println(
        "\n  Verified: every statement above is signed, authorized under the ledger's rules,");
    std::println("  and included in the checkpointed log.");
    std::println(
        "  Not provable from a bundle: that no revocation was left out (needs a full-log audit).");
    const bool mismatch =
        std::ranges::any_of(r.attachments, [](const protocol::AttachmentCheck& a) {
            return a.status == protocol::AttachmentStatus::mismatch;
        });
    return mismatch ? 2 : 0;
}

} // namespace cexchain::cli
