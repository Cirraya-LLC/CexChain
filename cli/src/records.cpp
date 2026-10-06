// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "records.hpp"

#include <algorithm>
#include <format>
#include <string>

#include <cexchain/core/cbor.hpp>

namespace cexchain::cli {

namespace {

std::string event_line(const protocol::RecordEvent& event) {
    std::string actor = "\"" + event.actor.name + "\" [" + std::string(kind_name(event.actor.kind));
    if (event.actor.kind == protocol::ActorKind::agent) {
        if (event.provenance && event.provenance->model) {
            actor += ": " + *event.provenance->model;
        }
        if (event.actor.responsible) {
            actor += "; responsible: " + *event.actor.responsible;
        }
        if (event.provenance && !event.provenance->tools.empty()) {
            std::string tools;
            for (const protocol::ToolPin& tool : event.provenance->tools) {
                tools += (tools.empty() ? "" : ", ") + tool.name;
            }
            actor += "; via " + tools;
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

std::string media_type_for(const std::filesystem::path& path) {
    const std::string extension = path.extension().string();
    if (extension == ".pdf") {
        return "application/pdf";
    }
    if (extension == ".ofd") {
        return "application/ofd";
    }
    if (extension == ".json") {
        return "application/json";
    }
    if (extension == ".png") {
        return "image/png";
    }
    if (extension == ".jpg" || extension == ".jpeg") {
        return "image/jpeg";
    }
    return "application/octet-stream";
}

} // namespace

std::string display_value(const cbor::Value& value) {
    if (const std::string* text = value.as_text()) {
        return *text;
    }
    return cbor::diagnostic(value);
}

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

protocol::Id issue_record(Session& session, const crypto::Signer& signer,
                          const IssueRequest& request) {
    ledger::SystemEntropy entropy;
    if (request.fields.empty()) {
        throw UsageError{"a record needs at least one field"};
    }
    Vault vault;
    for (const auto& [name, value] : request.fields) {
        vault.fields.push_back({name, entropy.bytes<16>(), cbor::Value::text(value)});
    }
    const auto commitment =
        unwrap(protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
               "committing to the fields");
    vault.fields = commitment.fields;

    protocol::RecordRegisterBody body;
    body.record_type = request.record_type;
    body.field_root = Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end());
    body.field_count = commitment.leaves.size();
    for (const std::filesystem::path& path : request.attachments) {
        const Bytes content = read_file(path);
        const VaultAttachment attachment{path.filename().string(), entropy.bytes<16>()};
        const auto digest =
            unwrap(protocol::attachment_commitment(session.provider(), session.state().hash(),
                                                   attachment.salt, content),
                   "committing to an attachment");
        body.attachments.push_back({attachment.name, media_type_for(path), content.size(),
                                    Bytes(digest.bytes().begin(), digest.bytes().end())});
        vault.attachments.push_back(attachment);
    }
    if (!request.metadata.empty()) {
        cbor::Map metadata;
        for (const auto& [name, value] : request.metadata) {
            metadata.push_back({cbor::Value::text(name), cbor::Value::text(value)});
        }
        body.metadata = cbor::Value::map(std::move(metadata));
    }
    const protocol::Id id = session.submit(signer, body, request.delegation, request.provenance);
    save_vault(session, id, vault);
    return id;
}

std::string format_report(const protocol::EvidenceReport& r, bool ledger_checked) {
    std::string out;
    auto line = [&out](const std::string& text) {
        out += text + "\n";
    };
    line("CexChain evidence report\n");
    line(std::format("  Ledger       {} (id {}, {})", r.organization, short_id(r.ledger_id),
                     crypto::name(r.hash)));
    if (!ledger_checked) {
        line("               ! not compared with an expected ledger id");
    }
    line(std::format("  Checkpoint   size {}, signed {} by the ledger's log key",
                     r.checkpoint.tree_size, format_time(r.checkpoint.timestamp)));
    line(std::format("  Witnesses    {} trusted, {} other", r.trusted_cosignatures,
                     r.untrusted_cosignatures));
    line(std::format("  Record       {} (id {})", r.record_type, short_id(r.record)));
    line(std::format("  State        {}{}", r.state, r.revoked ? " - REVOKED" : ""));
    if (r.metadata) {
        for (const cbor::MapEntry& m : *r.metadata->as_map()) {
            line(std::format("  Metadata     {} = {}", display_value(m.key),
                             display_value(m.value)));
        }
    }
    line("\n  History");
    for (const protocol::RecordEvent& event : r.events) {
        line(std::format("    #{:<4} {}  {}", event.index, format_time(event.registered_at),
                         event_line(event)));
        if (!event.authority.empty()) {
            std::string chain;
            for (const protocol::ActorSummary& link : event.authority) {
                chain += (chain.empty() ? "" : " <- ") + link.name;
            }
            line("           authorized by " + chain);
        }
    }
    if (!r.disclosed_fields.empty()) {
        line("\n  Disclosed fields (each proven against the record's commitment)");
        for (const protocol::RecordField& f : r.disclosed_fields) {
            line(std::format("    {} = {}", f.name, display_value(f.value)));
        }
    }
    if (!r.attachments.empty()) {
        line("\n  Attachments");
        for (const protocol::AttachmentCheck& a : r.attachments) {
            const char* status = a.status == protocol::AttachmentStatus::verified ? "matches"
                                 : a.status == protocol::AttachmentStatus::mismatch
                                     ? "DOES NOT MATCH"
                                     : "not checked (attachment content not provided)";
            line(std::format("    {} ({}, {} bytes): {}", a.name, a.media_type, a.size, status));
        }
    }
    line("\n  Verified: every statement above is signed, authorized under the ledger's rules,");
    line("  and included in the checkpointed log.");
    line("  Not provable from a bundle: that no revocation was left out (needs a full-log audit).");
    return out;
}

} // namespace cexchain::cli
