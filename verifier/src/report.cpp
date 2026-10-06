// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <chrono>
#include <format>

#include <cexchain/verifier/report.hpp>

namespace cexchain::verifier {

namespace {

std::string hex_id(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string short_id(const protocol::Id& id) {
    return hex_id(id).substr(0, 12);
}

Json optional_text(const std::optional<std::string>& text) {
    return text ? Json(*text) : Json(nullptr);
}

Json actor_json(const protocol::ActorSummary& actor) {
    Json out{{"id", hex_id(actor.id)}, {"kind", kind_text(actor.kind)}, {"name", actor.name}};
    if (actor.agent) {
        out["model"] = optional_text(actor.agent->model);
        out["model_version"] = optional_text(actor.agent->model_version);
    }
    if (actor.responsible) {
        out["responsible"] = *actor.responsible;
    }
    return out;
}

std::string_view attachment_status(protocol::AttachmentStatus status) {
    switch (status) {
    case protocol::AttachmentStatus::verified:
        return "verified";
    case protocol::AttachmentStatus::mismatch:
        return "mismatch";
    case protocol::AttachmentStatus::not_provided:
        return "not-provided";
    }
    return "unknown";
}

std::string event_line(const protocol::RecordEvent& event) {
    std::string actor = "\"" + event.actor.name + "\" [" + kind_label(event.actor.kind);
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
    if (event.actor.kind == protocol::ActorKind::person) {
        // Machine by default: only a proof of presence shows a person acted.
        actor += event.presence
                     ? (event.presence->user_verified ? "; present: passkey, user verified"
                                                      : "; present: passkey")
                     : "; presence not proven";
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

std::string format_time(protocol::Timestamp ms) {
    using namespace std::chrono;
    const sys_time<milliseconds> time{milliseconds{static_cast<std::int64_t>(ms)}};
    return std::format("{:%Y-%m-%d %H:%M:%S} UTC", floor<seconds>(time));
}

std::string iso_time(protocol::Timestamp ms) {
    using namespace std::chrono;
    const sys_time<milliseconds> time{milliseconds{static_cast<std::int64_t>(ms)}};
    return std::format("{:%Y-%m-%dT%H:%M:%S}Z", time);
}

std::string kind_text(const std::optional<protocol::ActorKind>& kind) {
    if (!kind) {
        return "organization";
    }
    switch (*kind) {
    case protocol::ActorKind::person:
        return "person";
    case protocol::ActorKind::agent:
        return "agent";
    case protocol::ActorKind::device:
        return "device";
    }
    return "unknown";
}

std::string kind_label(const std::optional<protocol::ActorKind>& kind) {
    return kind == protocol::ActorKind::agent ? "AI agent" : kind_text(kind);
}

std::string display_value(const cbor::Value& value) {
    if (const std::string* text = value.as_text()) {
        return *text;
    }
    return cbor::diagnostic(value);
}

Json cbor_json(const cbor::Value& value) {
    if (const std::string* text = value.as_text()) {
        return *text;
    }
    if (const auto number = value.as_int64()) {
        return *number;
    }
    if (const auto number = value.as_uint64()) {
        return *number;
    }
    if (const auto flag = value.as_bool()) {
        return *flag;
    }
    if (value.is_null()) {
        return nullptr;
    }
    if (const cbor::Map* map = value.as_map();
        map != nullptr && std::ranges::all_of(*map, [](const cbor::MapEntry& e) {
            return e.key.as_text() != nullptr;
        })) {
        Json out = Json::object();
        for (const cbor::MapEntry& entry : *map) {
            out[*entry.key.as_text()] = cbor_json(entry.value);
        }
        return out;
    }
    if (const cbor::Array* array = value.as_array()) {
        Json out = Json::array();
        for (const cbor::Value& item : *array) {
            out.push_back(cbor_json(item));
        }
        return out;
    }
    return cbor::diagnostic(value);
}

Json provenance_json(const protocol::Provenance& p) {
    Json tools = Json::array();
    for (const protocol::ToolPin& tool : p.tools) {
        tools.push_back({{"name", tool.name}, {"digest", to_hex(tool.digest)}});
    }
    return {{"model", optional_text(p.model)},
            {"model_version", optional_text(p.model_version)},
            {"input_commitment",
             p.input_commitment ? Json(to_hex(*p.input_commitment)) : Json(nullptr)},
            {"tools", std::move(tools)}};
}

Json checkpoint_json(const protocol::Checkpoint& c) {
    return {{"ledger_id", hex_id(c.ledger_id)},
            {"tree_hash", crypto::name(c.tree_hash)},
            {"tree_size", c.tree_size},
            {"root", to_hex(c.root.bytes())},
            {"timestamp", iso_time(c.timestamp)}};
}

bool has_attachment_mismatch(const protocol::EvidenceReport& report) {
    return std::ranges::any_of(report.attachments, [](const protocol::AttachmentCheck& a) {
        return a.status == protocol::AttachmentStatus::mismatch;
    });
}

Json report_json(const protocol::EvidenceReport& r, bool ledger_checked) {
    Json events = Json::array();
    for (const protocol::RecordEvent& e : r.events) {
        Json authority = Json::array();
        for (const protocol::ActorSummary& a : e.authority) {
            authority.push_back(actor_json(a));
        }
        events.push_back(
            {{"index", e.index},
             {"registered_at", iso_time(e.registered_at)},
             {"issued_at", iso_time(e.issued_at)},
             {"type", protocol::name(e.type)},
             {"summary", event_line(e)},
             {"actor", actor_json(e.actor)},
             {"authority", std::move(authority)},
             {"provenance", e.provenance ? provenance_json(*e.provenance) : Json(nullptr)},
             {"presence", e.presence ? Json{{"user_verified", e.presence->user_verified},
                                            {"origin", e.presence->origin},
                                            {"rp_id", e.presence->rp_id},
                                            {"label", e.presence->label ? Json(*e.presence->label)
                                                                        : Json(nullptr)}}
                                     : Json(nullptr)},
             {"detail", e.detail}});
    }
    Json fields = Json::object();
    for (const protocol::RecordField& f : r.disclosed_fields) {
        fields[f.name] = cbor_json(f.value);
    }
    Json attachments = Json::array();
    for (const protocol::AttachmentCheck& a : r.attachments) {
        attachments.push_back({{"name", a.name},
                               {"media_type", a.media_type},
                               {"size", a.size},
                               {"status", attachment_status(a.status)}});
    }
    return {
        {"verified", !has_attachment_mismatch(r)},
        {"ledger",
         {{"id", hex_id(r.ledger_id)},
          {"organization", r.organization},
          {"hash", crypto::name(r.hash)},
          {"id_checked", ledger_checked}}},
        {"checkpoint", checkpoint_json(r.checkpoint)},
        {"witnesses",
         {{"trusted", r.trusted_cosignatures}, {"untrusted", r.untrusted_cosignatures}}},
        {"record",
         {{"id", hex_id(r.record)},
          {"type", r.record_type},
          {"state", r.state},
          {"revoked", r.revoked},
          {"metadata", r.metadata ? cbor_json(*r.metadata) : Json(nullptr)}}},
        {"events", std::move(events)},
        {"disclosed_fields", std::move(fields)},
        {"attachments", std::move(attachments)},
        {"limits",
         "A bundle cannot prove that no revocation was left out; that needs a full-log audit."}};
}

std::string report_text(const protocol::EvidenceReport& r, bool ledger_checked) {
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

} // namespace cexchain::verifier
