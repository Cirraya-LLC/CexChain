// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <chrono>
#include <format>
#include <map>
#include <span>

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
    out["revoked"] = actor.revoked;
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
    std::string actor = "\"" + event.actor.name + "\" [" + kind_label(event.actor.kind) +
                        (event.actor.revoked ? ", since revoked" : "");
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
        actor += !event.presence ? "; presence not proven"
                 : event.presence->method == protocol::PresenceMethod::hardware_key
                     ? "; present: hardware key"
                     : (event.presence->user_verified ? "; present: passkey, user verified"
                                                      : "; present: passkey");
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
    case protocol::StatementType::asset_action:
        if (event.asset_action) {
            const protocol::AssetActionBody& a = *event.asset_action;
            std::string what(protocol::name(a.action));
            if (a.to) {
                what += " to ledger " + short_id(*a.to);
            }
            if (a.quantity) {
                what += std::format(" ({})", *a.quantity);
            }
            if (a.reference) {
                what += " (" + *a.reference + ")";
            }
            return what + ", recorded by " + actor;
        }
        return "asset action by " + actor;
    case protocol::StatementType::contract_call:
        if (event.contract_call) {
            const protocol::ContractCallBody& c = *event.contract_call;
            return (c.instance ? "call " : "create with ") + c.function + " by " + actor;
        }
        return "contract call by " + actor;
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
             {"presence",
              e.presence
                  ? Json{{"method", e.presence->method == protocol::PresenceMethod::hardware_key
                                        ? "hardware-key"
                                        : "webauthn"},
                         {"user_verified", e.presence->user_verified},
                         {"origin", e.presence->origin},
                         {"rp_id", e.presence->rp_id},
                         {"label", e.presence->label ? Json(*e.presence->label) : Json(nullptr)}}
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
        {"keys",
         {{"log_key",
           {{"algorithm", crypto::name(r.log_key.algorithm)}, {"key", to_hex(r.log_key.bytes)}}},
          {"log_key_rotations", r.log_key_rotations},
          {"root_key_rotations", r.root_key_rotations}}},
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
        {"complete", r.complete},
        {"state_commitment",
         r.state_commitment ? Json{{"index", r.state_commitment->tree_size},
                                   {"state_root", to_hex(r.state_commitment->state_root.bytes())},
                                   {"timestamp", iso_time(r.state_commitment->timestamp)}}
                            : Json(nullptr)},
        {"limits", r.complete ? Json(nullptr)
                              : Json("The checkpoint does not end with a state commitment, so "
                                     "the bundle cannot prove that "
                                     "nothing, such as a later revocation, was left out.")}};
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
    if (r.log_key_rotations + r.root_key_rotations > 0) {
        line(std::format("  Keys         log key rotated {} time(s), root key {} time(s); every "
                         "rotation checked",
                         r.log_key_rotations, r.root_key_rotations));
    }
    line(std::format("  Witnesses    {} trusted{}", r.trusted_cosignatures,
                     r.untrusted_cosignatures == 0
                         ? std::string()
                         : std::format(" ({} more from witnesses you do not trust, not checked)",
                                       r.untrusted_cosignatures)));
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
    if (r.complete) {
        line("  Complete: the record's whole history, and that of everyone involved, is proven");
        line("  against the state commitment in the ledger's log. Nothing, such as a revocation, "
             "was");
        line("  left out. (The commitment is part of the witnessed log, so a false one would be "
             "there");
        line("  for good; replaying the log checks it.)");
    } else {
        line("  Not provable from this bundle: that nothing, such as a revocation, was left out");
        line("  (its checkpoint does not end with a state commitment).");
    }
    return out;
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

int currency_exponent(std::string_view currency) {
    static constexpr std::array<std::string_view, 8> none{"JPY", "KRW", "VND", "CLP",
                                                          "ISK", "UGX", "PYG", "XAF"};
    static constexpr std::array<std::string_view, 7> three{"BHD", "KWD", "OMR", "JOD",
                                                           "TND", "LYD", "IQD"};
    if (std::ranges::contains(none, currency)) {
        return 0;
    }
    return std::ranges::contains(three, currency) ? 3 : 2;
}

std::string format_units(protocol::AssetKind kind, std::uint64_t units, std::string_view unit) {
    const int exponent = kind == protocol::AssetKind::receivable ? currency_exponent(unit) : 0;
    if (exponent == 0) {
        return std::format("{} {}", units, unit);
    }
    std::uint64_t scale = 1;
    for (int i = 0; i < exponent; ++i) {
        scale *= 10;
    }
    return std::format("{}.{:0{}} {}", units / scale, units % scale, exponent, unit);
}

namespace {

/// Party ledgers by id, named as their consents' evidence declares them.
using PartyNames = std::map<std::string, std::string>;

PartyNames party_names(const protocol::AssetReport& r) {
    PartyNames names;
    for (const protocol::AssetStep& step : r.steps) {
        for (const protocol::ConsentCheck& c : step.consents) {
            names[hex_id(c.ref.ledger)] = c.report.organization;
        }
    }
    return names;
}

Json party_json(const PartyNames& names, const std::optional<protocol::Id>& id) {
    if (!id) {
        return nullptr;
    }
    const auto name = names.find(hex_id(*id));
    return {{"ledger_id", hex_id(*id)},
            {"organization", name == names.end() ? Json(nullptr) : Json(name->second)}};
}

std::string party_text(const PartyNames& names, const protocol::Id& id) {
    const auto name = names.find(hex_id(id));
    return name == names.end() ? "ledger " + short_id(id)
                               : name->second + " (ledger " + short_id(id) + ")";
}

std::optional<protocol::AssetMetadata> asset_metadata(const protocol::EvidenceReport& r) {
    if (!r.asset || !r.metadata) {
        return std::nullopt;
    }
    auto m = protocol::decode_asset_metadata(r.asset->kind, *r.metadata);
    return m ? std::optional(std::move(*m)) : std::nullopt;
}

/// How a consent was given: by a person present, or by a key alone.
std::string presence_text(const protocol::RecordEvent& e) {
    if (!e.actor.kind) {
        return "the organization's own key";
    }
    if (e.actor.kind != protocol::ActorKind::person) {
        return "a machine: " + kind_label(e.actor.kind);
    }
    if (!e.presence) {
        return "a person's key, presence not proven";
    }
    return e.presence->method == protocol::PresenceMethod::hardware_key
               ? "a person, present: hardware key"
               : "a person, present: passkey";
}

/// "pledge to Bank (ledger 9a7a445f47f1), recorded by "Registrar" [device]"
std::string action_text(const PartyNames& names, const protocol::RecordEvent& e) {
    const protocol::AssetActionBody& a = *e.asset_action;
    std::string out(protocol::name(a.action));
    if (a.to) {
        out += " to " + party_text(names, *a.to);
    }
    if (a.quantity) {
        out += std::format(" ({})", *a.quantity);
    }
    if (a.reference) {
        out += " (" + *a.reference + ")";
    }
    return out + std::format(", recorded by \"{}\" [{}]", e.actor.name, kind_label(e.actor.kind));
}

} // namespace

Json asset_report_json(const protocol::AssetReport& r, bool ledger_checked) {
    const protocol::EvidenceReport& a = r.asset;
    const protocol::AssetState& asset = *a.asset;
    const PartyNames names = party_names(r);
    const auto m = asset_metadata(a);
    const std::string unit = m ? m->unit : std::string();
    Json chain = Json::array();
    for (const protocol::RecordEvent& e : a.events) {
        if (e.type == protocol::StatementType::record_register) {
            chain.push_back({{"index", e.index},
                             {"registered_at", iso_time(e.registered_at)},
                             {"action", "issue"},
                             {"to", m ? party_json(names, m->holder) : Json(nullptr)},
                             {"summary", event_line(e)},
                             {"recorded_by", actor_json(e.actor)},
                             {"consents", Json::array()}});
        }
    }
    for (const protocol::AssetStep& step : r.steps) {
        const protocol::RecordEvent& e = a.events[step.event];
        const protocol::AssetActionBody& action = *e.asset_action;
        Json consents = Json::array();
        for (const protocol::ConsentCheck& c : step.consents) {
            const protocol::RecordEvent* given =
                c.report.events.empty() ? nullptr : &c.report.events.front();
            Json authority = Json::array();
            if (given != nullptr) {
                for (const protocol::ActorSummary& link : given->authority) {
                    authority.push_back(link.name);
                }
            }
            consents.push_back(
                {{"ledger_id", hex_id(c.ref.ledger)},
                 {"organization", c.report.organization},
                 {"record", hex_id(c.ref.record)},
                 {"signer", given != nullptr ? actor_json(given->actor) : Json(nullptr)},
                 {"authority", std::move(authority)},
                 {"presence", given != nullptr ? Json(presence_text(*given)) : Json(nullptr)},
                 {"provenance", given != nullptr && given->provenance
                                    ? provenance_json(*given->provenance)
                                    : Json(nullptr)},
                 {"given_at",
                  given != nullptr ? Json(iso_time(given->registered_at)) : Json(nullptr)},
                 {"until", iso_time(c.consent.until)},
                 {"reference", optional_text(c.consent.reference)},
                 {"witnesses",
                  {{"trusted", c.report.trusted_cosignatures},
                   {"untrusted", c.report.untrusted_cosignatures}}}});
        }
        chain.push_back({{"index", e.index},
                         {"registered_at", iso_time(e.registered_at)},
                         {"action", protocol::name(action.action)},
                         {"to", party_json(names, action.to)},
                         {"quantity", action.quantity ? Json(*action.quantity) : Json(nullptr)},
                         {"reference", optional_text(action.reference)},
                         {"summary", event_line(e)},
                         {"recorded_by", actor_json(e.actor)},
                         {"consents", std::move(consents)}});
    }
    const bool receivable = asset.kind == protocol::AssetKind::receivable;
    return {{"verified", !has_attachment_mismatch(a)},
            {"asset",
             {{"id", hex_id(a.record)},
              {"type", a.record_type},
              {"state", a.state},
              {"holder", party_json(names, asset.holder)},
              {"pledgee", party_json(names, asset.pledgee)},
              {"payee", party_json(names, asset.payee)},
              {receivable ? "amount" : "quantity", asset.units},
              {receivable ? "currency" : "unit", unit},
              {"display", format_units(asset.kind, asset.units, unit)},
              {"due", m && m->due ? Json(iso_time(*m->due)) : Json(nullptr)},
              {"head", asset.head}}},
            {"home",
             {{"id", hex_id(a.ledger_id)},
              {"organization", a.organization},
              {"hash", crypto::name(a.hash)},
              {"id_checked", ledger_checked}}},
            {"checkpoint", checkpoint_json(a.checkpoint)},
            {"witnesses",
             {{"trusted", a.trusted_cosignatures}, {"untrusted", a.untrusted_cosignatures}}},
            {"chain", std::move(chain)},
            {"complete", a.complete},
            {"report", report_json(a, ledger_checked)}};
}

std::string asset_report_text(const protocol::AssetReport& r, bool ledger_checked) {
    const protocol::EvidenceReport& a = r.asset;
    const protocol::AssetState& asset = *a.asset;
    const PartyNames names = party_names(r);
    const auto m = asset_metadata(a);
    std::string out;
    auto line = [&out](const std::string& text) {
        out += text + "\n";
    };
    line("CexChain asset report\n");
    line(std::format("  Asset        {} (id {})", a.record_type, short_id(a.record)));
    line(std::format("  Home         {} (ledger {}, {})", a.organization, short_id(a.ledger_id),
                     crypto::name(a.hash)));
    if (!ledger_checked) {
        line("               ! not compared with an expected ledger id");
    }
    line(std::format("  State        {}", a.state));
    line("  Holder       " + party_text(names, asset.holder));
    if (asset.pledgee) {
        line("  Pledgee      " + party_text(names, *asset.pledgee));
    }
    if (asset.payee) {
        line("  Payee        " + party_text(names, *asset.payee));
    }
    if (m) {
        const bool receivable = asset.kind == protocol::AssetKind::receivable;
        line(std::format("  {}       {}{}", receivable ? "Amount" : "Units ",
                         format_units(asset.kind, asset.units, m->unit),
                         m->due ? ", due " + format_time(*m->due) : std::string()));
    }
    line(std::format("  Checkpoint   size {}, signed {} by the home's log key",
                     a.checkpoint.tree_size, format_time(a.checkpoint.timestamp)));
    line(std::format("  Witnesses    {} trusted{}", a.trusted_cosignatures,
                     a.untrusted_cosignatures == 0
                         ? std::string()
                         : std::format(" ({} more from witnesses you do not trust, not checked)",
                                       a.untrusted_cosignatures)));
    line("\n  Chain of title");
    for (const protocol::RecordEvent& e : a.events) {
        if (e.type == protocol::StatementType::record_register) {
            line(std::format("    #{:<4} {}  issued to {} by \"{}\" [{}]", e.index,
                             format_time(e.registered_at),
                             m ? party_text(names, m->holder) : std::string("?"), e.actor.name,
                             kind_label(e.actor.kind)));
        }
    }
    for (const protocol::AssetStep& step : r.steps) {
        const protocol::RecordEvent& e = a.events[step.event];
        line(std::format("    #{:<4} {}  {}", e.index, format_time(e.registered_at),
                         action_text(names, e)));
        for (const protocol::ConsentCheck& c : step.consents) {
            const protocol::RecordEvent* given =
                c.report.events.empty() ? nullptr : &c.report.events.front();
            std::string who = given != nullptr
                                  ? "\"" + given->actor.name + "\" (" + presence_text(*given) + ")"
                                  : "?";
            line(std::format("           consent of {}: given by {}{}", c.report.organization, who,
                             c.consent.reference ? ", ref. " + *c.consent.reference
                                                 : std::string()));
        }
    }
    if (!a.disclosed_fields.empty()) {
        line("\n  Disclosed fields (each proven against the asset's commitment)");
        for (const protocol::RecordField& f : a.disclosed_fields) {
            line(std::format("    {} = {}", f.name, display_value(f.value)));
        }
    }
    line("\n  Verified: the asset's complete history is proven against its home's state");
    line("  commitment, and each consent against the consenting party's own ledger. Party names");
    line("  are as their own ledgers declare them; ledger ids are what bind them.");
    return out;
}

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------

namespace {

/// Long values (arguments and states may be 64 KiB) shortened for a terminal.
std::string shortened(std::string text) {
    constexpr std::size_t limit = 240;
    if (text.size() <= limit) {
        return text;
    }
    const std::size_t size = text.size();
    text.resize(limit);
    // Never cut a UTF-8 sequence in two.
    while (!text.empty() && (static_cast<unsigned char>(text.back()) & 0xc0U) == 0x80U) {
        text.pop_back();
    }
    if (!text.empty() && static_cast<unsigned char>(text.back()) >= 0xc0U) {
        text.pop_back();
    }
    return std::format("{}... ({} characters)", text, size);
}

std::string encoded_hex(const cbor::Value& value) {
    auto encoded = cbor::encode(value);
    return encoded ? to_hex(*encoded) : std::string();
}

/// Party ledgers by id: the home, and each ledger that consented, as their
/// own evidence declares them.
PartyNames contract_party_names(const protocol::ContractReport& r) {
    PartyNames names;
    names[hex_id(r.instance.ledger_id)] = r.instance.organization;
    for (const protocol::ContractStep& step : r.steps) {
        for (const protocol::ContractConsentCheck& c : step.consents) {
            names[hex_id(c.ref.ledger)] = c.report.organization;
        }
    }
    return names;
}

Json parties_json(const PartyNames& names, const protocol::Parties& parties) {
    Json out = Json::object();
    for (const auto& [role, ledger] : parties) {
        out[role] = party_json(names, ledger);
    }
    return out;
}

std::string parties_text(const PartyNames& names, const protocol::Parties& parties) {
    std::string out;
    for (const auto& [role, ledger] : parties) {
        out += (out.empty() ? "" : ", ") + role + ": " + party_text(names, ledger);
    }
    return out.empty() ? "none" : out;
}

/// Who signed a consent's registration, for people: a person present, a key
/// alone, or a machine (with an AI agent's model and accountable person).
std::string signer_text(const protocol::RecordEvent& e) {
    std::string out = presence_text(e);
    if (e.actor.kind == protocol::ActorKind::agent) {
        if (e.provenance && e.provenance->model) {
            out += "; model " + *e.provenance->model;
        }
        if (e.actor.responsible) {
            out += "; responsible: " + *e.actor.responsible;
        }
    }
    return out;
}

/// What a call made of its instance; `children`, the ids of the instances
/// it created (v0.7), in order.
Json outcome_json(const PartyNames& names, const protocol::ContractAccept& a,
                  std::span<const protocol::Id> children_ids) {
    Json events = Json::array();
    for (const protocol::ContractEvent& e : a.events) {
        events.push_back({{"name", e.name}, {"data", cbor::diagnostic(e.data)}});
    }
    Json out{{"status", optional_text(a.status)},
             {"parties", a.parties ? parties_json(names, *a.parties) : Json(nullptr)},
             {"events", std::move(events)},
             {"final", a.final},
             {"state", cbor::diagnostic(a.state)}};
    // Children (v0.7), only where a call created some.
    if (!a.children.empty()) {
        Json children = Json::array();
        for (std::size_t n = 0; n < a.children.size(); ++n) {
            const protocol::ContractChild& c = a.children[n];
            children.push_back(
                {{"position", n},
                 {"id", n < children_ids.size() ? Json(hex_id(children_ids[n])) : Json(nullptr)},
                 {"status", optional_text(c.status)},
                 {"parties", parties_json(names, c.parties)},
                 {"state", cbor::diagnostic(c.state)}});
        }
        out["children"] = std::move(children);
    }
    return out;
}

std::string outcome_text(const PartyNames& names, const protocol::ContractAccept& a,
                         std::span<const protocol::Id> children_ids) {
    std::string out = a.status ? "status " + *a.status : std::string("no status");
    if (a.parties) {
        out += "; parties " + parties_text(names, *a.parties);
    }
    for (const protocol::ContractEvent& e : a.events) {
        out += "; event " + e.name + " " + shortened(cbor::diagnostic(e.data));
    }
    if (a.final) {
        out += "; final";
    }
    for (std::size_t n = 0; n < a.children.size(); ++n) {
        const protocol::ContractChild& c = a.children[n];
        out += std::format(
            "; part {}{}: {}{}", n,
            n < children_ids.size() ? " " + short_id(children_ids[n]) : std::string(),
            c.status.value_or("(no status)"),
            c.parties.empty() ? std::string() : " (" + parties_text(names, c.parties) + ")");
    }
    return out;
}

Json consent_json(const protocol::ContractConsentCheck& c) {
    const protocol::RecordEvent* given =
        c.report.events.empty() ? nullptr : &c.report.events.front();
    Json authority = Json::array();
    if (given != nullptr) {
        for (const protocol::ActorSummary& link : given->authority) {
            authority.push_back(link.name);
        }
    }
    return {{"ledger_id", hex_id(c.ref.ledger)},
            {"organization", c.report.organization},
            {"hash", crypto::name(c.report.hash)},
            {"record", hex_id(c.ref.record)},
            {"signer", given != nullptr ? actor_json(given->actor) : Json(nullptr)},
            {"authority", std::move(authority)},
            {"presence", given != nullptr ? Json(presence_text(*given)) : Json(nullptr)},
            {"provenance", given != nullptr && given->provenance
                               ? provenance_json(*given->provenance)
                               : Json(nullptr)},
            {"given_at", given != nullptr ? Json(iso_time(given->registered_at)) : Json(nullptr)},
            {"until", iso_time(c.consent.until)},
            {"reference", optional_text(c.consent.reference)},
            {"witnesses",
             {{"trusted", c.report.trusted_cosignatures},
              {"untrusted", c.report.untrusted_cosignatures}}}};
}

} // namespace

Json contract_report_json(const protocol::ContractReport& r, bool ledger_checked) {
    const protocol::EvidenceReport& e = r.instance;
    const protocol::InstanceReport& i = *e.instance;
    const PartyNames names = contract_party_names(r);
    Json calls = Json::array();
    for (const protocol::ContractStep& step : r.steps) {
        const protocol::RecordEvent& event = e.events[step.event];
        const protocol::ContractCallBody& call = *event.contract_call;
        Json authority = Json::array();
        for (const protocol::ActorSummary& a : event.authority) {
            authority.push_back(actor_json(a));
        }
        Json consents = Json::array();
        for (const protocol::ContractConsentCheck& c : step.consents) {
            consents.push_back(consent_json(c));
        }
        calls.push_back(
            {{"index", event.index},
             {"registered_at", iso_time(event.registered_at)},
             {"function", call.function},
             {"creates", !call.instance.has_value()},
             {"arguments", cbor::diagnostic(call.arguments)},
             {"arguments_cbor", encoded_hex(call.arguments)},
             {"reference", optional_text(call.reference)},
             {"summary", event_line(event)},
             {"called_by", actor_json(event.actor)},
             {"authority", std::move(authority)},
             {"presence", event.presence ? Json(presence_text(event)) : Json(nullptr)},
             {"provenance", event.provenance ? provenance_json(*event.provenance) : Json(nullptr)},
             {"outcome",
              event.outcome ? outcome_json(names, *event.outcome, event.children) : Json(nullptr)},
             {"consents", std::move(consents)}});
    }
    Json out{{"verified", true},
             {"instance",
              {{"id", hex_id(e.record)},
               {"status", optional_text(i.status)},
               {"parties", parties_json(names, i.parties)},
               {"final", i.final},
               {"head", i.head},
               {"state", cbor::diagnostic(i.state)},
               {"state_cbor", encoded_hex(i.state)},
               {"contract",
                {{"id", hex_id(i.contract)},
                 {"name", optional_text(i.contract_name)},
                 {"language", i.language},
                 {"compiler", i.compiler},
                 {"retired", i.contract_retired}}}}},
             {"home",
              {{"id", hex_id(e.ledger_id)},
               {"organization", e.organization},
               {"hash", crypto::name(e.hash)},
               {"id_checked", ledger_checked}}},
             {"checkpoint", checkpoint_json(e.checkpoint)},
             {"witnesses",
              {{"trusted", e.trusted_cosignatures}, {"untrusted", e.untrusted_cosignatures}}},
             {"calls", std::move(calls)},
             {"complete", e.complete},
             {"report", report_json(e, ledger_checked)}};
    // A child (v0.7): its place, and its ancestors, oldest first, each with
    // its calls (log indices) up to the one that created the next generation.
    // Its ancestors' calls are among the calls above.
    if (i.parent) {
        Json ancestors = Json::array();
        for (const protocol::AncestorReport& a : i.ancestors) {
            Json ancestor_calls = Json::array();
            for (const std::size_t n : a.events) {
                ancestor_calls.push_back(e.events[n].index);
            }
            ancestors.push_back({{"id", hex_id(a.id)},
                                 {"depth", a.depth},
                                 {"parent", a.parent ? Json(hex_id(*a.parent)) : Json(nullptr)},
                                 {"position", a.position},
                                 {"created_by", a.created_by},
                                 {"until", a.until},
                                 {"calls", std::move(ancestor_calls)}});
        }
        Json& instance = out["instance"];
        instance["parent"] = hex_id(*i.parent);
        instance["position"] = i.position;
        instance["depth"] = i.depth;
        instance["created_by"] = i.created_by;
        instance["ancestors"] = std::move(ancestors);
    }
    return out;
}

std::string contract_report_text(const protocol::ContractReport& r, bool ledger_checked) {
    const protocol::EvidenceReport& e = r.instance;
    const protocol::InstanceReport& i = *e.instance;
    const PartyNames names = contract_party_names(r);
    std::string out;
    auto line = [&out](const std::string& text) {
        out += text + "\n";
    };
    line("CexChain contract report\n");
    line(std::format("  Instance     {} of contract {}(id {})", short_id(e.record),
                     i.contract_name ? "\"" + *i.contract_name + "\" " : std::string(),
                     short_id(i.contract)));
    if (i.parent) {
        line(std::format("  Part of      {}: part {} of its call #{}, depth {}",
                         short_id(*i.parent), i.position, i.created_by, i.depth));
    }
    line(std::format("  Contract     {}, compiled with {}{}", i.language, i.compiler,
                     i.contract_retired ? "; retired: it creates no more instances" : ""));
    line(std::format("  Home         {} (ledger {}, {})", e.organization, short_id(e.ledger_id),
                     crypto::name(e.hash)));
    if (!ledger_checked) {
        line("               ! not compared with an expected ledger id");
    }
    line(std::format("  Status       {}{}", i.status.value_or("(none)"),
                     i.final ? " - FINAL: it takes no more calls" : ""));
    if (i.parties.empty()) {
        line("  Parties      none");
    }
    bool first = true;
    for (const auto& [role, ledger] : i.parties) {
        line(std::format("  {}{}: {}", first ? "Parties      " : "             ", role,
                         party_text(names, ledger)));
        first = false;
    }
    line("  State        " + shortened(cbor::diagnostic(i.state)));
    line(std::format("  Checkpoint   size {}, signed {} by the home's log key",
                     e.checkpoint.tree_size, format_time(e.checkpoint.timestamp)));
    line(std::format("  Witnesses    {} trusted{}", e.trusted_cosignatures,
                     e.untrusted_cosignatures == 0
                         ? std::string()
                         : std::format(" ({} more from witnesses you do not trust, not checked)",
                                       e.untrusted_cosignatures)));
    auto call_lines = [&](const protocol::ContractStep& step) {
        const protocol::RecordEvent& event = e.events[step.event];
        const protocol::ContractCallBody& call = *event.contract_call;
        line(std::format("    #{:<4} {}  {}", event.index, format_time(event.registered_at),
                         event_line(event)));
        if (!event.authority.empty()) {
            std::string chain;
            for (const protocol::ActorSummary& link : event.authority) {
                chain += (chain.empty() ? "" : " <- ") + link.name;
            }
            line("           authorized by " + chain);
        }
        line("           arguments  " + shortened(cbor::diagnostic(call.arguments)));
        if (call.reference) {
            line("           reference  " + *call.reference);
        }
        if (event.outcome) {
            line("           outcome    " + outcome_text(names, *event.outcome, event.children));
        }
        for (const protocol::ContractConsentCheck& c : step.consents) {
            const protocol::RecordEvent* given =
                c.report.events.empty() ? nullptr : &c.report.events.front();
            const std::string who =
                given != nullptr ? "\"" + given->actor.name + "\" (" + signer_text(*given) + ")"
                                 : "?";
            line(std::format("           consent of {} ({}): given by {}{}", c.report.organization,
                             crypto::name(c.report.hash), who,
                             c.consent.reference ? ", ref. " + *c.consent.reference
                                                 : std::string()));
        }
    };
    if (!i.parent) {
        line("\n  Calls");
        for (const protocol::ContractStep& step : r.steps) {
            call_lines(step);
        }
    } else {
        // A child (v0.7): its ancestors first, each with its calls up to the
        // one that created the next generation; then its own.
        line("\n  Ancestors    oldest first, each up to its call that created the next generation");
        for (const protocol::AncestorReport& a : i.ancestors) {
            line(std::format("    Instance {}, depth {}{}", short_id(a.id), a.depth,
                             a.parent
                                 ? std::format(", part {} of #{} (above)", a.position, a.created_by)
                                 : std::string()));
            // The call that created it is its parent's, shown above.
            for (const protocol::ContractStep& step : r.steps) {
                if (std::ranges::contains(a.events, step.event) &&
                    (!a.parent || e.events[step.event].index != a.created_by)) {
                    call_lines(step);
                }
            }
        }
        line(std::format("\n  Calls        its own, after the call that created it (#{}, above)",
                         i.created_by));
        bool any = false;
        for (const protocol::ContractStep& step : r.steps) {
            if (step.event > i.first_own_event) {
                call_lines(step);
                any = true;
            }
        }
        if (!any) {
            line("    none yet");
        }
    }
    line("\n  Verified: the instance's complete history is proven against its home's state");
    line("  commitment, and its contract was run again on every call, reaching the state");
    line("  above; each consent is verified on the consenting party's own ledger. Party names");
    line("  are as their own ledgers declare them; ledger ids are what bind them.");
    if (i.parent) {
        line("  Its ancestors' calls up to each one that created the next generation were run");
        line("  again too, consents and all: the instance is the part those calls created.");
    }
    return out;
}

} // namespace cexchain::verifier
