// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Claims on the console (spec v0.14): "Confirm a condition" on a record's
// page drafts a cexchain.claim/1 registration, its conditions checked here
// against the record's private data; the person approves it with a tap, as
// any registration. A condition that does not hold gets no claim unless the
// person asks for one that says so.

#include <string>
#include <utility>
#include <variant>

#include <nlohmann/json.hpp>

#include <cexchain/client/claims.hpp>
#include <cexchain/client/errors.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/claims.hpp>
#include <cexchain/core/protocol/record_types.hpp>
#include <cexchain/verifier/report.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::size_t max_subject = 256;

} // namespace

std::variant<std::pair<protocol::RecordRegisterBody, Draft>, http::Response>
Console::claim_draft(const Signed& who, const nlohmann::json& intent) const {
    const ledger::Ledger* const served = ledger();
    const auto bytes = from_hex(intent.value("record", ""));
    const auto source =
        bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(fail(Errc::malformed, "none"));
    if (!source) {
        return error(400, "invalid_argument", "name the record by its full id (hex)");
    }
    protocol::Claim claim;
    claim.source = *source;
    const auto conditions = intent.find("conditions");
    if (conditions == intent.end() || !conditions->is_array() || conditions->empty()) {
        return error(400, "invalid_argument", "say what to confirm: one condition or more");
    }
    try {
        for (const auto& c : *conditions) {
            if (!c.is_object() || !c.value("field", nlohmann::json()).is_string() ||
                !c.value("op", nlohmann::json()).is_string()) {
                return error(400, "invalid_argument", "a condition is {field, op, value}");
            }
            claim.condition.push_back(client::parse_claim_term(
                c["field"].get<std::string>(), c["op"].get<std::string>(), c.value("value", "")));
        }
    } catch (const client::UsageError& e) {
        return error(400, "invalid_argument", e.message);
    }
    const std::string subject = intent.value("subject", "");
    if (subject.size() > max_subject) {
        return error(400, "invalid_argument", "the subject is at most 256 bytes");
    }
    if (!subject.empty()) {
        claim.subject = subject;
    }
    claim.as_of = services_.clock->now();
    if (const auto until = intent.find("until"); until != intent.end() && !until->is_null()) {
        if (!until->is_number_unsigned()) {
            return error(400, "invalid_argument", "until is a time in milliseconds");
        }
        claim.until = until->get<protocol::Timestamp>();
    }
    if (auto shaped = protocol::encode_claim(claim); !shaped) {
        return error(400, "invalid_argument", std::string(shaped.error().detail));
    }
    // Checked against the record's private data, as only those who may read
    // it may.
    std::optional<http::Response> refused;
    std::optional<client::Vault> vault;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(*source);
        if (r == nullptr) {
            refused = error(404, "not_found", "no such record on this ledger");
        } else if (protocol::find_record_type(r->record_type) != nullptr) {
            refused = error(409, "conflict", "a claim is about a document, not a mechanism record");
        } else if (r->revoked || r->superseded_by) {
            refused =
                error(409, "conflict", "the record was revoked or replaced: confirm on the latest");
        } else if (!may_read_private(who, state, *r)) {
            refused = error(403, "forbidden", "you may not read this record's private data");
        } else if (vault = private_data(state, *source); !vault) {
            refused = services_.keys == nullptr || !services_.keys->unlocked()
                          ? error(423, "locked", "the console is locked: unlock it first")
                          : error(409, "conflict", "the record's private data is not here");
        }
    });
    if (refused) {
        return std::move(*refused);
    }
    const client::ClaimCheck check = client::check_claim(claim, vault->fields);
    claim.holds = check.holds;
    if (!claim.holds && !intent.value("allow_no", false)) {
        return error(422, "refused",
                     "the condition does not hold: no claim is issued unless you ask for one "
                     "that says so");
    }
    // The claim's own fields: the values it was checked against, sealed.
    std::vector<protocol::RecordField> fields;
    for (const auto& [name, value] : check.basis) {
        fields.push_back({name, services_.entropy->bytes<16>(), cbor::Value::text(value)});
    }
    const auto commitment = protocol::commit_fields(*services_.provider, served->hash(), fields);
    if (!commitment) {
        return error(500, "internal", std::string(commitment.error().detail));
    }
    protocol::RecordRegisterBody body;
    body.record_type = std::string(protocol::claim_type);
    body.field_root = Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end());
    body.field_count = commitment->leaves.size();
    body.metadata = *protocol::encode_claim(claim);
    Draft draft;
    draft.vault.fields = commitment->fields;
    return std::pair{std::move(body), std::move(draft)};
}

nlohmann::json Console::claim_view(const protocol::LedgerState& state,
                                   const protocol::RecordState& record,
                                   const protocol::RecordRegisterBody& body) const {
    const auto claim = body.metadata ? protocol::decode_claim(*body.metadata)
                                     : Result<protocol::Claim>(fail(Errc::malformed, "none"));
    if (!claim) {
        return nullptr;
    }
    const protocol::RecordState* source = state.record(claim->source);
    return {
        {"text", protocol::claim_text(*claim)},
        {"holds", claim->holds},
        {"subject", claim->subject ? nlohmann::json(*claim->subject) : nlohmann::json()},
        {"as_of", claim->as_of},
        {"until", claim->until ? nlohmann::json(*claim->until) : nlohmann::json()},
        {"source", to_hex(claim->source.bytes())},
        {"source_type", source != nullptr ? nlohmann::json(source->record_type) : nlohmann::json()},
        {"status", client::claim_status(state, record, *claim, services_.clock->now())}};
}

} // namespace cexchain::console
