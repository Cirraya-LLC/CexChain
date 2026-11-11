// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Claims on the console (spec v0.14): "Confirm a condition" on a record's
// page drafts a kanhe.claim/1 registration, its conditions checked here
// against the record's private data; the person approves it with a tap, as
// any registration. A condition that does not hold gets no claim unless the
// person asks for one that says so. A party's request that asks whether a
// condition holds (v0.15) is answered the same way: the claim's record and
// condition are the request's, and it names the request. Where a kind lets
// it, and an owner has let it, the console's machine answers by itself, but
// only when the condition holds: a "does not hold" waits for a person.

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <utility>
#include <variant>

#include <nlohmann/json.hpp>

#include <kanhe/client/access.hpp>
#include <kanhe/client/claims.hpp>
#include <kanhe/client/errors.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/console/kinds.hpp>
#include <kanhe/console/setup.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/claims.hpp>
#include <kanhe/core/protocol/record_types.hpp>
#include <kanhe/node/contracts.hpp>
#include <kanhe/node/peers.hpp>
#include <kanhe/verifier/report.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

constexpr std::size_t max_subject = 256;
/// How long an automatic answer waits on the ledger, and on its evidence.
constexpr auto answer_wait = std::chrono::seconds(30);

} // namespace

std::variant<std::pair<protocol::RecordRegisterBody, Draft>, http::Response>
Console::claim_draft(const Signed& who, const nlohmann::json& intent) const {
    const ledger::Ledger* const served = ledger();
    protocol::Claim claim;
    if (intent.value("action", "") == "access.answer") {
        // The record and the condition a party asked about, and the request.
        const auto bytes = from_hex(intent.value("request", ""));
        const auto request_id =
            bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(fail(Errc::malformed, "none"));
        if (!request_id) {
            return error(400, "invalid_argument", "name the request by its full id (hex)");
        }
        std::optional<client::ReceivedRequest> received;
        try {
            received =
                client::received_request(services_.directory.parent_path(), *services_.provider,
                                         served->id(), *request_id, services_.clock->now());
        } catch (const client::ActionError& e) {
            return error(404, "not_found", e.message);
        }
        if (!received->checked) {
            return error(409, "conflict", "the request does not check out: " + received->problem);
        }
        const protocol::AccessRequest& asked = received->checked->value;
        if (!asked.condition) {
            return error(409, "conflict", "the request asks for data: grant it instead");
        }
        claim.source = asked.record;
        claim.condition = *asked.condition;
        claim.answers = std::pair{received->peer->ledger_id, *request_id};
    } else {
        const auto bytes = from_hex(intent.value("record", ""));
        const auto source =
            bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(fail(Errc::malformed, "none"));
        if (!source) {
            return error(400, "invalid_argument", "name the record by its full id (hex)");
        }
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
                claim.condition.push_back(client::parse_claim_term(c["field"].get<std::string>(),
                                                                   c["op"].get<std::string>(),
                                                                   c.value("value", "")));
            }
        } catch (const client::UsageError& e) {
            return error(400, "invalid_argument", e.message);
        }
    }
    const protocol::Id source = claim.source;
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
        const protocol::RecordState* r = state.record(source);
        if (r == nullptr) {
            refused = error(404, "not_found", "no such record on this ledger");
        } else if (protocol::find_record_type(r->record_type) != nullptr) {
            refused = error(409, "conflict", "a claim is about a document, not a mechanism record");
        } else if (r->revoked || r->superseded_by) {
            refused =
                error(409, "conflict", "the record was revoked or replaced: confirm on the latest");
        } else if (!may_read_private(who, state, *r)) {
            refused = error(403, "forbidden", "you may not read this record's private data");
        } else if (vault = private_data(state, source); !vault) {
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

bool Console::answers_by_itself(const protocol::LedgerState& state) const {
    const auto machine = machine_actor(state);
    return machine &&
           node::choose_delegation(state, *machine, protocol::StatementType::record_register,
                                   std::string(protocol::claim_type), services_.clock->now())
               .has_value();
}

void Console::answer_questions() const {
    const ledger::Ledger* const served = ledger();
    const Submit submit = submitter();
    const Evidence source = evidence();
    if (served == nullptr || !submit || !source || services_.keys == nullptr ||
        !services_.keys->unlocked()) {
        return;
    }
    const std::filesystem::path dir = services_.directory.parent_path();
    std::vector<Kind> kinds;
    try {
        kinds = load_kinds(services_.directory);
    } catch (const std::exception&) {
        return;
    }
    if (std::ranges::none_of(kinds, [](const Kind& k) { return !k.answers.empty(); })) {
        return;
    }
    const auto vault_public = services_.keys->vault_public_key();
    if (!vault_public) {
        return;
    }
    for (const client::ReceivedRequest& r : client::received_requests(
             dir, *services_.provider, served->id(), services_.clock->now())) {
        if (!r.checked || r.granted || !r.checked->value.condition) {
            continue;
        }
        const protocol::AccessRequest& asked = r.checked->value;
        const protocol::Id request_id = r.checked->report.record;
        // Within the kind's fields, on the latest version, as the machine
        // may; then checked in the record's private data, answered only if
        // it holds.
        std::optional<Bytes> submission;
        std::optional<protocol::Id> claim_id;
        std::string kind_name;
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::RecordState* record = state.record(asked.record);
            if (record == nullptr || record->revoked || record->superseded_by) {
                return;
            }
            const auto kind = std::ranges::find(kinds, record->record_type, &Kind::type);
            if (kind == kinds.end() ||
                !std::ranges::all_of(*asked.condition, [&](const protocol::ClaimTerm& t) {
                    return std::ranges::contains(kind->answers, t.field);
                })) {
                return;
            }
            const auto machine = machine_actor(state);
            const protocol::Timestamp now = services_.clock->now();
            const auto delegation =
                machine ? node::choose_delegation(state, *machine,
                                                  protocol::StatementType::record_register,
                                                  std::string(protocol::claim_type), now)
                        : std::nullopt;
            const auto vault = delegation ? private_data(state, asked.record) : std::nullopt;
            if (!vault) {
                return;
            }
            protocol::Claim claim;
            claim.source = asked.record;
            claim.condition = *asked.condition;
            claim.as_of = now;
            // As long as the question was asked for.
            claim.until = asked.until;
            claim.answers = std::pair{r.peer->ledger_id, request_id};
            const client::ClaimCheck check = client::check_claim(claim, vault->fields);
            if (!check.holds) {
                return;
            }
            claim.holds = true;
            std::vector<protocol::RecordField> fields;
            for (const auto& [name, value] : check.basis) {
                fields.push_back({name, services_.entropy->bytes<16>(), cbor::Value::text(value)});
            }
            const auto commitment =
                protocol::commit_fields(*services_.provider, state.hash(), fields);
            const auto metadata = protocol::encode_claim(claim);
            if (!commitment || !metadata) {
                return;
            }
            protocol::RecordRegisterBody body;
            body.record_type = std::string(protocol::claim_type);
            body.field_root =
                Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end());
            body.field_count = commitment->leaves.size();
            body.metadata = *metadata;
            protocol::Statement statement;
            statement.ledger_id = state.ledger_id();
            statement.actor_id = *machine;
            statement.issued_at = now;
            statement.nonce = services_.entropy->bytes<16>();
            statement.delegation_id = delegation;
            statement.body = std::move(body);
            const auto made =
                protocol::sign_statement(services_.keys->open(machine_key_name),
                                         *services_.provider, state.hash(), statement);
            if (!made) {
                return;
            }
            auto encoded = cbor::encode(cbor::Value::map(
                {{cbor::Value::integer(1), cbor::Value::bytes(made->encoded)},
                 {cbor::Value::integer(2),
                  cbor::Value::bytes(client::seal_vault(state.ledger_id(), made->id,
                                                        client::Vault{commitment->fields, {}},
                                                        *vault_public))}}));
            if (encoded) {
                submission = std::move(*encoded);
                claim_id = made->id;
                kind_name = kind->name;
            }
        });
        if (!submission) {
            continue;
        }
        auto registered = std::make_shared<std::promise<http::Response>>();
        auto answer = registered->get_future();
        submit(std::move(*submission), true, [registered](http::Response response) {
            registered->set_value(std::move(response));
        });
        if (answer.wait_for(answer_wait) != std::future_status::ready ||
            answer.get().status / 100 != 2) {
            continue;
        }
        // Kept for the asker, checked as it will check it.
        auto exported = std::make_shared<std::promise<Result<Bytes>>>();
        auto bundle = exported->get_future();
        source(*claim_id,
               [exported](Result<Bytes> evidence) { exported->set_value(std::move(evidence)); });
        if (bundle.wait_for(answer_wait) != std::future_status::ready) {
            continue;
        }
        const Result<Bytes> evidence = bundle.get();
        if (!evidence || !protocol::check_claim_answer(*services_.provider, *evidence, served->id(),
                                                       r.peer->ledger_id, request_id, asked,
                                                       services_.clock->now())) {
            continue;
        }
        const auto path = node::access_path(dir, node::AccessBox::outbox, request_id);
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        try {
            client::write_file(path, *evidence, true);
        } catch (const client::ActionError&) {
            continue;
        }
        log_activity("console", "access.answered",
                     {{"peer", r.peer->name},
                      {"request", to_hex(request_id.bytes())},
                      {"claim", to_hex(claim_id->bytes())},
                      {"kind", kind_name},
                      {"text", protocol::condition_text(*asked.condition)}});
    }
}

} // namespace kanhe::console
