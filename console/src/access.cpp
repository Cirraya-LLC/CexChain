// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Documents between parties. One party asks another for one of its records
// (a request on its own ledger, with a key made for it, sent online); the
// other grants the fields and kept files it chooses with a tap (a grant on
// its ledger, and the delivery sealed to the request's key, which the asker
// fetches); the asker's console fetches it, shows it verified, and the
// person accepts it with a tap (a receipt on their ledger, sent back). Each
// step is checked as the command line checks it (app/access.hpp).

#include <algorithm>
#include <charconv>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/access.hpp>
#include <cexchain/app/errors.hpp>
#include <cexchain/app/peers.hpp>
#include <cexchain/app/records.hpp>
#include <cexchain/app/relay_client.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/ledger/verify.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/record_files.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view access_prefix = "/console/api/access";
constexpr protocol::Timestamp day_ms = 86'400'000;
/// A request or grant lasts 1 to this many days.
constexpr std::uint64_t max_days = 366;
/// A purpose is a line for people, recorded on both ledgers.
constexpr std::size_t max_purpose = 500;

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::optional<protocol::Id> id_of(std::string_view hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

template <typename F>
std::optional<std::string> attempt(F&& f) {
    try {
        f();
        return std::nullopt;
    } catch (const app::ActionError& e) {
        return e.message;
    } catch (const app::UsageError& e) {
        return e.message;
    } catch (const std::exception& e) {
        return std::string(e.what());
    }
}

nlohmann::json names_json(const std::optional<std::vector<std::string>>& names) {
    return names ? nlohmann::json(*names) : nlohmann::json();
}

/// Names from the page: a JSON array of text; nullopt for none given (null
/// or absent); `bad` set for anything else.
std::optional<std::vector<std::string>> names_of(const nlohmann::json& body, std::string_view key,
                                                 bool& bad) {
    const auto it = body.find(key);
    if (it == body.end() || it->is_null()) {
        return std::nullopt;
    }
    if (!it->is_array() || !std::ranges::all_of(*it, [](const auto& v) { return v.is_string(); })) {
        bad = true;
        return std::nullopt;
    }
    std::vector<std::string> out;
    for (const auto& v : *it) {
        if (!std::ranges::contains(out, v.get<std::string>())) {
            out.push_back(v.get<std::string>());
        }
    }
    return out;
}

/// The delivery fetched for one of this ledger's requests, in the console's
/// folder until it is accepted.
std::filesystem::path fetched_path(const std::filesystem::path& console,
                                   const protocol::Id& request) {
    return console / "access" / (hex_of(request) + ".cbor");
}

/// One of this ledger's access records, with its metadata from the log.
struct AccessRecord {
    protocol::Id id;
    std::string type;
    std::string state;
    bool revoked = false;
    std::uint64_t index = 0;
    std::optional<cbor::Value> metadata;
};

std::vector<AccessRecord> access_records(const ledger::Ledger& served,
                                         const crypto::Provider& provider) {
    std::vector<AccessRecord> out;
    served.read_state([&](const protocol::LedgerState& state) {
        for (const auto& [key, r] : state.records()) {
            if (r.record_type == protocol::access_request_type ||
                r.record_type == protocol::access_grant_type ||
                r.record_type == protocol::access_receipt_type) {
                out.push_back({protocol::Id(r.id), r.record_type, r.state, r.revoked,
                               r.registered_at_index, std::nullopt});
            }
        }
    });
    std::ranges::sort(out, {}, &AccessRecord::index);
    for (AccessRecord& r : out) {
        if (auto m = node::record_metadata(provider, served, r.id)) {
            r.metadata = std::move(*m);
        }
    }
    return out;
}

/// This ledger's requests that a receipt here acknowledges: request (hex)
/// to its grant and receipt, from the deliveries kept under the grants.
struct Acceptance {
    protocol::Id grant;
    protocol::Id receipt;
};
std::map<std::string, Acceptance> acceptances(const std::filesystem::path& dir,
                                              const crypto::Provider& provider,
                                              const std::vector<AccessRecord>& records) {
    std::map<std::string, Acceptance> out;
    for (const AccessRecord& r : records) {
        if (r.type != protocol::access_receipt_type || !r.metadata) {
            continue;
        }
        const auto receipt = protocol::decode_access_receipt(*r.metadata);
        if (!receipt) {
            continue;
        }
        const auto bytes = std::filesystem::exists(
                               node::access_path(dir, node::AccessBox::deliveries, receipt->grant))
                               ? std::optional(app::read_file(node::access_path(
                                     dir, node::AccessBox::deliveries, receipt->grant)))
                               : std::nullopt;
        const auto delivery =
            bytes ? protocol::decode_delivery(*bytes)
                  : Result<protocol::Delivery>(fail(Errc::not_found, "no delivery kept"));
        if (!delivery) {
            continue;
        }
        protocol::VerifyOptions pinned;
        pinned.expected_ledger = receipt->ledger;
        pinned.signatures = &ledger::signature_cache();
        const auto report = protocol::verify_bundle(provider, delivery->grant_bundle, pinned);
        const auto grant = report && report->metadata
                               ? protocol::decode_access_grant(*report->metadata)
                               : Result<protocol::AccessGrant>(fail(Errc::malformed, "no grant"));
        if (grant) {
            out[hex_of(grant->request)] = {receipt->grant, r.id};
        }
    }
    return out;
}

std::string peer_name(const std::vector<node::Peer>& peers, const protocol::Id& ledger) {
    const auto p = std::ranges::find(peers, ledger, &node::Peer::ledger_id);
    return p == peers.end() ? std::string() : p->name;
}

std::optional<node::Peer> online_peer(const std::filesystem::path& dir,
                                      const protocol::Id& ledger) {
    if (const auto peers = node::load_peers(dir)) {
        for (const node::Peer& p : *peers) {
            if (p.ledger_id == ledger && node::reachable(p)) {
                return p;
            }
        }
    }
    return std::nullopt;
}

/// A day count from the page: 1 to max_days, 30 if not given.
std::optional<std::uint64_t> days_of(const nlohmann::json& body) {
    const auto it = body.find("days");
    if (it == body.end() || it->is_null()) {
        return 30;
    }
    if (!it->is_number_unsigned() || it->get<std::uint64_t>() == 0 ||
        it->get<std::uint64_t>() > max_days) {
        return std::nullopt;
    }
    return it->get<std::uint64_t>();
}

/// A grant's delivery being made: the grant's evidence and the record's,
/// at one checkpoint (asked again if one came between), then sealed and
/// checked off the ledger's writer, and kept in the outbox.
struct DeliveryJob {
    Console::Evidence source;
    const crypto::Provider* provider;
    crypto::HashAlg hash;
    protocol::Id own;
    protocol::Id grant_id;
    protocol::AccessGrant grant;
    app::Vault vault;
    protocol::DeliveryContents contents;
    std::filesystem::path dir;
    Console::Respond respond;
    int tries = 0;
};

void deliver(const std::shared_ptr<DeliveryJob>& job) {
    job->source(job->grant_id, [job](Result<Bytes> grant_bundle) {
        if (!grant_bundle) {
            job->respond(error(503, "unavailable", grant_bundle.error().detail));
            return;
        }
        job->source(job->grant.record, [job, grant_bundle = std::move(*grant_bundle)](
                                           Result<Bytes> record_bundle) mutable {
            if (!record_bundle) {
                job->respond(error(503, "unavailable", record_bundle.error().detail));
                return;
            }
            std::thread([job, grant_bundle = std::move(grant_bundle),
                         record_bundle = std::move(*record_bundle)] {
                std::optional<Bytes> delivery;
                const auto problem = attempt([&] {
                    auto bundle = app::unwrap(protocol::decode_bundle(record_bundle),
                                              "the record's evidence");
                    const auto commitment = app::unwrap(
                        protocol::commit_fields(*job->provider, job->hash, job->vault.fields),
                        "the fields");
                    for (const std::string& name : job->grant.fields) {
                        bundle.disclosures.push_back(app::unwrap(
                            protocol::disclose_field(*job->provider, job->hash, commitment, name),
                            "disclosing " + name));
                    }
                    for (const app::VaultAttachment& a : job->vault.attachments) {
                        if (std::ranges::contains(job->grant.attachments, a.name)) {
                            bundle.attachments.push_back({a.name, a.salt});
                        }
                    }
                    protocol::DeliveryContents contents = job->contents;
                    contents.record_bundle =
                        app::unwrap(protocol::encode_bundle(bundle), "the record's evidence");
                    delivery = app::seal_delivery(*job->provider, job->own, grant_bundle,
                                                  job->grant, contents);
                });
                if (problem && problem->find("checkpoint") != std::string::npos &&
                    ++job->tries < 3) {
                    deliver(job);
                    return;
                }
                if (problem) {
                    job->respond(error(409, "conflict", *problem));
                    return;
                }
                const auto stored = attempt([&] {
                    const auto path =
                        node::access_path(job->dir, node::AccessBox::outbox, job->grant.request);
                    std::filesystem::create_directories(path.parent_path());
                    app::write_file(path, *delivery, true);
                });
                job->respond(stored ? error(500, "internal", *stored)
                                    : json(200, {{"delivered", true}}));
            }).detach();
        });
    });
}

} // namespace

nlohmann::json access_terms(std::string_view type, const cbor::Value& metadata) {
    if (type == protocol::access_request_type) {
        if (const auto r = protocol::decode_access_request(metadata)) {
            return {{"kind", "request"},
                    {"ledger", hex_of(r->ledger)},
                    {"record", hex_of(r->record)},
                    {"purpose", r->purpose},
                    {"until", r->until},
                    {"fields", names_json(r->fields)},
                    {"attachments", names_json(r->attachments)},
                    {"recipient", to_hex(r->recipient)}};
        }
    } else if (type == protocol::access_grant_type) {
        if (const auto g = protocol::decode_access_grant(metadata)) {
            return {{"kind", "grant"},
                    {"ledger", hex_of(g->ledger)},
                    {"request", hex_of(g->request)},
                    {"record", hex_of(g->record)},
                    {"fields", g->fields},
                    {"attachments", g->attachments},
                    {"until", g->until},
                    {"recipient", to_hex(g->recipient)}};
        }
    } else if (type == protocol::access_receipt_type) {
        if (const auto r = protocol::decode_access_receipt(metadata)) {
            return {{"kind", "receipt"},
                    {"ledger", hex_of(r->ledger)},
                    {"grant", hex_of(r->grant)},
                    {"delivery", to_hex(r->delivery)}};
        }
    }
    return nullptr;
}

std::variant<std::pair<protocol::RecordRegisterBody, Draft>, http::Response>
Console::access_draft(const Signed& who, const nlohmann::json& intent) const {
    const ledger::Ledger* const served = ledger();
    const std::filesystem::path dir = services_.directory.parent_path();
    const std::string action = intent.value("action", "");
    const protocol::Timestamp now = services_.clock->now();
    std::string note;
    std::string type;
    std::optional<cbor::Value> metadata;
    Draft draft;
    bool bad = false;
    if (action == "access.request") {
        // A request to a party reached online, for one of its records.
        const auto peer = [&]() -> std::optional<node::Peer> {
            if (const auto peers = node::load_peers(dir)) {
                for (const node::Peer& p : *peers) {
                    if (p.name == intent.value("peer", "")) {
                        return p;
                    }
                }
            }
            return std::nullopt;
        }();
        if (!peer) {
            return error(404, "not_found", "no party of that name");
        }
        if (!node::reachable(*peer)) {
            return error(409, "conflict", "that party is not reached online");
        }
        const auto record = id_of(intent.value("record", ""));
        if (!record) {
            return error(400, "invalid_argument",
                         "name the document by its full id (64 hex digits), as the party gave it");
        }
        protocol::AccessRequest request;
        request.ledger = peer->ledger_id;
        request.record = *record;
        request.purpose = intent.value("purpose", "");
        const auto days = days_of(intent);
        request.fields = names_of(intent, "fields", bad);
        request.attachments = names_of(intent, "files", bad);
        if (request.purpose.empty() || request.purpose.size() > max_purpose) {
            return error(400, "invalid_argument", "say why, in 1 to 500 bytes");
        }
        if (!days || bad) {
            return error(400, "invalid_argument",
                         "days are 1 to 366; fields and files are lists of names");
        }
        request.until = now + *days * day_ms;
        // A key made for this request: the delivery is sealed to it, and it
        // is kept sealed to the vault key once the request has its id.
        auto key = std::make_shared<crypto::openssl::HpkeKey>(
            app::unwrap(crypto::openssl::HpkeKey::generate(), "making the request's key"));
        request.recipient = Bytes(key->public_key().begin(), key->public_key().end());
        auto encoded = protocol::encode_access_request(request);
        if (!encoded) {
            return error(400, "invalid_argument", encoded.error().detail);
        }
        metadata = std::move(*encoded);
        draft.request_key = std::move(key);
        note = request.purpose;
        type = protocol::access_request_type;
    } else if (action == "access.grant") {
        const auto request_id = id_of(intent.value("request", ""));
        if (!request_id) {
            return error(400, "invalid_argument", "name the request by its full id (hex)");
        }
        std::optional<app::ReceivedRequest> received;
        if (const auto problem = attempt([&] {
                received =
                    app::received_request(dir, *services_.provider, served->id(), *request_id, now);
            })) {
            return error(404, "not_found", *problem);
        }
        if (!received->checked) {
            return error(409, "conflict", "the request does not check out: " + received->problem);
        }
        const protocol::AccessRequest& asked = received->checked->value;
        const auto fields = names_of(intent, "fields", bad);
        const auto files = names_of(intent, "files", bad);
        const auto days = days_of(intent);
        if (bad || !days) {
            return error(400, "invalid_argument",
                         "days are 1 to 366; fields and files are lists of names");
        }
        // What may be granted: what was asked, of what the record has here
        // (its files only where a copy is kept).
        std::optional<http::Response> refused;
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::RecordState* r = state.record(asked.record);
            if (r == nullptr || r->revoked) {
                refused = error(409, "conflict", "the document asked for is not on this ledger");
                return;
            }
            if (!may_read_private(who, state, *r)) {
                refused = error(403, "forbidden", "you may not share this document");
                return;
            }
            const auto vault = private_data(state, asked.record);
            const auto body = registration(state, asked.record);
            if (!vault || !body) {
                refused = error(409, "conflict", "the document's private data is not here");
                return;
            }
            const auto kept = node::kept_record_files(dir, asked.record);
            for (const std::string& f : fields.value_or(std::vector<std::string>{})) {
                const bool has =
                    std::ranges::find(vault->fields, f, &protocol::RecordField::name) !=
                    vault->fields.end();
                if (!has || (asked.fields && !std::ranges::contains(*asked.fields, f))) {
                    refused = error(400, "invalid_argument", "the field " + f + " is not asked");
                    return;
                }
            }
            for (const std::string& f : files.value_or(std::vector<std::string>{})) {
                const auto a = std::ranges::find(body->attachments, f, &protocol::Attachment::name);
                const auto index = static_cast<std::uint64_t>(a - body->attachments.begin());
                if (a == body->attachments.end() ||
                    (asked.attachments && !std::ranges::contains(*asked.attachments, f))) {
                    refused = error(400, "invalid_argument", "the file " + f + " is not asked");
                    return;
                }
                if (!std::ranges::contains(kept, index)) {
                    refused = error(409, "conflict", "no copy of " + f + " is kept here");
                    return;
                }
            }
        });
        if (refused) {
            return std::move(*refused);
        }
        protocol::AccessGrant grant;
        grant.ledger = received->peer->ledger_id;
        grant.request = *request_id;
        grant.record = asked.record;
        grant.fields = fields.value_or(std::vector<std::string>{});
        grant.attachments = files.value_or(std::vector<std::string>{});
        grant.until = std::min(asked.until, now + *days * day_ms);
        grant.recipient = asked.recipient;
        auto encoded = protocol::encode_access_grant(grant);
        if (!encoded) {
            return error(400, "invalid_argument", encoded.error().detail);
        }
        metadata = std::move(*encoded);
        note = asked.purpose;
        type = protocol::access_grant_type;
    } else if (action == "access.receipt") {
        const auto request_id = id_of(intent.value("request", ""));
        const std::filesystem::path file =
            request_id ? fetched_path(services_.directory, *request_id) : std::filesystem::path();
        if (!request_id || !std::filesystem::exists(file)) {
            return error(404, "not_found", "nothing was delivered for that request");
        }
        // Accepted by someone who may read what it brought.
        bool allowed = false;
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::RecordState* r = state.record(*request_id);
            allowed = r != nullptr && may_read_private(who, state, *r);
        });
        if (!allowed) {
            return error(403, "forbidden", "you may not accept what this request brought");
        }
        const Bytes delivery = app::read_file(file);
        std::optional<app::OpenedDelivery> opened;
        std::string refusal;
        const auto problem = attempt([&] {
            try {
                opened = app::open_delivery(
                    *served, dir, *services_.provider, delivery,
                    [&] { return services_.keys->open_vault_key(); }, now);
            } catch (const app::NotAccepted& e) {
                refusal = e.message;
            }
        });
        if (problem || !refusal.empty()) {
            return error(422, "not_verified", problem ? *problem : refusal);
        }
        if (opened->request != *request_id) {
            return error(409, "conflict", "the delivery answers another request");
        }
        auto encoded = protocol::encode_access_receipt(
            app::receipt_for(*services_.provider, *opened, delivery));
        if (!encoded) {
            return error(500, "internal", "the receipt could not be made");
        }
        metadata = std::move(*encoded);
        draft.delivery = std::pair(opened->grant.report.record, delivery);
        note = "received";
        type = protocol::access_receipt_type;
    } else {
        return error(400, "invalid_argument", "the console cannot prepare this action");
    }
    // The note is the record's one private field.
    const std::vector<protocol::RecordField> fields{
        {"note", services_.entropy->bytes<16>(), cbor::Value::text(note)}};
    const auto commitment = protocol::commit_fields(*services_.provider, served->hash(), fields);
    if (!commitment) {
        return error(500, "internal", "the note could not be committed");
    }
    protocol::RecordRegisterBody body;
    body.record_type = type;
    body.field_root = Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end());
    body.field_count = commitment->leaves.size();
    body.metadata = std::move(metadata);
    draft.vault.fields = commitment->fields;
    return std::pair(std::move(body), std::move(draft));
}

void Console::poll_deliveries() const {
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return;
    }
    const std::filesystem::path dir = services_.directory.parent_path();
    const auto records = access_records(*served, *services_.provider);
    const auto accepted = acceptances(dir, *services_.provider, records);
    const protocol::Timestamp now = services_.clock->now();
    for (const AccessRecord& r : records) {
        if (r.type != protocol::access_request_type || r.revoked || r.state != "requested" ||
            !r.metadata || accepted.contains(hex_of(r.id)) ||
            std::filesystem::exists(fetched_path(services_.directory, r.id))) {
            continue;
        }
        {
            const std::lock_guard lock(mutex_);
            if (ended_.contains(hex_of(r.id))) {
                continue;
            }
        }
        const auto request = protocol::decode_access_request(*r.metadata);
        const auto peer = request ? online_peer(dir, request->ledger) : std::nullopt;
        if (!peer || request->until <= now) {
            continue;
        }
        static_cast<void>(attempt([&] {
            const auto response =
                app::peer_request(*peer, "GET", "/v1/access/deliveries/" + hex_of(r.id));
            if (response.status == 200) {
                const std::filesystem::path file = fetched_path(services_.directory, r.id);
                std::filesystem::create_directories(file.parent_path());
                app::write_file(file, response.body, true);
            } else if (response.status == 410) {
                const std::lock_guard lock(mutex_);
                ended_.insert(hex_of(r.id));
            }
        }));
    }
}

http::Response Console::access_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const std::filesystem::path dir = services_.directory.parent_path();
    const protocol::Timestamp now = services_.clock->now();
    const std::string_view rest = std::string_view(request.path).substr(access_prefix.size());

    if (rest == "/dismiss") {
        if (request.method != "POST") {
            return error(405, "unsupported", "method not allowed");
        }
        if (signer.role == Role::viewer) {
            return error(403, "forbidden", "a viewer reads and verifies, and acts on nothing");
        }
        const auto body =
            nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
        const auto id = body.is_object() ? id_of(body.value("request", "")) : std::nullopt;
        const std::filesystem::path file =
            id ? node::access_path(dir, node::AccessBox::inbox, *id) : std::filesystem::path();
        if (!id || !std::filesystem::exists(file)) {
            return error(404, "not_found", "no such request in the inbox");
        }
        std::filesystem::remove(file);
        return json(200, {{"dismissed", hex_of(*id)}});
    }
    if (request.method != "GET") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET");
        return refused;
    }

    if (rest.empty()) {
        const auto peers = node::load_peers(dir).value_or(std::vector<node::Peer>{});
        nlohmann::json asked_of_us = nlohmann::json::array();
        for (const app::ReceivedRequest& r :
             app::received_requests(dir, *services_.provider, served->id(), now)) {
            nlohmann::json item{{"request", r.file.stem().string()}};
            if (!r.checked) {
                item["problem"] = r.problem;
                item["peer"] = r.peer ? nlohmann::json(r.peer->name) : nlohmann::json();
            } else {
                const protocol::AccessRequest& asked = r.checked->value;
                item.update({{"peer", r.peer->name},
                             {"from", app::acted_by(r.checked->report)},
                             {"record", hex_of(asked.record)},
                             {"purpose", asked.purpose},
                             {"until", asked.until},
                             {"fields", names_json(asked.fields)},
                             {"files", names_json(asked.attachments)},
                             {"granted", r.granted}});
                served->read_state([&](const protocol::LedgerState& state) {
                    const protocol::RecordState* d = state.record(asked.record);
                    item["record_type"] =
                        d != nullptr && !d->revoked ? nlohmann::json(d->record_type) : nullptr;
                });
            }
            asked_of_us.push_back(std::move(item));
        }
        const auto records = access_records(*served, *services_.provider);
        const auto accepted = acceptances(dir, *services_.provider, records);
        nlohmann::json asked_by_us = nlohmann::json::array();
        nlohmann::json granted = nlohmann::json::array();
        for (const AccessRecord& r : records) {
            if (!r.metadata) {
                continue;
            }
            if (r.type == protocol::access_request_type) {
                const auto asked = protocol::decode_access_request(*r.metadata);
                if (!asked) {
                    continue;
                }
                const std::string id = hex_of(r.id);
                bool ended = false;
                {
                    const std::lock_guard lock(mutex_);
                    ended = ended_.contains(id);
                }
                const auto acceptance = accepted.find(id);
                const std::string status =
                    r.revoked || r.state != "requested"                                ? "withdrawn"
                    : acceptance != accepted.end()                                     ? "accepted"
                    : std::filesystem::exists(fetched_path(services_.directory, r.id)) ? "delivered"
                    : ended                                                            ? "ended"
                    : asked->until <= now                                              ? "expired"
                                                                                       : "waiting";
                asked_by_us.push_back(
                    {{"request", id},
                     {"peer", peer_name(peers, asked->ledger)},
                     {"ledger", hex_of(asked->ledger)},
                     {"record", hex_of(asked->record)},
                     {"purpose", asked->purpose},
                     {"until", asked->until},
                     {"status", status},
                     {"online", online_peer(dir, asked->ledger).has_value()},
                     {"receipt", acceptance != accepted.end()
                                     ? nlohmann::json(hex_of(acceptance->second.receipt))
                                     : nlohmann::json()}});
            } else if (r.type == protocol::access_grant_type) {
                const auto g = protocol::decode_access_grant(*r.metadata);
                if (!g) {
                    continue;
                }
                const bool delivered = node::delivery_for_grant(dir, g->request, r.id).has_value();
                const bool acknowledged = std::filesystem::exists(
                    node::access_path(dir, node::AccessBox::receipts, r.id));
                granted.push_back({{"grant", hex_of(r.id)},
                                   {"request", hex_of(g->request)},
                                   {"peer", peer_name(peers, g->ledger)},
                                   {"record", hex_of(g->record)},
                                   {"fields", g->fields},
                                   {"files", g->attachments},
                                   {"until", g->until},
                                   {"status", r.revoked         ? "withdrawn"
                                              : acknowledged    ? "acknowledged"
                                              : g->until <= now ? "expired"
                                              : delivered       ? "delivered"
                                                                : "not_delivered"}});
            }
        }
        return json(200, {{"asked_of_us", asked_of_us},
                          {"asked_by_us", asked_by_us},
                          {"granted", granted},
                          {"may_act", signer.role != Role::viewer}});
    }

    if (rest.starts_with("/requests/")) {
        // A request received, with what the document has to give.
        const auto id = id_of(rest.substr(std::string_view("/requests/").size()));
        if (!id) {
            return error(400, "invalid_argument", "a request's id is 64 hex digits");
        }
        std::optional<app::ReceivedRequest> received;
        if (const auto problem = attempt([&] {
                received = app::received_request(dir, *services_.provider, served->id(), *id, now);
            })) {
            return error(404, "not_found", *problem);
        }
        if (!received->checked) {
            return json(200, {{"request", hex_of(*id)},
                              {"peer", received->peer ? nlohmann::json(received->peer->name)
                                                      : nlohmann::json()},
                              {"problem", received->problem}});
        }
        const protocol::AccessRequest& asked = received->checked->value;
        nlohmann::json out{{"request", hex_of(*id)},
                           {"peer", received->peer->name},
                           {"from", app::acted_by(received->checked->report)},
                           {"organization", received->checked->report.organization},
                           {"record", hex_of(asked.record)},
                           {"purpose", asked.purpose},
                           {"until", asked.until},
                           {"asked_fields", names_json(asked.fields)},
                           {"asked_files", names_json(asked.attachments)},
                           {"granted", received->granted},
                           {"may_grant", false}};
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::RecordState* r = state.record(asked.record);
            if (r == nullptr || r->revoked) {
                out["missing"] = true;
                return;
            }
            out["record_type"] = r->record_type;
            for (const Kind& k : load_kinds(services_.directory)) {
                if (k.type == r->record_type) {
                    out["kind"] = k.name;
                }
            }
            const bool allowed = signer.role != Role::viewer && may_read_private(signer, state, *r);
            const auto vault = allowed ? private_data(state, asked.record) : std::nullopt;
            const auto body = registration(state, asked.record);
            out["locked"] = services_.keys == nullptr || !services_.keys->unlocked();
            if (!vault || !body) {
                return;
            }
            nlohmann::json fields = nlohmann::json::array();
            for (const protocol::RecordField& f : vault->fields) {
                fields.push_back(
                    {{"name", f.name},
                     {"asked", !asked.fields || std::ranges::contains(*asked.fields, f.name)}});
            }
            const auto kept = node::kept_record_files(dir, asked.record);
            nlohmann::json files = nlohmann::json::array();
            for (std::size_t i = 0; i < body->attachments.size(); ++i) {
                const protocol::Attachment& a = body->attachments[i];
                files.push_back({{"name", a.name},
                                 {"size", a.size},
                                 {"kept", std::ranges::contains(kept, i)},
                                 {"asked", !asked.attachments ||
                                               std::ranges::contains(*asked.attachments, a.name)}});
            }
            out["fields"] = fields;
            out["files"] = files;
            out["may_grant"] = true;
        });
        return json(200, out);
    }

    if (rest.starts_with("/deliveries/")) {
        // A delivery to one of this ledger's requests, opened and checked;
        // or one of its files.
        std::string_view tail = rest.substr(std::string_view("/deliveries/").size());
        const std::size_t slash = tail.find('/');
        const auto id = id_of(tail.substr(0, slash));
        std::optional<std::size_t> file_index;
        if (slash != std::string_view::npos) {
            constexpr std::string_view files = "/files/";
            const std::string_view more = tail.substr(slash);
            std::size_t index = 0;
            const std::string_view digits = more.substr(std::min(files.size(), more.size()));
            const auto [end, ec] =
                std::from_chars(digits.data(), digits.data() + digits.size(), index);
            if (!more.starts_with(files) || digits.empty() || ec != std::errc{} ||
                end != digits.data() + digits.size()) {
                return error(404, "not_found", "no such console route");
            }
            file_index = index;
        }
        if (!id) {
            return error(400, "invalid_argument", "a request's id is 64 hex digits");
        }
        const auto records = access_records(*served, *services_.provider);
        const auto accepted = acceptances(dir, *services_.provider, records);
        const auto acceptance = accepted.find(hex_of(*id));
        const std::filesystem::path file =
            acceptance != accepted.end()
                ? node::access_path(dir, node::AccessBox::deliveries, acceptance->second.grant)
                : fetched_path(services_.directory, *id);
        if (!std::filesystem::exists(file)) {
            return error(404, "not_found", "nothing was delivered for that request (yet)");
        }
        bool allowed = false;
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::RecordState* r = state.record(*id);
            allowed = r != nullptr && may_read_private(signer, state, *r);
        });
        if (!allowed) {
            return error(403, "forbidden", "you may not read what this request brought");
        }
        if (services_.keys == nullptr || !services_.keys->unlocked()) {
            return error(423, "locked", "the console is locked: unlock it first");
        }
        const Bytes delivery = app::read_file(file);
        std::optional<app::OpenedDelivery> opened;
        std::string refusal;
        const auto problem = attempt([&] {
            try {
                opened = app::open_delivery(
                    *served, dir, *services_.provider, delivery,
                    [&] { return services_.keys->open_vault_key(); }, now);
            } catch (const app::NotAccepted& e) {
                refusal = e.message;
            }
        });
        if (problem || !refusal.empty()) {
            return error(422, "not_verified", problem ? *problem : refusal);
        }
        const protocol::EvidenceReport& record = opened->record;
        if (file_index) {
            if (*file_index >= record.attachments.size() ||
                record.attachments[*file_index].status != protocol::AttachmentStatus::verified) {
                return error(404, "not_found", "no such file was delivered");
            }
            const std::string& name = record.attachments[*file_index].name;
            const auto content = opened->contents.attachments.find(name);
            if (content == opened->contents.attachments.end() || !app::plain_file_name(name)) {
                return error(404, "not_found", "no such file was delivered");
            }
            return download(content->second, name, "application/octet-stream");
        }
        nlohmann::json fields = nlohmann::json::array();
        for (const protocol::RecordField& f : record.disclosed_fields) {
            fields.push_back({{"name", f.name},
                              {"value", f.value.as_text() != nullptr
                                            ? nlohmann::json(*f.value.as_text())
                                            : nlohmann::json(app::display_value(f.value))}});
        }
        nlohmann::json files = nlohmann::json::array();
        for (std::size_t i = 0; i < record.attachments.size(); ++i) {
            const protocol::AttachmentCheck& a = record.attachments[i];
            if (a.status == protocol::AttachmentStatus::verified) {
                files.push_back({{"index", i}, {"name", a.name}, {"size", a.size}});
            }
        }
        return json(200, {{"request", hex_of(*id)},
                          {"peer", opened->peer.name},
                          {"organization", record.organization},
                          {"granted_by", app::acted_by(opened->grant.report)},
                          {"grant", hex_of(opened->grant.report.record)},
                          {"record", hex_of(record.record)},
                          {"record_type", record.record_type},
                          {"state", record.state},
                          {"until", opened->grant.value.until},
                          {"fields", fields},
                          {"files", files},
                          {"accepted", acceptance != accepted.end()},
                          {"receipt", acceptance != accepted.end()
                                          ? nlohmann::json(hex_of(acceptance->second.receipt))
                                          : nlohmann::json()}});
    }
    return error(404, "not_found", "no such console route");
}

void Console::access_send_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    const ledger::Ledger* const served = ledger();
    const Evidence source = evidence();
    if (served == nullptr || !source) {
        respond(error(503, "unavailable", "the console has no ledger to send from"));
        return;
    }
    if (signer.role == Role::viewer) {
        respond(error(403, "forbidden", "a viewer reads and verifies, and acts on nothing"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    const auto record = body.is_object() ? id_of(body.value("record", "")) : std::nullopt;
    if (!record) {
        respond(error(400, "invalid_argument", "name the record by its full id (hex)"));
        return;
    }
    // A request goes to the ledger it asks, a receipt to the one that
    // granted: both from the record's own metadata.
    std::string type;
    served->read_state([&](const protocol::LedgerState& state) {
        if (const protocol::RecordState* r = state.record(*record); r != nullptr && !r->revoked) {
            type = r->record_type;
        }
    });
    const auto metadata = node::record_metadata(*services_.provider, *served, *record);
    std::optional<protocol::Id> to;
    std::string path;
    if (type == protocol::access_request_type && metadata) {
        if (const auto r = protocol::decode_access_request(*metadata)) {
            to = r->ledger;
            path = "/v1/access/requests";
        }
    } else if (type == protocol::access_receipt_type && metadata) {
        if (const auto r = protocol::decode_access_receipt(*metadata)) {
            to = r->ledger;
            path = "/v1/access/receipts";
        }
    }
    if (!to) {
        respond(error(404, "not_found", "no request or receipt of this ledger's by that id"));
        return;
    }
    const std::filesystem::path dir = services_.directory.parent_path();
    const auto peer = online_peer(dir, *to);
    if (!peer) {
        respond(error(409, "conflict", "that party is not reached online"));
        return;
    }
    const bool requesting = path == "/v1/access/requests";
    source(*record, [peer = *peer, path, requesting, dir, record = *record,
                     respond = std::move(respond)](Result<Bytes> bundle) mutable {
        if (!bundle) {
            respond(error(503, "unavailable", bundle.error().detail));
            return;
        }
        // To the party, off the ledger's writer.
        std::thread([peer = std::move(peer), path = std::move(path), requesting,
                     dir = std::move(dir), record, bundle = std::move(*bundle),
                     respond = std::move(respond)]() mutable {
            const auto problem = attempt([&] {
                if (requesting) {
                    // Kept as the command line keeps it, to send again.
                    const auto kept = node::access_path(dir, node::AccessBox::requests, record);
                    std::filesystem::create_directories(kept.parent_path());
                    app::write_file(kept, bundle, true);
                }
                static_cast<void>(app::peer_call(peer, "POST", path, bundle));
            });
            if (problem) {
                respond(error(502, "unavailable", *problem));
                return;
            }
            respond(json(200, {{"sent", true}, {"peer", peer.name}}));
        }).detach();
    });
}

void Console::access_deliver_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    const ledger::Ledger* const served = ledger();
    const Evidence source = evidence();
    if (served == nullptr || !source) {
        respond(error(503, "unavailable", "the console has no ledger to deliver from"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    const auto grant_id = body.is_object() ? id_of(body.value("grant", "")) : std::nullopt;
    if (!grant_id) {
        respond(error(400, "invalid_argument", "name the grant by its full id (hex)"));
        return;
    }
    // The grant, the record's private data it discloses, and the kept files
    // it grants, taken now.
    std::optional<protocol::AccessGrant> grant;
    std::optional<app::Vault> vault;
    protocol::DeliveryContents contents;
    std::optional<http::Response> refused;
    const auto metadata = node::record_metadata(*services_.provider, *served, *grant_id);
    const std::filesystem::path dir = services_.directory.parent_path();
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* g = state.record(*grant_id);
        if (g == nullptr || g->record_type != protocol::access_grant_type || !metadata) {
            refused = error(404, "not_found", "no grant of this ledger's by that id");
            return;
        }
        if (g->revoked) {
            refused = error(409, "conflict", "the grant was withdrawn");
            return;
        }
        auto decoded = protocol::decode_access_grant(*metadata);
        const protocol::RecordState* r = decoded ? state.record(decoded->record) : nullptr;
        if (r == nullptr || r->revoked) {
            refused = error(409, "conflict", "the document granted is no longer on this ledger");
            return;
        }
        if (signer.role == Role::viewer || !may_read_private(signer, state, *r)) {
            refused = error(403, "forbidden", "you may not share this document");
            return;
        }
        vault = private_data(state, decoded->record);
        const auto registered = registration(state, decoded->record);
        if (!vault || !registered) {
            refused = services_.keys == nullptr || !services_.keys->unlocked()
                          ? error(423, "locked", "the console is locked: unlock it first")
                          : error(409, "conflict", "the document's private data is not here");
            return;
        }
        for (const std::string& name : decoded->attachments) {
            const auto a =
                std::ranges::find(registered->attachments, name, &protocol::Attachment::name);
            const auto index = static_cast<std::uint64_t>(a - registered->attachments.begin());
            const std::filesystem::path kept = node::record_file_path(dir, decoded->record, index);
            if (a == registered->attachments.end() || !std::filesystem::exists(kept)) {
                refused = error(409, "conflict", "no copy of " + name + " is kept here");
                return;
            }
            const auto problem = attempt([&] {
                contents.attachments[name] =
                    app::open_sealed_file(app::read_file(kept), state.ledger_id(), decoded->record,
                                          name, services_.keys->open_vault_key());
            });
            if (problem) {
                refused = error(409, "conflict", "the kept copy of " + name + " cannot be opened");
                return;
            }
        }
        grant = std::move(*decoded);
    });
    if (refused) {
        respond(std::move(*refused));
        return;
    }
    deliver(std::make_shared<DeliveryJob>(DeliveryJob{
        source, services_.provider, served->hash(), served->id(), *grant_id, std::move(*grant),
        std::move(*vault), std::move(contents), dir, std::move(respond)}));
}

} // namespace cexchain::console
