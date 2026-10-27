// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Approving with a passkey, one tap per statement. The console builds the
// statement a signed-in person asked for and holds it for two minutes; the
// page shows it and has the person's passkey sign its presence challenge;
// the console checks that proof as the ledger will, opens the person's
// sealed key, signs, submits, and forgets the key. The ledger itself refuses
// the statement without the proof when the person's delegation requires it.

#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/records.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/record_files.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::size_t max_prepared = 256;

std::string field_text(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::optional<protocol::Id> id_of(std::string_view hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

/// An origin in its canonical form (lower case, no default port), or empty.
std::string canonical(std::string_view origin) {
    const auto parsed = parse_origin(origin);
    return parsed ? parsed->text() : std::string();
}

/// The statement body an intent asks for, if the console knows the action.
std::variant<protocol::Body, std::string> body_of_intent(const nlohmann::json& intent) {
    const std::string action = field_text(intent, "action");
    const auto record = id_of(field_text(intent, "record"));
    if (action == "record.endorse" || action == "record.revoke") {
        if (!record) {
            return std::string("name the record by its full id (hex)");
        }
        if (action == "record.endorse") {
            const std::string role = field_text(intent, "role");
            if (role.empty() || role.size() > 64) {
                return std::string("an endorsement names a role of 1 to 64 bytes");
            }
            return protocol::Body{protocol::RecordEndorseBody{*record, role}};
        }
        const std::string reason = field_text(intent, "reason");
        return protocol::Body{protocol::RecordRevokeBody{
            *record, reason.empty() ? std::nullopt : std::optional(reason)}};
    }
    if (action == "contract.retire") {
        const auto contract = id_of(field_text(intent, "contract"));
        if (!contract) {
            return std::string("name the contract by its full id (hex)");
        }
        const std::string reason = field_text(intent, "reason");
        return protocol::Body{protocol::ContractRetireBody{
            *contract, reason.empty() ? std::nullopt : std::optional(reason)}};
    }
    return std::string("the console cannot prepare this action");
}

nlohmann::json describe(const protocol::Statement& s, const protocol::LedgerState& state) {
    nlohmann::json out{{"type", std::string(protocol::name(protocol::type_of(s.body)))}};
    if (const auto* e = std::get_if<protocol::RecordEndorseBody>(&s.body)) {
        out["record"] = to_hex(e->record.bytes());
        out["role"] = e->role;
        if (const auto* r = state.record(e->record)) {
            out["record_type"] = r->record_type;
        }
    } else if (const auto* v = std::get_if<protocol::RecordRevokeBody>(&s.body)) {
        out["record"] = to_hex(v->record.bytes());
        out["reason"] = v->reason ? nlohmann::json(*v->reason) : nlohmann::json();
        if (const auto* r = state.record(v->record)) {
            out["record_type"] = r->record_type;
        }
    } else if (const auto* g = std::get_if<protocol::RecordRegisterBody>(&s.body)) {
        out["record_type"] = g->record_type;
        out["field_count"] = g->field_count;
    } else if (const auto* d = std::get_if<protocol::ContractDeployBody>(&s.body)) {
        out["name"] = d->name ? nlohmann::json(*d->name) : nlohmann::json();
        out["language"] = d->language;
        out["code_size"] = d->code.size();
        nlohmann::json functions = nlohmann::json::array();
        for (const auto& [name, kind] : d->interface) {
            functions.push_back(name);
        }
        out["functions"] = functions;
    } else if (const auto* r = std::get_if<protocol::ContractRetireBody>(&s.body)) {
        out["contract"] = to_hex(r->contract.bytes());
        out["reason"] = r->reason ? nlohmann::json(*r->reason) : nlohmann::json();
        if (const auto* c = state.contract(r->contract); c != nullptr && c->name) {
            out["name"] = *c->name;
        }
    }
    return out;
}

} // namespace

http::Response Console::prepare_route(const http::Request& request) const {
    const ledger::Ledger* const served = ledger();
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (signer.role == Role::viewer) {
        return error(403, "forbidden", "a viewer reads and verifies, and acts on nothing");
    }
    const auto intent =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!intent.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const std::string action = field_text(intent, "action");
    if (action.starts_with("contract.") && signer.role != Role::owner &&
        signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin deploys or retires rules");
    }
    if (served == nullptr || !submitter()) {
        return error(503, "unavailable", "the console has no ledger to act on");
    }
    const People people = load_people(services_.directory);
    const User* user = people.find(signer.user);
    if (user == nullptr || user->actor.empty() || user->key.empty()) {
        return error(409, "conflict",
                     "this user acts as no one on the ledger yet (console user link)");
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return error(423, "locked", "the console is locked: unlock it first");
    }
    // A registration is drafted first: its fields' salts, its files'
    // commitments, and what it keeps private.
    std::optional<Draft> draft;
    std::variant<protocol::Body, std::string> body = std::string();
    if (action == "contract.deploy") {
        // Built by the compiler in a child process, as the editor checked it.
        auto built = deploy_body(signer, field_text(intent, "source"));
        if (auto* refused = std::get_if<http::Response>(&built)) {
            return std::move(*refused);
        }
        body = protocol::Body{std::get<protocol::ContractDeployBody>(std::move(built))};
    } else if (action == "record.register") {
        auto drafted = register_draft(intent, signer.user);
        if (auto* problem = std::get_if<std::string>(&drafted)) {
            return error(400, "invalid_argument", *problem);
        }
        auto& [registration, d] = std::get<0>(drafted);
        body = protocol::Body{std::move(registration)};
        draft = std::move(d);
    } else {
        body = body_of_intent(intent);
    }
    if (auto* problem = std::get_if<std::string>(&body)) {
        return error(400, "invalid_argument", *problem);
    }
    const std::string origin = std::string(*request.header("origin"));
    const auto parsed_origin = parse_origin(origin);
    if (!parsed_origin || parsed_origin->host.starts_with('[') ||
        parsed_origin->host.find_first_not_of("0123456789.") == std::string::npos) {
        return error(400, "invalid_argument",
                     "passkeys need the console's name, not an address: open it at its "
                     "localhost or public URL");
    }
    const auto actor = id_of(user->actor);
    Prepared prepared;
    std::string problem;
    nlohmann::json summary;
    const crypto::HashAlg hash = served->hash();
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ActorState* a = actor ? state.actor(*actor) : nullptr;
        if (a == nullptr || a->revoked) {
            problem = "this user's actor is not on the ledger, or is revoked";
            return;
        }
        protocol::Statement& s = prepared.statement;
        s.body = std::get<protocol::Body>(std::move(body));
        std::optional<std::string> record_type;
        std::optional<protocol::Id> contract;
        if (const auto* e = std::get_if<protocol::RecordEndorseBody>(&s.body)) {
            const auto* r = state.record(e->record);
            record_type = r ? std::optional(r->record_type) : std::nullopt;
        } else if (const auto* v = std::get_if<protocol::RecordRevokeBody>(&s.body)) {
            const auto* r = state.record(v->record);
            record_type = r ? std::optional(r->record_type) : std::nullopt;
        } else if (const auto* g = std::get_if<protocol::RecordRegisterBody>(&s.body)) {
            record_type = g->record_type;
        } else if (const auto* r = std::get_if<protocol::ContractRetireBody>(&s.body)) {
            const auto* c = state.contract(r->contract);
            if (c == nullptr || c->retired) {
                problem = "no such contract on this ledger, or it is retired";
                return;
            }
            contract = r->contract;
        }
        const bool on_records = std::holds_alternative<protocol::RecordEndorseBody>(s.body) ||
                                std::holds_alternative<protocol::RecordRevokeBody>(s.body);
        if (on_records && !record_type) {
            problem = "no such record on this ledger";
            return;
        }
        s.ledger_id = state.ledger_id();
        s.actor_id = *actor;
        s.issued_at = services_.clock->now();
        s.nonce = services_.entropy->bytes<16>();
        s.delegation_id = node::choose_delegation(state, *actor, protocol::type_of(s.body),
                                                  record_type, s.issued_at, contract);
        if (!s.delegation_id) {
            problem = "no valid delegation lets " + a->display_name + " do this";
            return;
        }
        const auto kid = protocol::key_id(*services_.provider, hash, a->key);
        const auto challenge =
            kid ? protocol::presence_challenge(*services_.provider, hash, s, *kid)
                : Result<Bytes>(std::unexpected(kid.error()));
        if (!kid || !challenge) {
            problem = "the statement could not be prepared";
            return;
        }
        prepared.kid = *kid;
        prepared.challenge = *challenge;
        summary = describe(s, state);
        if (const auto* d = std::get_if<protocol::ContractDeployBody>(&s.body)) {
            // The code's digest, which the page computes from the bytes too.
            const auto digest = services_.provider->digest(crypto::HashAlg::sha256, d->code);
            summary["code_sha256"] =
                digest ? nlohmann::json(to_hex(digest->bytes())) : nlohmann::json();
        }
    });
    if (!problem.empty()) {
        return error(409, "conflict", problem);
    }
    if (draft) {
        // What the page shows and checks: the values and salts behind the
        // field root, and the salts behind the files' commitments.
        const auto& g = std::get<protocol::RecordRegisterBody>(prepared.statement.body);
        nlohmann::json fields = nlohmann::json::array();
        for (const protocol::RecordField& f : draft->vault.fields) {
            fields.push_back(
                {{"name", f.name}, {"value", *f.value.as_text()}, {"salt", to_base64url(f.salt)}});
        }
        nlohmann::json files = nlohmann::json::array();
        for (std::size_t i = 0; i < g.attachments.size(); ++i) {
            files.push_back({{"name", g.attachments[i].name},
                             {"media_type", g.attachments[i].media_type},
                             {"size", g.attachments[i].size},
                             {"salt", to_base64url(draft->vault.attachments[i].salt)},
                             {"upload", draft->uploads[i]}});
        }
        nlohmann::json metadata = nlohmann::json::object();
        if (g.metadata) {
            for (const auto& entry : *g.metadata->as_map()) {
                metadata[*entry.key.as_text()] = *entry.value.as_text();
            }
        }
        summary["fields"] = fields;
        summary["files"] = files;
        summary["metadata"] = metadata;
        summary["keep_files"] = draft->keep_files;
    }
    prepared.draft = std::move(draft);
    prepared.user = signer.user;
    prepared.key = user->key;
    prepared.rp_id = parsed_origin->host;
    prepared.origin = parsed_origin->text();
    prepared.expires = services_.clock->now() + approval_lifetime;
    const auto payload = protocol::encode_payload(prepared.statement);
    if (!payload) {
        return error(500, "internal", "the statement could not be encoded");
    }
    nlohmann::json allowed = nlohmann::json::array();
    for (const auto& p : user->passkeys) {
        if (p.rp_id == prepared.rp_id) {
            allowed.push_back({{"type", "public-key"}, {"id", to_base64url(p.credential_id)}});
        }
    }
    const std::string challenge = to_base64url(prepared.challenge);
    const std::string kid = to_base64url(prepared.kid.bytes());
    std::string id;
    {
        const protocol::Timestamp now = services_.clock->now();
        const std::lock_guard lock(mutex_);
        std::erase_if(prepared_, [&](const auto& e) { return e.second.expires <= now; });
        if (prepared_.size() >= max_prepared) {
            return error(429, "unavailable", "too many approvals are waiting; try again soon");
        }
        id = to_hex(services_.entropy->bytes<8>());
        prepared_.emplace(id, std::move(prepared));
    }
    return json(200, {{"prepared", id},
                      {"summary", summary},
                      {"payload", to_base64url(*payload)},
                      {"kid", kid},
                      {"hash", crypto::cose_id(hash)},
                      {"public_key",
                       {{"challenge", challenge},
                        {"rpId", parsed_origin->host},
                        {"allowCredentials", allowed},
                        {"userVerification", "required"},
                        {"timeout", approval_lifetime}}}});
}

std::variant<Console::Signing, http::Response>
Console::sign_approval(const http::Request& request) const {
    const ledger::Ledger* const served = ledger();
    if (served == nullptr || !submitter()) {
        return error(503, "unavailable", "the console has no ledger to act on");
    }
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    // Taken once: a second approval of the same statement finds nothing.
    std::optional<Prepared> prepared;
    {
        const protocol::Timestamp now = services_.clock->now();
        const std::lock_guard lock(mutex_);
        const auto found = prepared_.find(field_text(body, "prepared"));
        if (found != prepared_.end() && found->second.user == signer.user) {
            if (found->second.expires > now) {
                prepared = std::move(found->second);
            }
            prepared_.erase(found);
        }
    }
    const std::string origin = canonical(*request.header("origin"));
    if (!prepared || prepared->origin != origin) {
        return error(404, "not_found", "nothing of yours waits for approval under that id");
    }
    protocol::PresenceProof proof;
    for (auto [key, into] : {std::pair{"credential_id", &proof.credential_id},
                             std::pair{"authenticator_data", &proof.authenticator_data},
                             std::pair{"client_data_json", &proof.client_data_json},
                             std::pair{"signature", &proof.signature}}) {
        auto bytes = from_base64url(field_text(body, key));
        if (!bytes || bytes->empty()) {
            return error(400, "invalid_argument",
                         "an approval needs credential_id, authenticator_data, client_data_json, "
                         "and signature (base64url)");
        }
        *into = std::move(*bytes);
    }
    protocol::Statement statement = std::move(prepared->statement);
    statement.presence = std::move(proof);
    // The proof checked as the ledger checks it, against the person's
    // passkeys registered on the ledger, and from this console's page.
    std::string problem;
    std::optional<crypto::PublicKey> current_key;
    const crypto::HashAlg hash = served->hash();
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ActorState* a = state.actor(statement.actor_id.value());
        if (a == nullptr || a->revoked) {
            problem = "this user's actor is not on the ledger, or is revoked";
            return;
        }
        const auto check = protocol::verify_presence(*services_.provider, hash, statement,
                                                     prepared->kid, a->presence);
        if (!check) {
            problem =
                std::string("the passkey did not approve it: ") + std::string(check.error().detail);
        } else if (!check->user_verified || canonical(check->origin) != prepared->origin) {
            problem = "the passkey did not approve it on this console, with the person verified";
        }
        current_key = a->key;
    });
    if (!problem.empty()) {
        return error(403, "forbidden", problem);
    }
    std::optional<protocol::SignedStatement> signed_statement;
    {
        // The person's key is opened for this one signature, then dropped.
        const auto key = services_.keys->open(prepared->key);
        if (key.public_key() != *current_key) {
            return error(409, "conflict", "the console's key is no longer this person's key");
        }
        auto made = protocol::sign_statement(key, *services_.provider, hash, statement);
        if (!made) {
            return error(500, "internal", "signing failed");
        }
        signed_statement = std::move(*made);
    }
    if (!prepared->draft) {
        return Signing{std::move(signed_statement->encoded), false, {}};
    }
    // A registration: its private data, and its files if the kind keeps
    // them, sealed to the vault key for the record's id, sent along.
    const std::filesystem::path pub = services_.directory.parent_path() / "vault" / "vault.pub";
    const auto vault_key = std::filesystem::exists(pub)
                               ? app::decode_vault_public_key(app::read_file(pub))
                               : std::nullopt;
    if (!vault_key) {
        return error(409, "conflict", "this ledger has no vault key (cexchain vault rekey)");
    }
    const Draft& draft = *prepared->draft;
    const auto& registration = std::get<protocol::RecordRegisterBody>(statement.body);
    const protocol::Id& ledger_id = *statement.ledger_id;
    const protocol::Id& record = signed_statement->id;
    cbor::Map submission{
        {cbor::Value::integer(1), cbor::Value::bytes(signed_statement->encoded)},
        {cbor::Value::integer(2),
         cbor::Value::bytes(app::seal_vault(ledger_id, record, draft.vault, *vault_key))}};
    if (draft.keep_files && !draft.uploads.empty()) {
        std::vector<node::SealedFile> files;
        for (std::size_t i = 0; i < draft.uploads.size(); ++i) {
            std::filesystem::path path;
            {
                const std::lock_guard lock(mutex_);
                const auto it = uploads_.find(draft.uploads[i]);
                if (it == uploads_.end()) {
                    return error(409, "conflict", "a file is no longer here: upload it again");
                }
                path = it->second.path;
            }
            files.push_back(
                {i, app::seal_record_file(ledger_id, record, registration.attachments[i].name,
                                          app::read_file(path), *vault_key)});
        }
        submission.push_back({cbor::Value::integer(4), node::encode_sealed_files(files)});
    }
    auto encoded = cbor::encode(cbor::Value::map(std::move(submission)));
    if (!encoded) {
        return error(500, "internal", "the submission could not be encoded");
    }
    return Signing{std::move(*encoded), true, draft.uploads};
}

http::Response Console::approve_route(const http::Request& request) const {
    auto signed_or = sign_approval(request);
    if (auto* refused = std::get_if<http::Response>(&signed_or)) {
        return std::move(*refused);
    }
    // Waits for the ledger's answer (the node itself uses the asynchronous
    // handle instead); the promise outlives a wait that gives up.
    Signing signing = std::get<Signing>(std::move(signed_or));
    auto answered = std::make_shared<std::promise<http::Response>>();
    auto future = answered->get_future();
    submitter()(std::move(signing.body), signing.submission,
                [answered](http::Response r) { answered->set_value(std::move(r)); });
    if (future.wait_for(std::chrono::seconds(30)) != std::future_status::ready) {
        return error(504, "unavailable", "the ledger did not register it in time");
    }
    http::Response registered = future.get();
    if (registered.status >= 200 && registered.status < 300) {
        forget_uploads(signing.uploads);
    }
    secure(registered);
    return registered;
}

} // namespace cexchain::console
