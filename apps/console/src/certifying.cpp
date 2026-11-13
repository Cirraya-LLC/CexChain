// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Certificates on the console (certificates.hpp): the screen's list; a table
// checked, then issued by the console's machine once an owner or an admin
// approved the batch with a passkey; one certificate's QR code, page, and
// withdrawal; and a certificate a person registered, published at once. The
// machine signs only under the delegation the owner granted it for the
// kind (machine.certify), so the ledger shows the organization's device.

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

#include <kanhe/client/records.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/console/certificates.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/console/kinds.hpp>
#include <kanhe/console/people.hpp>
#include <kanhe/console/settings.hpp>
#include <kanhe/console/setup.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/node/contracts.hpp>
#include <kanhe/node/credentials.hpp>
#include <kanhe/node/published.hpp>
#include <kanhe/verifier/credentials.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

constexpr std::string_view verifier_url = "https://kanhe.cirraya.com/verify/";
/// How long the ledger may take to register one certificate.
constexpr auto register_wait = std::chrono::seconds(30);

std::string_view text_of(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? std::string_view(it->get_ref<const std::string&>())
                                               : std::string_view();
}

/// The kinds that print fields, by type.
std::map<std::string, Kind> certificate_kinds(const std::filesystem::path& directory) {
    std::map<std::string, Kind> out;
    for (Kind& kind : load_kinds(directory)) {
        if (!kind.printed.empty()) {
            out.emplace(kind.type, std::move(kind));
        }
    }
    return out;
}

/// Whether the machine may register records of `type` now.
bool may_issue(const protocol::LedgerState& state, const std::optional<protocol::Id>& machine,
               const std::string& type, protocol::Timestamp now) {
    return machine && node::choose_delegation(state, *machine,
                                              protocol::StatementType::record_register, type, now)
                          .has_value();
}

std::string language_of(const http::Request& request) {
    const auto it = request.query.find("language");
    return certificate_language_of(it == request.query.end() ? "en" : it->second);
}

} // namespace

std::optional<protocol::Id> Console::machine_actor(const protocol::LedgerState& state) const {
    if (services_.keys == nullptr) {
        return std::nullopt;
    }
    for (const SealedKeyInfo& k : services_.keys->keys()) {
        if (k.name != machine_key_name) {
            continue;
        }
        for (const auto& [key, actor] : state.actors()) {
            if (!actor.revoked && actor.kind == protocol::ActorKind::device &&
                actor.key == k.public_key) {
                return protocol::Id(actor.id);
            }
        }
    }
    return std::nullopt;
}

std::optional<crypto::PublicKey> Console::credential_public_key() const {
    if (services_.keys == nullptr) {
        return std::nullopt;
    }
    for (const SealedKeyInfo& k : services_.keys->keys()) {
        if (k.name == credential_key_name) {
            return k.public_key;
        }
    }
    return std::nullopt;
}

std::optional<protocol::Id> Console::credential_actor(const protocol::LedgerState& state) const {
    const auto key = credential_public_key();
    if (!key) {
        return std::nullopt;
    }
    for (const auto& [id, actor] : state.actors()) {
        if (!actor.revoked && actor.kind == protocol::ActorKind::device && actor.key == *key) {
            return protocol::Id(actor.id);
        }
    }
    return std::nullopt;
}

/// The table's list of what was issued: one a table, in the console's
/// folder, so that the same table again carries on.
std::filesystem::path Console::issued_list(const Kind& kind, std::string_view table) const {
    const auto digest = services_.provider->digest(crypto::HashAlg::sha256,
                                                   as_bytes(kind.type + "\n" + std::string(table)));
    return services_.directory / "certificates" / (to_hex(digest->bytes().first(16)) + ".csv");
}

std::vector<Certificate> Console::certificates_now(const protocol::LedgerState& state) const {
    const auto kinds = certificate_kinds(services_.directory);
    std::vector<Certificate> out;
    const ledger::Ledger* served = ledger();
    for (const node::Published& p : node::list_published(services_.directory.parent_path())) {
        const protocol::RecordState* record = state.record(p.record);
        const auto kind = record != nullptr ? kinds.find(record->record_type) : kinds.end();
        if (kind == kinds.end() || served == nullptr) {
            continue;
        }
        std::vector<std::pair<std::string, std::string>> disclosed;
        for (const protocol::FieldDisclosure& d : p.disclosures) {
            if (auto field = protocol::decode_field(d.leaf)) {
                disclosed.emplace_back(field->name, verifier::display_value(field->value));
            }
        }
        const auto registered = registration(state, p.record);
        protocol::Timestamp issued_at = 0;
        static_cast<void>(served->visit_entry(record->registered_at_index, [&](ByteView bytes) {
            if (const auto entry = protocol::decode_log_entry(bytes)) {
                issued_at = entry->registered_at;
            }
        }));
        out.push_back(certificate_of(kind->second, *record,
                                     registered ? registered->metadata : std::nullopt, issued_at,
                                     p.token, p.published_at, disclosed));
    }
    return out;
}

http::Response Console::certificates_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger to act on");
    }
    const bool manages = signer.role == Role::owner || signer.role == Role::admin;
    const std::string base = api_url();
    std::string rest = request.path.substr(std::string_view("/console/api/certificates").size());
    if (rest.empty() && request.method == "GET") {
        nlohmann::json out{{"kinds", nlohmann::json::array()},
                           {"certificates", nlohmann::json::array()},
                           {"address", base},
                           {"reachable", !base.empty() && !base.contains("://localhost") &&
                                             !base.contains("://127.")},
                           {"may_issue", manages},
                           {"may_grant", signer.role == Role::owner}};
        const auto issuer = verifier::parse_base_url(base);
        const protocol::Timestamp now = services_.clock->now();
        served->read_state([&](const protocol::LedgerState& state) {
            const auto machine = machine_actor(state);
            for (const auto& [type, kind] : certificate_kinds(services_.directory)) {
                out["kinds"].push_back({{"type", type},
                                        {"name", kind.name},
                                        {"printed", kind.printed},
                                        {"granted", may_issue(state, machine, type, now)}});
            }
            // Certificates as W3C credentials, once an owner turned them on:
            // the console's credential key, and the issuer its address names.
            const auto credential = credential_actor(state);
            const bool on = credential && node::is_credential_key(state, *state.actor(*credential));
            const auto entries = node::credential_entries(state);
            out["credentials"] = {
                {"state", on           ? "on"
                          : credential ? "registered"
                                       : "off"},
                {"issuer", issuer ? nlohmann::json(issuer->did) : nlohmann::json()},
                {"problem", issuer ? nlohmann::json() : nlohmann::json(issuer.error())}};
            for (const Certificate& c : certificates_now(state)) {
                nlohmann::json j = certificate_json(c, base + "/c/" + c.token);
                j["verify_url"] = verifier_link(verifier_url, state.ledger_id(), c.record,
                                                base + "/c/" + c.token);
                const auto entry = credential
                                       ? node::credential_entry_of(entries, c.record, *credential)
                                       : std::nullopt;
                j["credential"] = entry ? nlohmann::json(verifier::credential_role(entry->entry))
                                        : nlohmann::json();
                out["certificates"].push_back(std::move(j));
            }
        });
        return json(200, out);
    }
    if (rest == "/check" || rest == "/batch") {
        if (request.method != "POST") {
            http::Response refused = error(405, "unsupported", "method not allowed");
            refused.headers.emplace_back("Allow", "POST");
            return refused;
        }
        if (!manages) {
            return error(403, "forbidden", "owners and admins issue certificates");
        }
        const auto body =
            nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
        if (!body.is_object()) {
            return error(400, "invalid_argument", "the request's body is not a JSON object");
        }
        const auto kinds = certificate_kinds(services_.directory);
        const auto kind = kinds.find(std::string(text_of(body, "type")));
        if (kind == kinds.end()) {
            return error(404, "not_found", "no kind of that type prints fields");
        }
        const std::string table(text_of(body, "table"));
        std::vector<CertificateRow> rows;
        try {
            rows = certificate_rows(kind->second, table);
        } catch (const std::invalid_argument& e) {
            return error(400, "invalid_argument", e.what());
        }
        const std::filesystem::path list = issued_list(kind->second, table);
        const auto issued = read_issued(list);
        std::size_t already = 0;
        for (const CertificateRow& row : rows) {
            const auto prior = issued.find(row.line);
            if (prior != issued.end() && !prior->second.token.empty()) {
                ++already;
            }
        }
        nlohmann::json out{
            {"rows", rows.size()}, {"already", already}, {"to_issue", rows.size() - already}};
        if (rest == "/check") {
            return json(200, out);
        }
        // A batch to approve: the owner's or admin's passkey, checked here,
        // starts it; the machine signs each certificate.
        if (services_.keys == nullptr || !services_.keys->unlocked()) {
            return error(423, "locked", "the console is locked: unlock it first");
        }
        bool granted = false;
        served->read_state([&](const protocol::LedgerState& state) {
            granted = may_issue(state, machine_actor(state), kind->first, services_.clock->now());
        });
        if (!granted) {
            return error(409, "conflict",
                         "the console may not issue " + kind->second.name +
                             " certificates yet: an owner must allow it first");
        }
        const auto origin = parse_origin(request.header("origin").value_or(""));
        if (!origin || origin->host.starts_with('[') ||
            origin->host.find_first_not_of("0123456789.") == std::string::npos) {
            return error(400, "invalid_argument",
                         "passkeys need the console's name, not an address: open it at its "
                         "localhost or public URL");
        }
        const People people = load_people(services_.directory);
        const User* user = people.find(signer.user);
        nlohmann::json allowed = nlohmann::json::array();
        for (const auto& p :
             user != nullptr ? user->passkeys : std::vector<protocol::PresenceCredential>{}) {
            if (p.rp_id == origin->host) {
                allowed.push_back({{"type", "public-key"}, {"id", to_base64url(p.credential_id)}});
            }
        }
        Batch batch;
        batch.user = signer.user;
        batch.kind = kind->second;
        batch.rows = std::move(rows);
        batch.list = list;
        batch.challenge = Bytes(32);
        services_.entropy->fill(batch.challenge);
        const std::string challenge = to_base64url(batch.challenge);
        batch.origin = origin->text();
        batch.expires = services_.clock->now() + approval_lifetime;
        batch.total = batch.rows.size();
        batch.already = already;
        std::string id;
        {
            const std::lock_guard lock(mutex_);
            const protocol::Timestamp now = services_.clock->now();
            std::erase_if(batches_, [&](const auto& e) {
                return e.second.state == "waiting" && e.second.expires <= now;
            });
            if (batches_.size() >= 64) {
                return error(429, "unavailable", "too many batches wait; try again soon");
            }
            id = to_hex(services_.entropy->bytes<8>());
            batches_.emplace(id, std::move(batch));
        }
        out["batch"] = id;
        out["public_key"] = {{"challenge", challenge},
                             {"rpId", origin->host},
                             {"allowCredentials", allowed},
                             {"userVerification", "required"},
                             {"timeout", approval_lifetime}};
        return json(200, out);
    }
    if (rest.starts_with("/batch/") && request.method == "GET") {
        const std::lock_guard lock(mutex_);
        const auto found = batches_.find(rest.substr(7));
        if (found == batches_.end() || found->second.user != signer.user) {
            return error(404, "not_found", "no batch of yours under that id");
        }
        const Batch& b = found->second;
        return json(
            200, {{"state", b.state},
                  {"total", b.total},
                  {"already", b.already},
                  {"issued", b.issued},
                  {"problem", b.problem.empty() ? nlohmann::json() : nlohmann::json(b.problem)}});
    }
    // One certificate: its QR code, its page, or its withdrawal.
    const std::size_t slash = rest.find('/', 1);
    const std::string token = rest.substr(1, slash == std::string::npos ? rest.npos : slash - 1);
    const std::string what = slash == std::string::npos ? "" : rest.substr(slash);
    std::optional<Certificate> certificate;
    std::string issuer;
    protocol::Id ledger_id;
    served->read_state([&](const protocol::LedgerState& state) {
        for (Certificate& c : certificates_now(state)) {
            if (c.token == token) {
                certificate = std::move(c);
            }
        }
        issuer = state.organization();
        ledger_id = state.ledger_id();
    });
    if (!certificate) {
        return error(404, "not_found", "no certificate is published there");
    }
    if (what.empty() && request.method == "DELETE") {
        if (!manages) {
            return error(403, "forbidden", "owners and admins withdraw certificates");
        }
        if (auto s = node::unpublish(services_.directory.parent_path(), token); !s) {
            return error(404, "not_found", "no certificate is published there");
        }
        log_activity(signer.user, "certificates.withdraw",
                     {{"record", to_hex(certificate->record.bytes())}});
        return json(200, {{"withdrawn", token}});
    }
    if ((what == "/qr" || what == "/page") && request.method == "GET") {
        const std::string language = language_of(request);
        const std::string link = verifier_link(verifier_url, ledger_id, certificate->record,
                                               base + "/c/" + token, language);
        http::Response r;
        r.status = 200;
        if (what == "/qr") {
            const std::string svg = qr_svg(link);
            r.content_type = "image/svg+xml";
            r.body.assign(svg.begin(), svg.end());
        } else {
            const std::string page = fill_certificate(default_certificate_template(language),
                                                      page_of(*certificate, issuer, link));
            r.content_type = "text/html; charset=utf-8";
            r.body.assign(page.begin(), page.end());
        }
        secure(r);
        r.headers.emplace_back("Content-Security-Policy", "sandbox; default-src 'none'");
        return r;
    }
    if (what == "/credential" && request.method == "POST") {
        if (!manages) {
            return error(403, "forbidden", "owners and admins issue credentials");
        }
        return issue_credential(signer, *certificate, base);
    }
    http::Response refused = error(405, "unsupported", "method not allowed");
    refused.headers.emplace_back("Allow", what.empty()            ? "DELETE"
                                          : what == "/credential" ? "POST"
                                                                  : "GET");
    return refused;
}

http::Response Console::issue_credential(const Signed& signer, const Certificate& certificate,
                                         const std::string& address) const {
    const ledger::Ledger* served = ledger();
    const Submit submit = submitter();
    const Evidence source = evidence();
    if (served == nullptr || !submit || !source || services_.keys == nullptr ||
        !services_.keys->unlocked()) {
        return error(423, "locked", "the console is locked: unlock it first");
    }
    const auto base = verifier::parse_base_url(address);
    if (!base) {
        return error(409, "conflict",
                     "credentials name the console's address as their issuer, and it cannot be "
                     "one: " +
                         base.error());
    }
    const auto public_key = credential_public_key();
    std::optional<protocol::Id> actor;
    std::optional<node::CredentialEntry> existing;
    std::vector<node::CredentialEntry> entries;
    bool ready = false;
    served->read_state([&](const protocol::LedgerState& state) {
        actor = credential_actor(state);
        ready = actor && node::is_credential_key(state, *state.actor(*actor));
        entries = node::credential_entries(state);
        if (actor) {
            existing = node::credential_entry_of(entries, certificate.record, *actor);
        }
    });
    if (!public_key || !ready) {
        return error(409, "conflict", "credentials are not on: an owner turns them on first");
    }
    // The published address's evidence, as anyone holding it gets it.
    auto exported = std::make_shared<std::promise<Result<Bytes>>>();
    auto future = exported->get_future();
    source(certificate.record,
           [exported](Result<Bytes> bundle) { exported->set_value(std::move(bundle)); });
    if (future.wait_for(register_wait) != std::future_status::ready) {
        return error(503, "unavailable", "the ledger did not give the evidence in time");
    }
    const Result<Bytes> plain = future.get();
    const auto published =
        node::load_published(services_.directory.parent_path(), certificate.token);
    auto bundle = plain ? protocol::decode_bundle(*plain)
                        : Result<protocol::EvidenceBundle>(std::unexpected(plain.error()));
    if (!bundle || !published) {
        return error(500, "internal", "the certificate's evidence could not be made");
    }
    bundle->disclosures = published->disclosures;
    const auto encoded = protocol::encode_bundle(*bundle);
    protocol::VerifyOptions verify;
    verify.expected_ledger = served->id();
    const auto report = encoded
                            ? protocol::verify_bundle(*services_.provider, *encoded, verify)
                            : Result<protocol::EvidenceReport>(std::unexpected(encoded.error()));
    if (!report) {
        return error(500, "internal", "the certificate's evidence does not verify");
    }
    ledger::SystemEntropy entropy;
    const verifier::StatusEntry entry =
        existing ? existing->entry : node::choose_status_entry(entries, entropy);
    std::vector<std::string> metadata;
    if (const auto kinds = certificate_kinds(services_.directory);
        kinds.contains(certificate.type)) {
        metadata = printed_public_fields(kinds.at(certificate.type));
    }
    auto content = verifier::credential_content(*report, *base, certificate.token, entry, metadata,
                                                certificate.kind);
    if (!content) {
        return error(409, "conflict", content.error());
    }
    const crypto::openssl::KeyPair key = services_.keys->open(credential_key_name);
    if (!existing) {
        // The first time: the credential key endorses the record as this
        // credential, the ledger's witnessed account of the issue.
        std::optional<Bytes> statement;
        served->read_state([&](const protocol::LedgerState& state) {
            const auto delegation =
                node::choose_delegation(state, *actor, protocol::StatementType::record_endorse,
                                        certificate.type, services_.clock->now());
            protocol::Statement s;
            s.ledger_id = state.ledger_id();
            s.actor_id = *actor;
            s.delegation_id = delegation;
            s.issued_at = services_.clock->now();
            s.nonce = services_.entropy->bytes<16>();
            s.body =
                protocol::RecordEndorseBody{certificate.record, verifier::credential_role(entry)};
            if (auto made = protocol::sign_statement(key, *services_.provider, state.hash(), s)) {
                statement = std::move(made->encoded);
            }
        });
        if (!statement) {
            return error(500, "internal", "the endorsement could not be signed");
        }
        auto answered = std::make_shared<std::promise<http::Response>>();
        auto registered = answered->get_future();
        submit(std::move(*statement), false,
               [answered](http::Response r) { answered->set_value(std::move(r)); });
        if (registered.wait_for(register_wait) != std::future_status::ready) {
            return error(503, "unavailable", "the ledger did not register the credential in time");
        }
        const http::Response r = registered.get();
        if (r.status < 200 || r.status >= 300) {
            return r;
        }
        log_activity(signer.user, "certificates.credential",
                     {{"record", to_hex(certificate.record.bytes())},
                      {"entry", verifier::credential_role(entry)}});
    }
    const auto credential = verifier::sign_credential(key, *services_.provider, base->did,
                                                      verifier::credential_json(*content));
    if (!credential) {
        return error(500, "internal", "the credential could not be signed");
    }
    http::Response r;
    r.status = 200;
    r.content_type = std::string(verifier::credential_media_type);
    r.body.assign(credential->begin(), credential->end());
    secure(r);
    return r;
}

http::Response Console::batch_start_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    const ledger::Ledger* served = ledger();
    if (served == nullptr || !submitter() || services_.keys == nullptr ||
        !services_.keys->unlocked()) {
        return error(423, "locked", "the console is locked: unlock it first");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    protocol::PresenceProof proof;
    for (auto [key, into] : {std::pair{"credential_id", &proof.credential_id},
                             std::pair{"authenticator_data", &proof.authenticator_data},
                             std::pair{"client_data_json", &proof.client_data_json},
                             std::pair{"signature", &proof.signature}}) {
        auto bytes = from_base64url(text_of(body, key));
        if (!bytes || bytes->empty()) {
            return error(400, "invalid_argument",
                         "an approval needs credential_id, authenticator_data, client_data_json, "
                         "and signature (base64url)");
        }
        *into = std::move(*bytes);
    }
    const std::string id(text_of(body, "batch"));
    const auto canonical = [](std::string_view url) {
        const auto parsed = parse_origin(url);
        return parsed ? parsed->text() : std::string();
    };
    const std::string origin = canonical(request.header("origin").value_or(""));
    std::shared_ptr<Run> run;
    {
        // Approved once: a second start finds it running.
        const std::lock_guard lock(mutex_);
        const auto found = batches_.find(id);
        if (found == batches_.end() || found->second.user != signer.user ||
            found->second.state != "waiting" || found->second.origin != origin) {
            return error(404, "not_found", "nothing of yours waits for approval under that id");
        }
        if (found->second.expires <= services_.clock->now()) {
            batches_.erase(found);
            return error(404, "not_found", "nothing of yours waits for approval under that id");
        }
        if (std::ranges::any_of(batches_, [](const auto& e) {
                return e.second.state == "running" || e.second.state == "checking";
            })) {
            return error(409, "conflict", "another batch is being issued: wait for it to finish");
        }
        run = std::make_shared<Run>(id, found->second);
        found->second.state = "checking";
    }
    // The passkey checked against the approver's, on the ledger, from this
    // console's page, with the person verified.
    const People people = load_people(services_.directory);
    const User* approver = people.find(signer.user);
    std::string problem;
    served->read_state([&](const protocol::LedgerState& state) {
        const auto actor = approver != nullptr ? from_hex(approver->actor)
                                               : Result<Bytes>(fail(Errc::not_found, "none"));
        const auto actor_id =
            actor ? protocol::to_id(*actor) : Result<protocol::Id>(fail(Errc::not_found, "none"));
        const protocol::ActorState* a = actor_id ? state.actor(*actor_id) : nullptr;
        if (a == nullptr || a->revoked) {
            problem = "this user's actor is not on the ledger, or is revoked";
            return;
        }
        const auto check = protocol::verify_assertion(*services_.provider, run->batch.challenge,
                                                      proof, a->presence);
        if (!check) {
            problem = "the passkey did not approve it: " + std::string(check.error().detail);
        } else if (!check->user_verified || canonical(check->origin) != run->batch.origin) {
            problem = "the passkey did not approve it on this console, with the person verified";
        }
    });
    {
        const std::lock_guard lock(mutex_);
        Batch& b = batches_.at(id);
        b.state = problem.empty() ? "running" : "waiting";
        if (!problem.empty()) {
            return error(403, "forbidden", problem);
        }
    }
    log_activity(signer.user, "certificates.issue",
                 {{"type", run->batch.kind.type}, {"rows", run->batch.total}});
    // Issued one after another on the console's own thread, each waiting
    // for the ledger, so that nothing waits on the node's writer.
    {
        const std::lock_guard lock(certify_mutex_);
        certifier_ = std::jthread([this, run](const std::stop_token& stop) { issue(*run, stop); });
    }
    return json(202, {{"batch", id}, {"state", "running"}, {"total", run->batch.total}});
}

void Console::issue(Run& run, const std::stop_token& stop) const {
    const auto finish = [&](std::string state, std::string problem) {
        const std::lock_guard lock(mutex_);
        if (const auto found = batches_.find(run.id); found != batches_.end()) {
            found->second.state = std::move(state);
            found->second.problem = std::move(problem);
        }
    };
    try {
        const ledger::Ledger* served = ledger();
        const auto machine_key = services_.keys->open(machine_key_name);
        const auto vault_public = services_.keys->vault_public_key();
        if (served == nullptr || !vault_public) {
            finish("failed", "the console has no ledger, or no vault key");
            return;
        }
        const std::filesystem::path ledger_dir = services_.directory.parent_path();
        std::filesystem::create_directories(run.batch.list.parent_path());
        auto issued = read_issued(run.batch.list);
        const std::string base = api_url();
        for (const CertificateRow& row : run.batch.rows) {
            if (stop.stop_requested()) {
                finish("failed", "the console stopped: issue the same table again to carry on");
                return;
            }
            const auto prior = issued.find(row.line);
            if (prior != issued.end() && !prior->second.token.empty()) {
                continue;
            }
            const std::string fingerprint = row_fingerprint(*services_.provider, row);
            protocol::Id record;
            std::vector<protocol::RecordField> fields;
            if (prior != issued.end()) {
                // Registered, then stopped before it was published.
                const auto bytes = from_hex(prior->second.record);
                std::optional<client::Vault> vault;
                served->read_state([&](const protocol::LedgerState& state) {
                    if (bytes) {
                        if (auto id = protocol::to_id(*bytes)) {
                            record = *id;
                            vault = private_data(state, record);
                        }
                    }
                });
                if (!vault) {
                    finish("failed", "the private data of line " + std::to_string(row.line) +
                                         " cannot be opened");
                    return;
                }
                fields = vault->fields;
            } else {
                for (const auto& [name, value] : row.fields) {
                    fields.push_back(
                        {name, services_.entropy->bytes<16>(), cbor::Value::text(value)});
                }
                std::optional<Bytes> submission;
                std::string problem;
                served->read_state([&](const protocol::LedgerState& state) {
                    const auto commitment =
                        protocol::commit_fields(*services_.provider, state.hash(), fields);
                    const auto machine = machine_actor(state);
                    if (!commitment || !machine) {
                        problem = "the console's machine is not on the ledger";
                        return;
                    }
                    fields = commitment->fields;
                    protocol::RecordRegisterBody body;
                    body.record_type = run.batch.kind.type;
                    body.field_root =
                        Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end());
                    body.field_count = commitment->leaves.size();
                    if (!row.metadata.empty()) {
                        cbor::Map metadata;
                        for (const auto& [name, value] : row.metadata) {
                            metadata.push_back({cbor::Value::text(name), cbor::Value::text(value)});
                        }
                        body.metadata = cbor::Value::map(std::move(metadata));
                    }
                    protocol::Statement s;
                    s.ledger_id = state.ledger_id();
                    s.actor_id = *machine;
                    s.issued_at = services_.clock->now();
                    s.nonce = services_.entropy->bytes<16>();
                    s.delegation_id = node::choose_delegation(
                        state, *machine, protocol::StatementType::record_register,
                        run.batch.kind.type, s.issued_at);
                    if (!s.delegation_id) {
                        problem = "the console may no longer issue these certificates";
                        return;
                    }
                    s.body = std::move(body);
                    auto made =
                        protocol::sign_statement(machine_key, *services_.provider, state.hash(), s);
                    if (!made) {
                        problem = "signing failed";
                        return;
                    }
                    record = made->id;
                    auto encoded = cbor::encode(cbor::Value::map(
                        {{cbor::Value::integer(1), cbor::Value::bytes(made->encoded)},
                         {cbor::Value::integer(2),
                          cbor::Value::bytes(client::seal_vault(state.ledger_id(), record,
                                                                client::Vault{fields, {}},
                                                                *vault_public))}}));
                    if (encoded) {
                        submission = std::move(*encoded);
                    }
                });
                if (!submission) {
                    finish("failed", problem.empty() ? "a certificate could not be made" : problem);
                    return;
                }
                auto answered = std::make_shared<std::promise<http::Response>>();
                auto future = answered->get_future();
                submitter()(std::move(*submission), true,
                            [answered](http::Response r) { answered->set_value(std::move(r)); });
                if (future.wait_for(register_wait) != std::future_status::ready) {
                    finish("failed", "the ledger did not register line " +
                                         std::to_string(row.line) + " in time");
                    return;
                }
                const http::Response registered = future.get();
                if (registered.status < 200 || registered.status >= 300) {
                    const auto answer = nlohmann::json::parse(
                        registered.body.begin(), registered.body.end(), nullptr, false);
                    finish("failed", "line " + std::to_string(row.line) + ": " +
                                         (answer.is_object() && answer.contains("error")
                                              ? answer["error"].value("message", "refused")
                                              : std::string("refused")));
                    return;
                }
                append_issued(run.batch.list, row.line,
                              {fingerprint, to_hex(record.bytes()), "", ""});
            }
            const crypto::HashAlg hash = served->hash();
            const auto published = node::publish_record(
                ledger_dir, record,
                printed_disclosures(*services_.provider, hash, run.batch.kind, fields),
                *services_.entropy, *services_.clock);
            if (!published) {
                finish("failed", "publishing line " + std::to_string(row.line) + " failed");
                return;
            }
            append_issued(run.batch.list, row.line,
                          {fingerprint, to_hex(record.bytes()), published->token,
                           base + "/c/" + published->token});
            const std::lock_guard lock(mutex_);
            if (const auto found = batches_.find(run.id); found != batches_.end()) {
                ++found->second.issued;
            }
        }
        finish("done", "");
    } catch (const std::exception& e) {
        finish("failed", e.what());
    }
}

void Console::publish_certificate(const protocol::Id& record, const std::string& type,
                                  const std::vector<protocol::RecordField>& fields) const {
    const auto kinds = certificate_kinds(services_.directory);
    const auto kind = kinds.find(type);
    const ledger::Ledger* served = ledger();
    if (kind == kinds.end() || served == nullptr) {
        return;
    }
    static_cast<void>(node::publish_record(
        services_.directory.parent_path(), record,
        printed_disclosures(*services_.provider, served->hash(), kind->second, fields),
        *services_.entropy, *services_.clock));
}

} // namespace kanhe::console
