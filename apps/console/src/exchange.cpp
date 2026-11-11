// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Proposal and consent files (.kanhe) in the console, for ledgers that do
// not reach each other's APIs. The home writes a proposal for a call that
// waits for other parties' consents; a party opens it, reads the call
// against the contract's text and the instance's state (the evidence in the
// file, verified here), consents with a tap on its own ledger, and sends back
// the consent file; the home opens that and records the call, citing the
// consent, with a tap. Every file is read from the person's own upload.

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/bo/source.hpp>
#include <kanhe/client/contracts.hpp>
#include <kanhe/client/errors.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/contract_evidence.hpp>
#include <kanhe/core/protocol/contracts.hpp>
#include <kanhe/core/protocol/exchange.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/ledger/verify.hpp>
#include <kanhe/node/contracts.hpp>
#include <kanhe/node/peers.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::optional<protocol::Id> id_of(std::string_view hex) {
    if (hex.size() != 64) {
        return std::nullopt;
    }
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::string language_of(std::string_view asked) {
    return asked == "zh-Hant-HK" || asked == "zh-Hans-CN" ? std::string(asked) : std::string("en");
}

/// A file a download names: kind, the instance's first 12 hex digits, the function.
std::string file_name(const protocol::ExchangeFile& f) {
    std::string function;
    for (const char c : f.function) {
        function += std::isalnum(static_cast<unsigned char>(c)) != 0 ? c : '-';
    }
    return std::string(protocol::name(f.kind)) + "-" + hex_of(f.instance).substr(0, 12) + "-" +
           function + ".kanhe";
}

http::Response attachment(const Bytes& content, const std::string& name) {
    http::Response r;
    r.status = 200;
    r.content_type = "application/cbor";
    r.body = content;
    r.headers.emplace_back("Content-Disposition",
                           "attachment; filename*=UTF-8''" + http::percent_encode(name));
    secure(r);
    return r;
}

} // namespace

std::string Console::ledger_name(const protocol::LedgerState& state,
                                 const protocol::Id& ledger) const {
    if (ledger == state.ledger_id()) {
        return state.organization();
    }
    if (const auto peers = node::load_peers(services_.directory.parent_path())) {
        for (const node::Peer& p : *peers) {
            if (p.ledger_id == ledger) {
                return p.name;
            }
        }
    }
    return {};
}

std::variant<protocol::ExchangeFile, http::Response>
Console::uploaded_file(const Signed& who, const std::string& upload) const {
    std::filesystem::path path;
    {
        const std::lock_guard lock(mutex_);
        const auto it = uploads_.find(upload);
        if (it == uploads_.end() || it->second.user != who.user ||
            it->second.expires <= services_.clock->now()) {
            return error(404, "not_found", "that file is no longer here: open it again");
        }
        path = it->second.path;
    }
    auto file = protocol::decode_exchange_file(client::read_file(path));
    if (!file) {
        return error(422, "invalid_argument",
                     "this is not a proposal or consent file: " + std::string(file.error().detail));
    }
    return std::move(*file);
}

http::Response Console::exchange_read_route(const http::Request& request) const {
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
    std::string upload = body.value("upload", "");
    if (body.contains("opened")) {
        // A file opened on this computer (console open FILE): taken once,
        // as an upload of whoever signed in to read it.
        auto taken = take_opened(signer, body.value("opened", ""));
        if (auto* refused = std::get_if<http::Response>(&taken)) {
            return std::move(*refused);
        }
        upload = std::get<std::string>(taken);
    }
    auto read = uploaded_file(signer, upload);
    if (auto* refused = std::get_if<http::Response>(&read)) {
        return std::move(*refused);
    }
    auto shown = read_exchange(signer, std::get<protocol::ExchangeFile>(read),
                               language_of(body.value("language", "")));
    if (auto* refused = std::get_if<http::Response>(&shown)) {
        return std::move(*refused);
    }
    auto out = std::get<nlohmann::json>(std::move(shown));
    out["upload"] = upload;
    return json(200, out);
}

std::variant<std::string, http::Response> Console::take_opened(const Signed& who,
                                                               const std::string& id) const {
    if (id.size() != 24 || !std::ranges::all_of(id, [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) {
        return error(400, "invalid_argument", "not a file opened here");
    }
    const std::filesystem::path directory = opened_directory(services_.directory);
    std::error_code ec;
    // Files opened but never read are dropped after a day.
    const auto stale = std::filesystem::file_time_type::clock::now() - std::chrono::hours(24);
    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
        if (entry.last_write_time(ec) < stale) {
            std::filesystem::remove(entry.path(), ec);
        }
    }
    const std::filesystem::path path = directory / id;
    if (!std::filesystem::is_regular_file(path, ec) ||
        std::filesystem::file_size(path, ec) > protocol::max_exchange_file) {
        return error(404, "not_found", "that file is no longer here: open it again");
    }
    const Bytes content = client::read_file(path);
    std::filesystem::remove(path, ec);
    return store_upload(who.user, "opened.kanhe", content);
}

std::variant<nlohmann::json, http::Response>
Console::read_exchange(const Signed& signer, const protocol::ExchangeFile& file,
                       const std::string& language) const {
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    nlohmann::json out{{"kind", std::string(protocol::name(file.kind))},
                       {"home", hex_of(file.home)},
                       {"instance", hex_of(file.instance)},
                       {"head", file.head},
                       {"function", file.function},
                       {"arguments", cbor::diagnostic(file.arguments)},
                       {"note", file.note ? nlohmann::json(*file.note) : nlohmann::json()}};
    protocol::Id ours;
    std::string our_name;
    served->read_state([&](const protocol::LedgerState& state) {
        ours = state.ledger_id();
        our_name = state.organization();
        out["home_name"] = ledger_name(state, file.home);
    });
    out["ours"] = hex_of(ours);
    if (file.kind == protocol::ExchangeKind::proposal) {
        std::optional<client::ProposalTerms> terms;
        try {
            terms = client::check_proposal(*services_.provider, file);
        } catch (const std::exception& e) {
            return error(422, "verification_failed", e.what());
        }
        const protocol::EvidenceReport& home = terms->report.instance;
        const protocol::InstanceReport& instance = *home.instance;
        nlohmann::json needs = nlohmann::json::array();
        for (const protocol::Id& l : file.needs) {
            needs.push_back(hex_of(l));
        }
        out["verified"] = true;
        out["home_organization"] = home.organization;
        out["contract"] =
            instance.contract_name ? nlohmann::json(*instance.contract_name) : nlohmann::json();
        out["status"] = instance.status ? nlohmann::json(*instance.status) : nlohmann::json();
        out["needs"] = needs;
        out["asks_us"] = std::ranges::contains(file.needs, ours);
        // What the call does, in the contract's words, and the instance's
        // state: the compiler, in the child, on the deploy the evidence holds.
        if (instance.language == "bo" && instance.source) {
            const bo::BuiltContract built{instance.code,
                                          instance.interface,
                                          instance.compiler,
                                          *instance.source,
                                          instance.contract_name.value_or(""),
                                          file.hash};
            if (const auto boc = bo::encode_built(built)) {
                const auto state =
                    Bytes(instance.state.bytes().begin(), instance.state.bytes().end());
                auto ran = run_compiler(signer,
                                        {"calls", "contract.boc", "--language", language, "--state",
                                         to_hex(state), "--label", hex_of(ours) + "=" + our_name,
                                         "--label", hex_of(file.home) + "=" + home.organization},
                                        {{"contract.boc", std::string(boc->begin(), boc->end())}});
                if (auto* run = std::get_if<CompilerRun>(&ran); run && run->answer.is_object()) {
                    for (const auto& call : run->answer.value("calls", nlohmann::json::array())) {
                        if (call.value("function", "") == file.function) {
                            out["call"] = call;
                        }
                    }
                    out["state"] = run->answer.value("state", nlohmann::json());
                }
            }
        }
        return out;
    }
    // A consent: verified for its own ledger, its terms the file's, for a
    // call on one of this ledger's things at its head now.
    const auto from = protocol::bundle_ledger_id(file.evidence);
    if (!from) {
        return error(422, "verification_failed", "the consent's bundle does not read");
    }
    protocol::VerifyOptions options;
    options.expected_ledger = *from;
    const auto report = ledger::verify_bundle(*services_.provider, file.evidence, options);
    if (!report) {
        return error(422, "verification_failed",
                     "the consent does not verify: " + std::string(report.error().detail));
    }
    if (report->record_type != protocol::contract_consent_type || !report->metadata) {
        return error(422, "verification_failed", "the file carries no contract consent");
    }
    const auto consent = protocol::decode_contract_consent(*report->metadata);
    const auto digest =
        protocol::contract_arguments_digest(*services_.provider, file.hash, file.arguments);
    if (!consent || !digest || consent->ledger != file.home || consent->instance != file.instance ||
        consent->function != file.function || consent->head != file.head ||
        consent->arguments != *digest) {
        return error(422, "verification_failed", "the consent's terms are not the file's");
    }
    out["verified"] = true;
    out["from"] = hex_of(*from);
    out["from_organization"] = report->organization;
    out["until"] = consent->until;
    out["in_person"] = !report->events.empty() && report->events.front().presence.has_value();
    served->read_state([&](const protocol::LedgerState& state) {
        out["from_name"] = ledger_name(state, *from);
        const protocol::InstanceState* i = state.instance(file.instance);
        out["for_us"] = file.home == ours && i != nullptr;
        out["current"] = i != nullptr && i->head == file.head;
        out["lapsed"] = consent->until < services_.clock->now();
    });
    return out;
}

void Console::exchange_proposal_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    if (signer.role == Role::viewer) {
        respond(error(403, "forbidden", "a viewer reads and verifies, and acts on nothing"));
        return;
    }
    const ledger::Ledger* served = ledger();
    const Evidence of_instance = instance_evidence();
    if (served == nullptr || !of_instance) {
        respond(error(503, "unavailable", "the console has no ledger to propose from"));
        return;
    }
    const auto intent =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!intent.is_object()) {
        respond(error(400, "invalid_argument", "the request's body is not a JSON object"));
        return;
    }
    const std::string note = intent.value("note", "");
    if (note.size() > protocol::max_exchange_note) {
        respond(error(400, "invalid_argument", "a note is at most 1000 bytes"));
        return;
    }
    auto built = call_body(signer, intent, "contract.call");
    if (auto* refused = std::get_if<http::Response>(&built)) {
        respond(std::move(*refused));
        return;
    }
    const protocol::ContractCallBody call = std::get<protocol::ContractCallBody>(std::move(built));
    // Run as the person would sign it: it must wait for consents.
    const People people = load_people(services_.directory);
    const User* user = people.find(signer.user);
    const auto actor = user != nullptr ? id_of(user->actor) : std::nullopt;
    nlohmann::json run;
    protocol::ExchangeFile file;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ActorState* a = actor ? state.actor(*actor) : nullptr;
        if (a == nullptr) {
            run = {{"verdict", "refuse"}, {"reason", "this user acts as no one on the ledger yet"}};
            return;
        }
        protocol::Statement s;
        s.body = call;
        s.ledger_id = state.ledger_id();
        s.actor_id = *actor;
        s.issued_at = services_.clock->now();
        run = dry_run(state, s, *a, language_of(intent.value("language", "")));
        file.home = state.ledger_id();
        file.hash = state.hash();
    });
    if (run.value("verdict", "") != "needs") {
        const bool accepted = run.value("verdict", "") == "accept";
        respond(json(422, {{"error",
                            {{"code", accepted ? "no_consent_needed" : "refused"},
                             {"message", accepted ? std::string("the call needs no other party's "
                                                                "consent: make it")
                                                  : run.value("reason", std::string("refused"))}}},
                           {"dry_run", run}}));
        return;
    }
    file.kind = protocol::ExchangeKind::proposal;
    file.instance = *call.instance;
    file.head = *call.head;
    file.function = call.function;
    file.arguments = call.arguments;
    for (const auto& l : run["needs"]) {
        if (const auto id = id_of(l.get<std::string>())) {
            file.needs.push_back(*id);
        }
    }
    if (!note.empty()) {
        file.note = note;
    }
    of_instance(file.instance, [file = std::move(file),
                                respond = std::move(respond)](Result<Bytes> evidence) mutable {
        if (!evidence) {
            respond(error(503, "unavailable", evidence.error().detail));
            return;
        }
        file.evidence = std::move(*evidence);
        const auto encoded = protocol::encode_exchange_file(file);
        if (!encoded) {
            respond(error(500, "internal", "the proposal could not be written"));
            return;
        }
        respond(attachment(*encoded, file_name(file)));
    });
}

void Console::exchange_consent_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    const ledger::Ledger* served = ledger();
    const Evidence source = evidence();
    if (served == nullptr || !source) {
        respond(error(503, "unavailable", "the console has no ledger to answer from"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    const auto record = body.is_object() ? id_of(body.value("record", "")) : std::nullopt;
    if (!record) {
        respond(error(400, "invalid_argument", "name the consent's record by its full id (hex)"));
        return;
    }
    auto read = uploaded_file(signer, body.value("upload", ""));
    if (auto* refused = std::get_if<http::Response>(&read)) {
        respond(std::move(*refused));
        return;
    }
    const protocol::ExchangeFile proposal = std::get<protocol::ExchangeFile>(std::move(read));
    // The record must be this ledger's consent to the proposal's call.
    bool matches = false;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(*record);
        const auto registration = r != nullptr ? this->registration(state, *record) : std::nullopt;
        if (registration && registration->record_type == protocol::contract_consent_type &&
            registration->metadata) {
            const auto consent = protocol::decode_contract_consent(*registration->metadata);
            const auto digest = protocol::contract_arguments_digest(
                *services_.provider, proposal.hash, proposal.arguments);
            matches = consent && digest && consent->ledger == proposal.home &&
                      consent->instance == proposal.instance &&
                      consent->function == proposal.function && consent->head == proposal.head &&
                      consent->arguments == *digest;
        }
    });
    if (!matches) {
        respond(error(409, "conflict", "that record is not this ledger's consent to the proposal"));
        return;
    }
    source(*record, [proposal, respond = std::move(respond)](Result<Bytes> bundle) mutable {
        if (!bundle) {
            respond(error(503, "unavailable", bundle.error().detail));
            return;
        }
        const protocol::ExchangeFile answer = client::consent_file(proposal, std::move(*bundle));
        const auto encoded = protocol::encode_exchange_file(answer);
        if (!encoded) {
            respond(error(500, "internal", "the consent file could not be written"));
            return;
        }
        respond(attachment(*encoded, file_name(answer)));
    });
}

std::variant<std::pair<protocol::RecordRegisterBody, Draft>, http::Response>
Console::consent_draft(const Signed& who, const nlohmann::json& intent) const {
    auto read = uploaded_file(who, intent.value("upload", ""));
    if (auto* refused = std::get_if<http::Response>(&read)) {
        return std::move(*refused);
    }
    const protocol::ExchangeFile& file = std::get<protocol::ExchangeFile>(read);
    std::optional<client::ProposalTerms> terms;
    try {
        terms = client::check_proposal(*services_.provider, file);
    } catch (const client::ActionError& e) {
        return error(422, "verification_failed", e.message);
    } catch (const client::UsageError& e) {
        return error(422, "verification_failed", e.message);
    }
    bool asked = false;
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    served->read_state([&](const protocol::LedgerState& state) {
        asked = std::ranges::contains(file.needs, state.ledger_id());
    });
    if (!asked) {
        return error(409, "conflict", "the proposal does not ask this ledger for its consent");
    }
    const std::uint64_t days = intent.value("days", std::uint64_t{7});
    if (days < 1 || days > 366) {
        return error(400, "invalid_argument", "a consent lapses after 1 to 366 days");
    }
    protocol::ContractConsent consent = terms->consent;
    consent.until = services_.clock->now() + days * 86'400'000;
    auto metadata = protocol::encode_contract_consent(consent);
    if (!metadata) {
        return error(500, "internal", "the consent's terms could not be written");
    }
    const crypto::HashAlg hash = served->hash();
    std::vector<protocol::RecordField> fields{
        {"note", services_.entropy->bytes<16>(),
         cbor::Value::text("consent to " + consent.function + " on instance " +
                           hex_of(consent.instance).substr(0, 12))}};
    const auto commitment = protocol::commit_fields(*services_.provider, hash, fields);
    if (!commitment) {
        return error(500, "internal", "the consent's note could not be committed");
    }
    protocol::RecordRegisterBody body;
    body.record_type = std::string(protocol::contract_consent_type);
    body.field_root = Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end());
    body.field_count = commitment->leaves.size();
    body.metadata = std::move(*metadata);
    Draft draft;
    draft.vault.fields = commitment->fields;
    return std::pair{std::move(body), std::move(draft)};
}

std::variant<Console::Cited, http::Response>
Console::cited_call(const Signed& who, const nlohmann::json& intent) const {
    const auto uploads = intent.find("consents");
    if (uploads == intent.end() || !uploads->is_array() || uploads->empty() ||
        uploads->size() > protocol::max_exchange_needs ||
        !std::ranges::all_of(*uploads, [](const auto& u) { return u.is_string(); })) {
        return error(400, "invalid_argument", "name the consent files' uploads (1 to 16)");
    }
    std::vector<protocol::ExchangeFile> files;
    for (const auto& upload : *uploads) {
        auto read = uploaded_file(who, upload.get<std::string>());
        if (auto* refused = std::get_if<http::Response>(&read)) {
            return std::move(*refused);
        }
        files.push_back(std::get<protocol::ExchangeFile>(std::move(read)));
        const protocol::ExchangeFile& f = files.back();
        const protocol::ExchangeFile& first = files.front();
        if (f.kind != protocol::ExchangeKind::consent) {
            return error(409, "conflict", "this file is a proposal: it is answered by a consent");
        }
        if (f.home != first.home || f.instance != first.instance || f.head != first.head ||
            f.function != first.function || f.arguments != first.arguments) {
            return error(409, "conflict", "the consent files are to different calls");
        }
    }
    const protocol::ExchangeFile& file = files.front();
    Cited out;
    std::string problem;
    protocol::Id home;
    crypto::HashAlg hash = crypto::HashAlg::sha256;
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    served->read_state([&](const protocol::LedgerState& state) {
        home = state.ledger_id();
        hash = state.hash();
        const protocol::InstanceState* i = state.instance(file.instance);
        if (file.home != home || i == nullptr) {
            problem = "the consent is to a call on another ledger's thing";
        } else if (i->head != file.head) {
            problem = "the thing has moved on since the consent: ask again";
        } else if (i->final) {
            problem = "this thing is in a final state: it takes no more calls";
        }
    });
    if (!problem.empty()) {
        return error(409, "conflict", problem);
    }
    out.body.instance = file.instance;
    out.body.head = file.head;
    out.body.function = file.function;
    out.body.arguments = file.arguments;
    std::vector<std::pair<protocol::ContractConsentRef, Bytes>> consents;
    for (const protocol::ExchangeFile& f : files) {
        const auto ledger = protocol::bundle_ledger_id(f.evidence);
        if (!ledger) {
            return error(422, "verification_failed", "a consent's bundle does not read");
        }
        protocol::VerifyOptions options;
        options.expected_ledger = *ledger;
        const auto report = ledger::verify_bundle(*services_.provider, f.evidence, options);
        if (!report || report->events.empty()) {
            return error(422, "verification_failed", "a consent does not verify for its ledger");
        }
        const auto digest = services_.provider->digest(hash, f.evidence);
        if (!digest) {
            return error(500, "internal", "a consent could not be hashed");
        }
        consents.emplace_back(
            protocol::ContractConsentRef{*ledger, report->record, *digest,
                                         protocol::registration_signer(report->events.front())},
            f.evidence);
    }
    std::ranges::sort(consents, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.first.ledger.bytes(), b.first.ledger.bytes());
    });
    for (std::size_t i = 1; i < consents.size(); ++i) {
        if (consents[i].first.ledger == consents[i - 1].first.ledger) {
            return error(409, "conflict", "two consents are from one ledger");
        }
    }
    for (auto& [ref, bundle] : consents) {
        out.body.consents.push_back(ref);
        out.bundles.push_back(std::move(bundle));
    }
    if (const Status checked = node::check_call_consents(*services_.provider, home, hash, out.body,
                                                         out.bundles, services_.clock->now());
        !checked) {
        return error(422, "verification_failed",
                     "a consent does not hold for this call: " +
                         std::string(checked.error().detail));
    }
    return out;
}

void Console::exchange_propose_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    if (signer.role == Role::viewer) {
        respond(error(403, "forbidden", "a viewer reads and verifies, and acts on nothing"));
        return;
    }
    const ledger::Ledger* served = ledger();
    const Propose propose = proposer();
    if (served == nullptr || !propose) {
        respond(error(503, "unavailable", "this console runs no registrar"));
        return;
    }
    const auto intent =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!intent.is_object()) {
        respond(error(400, "invalid_argument", "the request's body is not a JSON object"));
        return;
    }
    const std::uint64_t days = intent.value("days", std::uint64_t{7});
    if (days < 1 || days > 30) {
        respond(error(400, "invalid_argument", "a proposal waits 1 to 30 days"));
        return;
    }
    auto built = call_body(signer, intent, "contract.call");
    if (auto* refused = std::get_if<http::Response>(&built)) {
        respond(std::move(*refused));
        return;
    }
    const protocol::ContractCallBody call = std::get<protocol::ContractCallBody>(std::move(built));
    node::PendingCall proposal;
    proposal.instance = *call.instance;
    proposal.head = *call.head;
    proposal.function = call.function;
    proposal.arguments = call.arguments;
    proposal.until = services_.clock->now() + days * 86'400'000;
    const auto encoded = node::encode_call_proposal(proposal);
    if (!encoded) {
        respond(error(400, "invalid_argument", encoded.error().detail));
        return;
    }
    // The registrar runs the call without consents: it holds it only if the
    // contract waits for some (otherwise it says why), and answers whose.
    propose(*encoded, [respond = std::move(respond)](http::Response held) {
        secure(held);
        respond(std::move(held));
    });
}

nlohmann::json Console::held_on(const protocol::Id& instance) const {
    nlohmann::json out = nlohmann::json::array();
    const Held list = held();
    if (!list) {
        return out;
    }
    const http::Response answer = list();
    if (answer.status != 200) {
        return out;
    }
    const auto held = nlohmann::json::parse(answer.body.begin(), answer.body.end(), nullptr, false);
    for (const auto& call : held.value("calls", nlohmann::json::array())) {
        if (call.value("instance", "") != hex_of(instance)) {
            continue;
        }
        const auto bytes = from_hex(call.value("arguments", ""));
        const auto arguments =
            bytes ? cbor::decode(*bytes) : Result<cbor::Value>(std::unexpected(bytes.error()));
        out.push_back({{"call", call.value("call", "")},
                       {"function", call.value("function", "")},
                       {"head", call.value("head", std::uint64_t{0})},
                       {"arguments", arguments ? cbor::diagnostic(*arguments) : std::string()},
                       {"missing", call.value("missing", nlohmann::json::array())},
                       {"consented", call.value("consented", nlohmann::json::array())},
                       {"until", call.value("until", std::uint64_t{0})}});
    }
    return out;
}

} // namespace kanhe::console
