// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Self-service forms: their sheets and file, and the applicant's routes.
//
//   GET  /console/api/apply/FORM     the form: its title, the providers to
//                                    sign in with, its fields (anyone)
//   POST /console/api/apply/FORM     {fields, values}: an applicant submits;
//                                    the intake actor registers the document
//                                    and creates the thing, its reference the
//                                    applicant's pseudonym
//   GET  /console/api/mine           the applicant's own things: state,
//                                    history, the steps they may take
//   POST /console/api/mine/THING     {function, values}: one of those steps

#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>

#include <cexchain/app/records.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/forms.hpp>
#include <cexchain/console/identity.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/search/index.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view forms_file = "forms.json";

bool plain_name(std::string_view name) {
    return !name.empty() && name.size() <= 32 && std::ranges::all_of(name, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    });
}

bool function_name(std::string_view name) {
    return !name.empty() && name.size() <= 64;
}

std::optional<protocol::Id> id_of(std::string_view hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::vector<std::string> strings_of(const nlohmann::json& sheet, std::string_view key) {
    std::vector<std::string> out;
    const auto it = sheet.find(key);
    if (it == sheet.end()) {
        return out;
    }
    if (!it->is_array() || !std::ranges::all_of(*it, [](const auto& v) { return v.is_string(); })) {
        throw std::invalid_argument(std::string(key) + " is a list of names");
    }
    for (const auto& v : *it) {
        out.push_back(v.get<std::string>());
    }
    return out;
}

} // namespace

SelfServiceForm parse_form(const nlohmann::json& sheet) {
    if (!sheet.is_object() || sheet.value("form", 0) != 1) {
        throw std::invalid_argument("a form sheet is {\"form\": 1, \"name\", \"title\", "
                                    "\"contract\", \"create\", ...}");
    }
    for (const auto& [key, value] : sheet.items()) {
        static const std::set<std::string> known{"form",      "name",    "title", "contract",
                                                 "create",    "steps",   "kind",  "record_field",
                                                 "providers", "per_hour"};
        if (!known.contains(key)) {
            throw std::invalid_argument("a form sheet has no " + key);
        }
    }
    SelfServiceForm f;
    f.name = sheet.value("name", "");
    if (!plain_name(f.name)) {
        throw std::invalid_argument("a form's name is 1 to 32 of a-z, 0-9, and -");
    }
    f.title = sheet.value("title", "");
    if (f.title.empty() || f.title.size() > 128) {
        throw std::invalid_argument("a form's title is 1 to 128 bytes");
    }
    const auto contract = id_of(sheet.value("contract", ""));
    if (!contract || sheet.value("contract", "").size() != 64) {
        throw std::invalid_argument("a form's contract is a deployed contract's full id (hex)");
    }
    f.contract = *contract;
    f.create = sheet.value("create", "");
    if (!function_name(f.create)) {
        throw std::invalid_argument("a form names its contract's creating call: \"create\"");
    }
    f.steps = strings_of(sheet, "steps");
    if (f.steps.size() > 32 || !std::ranges::all_of(f.steps, function_name)) {
        throw std::invalid_argument("a form has at most 32 steps, each a call's name");
    }
    if (sheet.contains("kind")) {
        if (!sheet["kind"].is_string() || sheet["kind"].get<std::string>().empty()) {
            throw std::invalid_argument("a form's kind is a document kind's record type");
        }
        f.kind = sheet["kind"].get<std::string>();
        f.record_field = sheet.value("record_field", "");
        if (!function_name(*f.record_field)) {
            throw std::invalid_argument("a form with a kind names the field that gets the "
                                        "document's id: \"record_field\"");
        }
    } else if (sheet.contains("record_field")) {
        throw std::invalid_argument("record_field goes with a kind");
    }
    f.providers = strings_of(sheet, "providers");
    if (!std::ranges::all_of(f.providers, plain_name)) {
        throw std::invalid_argument("providers are identity providers' names");
    }
    const auto per_hour = sheet.value("per_hour", 20);
    if (per_hour < 1 || per_hour > 1000) {
        throw std::invalid_argument("per_hour is 1 to 1,000");
    }
    f.per_hour = static_cast<std::uint32_t>(per_hour);
    return f;
}

nlohmann::json form_json(const SelfServiceForm& f) {
    nlohmann::json out{{"form", 1},
                       {"name", f.name},
                       {"title", f.title},
                       {"contract", to_hex(f.contract.bytes())},
                       {"create", f.create},
                       {"steps", f.steps},
                       {"providers", f.providers},
                       {"per_hour", f.per_hour}};
    if (f.kind) {
        out["kind"] = *f.kind;
        out["record_field"] = *f.record_field;
    }
    return out;
}

std::vector<SelfServiceForm> load_forms(const std::filesystem::path& directory) {
    const std::filesystem::path file = directory / forms_file;
    if (!std::filesystem::exists(file)) {
        return {};
    }
    const Bytes bytes = app::read_file(file);
    const auto doc = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!doc.is_object() || !doc.contains("forms") || !doc["forms"].is_array()) {
        throw std::runtime_error("the console's forms file is damaged");
    }
    std::vector<SelfServiceForm> out;
    try {
        for (const auto& f : doc["forms"]) {
            out.push_back(parse_form(f));
        }
    } catch (const std::invalid_argument&) {
        throw std::runtime_error("the console's forms file is damaged");
    }
    return out;
}

void save_forms(const std::filesystem::path& directory, const std::vector<SelfServiceForm>& forms) {
    nlohmann::json list = nlohmann::json::array();
    for (const SelfServiceForm& f : forms) {
        list.push_back(form_json(f));
    }
    app::write_file(directory / forms_file,
                    as_bytes(nlohmann::json{{"forms", list}}.dump(2) + "\n"), true);
}

protocol::Scope intake_scope(const std::vector<SelfServiceForm>& forms, protocol::Timestamp until) {
    protocol::Scope s;
    std::set<std::string> kinds;
    std::set<std::string> functions;
    std::set<protocol::IdKey> contracts;
    for (const SelfServiceForm& f : forms) {
        if (f.kind) {
            kinds.insert(*f.kind);
        }
        functions.insert(f.create);
        functions.insert(f.steps.begin(), f.steps.end());
        contracts.insert(protocol::key_of(f.contract));
    }
    if (!kinds.empty()) {
        s.statement_types.push_back(protocol::StatementType::record_register);
        s.record_types = std::vector<std::string>(kinds.begin(), kinds.end());
    }
    s.statement_types.push_back(protocol::StatementType::contract_call);
    s.not_after = until;
    s.contracts = std::vector<protocol::Id>{};
    for (const protocol::IdKey& k : contracts) {
        s.contracts->push_back(protocol::CompactId(k).id());
    }
    s.functions = std::vector<std::string>(functions.begin(), functions.end());
    return s;
}

// ---------------------------------------------------------------------------
// The applicant's routes

struct FormsState {
    std::mutex mutex;
    /// Contracts' calls (bo calls), by contract.
    std::map<protocol::IdKey, nlohmann::json> calls;
    /// Submissions by pseudonym, the last hour's.
    std::map<std::string, std::deque<protocol::Timestamp>> submitted;
};

std::shared_ptr<FormsState> make_forms_state() {
    return std::make_shared<FormsState>();
}

namespace {

std::optional<std::string> path_part(std::string_view path, std::string_view prefix) {
    if (!path.starts_with(prefix) || path.size() == prefix.size()) {
        return std::nullopt;
    }
    const std::string_view rest = path.substr(prefix.size());
    if (rest.find('/') != std::string_view::npos) {
        return std::nullopt;
    }
    return std::string(rest);
}

http::Response sign_in_first() {
    http::Response refused = error(401, "unauthorized", "sign in with your account first");
    refused.headers.emplace_back("WWW-Authenticate", "Bearer");
    return refused;
}

} // namespace

/// An applicant as the routes that run the compiler or build drafts see
/// them: a session of their own, named by their pseudonym.
Console::Signed Console::as_applicant(const Applicant& a) const {
    const protocol::Timestamp now = services_.clock->now();
    return Signed{"", Session{"a-" + a.pseudonym, "applicant " + a.pseudonym, now, now},
                  "applicant:" + a.pseudonym, Role::member};
}

std::variant<Bytes, http::Response> Console::intake_signed(protocol::Body body) const {
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger");
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return error(423, "locked", "the console is locked: its staff unlock it first");
    }
    std::optional<crypto::openssl::KeyPair> opened;
    try {
        opened.emplace(services_.keys->open(intake_key_name));
    } catch (const std::exception&) {
        return error(409, "conflict",
                     "this console has no intake actor yet (console intake grant)");
    }
    const crypto::openssl::KeyPair& key = *opened;
    const protocol::Timestamp now = services_.clock->now();
    std::variant<Bytes, http::Response> out = error(500, "internal", "nothing signed");
    served->read_state([&](const protocol::LedgerState& state) {
        if (const auto* call = std::get_if<protocol::ContractCallBody>(&body)) {
            auto made = node::sign_contract_call(*services_.provider, state, key, *call, now,
                                                 *services_.entropy);
            out = made ? std::variant<Bytes, http::Response>(made->encoded)
                       : error(409, "conflict",
                               "the intake actor may not do this: the form's rules changed? "
                               "(console intake grant)");
            return;
        }
        const auto kid = protocol::key_id(*services_.provider, state.hash(), key.public_key());
        const protocol::ActorState* actor = kid ? state.actor_by_kid(*kid) : nullptr;
        const auto& reg = std::get<protocol::RecordRegisterBody>(body);
        const auto delegation =
            actor == nullptr ? std::nullopt
                             : node::choose_delegation(state, actor->id,
                                                       protocol::StatementType::record_register,
                                                       reg.record_type, now);
        if (!delegation) {
            out = error(409, "conflict",
                        "the intake actor may not register this kind (console intake grant)");
            return;
        }
        protocol::Statement s;
        s.ledger_id = state.ledger_id();
        s.actor_id = protocol::Id(actor->id);
        s.delegation_id = *delegation;
        s.issued_at = now;
        s.nonce = services_.entropy->bytes<16>();
        s.body = body;
        auto made = protocol::sign_statement(key, *services_.provider, state.hash(), s);
        out = made ? std::variant<Bytes, http::Response>(made->encoded)
                   : error(500, "internal", "signing failed");
    });
    return out;
}

std::variant<nlohmann::json, http::Response>
Console::cached_calls(const Signed& who, const protocol::Id& contract) const {
    {
        const std::lock_guard lock(forms_->mutex);
        if (const auto it = forms_->calls.find(protocol::key_of(contract));
            it != forms_->calls.end()) {
            return it->second;
        }
    }
    auto calls = contract_calls(who, contract, "en", {});
    if (const auto* answer = std::get_if<nlohmann::json>(&calls)) {
        const std::lock_guard lock(forms_->mutex);
        forms_->calls.emplace(protocol::key_of(contract), *answer);
    }
    return calls;
}

http::Response Console::apply_get_route(const http::Request& request) const {
    const auto name = path_part(request.path, "/console/api/apply/");
    if (!name) {
        return error(404, "not_found", "no such form");
    }
    std::vector<SelfServiceForm> forms;
    std::vector<IdentityProvider> providers;
    try {
        forms = load_forms(services_.directory);
        providers = load_providers(services_.directory);
    } catch (const std::exception&) {
        return error(503, "unavailable", "the console's forms are damaged");
    }
    const auto form = std::ranges::find(forms, *name, &SelfServiceForm::name);
    if (form == forms.end()) {
        return error(404, "not_found", "no such form");
    }
    nlohmann::json signin = nlohmann::json::array();
    for (const IdentityProvider& p : providers) {
        if (form->providers.empty() || std::ranges::contains(form->providers, p.name)) {
            signin.push_back({{"name", p.name}, {"label", p.label}});
        }
    }
    // The fields: the kind's, then the creating call's own inputs (not the
    // one that gets the document's id).
    nlohmann::json fields = nlohmann::json::array();
    if (form->kind) {
        for (const Kind& k : load_kinds(services_.directory)) {
            if (k.type != *form->kind) {
                continue;
            }
            for (const KindField& f : k.fields) {
                fields.push_back({{"name", f.name},
                                  {"label", f.label.empty() ? f.name : f.label},
                                  {"type", name_of(f.type)},
                                  {"required", f.required},
                                  {"private", f.is_private},
                                  {"part", "document"}});
            }
        }
    }
    const auto who = applicant_of(request);
    nlohmann::json inputs = nlohmann::json::array();
    const std::string language =
        request.query.contains("language") ? request.query.at("language") : std::string("en");
    const Signed reader =
        who ? as_applicant(*who)
            : Signed{"", Session{"apply-" + *name, "apply", 0, 0}, "apply", Role::viewer};
    auto calls = language == "en" ? cached_calls(reader, form->contract)
                                  : contract_calls(reader, form->contract, language, {});
    if (auto* refused = std::get_if<http::Response>(&calls)) {
        return std::move(*refused);
    }
    for (const auto& c : std::get<nlohmann::json>(calls)["calls"]) {
        if (c.value("function", "") != form->create) {
            continue;
        }
        for (const auto& i : c["inputs"]) {
            if (form->record_field && i.value("name", "") == *form->record_field) {
                continue;
            }
            if (i.value("place", "") == "role") {
                continue;
            }
            inputs.push_back(i);
        }
    }
    return json(200, {{"name", form->name},
                      {"title", form->title},
                      {"providers", signin},
                      {"fields", fields},
                      {"inputs", inputs},
                      {"applicant", who ? applicant_json(*who) : nlohmann::json()}});
}

void Console::apply_post_route(const http::Request& request, Respond respond) const {
    const auto who = applicant_of(request);
    if (!who) {
        respond(sign_in_first());
        return;
    }
    const auto name = path_part(request.path, "/console/api/apply/");
    std::vector<SelfServiceForm> forms;
    try {
        forms = load_forms(services_.directory);
    } catch (const std::exception&) {
        respond(error(503, "unavailable", "the console's forms are damaged"));
        return;
    }
    const auto found = name ? std::ranges::find(forms, *name, &SelfServiceForm::name) : forms.end();
    if (found == forms.end()) {
        respond(error(404, "not_found", "no such form"));
        return;
    }
    const SelfServiceForm form = *found;
    if (!form.providers.empty() && !std::ranges::contains(form.providers, who->provider)) {
        respond(error(403, "forbidden", "this form takes another account: sign in with it"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        respond(error(400, "invalid_argument", "a submission is {\"fields\", \"values\"}"));
        return;
    }
    // At most per_hour submissions an hour, each applicant.
    const protocol::Timestamp now = services_.clock->now();
    {
        const std::lock_guard lock(forms_->mutex);
        auto& times = forms_->submitted[who->pseudonym];
        while (!times.empty() && times.front() + 3'600'000 <= now) {
            times.pop_front();
        }
        if (times.size() >= form.per_hour) {
            respond(error(429, "limit_exceeded", "too many submissions this hour: try later"));
            return;
        }
        times.push_back(now);
    }
    const Signed applicant = as_applicant(*who);
    nlohmann::json values = body.value("values", nlohmann::json::object());
    if (!values.is_object()) {
        respond(error(400, "invalid_argument", "values are {name: value}"));
        return;
    }
    // Every role of the creating call is the organization's own ledger: a
    // form is the organization's, and an applicant is no party of it.
    auto calls = cached_calls(applicant, form.contract);
    if (auto* refused = std::get_if<http::Response>(&calls)) {
        respond(std::move(*refused));
        return;
    }
    const ledger::Ledger* home = ledger();
    if (home == nullptr) {
        respond(error(503, "unavailable", "the console has no ledger"));
        return;
    }
    for (const auto& c : std::get<nlohmann::json>(calls)["calls"]) {
        if (c.value("function", "") != form.create) {
            continue;
        }
        for (const auto& i : c["inputs"]) {
            if (i.value("place", "") == "role") {
                values[i.value("name", "")] = to_hex(home->id().bytes());
            }
        }
    }
    // Then the thing, its reference the applicant's pseudonym, the
    // document's id (if any) in its field.
    auto create = [this, form, values, applicant, pseudonym = who->pseudonym,
                   respond](std::optional<protocol::Id> record) mutable {
        nlohmann::json v = values.is_object() ? values : nlohmann::json::object();
        if (record && form.record_field) {
            v[*form.record_field] = to_hex(record->bytes());
        }
        const nlohmann::json intent{{"contract", to_hex(form.contract.bytes())},
                                    {"function", form.create},
                                    {"values", v},
                                    {"reference", pseudonym}};
        auto call = call_body(applicant, intent, "contract.create");
        if (auto* refused = std::get_if<http::Response>(&call)) {
            respond(std::move(*refused));
            return;
        }
        auto made = intake_signed(std::get<protocol::ContractCallBody>(call));
        if (auto* refused = std::get_if<http::Response>(&made)) {
            respond(std::move(*refused));
            return;
        }
        submitter()(std::get<Bytes>(std::move(made)), false,
                    [respond, record](http::Response registered) {
                        if (registered.status / 100 == 2) {
                            auto answer = nlohmann::json::parse(
                                registered.body.begin(), registered.body.end(), nullptr, false);
                            nlohmann::json out{{"thing", answer.value("statement_id", "")}};
                            if (record) {
                                out["document"] = to_hex(record->bytes());
                            }
                            respond(json(201, out));
                            return;
                        }
                        respond(std::move(registered));
                    });
    };
    if (!form.kind) {
        create(std::nullopt);
        return;
    }
    // First the document, its private fields sealed to the vault key.
    auto draft = register_draft(
        {{"kind", *form.kind}, {"fields", body.value("fields", nlohmann::json::object())}},
        applicant.user);
    if (auto* problem = std::get_if<std::string>(&draft)) {
        respond(error(422, "invalid_argument", *problem));
        return;
    }
    auto [registration, prepared] = std::get<std::pair<protocol::RecordRegisterBody, Draft>>(draft);
    cbor::Map metadata;
    if (registration.metadata && registration.metadata->as_map() != nullptr) {
        metadata = *registration.metadata->as_map();
    }
    metadata.push_back({cbor::Value::text("applicant"), cbor::Value::text(who->pseudonym)});
    registration.metadata = cbor::Value::map(std::move(metadata));
    const ledger::Ledger* served = ledger();
    const std::filesystem::path pub = services_.directory.parent_path() / "vault" / "vault.pub";
    const auto vault_key = std::filesystem::exists(pub)
                               ? app::decode_vault_public_key(app::read_file(pub))
                               : std::nullopt;
    if (!vault_key || served == nullptr) {
        respond(error(409, "conflict", "this ledger has no vault key"));
        return;
    }
    auto signed_registration = intake_signed(registration);
    if (auto* refused = std::get_if<http::Response>(&signed_registration)) {
        respond(std::move(*refused));
        return;
    }
    const Bytes statement = std::get<Bytes>(std::move(signed_registration));
    const auto parsed = protocol::parse_statement(*services_.provider, statement, served->hash());
    if (!parsed) {
        respond(error(500, "internal", "the registration does not read back"));
        return;
    }
    const protocol::Id record = parsed->id;
    cbor::Map submission{
        {cbor::Value::integer(1), cbor::Value::bytes(statement)},
        {cbor::Value::integer(2),
         cbor::Value::bytes(app::seal_vault(served->id(), record, prepared.vault, *vault_key))}};
    auto encoded = cbor::encode(cbor::Value::map(std::move(submission)));
    if (!encoded) {
        respond(error(500, "internal", "the submission could not be encoded"));
        return;
    }
    submitter()(std::move(*encoded), true,
                [create = std::move(create), record, respond](http::Response registered) mutable {
                    if (registered.status / 100 != 2) {
                        respond(std::move(registered));
                        return;
                    }
                    create(record);
                });
}

http::Response Console::mine_route(const http::Request& request) const {
    const auto who = applicant_of(request);
    if (!who) {
        return sign_in_first();
    }
    const ledger::Ledger* served = ledger();
    search::Index* index = search_index();
    if (served == nullptr || index == nullptr) {
        return error(503, "unavailable", "this console's node keeps no search index");
    }
    std::vector<SelfServiceForm> forms;
    try {
        forms = load_forms(services_.directory);
    } catch (const std::exception&) {
        return error(503, "unavailable", "the console's forms are damaged");
    }
    if (index->as_of() < served->size()) {
        static_cast<void>(index->update(std::chrono::seconds(2)));
    }
    search::InstanceFilter filter;
    filter.reference = who->pseudonym;
    const auto page = index->instances(filter, {.limit = 200});
    if (!page) {
        return error(503, "unavailable", "the search index cannot be read");
    }
    nlohmann::json items = nlohmann::json::array();
    for (const search::InstanceRow& row : page->rows) {
        const auto form = std::ranges::find(forms, row.contract, &SelfServiceForm::contract);
        if (form == forms.end()) {
            continue;
        }
        // Its history: each call's function and time, never who by name.
        nlohmann::json history = nlohmann::json::array();
        std::vector<std::uint64_t> calls;
        served->read_state([&](const protocol::LedgerState& state) {
            if (const protocol::InstanceState* i = state.instance(row.id)) {
                calls = i->history.to_vector();
            }
        });
        for (const std::uint64_t at : calls) {
            if (history.size() >= 64) {
                break;
            }
            const auto bytes = served->entry(at);
            const auto entry = bytes ? protocol::decode_log_entry(*bytes)
                                     : Result<protocol::LogEntry>(std::unexpected(bytes.error()));
            if (!entry || entry->is_state_commitment()) {
                continue;
            }
            const auto s =
                protocol::parse_statement(*services_.provider, entry->statement, served->hash());
            const auto* call =
                s ? std::get_if<protocol::ContractCallBody>(&s->statement.body) : nullptr;
            if (call != nullptr) {
                history.push_back({{"function", call->function}, {"at", entry->registered_at}});
            }
        }
        nlohmann::json fields = nlohmann::json::object();
        for (const auto& [k, v] : row.fields) {
            fields[k] = v;
        }
        items.push_back({{"id", to_hex(row.id.bytes())},
                         {"form", form->name},
                         {"title", form->title},
                         {"state", row.status ? nlohmann::json(*row.status) : nlohmann::json()},
                         {"final", row.final},
                         {"fields", fields},
                         {"history", history},
                         {"steps", row.final ? std::vector<std::string>{} : form->steps}});
    }
    return json(200, {{"applicant", applicant_json(*who)}, {"items", items}});
}

void Console::mine_post_route(const http::Request& request, Respond respond) const {
    const auto who = applicant_of(request);
    if (!who) {
        respond(sign_in_first());
        return;
    }
    const auto thing = path_part(request.path, "/console/api/mine/");
    const auto id = thing && thing->size() == 64 ? id_of(*thing) : std::nullopt;
    const ledger::Ledger* served = ledger();
    if (!id || served == nullptr) {
        respond(error(404, "not_found", "no such thing of yours"));
        return;
    }
    // Theirs only: the call that created it names their pseudonym.
    std::optional<std::uint64_t> created;
    std::optional<protocol::Id> contract;
    served->read_state([&](const protocol::LedgerState& state) {
        if (const protocol::InstanceState* i = state.instance(*id)) {
            created = i->created_by;
            contract = protocol::Id(i->contract);
        }
    });
    std::optional<std::string> reference;
    if (created) {
        const auto bytes = served->entry(*created);
        const auto entry = bytes ? protocol::decode_log_entry(*bytes)
                                 : Result<protocol::LogEntry>(std::unexpected(bytes.error()));
        const auto s =
            entry ? protocol::parse_statement(*services_.provider, entry->statement, served->hash())
                  : Result<protocol::SignedStatement>(std::unexpected(entry.error()));
        if (const auto* call =
                s ? std::get_if<protocol::ContractCallBody>(&s->statement.body) : nullptr) {
            reference = call->reference;
        }
    }
    if (reference != who->pseudonym) {
        respond(error(404, "not_found", "no such thing of yours"));
        return;
    }
    std::vector<SelfServiceForm> forms;
    try {
        forms = load_forms(services_.directory);
    } catch (const std::exception&) {
        respond(error(503, "unavailable", "the console's forms are damaged"));
        return;
    }
    const auto form = std::ranges::find(forms, *contract, &SelfServiceForm::contract);
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    const std::string function = body.is_object() ? body.value("function", "") : "";
    if (form == forms.end() || !std::ranges::contains(form->steps, function)) {
        respond(error(403, "forbidden", "that step is not yours to take here"));
        return;
    }
    const nlohmann::json intent{{"instance", *thing},
                                {"function", function},
                                {"values", body.value("values", nlohmann::json::object())}};
    auto call = call_body(as_applicant(*who), intent, "contract.call");
    if (auto* refused = std::get_if<http::Response>(&call)) {
        respond(std::move(*refused));
        return;
    }
    auto made = intake_signed(std::get<protocol::ContractCallBody>(call));
    if (auto* refused = std::get_if<http::Response>(&made)) {
        respond(std::move(*refused));
        return;
    }
    submitter()(std::get<Bytes>(std::move(made)), false,
                [respond](http::Response registered) { respond(std::move(registered)); });
}

} // namespace cexchain::console
