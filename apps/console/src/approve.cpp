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

#include <cexchain/client/access.hpp>
#include <cexchain/client/records.hpp>
#include <cexchain/client/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/people.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/claims.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/peers.hpp>
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
        out["supersedes"] =
            g->supersedes ? nlohmann::json(to_hex(g->supersedes->bytes())) : nlohmann::json();
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
    } else if (const auto* reg = std::get_if<protocol::ActorRegisterBody>(&s.body)) {
        out["kind"] = static_cast<int>(reg->kind);
        out["display_name"] = reg->display_name;
        out["key"] = to_hex(reg->key.bytes);
        out["responsible"] =
            reg->responsible ? nlohmann::json(to_hex(reg->responsible->bytes())) : nlohmann::json();
        if (reg->responsible) {
            if (const auto* person = state.actor(*reg->responsible)) {
                out["responsible_name"] = person->display_name;
            }
        }
        out["model"] =
            reg->agent && reg->agent->model ? nlohmann::json(*reg->agent->model) : nlohmann::json();
    } else if (const auto* p = std::get_if<protocol::ActorSetPresenceBody>(&s.body)) {
        out["subject"] = to_hex(p->actor.bytes());
        if (const auto* subject = state.actor(p->actor)) {
            out["subject_name"] = subject->display_name;
        }
        nlohmann::json credentials = nlohmann::json::array();
        for (const protocol::PresenceCredential& c : p->credentials) {
            credentials.push_back(
                {{"rp_id", c.rp_id},
                 {"credential_id", to_base64url(c.credential_id)},
                 {"label", c.label ? nlohmann::json(*c.label) : nlohmann::json()}});
        }
        out["credentials"] = credentials;
    } else if (const auto* grant = std::get_if<protocol::DelegationGrantBody>(&s.body)) {
        out["grantee"] = to_hex(grant->grantee.bytes());
        if (const auto* grantee = state.actor(grant->grantee)) {
            out["grantee_name"] = grantee->display_name;
        }
        out["scope"] = scope_json(grant->scope);
        out["may"] = permissions_json(permissions_of(grant->scope));
    } else if (const auto* withdrawn = std::get_if<protocol::DelegationRevokeBody>(&s.body)) {
        out["delegation"] = to_hex(withdrawn->delegation.bytes());
        out["reason"] = withdrawn->reason ? nlohmann::json(*withdrawn->reason) : nlohmann::json();
    } else if (const auto* c = std::get_if<protocol::ContractCallBody>(&s.body)) {
        out["function"] = c->function;
        out["contract"] =
            c->contract ? nlohmann::json(to_hex(c->contract->bytes())) : nlohmann::json();
        out["instance"] =
            c->instance ? nlohmann::json(to_hex(c->instance->bytes())) : nlohmann::json();
        out["head"] = c->head ? nlohmann::json(*c->head) : nlohmann::json();
        out["arguments"] = cbor::diagnostic(c->arguments);
        if (c->answer) {
            out["request"] = to_hex(c->answer->request.bytes());
            out["status"] = static_cast<int>(c->answer->status);
        }
        std::optional<protocol::Id> contract = c->contract;
        if (c->instance) {
            if (const auto* i = state.instance(*c->instance)) {
                contract = protocol::Id(i->contract);
            }
        }
        if (const auto* deployed = contract ? state.contract(*contract) : nullptr;
            deployed != nullptr && deployed->name) {
            out["name"] = *deployed->name;
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
    if ((action == "contract.deploy" || action == "contract.retire") &&
        signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin deploys or retires rules");
    }
    if ((action.starts_with("person.") || action.starts_with("machine.") ||
         action == "delegation.revoke") &&
        signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin approves people and machines");
    }
    const bool calling =
        action == "contract.create" || action == "contract.call" || action == "request.answer";
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
    std::vector<Bytes> bundles;
    std::shared_ptr<const crypto::openssl::KeyPair> person_key;
    std::string person;
    std::string activity;
    struct {
        bool hand_out = false;
        bool agent = false;
        std::optional<std::string> model;
        std::optional<std::string> model_version;
        bool as_organization = false;
    } machine;
    std::variant<protocol::Body, std::string> body = std::string();
    if (action == "contract.deploy") {
        // Built by the compiler in a child process, as the editor checked it.
        auto built = deploy_body(signer, field_text(intent, "source"));
        if (auto* refused = std::get_if<http::Response>(&built)) {
            return std::move(*refused);
        }
        body = protocol::Body{std::get<protocol::ContractDeployBody>(std::move(built))};
    } else if (action == "contract.call" && intent.contains("consents")) {
        // A call the consent files answer: its terms and their bundles.
        auto cited = cited_call(signer, intent);
        if (auto* refused = std::get_if<http::Response>(&cited)) {
            return std::move(*refused);
        }
        Cited c = std::get<Cited>(std::move(cited));
        body = protocol::Body{std::move(c.body)};
        bundles = std::move(c.bundles);
    } else if (calling) {
        // Its arguments built by the compiler in a child process, from what
        // the person filled in; the contract runs below, before the tap.
        auto built = call_body(signer, intent, action);
        if (auto* refused = std::get_if<http::Response>(&built)) {
            return std::move(*refused);
        }
        body = protocol::Body{std::get<protocol::ContractCallBody>(std::move(built))};
    } else if (action == "contract.consent") {
        // A consent on this ledger to a proposal's call, drafted from the file.
        auto drafted = consent_draft(signer, intent);
        if (auto* refused = std::get_if<http::Response>(&drafted)) {
            return std::move(*refused);
        }
        auto& [registration, d] = std::get<0>(drafted);
        body = protocol::Body{std::move(registration)};
        draft = std::move(d);
    } else if (action.starts_with("person.") || action.starts_with("machine.") ||
               action == "delegation.revoke") {
        // A step of approving a person or adding a machine, or revoking
        // what someone may do.
        auto step = action.starts_with("machine.") ? machine_step(signer, intent)
                                                   : person_step(signer, intent);
        if (auto* refused = std::get_if<http::Response>(&step)) {
            return std::move(*refused);
        }
        PersonStep& p = std::get<PersonStep>(step);
        body = std::move(p.body);
        person_key = std::move(p.new_key);
        person = std::move(p.person);
        activity = std::move(p.activity);
        machine = {p.hand_out, p.agent, std::move(p.model), std::move(p.model_version),
                   p.as_organization};
    } else if (action.starts_with("access.") && action != "access.answer") {
        // A request to a party, a grant of a request received, or a receipt
        // for a delivery: a record of this ledger's, its note private.
        auto drafted = access_draft(signer, intent);
        if (auto* refused = std::get_if<http::Response>(&drafted)) {
            return std::move(*refused);
        }
        auto& [registration, d] = std::get<0>(drafted);
        body = protocol::Body{std::move(registration)};
        draft = std::move(d);
    } else if (action == "claim.issue" || action == "access.answer") {
        auto drafted = claim_draft(signer, intent);
        if (auto* refused = std::get_if<http::Response>(&drafted)) {
            return std::move(*refused);
        }
        auto& [registration, d] = std::get<0>(drafted);
        body = protocol::Body{std::move(registration)};
        draft = std::move(d);
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
    // A call the contract would not take now: what its dry run decided.
    nlohmann::json declined;
    const std::string language = field_text(intent, "language");
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
        } else if (const auto* call = std::get_if<protocol::ContractCallBody>(&s.body)) {
            if (call->instance) {
                const protocol::InstanceState* i = state.instance(*call->instance);
                if (i == nullptr || !call->head || i->head != *call->head) {
                    problem = "the thing changed meanwhile: look at it again, then try again";
                    return;
                }
                contract = protocol::Id(i->contract);
            } else {
                contract = call->contract;
            }
        }
        const bool on_records = std::holds_alternative<protocol::RecordEndorseBody>(s.body) ||
                                std::holds_alternative<protocol::RecordRevokeBody>(s.body);
        if (on_records && !record_type) {
            problem = "no such record on this ledger";
            return;
        }
        s.ledger_id = state.ledger_id();
        s.issued_at = services_.clock->now();
        s.nonce = services_.entropy->bytes<16>();
        if (machine.as_organization) {
            // The organization's own statement, signed with its root key:
            // what it grants a machine needs no presence, which a person's
            // delegation could not grant. The owner's passkey approves it
            // here; the ledger records the organization.
            for (const auto& [key, candidate] : state.actors()) {
                if (candidate.is_organization() && !candidate.revoked) {
                    s.actor_id = protocol::Id(candidate.id);
                }
            }
            s.delegation_id.reset();
        } else {
            s.actor_id = *actor;
            s.delegation_id = node::choose_delegation(state, *actor, protocol::type_of(s.body),
                                                      record_type, s.issued_at, contract);
            if (!s.delegation_id) {
                problem = "no valid delegation lets " + a->display_name + " do this";
                return;
            }
        }
        const auto kid = protocol::key_id(*services_.provider, hash,
                                          machine.as_organization ? state.root_key() : a->key);
        const auto challenge =
            kid ? protocol::presence_challenge(*services_.provider, hash, s, *kid)
                : Result<Bytes>(std::unexpected(kid.error()));
        if (!kid || !challenge) {
            problem = "the statement could not be prepared: " +
                      std::string(!kid ? kid.error().detail : challenge.error().detail);
            return;
        }
        prepared.kid = *kid;
        prepared.challenge = *challenge;
        summary = describe(s, state);
        if (calling) {
            // Run as the ledger will run it, with the person's presence: the
            // page shows what it decides, and a call it would not take is
            // not prepared.
            summary["dry_run"] = dry_run(state, s, *a, language);
            if (summary["dry_run"].value("verdict", "") != "accept") {
                declined = summary["dry_run"];
                return;
            }
        }
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
    if (!declined.is_null()) {
        const bool waits = declined.value("verdict", "") == "needs";
        return json(waits ? 409 : 422,
                    {{"error",
                      {{"code", waits ? "consent_needed" : "refused"},
                       {"message", declined.value("reason", std::string("the call is refused"))}}},
                     {"dry_run", declined}});
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
        if (g.record_type == protocol::contract_consent_type && g.metadata) {
            // A consent's terms, which the page checks in the bytes too.
            if (const auto c = protocol::decode_contract_consent(*g.metadata)) {
                summary["consent"] = {{"ledger", to_hex(c->ledger.bytes())},
                                      {"instance", to_hex(c->instance.bytes())},
                                      {"function", c->function},
                                      {"arguments", to_hex(c->arguments.bytes())},
                                      {"head", c->head},
                                      {"until", c->until}};
            }
        } else if (g.record_type == protocol::claim_type && g.metadata) {
            // A claim's terms, which the page checks in the bytes too.
            if (const auto c = protocol::decode_claim(*g.metadata)) {
                summary["claim"] = {
                    {"source", to_hex(c->source.bytes())},
                    {"text", protocol::claim_text(*c)},
                    {"holds", c->holds},
                    {"subject", c->subject ? nlohmann::json(*c->subject) : nlohmann::json()},
                    {"as_of", c->as_of},
                    {"until", c->until ? nlohmann::json(*c->until) : nlohmann::json()},
                    {"answers", c->answers ? nlohmann::json(to_hex(c->answers->second.bytes()))
                                           : nlohmann::json()}};
            }
        } else if (const auto terms =
                       g.metadata ? access_terms(g.record_type, *g.metadata) : nlohmann::json();
                   !terms.is_null()) {
            // An access record's terms, which the page checks in the bytes too.
            summary["access"] = terms;
        } else if (g.metadata) {
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
    prepared.bundles = std::move(bundles);
    prepared.new_key = std::move(person_key);
    prepared.person = std::move(person);
    prepared.activity = std::move(activity);
    prepared.hand_out = machine.hand_out;
    prepared.agent = machine.agent;
    prepared.model = std::move(machine.model);
    prepared.model_version = std::move(machine.model_version);
    summary["consents"] = prepared.bundles.size();
    prepared.user = signer.user;
    prepared.key = machine.as_organization ? std::string(root_key_name) : user->key;
    prepared.as_organization = machine.as_organization;
    if (machine.as_organization) {
        summary["by_organization"] = true;
    }
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
    // The organization's statements carry no presence: the console checks
    // the approving owner's passkey itself.
    const bool by_organization = prepared->as_organization;
    if (!by_organization) {
        statement.presence = proof;
    }
    // The proof checked as the ledger checks it, against the person's
    // passkeys registered on the ledger, and from this console's page.
    std::string problem;
    std::optional<crypto::PublicKey> current_key;
    const crypto::HashAlg hash = served->hash();
    const People people = load_people(services_.directory);
    const User* approver = people.find(prepared->user);
    const auto approver_actor = approver != nullptr ? id_of(approver->actor) : std::nullopt;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ActorState* a =
            by_organization ? (approver_actor ? state.actor(*approver_actor) : nullptr)
                            : state.actor(statement.actor_id.value());
        if (a == nullptr || a->revoked) {
            problem = "this user's actor is not on the ledger, or is revoked";
            return;
        }
        const auto check = by_organization
                               ? protocol::verify_assertion(*services_.provider,
                                                            prepared->challenge, proof, a->presence)
                               : protocol::verify_presence(*services_.provider, hash, statement,
                                                           prepared->kid, a->presence);
        if (!check) {
            problem =
                std::string("the passkey did not approve it: ") + std::string(check.error().detail);
        } else if (!check->user_verified || canonical(check->origin) != prepared->origin) {
            problem = "the passkey did not approve it on this console, with the person verified";
        }
        current_key = by_organization ? state.root_key() : a->key;
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
    if (!prepared->activity.empty()) {
        // A step of approving a person: their key sealed now; once the ledger
        // has registered their actor, the console user acts as it.
        std::string key_name;
        if (prepared->new_key && prepared->hand_out) {
            // A machine's key: handed out once, never kept.
            const std::lock_guard lock(mutex_);
            handed_[to_hex(signed_statement->id.bytes())] =
                Handed{prepared->new_key,
                       prepared->user,
                       prepared->person,
                       prepared->agent,
                       prepared->model,
                       prepared->model_version,
                       services_.clock->now() + 10 * 60'000};
        } else if (prepared->new_key) {
            key_name = "person-" + to_hex(signed_statement->id.bytes()).substr(0, 16);
            services_.keys->seal(key_name, *prepared->new_key);
        }
        const std::string by = prepared->user;
        return Signing{
            std::move(signed_statement->encoded),
            false,
            {},
            [this, by, person = prepared->person, activity = prepared->activity,
             key_name](const protocol::Id& registered) {
                if (!key_name.empty()) {
                    try {
                        change_people([&](People& users) {
                            if (User* u = users.find(person); u != nullptr && u->actor.empty()) {
                                u->actor = to_hex(registered.bytes());
                                u->key = key_name;
                            }
                        });
                    } catch (const std::exception&) {
                        // Linked by hand then: console user link.
                    }
                }
                log_activity(by, activity,
                             {{"user", person}, {"statement", to_hex(registered.bytes())}});
            }};
    }
    if (!prepared->bundles.empty()) {
        // A call citing consents goes with their bundles.
        cbor::Array bundles;
        for (const Bytes& b : prepared->bundles) {
            bundles.push_back(cbor::Value::bytes(b));
        }
        auto encoded = cbor::encode(cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::bytes(signed_statement->encoded)},
             {cbor::Value::integer(3), cbor::Value::array(std::move(bundles))}}));
        if (!encoded) {
            return error(500, "internal", "the submission could not be encoded");
        }
        return Signing{std::move(*encoded), true, {}};
    }
    if (!prepared->draft) {
        return Signing{std::move(signed_statement->encoded), false, {}};
    }
    // A registration: its private data, and its files if the kind keeps
    // them, sealed to the vault key for the record's id, sent along.
    const std::filesystem::path pub = services_.directory.parent_path() / "vault" / "vault.pub";
    const auto vault_key = std::filesystem::exists(pub)
                               ? client::decode_vault_public_key(client::read_file(pub))
                               : std::nullopt;
    if (!vault_key) {
        return error(409, "conflict", "this ledger has no vault key (cexchain vault rekey)");
    }
    const Draft& draft = *prepared->draft;
    const auto& registration = std::get<protocol::RecordRegisterBody>(statement.body);
    const protocol::Id& ledger_id = *statement.ledger_id;
    const protocol::Id& record = signed_statement->id;
    // A request's key, sealed to the vault key under the request's id; a
    // receipt's delivery, kept under its grant's (as the command line keeps
    // them).
    const std::filesystem::path ledger_dir = services_.directory.parent_path();
    if (draft.request_key) {
        const auto path = client::request_key_path(ledger_dir, record);
        std::filesystem::create_directories(path.parent_path());
        client::write_file(path, client::seal_request_key(*vault_key, record, *draft.request_key),
                           true);
    }
    if (draft.delivery) {
        const auto path =
            node::access_path(ledger_dir, node::AccessBox::deliveries, draft.delivery->first);
        std::filesystem::create_directories(path.parent_path());
        client::write_file(path, draft.delivery->second, true);
    }
    cbor::Map submission{
        {cbor::Value::integer(1), cbor::Value::bytes(signed_statement->encoded)},
        {cbor::Value::integer(2),
         cbor::Value::bytes(client::seal_vault(ledger_id, record, draft.vault, *vault_key))}};
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
                {i, client::seal_record_file(ledger_id, record, registration.attachments[i].name,
                                             client::read_file(path), *vault_key)});
        }
        submission.push_back({cbor::Value::integer(4), node::encode_sealed_files(files)});
    }
    auto encoded = cbor::encode(cbor::Value::map(std::move(submission)));
    if (!encoded) {
        return error(500, "internal", "the submission could not be encoded");
    }
    Signing signing{std::move(*encoded), true, draft.uploads};
    // A certificate's record: published once registered, its printed fields
    // disclosed (certifying.cpp).
    if (std::ranges::any_of(load_kinds(services_.directory), [&](const Kind& k) {
            return k.type == registration.record_type && !k.printed.empty();
        })) {
        signing.after = [this, type = registration.record_type,
                         fields = draft.vault.fields](const protocol::Id& id) {
            publish_certificate(id, type, fields);
        };
    }
    return signing;
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
    registered_now(signing, registered);
    secure(registered);
    return registered;
}

void Console::registered_now(const Signing& signing, const http::Response& registered) const {
    if (registered.status < 200 || registered.status >= 300) {
        return;
    }
    forget_uploads(signing.uploads);
    if (signing.after) {
        const auto answer =
            nlohmann::json::parse(registered.body.begin(), registered.body.end(), nullptr, false);
        if (const auto id = id_of(answer.is_object() ? answer.value("statement_id", "") : "")) {
            signing.after(*id);
        }
    }
}

} // namespace cexchain::console
