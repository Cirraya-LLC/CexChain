// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "contracts.hpp"

#include <algorithm>
#include <format>
#include <variant>

#include <cexchain/bo/messages.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/node/contracts.hpp>

#include "commands.hpp"
#include "peers.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

Json optional_text(const std::optional<std::string>& text) {
    return text ? Json(*text) : Json(nullptr);
}

/// A contract's reason, for a terminal: UTF-8 text as it is, control
/// characters and bytes that are not text as '?'.
std::string readable(ByteView reason) {
    const std::string text(reason.begin(), reason.end());
    std::string out;
    const bool utf8 = cbor::is_valid_utf8(text);
    for (const char c : text) {
        const auto b = static_cast<unsigned char>(c);
        out.push_back(b < 0x20 || b == 0x7f || (!utf8 && b >= 0x80) ? '?' : c);
    }
    return out;
}

} // namespace

cbor::Value parse_contract_arguments(std::string_view text, std::string_view what) {
    auto parsed = cbor::parse_diagnostic(text);
    if (!parsed) {
        throw UsageError{std::string(what) + ": " + std::string(parsed.error().detail) +
                         " (CBOR diagnostic notation; see cexchain contract call --help)"};
    }
    check_contract_arguments(*parsed);
    return *parsed;
}

void check_contract_arguments(const cbor::Value& arguments) {
    if (unwrap(cbor::encode(arguments), "the arguments").size() > protocol::max_contract_value) {
        throw UsageError{"the arguments are at most 65,536 bytes encoded"};
    }
}

std::string contract_label(const Session& session, const protocol::Id& contract) {
    const protocol::ContractState* c = session.state().contract(contract);
    return c != nullptr && c->name ? "\"" + *c->name + "\" (" + short_id(contract) + ")"
                                   : short_id(contract);
}

Json parties_json(const protocol::Parties& parties) {
    Json out = Json::object();
    for (const auto& [role, ledger] : parties) {
        out[role] = id_json(ledger);
    }
    return out;
}

std::string ledgers_text(const Session& session, const Json& list) {
    std::string out;
    if (!list.is_array()) {
        return "?";
    }
    for (const auto& item : list) {
        const std::string text = item.is_string() ? item.get<std::string>() : std::string("?");
        std::optional<protocol::Id> id;
        if (const auto bytes = from_hex(text)) {
            if (const auto parsed = protocol::to_id(*bytes)) {
                id = *parsed;
            }
        }
        out += (out.empty() ? "" : ", ") + (id ? ledger_label(session, *id) : "ledger " + text);
    }
    return out.empty() ? "none" : out;
}

// ---------------------------------------------------------------------------
// Calls on the home
// ---------------------------------------------------------------------------

protocol::ContractCallBody creation_call(const Session& session, std::string_view contract,
                                         const std::string& function) {
    const protocol::Id id = session.contract_id(contract);
    const protocol::ContractState& c = *session.state().contract(id);
    if (c.retired) {
        throw CommandError{"contract " + contract_label(session, id) +
                           " is retired: it creates no more instances"};
    }
    const auto f = c.interface.find(function);
    if (f == c.interface.end() || f->second != protocol::FunctionKind::create) {
        throw CommandError{"contract " + contract_label(session, id) + " has no function " +
                           function + " that creates instances"};
    }
    protocol::ContractCallBody body;
    body.contract = id;
    body.function = function;
    return body;
}

protocol::ContractCallBody instance_call(const Session& session, std::string_view instance,
                                         const std::string& function) {
    const protocol::Id id = session.instance_id(instance);
    const protocol::InstanceState& i = *session.state().instance(id);
    if (i.final) {
        throw CommandError{"instance " + short_id(id) + " is final: it takes no more calls"};
    }
    const protocol::ContractState& c = *session.state().contract(i.contract);
    const auto f = c.interface.find(function);
    if (f == c.interface.end() || f->second != protocol::FunctionKind::call) {
        throw CommandError{"contract " + contract_label(session, i.contract) + " has no function " +
                           function + " for instances"};
    }
    protocol::ContractCallBody body;
    body.instance = id;
    body.head = i.head;
    body.function = function;
    return body;
}

std::vector<Bytes> cite_consents(const Session& session, protocol::ContractCallBody& body,
                                 std::span<const std::string> paths) {
    std::vector<std::pair<protocol::ContractConsentRef, Bytes>> consents;
    for (const std::string& path : paths) {
        Bytes bundle = read_file(path);
        const protocol::Id ledger = unwrap(protocol::bundle_ledger_id(bundle), "reading " + path);
        protocol::VerifyOptions options;
        options.expected_ledger = ledger;
        const auto report = unwrap(protocol::verify_bundle(session.provider(), bundle, options),
                                   path + " does not verify");
        if (report.events.empty()) {
            throw CommandError{path + " shows no registration"};
        }
        const auto digest =
            unwrap(session.provider().digest(session.state().hash(), bundle), "hashing " + path);
        consents.emplace_back(
            protocol::ContractConsentRef{ledger, report.record, digest,
                                         protocol::registration_signer(report.events.front())},
            std::move(bundle));
    }
    std::ranges::sort(consents, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.first.ledger.bytes(), b.first.ledger.bytes());
    });
    for (std::size_t i = 1; i < consents.size(); ++i) {
        if (consents[i].first.ledger == consents[i - 1].first.ledger) {
            throw UsageError{"one consent per party: two consents are from ledger " +
                             short_id(consents[i].first.ledger)};
        }
    }
    std::vector<Bytes> bundles;
    for (auto& [ref, bundle] : consents) {
        body.consents.push_back(ref);
        bundles.push_back(std::move(bundle));
    }
    if (!bundles.empty()) {
        unwrap(node::check_call_consents(session.provider(), session.state().ledger_id(),
                                         session.state().hash(), body, bundles,
                                         ledger::SystemClock{}.now()),
               "checking the consents");
    }
    return bundles;
}

CallAttempt attempt_call(Session& session, const crypto::Signer& signer,
                         protocol::ContractCallBody body, std::span<const Bytes> bundles,
                         const CallOptions& options) {
    CallAttempt attempt;
    attempt.statement =
        session.sign(signer, std::move(body), options.delegation, options.provenance,
                     options.dry_run ? std::nullopt : options.presence);
    attempt.run = unwrap(session.state().run_contract(session.provider(), attempt.statement,
                                                      ledger::SystemClock{}.now()),
                         "running the contract");
    if (!options.dry_run && attempt.run.accepted() != nullptr) {
        attempt.recorded = session.submit_signed(attempt.statement, std::nullopt, bundles);
    }
    return attempt;
}

std::string refusal(const Session& session, const protocol::ContractRun& run) {
    if (run.outcome.trap) {
        if (*run.outcome.trap == vm::Trap::aborted) {
            const std::string reason = readable(run.outcome.abort_reason);
            // A compiled Bo contract's own checks ("bo:state sign"), in words.
            if (const auto words = bo::render_reason(reason, nullptr)) {
                return "the contract refuses the call: " + *words + " (" + reason + ")";
            }
            return "the contract refuses the call: " + reason;
        }
        return "the contract trapped on the call (" + std::string(vm::name(*run.outcome.trap)) +
               ")";
    }
    if (run.malformed) {
        return "the contract's output is not well formed: " + std::string(run.malformed->detail);
    }
    if (const auto* needs =
            run.output ? std::get_if<protocol::ContractNeeds>(&*run.output) : nullptr) {
        std::string who;
        for (const protocol::Id& l : needs->ledgers) {
            who += (who.empty() ? "" : ", ") + ledger_label(session, l);
        }
        return "the contract needs the consent of " + who;
    }
    return "the contract does not accept the call";
}

Json run_json(const Session& session, const protocol::ContractRun& run) {
    Json out{{"fuel_used", run.outcome.fuel_used}};
    if (const protocol::ContractAccept* a = run.accepted()) {
        Json events = Json::array();
        for (const protocol::ContractEvent& e : a->events) {
            events.push_back({{"name", e.name}, {"data", cbor::diagnostic(e.data)}});
        }
        out["verdict"] = "accept";
        out["status"] = optional_text(a->status);
        out["parties"] = a->parties ? parties_json(*a->parties) : Json(nullptr);
        out["events"] = std::move(events);
        out["final"] = a->final;
        out["state"] = cbor::diagnostic(a->state);
        return out;
    }
    if (const auto* needs =
            run.output ? std::get_if<protocol::ContractNeeds>(&*run.output) : nullptr) {
        Json ledgers = Json::array();
        for (const protocol::Id& l : needs->ledgers) {
            ledgers.push_back(id_json(l));
        }
        out["verdict"] = "needs";
        out["needs"] = std::move(ledgers);
    } else {
        out["verdict"] = "refuse";
    }
    out["reason"] = refusal(session, run);
    return out;
}

// ---------------------------------------------------------------------------
// A home's registrar, seen from a party
// ---------------------------------------------------------------------------

Json held_json(const Json& held) {
    Json out = held;
    const std::string hex = held.value("arguments", std::string());
    const auto bytes = from_hex(hex);
    const auto value =
        bytes ? cbor::decode(*bytes) : Result<cbor::Value>(fail(Errc::malformed, ""));
    out["arguments"] = value ? Json(cbor::diagnostic(*value)) : Json(nullptr);
    out["arguments_cbor"] = hex;
    if (held.contains("until") && held["until"].is_number_unsigned()) {
        out["until"] = iso_time(held["until"].get<protocol::Timestamp>());
    }
    return out;
}

Json pending_at(const node::Peer& home, const std::optional<std::string>& call) {
    const Json answer =
        peer_call(home, "GET", "/v1/contracts/calls" + (call ? "/" + *call : std::string()));
    Json calls = Json::array();
    for (const Json& h : call ? Json::array({answer}) : answer.value("calls", Json::array())) {
        calls.push_back(held_json(h));
    }
    return calls;
}

std::pair<Bytes, protocol::ContractReport> fetch_instance(const node::Peer& home,
                                                          const protocol::Id& instance) {
    const auto response =
        unwrap(peer_client(home).request("GET", "/v1/contracts/instances/" + hex_id(instance)),
               "reaching peer " + home.name);
    if (response.status == 404) {
        throw CommandError{"peer " + home.name +
                           " shows this instance only to its parties: ask for its evidence, or "
                           "give --head and --hash"};
    }
    if (response.status != 200) {
        throw CommandError{"peer " + home.name + " answered status " +
                           std::to_string(response.status)};
    }
    protocol::VerifyOptions options;
    options.expected_ledger = home.ledger_id;
    auto report =
        unwrap(protocol::verify_contract_evidence(shared_provider(), response.body, options),
               "the instance's evidence from " + home.name + " does not verify");
    if (report.instance.record != instance) {
        throw CommandError{"peer " + home.name + " sent evidence of another instance"};
    }
    return {response.body, std::move(report)};
}

crypto::HashAlg home_hash(const node::Peer& home, const protocol::Id& instance) {
    if (!home.url) {
        throw UsageError{"give --hash: the home's hash (sha256 or sm3), which the consent hashes "
                         "the arguments with"};
    }
    const auto response =
        unwrap(peer_client(home).request("GET", "/v1/checkpoint"), "reaching peer " + home.name);
    if (response.status == 404) {
        // No checkpoint yet: the instance's evidence names the hash.
        return fetch_instance(home, instance).second.instance.hash;
    }
    if (response.status != 200) {
        throw CommandError{"peer " + home.name + " shows no checkpoint (status " +
                           std::to_string(response.status) + "): give --hash"};
    }
    const auto checkpoint =
        unwrap(protocol::parse_checkpoint(response.body), "peer " + home.name + "'s checkpoint");
    if (checkpoint.checkpoint.ledger_id != home.ledger_id) {
        throw CommandError{"peer " + home.name + " serves another ledger than the one pinned"};
    }
    return checkpoint.checkpoint.tree_hash;
}

HeldTerms held_call_terms(const Session& session, const node::Peer& home, const protocol::Id& call,
                          std::optional<crypto::HashAlg> hash) {
    const Json held = peer_call(home, "GET", "/v1/contracts/calls/" + hex_id(call));
    HeldTerms terms;
    terms.consent.ledger = home.ledger_id;
    terms.consent.instance = full_id(held.value("instance", std::string()), "the call's instance");
    terms.consent.head = held.value("head", std::uint64_t{0});
    terms.consent.function = held.value("function", std::string());
    const auto bytes = from_hex(held.value("arguments", std::string()));
    if (!bytes) {
        throw CommandError{"peer " + home.name + " sent arguments that are not hex"};
    }
    terms.arguments = unwrap(cbor::decode(*bytes), "the call's arguments");
    if (!hash) {
        hash = home_hash(home, terms.consent.instance);
    }
    terms.consent.arguments =
        unwrap(protocol::contract_arguments_digest(session.provider(), *hash, terms.arguments),
               "the digest");
    if (held.value("arguments_digest", std::string()) != hex_id(terms.consent.arguments)) {
        throw CommandError{"the home's call names other arguments than it sent; nothing recorded"};
    }
    // The call's id is a hash of its terms: the terms consented to are the
    // ones the call named.
    const protocol::Id named =
        unwrap(node::pending_call_id(session.provider(), terms.consent.instance, terms.consent.head,
                                     terms.consent.function, terms.consent.arguments),
               "the call's id");
    if (named != call) {
        throw CommandError{"the home sent other terms than call " + short_id(call) +
                           " names; nothing recorded"};
    }
    return terms;
}

// ---------------------------------------------------------------------------
// A party's consent
// ---------------------------------------------------------------------------

GivenConsent give_consent(Session& session, const crypto::Signer& signer,
                          protocol::ContractConsent& consent, const ConsentOptions& options,
                          const Args& ledger_args) {
    consent.until = ledger::SystemClock{}.now() + options.days * day_ms;
    consent.reference = options.reference;
    IssueRequest request;
    request.record_type = std::string(protocol::contract_consent_type);
    request.fields.emplace_back("note", "consent to " + consent.function + " on instance " +
                                            short_id(consent.instance));
    request.metadata_value = unwrap(protocol::encode_contract_consent(consent), "the consent");
    request.delegation = options.delegation;
    request.provenance = options.provenance;
    request.presence = options.presence;
    GivenConsent given;
    given.record = issue_record(session, signer, request);
    static_cast<void>(session.checkpoint(ledger_args));
    given.bundle = unwrap(protocol::encode_bundle(session.evidence(ledger_args, given.record)),
                          "encoding the consent");
    return given;
}

Json consent_json(const protocol::Id& record, const protocol::ContractConsent& consent,
                  const cbor::Value& arguments) {
    return {{"consent", id_json(record)},
            {"home", id_json(consent.ledger)},
            {"instance", id_json(consent.instance)},
            {"function", consent.function},
            {"arguments", cbor::diagnostic(arguments)},
            {"arguments_digest", id_json(consent.arguments)},
            {"head", consent.head},
            {"until", iso_time(consent.until)}};
}

} // namespace cexchain::cli
