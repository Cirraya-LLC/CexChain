// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Contracts (D-053): WebAssembly modules deployed on a ledger, their home,
// that govern instances such as agreements and orders. The home records a
// call only if the contract accepts it; parties on other ledgers consent on
// their own, and anyone holding an instance's evidence replays every call.
//
//   home:   contract deploy, show, list, retire, create, call, instance,
//           instances, evidence, pending; serve --registrar-key takes
//           proposed calls and collects the consents their contracts ask for
//   party:  contract propose (to the home's registrar), pending, consent,
//           send, withdraw, fetch
//   anyone: contract verify

#include <algorithm>
#include <format>
#include <print>
#include <variant>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/peers.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "peers.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

constexpr protocol::Timestamp day_ms = 86'400'000;

Json optional_text(const std::optional<std::string>& text) {
    return text ? Json(*text) : Json(nullptr);
}

std::string encoded_hex(const cbor::Value& value) {
    return to_hex(unwrap(cbor::encode(value), "encoding a value"));
}

/// Long values (arguments and states reach 64 KiB) shortened for a terminal.
std::string shortened(const std::string& text) {
    constexpr std::size_t limit = 200;
    if (text.size() <= limit) {
        return text;
    }
    std::string out = text.substr(0, limit);
    while (!out.empty() && (static_cast<unsigned char>(out.back()) & 0xc0U) == 0x80U) {
        out.pop_back();
    }
    if (!out.empty() && static_cast<unsigned char>(out.back()) >= 0xc0U) {
        out.pop_back();
    }
    return std::format("{}... ({} characters; --json shows it all)", out, text.size());
}

/// The arguments: --args in diagnostic notation, --args-cbor from a file of
/// CBOR, or null.
cbor::Value arguments_of(const Args& args) {
    const auto text = args.get("args");
    const auto file = args.get("args-cbor");
    if (text && file) {
        throw UsageError{"give --args or --args-cbor, not both"};
    }
    cbor::Value value;
    if (text) {
        auto parsed = cbor::parse_diagnostic(*text);
        if (!parsed) {
            throw UsageError{"--args: " + std::string(parsed.error().detail) +
                             " (see cexchain contract call --help)"};
        }
        value = *parsed;
    } else if (file) {
        value = unwrap(cbor::decode(read_file(*file)), "--args-cbor " + *file);
    }
    if (unwrap(cbor::encode(value), "the arguments").size() > protocol::max_contract_value) {
        throw UsageError{"the arguments are at most 65,536 bytes encoded"};
    }
    return value;
}

std::string_view kind_name(protocol::FunctionKind kind) {
    return kind == protocol::FunctionKind::create ? "create" : "call";
}

std::optional<protocol::ActorKind> signer_kind(const protocol::ContractSigner& signer) {
    if (signer.kind == 0) {
        return std::nullopt;
    }
    return static_cast<protocol::ActorKind>(signer.kind);
}

Json signer_json(const protocol::ContractSigner& signer) {
    Json presence = nullptr;
    if (signer.presence) {
        presence = *signer.presence == protocol::PresenceMethod::hardware_key ? "hardware-key"
                                                                              : "webauthn";
    }
    return {{"kind", kind_text(signer_kind(signer))},
            {"presence", std::move(presence)},
            {"model", optional_text(signer.model)}};
}

std::string signer_text(const protocol::ContractSigner& signer) {
    std::string out = kind_label(signer_kind(signer));
    if (signer.presence) {
        out += *signer.presence == protocol::PresenceMethod::hardware_key
                   ? ", present: hardware key"
                   : ", present: passkey";
    }
    if (signer.model) {
        out += ", model " + *signer.model;
    }
    return out;
}

Json parties_json(const protocol::Parties& parties) {
    Json out = Json::object();
    for (const auto& [role, ledger] : parties) {
        out[role] = id_json(ledger);
    }
    return out;
}

/// The deploy statement's body: the code, the source, the interface.
protocol::ContractDeployBody deploy_of(const Session& session, const protocol::ContractState& c) {
    const protocol::SignedStatement deploy = session.statement(c.deployed_at_index);
    return std::get<protocol::ContractDeployBody>(deploy.statement.body);
}

std::optional<std::string> retire_reason(const Session& session, const protocol::ContractState& c) {
    if (!c.retired_at_index) {
        return std::nullopt;
    }
    const protocol::SignedStatement retire = session.statement(*c.retired_at_index);
    return std::get<protocol::ContractRetireBody>(retire.statement.body).reason;
}

} // namespace

Json contract_json(const Session& session, const protocol::ContractState& c) {
    const protocol::ContractDeployBody deploy = deploy_of(session, c);
    Json functions = Json::object();
    for (const auto& [name, kind] : c.interface) {
        functions[name] = kind_name(kind);
    }
    std::size_t instances = 0;
    std::size_t open = 0;
    for (const auto& [key, i] : session.state().instances()) {
        if (i.contract == c.id) {
            ++instances;
            open += i.final ? 0U : 1U;
        }
    }
    const auto code_hash =
        unwrap(session.provider().digest(session.state().hash(), deploy.code), "hashing the code");
    return {{"id", id_json(c.id)},
            {"name", optional_text(c.name)},
            {"language", c.language},
            {"compiler", c.compiler},
            {"functions", std::move(functions)},
            {"deployer", actor_ref(session, c.deployer)},
            {"deployed_at", iso_time(session.log_entry(c.deployed_at_index).registered_at)},
            {"deployed_at_index", c.deployed_at_index},
            {"retired", c.retired},
            {"retired_at_index", c.retired_at_index ? Json(*c.retired_at_index) : Json(nullptr)},
            {"retire_reason", optional_text(retire_reason(session, c))},
            {"code_size", deploy.code.size()},
            {"code_hash", to_hex(code_hash.bytes())},
            {"source_size", deploy.source ? Json(deploy.source->size()) : Json(nullptr)},
            {"instances", instances},
            {"open_instances", open}};
}

namespace {

std::string contract_label(const Session& session, const protocol::Id& id) {
    const protocol::ContractState* c = session.state().contract(id);
    return c != nullptr && c->name ? "\"" + *c->name + "\" (" + short_id(id) + ")" : short_id(id);
}

Json call_json(const Session& session, std::uint64_t index, const protocol::SignedStatement& s,
               const protocol::ContractCallBody& call) {
    Json consents = Json::array();
    for (const protocol::ContractConsentRef& c : call.consents) {
        consents.push_back({{"ledger", id_json(c.ledger)},
                            {"record", id_json(c.record)},
                            {"bundle", id_json(c.bundle)},
                            {"signer", signer_json(c.signer)}});
    }
    return {{"index", index},
            {"statement_id", id_json(s.id)},
            {"registered_at", iso_time(session.log_entry(index).registered_at)},
            {"function", call.function},
            {"creates", !call.instance.has_value()},
            {"arguments", cbor::diagnostic(call.arguments)},
            {"arguments_cbor", encoded_hex(call.arguments)},
            {"reference", optional_text(call.reference)},
            {"by", actor_ref(session, *s.statement.actor_id)},
            {"consents", std::move(consents)}};
}

} // namespace

Json instance_json(const Session& session, const protocol::InstanceState& i) {
    Json calls = Json::array();
    for (const std::uint64_t index : i.history) {
        const protocol::SignedStatement s = session.statement(index);
        if (const auto* call = std::get_if<protocol::ContractCallBody>(&s.statement.body)) {
            calls.push_back(call_json(session, index, s, *call));
        }
    }
    const protocol::ContractState* c = session.state().contract(i.contract);
    return {{"id", id_json(i.id)},
            {"contract", id_json(i.contract)},
            {"contract_name", c != nullptr ? optional_text(c->name) : Json(nullptr)},
            {"status", optional_text(i.status)},
            {"parties", parties_json(i.parties)},
            {"final", i.final},
            {"head", i.head},
            {"state", cbor::diagnostic(i.state)},
            {"state_cbor", encoded_hex(i.state)},
            {"calls", std::move(calls)}};
}

namespace {

void print_parties(const Session& session, const protocol::Parties& parties) {
    if (parties.empty()) {
        std::println("parties:   none");
    }
    bool first = true;
    for (const auto& [role, ledger] : parties) {
        std::println("{}{}: {}", first ? "parties:   " : "           ", role,
                     ledger_label(session, ledger));
        first = false;
    }
}

void print_instance(const Session& session, const protocol::InstanceState& i) {
    std::println("instance:  {}", hex_id(i.id));
    std::println("contract:  {}", contract_label(session, i.contract));
    std::println("status:    {}{}", i.status.value_or("(none)"),
                 i.final ? " (final: it takes no more calls)" : "");
    print_parties(session, i.parties);
    std::println("state:     {}", shortened(cbor::diagnostic(i.state)));
    std::println("head:      #{} (calls and consents name it)", i.head);
    for (const std::uint64_t index : i.history) {
        const protocol::SignedStatement s = session.statement(index);
        const auto* call = std::get_if<protocol::ContractCallBody>(&s.statement.body);
        if (call == nullptr) {
            continue;
        }
        std::string consents;
        for (const protocol::ContractConsentRef& c : call->consents) {
            consents += (consents.empty() ? ", consents: " : "; ") +
                        ledger_label(session, c.ledger) + " [" + signer_text(c.signer) + "]";
        }
        std::println("  #{:<5} {}  {} {} by \"{}\"{}", index,
                     format_time(session.log_entry(index).registered_at),
                     call->instance ? "call" : "create with", call->function,
                     session.actor_name(*s.statement.actor_id), consents);
        std::println("          arguments: {}", shortened(cbor::diagnostic(call->arguments)));
    }
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

/// Why a run does not accept the call, for people.
std::string refusal(const Session& session, const protocol::ContractRun& run) {
    if (run.outcome.trap) {
        if (*run.outcome.trap == vm::Trap::aborted) {
            return "the contract refuses the call: " + readable(run.outcome.abort_reason);
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

/// What a run would do, as JSON: accept (with its effect), needs, or refuse.
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

/// Each consent's evidence, from files, cited as the call will cite it: by
/// its ledger, its record, its hash under this ledger's hash, and the signer
/// of its registration. In ledger order.
std::vector<std::pair<protocol::ContractConsentRef, Bytes>> consents_from(const Session& session,
                                                                          const Args& args) {
    std::vector<std::pair<protocol::ContractConsentRef, Bytes>> out;
    for (const std::string& path : args.all("consent")) {
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
        out.emplace_back(
            protocol::ContractConsentRef{ledger, report.record, digest,
                                         protocol::registration_signer(report.events.front())},
            std::move(bundle));
    }
    std::ranges::sort(out, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.first.ledger.bytes(), b.first.ledger.bytes());
    });
    for (std::size_t i = 1; i < out.size(); ++i) {
        if (out[i].first.ledger == out[i - 1].first.ledger) {
            throw UsageError{"one consent per party: two --consent files are from ledger " +
                             short_id(out[i].first.ledger)};
        }
    }
    return out;
}

/// Signs the call, runs its contract here as the ledger will, and records
/// it if the contract accepts it (or, with --dry-run, reports the run).
int record_call(const Args& args, Session& session, protocol::ContractCallBody body,
                const std::vector<Bytes>& bundles) {
    const bool dry_run = args.has("dry-run");
    const auto signer = load_signer(args.need("as"), args);
    const protocol::SignedStatement statement =
        session.sign(*signer, std::move(body), args.get("delegation"), session.provenance(args),
                     dry_run ? std::nullopt : presence_request(args));
    const protocol::ContractRun run = unwrap(
        session.state().run_contract(session.provider(), statement, ledger::SystemClock{}.now()),
        "running the contract");
    const auto& call = std::get<protocol::ContractCallBody>(statement.statement.body);
    if (dry_run) {
        if (args.json()) {
            Json out = run_json(session, run);
            out["function"] = call.function;
            print_json(out);
            return exit_ok;
        }
        if (const protocol::ContractAccept* a = run.accepted()) {
            std::println("the contract would accept {}: status {}{}", call.function,
                         a->status.value_or("(none)"), a->final ? ", final" : "");
            if (a->parties) {
                print_parties(session, *a->parties);
            }
            for (const protocol::ContractEvent& e : a->events) {
                std::println("event:     {} {}", e.name, shortened(cbor::diagnostic(e.data)));
            }
            std::println("state:     {}", shortened(cbor::diagnostic(a->state)));
        } else {
            std::println("it would not be recorded: {}", refusal(session, run));
        }
        std::println("fuel used: {}", run.outcome.fuel_used);
        return exit_ok;
    }
    if (run.accepted() == nullptr) {
        std::string advice;
        if (run.output && std::holds_alternative<protocol::ContractNeeds>(*run.output)) {
            advice = call.instance ? ": pass each party's consent with --consent (from contract "
                                     "consent), or propose the call to the registrar (contract "
                                     "propose)"
                                   : ": a creation takes no consents";
        }
        throw CommandError{refusal(session, run) + advice};
    }
    const protocol::Id id = session.submit_signed(statement, std::nullopt, bundles);
    const protocol::Id instance = call.instance ? *call.instance : id;
    const protocol::InstanceState& now = *session.state().instance(instance);
    std::string text =
        call.instance
            ? std::format("called {} on {}\nstatus: {}{}", call.function, hex_id(instance),
                          now.status.value_or("(none)"), now.final ? " (final)" : "")
            : std::format("created instance {} of contract {}\nstatus: {}", hex_id(instance),
                          contract_label(session, *call.contract), now.status.value_or("(none)"));
    for (const auto& [role, ledger] : now.parties) {
        text += "\n" + role + ": " + ledger_label(session, ledger);
    }
    return report_submitted(args, session, id, {{"instance", instance_json(session, now)}}, text);
}

/// A call the registrar holds, as the server shows it (`GET
/// /v1/contracts/calls`), for people and scripts: arguments in diagnostic
/// notation, times in RFC 3339.
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

/// A held call from this ledger's own files, as the server would show it.
Json local_held_json(const Session& session, const node::HeldCall& h) {
    Json missing = Json::array();
    for (const protocol::Id& m : h.call.missing) {
        missing.push_back(id_json(m));
    }
    Json consented = Json::array();
    for (const auto& [ledger, bundle] : h.call.consents) {
        consented.push_back(id_json(ledger));
    }
    const auto digest = unwrap(protocol::contract_arguments_digest(
                                   session.provider(), session.state().hash(), h.call.arguments),
                               "the arguments' digest");
    return {{"call", id_json(h.name.id)},
            {"instance", id_json(h.call.instance)},
            {"head", h.call.head},
            {"function", h.call.function},
            {"arguments", cbor::diagnostic(h.call.arguments)},
            {"arguments_cbor", encoded_hex(h.call.arguments)},
            {"arguments_digest", id_json(digest)},
            {"reference", optional_text(h.call.reference)},
            {"until", iso_time(h.call.until)},
            {"missing", std::move(missing)},
            {"consented", std::move(consented)},
            {"proposer", h.call.proposer}};
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

void print_held(const Session& session, const Json& h) {
    std::println("call {}  {} on instance {} (head #{})",
                 h["call"].get<std::string>().substr(0, 12), h["function"].get<std::string>(),
                 h["instance"].get<std::string>().substr(0, 12), h["head"].get<std::uint64_t>());
    std::println("  arguments:    {}", h["arguments"].is_string()
                                           ? shortened(h["arguments"].get<std::string>())
                                           : std::string("(not CBOR)"));
    if (h.contains("reference") && h["reference"].is_string()) {
        std::println("  reference:    {}", h["reference"].get<std::string>());
    }
    std::println("  waiting for:  {}", ledgers_text(session, h["missing"]));
    std::println("  consented:    {}", ledgers_text(session, h["consented"]));
    std::println("  lapses:       {}", h.value("until", std::string("?")));
    if (h.contains("proposer")) {
        std::println("  proposed by:  {}", h["proposer"].get<std::string>());
    }
}

/// The ledger's hash a peer's checkpoint names: what the home hashes the
/// arguments with in a consent's terms.
crypto::HashAlg hash_of_peer(const node::Peer& peer) {
    const auto response =
        unwrap(peer_client(peer).request("GET", "/v1/checkpoint"), "reaching peer " + peer.name);
    if (response.status != 200) {
        throw CommandError{"peer " + peer.name + " shows no checkpoint (status " +
                           std::to_string(response.status) + "): give --hash"};
    }
    const auto checkpoint =
        unwrap(protocol::parse_checkpoint(response.body), "peer " + peer.name + "'s checkpoint");
    if (checkpoint.checkpoint.ledger_id != peer.ledger_id) {
        throw CommandError{"peer " + peer.name + " serves another ledger than the one pinned"};
    }
    return checkpoint.checkpoint.tree_hash;
}

/// An instance's contract evidence from its home (a peer), verified for it.
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

/// What a registrar answered to a proposal or a consent, for people.
void print_answer(const Session* session, const std::string& who, const Json& answer) {
    const std::string status = answer.value("status", std::string("?"));
    std::println("{}: {}", who, status);
    if (answer.contains("call") && answer["call"].is_string()) {
        std::println("  call:         {}", answer["call"].get<std::string>());
    }
    if (status == "waiting" && answer.contains("missing") && session != nullptr) {
        std::println("  waiting for:  {}", ledgers_text(*session, answer["missing"]));
    }
    if (answer.contains("statement_id")) {
        std::println("  recorded as {} (entry #{}); the instance is now {}",
                     answer["statement_id"].get<std::string>(),
                     answer.value("index", std::uint64_t{0}),
                     answer.contains("instance_status") && answer["instance_status"].is_string()
                         ? answer["instance_status"].get<std::string>()
                         : std::string("(no status)"));
    }
}

} // namespace

// ---------------------------------------------------------------------------
// The home: contracts
// ---------------------------------------------------------------------------

int cmd_contract_deploy(const Args& args) {
    Session session(args);
    protocol::ContractDeployBody body;
    const std::string path = args.positional().front();
    body.code = read_file(path);
    if (body.code.size() > vm::max_module_size) {
        throw CommandError{path + " is larger than a contract may be (512 KiB)"};
    }
    static_cast<void>(unwrap(vm::load(body.code), path + " is not a contract module"));
    for (const std::string& item : args.all("function")) {
        auto [name, kind] = split_pair(item, "--function");
        if (name.empty() || name.size() > protocol::max_function_name) {
            throw UsageError{"a function name is 1 to 64 bytes"};
        }
        if (kind != "create" && kind != "call") {
            throw UsageError{"--function " + item + ": the kind is create or call"};
        }
        if (!body.interface
                 .emplace(name, kind == "create" ? protocol::FunctionKind::create
                                                 : protocol::FunctionKind::call)
                 .second) {
            throw UsageError{"--function " + name + " is given twice"};
        }
    }
    if (std::ranges::none_of(body.interface, [](const auto& f) {
            return f.second == protocol::FunctionKind::create;
        })) {
        throw UsageError{"at least one function creates instances (--function NAME=create)"};
    }
    body.language = args.get("language").value_or("wasm");
    body.compiler = args.need("compiler");
    if (const auto source = args.get("source")) {
        body.source = read_file(*source);
    }
    body.name = args.get("name");
    const protocol::Id id = session.submit(args, body);
    const protocol::ContractState& c = *session.state().contract(id);
    std::string functions;
    for (const auto& [name, kind] : c.interface) {
        functions += (functions.empty() ? "" : ", ") + name +
                     (kind == protocol::FunctionKind::create ? " (creates)" : "");
    }
    return report_submitted(args, session, id, {{"contract", contract_json(session, c)}},
                            std::format("deployed contract {}{}\nfunctions: {}", hex_id(id),
                                        c.name ? " \"" + *c.name + "\"" : "", functions));
}

int cmd_contract_show(const Args& args) {
    Session session(args);
    const protocol::ContractState& c =
        *session.state().contract(session.contract_id(args.positional().front()));
    const protocol::ContractDeployBody deploy = deploy_of(session, c);
    if (const auto out = args.get("code-out")) {
        write_file(*out, deploy.code, false);
    }
    if (const auto out = args.get("source-out")) {
        if (!deploy.source) {
            throw CommandError{"the contract was deployed without its source"};
        }
        write_file(*out, *deploy.source, false);
    }
    const Json j = contract_json(session, c);
    if (args.json()) {
        print_json(j);
        return exit_ok;
    }
    std::println("contract:   {}", hex_id(c.id));
    if (c.name) {
        std::println("name:       {}", *c.name);
    }
    std::println("language:   {} (compiler: {})", c.language, c.compiler);
    std::string functions;
    for (const auto& [name, kind] : c.interface) {
        functions += (functions.empty() ? "" : ", ") + name +
                     (kind == protocol::FunctionKind::create ? " (creates)" : "");
    }
    std::println("functions:  {}", functions);
    std::println("code:       {} bytes, {} {}", deploy.code.size(),
                 crypto::name(session.state().hash()), j["code_hash"].get<std::string>());
    std::println("source:     {}", deploy.source ? std::format("{} bytes", deploy.source->size())
                                                 : std::string("not deployed with it"));
    std::println("deployed:   #{} {} by \"{}\"", c.deployed_at_index,
                 format_time(session.log_entry(c.deployed_at_index).registered_at),
                 session.actor_name(c.deployer));
    if (c.retired_at_index) {
        const auto reason = retire_reason(session, c);
        std::println("retired:    #{} {}{}: it creates no more instances", *c.retired_at_index,
                     format_time(session.log_entry(*c.retired_at_index).registered_at),
                     reason ? " (" + *reason + ")" : "");
    }
    std::println("instances:  {} ({} open)", j["instances"].get<std::size_t>(),
                 j["open_instances"].get<std::size_t>());
    return exit_ok;
}

int cmd_contract_list(const Args& args) {
    Session session(args);
    Json out = Json::array();
    for (const auto& [key, c] : session.state().contracts()) {
        if (c.retired && args.has("active")) {
            continue;
        }
        const Json j = contract_json(session, c);
        if (args.json()) {
            out.push_back(j);
            continue;
        }
        std::println("{}  {:<28} {:<6} {} function(s), {} instance(s){}", short_id(c.id),
                     c.name ? "\"" + *c.name + "\"" : std::string("-"), c.language,
                     c.interface.size(), j["instances"].get<std::size_t>(),
                     c.retired ? ", retired" : "");
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_contract_retire(const Args& args) {
    Session session(args);
    const protocol::Id contract = session.contract_id(args.positional().front());
    if (session.state().contract(contract)->retired) {
        throw CommandError{"contract " + short_id(contract) + " is retired already"};
    }
    const protocol::Id id =
        session.submit(args, protocol::ContractRetireBody{contract, args.get("reason")});
    const protocol::ContractState& c = *session.state().contract(contract);
    const Json j = contract_json(session, c);
    return report_submitted(
        args, session, id, {{"contract", j}},
        std::format("retired contract {}: it creates no more instances; its {} open instance(s) "
                    "carry on",
                    contract_label(session, contract), j["open_instances"].get<std::size_t>()));
}

// ---------------------------------------------------------------------------
// The home: instances
// ---------------------------------------------------------------------------

int cmd_contract_create(const Args& args) {
    Session session(args);
    const protocol::Id contract = session.contract_id(args.positional()[0]);
    const protocol::ContractState& c = *session.state().contract(contract);
    const std::string& function = args.positional()[1];
    if (c.retired) {
        throw CommandError{"contract " + contract_label(session, contract) +
                           " is retired: it creates no more instances"};
    }
    const auto f = c.interface.find(function);
    if (f == c.interface.end() || f->second != protocol::FunctionKind::create) {
        throw CommandError{"contract " + contract_label(session, contract) + " has no function " +
                           function + " that creates instances"};
    }
    protocol::ContractCallBody body;
    body.contract = contract;
    body.function = function;
    body.arguments = arguments_of(args);
    body.reference = args.get("reference");
    return record_call(args, session, std::move(body), {});
}

int cmd_contract_call(const Args& args) {
    Session session(args);
    const protocol::Id instance = session.instance_id(args.positional()[0]);
    const protocol::InstanceState& i = *session.state().instance(instance);
    const std::string& function = args.positional()[1];
    if (i.final) {
        throw CommandError{"instance " + short_id(instance) + " is final: it takes no more calls"};
    }
    const protocol::ContractState& c = *session.state().contract(i.contract);
    const auto f = c.interface.find(function);
    if (f == c.interface.end() || f->second != protocol::FunctionKind::call) {
        throw CommandError{"contract " + contract_label(session, i.contract) + " has no function " +
                           function + " for instances"};
    }
    protocol::ContractCallBody body;
    body.instance = instance;
    body.head = i.head;
    body.function = function;
    body.arguments = arguments_of(args);
    body.reference = args.get("reference");
    std::vector<Bytes> bundles;
    for (auto& [ref, bundle] : consents_from(session, args)) {
        body.consents.push_back(ref);
        bundles.push_back(std::move(bundle));
    }
    if (!bundles.empty()) {
        // Checked as a verifier will, for a clear answer before signing.
        unwrap(node::check_call_consents(session.provider(), session.state().ledger_id(),
                                         session.state().hash(), body, bundles,
                                         ledger::SystemClock{}.now()),
               "checking the consents");
    }
    return record_call(args, session, std::move(body), bundles);
}

int cmd_contract_instance(const Args& args) {
    Session session(args);
    const protocol::InstanceState& i =
        *session.state().instance(session.instance_id(args.positional().front()));
    if (args.json()) {
        print_json(instance_json(session, i));
    } else {
        print_instance(session, i);
    }
    return exit_ok;
}

int cmd_contract_instances(const Args& args) {
    Session session(args);
    const std::optional<protocol::Id> contract =
        args.has("contract") ? std::optional(session.contract_id(*args.get("contract")))
                             : std::nullopt;
    const auto status = args.get("status");
    const std::optional<protocol::Id> party =
        args.has("party") ? std::optional(ledger_of(session, *args.get("party"))) : std::nullopt;
    Json out = Json::array();
    for (const auto& [key, i] : session.state().instances()) {
        if ((contract && !(i.contract == *contract)) || (status && i.status != *status) ||
            (args.has("open") && i.final) ||
            (party &&
             std::ranges::none_of(i.parties, [&](const auto& p) { return p.second == *party; }))) {
            continue;
        }
        if (args.json()) {
            out.push_back(instance_json(session, i));
            continue;
        }
        std::string parties;
        for (const auto& [role, ledger] : i.parties) {
            parties += (parties.empty() ? "" : ", ") + role + ": " + ledger_label(session, ledger);
        }
        std::println("{}  {:<12} head #{:<6} of {}; {}{}", short_id(i.id), i.status.value_or("-"),
                     i.head, contract_label(session, i.contract),
                     parties.empty() ? std::string("no parties") : parties,
                     i.final ? " (final)" : "");
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_contract_evidence(const Args& args) {
    Session session(args);
    const protocol::Id instance = session.instance_id(args.positional().front());
    const Bytes evidence = session.contract_evidence(args, instance);
    write_file(args.need("out"), evidence, false);
    const protocol::InstanceState& i = *session.state().instance(instance);
    if (args.json()) {
        print_json({{"instance", id_json(instance)},
                    {"status", optional_text(i.status)},
                    {"out", args.need("out")},
                    {"size", evidence.size()}});
    } else {
        std::println("wrote the evidence of instance {} ({}) to {}", short_id(instance),
                     i.status.value_or("no status"), args.need("out"));
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// The registrar: proposed calls
// ---------------------------------------------------------------------------

int cmd_contract_propose(const Args& args) {
    std::optional<node::Peer> home;
    std::optional<Session> session;
    if (const auto peer = args.get("peer")) {
        if (args.has("server")) {
            throw UsageError{"give --peer (as a party) or --server (as the home's staff)"};
        }
        home = peer_named(args.ledger(), *peer);
    } else {
        session.emplace(args);
        if (!session->remote()) {
            throw UsageError{"propose to a home's registrar: --peer NAME as one of the instance's "
                             "parties, or --server URL as the home's staff"};
        }
    }
    node::PendingCall proposal;
    proposal.instance = home ? full_id(args.positional()[0], "INSTANCE")
                             : session->instance_id(args.positional()[0]);
    proposal.function = args.positional()[1];
    proposal.arguments = arguments_of(args);
    proposal.reference = args.get("reference");
    if (const auto head = args.get("head")) {
        proposal.head = parse_number(*head, "--head");
    } else if (home) {
        proposal.head = fetch_instance(*home, proposal.instance).second.instance.instance->head;
    } else {
        proposal.head = session->state().instance(proposal.instance)->head;
    }
    if (const auto days = args.get("days")) {
        const std::uint64_t n = parse_number(*days, "--days");
        if (n == 0 || n > 30) {
            throw UsageError{"--days is 1 to 30"};
        }
        proposal.until = ledger::SystemClock{}.now() + n * day_ms;
    }
    const Bytes encoded = unwrap(node::encode_call_proposal(proposal), "the proposal");
    Json answer;
    if (home) {
        answer = peer_call(*home, "POST", "/v1/contracts/calls", encoded);
    } else {
        const Bytes body =
            session->request("POST", "/v1/contracts/calls", encoded, "application/cbor");
        answer = Json::parse(body.begin(), body.end(), nullptr, false);
    }
    if (args.json()) {
        print_json(held_json(answer));
        return exit_ok;
    }
    std::optional<Session> local;
    if (session) {
        print_answer(&*session, "the registrar", answer);
    } else {
        local.emplace(args.ledger());
        print_answer(&*local, home->name, answer);
    }
    return exit_ok;
}

int cmd_contract_pending(const Args& args) {
    const std::optional<std::string> call =
        args.positional().empty() ? std::nullopt : std::optional(args.positional().front());
    if (call && call->size() != 2 * protocol::id_size) {
        throw UsageError{"CALL is a full call id (64 hex digits)"};
    }
    const std::string path = "/v1/contracts/calls" + (call ? "/" + *call : std::string());
    Json calls = Json::array();
    std::optional<Session> session;
    if (const auto peer = args.get("peer")) {
        if (args.has("server")) {
            throw UsageError{"give --peer (as a party) or --server (as the home's staff)"};
        }
        const node::Peer home = peer_named(args.ledger(), *peer);
        const Json answer = peer_call(home, "GET", path);
        for (const Json& h : call ? Json::array({answer}) : answer.value("calls", Json::array())) {
            calls.push_back(held_json(h));
        }
        session.emplace(args.ledger());
    } else {
        session.emplace(args);
        if (session->remote()) {
            const Bytes body = session->request("GET", path);
            const Json answer = Json::parse(body.begin(), body.end(), nullptr, false);
            for (const Json& h :
                 call ? Json::array({answer}) : answer.value("calls", Json::array())) {
                calls.push_back(held_json(h));
            }
        } else {
            // This ledger's registrar's files: the calls still current.
            const protocol::Timestamp now = ledger::SystemClock{}.now();
            for (const node::HeldCall& h : node::held_calls(session->directory())) {
                const protocol::InstanceState* i = session->state().instance(h.name.instance);
                const bool current =
                    i != nullptr && !i->final && i->head == h.name.head && h.call.until >= now;
                if (current && (!call || hex_id(h.name.id) == *call)) {
                    calls.push_back(local_held_json(*session, h));
                }
            }
            if (call && calls.empty()) {
                throw CommandError{"no pending call " + *call};
            }
        }
    }
    if (args.json()) {
        print_json(call ? calls.front() : calls);
        return exit_ok;
    }
    if (calls.empty()) {
        std::println("no pending calls");
    }
    for (const Json& h : calls) {
        print_held(*session, h);
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// A party: consenting on its own ledger
// ---------------------------------------------------------------------------

int cmd_contract_consent(const Args& args) {
    Session session(args);
    std::optional<node::Peer> home_peer;
    protocol::ContractConsent consent;
    if (const auto peer = args.get("peer")) {
        if (session.remote()) {
            throw UsageError{"--peer needs this ledger's directory; with --server give --home"};
        }
        home_peer = peer_named(session.directory(), *peer);
        consent.ledger = home_peer->ledger_id;
    } else {
        consent.ledger = full_id(args.need("home"), "--home");
    }
    std::optional<crypto::HashAlg> hash;
    if (const auto name = args.get("hash")) {
        hash = parse_hash(*name);
    }
    cbor::Value arguments;
    std::optional<std::string> claimed_digest;
    if (const auto call = args.get("call")) {
        // The terms of a call the home's registrar holds.
        if (!home_peer) {
            throw UsageError{"--call needs --peer (the instance's home)"};
        }
        for (const std::string_view option :
             {"instance", "function", "args", "args-cbor", "head", "evidence"}) {
            if (args.has(option)) {
                throw UsageError{
                    std::format("--call takes the terms from the home: drop --{}", option)};
            }
        }
        const Json held =
            peer_call(*home_peer, "GET", "/v1/contracts/calls/" + hex_id(full_id(*call, "--call")));
        consent.instance = full_id(held.value("instance", std::string()), "the call's instance");
        consent.head = held.value("head", std::uint64_t{0});
        consent.function = held.value("function", std::string());
        const auto bytes = from_hex(held.value("arguments", std::string()));
        if (!bytes) {
            throw CommandError{"peer " + home_peer->name + " sent arguments that are not hex"};
        }
        arguments = unwrap(cbor::decode(*bytes), "the call's arguments");
        claimed_digest = held.value("arguments_digest", std::string());
    } else {
        consent.instance = full_id(args.need("instance"), "--instance");
        consent.function = args.need("function");
        arguments = arguments_of(args);
        if (const auto head = args.get("head")) {
            consent.head = parse_number(*head, "--head");
        } else if (const auto evidence = args.get("evidence")) {
            protocol::VerifyOptions options;
            options.expected_ledger = consent.ledger;
            const auto report = unwrap(protocol::verify_contract_evidence(
                                           session.provider(), read_file(*evidence), options),
                                       "the instance's evidence does not verify");
            if (report.instance.record != consent.instance) {
                throw UsageError{"the evidence is of another instance"};
            }
            consent.head = report.instance.instance->head;
            hash = hash.value_or(report.instance.hash);
        } else if (home_peer) {
            const auto report = fetch_instance(*home_peer, consent.instance).second;
            consent.head = report.instance.instance->head;
            hash = hash.value_or(report.instance.hash);
        } else {
            throw UsageError{"give --call or --head, --evidence, or --peer (to ask the home)"};
        }
    }
    if (!hash) {
        if (!home_peer || !home_peer->url) {
            throw UsageError{"give --hash: the home's hash (sha256 or sm3), which the consent "
                             "hashes the arguments with"};
        }
        hash = hash_of_peer(*home_peer);
    }
    consent.arguments = unwrap(
        protocol::contract_arguments_digest(session.provider(), *hash, arguments), "the digest");
    if (claimed_digest && *claimed_digest != hex_id(consent.arguments)) {
        throw CommandError{"the home's call names other arguments than it sent; nothing recorded"};
    }
    const std::uint64_t days =
        args.has("days") ? parse_number(*args.get("days"), "--days") : std::uint64_t{7};
    consent.until = ledger::SystemClock{}.now() + days * day_ms;
    consent.reference = args.get("reference");

    IssueRequest request;
    request.record_type = std::string(protocol::contract_consent_type);
    request.fields.emplace_back("note", "consent to " + consent.function + " on instance " +
                                            short_id(consent.instance));
    request.metadata_value = unwrap(protocol::encode_contract_consent(consent), "the consent");
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id record = issue_record(session, *load_signer(args.need("as"), args), request);
    static_cast<void>(session.checkpoint(args));
    const Bytes bundle =
        unwrap(protocol::encode_bundle(session.evidence(args, record)), "encoding the consent");
    if (const auto out = args.get("out")) {
        write_file(*out, bundle, false);
    }
    Json result{{"consent", id_json(record)},
                {"home", id_json(consent.ledger)},
                {"instance", id_json(consent.instance)},
                {"function", consent.function},
                {"arguments", cbor::diagnostic(arguments)},
                {"arguments_digest", id_json(consent.arguments)},
                {"head", consent.head},
                {"until", iso_time(consent.until)}};
    std::optional<Json> answer;
    if (args.has("send")) {
        if (!home_peer) {
            throw UsageError{"--send needs --peer (the instance's home)"};
        }
        answer = peer_call(*home_peer, "POST", "/v1/contracts/consents", bundle);
        result["home_answer"] = *answer;
    }
    if (args.json()) {
        print_json(result);
        return exit_ok;
    }
    std::println("consented to {} on instance {} (head #{}) as record {}", consent.function,
                 short_id(consent.instance), consent.head, hex_id(record));
    std::println("  arguments: {}", shortened(cbor::diagnostic(arguments)));
    std::println("  lapses:    {}", format_time(consent.until));
    if (answer) {
        print_answer(&session, home_peer->name, *answer);
    }
    return exit_ok;
}

int cmd_contract_withdraw(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    if (session.state().record(record)->record_type != protocol::contract_consent_type) {
        throw UsageError{"record " + short_id(record) + " is not a contract consent"};
    }
    const protocol::Id id = session.submit(
        args, protocol::RecordTransitionBody{record, std::string(protocol::consent_given),
                                             std::string(protocol::consent_withdrawn)});
    return report_submitted(args, session, id, {{"consent", id_json(record)}},
                            "withdrew consent " + short_id(record));
}

int cmd_contract_send(const Args& args) {
    const node::Peer home = peer_named(args.ledger(), args.need("peer"));
    const Json answer =
        peer_call(home, "POST", "/v1/contracts/consents", read_file(args.positional().front()));
    if (args.json()) {
        print_json(answer);
        return exit_ok;
    }
    const Session session(args.ledger());
    print_answer(&session, home.name, answer);
    return exit_ok;
}

int cmd_contract_fetch(const Args& args) {
    const node::Peer home = peer_named(args.ledger(), args.need("peer"));
    const protocol::Id instance = full_id(args.need("instance"), "--instance");
    const auto [evidence, report] = fetch_instance(home, instance);
    write_file(args.need("out"), evidence, false);
    if (args.json()) {
        Json out = verifier::contract_report_json(report, true);
        out["out"] = args.need("out");
        print_json(out);
    } else {
        std::println("fetched the evidence of instance {} from {}: {} (verified), written to {}",
                     short_id(instance), home.name,
                     report.instance.instance->status.value_or("no status"), args.need("out"));
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// Anyone: verifying
// ---------------------------------------------------------------------------

int cmd_contract_verify(const Args& args) {
    const crypto::openssl::Provider provider;
    protocol::VerifyOptions options;
    if (const auto ledger_id = args.get("ledger-id")) {
        options.expected_ledger = full_id(*ledger_id, "--ledger-id");
    }
    for (const std::string& path : args.all("witness")) {
        options.trusted_witnesses.push_back(load_public_key(path));
    }
    const auto report =
        protocol::verify_contract_evidence(provider, read_file(args.positional().front()), options);
    if (!report) {
        if (args.json()) {
            print_json({{"verified", false}, {"error", report.error().detail}});
        } else {
            std::println("VERIFICATION FAILED: {}", report.error().detail);
        }
        return exit_not_verified;
    }
    std::vector<std::string> problems;
    const std::uint64_t min_witnesses =
        args.has("min-witnesses") ? parse_number(*args.get("min-witnesses"), "--min-witnesses") : 0;
    if (report->instance.trusted_cosignatures < min_witnesses) {
        problems.push_back(std::format("{} trusted witness cosignatures, {} required",
                                       report->instance.trusted_cosignatures, min_witnesses));
    }
    if (args.has("require-presence")) {
        for (const protocol::ContractStep& step : report->steps) {
            for (const protocol::ContractConsentCheck& c : step.consents) {
                if (c.report.events.empty() || !c.report.events.front().presence) {
                    problems.push_back("a consent of " + c.report.organization +
                                       " was given without proof of a person's presence");
                }
            }
        }
    }
    const bool verified = problems.empty();
    const bool checked = options.expected_ledger.has_value();
    if (args.json()) {
        Json out = verifier::contract_report_json(*report, checked);
        out["verified"] = verified;
        if (!verified) {
            out["error"] = problems.front();
        }
        print_json(out);
    } else {
        std::print("{}", verifier::contract_report_text(*report, checked));
        for (const std::string& p : problems) {
            std::println("\nVERIFICATION FAILED: {}", p);
        }
    }
    return verified ? exit_ok : exit_not_verified;
}

} // namespace cexchain::cli
