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
#include <map>
#include <print>
#include <span>
#include <variant>
#include <vector>

#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/peers.hpp>

#include "bo_support.hpp"
#include "commands.hpp"
#include "contracts.hpp"
#include "output.hpp"
#include "peers.hpp"
#include "records.hpp"
#include "requests.hpp"

namespace cexchain::cli {

namespace {

Json optional_text(const std::optional<std::string>& text) {
    return text ? Json(*text) : Json(nullptr);
}

std::string encoded_hex(const cbor::Value& value) {
    return to_hex(unwrap(cbor::encode(value), "encoding a value"));
}

std::string encoded_hex(const cbor::Encoded& value) {
    return to_hex(value.bytes());
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

/// The requests calls made (v0.8), by instance, each list in the order they
/// were made. The ledger keeps them in one table: scanned once per command.
using RequestsByInstance = std::map<protocol::IdKey, std::vector<const protocol::RequestState*>>;

RequestsByInstance requests_by_instance(const protocol::LedgerState& state) {
    RequestsByInstance out;
    for (const auto& [key, r] : state.requests()) {
        out[r.instance.key()].push_back(&r);
    }
    return out;
}

std::span<const protocol::RequestState* const> requests_of(const RequestsByInstance& requests,
                                                           const protocol::Id& instance) {
    const auto it = requests.find(protocol::key_of(instance));
    return it == requests.end() ? std::span<const protocol::RequestState* const>()
                                : std::span<const protocol::RequestState* const>(it->second);
}

Json call_json(const Session& session, std::uint64_t index, const protocol::SignedStatement& s,
               const protocol::ContractCallBody& call,
               std::span<const protocol::RequestState* const> requests) {
    // The requests it made on this instance (v0.8), and the one it answers.
    Json made = Json::array();
    for (const protocol::RequestState* r : requests) {
        if (r->call == index) {
            made.push_back(id_json(r->id));
        }
    }
    Json answer = nullptr;
    if (call.answer) {
        answer = {{"request", id_json(call.answer->request)},
                  {"status", std::string(protocol::name(call.answer->status))}};
        if (const protocol::RequestState* r = session.state().request(call.answer->request)) {
            answer["kind"] = r->kind;
            answer["late_by_ms"] = r->late_by();
        }
    }
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
            {"consents", std::move(consents)},
            {"requests", std::move(made)},
            {"answer", std::move(answer)}};
}

/// The instances calls created (v0.7), by parent, each list in the order
/// they were created. The ledger keeps no such index: the state is scanned
/// once per command.
using Children = std::map<protocol::IdKey, std::vector<const protocol::InstanceState*>>;

Children children_by_parent(const protocol::LedgerState& state) {
    Children out;
    for (const auto& [key, i] : state.instances()) {
        if (i.parent) {
            out[i.parent->key()].push_back(&i);
        }
    }
    return out;
}

std::span<const protocol::InstanceState* const> children_of(const Children& children,
                                                            const protocol::Id& parent) {
    const auto it = children.find(protocol::key_of(parent));
    return it == children.end() ? std::span<const protocol::InstanceState* const>()
                                : std::span<const protocol::InstanceState* const>(it->second);
}

Json instance_json_with(const Session& session, const protocol::InstanceState& i,
                        const Children& all_children, const RequestsByInstance& all_requests);

} // namespace

Json instance_json(const Session& session, const protocol::InstanceState& i) {
    return instance_json_with(session, i, children_by_parent(session.state()),
                              requests_by_instance(session.state()));
}

namespace {

Json instance_json_with(const Session& session, const protocol::InstanceState& i,
                        const Children& all_children, const RequestsByInstance& all_requests) {
    const auto requests = requests_of(all_requests, i.id);
    Json calls = Json::array();
    for (const std::uint64_t index : i.history) {
        const protocol::SignedStatement s = session.statement(index);
        if (const auto* call = std::get_if<protocol::ContractCallBody>(&s.statement.body)) {
            calls.push_back(call_json(session, index, s, *call, requests));
        }
    }
    // Its requests (v0.8): each with its answer, and which are open.
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    Json request_list = Json::array();
    for (const protocol::RequestState* r : requests) {
        request_list.push_back(request_json(session, *r, now));
    }
    Json open = Json::array();
    for (const protocol::CompactId& id : i.open_requests) {
        open.push_back(id_json(id));
    }
    // Its place among instances created by a call (v0.7): its ancestors,
    // oldest first, and the instances its calls created.
    Json ancestors = Json::array();
    for (const protocol::InstanceAncestor& a : protocol::instance_ancestors(session.state(), i)) {
        ancestors.push_back(id_json(a.instance->id));
    }
    Json children = Json::array();
    for (const protocol::InstanceState* child : children_of(all_children, i.id)) {
        children.push_back({{"id", id_json(child->id)},
                            {"position", child->position},
                            {"created_by", child->created_by},
                            {"status", optional_text(child->status)},
                            {"parties", parties_json(child->parties)},
                            {"final", child->final}});
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
            {"calls", std::move(calls)},
            {"parent", i.parent ? id_json(i.parent->id()) : Json(nullptr)},
            {"position", i.position},
            {"depth", i.depth},
            {"created_by", i.created_by},
            {"ancestors", std::move(ancestors)},
            {"children", std::move(children)},
            {"requests", std::move(request_list)},
            {"open_requests", std::move(open)}};
}

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
    if (i.parent) {
        std::println("parent:    {} (part {} of its call #{}; depth {})", hex_id(i.parent->id()),
                     i.position, i.created_by, i.depth);
        std::string chain;
        for (const protocol::InstanceAncestor& a :
             protocol::instance_ancestors(session.state(), i)) {
            chain += (chain.empty() ? "" : " > ") + short_id(a.instance->id) +
                     std::format(" ({})", a.instance->status.value_or("no status"));
        }
        std::println("ancestors: {} > this one", chain);
    }
    std::println("status:    {}{}", i.status.value_or("(none)"),
                 !i.final ? ""
                 : i.open_requests.empty()
                     ? " (final: it takes no more calls)"
                     : " (final: it takes only answers to its open requests)");
    print_parties(session, i.parties);
    std::println("state:     {}", shortened(cbor::diagnostic(i.state)));
    std::println("head:      #{} (calls and consents name it)", i.head);
    bool first_child = true;
    const Children children = children_by_parent(session.state());
    for (const protocol::InstanceState* child : children_of(children, i.id)) {
        std::string parties;
        for (const auto& [role, ledger] : child->parties) {
            parties +=
                (parties.empty() ? "; " : ", ") + role + ": " + ledger_label(session, ledger);
        }
        std::println("{}{} part {} of #{}: {}{}{}", first_child ? "children:  " : "           ",
                     hex_id(child->id), child->position, child->created_by,
                     child->status.value_or("(no status)"), parties,
                     child->final ? " (final)" : "");
        first_child = false;
    }
    // Its requests (v0.8): how many, and the open ones.
    const RequestsByInstance all_requests = requests_by_instance(session.state());
    const auto requests = requests_of(all_requests, i.id);
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    if (!requests.empty()) {
        const auto overdue = std::ranges::count_if(
            requests, [&](const auto* r) { return request_overdue(*r, now); });
        std::println("requests:  {} made by its calls, {} open{}", requests.size(),
                     i.open_requests.size(),
                     overdue > 0 ? std::format(", {} OVERDUE", overdue) : std::string());
        for (const protocol::CompactId& id : i.open_requests) {
            std::println("           {}", request_line(session, *session.state().request(id), now));
        }
    }
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
        // A child's first call is its parent's, which created it (v0.7).
        const bool on_parent = i.parent && index == i.created_by;
        std::println("  #{:<5} {}  {} {}{} by \"{}\"{}", index,
                     format_time(session.log_entry(index).registered_at),
                     on_parent ? "created by" : (call->instance ? "call" : "create with"),
                     call->function, on_parent ? " on the parent" : "",
                     session.actor_name(*s.statement.actor_id), consents);
        std::println("          arguments: {}", shortened(cbor::diagnostic(call->arguments)));
        if (call->answer) {
            const protocol::RequestState* r = session.state().request(call->answer->request);
            std::println(
                "          answers:   {} ({}): {}{}", short_id(call->answer->request),
                r != nullptr ? r->kind : std::string("?"), protocol::name(call->answer->status),
                r != nullptr && r->late_by() > 0 ? ", late by " + duration_text(r->late_by())
                                                 : std::string());
        }
        for (const protocol::RequestState* r : requests) {
            if (r->call == index) {
                std::println("          requests:  {} {}, due {}", short_id(r->id), r->kind,
                             format_time(r->deadline));
            }
        }
    }
}

/// Signs the call, runs its contract here as the ledger will, and records
/// it if the contract accepts it (or, with --dry-run, reports the run).
int record_call(const Args& args, Session& session, protocol::ContractCallBody body,
                const std::vector<Bytes>& bundles) {
    const auto signer = load_signer(args.need("as"), args);
    CallOptions options;
    options.delegation = args.get("delegation");
    options.provenance = session.provenance(args);
    options.dry_run = args.has("dry-run");
    if (!options.dry_run) {
        options.presence = presence_request(args);
    }
    if (const auto at = args.get("at")) {
        if (!options.dry_run) {
            throw UsageError{"--at needs --dry-run: a recorded call runs at the time the ledger "
                             "registers it"};
        }
        options.at = parse_time(*at);
    }
    const CallAttempt attempt = attempt_call(session, *signer, std::move(body), bundles, options);
    const protocol::ContractRun& run = attempt.run;
    const auto& call = std::get<protocol::ContractCallBody>(attempt.statement.statement.body);
    if (options.dry_run) {
        if (args.json()) {
            Json out = run_json(session, attempt);
            out["function"] = call.function;
            print_json(out);
            return exit_ok;
        }
        if (const protocol::ContractAccept* a = run.accepted(); a != nullptr && !attempt.refused) {
            std::println("the contract would accept {}: status {}{}", call.function,
                         a->status.value_or("(none)"), a->final ? ", final" : "");
            if (a->parties) {
                print_parties(session, *a->parties);
            }
            for (const protocol::ContractEvent& e : a->events) {
                std::println("event:     {} {}", e.name, shortened(cbor::diagnostic(e.data)));
            }
            std::println("state:     {}", shortened(cbor::diagnostic(a->state)));
            for (std::size_t n = 0; n < a->children.size(); ++n) {
                std::println("part {}:    {}; state {}", n,
                             a->children[n].status.value_or("(no status)"),
                             shortened(cbor::diagnostic(a->children[n].state)));
            }
        } else {
            std::println("it would not be recorded: {}", refusal(session, attempt));
        }
        std::println("fuel used: {}", run.outcome.fuel_used);
        return exit_ok;
    }
    if (!attempt.recorded) {
        std::string advice;
        if (!attempt.refused && run.output &&
            std::holds_alternative<protocol::ContractNeeds>(*run.output)) {
            advice = call.instance ? ": pass each party's consent with --consent (from contract "
                                     "consent), or propose the call to the registrar (contract "
                                     "propose)"
                                   : ": a creation takes no consents";
        }
        throw CommandError{refusal(session, attempt) + advice};
    }
    const protocol::Id id = *attempt.recorded;
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
    // The instances the call created (v0.7), in order.
    Json children = Json::array();
    for (const protocol::Id& child : created_children(session, id)) {
        const protocol::InstanceState& c = *session.state().instance(child);
        std::string parties;
        for (const auto& [role, ledger] : c.parties) {
            parties +=
                (parties.empty() ? "; " : ", ") + role + ": " + ledger_label(session, ledger);
        }
        text += std::format("\npart {}: {} {}{}", c.position, hex_id(child),
                            c.status.value_or("(no status)"), parties);
        children.push_back(id_json(child));
    }
    return report_submitted(args, session, id,
                            {{"instance", instance_json(session, now)},
                             {"children", std::move(children)},
                             {"fuel_used", run.outcome.fuel_used}},
                            text);
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
    // The instances the recorded call created (v0.7).
    if (answer.contains("children") && answer["children"].is_array()) {
        std::size_t n = 0;
        for (const Json& child : answer["children"]) {
            std::println("  part {}:       {}", n++,
                         child.is_string() ? child.get<std::string>() : std::string("?"));
        }
    }
}

} // namespace

// ---------------------------------------------------------------------------
// The home: contracts
// ---------------------------------------------------------------------------

int cmd_contract_deploy(const Args& args) {
    Session session(args);
    protocol::ContractDeployBody body;
    std::optional<Json> build;
    if (const auto bo_file = args.get("bo")) {
        // Bo: the build fills in everything the deploy records.
        if (!args.positional().empty()) {
            throw UsageError{"give a module (WASM) or --bo FILE, not both"};
        }
        for (const char* option : {"function", "compiler", "language", "source", "name"}) {
            if (args.has(option)) {
                throw UsageError{std::string("--bo fills in --") + option +
                                 " from the contract's source"};
            }
        }
        BoDeploy built = bo_deploy_body(args, *bo_file, session.provider(), session.state().hash());
        body = std::move(built.body);
        build = std::move(built.build);
    } else {
        if (args.positional().empty()) {
            throw UsageError{"give the module to deploy (WASM), or --bo FILE for Bo"};
        }
        if (args.has("pack") || args.has("vocab")) {
            throw UsageError{std::string("--") + (args.has("pack") ? "pack" : "vocab") +
                             " reads Bo source: use it with --bo"};
        }
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
        if (!args.has("compiler")) {
            throw UsageError{"missing required option --compiler (or deploy Bo with --bo)"};
        }
        body.compiler = args.need("compiler");
        if (const auto source = args.get("source")) {
            body.source = read_file(*source);
        }
        body.name = args.get("name");
    }
    const protocol::Id id = session.submit(args, body);
    const protocol::ContractState& c = *session.state().contract(id);
    std::string functions;
    for (const auto& [name, kind] : c.interface) {
        functions += (functions.empty() ? "" : ", ") + name +
                     (kind == protocol::FunctionKind::create ? " (creates)" : "");
    }
    Json extra = {{"contract", contract_json(session, c)}};
    std::string text = std::format("deployed contract {}{}\nfunctions: {}", hex_id(id),
                                   c.name ? " \"" + *c.name + "\"" : "", functions);
    if (build) {
        extra["build"] = *build;
        text += std::format("\nbuilt from {}: {} bytes of code, with {}; the source (Bo "
                            "edition {}) is recorded with it, so anyone can rebuild the code",
                            *args.get("bo"), (*build)["code_size"].get<std::size_t>(), c.compiler,
                            (*build)["edition"].get<std::uint64_t>());
    }
    return report_submitted(args, session, id, std::move(extra), text);
}

int cmd_contract_show(const Args& args) {
    Session session(args);
    const protocol::ContractState& c =
        *session.state().contract(session.contract_id(args.positional().front()));
    const protocol::ContractDeployBody deploy = deploy_of(session, c);
    // A Bo contract's source is checked against its code: rebuilt where this
    // build has the compiler.
    std::optional<SourceCheck> source_check;
    if (c.language == "bo") {
        source_check = check_bo_source(deploy, session.provider(), session.state().hash());
    }
    if (const auto out = args.get("code-out")) {
        write_file(*out, deploy.code, false);
    }
    if (const auto out = args.get("source-out")) {
        if (!deploy.source) {
            throw CommandError{"the contract was deployed without its source"};
        }
        if (source_check && source_check->bundle) {
            // The Bo source as written, from its bundle.
            write_file(*out, as_bytes(source_check->bundle->source), false);
        } else {
            write_file(*out, *deploy.source, false);
        }
    }
    if (const auto out = args.get("bundle-out")) {
        if (c.language != "bo" || !deploy.source) {
            throw CommandError{"only a contract written in Bo has a source bundle"};
        }
        write_file(*out, *deploy.source, false);
    }
    Json j = contract_json(session, c);
    if (source_check) {
        j["bo"] = source_check_json(*source_check, deploy);
    }
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
    if (source_check) {
        std::println("            {}", bundle_text(*source_check));
        std::println("rebuild:    {}", source_check_text(*source_check));
    }
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
    protocol::ContractCallBody body =
        creation_call(session, args.positional()[0], args.positional()[1]);
    body.arguments = contract_arguments_of(args);
    body.reference = args.get("reference");
    return record_call(args, session, std::move(body), {});
}

int cmd_contract_call(const Args& args) {
    Session session(args);
    protocol::ContractCallBody body =
        instance_call(session, args.positional()[0], args.positional()[1]);
    body.arguments = contract_arguments_of(args);
    body.reference = args.get("reference");
    const std::vector<Bytes> bundles = cite_consents(session, body, args.all("consent"));
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
    const std::optional<protocol::Id> parent =
        args.has("parent") ? std::optional(session.instance_id(*args.get("parent"))) : std::nullopt;
    Json out = Json::array();
    const Children children = args.json() ? children_by_parent(session.state()) : Children();
    const RequestsByInstance requests =
        args.json() ? requests_by_instance(session.state()) : RequestsByInstance();
    for (const auto& [key, i] : session.state().instances()) {
        if ((contract && !(i.contract == *contract)) || (status && i.status != *status) ||
            (args.has("open") && i.final) || (parent && !(i.parent && *i.parent == *parent)) ||
            (party &&
             std::ranges::none_of(i.parties, [&](const auto& p) { return p.second == *party; }))) {
            continue;
        }
        if (args.json()) {
            out.push_back(instance_json_with(session, i, children, requests));
            continue;
        }
        std::string parties;
        for (const auto& [role, ledger] : i.parties) {
            parties += (parties.empty() ? "" : ", ") + role + ": " + ledger_label(session, ledger);
        }
        std::println("{}  {:<12} head #{:<6} of {}; {}{}{}", short_id(i.id), i.status.value_or("-"),
                     i.head, contract_label(session, i.contract),
                     parties.empty() ? std::string("no parties") : parties,
                     i.final ? " (final)" : "",
                     i.parent ? std::format("; part {} of {}, depth {}", i.position,
                                            short_id(i.parent->id()), i.depth)
                              : std::string());
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
    proposal.arguments = contract_arguments_of(args);
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
        calls = pending_at(peer_named(args.ledger(), *peer), call);
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
    if (const auto peer = args.get("peer")) {
        if (session.remote()) {
            throw UsageError{"--peer needs this ledger's directory; with --server give --home"};
        }
        home_peer = peer_named(session.directory(), *peer);
    } else if (args.has("send")) {
        throw UsageError{"--send needs --peer (the instance's home)"};
    }
    std::optional<crypto::HashAlg> hash;
    if (const auto name = args.get("hash")) {
        hash = parse_hash(*name);
    }
    HeldTerms terms;
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
        terms = held_call_terms(session, *home_peer, full_id(*call, "--call"), hash);
    } else {
        protocol::ContractConsent& consent = terms.consent;
        consent.ledger = home_peer ? home_peer->ledger_id : full_id(args.need("home"), "--home");
        consent.instance = full_id(args.need("instance"), "--instance");
        consent.function = args.need("function");
        terms.arguments = contract_arguments_of(args);
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
        if (!hash) {
            if (!home_peer) {
                throw UsageError{"give --hash: the home's hash (sha256 or sm3), which the consent "
                                 "hashes the arguments with"};
            }
            hash = home_hash(*home_peer, consent.instance);
        }
        consent.arguments =
            unwrap(protocol::contract_arguments_digest(session.provider(), *hash, terms.arguments),
                   "the digest");
    }
    ConsentOptions options;
    if (const auto days = args.get("days")) {
        options.days = parse_number(*days, "--days");
    }
    options.reference = args.get("reference");
    options.delegation = args.get("delegation");
    options.provenance = session.provenance(args);
    options.presence = presence_request(args);
    const protocol::ContractConsent& consent = terms.consent;
    const GivenConsent given =
        give_consent(session, *load_signer(args.need("as"), args), terms.consent, options, args);
    if (const auto out = args.get("out")) {
        write_file(*out, given.bundle, false);
    }
    Json result = consent_json(given.record, consent, terms.arguments);
    std::optional<Json> answer;
    if (args.has("send")) {
        answer = peer_call(*home_peer, "POST", "/v1/contracts/consents", given.bundle);
        result["home_answer"] = *answer;
    }
    if (args.json()) {
        print_json(result);
        return exit_ok;
    }
    std::println("consented to {} on instance {} (head #{}) as record {}", consent.function,
                 short_id(consent.instance), consent.head, hex_id(given.record));
    std::println("  arguments: {}", shortened(cbor::diagnostic(terms.arguments)));
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
    // Requests open past their deadline at the checkpoint's time (v0.8):
    // work nobody answered in time. Open ones not yet due are work in
    // progress and pass.
    if (args.has("require-answered")) {
        const protocol::InstanceReport& i = *report->instance.instance;
        if (const auto overdue = i.overdue_requests(); !overdue.empty()) {
            std::string ids;
            for (const std::size_t n : overdue) {
                ids += (ids.empty() ? "" : ", ") + short_id(i.requests[n].id) + " (" +
                       i.requests[n].kind + ")";
            }
            problems.push_back(
                std::format("{} request(s) still open past their deadline at the checkpoint: {}",
                            overdue.size(), ids));
        }
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
    // A contract written in Bo: its source, rebuilt and compared with its
    // code (where this build has the compiler).
    const protocol::InstanceReport& instance = *report->instance.instance;
    std::optional<protocol::ContractDeployBody> deploy;
    std::optional<SourceCheck> source_check;
    if (instance.language == "bo") {
        deploy = protocol::ContractDeployBody{instance.code,     instance.interface,
                                              instance.language, instance.compiler,
                                              instance.source,   instance.contract_name};
        source_check = check_bo_source(*deploy, provider, report->instance.hash);
        if (source_check->failed) {
            problems.push_back(source_check->status == "differs"
                                   ? "the contract's source does not rebuild to its code"
                                   : "the contract's Bo source is malformed");
        }
    }
    if (args.has("require-rebuild")) {
        if (!source_check) {
            problems.push_back("the contract is written in " + instance.language +
                               ", not Bo: nothing rebuilds its code from a source");
        } else if (source_check->status != "rebuilds" && !source_check->failed) {
            problems.push_back("the contract's source was not rebuilt to its code");
        }
    }
    const bool verified = problems.empty();
    const bool checked = options.expected_ledger.has_value();
    if (args.json()) {
        Json out = verifier::contract_report_json(*report, checked);
        if (source_check) {
            out["source"] = source_check_json(*source_check, *deploy);
        }
        out["verified"] = verified;
        if (!verified) {
            out["error"] = problems.front();
        }
        print_json(out);
    } else {
        std::print("{}", verifier::contract_report_text(*report, checked));
        if (source_check) {
            std::println("\n  Source       {}", bundle_text(*source_check));
            std::println("               {}", source_check_text(*source_check));
        }
        for (const std::string& p : problems) {
            std::println("\nVERIFICATION FAILED: {}", p);
        }
    }
    return verified ? exit_ok : exit_not_verified;
}

int cmd_contract_explain(const Args& args) {
    Session session(args);
    const std::string wanted = args.positional().front();
    // CONTRACT, or an INSTANCE of one: its contract's text, with the
    // instance's status, parties, and state.
    const protocol::InstanceState* instance = nullptr;
    protocol::Id contract_id;
    try {
        contract_id = session.contract_id(wanted);
    } catch (const CommandError&) {
        instance = session.state().instance(session.instance_id(wanted));
        contract_id = instance->contract;
    }
    const protocol::ContractState& c = *session.state().contract(contract_id);
    if (c.language != "bo") {
        throw CommandError{"contract " + hex_id(c.id) + " is written in " + c.language +
                           ", not Bo: only a contract written in Bo has a contract text"};
    }
    const protocol::ContractDeployBody deploy = deploy_of(session, c);
    const DeployText text =
        explain_deploy(deploy, session.provider(), session.state().hash(), args.get("language"));
    Json j = {{"contract", id_json(c.id)},
              {"name", optional_text(c.name)},
              {"source", source_check_json(text.check, deploy)},
              {"explained", text.explained.has_value()}};
    // An instance's state in the text's words: its state and fields, read
    // by the contract's types, parties named as this ledger knows them.
    std::optional<bo::ExplainedState> values;
    if (instance != nullptr && text.model && text.explained) {
        const bo::Pack* language =
            bo::find_language(bo::official_packs(), text.explained->language);
        values =
            bo::explain_state(*text.model, instance->state.value(), language, [&](ByteView ledger) {
                const auto id = protocol::Id::from_bytes(ledger);
                return id ? ledger_label(session, *id) : to_hex(ledger);
            });
    }
    if (instance != nullptr) {
        j["instance"] = {{"id", id_json(instance->id)},
                         {"status", optional_text(instance->status)},
                         {"final", instance->final},
                         {"parties", parties_json(instance->parties)},
                         {"state", cbor::diagnostic(instance->state)}};
        if (values) {
            Json fields = Json::array();
            for (const bo::ExplainedValue& v : values->fields) {
                fields.push_back({{"field", v.field}, {"value", v.value}});
            }
            j["instance"]["state_text"] = values->state;
            j["instance"]["fields"] = std::move(fields);
        }
    }
    if (!text.explained) {
        // The parties confirm the text of the code that runs: a source that
        // does not rebuild to it has no text here.
        const std::string why =
            text.check.failed
                ? "its source does not rebuild to its code, so a text of it would not be the "
                  "text of the code that runs"
                : "its source was not rebuilt to its code here, so a text of it could not be "
                  "confirmed as the text of the code that runs";
        if (args.json()) {
            j["error"] = why;
            print_json(j);
        } else {
            std::println("contract {}: no contract text: {}", hex_id(c.id), why);
            std::println("rebuild:  {}", source_check_text(text.check));
        }
        return text.check.failed ? exit_not_verified : exit_failure;
    }
    if (args.json()) {
        j.update(explained_json(*text.explained));
        print_json(j);
        return exit_ok;
    }
    std::println("contract:  {}{}", hex_id(c.id), c.name ? " (" + *c.name + ")" : "");
    std::println("rebuild:   {}", source_check_text(text.check));
    if (instance != nullptr) {
        std::println("instance:  {}", hex_id(instance->id));
        std::println("status:    {}{}", instance->status.value_or("(none)"),
                     instance->final ? " (final: it takes no more calls)" : "");
        print_parties(session, instance->parties);
        std::println("state:     {}", values && !values->state.empty()
                                          ? values->state
                                          : shortened(cbor::diagnostic(instance->state)));
        for (std::size_t i = 0; values && i < values->fields.size(); ++i) {
            std::println("{}{}: {}", i == 0 ? "fields:    " : "           ",
                         values->fields[i].field, values->fields[i].value);
        }
    }
    std::println("");
    std::print("{}", text.explained->text);
    return exit_ok;
}

} // namespace cexchain::cli
