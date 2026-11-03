// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Contracts: WebAssembly modules deployed on a ledger, their home,
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

#include <cexchain/app/peers.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/deploy_file.hpp>
#include <cexchain/core/protocol/exchange.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/peers.hpp>

#include "commands.hpp"
#include "contracts.hpp"
#include "output.hpp"
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
    const InstanceChildren children = children_by_parent(session.state());
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
    const std::string path = args.positional().front();
    const Bytes file = read_file(path);
    // A deploy file (a compiler's output, such as bo build --out's FILE.boc,
    // or contract export's) carries everything the deploy records: a CBOR
    // map, where a module starts with \0asm.
    const bool deploy_file = !file.empty() && (file.front() & 0xe0) == 0xa0;
    if (deploy_file) {
        for (const char* option : {"function", "compiler", "language", "source", "name"}) {
            if (args.has(option)) {
                throw UsageError{std::string("a deploy file has its own --") + option +
                                 "; give options with a module (WASM)"};
            }
        }
        protocol::DeployFile deploy =
            unwrap(protocol::decode_deploy_file(file), path + " is not a deploy file or a module");
        if (deploy.hash != session.state().hash()) {
            throw CommandError{path + "'s digests are made with " +
                               std::string(crypto::name(deploy.hash)) + ", this ledger's with " +
                               std::string(crypto::name(session.state().hash())) +
                               ": build it again for this ledger"};
        }
        body = std::move(deploy.body);
        static_cast<void>(unwrap(vm::load(body.code), path + "'s code is not a contract module"));
    } else {
        body.code = file;
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
            throw UsageError{"missing required option --compiler (or give a deploy file)"};
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
    if (body.source) {
        text += std::format("\nwritten in {}, built with {}: its source is recorded with it, so "
                            "anyone can rebuild the code",
                            c.language, c.compiler);
    }
    return report_submitted(args, session, id, std::move(extra), text);
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
    Json j = contract_json(session, c);
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
    std::println("source:     {}",
                 deploy.source ? std::format("{} bytes (contract export, then rebuild it with its "
                                             "language's tools)",
                                             deploy.source->size())
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
    // Consent files carry the call's arguments: without --args, they are
    // taken from them (all must name the same).
    if (!args.has("args") && !args.has("args-cbor")) {
        std::optional<cbor::Value> given;
        for (const std::string& path : args.all("consent")) {
            const ConsentInput input = read_consent_input(read_file(path));
            if (!input.file) {
                continue;
            }
            if (given && *given != input.file->arguments) {
                throw UsageError{"the consent files name different arguments"};
            }
            given = input.file->arguments;
        }
        if (given) {
            body.arguments = *given;
        }
    }
    body.reference = args.get("reference");
    const std::vector<Bytes> bundles = cite_consents(session, body, args.all("consent"));
    return record_call(args, session, std::move(body), bundles);
}

int cmd_contract_instance(const Args& args) {
    Session session(args);
    const protocol::InstanceState& i =
        *session.state().instance(session.instance_id(args.positional().front()));
    // Its state as CBOR, for the contract's language's tools (bo explain).
    if (const auto out = args.get("state-out")) {
        const ByteView state = i.state.bytes();
        write_file(*out, Bytes(state.begin(), state.end()), false);
    }
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
    const InstanceChildren children =
        args.json() ? children_by_parent(session.state()) : InstanceChildren();
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
// Proposal and consent files (.cexchain)
// ---------------------------------------------------------------------------

int cmd_contract_proposal(const Args& args) {
    Session session(args);
    protocol::ContractCallBody body =
        instance_call(session, args.positional()[0], args.positional()[1]);
    body.arguments = contract_arguments_of(args);
    const protocol::Id instance = *body.instance;
    // The call run first, as for a dry run: whose consents does it wait for?
    CallOptions options;
    options.delegation = args.get("delegation");
    options.dry_run = true;
    const auto signer = load_signer(args.need("as"), args);
    const CallAttempt attempt = attempt_call(session, *signer, body, {}, options);
    const auto* needs = attempt.run.output && !attempt.refused
                            ? std::get_if<protocol::ContractNeeds>(&*attempt.run.output)
                            : nullptr;
    if (needs == nullptr) {
        if (attempt.run.accepted() != nullptr && !attempt.refused) {
            throw ActionError{"the call needs no other party's consent: make it (contract call)"};
        }
        throw ActionError{"the call would not be recorded: " + refusal(session, attempt)};
    }
    protocol::ExchangeFile file;
    file.kind = protocol::ExchangeKind::proposal;
    file.home = session.state().ledger_id();
    file.instance = instance;
    file.head = *body.head;
    file.function = body.function;
    file.arguments = body.arguments;
    file.hash = session.state().hash();
    file.needs.assign(needs->ledgers.begin(), needs->ledgers.end());
    file.note = args.get("note");
    file.evidence = session.contract_evidence(args, instance);
    const Bytes encoded = unwrap(protocol::encode_exchange_file(file), "the proposal file");
    write_file(args.need("out"), encoded, false);
    Json ledgers = Json::array();
    for (const protocol::Id& l : file.needs) {
        ledgers.push_back(id_json(l));
    }
    if (args.json()) {
        print_json({{"instance", id_json(instance)},
                    {"head", file.head},
                    {"function", file.function},
                    {"arguments", cbor::diagnostic(file.arguments)},
                    {"needs", ledgers},
                    {"out", args.need("out")},
                    {"size", encoded.size()}});
        return exit_ok;
    }
    std::println("wrote a proposal of {} on {} to {}: it waits for the consent of {}",
                 file.function, short_id(instance), args.need("out"),
                 ledgers_text(session, ledgers));
    return exit_ok;
}

int cmd_contract_file_show(const Args& args) {
    const std::string path = args.positional().front();
    const auto file = unwrap(protocol::decode_exchange_file(read_file(path)),
                             path + " is not a proposal or consent file");
    const crypto::openssl::Provider provider;
    Json out{{"file", path},
             {"kind", std::string(protocol::name(file.kind))},
             {"home", id_json(file.home)},
             {"instance", id_json(file.instance)},
             {"head", file.head},
             {"function", file.function},
             {"arguments", cbor::diagnostic(file.arguments)},
             {"hash", crypto::name(file.hash)},
             {"note", optional_text(file.note)}};
    if (file.kind == protocol::ExchangeKind::proposal) {
        const ProposalTerms terms = check_proposal(provider, file);
        const protocol::EvidenceReport& home = terms.report.instance;
        Json needs = Json::array();
        for (const protocol::Id& l : file.needs) {
            needs.push_back(id_json(l));
        }
        out["verified"] = true;
        out["organization"] = home.organization;
        out["contract"] = optional_text(home.instance->contract_name);
        out["status"] = optional_text(home.instance->status);
        out["needs"] = std::move(needs);
    } else {
        const protocol::Id ledger =
            unwrap(protocol::bundle_ledger_id(file.evidence), path + ": its consent's bundle");
        protocol::VerifyOptions options;
        options.expected_ledger = ledger;
        const auto report = unwrap(ledger::verify_bundle(provider, file.evidence, options),
                                   path + ": its consent does not verify");
        if (report.record_type != protocol::contract_consent_type || !report.metadata) {
            throw ActionError{path + " carries no contract consent"};
        }
        const auto consent = unwrap(protocol::decode_contract_consent(*report.metadata),
                                    path + ": the consent's terms");
        const auto digest = unwrap(
            protocol::contract_arguments_digest(provider, file.hash, file.arguments), "the digest");
        if (consent.ledger != file.home || consent.instance != file.instance ||
            consent.function != file.function || consent.head != file.head ||
            consent.arguments != digest) {
            throw ActionError{path + ": the consent's terms are not the file's"};
        }
        out["verified"] = true;
        out["from"] = id_json(ledger);
        out["organization"] = report.organization;
        out["consent"] = id_json(report.record);
        out["until"] = iso_time(consent.until);
    }
    if (args.json()) {
        print_json(out);
        return exit_ok;
    }
    std::println("{} {}, verified", out["kind"].get<std::string>(), path);
    std::println("call:      {} on {} at head #{}", file.function, short_id(file.instance),
                 file.head);
    std::println("arguments: {}", cbor::diagnostic(file.arguments));
    if (file.kind == protocol::ExchangeKind::proposal) {
        std::println("home:      {} ({})", out["organization"].get<std::string>(),
                     short_id(file.home));
        std::println("waits for: {}", out["needs"].dump());
    } else {
        std::println("from:      {} ({}), until {}", out["organization"].get<std::string>(),
                     out["from"].get<std::string>().substr(0, 12), out["until"].get<std::string>());
    }
    if (file.note) {
        std::println("note:      {}", *file.note);
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
    // A home reached through its relay: as this ledger, with --log-key.
    std::optional<Session> own;
    std::optional<RelayReach> reach;
    if (home && args.has("log-key")) {
        own.emplace(args);
        reach.emplace(args, *own);
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
    const RelayReach reach(args, session);
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
    std::optional<protocol::ExchangeFile> proposal;
    if (const auto file = args.get("proposal")) {
        // The terms of a proposal file, checked against its evidence.
        for (const std::string_view option : {"call", "instance", "function", "args", "args-cbor",
                                              "head", "evidence", "home", "hash"}) {
            if (args.has(option)) {
                throw UsageError{
                    std::format("--proposal takes the terms from the file: drop --{}", option)};
            }
        }
        proposal = unwrap(protocol::decode_exchange_file(read_file(*file)),
                          *file + " is not a proposal file");
        ProposalTerms checked = check_proposal(session.provider(), *proposal);
        terms.consent = checked.consent;
        terms.arguments = std::move(checked.arguments);
    } else if (const auto call = args.get("call")) {
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
            const auto report =
                unwrap(ledger::verify_contract_evidence(session.provider(), read_file(*evidence),
                                                        options, on_all_cores()),
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
        // Answering a proposal file: a consent file, with the terms; else the
        // consent's evidence bundle alone.
        write_file(
            *out,
            proposal ? unwrap(protocol::encode_exchange_file(consent_file(*proposal, given.bundle)),
                              "the consent file")
                     : given.bundle,
            false);
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
    std::optional<Session> own;
    std::optional<RelayReach> reach;
    if (args.has("log-key")) {
        own.emplace(args);
        reach.emplace(args, *own);
    }
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
    std::optional<Session> own;
    std::optional<RelayReach> reach;
    if (args.has("log-key")) {
        own.emplace(args);
        reach.emplace(args, *own);
    }
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
    const auto report = ledger::verify_contract_evidence(
        provider, read_file(args.positional().front()), options, on_all_cores());
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
    // The deploy the evidence carries, as a file for its language's tools
    // (bo rebuild compares a Bo contract's source with its code).
    if (const auto out = args.get("deploy-out")) {
        const protocol::InstanceReport& i = *report->instance.instance;
        const protocol::DeployFile file{
            {i.code, i.interface, i.language, i.compiler, i.source, i.contract_name},
            report->instance.hash};
        write_file(*out, unwrap(protocol::encode_deploy_file(file), "the deploy file"), false);
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

int cmd_contract_export(const Args& args) {
    Session session(args);
    const protocol::ContractState& c =
        *session.state().contract(session.contract_id(args.positional().front()));
    // The deploy as a file, as a compiler writes one: another tool (bo
    // rebuild, for Bo) rebuilds or explains it from there.
    const protocol::ContractDeployBody deploy = deploy_of(session, c);
    const protocol::DeployFile file{deploy, session.state().hash()};
    const Bytes encoded = unwrap(protocol::encode_deploy_file(file), "the deploy file");
    const std::string out = args.need("out");
    write_file(out, encoded, false);
    if (args.json()) {
        print_json({{"contract", id_json(c.id)},
                    {"file", out},
                    {"bytes", encoded.size()},
                    {"language", c.language},
                    {"source", deploy.source.has_value()}});
        return exit_ok;
    }
    std::println("wrote {}: contract {} ({}, {} bytes){}", out, hex_id(c.id), c.language,
                 encoded.size(), deploy.source ? ", with its source" : "");
    return exit_ok;
}

} // namespace cexchain::cli
