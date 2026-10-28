// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Things with rules: what a contract's calls take, a thing's page, and the
// calls a person makes (a creation, an action, a time rule, an answer to a
// request), each built here and run on the node's state before the tap, so
// that the page shows what the ledger will decide. The compiler, in a child
// process, describes the calls and builds their arguments from what the
// person filled in; the contract itself runs in the node, as the ledger runs
// it.

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/bo/calls.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/node/keeper.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view instances_prefix = "/console/api/instances/";

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

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

bool known_language(std::string_view language) {
    return language == "en" || language == "zh-Hant-HK" || language == "zh-Hans-CN";
}

/// The reader's language from ?language= (or a body's "language"), else
/// English.
std::string language_of(std::string_view asked) {
    return known_language(asked) ? std::string(asked) : std::string("en");
}

nlohmann::json optional_text(const std::optional<std::string>& text) {
    return text ? nlohmann::json(*text) : nlohmann::json();
}

/// What a contract's run decided, for people: accept (the state after, its
/// events, final or not), needs (the ledgers whose consents it waits for),
/// or refuse (the contract's reason, in the reader's words, or the
/// ledger's).
nlohmann::json verdict_json(const protocol::LedgerState& state, const protocol::ContractRun& run,
                            const protocol::ContractCallBody& call,
                            const std::optional<std::string>& ledger_refusal,
                            protocol::Timestamp now, const std::string& language) {
    nlohmann::json out{{"fuel_used", run.outcome.fuel_used}};
    std::optional<std::string> refused = ledger_refusal;
    const protocol::ContractAccept* accept = run.accepted();
    if (accept != nullptr && !refused) {
        Status allowed = state.check_children(call, *accept);
        if (allowed) {
            allowed = state.check_requests(call, *accept, now);
        }
        if (!allowed) {
            refused = "the ledger refuses the call: " + std::string(allowed.error().detail);
        }
    }
    if (accept != nullptr && !refused) {
        nlohmann::json events = nlohmann::json::array();
        for (const protocol::ContractEvent& e : accept->events) {
            events.push_back(e.name);
        }
        out["verdict"] = "accept";
        out["status"] = optional_text(accept->status);
        out["events"] = std::move(events);
        out["final"] = accept->final;
        out["requests"] = accept->requests.size();
        return out;
    }
    if (const auto* needs =
            run.output && !refused ? std::get_if<protocol::ContractNeeds>(&*run.output) : nullptr) {
        nlohmann::json ledgers = nlohmann::json::array();
        for (const protocol::Id& l : needs->ledgers) {
            ledgers.push_back(hex_of(l));
        }
        out["verdict"] = "needs";
        out["needs"] = std::move(ledgers);
        out["reason"] = "the call waits for the consent of other parties on their own ledgers";
        return out;
    }
    out["verdict"] = "refuse";
    if (refused) {
        out["reason"] = *refused;
    } else if (run.outcome.trap && *run.outcome.trap == vm::Trap::aborted) {
        const std::string reason(run.outcome.abort_reason.begin(), run.outcome.abort_reason.end());
        const bo::Pack* pack = bo::find_language(bo::official_packs(), language);
        const auto words = bo::render_reason(reason, pack);
        out["reason"] = words ? *words : reason;
        out["code"] = reason;
    } else if (run.outcome.trap) {
        out["reason"] =
            "the contract trapped on the call (" + std::string(vm::name(*run.outcome.trap)) + ")";
    } else {
        out["reason"] = "the contract's answer does not read";
    }
    return out;
}

} // namespace

std::optional<Bytes> Console::deployed_boc(const protocol::Id& contract) const {
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return std::nullopt;
    }
    std::optional<std::uint64_t> index;
    served->read_state([&](const protocol::LedgerState& state) {
        if (const protocol::ContractState* c = state.contract(contract); c && c->language == "bo") {
            index = c->deployed_at_index;
        }
    });
    if (!index) {
        return std::nullopt;
    }
    std::optional<Bytes> out;
    static_cast<void>(served->visit_entry(*index, [&](ByteView bytes) {
        const auto entry = protocol::decode_log_entry(bytes);
        if (!entry) {
            return;
        }
        const auto parsed =
            protocol::parse_statement(*services_.provider, entry->statement, served->hash());
        const auto* deploy =
            parsed ? std::get_if<protocol::ContractDeployBody>(&parsed->statement.body) : nullptr;
        if (deploy == nullptr || !deploy->source) {
            return;
        }
        const bo::BuiltContract built{deploy->code,    deploy->interface,         deploy->compiler,
                                      *deploy->source, deploy->name.value_or(""), served->hash()};
        if (auto encoded = bo::encode_built(built)) {
            out = std::move(*encoded);
        }
    }));
    return out;
}

std::variant<nlohmann::json, http::Response>
Console::contract_calls(const Signed& who, const protocol::Id& contract,
                        const std::string& language, const std::vector<std::string>& more) const {
    const auto boc = deployed_boc(contract);
    if (!boc) {
        return error(404, "not_found", "no contract written in Bo with that id on this ledger");
    }
    std::vector<std::string> args{"calls", "contract.boc", "--language", language};
    args.insert(args.end(), more.begin(), more.end());
    auto ran = run_compiler(who, std::move(args),
                            {{"contract.boc", std::string(boc->begin(), boc->end())}});
    if (auto* refused = std::get_if<http::Response>(&ran)) {
        return std::move(*refused);
    }
    nlohmann::json answer = std::get<CompilerRun>(std::move(ran)).answer;
    if (!answer.is_object() || !answer.value("ok", false)) {
        return error(422, "verification_failed",
                     "the contract's source does not check with this console's compiler");
    }
    return answer;
}

http::Response Console::contract_route(const Signed& who, const protocol::Id& contract,
                                       const http::Request& request) const {
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    nlohmann::json facts;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ContractState* c = state.contract(contract);
        if (c == nullptr) {
            return;
        }
        std::size_t instances = 0;
        for (const auto& [key, i] : state.instances()) {
            instances += protocol::Id(i.contract) == contract ? 1U : 0U;
        }
        facts = {{"id", hex_of(contract)},  {"name", optional_text(c->name)},
                 {"language", c->language}, {"compiler", c->compiler},
                 {"retired", c->retired},   {"index", c->deployed_at_index},
                 {"instances", instances}};
    });
    if (facts.is_null()) {
        return error(404, "not_found", "no such contract on this ledger");
    }
    const auto asked = request.query.find("language");
    auto calls = contract_calls(who, contract,
                                language_of(asked != request.query.end() ? asked->second : ""));
    if (std::holds_alternative<http::Response>(calls)) {
        // A contract the console cannot describe is still shown.
        return json(200, {{"contract", facts}, {"calls", nullptr}});
    }
    return json(200, {{"contract", facts}, {"calls", std::get<nlohmann::json>(calls)["calls"]}});
}

http::Response Console::instance_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    if (request.method != "GET") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET");
        return refused;
    }
    const Signed& signer = std::get<Signed>(who);
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const auto id = id_of(std::string_view(request.path).substr(instances_prefix.size()));
    if (!id) {
        return error(400, "invalid_argument", "an instance id is 64 hex digits");
    }
    const auto asked = request.query.find("language");
    const std::string language = language_of(asked != request.query.end() ? asked->second : "");
    const protocol::Timestamp now = services_.clock->now();

    nlohmann::json instance;
    nlohmann::json requests = nlohmann::json::array();
    nlohmann::json due = nlohmann::json::array();
    std::vector<std::uint64_t> history;
    std::optional<protocol::Id> contract;
    Bytes state_bytes;
    std::vector<std::string> labels;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::InstanceState* i = state.instance(*id);
        if (i == nullptr) {
            return;
        }
        contract = protocol::Id(i->contract);
        const protocol::ContractState* c = state.contract(*contract);
        nlohmann::json parties = nlohmann::json::array();
        for (const auto& [role, ledger] : i->parties) {
            const bool ours = ledger == state.ledger_id();
            parties.push_back(
                {{"role", role},
                 {"ledger", hex_of(ledger)},
                 {"ours", ours},
                 {"label", ours ? nlohmann::json(state.organization()) : nlohmann::json()}});
            if (ours) {
                labels.push_back("--label");
                labels.push_back(to_hex(ledger.bytes()) + "=" + state.organization());
            }
        }
        instance = {{"id", hex_of(*id)},
                    {"contract", hex_of(*contract)},
                    {"contract_name", c != nullptr ? optional_text(c->name) : nlohmann::json()},
                    {"retired", c != nullptr && c->retired},
                    {"status", optional_text(i->status)},
                    {"final", i->final},
                    {"head", i->head},
                    {"created_by", i->created_by},
                    {"depth", i->depth},
                    {"parties", std::move(parties)}};
        for (const auto& open : i->open_requests) {
            const protocol::RequestState* r = state.request(protocol::Id(open));
            if (r == nullptr) {
                continue;
            }
            requests.push_back({{"id", hex_of(r->id)},
                                {"kind", r->kind},
                                {"params", cbor::diagnostic(r->params)},
                                {"deadline", r->deadline},
                                {"asked_at", r->asked_at},
                                {"reply", r->reply},
                                {"overdue", now >= r->deadline}});
        }
        history.assign(i->history.begin(), i->history.end());
        state_bytes = Bytes(i->state.bytes().begin(), i->state.bytes().end());
        // The time rules due now on this instance, as a keeper would find
        // them; the person may call them.
        node::DueOptions options;
        options.now = now;
        options.instance = *id;
        options.expiries = false;
        options.parallel = false;
        if (auto work = node::find_due(*services_.provider, state, options)) {
            for (const node::DueRule& rule : work->rules) {
                due.push_back(
                    {{"function", rule.function},
                     {"time", rule.time ? nlohmann::json(*rule.time) : nlohmann::json()}});
            }
        }
    });
    if (!contract) {
        return error(404, "not_found", "no such instance on this ledger");
    }
    // Each call in its history: who made it, when, whether in person.
    nlohmann::json calls_made = nlohmann::json::array();
    for (const std::uint64_t index : history) {
        nlohmann::json item{{"index", index}};
        static_cast<void>(served->visit_entry(index, [&](ByteView bytes) {
            const auto entry = protocol::decode_log_entry(bytes);
            if (!entry) {
                return;
            }
            item["time"] = entry->registered_at;
            const auto parsed =
                protocol::parse_statement(*services_.provider, entry->statement, served->hash());
            if (!parsed) {
                return;
            }
            const protocol::Statement& s = parsed->statement;
            if (const auto* call = std::get_if<protocol::ContractCallBody>(&s.body)) {
                item["function"] = call->function;
                item["arguments"] = cbor::diagnostic(call->arguments);
                item["consents"] = call->consents.size();
                if (call->answer) {
                    item["answer"] = {{"request", hex_of(call->answer->request)},
                                      {"status", static_cast<int>(call->answer->status)}};
                }
            }
            item["in_person"] = s.presence.has_value();
            if (s.actor_id) {
                item["actor"] = hex_of(*s.actor_id);
            }
        }));
        calls_made.push_back(std::move(item));
    }
    served->read_state([&](const protocol::LedgerState& state) {
        for (nlohmann::json& item : calls_made) {
            if (const auto actor = item.find("actor"); actor != item.end()) {
                const auto actor_id = id_of(actor->get<std::string>());
                const protocol::ActorState* a = actor_id ? state.actor(*actor_id) : nullptr;
                item["by"] = a != nullptr ? nlohmann::json(a->display_name) : nlohmann::json();
                item["by_kind"] = a != nullptr && a->kind
                                      ? nlohmann::json(static_cast<int>(*a->kind))
                                      : nlohmann::json();
            }
        }
    });
    // What the contract says of its calls, and the state in its words.
    std::vector<std::string> more{"--state", to_hex(state_bytes)};
    more.insert(more.end(), labels.begin(), labels.end());
    auto described = contract_calls(signer, *contract, language, more);
    nlohmann::json calls;
    nlohmann::json words;
    if (auto* answer = std::get_if<nlohmann::json>(&described)) {
        calls = (*answer)["calls"];
        words = answer->value("state", nlohmann::json());
    }
    return json(200, {{"instance", std::move(instance)},
                      {"history", std::move(calls_made)},
                      {"requests", std::move(requests)},
                      {"due", std::move(due)},
                      {"calls", std::move(calls)},
                      {"state", std::move(words)},
                      {"may_act", signer.role != Role::viewer}});
}

std::variant<protocol::ContractCallBody, http::Response>
Console::call_body(const Signed& who, const nlohmann::json& intent,
                   const std::string& action) const {
    const ledger::Ledger* served = ledger();
    const std::string function = intent.value("function", "");
    std::optional<protocol::Id> contract;
    std::optional<protocol::Id> instance;
    std::optional<std::uint64_t> head;
    if (action == "request.answer") {
        const auto request = id_of(intent.value("request", ""));
        const std::string status = intent.value("status", "");
        const auto answer = status == "done"      ? protocol::AnswerStatus::done
                            : status == "failed"  ? protocol::AnswerStatus::failed
                            : status == "expired" ? protocol::AnswerStatus::expired
                                                  : protocol::AnswerStatus{};
        if (!request || answer == protocol::AnswerStatus{}) {
            return error(400, "invalid_argument",
                         "an answer names the request (its full id) and a status: done, failed, "
                         "or expired");
        }
        const std::string reason = intent.value("reason", "");
        if (!reason.empty() && !protocol::is_request_kind(reason)) {
            return error(400, "invalid_argument",
                         "a reason is a code written like a request kind (such as cancelled)");
        }
        std::optional<protocol::ContractCallBody> body;
        std::string problem;
        const protocol::Timestamp now = services_.clock->now();
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::RequestState* r = state.request(*request);
            const protocol::InstanceState* i = r != nullptr ? state.instance(r->instance) : nullptr;
            if (r == nullptr || i == nullptr) {
                problem = "no such request on this ledger";
            } else if (!r->open()) {
                problem = "the request is answered already: a request takes one answer";
            } else if (answer == protocol::AnswerStatus::expired && now < r->deadline) {
                problem = "the request can expire only from its deadline";
            } else {
                body = protocol::ContractCallBody{};
                body->instance = protocol::Id(r->instance);
                body->head = i->head;
                body->function = r->reply;
                body->arguments = cbor::Value::null();
                if (!reason.empty()) {
                    cbor::Map entries;
                    entries.push_back({cbor::Value::text("reason"), cbor::Value::text(reason)});
                    body->arguments = cbor::Value::map(std::move(entries));
                }
                body->answer = protocol::ContractAnswer{*request, answer};
            }
        });
        if (!body) {
            return error(409, "conflict", problem);
        }
        return std::move(*body);
    }
    if (action == "contract.create") {
        contract = id_of(intent.value("contract", ""));
        if (!contract) {
            return error(400, "invalid_argument", "name the contract by its full id (hex)");
        }
        std::string problem;
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::ContractState* c = state.contract(*contract);
            if (c == nullptr) {
                problem = "no such contract on this ledger";
            } else if (c->retired) {
                problem = "these rules are retired: they put no new thing under them";
            } else if (const auto f = c->interface.find(function);
                       f == c->interface.end() || f->second != protocol::FunctionKind::create) {
                problem = "the contract has no function " + function + " that creates";
            }
        });
        if (!problem.empty()) {
            return error(409, "conflict", problem);
        }
    } else {
        instance = id_of(intent.value("instance", ""));
        if (!instance) {
            return error(400, "invalid_argument", "name the thing by its full id (hex)");
        }
        std::string problem;
        served->read_state([&](const protocol::LedgerState& state) {
            const protocol::InstanceState* i = state.instance(*instance);
            const protocol::ContractState* c =
                i != nullptr ? state.contract(protocol::Id(i->contract)) : nullptr;
            if (i == nullptr || c == nullptr) {
                problem = "no such thing under rules on this ledger";
            } else if (i->final) {
                problem = "this thing is in a final state: it takes no more calls";
            } else if (const auto f = c->interface.find(function);
                       f == c->interface.end() || f->second != protocol::FunctionKind::call) {
                problem = "the contract has no action " + function;
            } else {
                contract = protocol::Id(i->contract);
                head = i->head;
            }
        });
        if (!problem.empty()) {
            return error(409, "conflict", problem);
        }
    }
    // The arguments, built by the compiler from what the person filled in.
    const auto values = intent.find("values");
    const nlohmann::json given =
        values != intent.end() && values->is_object() ? *values : nlohmann::json::object();
    const std::string values_text = given.dump();
    if (values_text.size() > bo::calls::max_values_json) {
        return error(413, "limit_exceeded", "the values are at most 64 KiB");
    }
    const auto boc = deployed_boc(*contract);
    if (!boc) {
        return error(409, "conflict", "only rules written in Bo take values from the console");
    }
    auto ran = run_compiler(who,
                            {"args", "contract.boc", function, "--values", values_text,
                             "--language", language_of(intent.value("language", ""))},
                            {{"contract.boc", std::string(boc->begin(), boc->end())}});
    if (auto* refused = std::get_if<http::Response>(&ran)) {
        return std::move(*refused);
    }
    const nlohmann::json& answer = std::get<CompilerRun>(ran).answer;
    if (!answer.is_object() || !answer.value("ok", false)) {
        return json(
            422,
            {{"error",
              {{"code", "invalid_argument"}, {"message", "some values do not go into the call"}}},
             {"problems", answer.is_object() ? answer.value("problems", nlohmann::json::array())
                                             : nlohmann::json::array()}});
    }
    const auto bytes = from_hex(answer.value("cbor", ""));
    auto arguments =
        bytes ? cbor::decode(*bytes) : Result<cbor::Value>(std::unexpected(bytes.error()));
    if (!arguments) {
        return error(500, "internal", "the compiler's arguments do not read");
    }
    protocol::ContractCallBody body;
    body.function = function;
    body.arguments = std::move(*arguments);
    if (action == "contract.create") {
        body.contract = *contract;
        const std::string reference = intent.value("reference", "");
        if (!reference.empty()) {
            body.reference = reference;
        }
    } else {
        body.instance = *instance;
        body.head = *head;
    }
    return body;
}

nlohmann::json Console::dry_run(const protocol::LedgerState& state,
                                const protocol::Statement& statement,
                                const protocol::ActorState& actor,
                                const std::string& language) const {
    // As the person will sign it: with their passkey's presence, which the
    // contract may ask for.
    protocol::SignedStatement trial;
    trial.statement = statement;
    if (!actor.presence.empty()) {
        protocol::PresenceProof presence;
        presence.credential_id = actor.presence.front().credential_id;
        trial.statement.presence = std::move(presence);
    }
    const protocol::Timestamp now = services_.clock->now();
    const auto& call = std::get<protocol::ContractCallBody>(statement.body);
    auto run = state.run_contract(*services_.provider, trial, now);
    if (!run) {
        return {{"verdict", "refuse"}, {"reason", std::string(run.error().detail)}};
    }
    return verdict_json(state, *run, call, std::nullopt, now, language);
}

} // namespace cexchain::console
