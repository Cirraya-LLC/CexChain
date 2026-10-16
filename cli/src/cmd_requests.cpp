// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Requests and answers (spec v0.8, 6b): a contract's accepted call may ask
// executors for work outside the ledger (send a notice, call a system). An
// executor, an AI agent, or a person by hand answers with a call on the
// instance that names the request: done, failed, or expired. Executors are
// devices (or agents) with a narrow delegation: calls on some contracts
// (scope key 7), of the reply functions (key 8), answering requests of some
// kinds only (key 9).
//
//   request list, show, answer, cancel (an answer: failed, reason cancelled),
//           wait (a server's discovery route, a long poll; a hint only)
//   executor add (an actor and its delegation), list, show, revoke

#include <algorithm>
#include <format>
#include <print>
#include <set>
#include <variant>

#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/executor.hpp>

#include "commands.hpp"
#include "contracts.hpp"
#include "output.hpp"
#include "peers.hpp"
#include "requests.hpp"

namespace cexchain::cli {

namespace {

constexpr std::string_view cancelled_reason = "cancelled";

RequestFilter filter_of(const Session& session, const Args& args) {
    RequestFilter filter;
    int which = 0;
    for (const auto& [flag, value] : {std::pair{"open", RequestFilter::Which::open},
                                      std::pair{"answered", RequestFilter::Which::answered},
                                      std::pair{"failed", RequestFilter::Which::failed},
                                      std::pair{"overdue", RequestFilter::Which::overdue}}) {
        if (args.has(flag)) {
            filter.which = value;
            ++which;
        }
    }
    if (which > 1) {
        throw UsageError{"give one of --open, --answered, --failed, and --overdue"};
    }
    if (const auto kinds = args.get("kind")) {
        filter.kinds = parse_request_kinds(*kinds, "--kind");
    }
    if (const auto contract = args.get("contract")) {
        filter.contract = session.contract_id(*contract);
    }
    if (const auto instance = args.get("instance")) {
        filter.instance = session.instance_id(*instance);
    }
    if (const auto actor = args.get("answered-by")) {
        filter.answered_by = session.actor_id(*actor);
    }
    if (const auto since = args.get("since")) {
        filter.since = parse_time(*since);
    }
    return filter;
}

const protocol::RequestState& request_named(const Session& session, std::string_view text) {
    return *session.state().request(session.request_id(text));
}

/// Signs and records an answer (or, with --dry-run, says what the contract
/// and the ledger would make of it), and reports it.
int record_answer(const Args& args, Session& session, const protocol::RequestState& request,
                  protocol::AnswerStatus status, cbor::Value arguments, bool cancel) {
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
            throw UsageError{"--at needs --dry-run: a recorded answer runs at the time the "
                             "ledger registers it"};
        }
        options.at = parse_time(*at);
    }
    const protocol::Id request_id = request.id;
    protocol::ContractCallBody body =
        answer_call(session, request, status, std::move(arguments), answer_time(options));
    body.reference = args.get("reference");
    const CallAttempt attempt = attempt_answer(session, *signer, std::move(body), options);
    if (options.dry_run) {
        if (args.json()) {
            Json out = run_json(session, attempt);
            out["request"] = id_json(request_id);
            out["answer"] = protocol::name(status);
            print_json(out);
            return exit_ok;
        }
        if (const protocol::ContractAccept* a = attempt.run.accepted();
            a != nullptr && !attempt.refused) {
            std::println("the answer {} would be recorded: the instance's status {}{}",
                         protocol::name(status), a->status.value_or("(none)"),
                         a->final ? ", final" : "");
            for (const protocol::ContractEvent& e : a->events) {
                std::println("event:     {} {}", e.name, cbor::diagnostic(e.data));
            }
            for (const protocol::ContractRequest& r : a->requests) {
                std::println("request:   {} (new), due {}", r.kind, format_time(r.deadline));
            }
        } else {
            std::println("it would not be recorded: {}", refusal(session, attempt));
        }
        std::println("fuel used: {}", attempt.run.outcome.fuel_used);
        return exit_ok;
    }
    if (!attempt.recorded) {
        throw CommandError{refusal(session, attempt) +
                           (attempt.refused ? std::string()
                                            : ": the request stays open (the contract decides "
                                              "which answers it takes)")};
    }
    const protocol::Id id = *attempt.recorded;
    const protocol::RequestState& closed = *session.state().request(request_id);
    const protocol::InstanceState& instance = *session.state().instance(closed.instance);
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    std::string text = cancel
                           ? std::format("cancelled request {} ({}): answered failed, reason {}",
                                         hex_id(request_id), closed.kind,
                                         args.get("reason").value_or(std::string(cancelled_reason)))
                           : std::format("answered request {} ({}): {}", hex_id(request_id),
                                         closed.kind, request_status(closed));
    if (closed.late_by() > 0) {
        text += ", late by " + duration_text(closed.late_by());
    }
    text += std::format("\ninstance {}: status {}{}", short_id(instance.id),
                        instance.status.value_or("(none)"), instance.final ? " (final)" : "");
    // The requests the answer made (a retry, the next step).
    Json made = Json::array();
    const std::uint64_t index = session.state().statement_index(id).value_or(0);
    for (const protocol::CompactId& open : instance.open_requests) {
        const protocol::RequestState& r = *session.state().request(open);
        if (r.call == index) {
            text += std::format("\nnew request {} ({}), due {}", short_id(r.id), r.kind,
                                format_time(r.deadline));
            made.push_back(id_json(r.id));
        }
    }
    return report_submitted(
        args, session, id,
        {{"request", request_json(session, closed, now)},
         {"instance_status", instance.status ? Json(*instance.status) : Json(nullptr)},
         {"final", instance.final},
         {"requests_made", std::move(made)},
         {"fuel_used", attempt.run.outcome.fuel_used}},
        text);
}

// ---------------------------------------------------------------------------
// Executors: actors whose delegations answer requests (scope key 9)
// ---------------------------------------------------------------------------

bool answers_requests(const protocol::DelegationState& d) {
    return d.scope.request_kinds.has_value();
}

std::vector<const protocol::DelegationState*> executor_delegations(const Session& session,
                                                                   const protocol::Id& actor) {
    std::vector<const protocol::DelegationState*> out;
    for (const auto& [key, d] : session.state().delegations()) {
        if (d.grantee == actor && answers_requests(d)) {
            out.push_back(&d);
        }
    }
    return out;
}

/// The requests `actor` answered, in log order.
std::vector<const protocol::RequestState*> answered_by(const Session& session,
                                                       const protocol::Id& actor) {
    RequestFilter filter;
    filter.answered_by = actor;
    return select_requests(session, filter, 0);
}

/// Open requests an executor's active delegations let it answer.
std::vector<const protocol::RequestState*>
work_for(const Session& session, const std::vector<const protocol::DelegationState*>& delegations,
         protocol::Timestamp now) {
    std::vector<const protocol::RequestState*> out;
    RequestFilter filter;
    filter.which = RequestFilter::Which::open;
    for (const protocol::RequestState* r : select_requests(session, filter, now)) {
        const protocol::InstanceState* i = session.state().instance(r->instance);
        const bool covered = std::ranges::any_of(delegations, [&](const auto* d) {
            return delegation_active(*d, now) &&
                   std::ranges::contains(*d->scope.request_kinds, r->kind) &&
                   (!d->scope.functions || std::ranges::contains(*d->scope.functions, r->reply)) &&
                   (!d->scope.contracts ||
                    (i != nullptr && std::ranges::contains(*d->scope.contracts, i->contract.id())));
        });
        if (covered) {
            out.push_back(r);
        }
    }
    return out;
}

std::string joined(const std::vector<std::string>& items, std::string_view separator) {
    std::string out;
    for (const std::string& item : items) {
        out += (out.empty() ? std::string() : std::string(separator)) + item;
    }
    return out;
}

std::string list_text(const std::vector<std::string>& items) {
    return joined(items, ", ");
}

/// What a delegation lets an executor do, for people.
std::string executor_scope_text(const Session& session, const protocol::DelegationState& d,
                                protocol::Timestamp now) {
    std::string out = "answers " + list_text(*d.scope.request_kinds);
    if (d.scope.contracts) {
        std::string contracts;
        for (const protocol::Id& c : *d.scope.contracts) {
            contracts += (contracts.empty() ? "" : ", ") + contract_label(session, c);
        }
        out += " on " + contracts;
    } else {
        out += " on any contract";
    }
    if (d.scope.functions) {
        out += ", calling " + list_text(*d.scope.functions);
    }
    if (d.scope.not_after) {
        out += ", until " + format_time(*d.scope.not_after);
    }
    out += d.revoked ? " [revoked]" : delegation_active(d, now) ? "" : " [not valid now]";
    return out;
}

Json executor_json(const Session& session, const protocol::ActorState& actor,
                   protocol::Timestamp now, bool detail) {
    const auto delegations = executor_delegations(session, actor.id);
    Json list = Json::array();
    std::set<std::string> kinds;
    for (const protocol::DelegationState* d : delegations) {
        list.push_back(delegation_json(session, *d));
        if (!d->revoked) {
            kinds.insert(d->scope.request_kinds->begin(), d->scope.request_kinds->end());
        }
    }
    const auto answers = answered_by(session, actor.id);
    const auto work = work_for(session, delegations, now);
    Json out{{"actor", actor_json(session, actor)},
             {"active", !actor.revoked && std::ranges::any_of(delegations,
                                                              [&](const auto* d) {
                                                                  return delegation_active(*d, now);
                                                              })},
             {"kinds", std::vector<std::string>(kinds.begin(), kinds.end())},
             {"delegations", std::move(list)},
             {"answers", answers.size()},
             {"late_answers",
              std::ranges::count_if(answers, [](const auto* r) { return r->late_by() > 0; })},
             {"open_requests", work.size()},
             {"overdue_requests", std::ranges::count_if(work, [&](const auto* r) {
                  return request_overdue(*r, now);
              })}};
    if (detail) {
        Json given = Json::array();
        for (const protocol::RequestState* r : answers) {
            given.push_back(request_json(session, *r, now));
        }
        Json waiting = Json::array();
        for (const protocol::RequestState* r : work) {
            waiting.push_back(request_json(session, *r, now));
        }
        out["answered"] = std::move(given);
        out["waiting"] = std::move(waiting);
    }
    return out;
}

const protocol::ActorState& executor_named(const Session& session, std::string_view text) {
    const protocol::ActorState& actor = *session.state().actor(session.actor_id(text));
    if (executor_delegations(session, actor.id).empty()) {
        throw CommandError{"\"" + actor.display_name +
                           "\" is no executor: none of its delegations answers requests (scope "
                           "key 9; see executor add)"};
    }
    return actor;
}

} // namespace

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

int cmd_request_list(const Args& args) {
    Session session(args);
    const RequestFilter filter = filter_of(session, args);
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    const auto found = select_requests(session, filter, now);
    if (args.json()) {
        Json out = Json::array();
        for (const protocol::RequestState* r : found) {
            out.push_back(request_json(session, *r, now));
        }
        print_json(out);
        return exit_ok;
    }
    if (found.empty()) {
        std::println("no requests");
    }
    for (const protocol::RequestState* r : found) {
        std::println("{}", request_line(session, *r, now));
    }
    return exit_ok;
}

int cmd_request_show(const Args& args) {
    Session session(args);
    const protocol::RequestState& r = request_named(session, args.positional().front());
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    if (args.json()) {
        print_json(request_json(session, r, now));
    } else {
        print_request(session, r, now);
    }
    return exit_ok;
}

int cmd_request_answer(const Args& args) {
    Session session(args);
    const protocol::RequestState& r = request_named(session, args.positional().front());
    std::optional<protocol::AnswerStatus> status;
    for (const auto s : {protocol::AnswerStatus::done, protocol::AnswerStatus::failed,
                         protocol::AnswerStatus::expired}) {
        if (args.has(protocol::name(s))) {
            if (status) {
                throw UsageError{"give one of --done, --failed, and --expired"};
            }
            status = s;
        }
    }
    if (!status) {
        throw UsageError{"say what became of the request: --done, --failed, or --expired"};
    }
    const auto reason = args.get("reason");
    if (reason && *status == protocol::AnswerStatus::done) {
        throw UsageError{"--reason explains a failure or an expiry, not --done"};
    }
    cbor::Value arguments =
        answer_arguments(args.has("args") || args.has("args-cbor")
                             ? std::optional<cbor::Value>(contract_arguments_of(args))
                             : std::nullopt,
                         reason);
    return record_answer(args, session, r, *status, std::move(arguments), false);
}

int cmd_request_cancel(const Args& args) {
    Session session(args);
    const protocol::RequestState& r = request_named(session, args.positional().front());
    cbor::Value arguments =
        answer_arguments(std::nullopt, args.get("reason").value_or(std::string(cancelled_reason)));
    return record_answer(args, session, r, protocol::AnswerStatus::failed, std::move(arguments),
                         true);
}

int cmd_request_wait(const Args& args) {
    const auto url = server_option(args);
    if (!url) {
        throw UsageError{"request wait asks a server: give --server URL (or $CEXCHAIN_SERVER)"};
    }
    const std::uint64_t wait =
        args.has("timeout") ? parse_number(*args.get("timeout"), "--timeout") : 25;
    if (wait > 25) {
        throw UsageError{"--timeout is 0 to 25 seconds"};
    }
    std::string query = "wait=" + std::to_string(wait);
    if (const auto state = args.get("state")) {
        if (*state != "open" && *state != "answered" && *state != "all") {
            throw UsageError{"--state is open, answered, or all"};
        }
        query += "&state=" + *state;
    }
    if (const auto kinds = args.get("kind")) {
        query += "&kind=" + joined(parse_request_kinds(*kinds, "--kind"), ",");
    }
    for (const char* name : {"contract", "instance"}) {
        if (const auto id = args.get(name)) {
            query += std::string("&") + name + "=" + hex_id(full_id(*id, std::string("--") + name));
        }
    }
    if (const auto after = args.get("after")) {
        query += "&after=" + std::to_string(parse_number(*after, "--after"));
    }
    if (const auto limit = args.get("limit")) {
        const std::uint64_t n = parse_number(*limit, "--limit");
        if (n == 0 || n > 1000) {
            throw UsageError{"--limit is 1 to 1000"};
        }
        query += "&limit=" + std::to_string(n);
    }
    node::ClientOptions options;
    options.bearer_token = api_token(args);
    if (const auto ca = args.get("ca-file")) {
        options.ca_file = *ca;
    }
    options.timeout = std::chrono::seconds(wait + 15);
    const node::Client client(unwrap(node::Url::parse(*url), "reading the URL"), options);
    const auto response =
        unwrap(client.request("GET", "/v1/requests?" + query), "reaching " + *url);
    const Json answer = Json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (response.status != 200) {
        const std::string message = answer.is_object() && answer.contains("error")
                                        ? answer["error"].value("message", std::string("?"))
                                        : std::string("status ") + std::to_string(response.status);
        throw CommandError{"the server refused: " + message};
    }
    if (!answer.is_object() || !answer.contains("requests") || !answer["requests"].is_array()) {
        throw CommandError{"the server's answer is not a list of requests"};
    }
    // Params in diagnostic notation and times in RFC 3339, as the other
    // request commands show them.
    Json requests = Json::array();
    for (const Json& r : answer["requests"]) {
        Json item = r;
        const auto bytes = from_hex(r.value("params", std::string()));
        const auto value =
            bytes ? cbor::decode(*bytes) : Result<cbor::Value>(fail(Errc::malformed, ""));
        item["params"] = value ? Json(cbor::diagnostic(*value)) : Json(nullptr);
        item["params_cbor"] = r.value("params", std::string());
        for (const char* time : {"deadline", "asked_at", "answered_at"}) {
            if (r.contains(time) && r[time].is_number_unsigned()) {
                item[time] = iso_time(r[time].get<protocol::Timestamp>());
            }
        }
        requests.push_back(std::move(item));
    }
    const std::uint64_t cursor = answer.value("cursor", std::uint64_t{0});
    if (args.json()) {
        print_json({{"requests", std::move(requests)},
                    {"cursor", cursor},
                    {"more", answer.value("more", false)},
                    {"hint", true}});
        return exit_ok;
    }
    if (requests.empty()) {
        std::println("no requests (waited up to {} s)", wait);
    }
    for (const Json& r : requests) {
        std::println("{}  {:<16} {:<8} instance {} (head #{})  due {}{}",
                     r.value("id", std::string()).substr(0, 12), r.value("kind", std::string()),
                     r.value("status", std::string()),
                     r.value("instance", std::string()).substr(0, 12),
                     r.value("head", std::uint64_t{0}), r.value("deadline", std::string()),
                     r.value("overdue", false) ? "  OVERDUE" : "");
    }
    std::println("cursor: {} (--after {} waits for what comes next)", cursor, cursor);
    std::println("a hint from the server: check a request in the instance's evidence before "
                 "acting on it");
    return exit_ok;
}

// ---------------------------------------------------------------------------
// Executors
// ---------------------------------------------------------------------------

int cmd_executor_add(const Args& args) {
    Session session(args);
    const std::string name = args.positional().front();
    const std::optional<std::string> config_out = args.get("config-out");
    if (config_out && std::filesystem::exists(*config_out)) {
        throw CommandError{*config_out + " already exists; configs are never overwritten"};
    }
    const protocol::Id contract = session.contract_id(args.need("contract"));
    const protocol::ContractState& c = *session.state().contract(contract);
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::contract_call};
    scope.contracts = std::vector<protocol::Id>{contract};
    scope.request_kinds = parse_request_kinds(args.need("kinds"), "--kinds");
    std::vector<std::string> functions;
    if (const auto list = args.get("functions")) {
        functions = split(*list, ',');
    } else if (const auto f = c.interface.find("result");
               f != c.interface.end() && f->second == protocol::FunctionKind::call) {
        functions = {"result"};
    } else {
        throw UsageError{"give --functions: the function(s) its answers call (the requests' "
                         "reply; the contract has no function result)"};
    }
    for (const std::string& f : functions) {
        const auto found = c.interface.find(f);
        if (found == c.interface.end() || found->second != protocol::FunctionKind::call) {
            throw UsageError{"--functions: contract " + contract_label(session, contract) +
                             " has no function " + f + " for instances"};
        }
    }
    std::ranges::sort(functions);
    functions.erase(std::ranges::unique(functions).begin(), functions.end());
    scope.functions = functions;
    scope.not_after = validity_end(args);
    const NewActorKey made = new_actor_key(args, "the executor's");
    const crypto::PublicKey& key = made.key;
    const std::optional<std::string>& key_out = made.file;
    const bool agent = args.has("agent");
    protocol::ActorRegisterBody body{agent ? protocol::ActorKind::agent
                                           : protocol::ActorKind::device,
                                     name, key, std::nullopt, std::nullopt};
    if (const auto responsible = args.get("responsible")) {
        body.responsible = session.actor_id(*responsible);
    }
    if (agent) {
        if (!args.has("model") || !body.responsible) {
            throw UsageError{"an agent needs --model (the model it runs) and --responsible (the "
                             "person accountable for it)"};
        }
        body.agent =
            protocol::AgentProfile{args.get("model"), args.get("model-version"), std::nullopt};
    }
    const auto signer = load_signer(args.need("as"), args);
    // For an agent, --model describes the agent, not the signer.
    const std::optional<protocol::Provenance> provenance =
        agent ? std::nullopt : session.provenance(args);
    const auto presence = presence_request(args);
    const protocol::Id actor =
        session.submit(*signer, body, args.get("delegation"), provenance, presence);
    protocol::Id delegation;
    try {
        delegation = session.submit(*signer, protocol::DelegationGrantBody{actor, scope},
                                    args.get("delegation"), provenance, presence);
    } catch (const CommandError& e) {
        throw CommandError{"registered \"" + name + "\" as " + hex_id(actor) +
                           ", but its delegation was refused (" + e.message +
                           "): grant one with delegation grant, or revoke the actor"};
    }
    const protocol::DelegationState& d = *session.state().delegation(delegation);
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    std::string text =
        std::format("registered {} \"{}\" as {}\ngranted delegation {}: {}", kind_text(body.kind),
                    name, hex_id(actor), hex_id(delegation), executor_scope_text(session, d, now));
    if (key_out) {
        text += "\nits key is in " + *key_out + " (encrypted): give it to the executor alone";
    }
    if (config_out) {
        // What executor run needs to know without reading the ledger: the
        // home, and who it answers as, under which delegation.
        node::executor::Config config;
        config.ledger = session.state().ledger_id();
        config.actor = actor;
        config.delegation = delegation;
        if (agent) {
            config.model = args.get("model");
            config.model_version = args.get("model-version");
        }
        const std::string written = node::executor::config_text(config);
        write_file(*config_out, as_bytes(std::string_view(written)), true);
        text += "\nits config is in " + *config_out +
                ": add connectors with executor connector add, then run it with executor run";
    }
    if (args.json()) {
        Json out = executor_json(session, *session.state().actor(actor), now, false);
        out["config_file"] = config_out ? Json(*config_out) : Json(nullptr);
        out["actor_statement_id"] = id_json(actor);
        out["delegation_statement_id"] = id_json(delegation);
        out["key_file"] = key_out ? Json(*key_out) : Json(nullptr);
        print_json(out);
    } else {
        std::println("{}", text);
    }
    return exit_ok;
}

int cmd_executor_list(const Args& args) {
    Session session(args);
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    const std::optional<protocol::Id> contract =
        args.has("contract") ? std::optional(session.contract_id(*args.get("contract")))
                             : std::nullopt;
    const std::vector<std::string> kinds = args.has("kind")
                                               ? parse_request_kinds(*args.get("kind"), "--kind")
                                               : std::vector<std::string>{};
    Json out = Json::array();
    bool any = false;
    for (const auto& [key, actor] : session.state().actors()) {
        const auto delegations = executor_delegations(session, actor.id);
        if (delegations.empty()) {
            continue;
        }
        const bool active = !actor.revoked && std::ranges::any_of(delegations, [&](const auto* d) {
            return delegation_active(*d, now);
        });
        const bool matches = std::ranges::any_of(delegations, [&](const auto* d) {
            return (!contract || !d->scope.contracts ||
                    std::ranges::contains(*d->scope.contracts, *contract)) &&
                   std::ranges::all_of(kinds, [&](const std::string& k) {
                       return std::ranges::contains(*d->scope.request_kinds, k);
                   });
        });
        if ((!active && !args.has("all")) || !matches) {
            continue;
        }
        any = true;
        if (args.json()) {
            out.push_back(executor_json(session, actor, now, false));
            continue;
        }
        const Json j = executor_json(session, actor, now, false);
        std::println("{}  {:<6} {:<20} {}; {} answer(s), {} open request(s){}", short_id(actor.id),
                     kind_text(actor.kind), "\"" + actor.display_name + "\"",
                     "answers " + list_text(j["kinds"].get<std::vector<std::string>>()),
                     j["answers"].get<std::size_t>(), j["open_requests"].get<std::size_t>(),
                     active ? "" : (actor.revoked ? "  [revoked]" : "  [no valid delegation]"));
    }
    if (args.json()) {
        print_json(out);
    } else if (!any) {
        std::println("no executors (executor add registers one)");
    }
    return exit_ok;
}

int cmd_executor_show(const Args& args) {
    Session session(args);
    const protocol::ActorState& actor = executor_named(session, args.positional().front());
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    if (args.json()) {
        print_json(executor_json(session, actor, now, true));
        return exit_ok;
    }
    const auto delegations = executor_delegations(session, actor.id);
    std::println("executor:    {}", hex_id(actor.id));
    std::println("name:        {}", actor.display_name);
    std::println("kind:        {}{}", kind_text(actor.kind),
                 actor.agent && actor.agent->model ? ", model " + *actor.agent->model : "");
    if (actor.responsible) {
        std::println("responsible: {}", session.actor_name(*actor.responsible));
    }
    std::println("status:      {}", actor.revoked ? "REVOKED" : "active");
    bool first = true;
    for (const protocol::DelegationState* d : delegations) {
        std::println("{}{} {}", first ? "delegation:  " : "             ", short_id(d->id),
                     executor_scope_text(session, *d, now));
        first = false;
    }
    const auto answers = answered_by(session, actor.id);
    std::println("answers:     {}", answers.size());
    for (const protocol::RequestState* r : answers) {
        std::println("  #{:<5} {}  {} {} ({}){}", *r->answered_by, format_time(r->answered_at),
                     request_status(*r), short_id(r->id), r->kind,
                     r->late_by() > 0 ? ", late by " + duration_text(r->late_by()) : "");
    }
    const auto work = work_for(session, delegations, now);
    std::println("waiting:     {} open request(s) it may answer", work.size());
    for (const protocol::RequestState* r : work) {
        std::println("  {}", request_line(session, *r, now));
    }
    return exit_ok;
}

int cmd_executor_revoke(const Args& args) {
    Session session(args);
    const protocol::ActorState& actor = executor_named(session, args.positional().front());
    const protocol::Id actor_id = actor.id;
    const std::string name = actor.display_name;
    const bool keep_actor = args.has("keep-actor");
    if (actor.revoked && keep_actor) {
        throw CommandError{"\"" + name + "\" is revoked already"};
    }
    std::vector<protocol::Id> revoked;
    std::vector<protocol::Id> statements;
    for (const protocol::DelegationState* d : executor_delegations(session, actor_id)) {
        if (!d->revoked) {
            revoked.push_back(d->id);
        }
    }
    for (const protocol::Id& d : revoked) {
        statements.push_back(
            session.submit(args, protocol::DelegationRevokeBody{d, args.get("reason")}));
    }
    const bool revoke_actor = !keep_actor && !session.state().actor(actor_id)->revoked;
    if (revoke_actor) {
        statements.push_back(
            session.submit(args, protocol::ActorRevokeBody{actor_id, args.get("reason")}));
    }
    if (statements.empty()) {
        throw CommandError{"\"" + name + "\" and its delegations are revoked already"};
    }
    if (args.json()) {
        Json ids = Json::array();
        for (const protocol::Id& d : revoked) {
            ids.push_back(id_json(d));
        }
        Json made = Json::array();
        for (const protocol::Id& s : statements) {
            made.push_back(id_json(s));
        }
        print_json({{"actor", id_json(actor_id)},
                    {"delegations_revoked", std::move(ids)},
                    {"actor_revoked", revoke_actor},
                    {"statement_ids", std::move(made)}});
        return exit_ok;
    }
    for (const protocol::Id& d : revoked) {
        std::println("revoked delegation {}", hex_id(d));
    }
    if (revoke_actor) {
        std::println("revoked executor \"{}\" {}: it answers nothing more", name, hex_id(actor_id));
    } else {
        std::println("\"{}\" {} answers nothing more under its delegations", name,
                     hex_id(actor_id));
    }
    return exit_ok;
}

} // namespace cexchain::cli
