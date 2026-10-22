// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Keepers (spec section 15): a ledger acts only on calls, so a keeper,
// a device of the home, calls each contract's time rules (functions
// when.*) once they are due, and expires the requests left open past their
// deadline plus a grace period. Its delegation covers contract calls only,
// on some contracts (scope key 7), of the time rules and the replies (key
// 8), answering no request kinds (no key 9).
//
//   keeper add (an actor and its delegation), list, show, revoke
//   keeper due (what is due, found by dry runs; or a server's GET
//           /v1/contracts/due), run (fire what is due, once or on a schedule)
//
// `serve --keeper-key` runs a keeper inside the server.

#include <algorithm>
#include <chrono>
#include <format>
#include <iterator>
#include <print>
#include <set>
#include <thread>

#include <cexchain/core/bytes.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/keeper.hpp>

#include "commands.hpp"
#include "contracts.hpp"
#include "output.hpp"
#include "peers.hpp"
#include "requests.hpp"

namespace cexchain::cli {

namespace {

std::vector<const protocol::DelegationState*> keeper_delegations(const Session& session,
                                                                 const protocol::Id& actor) {
    std::vector<const protocol::DelegationState*> out;
    for (const auto& [key, d] : session.state().delegations()) {
        if (d.grantee == actor && node::is_keeper_delegation(d)) {
            out.push_back(&d);
        }
    }
    return out;
}

std::string joined(const std::vector<std::string>& items) {
    std::string out;
    for (const std::string& item : items) {
        out += (out.empty() ? "" : ", ") + item;
    }
    return out;
}

/// What a keeper's delegation lets it call, for people.
std::string keeper_scope_text(const Session& session, const protocol::DelegationState& d,
                              protocol::Timestamp now) {
    std::string out = "calls " + joined(*d.scope.functions);
    if (d.scope.contracts) {
        std::string contracts;
        for (const protocol::Id& c : *d.scope.contracts) {
            contracts += (contracts.empty() ? "" : ", ") + contract_label(session, c);
        }
        out += " on " + contracts;
    } else {
        out += " on any contract";
    }
    if (d.scope.not_after) {
        out += ", until " + format_time(*d.scope.not_after);
    }
    out += d.revoked ? " [revoked]" : delegation_active(d, now) ? "" : " [not valid now]";
    return out;
}

/// A call the keeper made: a time rule fired, or a request expired.
struct KeeperCall {
    std::uint64_t index = 0;
    protocol::Id instance;
    std::string function;
    std::optional<protocol::Id> request;
};

/// The calls `actor` made on instances its delegations' contracts cover,
/// in log order: its time rules and its expiries.
std::vector<KeeperCall> keeper_calls(const Session& session, const protocol::Id& actor,
                                     const std::vector<const protocol::DelegationState*>& ds) {
    std::optional<std::set<protocol::IdKey>> contracts;
    for (const protocol::DelegationState* d : ds) {
        if (!d->scope.contracts) {
            contracts.reset();
            break;
        }
        contracts = contracts.value_or(std::set<protocol::IdKey>{});
        for (const protocol::Id& c : *d->scope.contracts) {
            contracts->insert(protocol::key_of(c));
        }
    }
    std::vector<KeeperCall> out;
    for (const auto& [key, instance] : session.state().instances()) {
        if (contracts && !contracts->contains(instance.contract.key())) {
            continue;
        }
        for (const std::uint64_t index : instance.history) {
            if (index == instance.created_by) {
                continue;
            }
            const protocol::SignedStatement s = session.statement(index);
            const auto* call = std::get_if<protocol::ContractCallBody>(&s.statement.body);
            if (call == nullptr || s.statement.actor_id != actor) {
                continue;
            }
            if (node::is_time_rule(call->function) ||
                (call->answer && call->answer->status == protocol::AnswerStatus::expired)) {
                out.push_back({index, instance.id.id(), call->function,
                               call->answer ? std::optional<protocol::Id>(call->answer->request)
                                            : std::nullopt});
            }
        }
    }
    std::ranges::sort(out, {}, &KeeperCall::index);
    return out;
}

protocol::Id id_from_hex(const std::string& hex) {
    const auto bytes = from_hex(hex);
    const auto id =
        bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(fail(Errc::malformed, ""));
    if (!id) {
        throw CommandError{"the server's answer holds an id that is not one: " + hex};
    }
    return *id;
}

/// An actor for people: its name here, else its abbreviated id.
std::string actor_text(const Session* session, const std::string& hex) {
    return session != nullptr ? "\"" + session->actor_name(id_from_hex(hex)) + "\""
                              : hex.substr(0, 12);
}

std::string contract_text(const Session* session, const std::string& hex) {
    return session != nullptr ? contract_label(*session, id_from_hex(hex)) : hex.substr(0, 12);
}

std::string keepers_text(const Session* session, const Json& keepers) {
    if (keepers.empty()) {
        return "no keeper may call it";
    }
    std::vector<std::string> names;
    for (const Json& k : keepers) {
        names.push_back(actor_text(session, k.get<std::string>()));
    }
    return "keepers: " + joined(names);
}

/// What is due, as GET /v1/contracts/due answers (times in milliseconds),
/// for scripts: times in RFC 3339, as the other commands show them.
Json due_for_scripts(Json due) {
    due["at"] = iso_time(due["at"].get<protocol::Timestamp>());
    for (Json& r : due["rules"]) {
        if (r["time"].is_number_unsigned()) {
            r["time"] = iso_time(r["time"].get<protocol::Timestamp>());
        }
    }
    for (Json& e : due["expiries"]) {
        e["deadline"] = iso_time(e["deadline"].get<protocol::Timestamp>());
    }
    return due;
}

/// The same, for people; `session` names actors and contracts (none when a
/// server answered).
void print_due(const Json& due, const Session* session) {
    const bool any_keeper = due["keeper"].is_null();
    std::println("at {}, expiry grace {}; {}", format_time(due["at"].get<protocol::Timestamp>()),
                 duration_text(due["grace_ms"].get<protocol::Timestamp>()),
                 any_keeper
                     ? std::string("for any keeper")
                     : "for keeper " + actor_text(session, due["keeper"].get<std::string>()));
    const Json& rules = due["rules"];
    const Json& expiries = due["expiries"];
    if (rules.empty() && expiries.empty()) {
        std::println("nothing due");
    }
    for (const Json& r : rules) {
        std::string line = std::format(
            "rule    {} on {} ({}), status {}", r["function"].get<std::string>(),
            r["instance"].get<std::string>().substr(0, 12),
            contract_text(session, r["contract"].get<std::string>()),
            r["status"].is_null() ? std::string("(none)") : r["status"].get<std::string>());
        if (r["time"].is_number_unsigned()) {
            line += ": its time was " + format_time(r["time"].get<protocol::Timestamp>());
            if (r["late_ms"].is_number_unsigned()) {
                line += " (" + duration_text(r["late_ms"].get<protocol::Timestamp>()) + " ago)";
            }
        }
        if (any_keeper) {
            line += "; " + keepers_text(session, r["keepers"]);
        }
        std::println("{}", line);
    }
    for (const Json& e : expiries) {
        std::string line =
            std::format("expiry  request {} ({}) on {}, due {}, overdue {}",
                        e["request"].get<std::string>().substr(0, 12), e["kind"].get<std::string>(),
                        e["instance"].get<std::string>().substr(0, 12),
                        format_time(e["deadline"].get<protocol::Timestamp>()),
                        duration_text(e["overdue_ms"].get<protocol::Timestamp>()));
        if (any_keeper) {
            line += "; " + keepers_text(session, e["keepers"]);
        }
        std::println("{}", line);
    }
    for (const Json& f : due["refused"]) {
        std::println("refused {} on {}{}: {}", f["function"].get<std::string>(),
                     f["instance"].get<std::string>().substr(0, 12),
                     f["request"].is_null()
                         ? std::string()
                         : " (request " + f["request"].get<std::string>().substr(0, 12) + ")",
                     f["reason"].get<std::string>());
    }
    std::println("{} instance(s) examined, {} contract run(s), {} fuel",
                 due["instances"].get<std::size_t>(), due["runs"].get<std::size_t>(),
                 due["fuel"].get<std::uint64_t>());
    if (due["next"].is_number_unsigned()) {
        std::println("stopped at the run limit: --start {} goes on",
                     due["next"].get<std::uint64_t>());
    }
}

/// --grace SECONDS, in milliseconds.
std::optional<protocol::Timestamp> grace_of(const Args& args) {
    if (const auto grace = args.get("grace")) {
        const std::uint64_t seconds = parse_number(*grace, "--grace");
        if (seconds > 31'622'400) {
            throw UsageError{"--grace is 0 to 31622400 seconds (366 days)"};
        }
        return seconds * 1000;
    }
    return std::nullopt;
}

/// --limit N: contract runs at most.
std::size_t run_limit(const Args& args) {
    if (const auto limit = args.get("limit")) {
        const std::uint64_t n = parse_number(*limit, "--limit");
        if (n == 0 || n > node::max_due_runs) {
            throw UsageError{"--limit is 1 to 100000 contract runs"};
        }
        return n;
    }
    return node::default_due_runs;
}

/// What is due, from this ledger.
Json local_due(const Session& session, const node::DueOptions& options) {
    const node::DueWork work =
        unwrap(node::find_due(session.provider(), session.state(), options), "finding what is due");
    return Json::parse(node::due_json_text(work));
}

/// What is due, from a server's GET /v1/contracts/due.
Json server_due(const Args& args, const std::string& url) {
    std::string query;
    auto add = [&](std::string_view name, const std::string& value) {
        query += (query.empty() ? "?" : "&") + std::string(name) + "=" + value;
    };
    if (const auto at = args.get("at")) {
        add("at", std::to_string(parse_time(*at)));
    }
    if (const auto grace = grace_of(args)) {
        add("grace", std::to_string(*grace / 1000));
    }
    for (const char* name : {"keeper", "contract", "instance"}) {
        if (const auto id = args.get(name)) {
            add(name, hex_id(full_id(*id, std::string("--") + name +
                                              " (with --server, a full id of 64 hex digits)")));
        }
    }
    if (const auto start = args.get("start")) {
        add("start", std::to_string(parse_number(*start, "--start")));
    }
    if (args.has("limit")) {
        add("limit", std::to_string(run_limit(args)));
    }
    node::ClientOptions options;
    options.bearer_token = api_token(args);
    if (const auto ca = args.get("ca-file")) {
        options.ca_file = *ca;
    }
    options.timeout = std::chrono::seconds(60);
    const node::Client client(unwrap(node::Url::parse(url), "reading the URL"), options);
    const auto response =
        unwrap(client.request("GET", "/v1/contracts/due" + query), "reaching " + url);
    const Json answer = Json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (response.status != 200) {
        const std::string message = answer.is_object() && answer.contains("error")
                                        ? answer["error"].value("message", std::string("?"))
                                        : std::string("status ") + std::to_string(response.status);
        throw CommandError{"the server refused: " + message};
    }
    if (!answer.is_object() || !answer.contains("rules") || !answer.contains("expiries")) {
        throw CommandError{"the server's answer is not a list of what is due"};
    }
    return answer;
}

Json keeper_json(const Session& session, const protocol::ActorState& actor, protocol::Timestamp now,
                 bool detail) {
    const auto delegations = keeper_delegations(session, actor.id);
    Json list = Json::array();
    std::set<std::string> functions;
    std::set<std::string> contracts;
    bool any_contract = false;
    for (const protocol::DelegationState* d : delegations) {
        list.push_back(delegation_json(session, *d));
        if (!delegation_active(*d, now)) {
            continue;
        }
        functions.insert(d->scope.functions->begin(), d->scope.functions->end());
        if (d->scope.contracts) {
            for (const protocol::Id& c : *d->scope.contracts) {
                contracts.insert(hex_id(c));
            }
        } else {
            any_contract = true;
        }
    }
    const bool active = !actor.revoked && std::ranges::any_of(delegations, [&](const auto* d) {
        return delegation_active(*d, now);
    });
    Json out{{"actor", actor_json(session, actor)},
             {"active", active},
             {"functions", std::vector<std::string>(functions.begin(), functions.end())},
             {"contracts",
              any_contract ? Json(nullptr)
                           : Json(std::vector<std::string>(contracts.begin(), contracts.end()))},
             {"delegations", std::move(list)}};
    if (detail) {
        Json calls = Json::array();
        std::size_t rules = 0;
        for (const KeeperCall& c : keeper_calls(session, actor.id, delegations)) {
            rules += c.request ? 0U : 1U;
            calls.push_back({{"index", c.index},
                             {"instance", id_json(c.instance)},
                             {"function", c.function},
                             {"request", c.request ? id_json(*c.request) : Json(nullptr)}});
        }
        out["rules_fired"] = rules;
        out["expiries"] = calls.size() - rules;
        out["calls"] = std::move(calls);
        if (active) {
            node::DueOptions options;
            options.now = now;
            options.keeper = actor.id;
            out["due"] = due_for_scripts(local_due(session, options));
        } else {
            out["due"] = nullptr;
        }
    }
    return out;
}

const protocol::ActorState& keeper_named(const Session& session, std::string_view text) {
    const protocol::ActorState& actor = *session.state().actor(session.actor_id(text));
    if (keeper_delegations(session, actor.id).empty()) {
        throw CommandError{"\"" + actor.display_name +
                           "\" is no keeper: none of its delegations is a keeper's (contract "
                           "calls only, of some functions; see keeper add)"};
    }
    return actor;
}

/// One round of `keeper run`: everything due for the keeper, fired, one
/// call per instance at a time (each moves its head), until nothing more is
/// due or 16 passes.
Json keeper_round(const Args& args, const crypto::Signer& signer, protocol::Timestamp grace,
                  std::size_t limit) {
    Session session(args);
    if (!session.remote()) {
        session.require_primary(); // not a cluster member's or a replica's files
    }
    const protocol::Id keeper = session.actor_for(signer).id;
    Json calls = Json::array();
    Json refused = Json::array();
    std::size_t runs = 0;
    constexpr int max_passes = 16;
    for (int pass = 0; pass < max_passes; ++pass) {
        node::DueOptions options;
        options.now = ledger::SystemClock{}.now();
        options.grace = grace;
        options.keeper = keeper;
        options.max_runs = limit;
        std::vector<node::DueExpiry> expiries;
        std::vector<node::DueRule> rules;
        for (;;) {
            node::DueWork work =
                unwrap(node::find_due(session.provider(), session.state(), options),
                       "finding what is due");
            runs += work.runs;
            std::ranges::move(work.expiries, std::back_inserter(expiries));
            std::ranges::move(work.rules, std::back_inserter(rules));
            if (pass == 0) {
                for (const node::DueRefusal& f : work.refused) {
                    refused.push_back({{"instance", id_json(f.instance)},
                                       {"function", f.function},
                                       {"request", f.request ? id_json(*f.request) : Json(nullptr)},
                                       {"reason", f.reason}});
                }
            }
            if (!work.next) {
                break;
            }
            options.start = *work.next;
        }
        std::set<protocol::IdKey> touched;
        bool more = false;
        bool fired = false;
        auto fire = [&](protocol::ContractCallBody body, Json item) {
            if (!touched.insert(protocol::key_of(*body.instance)).second) {
                more = true;
                return;
            }
            item["instance"] = id_json(*body.instance);
            item["function"] = body.function;
            try {
                const CallAttempt attempt = attempt_call(session, signer, std::move(body), {}, {});
                if (!attempt.recorded) {
                    item["reason"] = refusal(session, attempt);
                    refused.push_back(std::move(item));
                    return;
                }
                const protocol::InstanceState& i =
                    *session.state().instance(id_from_hex(item["instance"].get<std::string>()));
                item["statement_id"] = id_json(*attempt.recorded);
                item["index"] = session.state().statement_index(*attempt.recorded).value_or(0);
                item["status"] = i.status ? Json(*i.status) : Json(nullptr);
                calls.push_back(std::move(item));
                fired = true;
            } catch (const CommandError& e) {
                item["reason"] = e.message;
                refused.push_back(std::move(item));
            }
        };
        for (const node::DueExpiry& e : expiries) {
            fire(node::expiry_call(e), {{"kind", "expiry"},
                                        {"request", id_json(e.request)},
                                        {"request_kind", e.kind},
                                        {"overdue_ms", options.now - e.deadline}});
        }
        for (const node::DueRule& r : rules) {
            fire(node::rule_call(r), {{"kind", "rule"},
                                      {"request", nullptr},
                                      {"late_ms", r.late ? Json(*r.late) : Json(nullptr)}});
        }
        if (!more || !fired) {
            break;
        }
    }
    return {{"at", iso_time(ledger::SystemClock{}.now())},
            {"keeper", id_json(keeper)},
            {"calls", std::move(calls)},
            {"refused", std::move(refused)},
            {"runs", runs}};
}

void print_round(const Json& round) {
    for (const Json& c : round["calls"]) {
        const std::string where = std::format(
            "on {} (entry #{}): status {}", c["instance"].get<std::string>().substr(0, 12),
            c["index"].get<std::uint64_t>(),
            c["status"].is_null() ? std::string("(none)") : c["status"].get<std::string>());
        if (c["kind"] == "rule") {
            std::println("fired {} {}{}", c["function"].get<std::string>(), where,
                         c["late_ms"].is_number_unsigned()
                             ? ", " + duration_text(c["late_ms"].get<protocol::Timestamp>()) +
                                   " after its time"
                             : std::string());
        } else {
            std::println("expired request {} ({}) {}, {} after its deadline",
                         c["request"].get<std::string>().substr(0, 12),
                         c["request_kind"].get<std::string>(), where,
                         duration_text(c["overdue_ms"].get<protocol::Timestamp>()));
        }
    }
    for (const Json& f : round["refused"]) {
        std::println("refused {} on {}: {}", f["function"].get<std::string>(),
                     f["instance"].get<std::string>().substr(0, 12),
                     f["reason"].get<std::string>());
    }
    if (round["calls"].empty() && round["refused"].empty()) {
        std::println("{}: nothing due", round["at"].get<std::string>());
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Keepers
// ---------------------------------------------------------------------------

int cmd_keeper_add(const Args& args) {
    Session session(args);
    const std::string name = args.positional().front();
    std::vector<protocol::Id> contracts;
    for (const std::string& c : split(args.need("contracts"), ',')) {
        contracts.push_back(session.contract_id(c));
    }
    std::ranges::sort(contracts, {}, [](const protocol::Id& id) { return protocol::key_of(id); });
    contracts.erase(std::ranges::unique(contracts).begin(), contracts.end());
    if (contracts.empty()) {
        throw UsageError{"--contracts names at least one contract"};
    }
    auto has_call = [&](const std::string& function) {
        return std::ranges::any_of(contracts, [&](const protocol::Id& c) {
            const auto& interface = session.state().contract(c)->interface;
            const auto found = interface.find(function);
            return found != interface.end() && found->second == protocol::FunctionKind::call;
        });
    };
    std::vector<std::string> functions;
    if (const auto list = args.get("functions")) {
        functions = split(*list, ',');
        for (const std::string& f : functions) {
            if (!has_call(f)) {
                throw UsageError{"--functions: none of the contracts has a function " + f +
                                 " for instances"};
            }
        }
    } else {
        for (const protocol::Id& c : contracts) {
            for (std::string& rule : node::time_rules(*session.state().contract(c))) {
                functions.push_back(std::move(rule));
            }
        }
        if (has_call("result")) {
            functions.emplace_back("result");
        }
        if (functions.empty()) {
            throw UsageError{"give --functions: these contracts have no time rules (functions "
                             "when.*) and no function result (a requests' reply)"};
        }
    }
    std::ranges::sort(functions);
    functions.erase(std::ranges::unique(functions).begin(), functions.end());
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::contract_call};
    scope.contracts = contracts;
    scope.functions = functions;
    scope.not_after = validity_end(args);
    const NewActorKey key = new_actor_key(args, "the keeper's");

    const auto signer = load_signer(args.need("as"), args);
    const std::optional<protocol::Provenance> provenance = session.provenance(args);
    const auto presence = presence_request(args);
    const protocol::Id actor =
        session.submit(*signer,
                       protocol::ActorRegisterBody{protocol::ActorKind::device, name, key.key,
                                                   std::nullopt, std::nullopt},
                       args.get("delegation"), provenance, presence);
    protocol::Id delegation;
    try {
        delegation = session.submit(*signer, protocol::DelegationGrantBody{actor, scope},
                                    args.get("delegation"), provenance, presence);
    } catch (const CommandError& e) {
        throw CommandError{"registered \"" + name + "\" as " + hex_id(actor) +
                           ", but its delegation was refused (" + e.message +
                           "): grant one with delegation grant, or revoke the actor"};
    }
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    if (args.json()) {
        Json out = keeper_json(session, *session.state().actor(actor), now, false);
        out["actor_statement_id"] = id_json(actor);
        out["delegation_statement_id"] = id_json(delegation);
        out["key_file"] = key.file ? Json(*key.file) : Json(nullptr);
        print_json(out);
        return exit_ok;
    }
    std::println("registered device \"{}\" as {}", name, hex_id(actor));
    std::println("granted delegation {}: {}", hex_id(delegation),
                 keeper_scope_text(session, *session.state().delegation(delegation), now));
    if (key.file) {
        std::println("its key is in {} (encrypted): give it to the keeper alone (serve "
                     "--keeper-key, or keeper run --as)",
                     *key.file);
    }
    return exit_ok;
}

int cmd_keeper_list(const Args& args) {
    Session session(args);
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    const std::optional<protocol::Id> contract =
        args.has("contract") ? std::optional(session.contract_id(*args.get("contract")))
                             : std::nullopt;
    Json out = Json::array();
    bool any = false;
    for (const protocol::Id& id : node::keeper_actors(session.state())) {
        const protocol::ActorState& actor = *session.state().actor(id);
        const auto delegations = keeper_delegations(session, id);
        const bool active = !actor.revoked && std::ranges::any_of(delegations, [&](const auto* d) {
            return delegation_active(*d, now);
        });
        const bool matches = !contract || std::ranges::any_of(delegations, [&](const auto* d) {
            return !d->scope.contracts || std::ranges::contains(*d->scope.contracts, *contract);
        });
        if ((!active && !args.has("all")) || !matches) {
            continue;
        }
        any = true;
        if (args.json()) {
            out.push_back(keeper_json(session, actor, now, false));
            continue;
        }
        std::string scope;
        for (const protocol::DelegationState* d : delegations) {
            if (delegation_active(*d, now)) {
                scope += (scope.empty() ? "" : "; ") + keeper_scope_text(session, *d, now);
            }
        }
        std::println("{}  {:<6} {:<20} {}{}", short_id(id), kind_text(actor.kind),
                     "\"" + actor.display_name + "\"",
                     scope.empty() ? std::string("no valid delegation") : scope,
                     actor.revoked ? "  [revoked]" : "");
    }
    if (args.json()) {
        print_json(out);
    } else if (!any) {
        std::println("no keepers (keeper add registers one)");
    }
    return exit_ok;
}

int cmd_keeper_show(const Args& args) {
    Session session(args);
    const protocol::ActorState& actor = keeper_named(session, args.positional().front());
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    const Json j = keeper_json(session, actor, now, true);
    if (args.json()) {
        print_json(j);
        return exit_ok;
    }
    std::println("keeper:      {}", hex_id(actor.id));
    std::println("name:        {}", actor.display_name);
    std::println("kind:        {}", kind_text(actor.kind));
    std::println("status:      {}", actor.revoked             ? "REVOKED"
                                    : j["active"].get<bool>() ? "active"
                                                              : "no valid delegation");
    bool first = true;
    for (const protocol::DelegationState* d : keeper_delegations(session, actor.id)) {
        std::println("{}{} {}", first ? "delegation:  " : "             ", short_id(d->id),
                     keeper_scope_text(session, *d, now));
        first = false;
    }
    std::println("calls:       {} time rule(s) fired, {} request(s) expired",
                 j["rules_fired"].get<std::size_t>(), j["expiries"].get<std::size_t>());
    for (const Json& c : j["calls"]) {
        std::println("  #{:<5} {} on {}{}", c["index"].get<std::uint64_t>(),
                     c["function"].get<std::string>(),
                     c["instance"].get<std::string>().substr(0, 12),
                     c["request"].is_null()
                         ? std::string()
                         : ", expiring request " + c["request"].get<std::string>().substr(0, 12));
    }
    if (!j["due"].is_null()) {
        const Json& due = j["due"];
        std::println("due now:     {} time rule(s), {} expiry(ies)", due["rules"].size(),
                     due["expiries"].size());
        for (const Json& r : due["rules"]) {
            std::println("  {} on {}", r["function"].get<std::string>(),
                         r["instance"].get<std::string>().substr(0, 12));
        }
        for (const Json& e : due["expiries"]) {
            std::println(
                "  expire request {} ({}) on {}", e["request"].get<std::string>().substr(0, 12),
                e["kind"].get<std::string>(), e["instance"].get<std::string>().substr(0, 12));
        }
    }
    return exit_ok;
}

int cmd_keeper_revoke(const Args& args) {
    Session session(args);
    const protocol::ActorState& actor = keeper_named(session, args.positional().front());
    const protocol::Id actor_id = actor.id;
    const std::string name = actor.display_name;
    const bool keep_actor = args.has("keep-actor");
    if (actor.revoked && keep_actor) {
        throw CommandError{"\"" + name + "\" is revoked already"};
    }
    std::vector<protocol::Id> revoked;
    for (const protocol::DelegationState* d : keeper_delegations(session, actor_id)) {
        if (!d->revoked) {
            revoked.push_back(d->id);
        }
    }
    std::vector<protocol::Id> statements;
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
        std::println("revoked keeper \"{}\" {}: it calls nothing more", name, hex_id(actor_id));
    } else {
        std::println("\"{}\" {} calls nothing more under its delegations", name, hex_id(actor_id));
    }
    return exit_ok;
}

int cmd_keeper_due(const Args& args) {
    if (const auto url = server_option(args)) {
        const Json due = server_due(args, *url);
        if (args.json()) {
            print_json(due_for_scripts(due));
        } else {
            print_due(due, nullptr);
        }
        return exit_ok;
    }
    Session session(args);
    node::DueOptions options;
    options.now = args.has("at") ? parse_time(*args.get("at")) : ledger::SystemClock{}.now();
    options.grace = grace_of(args).value_or(node::default_expiry_grace);
    if (const auto keeper = args.get("keeper")) {
        options.keeper = session.actor_id(*keeper);
    }
    if (const auto contract = args.get("contract")) {
        options.contract = session.contract_id(*contract);
    }
    if (const auto instance = args.get("instance")) {
        options.instance = session.instance_id(*instance);
    }
    if (const auto start = args.get("start")) {
        options.start = parse_number(*start, "--start");
    }
    options.max_runs = run_limit(args);
    const Json due = local_due(session, options);
    if (args.json()) {
        print_json(due_for_scripts(due));
    } else {
        print_due(due, &session);
    }
    return exit_ok;
}

int cmd_keeper_run(const Args& args) {
    const auto signer = load_signer(args.need("as"), args);
    const protocol::Timestamp grace = grace_of(args).value_or(node::default_expiry_grace);
    const std::size_t limit = run_limit(args);
    std::uint64_t every = 0;
    if (const auto e = args.get("every")) {
        every = parse_number(*e, "--every");
        if (every == 0 || every > 86'400) {
            throw UsageError{"--every is 1 to 86400 seconds"};
        }
    }
    std::uint64_t rounds = every > 0 ? 0 : 1;
    if (const auto r = args.get("rounds")) {
        if (every == 0) {
            throw UsageError{"--rounds goes with --every"};
        }
        rounds = parse_number(*r, "--rounds");
        if (rounds == 0) {
            throw UsageError{"--rounds is at least 1"};
        }
    }
    for (std::uint64_t n = 0; rounds == 0 || n < rounds; ++n) {
        if (n > 0) {
            std::this_thread::sleep_for(std::chrono::seconds(every));
        }
        const Json round = keeper_round(args, *signer, grace, limit);
        if (args.json()) {
            if (every > 0) {
                std::println("{}", round.dump()); // one line a round
            } else {
                print_json(round);
            }
        } else {
            print_round(round);
        }
        std::fflush(stdout);
    }
    return exit_ok;
}

} // namespace cexchain::cli
