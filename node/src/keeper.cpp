// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <map>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include <cexchain/core/bytes.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/keeper.hpp>

namespace cexchain::node {

namespace {

using json = nlohmann::json;

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

/// Why a run does not end in an accept, in a few words.
std::string refusal_reason(const protocol::ContractRun& run) {
    if (run.outcome.trap) {
        if (*run.outcome.trap == vm::Trap::aborted) {
            std::string reason(run.outcome.abort_reason.begin(), run.outcome.abort_reason.end());
            const bool readable = std::ranges::all_of(
                reason, [](char c) { return static_cast<unsigned char>(c) >= 0x20; });
            return "the contract refuses: " + (readable ? reason : std::string("(not text)"));
        }
        return "the contract trapped (" + std::string(vm::name(*run.outcome.trap)) + ")";
    }
    if (run.malformed) {
        return "the contract's output is not well formed";
    }
    return "the contract asks for consents";
}

/// An accept that leaves the instance as it is: a call of it would only
/// move the head, so a rule that accepts it is not due.
bool changes_nothing(const protocol::InstanceState& instance, const protocol::ContractAccept& a) {
    return a.state == instance.state && (!a.status || a.status == instance.status) &&
           (!a.parties || *a.parties == instance.parties) && a.events.empty() &&
           (!a.final || instance.final) && a.children.empty() && a.requests.empty();
}

/// The rule's time and lateness, from an event ["when", {"time", "late"}].
void rule_timing(const protocol::ContractAccept& accept, DueRule& rule) {
    for (const protocol::ContractEvent& e : accept.events) {
        if (e.name != "when") {
            continue;
        }
        if (const cbor::Value* t = e.data.find("time")) {
            rule.time = t->as_uint64();
        }
        if (const cbor::Value* l = e.data.find("late")) {
            rule.late = l->as_uint64();
        }
        return;
    }
}

/// Runs the call as the caller would sign it at `now`, unsigned (a dry run
/// needs only the statement): the run, or why the ledger refuses it after.
struct DryRun {
    std::optional<protocol::ContractRun> run;
    std::string refused;
};

class Scanner {
public:
    Scanner(const crypto::Provider& provider, const protocol::LedgerState& state,
            const DueOptions& options, protocol::Id caller)
        : provider_(provider), state_(state), options_(options), caller_(std::move(caller)) {
        for (const protocol::Id& k : keeper_actors(state)) {
            const protocol::ActorState* a = state.actor(k);
            if (a != nullptr && !a->revoked) {
                keepers_.push_back(k);
            }
        }
    }

    /// The delegation `actor` would call under, if any covers the call.
    [[nodiscard]] std::optional<std::optional<protocol::Id>>
    authority(const protocol::Id& actor, const protocol::Id& contract,
              const protocol::ContractCallBody& call) const {
        const protocol::ActorState* a = state_.actor(actor);
        if (a == nullptr || a->revoked) {
            return std::nullopt;
        }
        if (a->is_organization()) {
            return std::optional<protocol::Id>();
        }
        auto chosen = choose_delegation(state_, actor, protocol::StatementType::contract_call,
                                        std::nullopt, options_.now, contract, &call);
        if (!chosen) {
            return std::nullopt;
        }
        return std::optional<protocol::Id>(*chosen);
    }

    /// The keepers that may make the call (without DueOptions::keeper).
    [[nodiscard]] std::vector<protocol::Id> covering(const protocol::Id& contract,
                                                     const protocol::ContractCallBody& call) const {
        std::vector<protocol::Id> out;
        if (options_.keeper) {
            return out;
        }
        for (const protocol::Id& k : keepers_) {
            if (authority(k, contract, call)) {
                out.push_back(k);
            }
        }
        return out;
    }

    /// A dry run of the call by the caller under `delegation`.
    DryRun run(const protocol::ContractCallBody& call,
               const std::optional<protocol::Id>& delegation) {
        protocol::SignedStatement s;
        s.statement.ledger_id = state_.ledger_id();
        s.statement.actor_id = caller_;
        s.statement.delegation_id = delegation;
        s.statement.issued_at = options_.now;
        s.statement.body = call;
        DryRun out;
        auto run = state_.run_contract(provider_, s, options_.now);
        ++work_.runs;
        if (!run) {
            out.refused = std::string(run.error().detail);
            return out;
        }
        work_.fuel += run->outcome.fuel_used;
        if (const protocol::ContractAccept* accept = run->accepted()) {
            Status allowed = state_.check_children(call, *accept);
            if (allowed) {
                allowed = state_.check_requests(call, *accept, options_.now);
            }
            if (!allowed) {
                out.refused = "the ledger refuses the call: " + std::string(allowed.error().detail);
            }
        } else {
            out.refused = refusal_reason(*run);
        }
        out.run = std::move(*run);
        return out;
    }

    /// The runs an instance needs: its rules (unless final) and its expired
    /// requests.
    [[nodiscard]] std::size_t cost(const protocol::InstanceState& instance,
                                   const std::vector<std::string>& rules) const {
        std::size_t n = options_.rules && !instance.final ? rules.size() : 0;
        if (options_.expiries) {
            for (const protocol::CompactId& id : instance.open_requests) {
                const protocol::RequestState* r = state_.request(id);
                n += r != nullptr && expired(*r) ? 1U : 0U;
            }
        }
        return n;
    }

    [[nodiscard]] bool expired(const protocol::RequestState& r) const noexcept {
        return r.open() && r.deadline <= options_.now &&
               options_.now - r.deadline >= options_.grace;
    }

    void scan_instance(const protocol::InstanceState& instance,
                       const std::vector<std::string>& rules) {
        ++work_.instances;
        const protocol::Id contract = instance.contract.id();
        // Expiries first: their deadlines have passed.
        if (options_.expiries) {
            for (const protocol::CompactId& id : instance.open_requests) {
                const protocol::RequestState* r = state_.request(id);
                if (r == nullptr || !expired(*r)) {
                    continue;
                }
                DueExpiry e{.request = r->id.id(),
                            .instance = instance.id.id(),
                            .contract = contract,
                            .head = instance.head,
                            .kind = r->kind,
                            .reply = r->reply,
                            .deadline = r->deadline,
                            .keepers = {}};
                const protocol::ContractCallBody call = expiry_call(e);
                const auto delegation = authority(caller_, contract, call);
                if (!delegation) {
                    continue; // not the keeper's to answer
                }
                DryRun dry = run(call, *delegation);
                if (!dry.refused.empty()) {
                    work_.refused.push_back({e.instance, e.reply, e.request, dry.refused});
                    continue;
                }
                e.keepers = covering(contract, call);
                work_.expiries.push_back(std::move(e));
            }
        }
        if (!options_.rules || instance.final) {
            return;
        }
        for (const std::string& function : rules) {
            DueRule rule{.instance = instance.id.id(),
                         .contract = contract,
                         .head = instance.head,
                         .status = instance.status,
                         .function = function,
                         .time = std::nullopt,
                         .late = std::nullopt,
                         .keepers = {}};
            const protocol::ContractCallBody call = rule_call(rule);
            const auto delegation = authority(caller_, contract, call);
            if (!delegation) {
                continue;
            }
            DryRun dry = run(call, *delegation);
            const protocol::ContractAccept* accept = dry.run ? dry.run->accepted() : nullptr;
            if (accept == nullptr || changes_nothing(instance, *accept)) {
                continue; // not due: refused, or nothing to do
            }
            if (!dry.refused.empty()) {
                work_.refused.push_back({rule.instance, function, std::nullopt, dry.refused});
                continue;
            }
            rule_timing(*accept, rule);
            rule.keepers = covering(contract, call);
            work_.rules.push_back(std::move(rule));
        }
    }

    Result<DueWork> scan() {
        work_.at = options_.now;
        work_.grace = options_.grace;
        work_.keeper = options_.keeper;
        // Each contract's rules, once.
        std::map<protocol::IdKey, std::vector<std::string>> rules;
        for (const auto& [key, c] : state_.contracts()) {
            rules.emplace(c.id.key(), time_rules(c));
        }
        auto scan_one = [&](const protocol::InstanceState& instance, std::uint64_t position) {
            if (options_.contract && !(instance.contract == *options_.contract)) {
                return true;
            }
            const auto found = rules.find(instance.contract.key());
            static const std::vector<std::string> none;
            const std::vector<std::string>& its = found == rules.end() ? none : found->second;
            const std::size_t needs = cost(instance, its);
            if (needs > 0 && work_.runs > 0 && work_.runs + needs > options_.max_runs) {
                work_.next = position;
                return false;
            }
            scan_instance(instance, its);
            return true;
        };
        if (options_.instance) {
            if (const protocol::InstanceState* i = state_.instance(*options_.instance)) {
                scan_one(*i, 0);
            }
            return std::move(work_);
        }
        std::uint64_t position = 0;
        for (const auto& [key, instance] : state_.instances()) {
            if (position >= options_.start && !scan_one(instance, position)) {
                break;
            }
            ++position;
        }
        return std::move(work_);
    }

private:
    const crypto::Provider& provider_;
    const protocol::LedgerState& state_;
    const DueOptions& options_;
    protocol::Id caller_;
    std::vector<protocol::Id> keepers_;
    DueWork work_;
};

json ids_json(const std::vector<protocol::Id>& ids) {
    json out = json::array();
    for (const protocol::Id& id : ids) {
        out.push_back(hex(id));
    }
    return out;
}

template <class T>
json optional_json(const std::optional<T>& value) {
    return value ? json(*value) : json(nullptr);
}

} // namespace

bool is_time_rule(std::string_view function) noexcept {
    return function.starts_with(time_rule_prefix) && function.size() > time_rule_prefix.size();
}

std::vector<std::string> time_rules(const protocol::ContractState& contract) {
    std::vector<std::string> out;
    for (const auto& [name, kind] : contract.interface) {
        if (kind == protocol::FunctionKind::call && is_time_rule(name)) {
            out.push_back(name);
        }
    }
    return out; // the interface is a std::map: name order
}

bool is_keeper_delegation(const protocol::DelegationState& d) noexcept {
    return d.scope.statement_types.size() == 1 &&
           d.scope.statement_types.front() == protocol::StatementType::contract_call &&
           d.scope.functions.has_value() && !d.scope.request_kinds.has_value();
}

std::vector<protocol::Id> keeper_actors(const protocol::LedgerState& state) {
    std::vector<protocol::Id> out;
    for (const auto& [key, d] : state.delegations()) {
        if (is_keeper_delegation(d) && !std::ranges::contains(out, d.grantee.id())) {
            out.push_back(d.grantee.id());
        }
    }
    // In log order of the actors.
    std::vector<protocol::Id> ordered;
    for (const auto& [key, a] : state.actors()) {
        if (std::ranges::contains(out, a.id.id())) {
            ordered.push_back(a.id.id());
        }
    }
    return ordered;
}

Result<DueWork> find_due(const crypto::Provider& provider, const protocol::LedgerState& state,
                         const DueOptions& options) {
    protocol::Id caller;
    if (options.keeper) {
        const protocol::ActorState* keeper = state.actor(*options.keeper);
        if (keeper == nullptr || keeper->revoked) {
            return fail(Errc::not_found, "the keeper is not an active actor of this ledger");
        }
        caller = *options.keeper;
    } else {
        bool found = false;
        for (const auto& [key, a] : state.actors()) {
            if (a.is_organization()) {
                caller = a.id.id();
                found = true;
                break;
            }
        }
        if (!found) {
            return fail(Errc::not_found, "the ledger has no organization actor");
        }
    }
    if (options.max_runs == 0 || options.max_runs > max_due_runs) {
        return fail(Errc::invalid_argument, "a scan makes 1 to 100,000 contract runs");
    }
    Scanner scanner(provider, state, options, caller);
    return scanner.scan();
}

protocol::ContractCallBody rule_call(const DueRule& rule) {
    protocol::ContractCallBody body;
    body.instance = rule.instance;
    body.head = rule.head;
    body.function = rule.function;
    body.arguments = cbor::Value::null();
    return body;
}

protocol::ContractCallBody expiry_call(const DueExpiry& expiry) {
    protocol::ContractCallBody body;
    body.instance = expiry.instance;
    body.head = expiry.head;
    body.function = expiry.reply;
    body.arguments = cbor::Value::null();
    body.answer = protocol::ContractAnswer{expiry.request, protocol::AnswerStatus::expired};
    return body;
}

std::string due_json_text(const DueWork& work) {
    json rules = json::array();
    for (const DueRule& r : work.rules) {
        rules.push_back({{"instance", hex(r.instance)},
                         {"contract", hex(r.contract)},
                         {"head", r.head},
                         {"status", optional_json(r.status)},
                         {"function", r.function},
                         {"time", optional_json(r.time)},
                         {"late_ms", optional_json(r.late)},
                         {"keepers", ids_json(r.keepers)}});
    }
    json expiries = json::array();
    for (const DueExpiry& e : work.expiries) {
        expiries.push_back({{"request", hex(e.request)},
                            {"instance", hex(e.instance)},
                            {"contract", hex(e.contract)},
                            {"head", e.head},
                            {"kind", e.kind},
                            {"reply", e.reply},
                            {"deadline", e.deadline},
                            {"overdue_ms", work.at - e.deadline},
                            {"keepers", ids_json(e.keepers)}});
    }
    json refused = json::array();
    for (const DueRefusal& r : work.refused) {
        refused.push_back({{"instance", hex(r.instance)},
                           {"function", r.function},
                           {"request", r.request ? json(hex(*r.request)) : json(nullptr)},
                           {"reason", r.reason}});
    }
    const json out = {{"at", work.at},
                      {"grace_ms", work.grace},
                      {"keeper", work.keeper ? json(hex(*work.keeper)) : json(nullptr)},
                      {"rules", std::move(rules)},
                      {"expiries", std::move(expiries)},
                      {"refused", std::move(refused)},
                      {"instances", work.instances},
                      {"runs", work.runs},
                      {"fuel", work.fuel},
                      {"next", optional_json(work.next)}};
    return out.dump();
}

} // namespace cexchain::node
