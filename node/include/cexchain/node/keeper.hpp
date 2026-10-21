// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/state.hpp>

/// The keeper (6b; spec section 15): a ledger acts only on calls, so an actor
/// of the home calls each contract's time rules once they are due, and
/// expires the requests left open past their deadline plus a grace period.
/// `serve --keeper-key` runs one inside the server (the leader, in a
/// cluster); `cexchain keeper run` runs one on a ledger directory.
///
/// What is due is found by dry runs at the time asked: a time rule is due if
/// its contract accepts the call (with no arguments) and the call would
/// change something; an expiry is due if the request is open, its deadline
/// plus the grace has passed, and the contract takes the answer. Refused
/// calls record nothing, so asking early is harmless. Each dry run costs one
/// contract run (Bo's time rules: about 10,000 to 13,000 fuel); a scan stops
/// after a bounded number of runs and says where to go on.
namespace cexchain::node {

/// Functions whose names start with this are a contract's time rules: Bo
/// compiles each `when` rule to one (`when.suspend`). A keeper calls them
/// with null arguments; the contract refuses a rule before its time.
inline constexpr std::string_view time_rule_prefix = "when.";

/// A function name that is a time rule's.
[[nodiscard]] bool is_time_rule(std::string_view function) noexcept;

/// A contract's time rules: its functions of kind 2 named `when.*`, in name
/// order.
[[nodiscard]] std::vector<std::string> time_rules(const protocol::ContractState& contract);

/// A keeper's delegation: contract calls only (scope types), narrowed to
/// some functions (key 8), answering no request kinds (no key 9, which would
/// keep it from firing rules). An executor's has key 9.
[[nodiscard]] bool is_keeper_delegation(const protocol::DelegationState& delegation) noexcept;

/// The actors with keeper delegations (any, revoked ones included), in log
/// order.
[[nodiscard]] std::vector<protocol::Id> keeper_actors(const protocol::LedgerState& state);

/// An expiry waits this long after the request's deadline by default, so
/// that a slow but real result is recorded rather than lost.
inline constexpr protocol::Timestamp default_expiry_grace = protocol::Timestamp{15} * 60'000;
/// Contract runs a scan makes at most, by default.
inline constexpr std::size_t default_due_runs = 10'000;
/// The most a scan may be asked to make.
inline constexpr std::size_t max_due_runs = 100'000;

struct DueOptions {
    /// The time the dry runs run at.
    protocol::Timestamp now = 0;
    /// An open request may expire once `now >= deadline + grace`.
    protocol::Timestamp grace = default_expiry_grace;
    /// Whose work: an actor of the ledger, the dry runs' caller, whose
    /// active delegations decide which calls are its to make. Without one,
    /// everything due, run as the organization.
    std::optional<protocol::Id> keeper;
    /// Only instances of this contract, or this instance.
    std::optional<protocol::Id> contract;
    std::optional<protocol::Id> instance;
    /// Rules, expiries, or both.
    bool rules = true;
    bool expiries = true;
    /// Skip the first `start` instances (log order): a scan's `next`.
    std::uint64_t start = 0;
    /// Stop before an instance whose runs would pass this many in all (each
    /// scan finishes at least one instance).
    std::size_t max_runs = default_due_runs;
    /// Scan instances on the process's worker threads (ledger::parallel_for)
    /// rather than on the calling thread alone. Each instance's dry runs
    /// depend on the state, the options, and that instance only, and the
    /// results are merged in log order, so the answer is the same either way.
    bool parallel = true;
    /// Keep each due call's dry run (DueRule::run, DueExpiry::run): a keeper
    /// that makes the calls offers them to the ledger (D-056 P7), which
    /// takes one only if the input it builds is the run's.
    bool keep_runs = false;
};

/// A time rule whose call the contract accepts now.
struct DueRule {
    protocol::Id instance;
    protocol::Id contract;
    /// The instance's head, which the call names.
    std::uint64_t head = 0;
    std::optional<std::string> status;
    std::string function;
    /// The rule's time and how late the call comes, if the contract says
    /// so in an event ["when", {"time": T, "late": L, ...}] (Bo's do).
    std::optional<protocol::Timestamp> time;
    std::optional<protocol::Timestamp> late;
    /// The keepers whose active delegations cover the call (filled without
    /// DueOptions::keeper).
    std::vector<protocol::Id> keepers;
    /// The dry run, with DueOptions::keep_runs.
    std::optional<protocol::ContractRun> run;
};

/// An open request past its deadline plus the grace, whose expiry the
/// contract takes.
struct DueExpiry {
    protocol::Id request;
    protocol::Id instance;
    protocol::Id contract;
    std::uint64_t head = 0;
    std::string kind;
    std::string reply;
    protocol::Timestamp deadline = 0;
    std::vector<protocol::Id> keepers;
    /// The dry run, with DueOptions::keep_runs.
    std::optional<protocol::ContractRun> run;
};

/// Work that is due but would not be recorded: an expiry the contract or
/// the ledger refuses (the request then stays open), or a rule the
/// contract accepts but the ledger's rules for requests or children refuse.
struct DueRefusal {
    protocol::Id instance;
    std::string function;
    std::optional<protocol::Id> request;
    std::string reason;
};

struct DueWork {
    protocol::Timestamp at = 0;
    protocol::Timestamp grace = 0;
    std::optional<protocol::Id> keeper;
    std::vector<DueRule> rules;
    std::vector<DueExpiry> expiries;
    std::vector<DueRefusal> refused;
    /// Instances examined, contract runs made, and their fuel.
    std::size_t instances = 0;
    std::size_t runs = 0;
    std::uint64_t fuel = 0;
    /// Set when max_runs cut the scan short: the `start` to go on from.
    std::optional<std::uint64_t> next;
};

/// What is due on the ledger at `options.now`: a function of the state and
/// the options alone. Fails if `options.keeper` is not an active actor of
/// the ledger. The state must not change while it runs (a ledger's
/// `read_state`).
[[nodiscard]] Result<DueWork> find_due(const crypto::Provider& provider,
                                       const protocol::LedgerState& state,
                                       const DueOptions& options);

/// The call that fires a rule: on the instance at its head, no arguments.
[[nodiscard]] protocol::ContractCallBody rule_call(const DueRule& rule);
/// The answer that expires a request: its reply, null arguments.
[[nodiscard]] protocol::ContractCallBody expiry_call(const DueExpiry& expiry);

/// What is due, as GET /v1/contracts/due answers (JSON text): ids in hex,
/// times in milliseconds since the epoch.
[[nodiscard]] std::string due_json_text(const DueWork& work);

} // namespace cexchain::node
