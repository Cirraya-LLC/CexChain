// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/lower.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/vm.hpp>

/// Part of cexchain::bo, the compiler proper (GCC 16). Running a contract's
/// `test` blocks (`bo test`): each test runs its own
/// instance of the compiled contract exactly as a ledger would, every call
/// through protocol::encode_contract_input, vm::run, and
/// protocol::decode_contract_output.
///
/// A scenario's ledgers:
///   - every party a test names is a ledger of its own, whose id is the
///     SHA-256 of "cexchain-bo-test ledger " and the party's key (a role's
///     concept id, `role.supplier`, or a name as written, `bank1`), so the
///     same in every language and every run;
///   - the first step creates the instance (`issue` for an asset, `create`
///     otherwise); its subject is the home, whose ledger runs the contract
///     (`we`, if the contract has that role);
///   - the creation binds each role bound at creation to the role's own
///     ledger (the home's, for the role that creates); a role an action binds
///     (`can pledge to bank`) is bound to the ledger the step's `to` names;
///     once bound, a role in a step stands for that ledger.
/// A step's call:
///   - is signed by the subject: the caller's signer when the subject is the
///     home, else the signer of the subject's consent. A person who proves
///     presence with `in person` (kind 1, a passkey), an AI agent with `by AI
///     agent` (kind 2), the organization otherwise (kind 0);
///   - runs first without consents, as the home does to learn whom to ask;
///     then every party the contract asks for consents (its signer the
///     organization's, but the subject's own), and the call runs again, until
///     it is accepted, refused, or waits only for parties that do not consent.
///     Parties that do not consent: those the expectation names (`-> consent
///     of bank`), and the party that starts the action (`by`) when the step's
///     subject is someone else. The home agrees by making the call, so a step
///     whose subject is not the home's party waits for the home when the home
///     starts the action;
///   - acts on the test's instance; once a split has made parts (R30), on
///     the instance the party it names after the action holds (`issuer pay
///     smith1`), else on the one whose holder, pledgee, or payee (any party
///     field) the subject is: of those, the one that takes calls, else the
///     one final instance. A part's id is protocol::child_instance_id of its
///     parent's id and its position, its view names its parent and depth,
///     and the report names it by its path (part 1.2: the second part of the
///     first part);
///   - happens at the time of the step before it, or on the day `at DATE`
///     names (local midnight, +08:00); a test starts on 2026-01-01, or on its
///     first `at` date if that is earlier. Time never goes back (the checker
///     sees to it).
/// A step that answers a request , `executor notify done [with result =
/// TEXT, reason = TEXT] [at DATE]`, `keeper notify expires at DATE`, or a
/// party's by hand, answers the instance's oldest open request of that kind,
/// as the ledger takes answers: a call of the request's reply with the
/// request in input key 9, no consents, the executor and the keeper signing
/// as the home's devices. The ledger refuses an answer when no request of
/// the kind is open, an expiry before the deadline, and an accept that would
/// leave more than 64 open requests; a final instance takes answers, stays
/// final, and makes no requests. Request ids derive from a call id of the
/// instance and its head (call_prefix in scenario.cpp).
/// A step passes if what happened is what it expects (`-> STATE`, `->
/// refused`, `-> refused "REASON"` with the reason exactly as the contract
/// gives it, `-> consent of PARTY`), or, without an expectation, if the call
/// is accepted. A test stops at its first failing step.
namespace cexchain::bo {

enum class StepStatus : std::uint8_t { passed, failed, skipped };

inline constexpr std::array<std::string_view, 3> step_status_names{"passed", "failed", "skipped"};

/// What happened when a step ran.
enum class Happened : std::uint8_t {
    none,           ///< not run
    accepted,       ///< the contract accepted the call
    waits,          ///< the call waits for consents (or for the home's call)
    refused,        ///< the contract refused it
    no_instance,    ///< the ledger refuses: there is no instance
    final_instance, ///< the ledger refuses: the instance is final
    broken,         ///< the code did what compiled code never does (a bug)
    no_part,        ///< the step names no single instance of the test's (it fails)
    no_request,     ///< the ledger refuses an answer: no request of the kind is open
    early,          ///< the ledger refuses an expiry before the request's deadline
    too_many,       ///< the ledger refuses: the instance would have more than 64 open requests
};

inline constexpr std::array<std::string_view, 11> happened_names{
    "none",   "accepted", "waits",      "refused", "no-instance",      "final-instance",
    "broken", "no-part",  "no-request", "early",   "too-many-requests"};

/// One run of the contract.
struct TestCall {
    protocol::ContractInput input;
    Bytes encoded;
    vm::Outcome run;
    std::optional<protocol::ContractOutput> output;
};

struct StepResult {
    StepStatus status = StepStatus::skipped;
    Happened happened = Happened::none;
    /// The home of the step's test: the ledger that runs the contract.
    protocol::Id home;
    /// When the step happens: milliseconds since the epoch.
    std::int64_t time = 0;
    /// Accepted: the instance's state, its events, and whether it is final.
    std::string state;
    std::vector<std::string> events;
    bool final = false;
    /// Accepted: the ledgers that consented, ascending.
    std::vector<protocol::Id> consents;
    /// Waits: the ledgers whose consent the call lacks, ascending (the home
    /// among them when the call waits for the home's).
    std::vector<protocol::Id> waits;
    /// Expectation::waits: the ledgers the step expects it to wait for.
    std::vector<protocol::Id> expected_waits;
    /// Refused: the reason as the contract gives it ("bo:requires sign 2",
    /// or a `reject` text). Broken: what went wrong.
    std::string reason;
    /// The calls run, in order: without consents, then with those given.
    std::vector<TestCall> calls;
    /// Accepted as an AI agent's proposal of this action (its function's
    /// name), awaiting approval: the instance did not change.
    std::string proposed;
    /// Accepted with a bill made (R26): the bill, as its event gives it, in
    /// short ("price=11005 total=11665 VAT=660@60000"; amounts in the minor
    /// unit, rates in millionths, each line's charges in brackets).
    std::string bill;
    /// The part the step acted on, by its path ("1.2"); empty for the
    /// instance the test created. Accepted: the parts the call created.
    std::string part;
    std::size_t parts = 0;
    /// No part: the party the step named as the holder, if it named one.
    std::optional<protocol::Id> holder;
    /// Accepted: the requests the call made , each its kind and
    /// deadline. An answer: the kind, and the deadline of the request it
    /// answers (no_request: none).
    std::vector<std::pair<std::string, std::int64_t>> requests;
    std::string kind;
    std::int64_t deadline = 0;
    /// The contract's offset from UTC, for the times the report writes.
    std::int64_t offset_ms = 0;
    /// The values of fields the step expects (Step::fields), by wire name,
    /// as compiled code keeps them; and, accepted, those the instance holds
    /// otherwise (null for a field it does not hold).
    std::vector<std::pair<std::string, cbor::Value>> expected_fields;
    std::vector<std::pair<std::string, cbor::Value>> differing;
};

struct TestResult {
    bool passed = false;
    /// The home's ledger.
    protocol::Id home;
    /// One per step, in order.
    std::vector<StepResult> steps;
};

/// A ledger the tests name.
struct TestLedger {
    protocol::Id id;
    /// How the tests name it: a role word, or a name as written.
    const Concept* word = nullptr;
    std::string name;
};

struct TestResults {
    /// One per test of the model, in order.
    std::vector<TestResult> tests;
    /// Every ledger the tests named, ascending by id.
    std::vector<TestLedger> ledgers;
    std::size_t passed = 0;
    std::size_t failed = 0;

    [[nodiscard]] const TestLedger* ledger(const protocol::Id& id) const noexcept;
};

/// When a test starts, unless its first `at` date is earlier: 2026-01-01,
/// local midnight at the contract's offset (+08:00 unless it names one).
[[nodiscard]] std::int64_t test_start_ms(std::int64_t offset_ms = default_offset_ms) noexcept;

/// A test ledger's id: SHA-256("cexchain-bo-test ledger " + key).
[[nodiscard]] protocol::Id test_ledger_id(std::string_view key, const crypto::Provider& provider);

/// Runs every test of a model that checked without errors on the code
/// built from it.
[[nodiscard]] TestResults run_tests(const model::Model& model, const Build& build,
                                    const crypto::Provider& provider);

/// A ledger as the report names it, in a pack's language: a role's word
/// (its object form where the pack has one: "the supplier"), or the name.
[[nodiscard]] std::string ledger_label(const TestResults& results, const protocol::Id& id,
                                       const Pack* language);

/// The step as written in the source, its expectation included.
[[nodiscard]] std::string step_source(std::string_view source, const model::Step& step);

/// What a step expects, in words of a pack's language.
[[nodiscard]] std::string expectation_text(const model::Step& step, const StepResult& result,
                                           const TestResults& results, const Pack* language);

/// What happened, in words of a pack's language (a refusal of the
/// compiler's own worded as the pack says, with its code).
[[nodiscard]] std::string outcome_text(const StepResult& result, const TestResults& results,
                                       const Pack* language);

/// For a step the contract refused, the clause of the contract text the
/// refusal comes from: the requirement it names (`bo:requires sign 2`), the
/// requirement asking for presence (`bo:in-person sign`), the action's state
/// change (`bo:state sign`), or the `reject` with that text; null if none.
[[nodiscard]] const ExplainedClause* refusal_clause(const Explained& text,
                                                    const model::Model& model,
                                                    const model::Step& step,
                                                    const StepResult& result);

/// The results as people read them, in a pack's language (English if
/// null): each test, passed or failed; each step as written, with what it
/// expected (when it failed), what happened, and for a refusal the clause of
/// the contract text; then the count.
[[nodiscard]] std::string test_report(const model::Model& model, const TestResults& results,
                                      std::string_view source, const Pack* language);

/// The results as canonical text, without places, spellings, or languages
/// (the same for one contract and its tests in any language): each step's
/// status, time, what happened (ledgers by key), and each call's fuel.
[[nodiscard]] std::string dump(const model::Model& model, const TestResults& results);

} // namespace cexchain::bo
