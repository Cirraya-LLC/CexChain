// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Running tests (milestone 10 of the Bo compiler): `bo test` runs a
// contract's test blocks on its compiled code as a ledger runs calls
// (scenario.hpp). The goldens in tests/bo/golden/test/CASE/ hold each case's
// results as canonical text (results.txt) and its report in each official
// language (en.txt, zh-hant.txt, zh-hans.txt); one contract and its tests
// give the same results whatever language they are written in; and each rule
// of a step is checked: implicit consents, the party that starts an action,
// the home, signers, time, the ledger's own refusals, a failing step that
// stops its test, and the clause of the contract text a refusal comes from.
// Set CEXCHAIN_UPDATE_GOLDENS=1 to rewrite the goldens.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/scenario.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;
const std::filesystem::path source_dir = golden_dir.parent_path().parent_path().parent_path();

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

const PackSet& official_set() {
    static const PackSet set = [] {
        PackSetRead read = make_pack_set({});
        REQUIRE(read.set.has_value());
        return std::move(*read.set);
    }();
    return set;
}

/// A source compiled, and its tests run.
struct Tested {
    Compiled compiled;
    TestResults results;
};

Tested tested(std::string_view source) {
    Tested out;
    out.compiled = compile(source, official_set());
    std::string problems;
    for (const Diagnostic& d : out.compiled.diagnostics) {
        problems += std::string(d.code) + " ";
    }
    INFO(source);
    INFO(problems);
    REQUIRE(out.compiled.build.has_value());
    REQUIRE(out.compiled.model.has_value());
    out.results = run_tests(*out.compiled.model, *out.compiled.build, provider());
    return out;
}

std::string results_of(std::string_view source) {
    const Tested t = tested(source);
    return dump(*t.compiled.model, t.results);
}

/// The golden cases: a name and the source it runs.
std::vector<std::pair<std::string, std::filesystem::path>> cases() {
    return {
        {"agreement", golden_dir / "build/agreement-en/source.bo"},
        {"check-agreement", golden_dir / "check-agreement/source.bo"},
        {"failing", golden_dir / "test/failing/source.bo"},
        {"loan", golden_dir / "check-tests/source.bo"},
        {"supply-agreement", source_dir / "examples/supply-agreement/supply-agreement.bo"},
        // The standard library (milestone 11): the spec's ReceivableFinancing,
        // the native assets' flows, and an AI agent's proposal.
        {"receivable-financing", golden_dir / "test/receivable-financing/source.bo"},
        {"receivable", golden_dir / "test/receivable/source.bo"},
        {"warehouse-receipt", golden_dir / "test/warehouse-receipt/source.bo"},
        {"standard", golden_dir / "check-standard/source.bo"},
        // Time rules and the keeper (milestone 12): the spec's "3 days
        // overdue, suspend", every kind of time, and the IP pool.
        {"time", golden_dir / "test/time/source.bo"},
        {"membership", golden_dir / "check-time/source.bo"},
        {"ip-pool", golden_dir / "test/ip-pool/source.bo"},
        // Lists and charges (milestone 13): the spec's VAT on both sides of
        // its rate change, charges of every kind on one bill, and lists.
        {"tax", golden_dir / "test/tax/source.bo"},
        {"charges", golden_dir / "test/charges/source.bo"},
        {"lists", golden_dir / "test/lists/source.bo"},
        // Splitting (milestone 17): parts, and the demo's receivable.
        {"split", golden_dir / "test/split/source.bo"},
        {"multi-tier-split", source_dir / "examples/multi-tier-split/multi-tier-split.bo"},
        // R31: a counterparty made holder or pledgee consents, whenever its
        // role was bound.
        {"role-taking", golden_dir / "check-role-taking/source.bo"},
        // Measures (G5b): durations divided by durations, field defaults,
        // temperatures and negative literals, expectations on fields.
        {"measures", golden_dir / "test/measures/source.bo"},
        {"shipment", golden_dir / "test/shipment/source.bo"},
        {"shipment-notice", source_dir / "examples/shipment/shipment.bo"},
        // Requests (E8): made by actions and time rules, answered done,
        // failed, and expired, refused by the ledger, and after the end.
        {"requests", golden_dir / "check-requests/source.bo"},
        // A service (E9): subscribed, invoiced, paid, renewed, suspended,
        // resumed, and terminated; the spec's VPS, in English and in
        // Traditional Chinese.
        {"vps", golden_dir / "test/vps/source.bo"},
        {"vps-zh-hant", golden_dir / "test/vps-zh-hant/source.bo"},
        {"services", golden_dir / "check-services/source.bo"},
        // A time rule's action on the next line of its block (E11, codegen
        // 4): the states it ends in are final.
        {"rule-block", golden_dir / "test/rule-block/source.bo"},
    };
}

const Pack* pack(std::string_view id) {
    return official_pack(id);
}

/// The contract every rule below is tested on: a loan the customer must
/// accept in person above HKD 10,000, which a bank bound by the action
/// funds, and which the holder of the note repays.
constexpr std::string_view loan = R"(use commerce
use finance
contract Loan
parties we, customer, bank

thing Note
  amount HKD
  holder customer

can offer by we to bank with fee HKD
  requires consent of customer
  proposed -> offered
can accept by customer
  over 10_000 requires in person
  requires now < 2027-06-01
  offered -> accepted
can repay by holder
  accepted -> repaid
)";

/// The loan with these test lines.
std::string with_tests(std::string_view tests) {
    return std::string(loan) + "\n" + std::string(tests);
}

const TestResult& only(const Tested& t) {
    REQUIRE(t.results.tests.size() == 1);
    return t.results.tests.front();
}

} // namespace

TEST_CASE("bo test: the goldens", "[bo][test]") {
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    for (const auto& [name, path] : cases()) {
        INFO(name);
        const std::string source = read_text(path);
        const Tested t = tested(source);
        const std::filesystem::path dir = golden_dir / "test" / name;
        std::vector<std::pair<std::string, std::string>> texts{
            {"results.txt", dump(*t.compiled.model, t.results)},
            {"en.txt", test_report(*t.compiled.model, t.results, source, pack("en"))},
            {"zh-hant.txt", test_report(*t.compiled.model, t.results, source, pack("zh-Hant-HK"))},
            {"zh-hans.txt", test_report(*t.compiled.model, t.results, source, pack("zh-Hans-CN"))},
        };
        for (const auto& [file, text] : texts) {
            INFO(file);
            if (update) {
                std::filesystem::create_directories(dir);
                std::ofstream(dir / file, std::ios::binary) << text;
            }
            CHECK(text == read_text(dir / file));
        }
        // The same twice; every report ends with its count.
        CHECK(dump(*t.compiled.model, tested(source).results) == texts[0].second);
        const std::size_t total = t.results.tests.size();
        CHECK(texts[1].second.ends_with(
            (total == 1 ? std::string("1 test: ") : std::to_string(total) + " tests: ") +
            std::to_string(t.results.passed) + " passed, " + std::to_string(t.results.failed) +
            " failed.\n"));
        // Only the failing case fails.
        CHECK((t.results.failed > 0) == (name == "failing"));
    }
}

TEST_CASE("bo test: one contract and its tests, in any language, give the same results",
          "[bo][test]") {
    // The agreement in four spellings, its tests included.
    const std::string english = results_of(read_text(golden_dir / "build/agreement-en/source.bo"));
    CHECK(english.find("3 tests: 3 passed, 0 failed") != std::string::npos);
    for (const std::string_view spelling : {"zh-hant", "zh-hans", "mixed"}) {
        INFO(spelling);
        const std::string source =
            read_text(golden_dir / "build" / ("agreement-" + std::string(spelling)) / "source.bo");
        CHECK(results_of(source) == english);
    }
    // The spec's VPS (E9): its contract in four spellings, with the same
    // tests.
    {
        const std::string vps = read_text(golden_dir / "test/vps/source.bo");
        const std::string tests = vps.substr(vps.find("\ntest ") + 1);
        const std::string expected = results_of(vps);
        CHECK(expected.find("5 tests: 5 passed, 0 failed") != std::string::npos);
        for (const std::string_view spelling : {"en", "zh-hant", "zh-hans", "mixed"}) {
            INFO("vps " << spelling);
            const std::string contract =
                read_text(golden_dir / ("example-vps-" + std::string(spelling)) / "source.bo");
            CHECK(results_of(contract + "\n" + tests) == expected);
        }
    }
    // Every case, formatted into each language.
    const Lexicon lexicon(official_set());
    for (const auto& [name, path] : cases()) {
        const std::string source = read_text(path);
        const std::string expected = results_of(source);
        for (const std::string_view language : {"en", "zh-Hant-HK", "zh-Hans-CN"}) {
            INFO(name << " in " << language);
            const Formatted f = format_source(source, official_set(), lexicon, pack(language));
            REQUIRE(f.source.has_value());
            CHECK(results_of(*f.source) == expected);
        }
    }
}

TEST_CASE("bo test: a step expects the values of fields after its call", "[bo][test]") {
    // G5b: `-> STATE, FIELD = VALUE`, or values alone (accepted); a party
    // field by its party.
    const std::string source =
        with_tests("test \"values\"\n"
                   "  we create with amount = HKD 5_000 -> amount = HKD 5_000\n"
                   "  we offer to bank1 with fee = HKD 3 -> offered, "
                   "holder = customer, amount = HKD 5_000\n"
                   "test \"wrong\"\n"
                   "  we create with amount = HKD 5_000\n"
                   "  we offer to bank1 with fee = HKD 3 -> offered, "
                   "holder = bank1, amount = HKD 6_000\n");
    const Tested t = tested(source);
    REQUIRE(t.results.tests.size() == 2);
    CHECK(t.results.tests[0].passed);
    CHECK(t.results.tests[0].steps[1].expected_fields.size() == 2);
    CHECK(t.results.tests[0].steps[1].differing.empty());
    const StepResult& wrong = t.results.tests[1].steps[1];
    CHECK(!t.results.tests[1].passed);
    CHECK(wrong.happened == Happened::accepted);
    REQUIRE(wrong.differing.size() == 2);
    CHECK(wrong.differing[0].first == "holder");
    CHECK(wrong.differing[1].first == "amount");
    CHECK(*wrong.differing[1].second.as_int64() == 500'000);
    const std::string report = test_report(*t.compiled.model, t.results, source, pack("en"));
    // In the words of each language, fields in the contract's order.
    CHECK(report.find("Expected: the call is accepted, and the instance is offered; then amount is "
                      "HKD 6,000.00 and holder is bank1.") != std::string::npos);
    CHECK(report.find("but amount is HKD 5,000.00 and holder is the customer.") !=
          std::string::npos);
}

TEST_CASE("bo test: consents are given by every party asked, but those a step withholds",
          "[bo][test]") {
    // The bank, bound by the offer to a ledger only the test names, and the
    // customer consent; without an expectation, a step expects an accept.
    const Tested t = tested(with_tests("test \"offered\"\n"
                                       "  we create with amount = HKD 5_000\n"
                                       "  we offer to bank1 with fee = HKD 3\n"));
    const TestResult& r = only(t);
    CHECK(r.passed);
    const StepResult& offer = r.steps[1];
    CHECK(offer.happened == Happened::accepted);
    CHECK(offer.state == "offered");
    REQUIRE(offer.consents.size() == 2);
    CHECK(ledger_label(t.results, offer.consents[0], nullptr) != "");
    // The first run asks; the second carries the consents, in ascending
    // order of ledger, none the home's.
    REQUIRE(offer.calls.size() == 2);
    CHECK(offer.calls[0].input.consents.empty());
    REQUIRE(offer.calls[1].input.consents.size() == 2);
    CHECK(std::ranges::lexicographical_compare(offer.calls[1].input.consents[0].first.bytes(),
                                               offer.calls[1].input.consents[1].first.bytes()));
    for (const auto& [id, signer] : offer.calls[1].input.consents) {
        CHECK(id != r.home);
        CHECK(signer.kind == 0);
    }
    // The bank is bound to bank1's ledger by the offer's argument.
    const protocol::Id bank1 = test_ledger_id("bank1", provider());
    CHECK(offer.calls[1].input.arguments.find("bank")->as_bytes() != nullptr);
    CHECK(*offer.calls[1].input.arguments.find("bank")->as_bytes() ==
          Bytes(bank1.bytes().begin(), bank1.bytes().end()));
    CHECK(ledger_label(t.results, bank1, nullptr) == "bank1");
    CHECK(ledger_label(t.results, test_ledger_id("role.customer", provider()), nullptr) ==
          "the customer");
    CHECK(ledger_label(t.results, test_ledger_id("role.customer", provider()),
                       pack("zh-Hant-HK")) == "客戶");
    // The home is we's ledger.
    CHECK(r.home == test_ledger_id("role.we", provider()));

    // Withheld: the call waits for exactly those parties.
    const Tested waits =
        tested(with_tests("test \"waits\"\n"
                          "  we create with amount = HKD 5_000\n"
                          "  we offer to bank1 with fee = HKD 3 -> consent of bank1\n"
                          "  we offer to bank1 with fee = HKD 3 -> consent of (customer, bank1)\n"
                          "  we offer to bank1 with fee = HKD 3 -> consent of customer\n"));
    CHECK(only(waits).passed);
    CHECK(only(waits).steps[1].happened == Happened::waits);
    CHECK(only(waits).steps[2].waits.size() == 2);
    // A consent the call does not need is no wait: the step fails.
    const Tested not_asked =
        tested(with_tests("test \"not asked\"\n"
                          "  we create with amount = HKD 5_000\n"
                          "  we offer to bank1 with fee = HKD 3\n"
                          "  customer accept in person -> consent of bank1\n"));
    CHECK(!only(not_asked).passed);
    CHECK(only(not_asked).steps[2].happened == Happened::accepted);
}

TEST_CASE("bo test: a step whose party does not start the action waits for the one that does",
          "[bo][test]") {
    const Tested t =
        tested(with_tests("test \"starters\"\n"
                          "  we create with amount = HKD 5_000\n"
                          "  customer offer to bank1 with fee = HKD 3 -> consent of we\n"
                          "  we offer to bank1 with fee = HKD 3 -> offered\n"
                          "  we accept -> consent of customer\n"
                          "  customer accept -> accepted\n"
                          "  bank1 repay -> consent of customer\n"
                          "  customer repay -> repaid\n"));
    const TestResult& r = only(t);
    CHECK(r.passed);
    // The home starts the offer: the customer's step waits for the home's
    // call, worded so.
    CHECK(r.steps[1].happened == Happened::waits);
    CHECK(r.steps[1].waits == std::vector<protocol::Id>{r.home});
    CHECK(outcome_text(r.steps[1], t.results, nullptr) == "the call waits for us to make it");
    CHECK(outcome_text(r.steps[1], t.results, pack("zh-Hant-HK")) == "調用正等待我方提交");
    // The holder (a field) starts repay: the bank's step waits for it.
    CHECK(r.steps[5].waits ==
          std::vector<protocol::Id>{test_ledger_id("role.customer", provider())});
}

TEST_CASE("bo test: signers, presence, and AI agents", "[bo][test]") {
    // Over HKD 10,000 the customer must prove presence: an AI agent, or the
    // organization's own signature, is refused; a person in person is not.
    const Tested t = tested(with_tests("test \"presence\"\n"
                                       "  we create with amount = HKD 50_000\n"
                                       "  we offer to bank1 with fee = HKD 3\n"
                                       "  customer accept -> refused \"bo:in-person accept\"\n"
                                       "  customer accept by AI agent -> refused\n"
                                       "  customer accept in person -> accepted\n"));
    const TestResult& r = only(t);
    CHECK(r.passed);
    const auto starter_signer = [&](const StepResult& s) {
        REQUIRE(!s.calls.empty());
        REQUIRE(!s.calls.back().input.consents.empty());
        return s.calls.back().input.consents.front().second;
    };
    CHECK(starter_signer(r.steps[2]).kind == 0);
    CHECK(starter_signer(r.steps[3]).kind == 2);
    CHECK(starter_signer(r.steps[3]).model.has_value());
    CHECK(starter_signer(r.steps[4]).kind == 1);
    CHECK(starter_signer(r.steps[4]).presence == protocol::PresenceMethod::webauthn);
    // The home's own call carries the step's signer.
    const Tested home = tested(with_tests("test \"home\"\n"
                                          "  we create in person with amount = HKD 5\n"
                                          "  we offer to bank1 by AI agent with fee = HKD 3\n"));
    CHECK(only(home).steps[0].calls[0].input.caller_signer.kind == 1);
    CHECK(only(home).steps[1].calls[0].input.caller_signer.kind == 2);
}

TEST_CASE("bo test: time, from 2026-01-01 or the first at, never going back", "[bo][test]") {
    const Tested none = tested(with_tests("test \"no date\"\n"
                                          "  we create with amount = HKD 5\n"));
    CHECK(only(none).steps[0].time == test_start_ms());
    CHECK(test_start_ms() == days_from_civil(2026, 1, 1) * 86'400'000 - default_offset_ms);
    // A test starts on 2026-01-01 (its first date is later); each step keeps
    // the time before it.
    const Tested t = tested(with_tests("test \"late\"\n"
                                       "  we create with amount = HKD 5\n"
                                       "  we offer to bank1 with fee = HKD 3 at 2027-05-01\n"
                                       "  customer accept\n"
                                       "  customer repay at 2027-07-01\n"));
    const TestResult& r = only(t);
    CHECK(r.passed);
    const std::int64_t may = days_from_civil(2027, 5, 1) * 86'400'000 - default_offset_ms;
    CHECK(r.steps[0].time == test_start_ms());
    CHECK(r.steps[1].time == may);
    CHECK(r.steps[2].time == may);
    CHECK(r.steps[2].calls.back().input.time == static_cast<protocol::Timestamp>(may));
    CHECK(r.steps[3].time == days_from_civil(2027, 7, 1) * 86'400'000 - default_offset_ms);
    // A test whose first date is earlier starts then.
    const Tested early = tested(with_tests("test \"early\"\n"
                                           "  we create with amount = HKD 5\n"
                                           "  we offer to bank1 with fee = HKD 3 at 2025-03-01\n"));
    CHECK(only(early).steps[0].time ==
          days_from_civil(2025, 3, 1) * 86'400'000 - default_offset_ms);
    // The contract reads it: too late to accept.
    const Tested late = tested(with_tests("test \"too late\"\n"
                                          "  we create with amount = HKD 5\n"
                                          "  we offer to bank1 with fee = HKD 3\n"
                                          "  customer accept at 2027-06-01 -> refused "
                                          "\"bo:requires accept 2\"\n"));
    CHECK(only(late).passed);
}

TEST_CASE("bo test: time rules, the keeper, a UTC offset, and month ends", "[bo][test]") {
    // Due on 31 January at UTC-05:00: a month later is the end of February
    // (U6), and days are counted at -05:00.
    constexpr std::string_view source = R"(use commerce
contract Rent
parties we, customer

thing Lease
  due date
  fee HKD
  UTC offset "-05:00"

can pause by we
  active -> paused
when due + 1 month and active
  fee = fee + HKD 10
when paused 2 days
  -> ended

test "two days paused"
  we create with due = 2027-01-31, fee = HKD 100 at 2027-01-01
  we pause at 2027-02-28
  keeper ended at 2027-03-01 -> refused "bo:when when.ended"
  keeper ended at 2027-03-02 -> ended
)";
    const Tested t = tested(source);
    REQUIRE(t.compiled.model->utc_offset_ms == -5 * 3'600'000);
    CHECK(t.compiled.model->offset_rule.empty());
    const TestResult& r = only(t);
    CHECK(r.passed);
    constexpr std::int64_t day = 86'400'000;
    constexpr std::int64_t offset = -5 * 3'600'000;
    // Local midnights at -05:00.
    CHECK(r.steps[1].time == days_from_civil(2027, 2, 28) * day - offset);
    // The rule that only sets a field has a function, which no step can name
    // (a step names the action a rule does, or its state change's target).
    CHECK(t.compiled.build->interface.contains("when.rule"));
    CHECK(t.compiled.build->interface.contains("when.ended"));
    // The keeper's call: the rule's function, no arguments, a device.
    const TestCall& kept = r.steps[3].calls.back();
    CHECK(kept.input.function == "when.ended");
    CHECK(kept.input.arguments.is_null());
    CHECK(kept.input.caller_signer.kind == 3);
    CHECK(kept.input.caller == r.steps[0].calls[0].input.caller);
    // The state keeps the time each rule last applied for, and when the
    // instance last changed state; the event says when the rule applied.
    const auto* accept = std::get_if<protocol::ContractAccept>(&*kept.output);
    REQUIRE(accept != nullptr);
    const std::int64_t at = days_from_civil(2027, 3, 2) * day - offset;
    CHECK(*accept->state.find("since")->as_int64() == at);
    CHECK(*accept->state.find("fired")->find("when.ended")->as_int64() == at);
    CHECK(accept->state.find("fired")->find("when.rule")->is_null());
    REQUIRE(accept->events.size() == 2);
    CHECK(accept->events[0].name == "when");
    CHECK(*accept->events[0].data.find("time")->as_int64() == at);
    CHECK(*accept->events[0].data.find("late")->as_int64() == 0);
    CHECK(accept->events[1].name == "ended");
    // The fee rule's time: 28 February at -05:00, not the 31st of a month
    // that has none.
    const Tested fee = tested(std::string(source.substr(0, source.find("test \""))) +
                              "test\n"
                              "  we create with due = 2027-01-31, fee = HKD 100\n");
    const model::Model& m = *fee.compiled.model;
    const Build& b = *fee.compiled.build;
    // Run the rule by hand: on 27 February it is not due; on the 28th it is.
    const auto run_at = [&](std::int64_t time) {
        protocol::ContractInput in = only(fee).steps[0].calls[0].input;
        const auto created =
            std::get<protocol::ContractAccept>(*only(fee).steps[0].calls[0].output);
        in.function = "when.rule";
        in.arguments = cbor::Value::null();
        in.instance = protocol::ContractInstanceView{only(fee).steps[0].calls[0].input.contract,
                                                     1,
                                                     created.state,
                                                     created.status,
                                                     *created.parties,
                                                     {},
                                                     0};
        in.time = static_cast<protocol::Timestamp>(time);
        const auto bytes = protocol::encode_contract_input(in);
        REQUIRE(bytes.has_value());
        const auto module = vm::load(b.code);
        REQUIRE(module.has_value());
        auto outcome = vm::run(*module, *bytes, provider(), crypto::HashAlg::sha256);
        REQUIRE(outcome.has_value());
        return std::string(outcome->abort_reason.begin(), outcome->abort_reason.end());
    };
    CHECK(m.rules.size() == 2);
    CHECK(run_at(days_from_civil(2027, 2, 28) * day - offset - 1) == "bo:when when.rule");
    CHECK(run_at(days_from_civil(2027, 2, 28) * day - offset).empty());
}

TEST_CASE("bo test: the ledger's own refusals, and a test that stops at its first failure",
          "[bo][test]") {
    const Tested t = tested(with_tests("test \"final\"\n"
                                       "  we create with amount = HKD 5\n"
                                       "  we offer to bank1 with fee = HKD 3\n"
                                       "  customer accept\n"
                                       "  customer repay -> repaid\n"
                                       "  customer repay -> refused\n"
                                       "  customer repay -> refused \"bo:state repay\"\n"
                                       "  customer repay\n"));
    const TestResult& r = only(t);
    CHECK(!r.passed);
    CHECK(r.steps[3].final);
    CHECK(r.steps[4].happened == Happened::final_instance);
    CHECK(r.steps[4].calls.empty());
    CHECK(r.steps[4].status == StepStatus::passed);
    // A reason the ledger's refusal does not give.
    CHECK(r.steps[5].status == StepStatus::failed);
    CHECK(r.steps[6].status == StepStatus::skipped);
    CHECK(r.steps[6].calls.empty());
    CHECK(t.results.failed == 1);
    // A creation that waits for the home leaves no instance.
    const Tested none = tested(with_tests("test \"no instance\"\n"
                                          "  we create with amount = HKD 5 -> consent of we\n"
                                          "  we offer to bank1 with fee = HKD 3 -> refused\n"));
    CHECK(only(none).passed);
    CHECK(only(none).steps[1].happened == Happened::no_instance);
    CHECK(outcome_text(only(none).steps[1], none.results, nullptr) ==
          "refused by the ledger: there is no instance, since its creation was not accepted");
}

TEST_CASE("bo test: a refusal names the clause of the contract text it comes from", "[bo][test]") {
    const Tested t = tested(with_tests("test \"clauses\"\n"
                                       "  we create with amount = HKD 50_000\n"
                                       "  customer accept -> refused\n"
                                       "  we offer to bank1 with fee = HKD 3\n"
                                       "  customer accept -> refused\n"
                                       "  customer accept in person at 2027-07-01 -> refused\n"));
    const TestResult& r = only(t);
    CHECK(r.passed);
    const model::Test& test = t.compiled.model->tests.front();
    for (const Pack* language : {pack("en"), pack("zh-Hant-HK"), pack("zh-Hans-CN")}) {
        const Explained text = explain(*t.compiled.model, language);
        const ExplainedClause* state =
            refusal_clause(text, *t.compiled.model, test.steps[1], r.steps[1]);
        REQUIRE(state != nullptr);
        CHECK(state->kind == "transition");
        CHECK(state->function == "accept");
        const ExplainedClause* presence =
            refusal_clause(text, *t.compiled.model, test.steps[3], r.steps[3]);
        REQUIRE(presence != nullptr);
        CHECK(presence->requirement == 1);
        const ExplainedClause* time =
            refusal_clause(text, *t.compiled.model, test.steps[4], r.steps[4]);
        REQUIRE(time != nullptr);
        CHECK(time->requirement == 2);
        CHECK(refusal_clause(text, *t.compiled.model, test.steps[2], r.steps[2]) == nullptr);
    }
    CHECK(r.steps[1].reason == "bo:state accept");
    CHECK(r.steps[3].reason == "bo:in-person accept");
    CHECK(r.steps[4].reason == "bo:requires accept 2");
    CHECK(outcome_text(r.steps[4], t.results, pack("zh-Hans-CN")) ==
          "调用被拒绝，因为 accept 的第 2 项要求未满足（bo:requires accept 2）");
}

TEST_CASE("bo test: parts, by the party that holds them", "[bo][test]") {
    // A receivable split twice (milestone 17): each part is an instance of
    // its own, with its parent's id and its depth in the view, and a step
    // acts on the part its party holds or the party it names holds.
    constexpr std::string_view contract = R"(use finance
contract Split
parties issuer, supplier

asset Receivable
  amount HKD
  tier number
  holder supplier

can split
can pledge
can pay

)";
    const std::string source =
        std::string(contract) +
        "test \"parts\"\n"
        "  issuer issue with amount = HKD 10, tier = 1\n"
        "  supplier split with parts = (HKD 6, HKD 4), recipients = (a1, a2)\n"
        "  a1 split with parts = (HKD 5, HKD 1), recipients = (b1, a1)\n"
        "  b1 pledge to bank1 -> pledged\n"
        "  issuer pay a2 -> paid\n"
        "  issuer pay b1 -> paid\n";
    const Tested t = tested(source);
    const TestResult& r = only(t);
    CHECK(r.passed);
    CHECK(r.steps[1].part.empty());
    CHECK(r.steps[1].parts == 2);
    CHECK(r.steps[1].final);
    CHECK(r.steps[2].part == "1");
    CHECK(r.steps[2].parts == 2);
    CHECK(r.steps[3].part == "1.1");
    CHECK(r.steps[4].part == "2");
    CHECK(r.steps[5].part == "1.1");
    // The part's view: its parent (the root's first part) and its depth.
    const protocol::ContractInput& in = r.steps[3].calls.front().input;
    REQUIRE(in.instance.has_value());
    CHECK(in.instance->depth == 2);
    REQUIRE(in.instance->parent.has_value());
    const protocol::ContractInput& parent = r.steps[2].calls.front().input;
    REQUIRE(parent.instance.has_value());
    CHECK(*in.instance->parent == parent.instance->id);
    CHECK(parent.instance->depth == 1);
    const auto id =
        protocol::child_instance_id(provider(), crypto::HashAlg::sha256, parent.instance->id, 0);
    REQUIRE(id.has_value());
    CHECK(in.instance->id == *id);
    // The parts' states: the amount, the holder, one tier down.
    const cbor::Value* fields = in.instance->state.find("fields");
    REQUIRE(fields != nullptr);
    CHECK(fields->find("amount")->as_int64() == 500);
    CHECK(fields->find("tier")->as_int64() == 3);
    CHECK(in.instance->parties.at("holder") == test_ledger_id("b1", provider()));
    CHECK(dump(*t.compiled.model, t.results).find("part=1.1") != std::string::npos);
    CHECK(test_report(*t.compiled.model, t.results, source, pack("en")).find("On part 1.1.") !=
          std::string::npos);

    // No single part: a party that holds none (or several), or a holder
    // named that holds none.
    const Tested none =
        tested(std::string(contract) +
               "test \"no part\"\n"
               "  issuer issue with amount = HKD 10, tier = 1\n"
               "  supplier split with parts = (HKD 6, HKD 4), recipients = (a1, a2)\n"
               "  issuer pay -> paid\n"
               "test \"no holder\"\n"
               "  issuer issue with amount = HKD 10, tier = 1\n"
               "  supplier split with parts = (HKD 6, HKD 4), recipients = (a1, a1)\n"
               "  issuer pay a1 -> paid\n");
    REQUIRE(none.results.tests.size() == 2);
    const StepResult& anyone = none.results.tests[0].steps[2];
    CHECK(anyone.happened == Happened::no_part);
    CHECK(anyone.status == StepStatus::failed);
    CHECK(outcome_text(anyone, none.results, nullptr).starts_with("no single instance to act on"));
    const StepResult& two = none.results.tests[1].steps[2];
    CHECK(two.happened == Happened::no_part);
    REQUIRE(two.holder.has_value());
    CHECK(outcome_text(two, none.results, nullptr) ==
          "no single instance to act on: a1 holds none of this test's instances, or more than one");
}

TEST_CASE("bo test: the report", "[bo][test]") {
    const Tested t = tested(with_tests("test \"one\"\n"
                                       "  we create with amount = HKD 5\n"
                                       "  we offer to bank1 with fee = HKD 3 -> offered\n"
                                       "test\n"
                                       "  we create with amount = HKD 5\n"
                                       "  we offer to bank1 with fee = HKD 3\n"
                                       "  -> accepted\n"
                                       "  customer accept\n"));
    const std::string report =
        test_report(*t.compiled.model, t.results,
                    with_tests("test \"one\"\n"
                               "  we create with amount = HKD 5\n"
                               "  we offer to bank1 with fee = HKD 3 -> offered\n"
                               "test\n"
                               "  we create with amount = HKD 5\n"
                               "  we offer to bank1 with fee = HKD 3\n"
                               "  -> accepted\n"
                               "  customer accept\n"),
                    nullptr);
    CHECK(report.starts_with("Test \"one\": passed\n"));
    CHECK(report.find("Test number 2: FAILED at step 2\n") != std::string::npos);
    // A step and its expectation on two lines are shown as one.
    CHECK(report.find("  Step 2 (line 25) FAILED: we offer to bank1 with fee = HKD 3 -> "
                      "accepted\n") != std::string::npos);
    CHECK(report.find("    Expected: the call is accepted, and the instance is accepted.\n") !=
          std::string::npos);
    CHECK(report.find("  Step 3 (line 27) not run: customer accept\n") != std::string::npos);
    CHECK(report.ends_with("2 tests: 1 passed, 1 failed.\n"));
    // No tests at all.
    const Tested none = tested(loan);
    CHECK(test_report(*none.compiled.model, none.results, loan, nullptr)
              .starts_with("This file has no tests"));
    CHECK(none.results.tests.empty());
}
