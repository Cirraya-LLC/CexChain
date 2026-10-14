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
        {"supply-agreement", source_dir / "deploy/demo/supply-agreement.bo"},
        // The standard library (milestone 11): the spec's ReceivableFinancing,
        // the native assets' flows, and an AI agent's proposal.
        {"receivable-financing", golden_dir / "test/receivable-financing/source.bo"},
        {"receivable", golden_dir / "test/receivable/source.bo"},
        {"warehouse-receipt", golden_dir / "test/warehouse-receipt/source.bo"},
        {"standard", golden_dir / "check-standard/source.bo"},
    };
}

const Pack* pack(std::string_view id) {
    return official_pack(id);
}

/// The contract every rule below is tested on: a loan the customer must
/// accept in person above HKD 10,000, which a bank bound by the action
/// funds, and which the holder of the note repays.
constexpr std::string_view loan = R"(contract Loan
parties we, customer, bank

record Note
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
    CHECK(outcome_text(r.steps[1], t.results, pack("zh-Hant-HK")) == "調用正等待本公司提交");
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
    CHECK(report.find("  Step 2 (line 23) FAILED: we offer to bank1 with fee = HKD 3 -> "
                      "accepted\n") != std::string::npos);
    CHECK(report.find("    Expected: the call is accepted, and the instance is accepted.\n") !=
          std::string::npos);
    CHECK(report.find("  Step 3 (line 25) not run: customer accept\n") != std::string::npos);
    CHECK(report.ends_with("2 tests: 1 passed, 1 failed.\n"));
    // No tests at all.
    const Tested none = tested(loan);
    CHECK(test_report(*none.compiled.model, none.results, loan, nullptr)
              .starts_with("This file has no tests"));
    CHECK(none.results.tests.empty());
}
