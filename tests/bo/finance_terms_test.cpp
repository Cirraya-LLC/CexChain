// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The finance pack's standard terms (of the standard library, now a
// vocabulary pack's): a Bo contract that uses the pack and whose actions are its
// built-in ones gives, call by call, the states, holders, pledgees, payees,
// quantities, consents, and refusals that CexChain's native assets gave
// (spec v0.5 to v0.8, section 13). Spec v0.9 removed the native assets from
// the protocol; their verdicts on these flows, taken from core's
// asset rules before the removal, are kept here as goldens. And a built-in
// action copied under a name of the contract's own compiles and behaves as
// the original.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/scenario.hpp>
#include <cexchain/bo/stdlib.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;
using protocol::Id;

namespace {

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

/// A test ledger, as the Bo runner names it: a role's concept id, or a name
/// as written.
Id ledger(std::string_view key) {
    return test_ledger_id(key, provider());
}

/// One call, and the native rules' verdict on it: refused (no status), or
/// the status after it, the parties whose consent it needed, and the parties
/// (and a receipt's quantity, in grams) afterwards. Parties are the Bo
/// test's ledger keys: a role's concept id, or a name as written. The action
/// is as a test step writes it.
struct Step {
    std::string party{};
    std::string action{};
    std::optional<std::string> to{};
    std::optional<std::uint64_t> kg{};
    std::optional<std::string> status{};
    std::vector<std::string> consents{};
    std::string holder{};
    std::optional<std::string> pledgee{};
    std::optional<std::string> payee{};
    std::optional<std::uint64_t> grams{};
};

/// How a Bo test step names a party: a role by its word, a name as written.
std::string step_party(std::string_view key) {
    return key.starts_with("role.") ? std::string(key.substr(5)) : std::string(key);
}

struct Kind {
    std::string contract;
    std::string issue;
};

const Kind& receivable() {
    static const Kind k{"use finance\ncontract Receivable\nparties issuer, supplier\n\n"
                        "asset Receivable\n  amount HKD\n  due date\n  holder supplier\n\n"
                        "can transfer\ncan pledge\ncan release\ncan enforce\ncan pay\n"
                        "can confirm payment\ncan dispute\ncan freeze\ncan unfreeze\ncan cancel\n",
                        "issuer issue with amount = HKD 1_000, due = 2027-06-30"};
    return k;
}

const Kind& receipt() {
    static const Kind k{"use finance\ncontract WarehouseReceipt\nparties warehouse, depositor\n\n"
                        "asset Receipt\n  quantity kg\n  holder depositor\n\n"
                        "can transfer\ncan pledge\ncan release\ncan enforce\ncan redeem\n"
                        "can freeze\ncan unfreeze\ncan cancel\n",
                        "warehouse issue with quantity = 30 kg"};
    return k;
}

/// The receivable with its bank bound when it is issued (a field names the
/// bank): a pledge or a transfer to the bank asks the bank's consent (R31),
/// as the native rules asked any counterparty's; enforce asks only the
/// pledgee's.
const Kind& receivable_with_bank() {
    static const Kind k{"use finance\ncontract Receivable\nparties issuer, supplier, bank\n\n"
                        "asset Receivable\n  amount HKD\n  due date\n  holder supplier\n"
                        "  banker bank\n\n"
                        "can transfer to bank\ncan pledge to bank\ncan release\ncan enforce\n"
                        "can pay\ncan confirm payment\ncan dispute\ncan freeze\ncan unfreeze\n"
                        "can cancel\n",
                        "issuer issue with amount = HKD 1_000, due = 2027-06-30"};
    return k;
}

std::vector<Id> sorted_ids(std::vector<Id> ids) {
    std::ranges::sort(ids, [](const Id& a, const Id& b) {
        return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
    });
    return ids;
}

/// Runs a flow on the Bo contract and compares every step with the native
/// verdict.
void compare(const Kind& kind, const std::vector<Step>& steps) {
    std::string test = "test \"the native rules' flow\"\n  " + kind.issue + " -> active\n";
    for (const Step& s : steps) {
        std::string step = step_party(s.party) + " " + s.action;
        if (s.to) {
            step += " to " + step_party(*s.to);
        }
        if (s.kg) {
            step += std::format(" with portion = {} kg", *s.kg);
        }
        step += s.status ? " -> " + *s.status : std::string(" -> refused");
        test += "  " + step + "\n";
    }
    const std::string source = kind.contract + "\n" + test;
    INFO(source);
    const Compiled compiled = compile(source, official_set());
    REQUIRE(compiled.build.has_value());
    REQUIRE(compiled.model.has_value());
    const TestResults results = run_tests(*compiled.model, *compiled.build, provider());
    REQUIRE(results.tests.size() == 1);
    const TestResult& t = results.tests.front();
    INFO(dump(*compiled.model, results));
    CHECK(t.passed);
    REQUIRE(t.steps.size() == steps.size() + 1);
    for (std::size_t i = 0; i < steps.size(); ++i) {
        INFO("call " << i + 1);
        const StepResult& r = t.steps[i + 1];
        const Step& expected = steps[i];
        CHECK((r.happened == Happened::accepted) == expected.status.has_value());
        if (r.happened != Happened::accepted || !expected.status) {
            continue;
        }
        // The same consents, and the same parties afterwards.
        std::vector<Id> consents;
        for (const std::string& key : expected.consents) {
            consents.push_back(ledger(key));
        }
        CHECK(sorted_ids(r.consents) == sorted_ids(consents));
        CHECK(r.state == *expected.status);
        REQUIRE(!r.calls.empty());
        REQUIRE(r.calls.back().output.has_value());
        const auto* accept = std::get_if<protocol::ContractAccept>(&*r.calls.back().output);
        REQUIRE(accept != nullptr);
        REQUIRE(accept->parties.has_value());
        const auto party = [&](std::string_view key) -> std::optional<Id> {
            const auto it = accept->parties->find(std::string(key));
            return it == accept->parties->end() ? std::nullopt : std::optional<Id>(it->second);
        };
        const auto id_of = [](const std::optional<std::string>& key) -> std::optional<Id> {
            return key ? std::optional<Id>(ledger(*key)) : std::nullopt;
        };
        CHECK(party("holder") == std::optional<Id>(ledger(expected.holder)));
        CHECK(party("pledgee") == id_of(expected.pledgee));
        CHECK(party("payee") == id_of(expected.payee));
        if (expected.grams) {
            const cbor::Value state = accept->state.value();
            const cbor::Value* fields = state.find("fields");
            REQUIRE(fields != nullptr);
            const cbor::Value* quantity = fields->find("quantity");
            REQUIRE(quantity != nullptr);
            CHECK(quantity->as_int64() ==
                  std::optional<std::int64_t>(static_cast<std::int64_t>(*expected.grams)));
        }
    }
}

} // namespace

TEST_CASE("the standard library's receivable acts as the native one", "[bo][stdlib]") {
    // Pledged, paid to the pledgee, disputed, frozen, paid again, settled.
    compare(receivable(), {
                              {.party = "role.supplier",
                               .action = "pledge",
                               .to = "bank1",
                               .status = "pledged",
                               .consents = {"role.supplier", "bank1"},
                               .holder = "role.supplier",
                               .pledgee = "bank1"},
                              {.party = "role.supplier", .action = "pledge", .to = "bank2"},
                              {.party = "role.supplier", .action = "transfer", .to = "factor1"},
                              {.party = "role.supplier", .action = "cancel"},
                              {.party = "bank1", .action = "confirm payment"},
                              {.party = "role.issuer",
                               .action = "pay",
                               .status = "paid",
                               .holder = "role.supplier",
                               .pledgee = "bank1",
                               .payee = "bank1"},
                              {.party = "bank1",
                               .action = "dispute",
                               .status = "disputed",
                               .consents = {"bank1"},
                               .holder = "role.supplier",
                               .pledgee = "bank1",
                               .payee = "bank1"},
                              {.party = "role.issuer",
                               .action = "freeze",
                               .status = "frozen",
                               .holder = "role.supplier",
                               .pledgee = "bank1",
                               .payee = "bank1"},
                              {.party = "bank1", .action = "confirm payment"},
                              {.party = "role.issuer",
                               .action = "unfreeze",
                               .status = "disputed",
                               .holder = "role.supplier",
                               .pledgee = "bank1",
                               .payee = "bank1"},
                              {.party = "role.issuer",
                               .action = "pay",
                               .status = "paid",
                               .holder = "role.supplier",
                               .pledgee = "bank1",
                               .payee = "bank1"},
                              {.party = "bank1",
                               .action = "confirm payment",
                               .status = "settled",
                               .consents = {"bank1"},
                               .holder = "role.supplier",
                               .pledgee = "bank1",
                               .payee = "bank1"},
                              {.party = "role.issuer", .action = "freeze"},
                          });
    // Sold, pledged, released, pledged again, enforced, paid to the holder.
    compare(receivable(),
            {
                {.party = "role.supplier", .action = "transfer", .to = "role.supplier"},
                {.party = "role.supplier",
                 .action = "transfer",
                 .to = "factor1",
                 .status = "active",
                 .consents = {"role.supplier", "factor1"},
                 .holder = "factor1"},
                {.party = "factor1", .action = "pledge", .to = "factor1"},
                {.party = "factor1",
                 .action = "pledge",
                 .to = "bank1",
                 .status = "pledged",
                 .consents = {"factor1", "bank1"},
                 .holder = "factor1",
                 .pledgee = "bank1"},
                {.party = "bank1",
                 .action = "release",
                 .status = "active",
                 .consents = {"bank1"},
                 .holder = "factor1"},
                {.party = "bank1", .action = "release"},
                {.party = "factor1",
                 .action = "pledge",
                 .to = "bank2",
                 .status = "pledged",
                 .consents = {"factor1", "bank2"},
                 .holder = "factor1",
                 .pledgee = "bank2"},
                {.party = "bank2",
                 .action = "enforce",
                 .status = "active",
                 .consents = {"bank2"},
                 .holder = "bank2"},
                {.party = "role.issuer",
                 .action = "pay",
                 .status = "paid",
                 .holder = "bank2",
                 .payee = "bank2"},
                {.party = "bank2",
                 .action = "dispute",
                 .status = "disputed",
                 .consents = {"bank2"},
                 .holder = "bank2",
                 .payee = "bank2"},
                {.party = "role.issuer",
                 .action = "pay",
                 .status = "paid",
                 .holder = "bank2",
                 .payee = "bank2"},
                {.party = "bank2",
                 .action = "confirm payment",
                 .status = "settled",
                 .consents = {"bank2"},
                 .holder = "bank2",
                 .payee = "bank2"},
            });
    // Frozen while active, cancelled, and nothing after.
    compare(receivable(), {
                              {.party = "role.issuer", .action = "unfreeze"},
                              {.party = "role.issuer",
                               .action = "freeze",
                               .status = "frozen",
                               .holder = "role.supplier"},
                              {.party = "role.issuer", .action = "freeze"},
                              {.party = "role.supplier", .action = "cancel"},
                              {.party = "role.issuer",
                               .action = "unfreeze",
                               .status = "active",
                               .holder = "role.supplier"},
                              {.party = "role.supplier",
                               .action = "cancel",
                               .status = "cancelled",
                               .consents = {"role.supplier"},
                               .holder = "role.supplier"},
                              {.party = "role.issuer", .action = "pay"},
                          });
}

TEST_CASE("a counterparty bound at creation consents as the native one does", "[bo][stdlib]") {
    // R31: the bank, bound when the receivable is issued, consents to
    // each pledge and transfer to it; it enforces with its own consent alone.
    compare(receivable_with_bank(),
            {
                {.party = "role.supplier",
                 .action = "pledge",
                 .to = "role.bank",
                 .status = "pledged",
                 .consents = {"role.supplier", "role.bank"},
                 .holder = "role.supplier",
                 .pledgee = "role.bank"},
                {.party = "role.supplier", .action = "pledge", .to = "role.bank"},
                {.party = "role.supplier", .action = "transfer", .to = "role.bank"},
                {.party = "role.bank",
                 .action = "enforce",
                 .status = "active",
                 .consents = {"role.bank"},
                 .holder = "role.bank"},
                {.party = "role.bank", .action = "pledge", .to = "role.bank"},
                {.party = "role.bank", .action = "transfer", .to = "role.bank"},
                {.party = "role.issuer",
                 .action = "pay",
                 .status = "paid",
                 .holder = "role.bank",
                 .payee = "role.bank"},
                {.party = "role.bank",
                 .action = "confirm payment",
                 .status = "settled",
                 .consents = {"role.bank"},
                 .holder = "role.bank",
                 .payee = "role.bank"},
            });
    // Pledged, released, then sold to the bank, which is paid.
    compare(receivable_with_bank(),
            {
                {.party = "role.supplier",
                 .action = "pledge",
                 .to = "role.bank",
                 .status = "pledged",
                 .consents = {"role.supplier", "role.bank"},
                 .holder = "role.supplier",
                 .pledgee = "role.bank"},
                {.party = "role.bank",
                 .action = "release",
                 .status = "active",
                 .consents = {"role.bank"},
                 .holder = "role.supplier"},
                {.party = "role.supplier",
                 .action = "transfer",
                 .to = "role.bank",
                 .status = "active",
                 .consents = {"role.supplier", "role.bank"},
                 .holder = "role.bank"},
                {.party = "role.bank", .action = "pledge", .to = "role.bank"},
                {.party = "role.issuer",
                 .action = "pay",
                 .status = "paid",
                 .holder = "role.bank",
                 .payee = "role.bank"},
                {.party = "role.bank",
                 .action = "dispute",
                 .status = "disputed",
                 .consents = {"role.bank"},
                 .holder = "role.bank",
                 .payee = "role.bank"},
                {.party = "role.issuer",
                 .action = "pay",
                 .status = "paid",
                 .holder = "role.bank",
                 .payee = "role.bank"},
                {.party = "role.bank",
                 .action = "confirm payment",
                 .status = "settled",
                 .consents = {"role.bank"},
                 .holder = "role.bank",
                 .payee = "role.bank"},
            });
    // Sold to the bank at once, then cancelled by it, and nothing after.
    compare(receivable_with_bank(),
            {
                {.party = "role.supplier",
                 .action = "transfer",
                 .to = "role.bank",
                 .status = "active",
                 .consents = {"role.supplier", "role.bank"},
                 .holder = "role.bank"},
                {.party = "role.bank", .action = "pledge", .to = "role.bank"},
                {.party = "role.bank",
                 .action = "cancel",
                 .status = "cancelled",
                 .consents = {"role.bank"},
                 .holder = "role.bank"},
                {.party = "role.supplier", .action = "transfer", .to = "role.bank"},
            });
}

TEST_CASE("the standard library's warehouse receipt acts as the native one", "[bo][stdlib]") {
    // Redeemed in parts, with the pledgee's consent while pledged.
    compare(receipt(), {
                           {.party = "depositor",
                            .action = "redeem",
                            .kg = 10,
                            .status = "active",
                            .consents = {"depositor"},
                            .holder = "depositor",
                            .grams = 20000},
                           {.party = "depositor", .action = "redeem", .kg = 25},
                           {.party = "depositor",
                            .action = "pledge",
                            .to = "bank1",
                            .status = "pledged",
                            .consents = {"depositor", "bank1"},
                            .holder = "depositor",
                            .pledgee = "bank1",
                            .grams = 20000},
                           {.party = "depositor",
                            .action = "redeem",
                            .kg = 5,
                            .status = "pledged",
                            .consents = {"depositor", "bank1"},
                            .holder = "depositor",
                            .pledgee = "bank1",
                            .grams = 15000},
                           {.party = "depositor", .action = "transfer", .to = "trader1"},
                           {.party = "bank1",
                            .action = "release",
                            .status = "active",
                            .consents = {"bank1"},
                            .holder = "depositor",
                            .grams = 15000},
                           {.party = "depositor",
                            .action = "transfer",
                            .to = "trader1",
                            .status = "active",
                            .consents = {"trader1", "depositor"},
                            .holder = "trader1",
                            .grams = 15000},
                           {.party = "warehouse",
                            .action = "freeze",
                            .status = "frozen",
                            .holder = "trader1",
                            .grams = 15000},
                           {.party = "trader1", .action = "redeem", .kg = 1},
                           {.party = "warehouse",
                            .action = "unfreeze",
                            .status = "active",
                            .holder = "trader1",
                            .grams = 15000},
                           {.party = "trader1",
                            .action = "redeem",
                            .kg = 15,
                            .status = "redeemed",
                            .consents = {"trader1"},
                            .holder = "trader1",
                            .grams = 0},
                           {.party = "trader1", .action = "cancel"},
                       });
    // Enforced by the bank, then cancelled.
    compare(receipt(), {
                           {.party = "depositor",
                            .action = "pledge",
                            .to = "bank1",
                            .status = "pledged",
                            .consents = {"depositor", "bank1"},
                            .holder = "depositor",
                            .pledgee = "bank1",
                            .grams = 30000},
                           {.party = "depositor", .action = "cancel"},
                           {.party = "bank1",
                            .action = "enforce",
                            .status = "active",
                            .consents = {"bank1"},
                            .holder = "bank1",
                            .grams = 30000},
                           {.party = "bank1",
                            .action = "redeem",
                            .kg = 30,
                            .status = "redeemed",
                            .consents = {"bank1"},
                            .holder = "bank1",
                            .grams = 0},
                           {.party = "bank1", .action = "cancel"},
                       });
}

TEST_CASE("a built-in action copied under a name of its own acts as the original", "[bo][stdlib]") {
    const Concept* pledge = find_concept("act.pledge");
    const std::optional<std::string> terms = standard_terms_source(pledge, nullptr);
    REQUIRE(terms.has_value());
    REQUIRE(terms->starts_with("can pledge to counterparty by holder\n"));
    std::string copy = *terms;
    copy.replace(0, std::string_view("can pledge").size(), "can lodge");
    const std::string head = "use finance\ncontract C\nparties issuer, supplier\n\n"
                             "asset A\n  amount HKD\n  holder supplier\n\n";
    const auto outcomes = [&](const std::string& actions, std::string_view verb) {
        const std::string source = head + actions +
                                   std::format("\ntest\n  issuer issue with amount = HKD 1\n"
                                               "  supplier {0} to supplier -> refused\n"
                                               "  issuer {0} to bank1 -> consent of supplier\n"
                                               "  supplier {0} to bank1 -> pledged\n"
                                               "  supplier {0} to bank2 -> refused\n",
                                               verb);
        const Compiled compiled = compile(source, official_set());
        INFO(source);
        REQUIRE(compiled.build.has_value());
        const TestResults results = run_tests(*compiled.model, *compiled.build, provider());
        std::vector<std::string> out;
        for (const StepResult& r : results.tests.front().steps) {
            out.push_back(std::format("{} {} {}",
                                      happened_names[static_cast<std::size_t>(r.happened)], r.state,
                                      r.consents.size()));
        }
        return out;
    };
    // The first refusal stops the test: compare what ran.
    CHECK(outcomes("can pledge\n", "pledge") == outcomes(copy, "lodge"));
    // Changed, it is the contract's own action: in person, say.
    const Compiled changed =
        compile(head + copy + "  requires in person\n" +
                    "\ntest\n  issuer issue with amount = HKD 1\n"
                    "  supplier lodge to bank1 -> refused \"bo:in-person lodge\"\n"
                    "  supplier lodge to bank1 in person -> pledged\n",
                official_set());
    REQUIRE(changed.build.has_value());
    REQUIRE(changed.model.has_value());
    CHECK(changed.model->actions.front().word == nullptr);
    CHECK(!changed.model->actions.front().terms);
    CHECK(run_tests(*changed.model, *changed.build, provider()).tests.front().passed);
}
