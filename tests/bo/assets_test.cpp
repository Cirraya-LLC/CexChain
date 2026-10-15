// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The standard library (milestone 11 of the Bo compiler) against CexChain's
// native assets (spec section 13): the same calls, run on core's asset rules
// (protocol/assets) and on a Bo contract whose actions are the library's
// built-in ones, give the same states, holders, pledgees, payees,
// quantities, consents, and refusals. And a built-in action copied under a
// name of the contract's own compiles and behaves as the original.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <map>
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
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;
using protocol::AssetAction;
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

/// One call: who makes it (a key of the Bo test's parties), the action, and
/// its counterparty or quantity (kg).
struct Call {
    std::string party;
    AssetAction action = AssetAction::transfer;
    std::optional<std::string> to;
    std::optional<std::uint64_t> kg;
};

/// How a Bo test step names a party: a role by its word, a name as written.
std::string step_party(std::string_view key) {
    return key.starts_with("role.") ? std::string(key.substr(5)) : std::string(key);
}

std::string step_action(AssetAction action) {
    return action == AssetAction::confirm ? "confirm payment" : std::string(protocol::name(action));
}

struct Kind {
    protocol::AssetKind kind = protocol::AssetKind::receivable;
    std::string contract;
    std::string issue;
    std::string home;
    std::string holder;
};

const Kind& receivable() {
    static const Kind k{protocol::AssetKind::receivable,
                        "contract Receivable\nparties issuer, supplier\n\n"
                        "asset Receivable\n  amount HKD\n  due date\n  holder supplier\n\n"
                        "can transfer\ncan pledge\ncan release\ncan enforce\ncan pay\n"
                        "can confirm payment\ncan dispute\ncan freeze\ncan unfreeze\ncan cancel\n",
                        "issuer issue with amount = HKD 1_000, due = 2027-06-30", "role.issuer",
                        "role.supplier"};
    return k;
}

const Kind& receipt() {
    static const Kind k{protocol::AssetKind::warehouse_receipt,
                        "contract WarehouseReceipt\nparties warehouse, depositor\n\n"
                        "asset Receipt\n  quantity kg\n  holder depositor\n\n"
                        "can transfer\ncan pledge\ncan release\ncan enforce\ncan redeem\n"
                        "can freeze\ncan unfreeze\ncan cancel\n",
                        "warehouse issue with quantity = 30 kg", "warehouse", "depositor"};
    return k;
}

/// The receivable with its bank bound when it is issued (a field names the
/// bank): a pledge or a transfer to the bank asks the bank's consent (R31),
/// as the native rules ask any counterparty's; enforce asks only the
/// pledgee's.
const Kind& receivable_with_bank() {
    static const Kind k{protocol::AssetKind::receivable,
                        "contract Receivable\nparties issuer, supplier, bank\n\n"
                        "asset Receivable\n  amount HKD\n  due date\n  holder supplier\n"
                        "  banker bank\n\n"
                        "can transfer to bank\ncan pledge to bank\ncan release\ncan enforce\n"
                        "can pay\ncan confirm payment\ncan dispute\ncan freeze\ncan unfreeze\n"
                        "can cancel\n",
                        "issuer issue with amount = HKD 1_000, due = 2027-06-30", "role.issuer",
                        "role.supplier"};
    return k;
}

/// The asset as the native rules keep it, from its registration.
struct Native {
    protocol::AssetState asset;
    std::string status;
};

Native register_native(const Kind& kind) {
    protocol::AssetMetadata metadata;
    metadata.holder = ledger(kind.holder);
    if (kind.kind == protocol::AssetKind::receivable) {
        metadata.units = 100'000; // HKD 1,000 in cents
        metadata.unit = "HKD";
        metadata.due = 1'000;
    } else {
        metadata.units = 30'000; // 30 kg in grams, as Bo keeps quantities
        metadata.unit = "g";
    }
    const auto encoded = protocol::encode_asset_metadata(kind.kind, metadata);
    REQUIRE(encoded.has_value());
    const Id home = ledger(kind.home);
    const Id id = ledger("cexchain-bo-test asset");
    auto asset = protocol::register_asset(kind.kind, *encoded, home, id, 1);
    REQUIRE(asset.has_value());
    return {*asset, std::string(protocol::asset_status::active)};
}

/// The native rules' word on a call: refused, or the new status, with the
/// consents it needed.
struct Verdict {
    bool accepted = false;
    std::vector<Id> consents;
};

Verdict native_call(Native& n, const Kind& kind, const Call& call, std::uint64_t index) {
    protocol::AssetActionBody body;
    body.asset = ledger("cexchain-bo-test asset");
    body.action = call.action;
    body.head = n.asset.head;
    if (call.to) {
        body.to = ledger(*call.to);
    }
    if (call.kg) {
        body.quantity = *call.kg * 1'000;
    }
    Verdict v;
    v.consents = protocol::consenting_parties(n.asset, n.status, body);
    for (const Id& party : v.consents) {
        body.consents.push_back({party, Id{}, Id{}});
    }
    if (!protocol::check_asset_action(n.asset, n.status, body, ledger(kind.home))) {
        return v;
    }
    v.accepted = true;
    n.status = protocol::apply_asset_action(n.asset, n.status, body, index);
    return v;
}

/// Runs a flow both ways and compares every step.
void compare(const Kind& kind, const std::vector<Call>& calls) {
    // The native rules first: each step's expectation is their verdict.
    Native n = register_native(kind);
    std::vector<Verdict> verdicts;
    std::vector<Native> after;
    std::string test = "test \"the native rules' flow\"\n  " + kind.issue + " -> active\n";
    for (std::size_t i = 0; i < calls.size(); ++i) {
        const Call& c = calls[i];
        const bool final = protocol::is_final_asset_status(n.status);
        verdicts.push_back(final ? Verdict{} : native_call(n, kind, c, i + 2));
        after.push_back(n);
        std::string step = step_party(c.party) + " " + step_action(c.action);
        if (c.to) {
            step += " to " + step_party(*c.to);
        }
        if (c.kg) {
            step += std::format(" with portion = {} kg", *c.kg);
        }
        step += verdicts.back().accepted ? " -> " + n.status : std::string(" -> refused");
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
    REQUIRE(t.steps.size() == calls.size() + 1);
    for (std::size_t i = 0; i < calls.size(); ++i) {
        INFO("call " << i + 1);
        const StepResult& r = t.steps[i + 1];
        const Native& expected = after[i];
        CHECK((r.happened == Happened::accepted) == verdicts[i].accepted);
        if (r.happened != Happened::accepted) {
            continue;
        }
        // The same consents, and the same parties afterwards.
        std::vector<Id> consents = r.consents;
        std::ranges::sort(consents, [](const Id& a, const Id& b) {
            return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
        });
        CHECK(consents == verdicts[i].consents);
        CHECK(r.state == expected.status);
        REQUIRE(!r.calls.empty());
        REQUIRE(r.calls.back().output.has_value());
        const auto* accept = std::get_if<protocol::ContractAccept>(&*r.calls.back().output);
        REQUIRE(accept != nullptr);
        REQUIRE(accept->parties.has_value());
        const auto party = [&](std::string_view key) -> std::optional<Id> {
            const auto it = accept->parties->find(std::string(key));
            return it == accept->parties->end() ? std::nullopt : std::optional<Id>(it->second);
        };
        CHECK(party("holder") == std::optional<Id>(expected.asset.holder));
        CHECK(party("pledgee") == expected.asset.pledgee);
        CHECK(party("payee") == expected.asset.payee);
        if (kind.kind == protocol::AssetKind::warehouse_receipt) {
            const cbor::Value* fields = accept->state.find("fields");
            REQUIRE(fields != nullptr);
            const cbor::Value* quantity = fields->find("quantity");
            REQUIRE(quantity != nullptr);
            CHECK(quantity->as_int64() ==
                  std::optional<std::int64_t>(static_cast<std::int64_t>(expected.asset.units)));
        }
    }
}

} // namespace

TEST_CASE("the standard library's receivable acts as the native one", "[bo][stdlib]") {
    using enum AssetAction;
    // Pledged, paid to the pledgee, disputed, frozen, paid again, settled.
    compare(receivable(), {{"role.supplier", pledge, "bank1", {}},
                           {"role.supplier", pledge, "bank2", {}},
                           {"role.supplier", transfer, "factor1", {}},
                           {"role.supplier", cancel, {}, {}},
                           {"bank1", confirm, {}, {}},
                           {"role.issuer", pay, {}, {}},
                           {"bank1", dispute, {}, {}},
                           {"role.issuer", freeze, {}, {}},
                           {"bank1", confirm, {}, {}},
                           {"role.issuer", unfreeze, {}, {}},
                           {"role.issuer", pay, {}, {}},
                           {"bank1", confirm, {}, {}},
                           {"role.issuer", freeze, {}, {}}});
    // Sold, pledged, released, pledged again, enforced, paid to the holder.
    compare(receivable(), {{"role.supplier", transfer, "role.supplier", {}},
                           {"role.supplier", transfer, "factor1", {}},
                           {"factor1", pledge, "factor1", {}},
                           {"factor1", pledge, "bank1", {}},
                           {"bank1", release, {}, {}},
                           {"bank1", release, {}, {}},
                           {"factor1", pledge, "bank2", {}},
                           {"bank2", enforce, {}, {}},
                           {"role.issuer", pay, {}, {}},
                           {"bank2", dispute, {}, {}},
                           {"role.issuer", pay, {}, {}},
                           {"bank2", confirm, {}, {}}});
    // Frozen while active, cancelled, and nothing after.
    compare(receivable(), {{"role.issuer", unfreeze, {}, {}},
                           {"role.issuer", freeze, {}, {}},
                           {"role.issuer", freeze, {}, {}},
                           {"role.supplier", cancel, {}, {}},
                           {"role.issuer", unfreeze, {}, {}},
                           {"role.supplier", cancel, {}, {}},
                           {"role.issuer", pay, {}, {}}});
}

TEST_CASE("a counterparty bound at creation consents as the native one does", "[bo][stdlib]") {
    using enum AssetAction;
    // Q17 (R31): the bank, bound when the receivable is issued, consents to
    // each pledge and transfer to it; it enforces with its own consent alone.
    compare(receivable_with_bank(), {{"role.supplier", pledge, "role.bank", {}},
                                     {"role.supplier", pledge, "role.bank", {}},
                                     {"role.supplier", transfer, "role.bank", {}},
                                     {"role.bank", enforce, {}, {}},
                                     {"role.bank", pledge, "role.bank", {}},
                                     {"role.bank", transfer, "role.bank", {}},
                                     {"role.issuer", pay, {}, {}},
                                     {"role.bank", confirm, {}, {}}});
    // Pledged, released, then sold to the bank, which is paid.
    compare(receivable_with_bank(), {{"role.supplier", pledge, "role.bank", {}},
                                     {"role.bank", release, {}, {}},
                                     {"role.supplier", transfer, "role.bank", {}},
                                     {"role.bank", pledge, "role.bank", {}},
                                     {"role.issuer", pay, {}, {}},
                                     {"role.bank", dispute, {}, {}},
                                     {"role.issuer", pay, {}, {}},
                                     {"role.bank", confirm, {}, {}}});
    // Sold to the bank at once, then cancelled by it, and nothing after.
    compare(receivable_with_bank(), {{"role.supplier", transfer, "role.bank", {}},
                                     {"role.bank", pledge, "role.bank", {}},
                                     {"role.bank", cancel, {}, {}},
                                     {"role.supplier", transfer, "role.bank", {}}});
}

TEST_CASE("the standard library's warehouse receipt acts as the native one", "[bo][stdlib]") {
    using enum AssetAction;
    // Redeemed in parts, with the pledgee's consent while pledged.
    compare(receipt(), {{"depositor", redeem, {}, 10},
                        {"depositor", redeem, {}, 25},
                        {"depositor", pledge, "bank1", {}},
                        {"depositor", redeem, {}, 5},
                        {"depositor", transfer, "trader1", {}},
                        {"bank1", release, {}, {}},
                        {"depositor", transfer, "trader1", {}},
                        {"warehouse", freeze, {}, {}},
                        {"trader1", redeem, {}, 1},
                        {"warehouse", unfreeze, {}, {}},
                        {"trader1", redeem, {}, 15},
                        {"trader1", cancel, {}, {}}});
    // Enforced by the bank, then cancelled.
    compare(receipt(), {{"depositor", pledge, "bank1", {}},
                        {"depositor", cancel, {}, {}},
                        {"bank1", enforce, {}, {}},
                        {"bank1", redeem, {}, 30},
                        {"bank1", cancel, {}, {}}});
}

TEST_CASE("a built-in action copied under a name of its own acts as the original", "[bo][stdlib]") {
    const Concept* pledge = find_concept("act.pledge");
    const std::optional<std::string> terms = standard_terms_source(pledge, nullptr);
    REQUIRE(terms.has_value());
    REQUIRE(terms->starts_with("can pledge to counterparty by holder\n"));
    std::string copy = *terms;
    copy.replace(0, std::string_view("can pledge").size(), "can lodge");
    const std::string head = "contract C\nparties issuer, supplier\n\n"
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
