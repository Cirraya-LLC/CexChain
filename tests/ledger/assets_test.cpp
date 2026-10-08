// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Ownership assets across four ledgers (D-052): a core enterprise's
// receivable, held by a supplier, pledged to a bank, and verified offline
// with the consents each party gave on its own ledger.

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

const protocol::Nonce salt{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};

protocol::RecordRegisterBody body_with(const std::string& type, cbor::Value metadata) {
    auto commitment = protocol::commit_fields(provider(), crypto::HashAlg::sha256,
                                              {{"contract", salt, cbor::Value::text("PO-0815")}});
    REQUIRE(commitment);
    return {type,
            Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end()),
            1,
            {},
            std::move(metadata)};
}

/// A party's consent: its record, and its evidence (after a checkpoint).
struct Consent {
    protocol::Id record;
    Bytes bundle;
};

Consent consent(World& party, const protocol::AssetTerms& terms,
                protocol::Timestamp until = t0 + 30 * day) {
    auto metadata = protocol::encode_asset_consent({terms, until, std::nullopt});
    REQUIRE(metadata);
    const protocol::Id record =
        party.ok(party.org(), party.statement(party.org_id(), std::nullopt,
                                              body_with(std::string(protocol::asset_consent_type),
                                                        std::move(*metadata))));
    REQUIRE(party.ledger().checkpoint(party.log_key()));
    auto bundle = party.ledger().export_evidence(party.log_key(), record);
    REQUIRE(bundle);
    auto encoded = protocol::encode_bundle(*bundle);
    REQUIRE(encoded);
    return {record, *encoded};
}

struct Market {
    World home{crypto::HashAlg::sha256, "Core Enterprise"};
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    protocol::Id receivable;

    Market() {
        protocol::AssetMetadata m{supplier.ledger().id(), 12'500'000, "CNY", t0 + 90 * day};
        auto metadata = protocol::encode_asset_metadata(
            protocol::AssetKind::receivable, m,
            {{cbor::Value::text("title"), cbor::Value::text("PO-0815")}});
        REQUIRE(metadata);
        receivable =
            home.ok(home.org(), home.statement(home.org_id(), std::nullopt,
                                               body_with(std::string(protocol::receivable_type),
                                                         std::move(*metadata))));
    }

    const protocol::AssetState& asset() {
        const protocol::AssetState* a = home.ledger().state().asset(receivable);
        REQUIRE(a != nullptr);
        return *a;
    }
    const std::string& status() { return home.ledger().state().record(receivable)->state; }

    protocol::AssetActionBody action(protocol::AssetAction what,
                                     std::optional<protocol::Id> to = std::nullopt) {
        protocol::AssetActionBody b;
        b.asset = receivable;
        b.action = what;
        b.head = asset().head;
        b.to = std::move(to);
        return b;
    }

    /// Each party consents to `b`; the bundles, in the order of `parties`.
    std::vector<Bytes> consent_to(protocol::AssetActionBody& b, std::vector<World*> parties) {
        const protocol::AssetTerms terms = protocol::terms_of(b, home.ledger().id());
        std::vector<std::pair<protocol::ConsentRef, Bytes>> refs;
        for (World* party : parties) {
            Consent c = consent(*party, terms);
            auto digest = provider().digest(home.hash(), c.bundle);
            REQUIRE(digest);
            refs.emplace_back(protocol::ConsentRef{party->ledger().id(), c.record, *digest},
                              std::move(c.bundle));
        }
        std::ranges::sort(refs, [](const auto& x, const auto& y) {
            return std::ranges::lexicographical_compare(x.first.ledger.bytes(),
                                                        y.first.ledger.bytes());
        });
        std::vector<Bytes> bundles;
        for (auto& [ref, bundle] : refs) {
            b.consents.push_back(ref);
            bundles.push_back(std::move(bundle));
        }
        return bundles;
    }

    cexchain::Result<ledger::Registration> record(const protocol::AssetActionBody& b) {
        return home.submit(home.org(), home.statement(home.org_id(), std::nullopt, b));
    }

    /// The asset's evidence now, with `consents`.
    Bytes evidence(const std::vector<Bytes>& consents, bool complete = true) {
        REQUIRE(home.ledger().checkpoint(home.log_key()));
        auto bundle = home.ledger().export_evidence(home.log_key(), receivable);
        REQUIRE(bundle);
        if (!complete) {
            bundle->state_proofs.clear();
        }
        auto asset_bundle = protocol::encode_bundle(*bundle);
        REQUIRE(asset_bundle);
        auto encoded = protocol::encode_asset_evidence({*asset_bundle, consents});
        REQUIRE(encoded);
        return *encoded;
    }

    cexchain::Result<protocol::AssetReport> verify(const Bytes& evidence) {
        protocol::VerifyOptions options;
        options.expected_ledger = home.ledger().id();
        return protocol::verify_asset_evidence(provider(), evidence, options);
    }
};

} // namespace

TEST_CASE("a receivable is pledged with both parties' consents and verified offline", "[assets]") {
    Market m;
    CHECK(m.status() == "active");
    CHECK(m.asset().holder == m.supplier.ledger().id());

    auto pledge = m.action(protocol::AssetAction::pledge, m.bank.ledger().id());
    const auto bundles = m.consent_to(pledge, {&m.supplier, &m.bank});
    REQUIRE(m.record(pledge));
    m.home.clock().advance(1000);
    CHECK(m.status() == "pledged");
    REQUIRE(m.asset().pledgee);
    CHECK(*m.asset().pledgee == m.bank.ledger().id());

    auto report = m.verify(m.evidence(bundles));
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->asset.complete);
    CHECK(report->asset.state == "pledged");
    REQUIRE(report->asset.asset);
    CHECK(*report->asset.asset->pledgee == m.bank.ledger().id());
    REQUIRE(report->steps.size() == 1);
    const auto& step = report->steps.front();
    CHECK(report->asset.events[step.event].asset_action->action == protocol::AssetAction::pledge);
    REQUIRE(step.consents.size() == 2);
    std::vector<std::string> organizations;
    for (const auto& c : step.consents) {
        CHECK(c.report.complete);
        organizations.push_back(c.report.organization);
    }
    std::ranges::sort(organizations);
    CHECK(organizations == std::vector<std::string>{"Bank", "Supplier"});

    SECTION("a second pledge is refused") {
        auto again = m.action(protocol::AssetAction::pledge, m.buyer.ledger().id());
        static_cast<void>(m.consent_to(again, {&m.supplier, &m.buyer}));
        const auto refused = m.record(again);
        REQUIRE_FALSE(refused);
        CHECK(refused.error().code == Errc::rejected);
    }
    SECTION("a consent to an earlier head no longer counts") {
        auto release = m.action(protocol::AssetAction::release);
        release.head = m.home.ledger().state().record(m.receivable)->registered_at_index;
        static_cast<void>(m.consent_to(release, {&m.bank}));
        CHECK_FALSE(m.record(release));
    }
    SECTION("only the pledgee releases") {
        auto release = m.action(protocol::AssetAction::release);
        static_cast<void>(m.consent_to(release, {&m.supplier}));
        CHECK_FALSE(m.record(release));
    }
    SECTION("an asset is not revoked or moved as a record") {
        CHECK(m.home.rejected(m.home.org(),
                              m.home.statement(m.home.org_id(), std::nullopt,
                                               protocol::RecordRevokeBody{m.receivable, "oops"})) ==
              Errc::rejected);
        CHECK(m.home.rejected(m.home.org(), m.home.statement(m.home.org_id(), std::nullopt,
                                                             protocol::RecordTransitionBody{
                                                                 m.receivable, "pledged",
                                                                 "active"})) == Errc::rejected);
    }
}

TEST_CASE("asset evidence fails without exactly the consents its actions pin", "[assets]") {
    Market m;
    auto pledge = m.action(protocol::AssetAction::pledge, m.bank.ledger().id());
    const auto bundles = m.consent_to(pledge, {&m.supplier, &m.bank});
    REQUIRE(m.record(pledge));
    m.home.clock().advance(1000);
    REQUIRE(m.verify(m.evidence(bundles)));

    SECTION("a missing consent") {
        CHECK_FALSE(m.verify(m.evidence({bundles.front()})));
    }
    SECTION("a bundle no action pins") {
        auto extra = bundles;
        extra.push_back(consent(m.buyer, protocol::terms_of(pledge, m.home.ledger().id())).bundle);
        CHECK_FALSE(m.verify(m.evidence(extra)));
    }
    SECTION("a repeated bundle") {
        auto repeated = bundles;
        repeated.push_back(bundles.front());
        CHECK_FALSE(m.verify(m.evidence(repeated)));
    }
    SECTION("an asset bundle that does not prove its complete history") {
        CHECK_FALSE(m.verify(m.evidence(bundles, false)));
    }
    SECTION("evidence pinned to another home") {
        protocol::VerifyOptions options;
        options.expected_ledger = m.bank.ledger().id();
        CHECK_FALSE(protocol::verify_asset_evidence(provider(), m.evidence(bundles), options));
    }
}

TEST_CASE("a consent counts only for its own terms, while given, and in time", "[assets]") {
    Market m;
    auto pledge = m.action(protocol::AssetAction::pledge, m.bank.ledger().id());
    const protocol::AssetTerms terms = protocol::terms_of(pledge, m.home.ledger().id());
    const protocol::Timestamp at = t0 + day;

    auto check = [&](World& party, const Consent& c, const protocol::AssetTerms& wanted,
                     protocol::Timestamp when) {
        auto digest = provider().digest(m.home.hash(), c.bundle);
        REQUIRE(digest);
        return protocol::check_consent(provider(), {party.ledger().id(), c.record, *digest},
                                       c.bundle, wanted, when, m.home.hash());
    };

    const Consent given = consent(m.supplier, terms);
    REQUIRE(check(m.supplier, given, terms, at));

    SECTION("other terms") {
        auto other = terms;
        other.to = m.buyer.ledger().id();
        CHECK_FALSE(check(m.supplier, given, other, at));
        other = terms;
        other.head += 1;
        CHECK_FALSE(check(m.supplier, given, other, at));
    }
    SECTION("lapsed") {
        CHECK_FALSE(check(m.supplier, given, terms, t0 + 31 * day));
    }
    SECTION("from another ledger than cited") {
        CHECK_FALSE(check(m.bank, given, terms, at));
    }
    SECTION("withdrawn") {
        m.supplier.ok(m.supplier.org(),
                      m.supplier.statement(
                          m.supplier.org_id(), std::nullopt,
                          protocol::RecordTransitionBody{given.record, "given", "withdrawn"}));
        REQUIRE(m.supplier.ledger().checkpoint(m.supplier.log_key()));
        auto bundle = m.supplier.ledger().export_evidence(m.supplier.log_key(), given.record);
        REQUIRE(bundle);
        const Consent withdrawn{given.record, *protocol::encode_bundle(*bundle)};
        CHECK_FALSE(check(m.supplier, withdrawn, terms, at));
    }
    SECTION("another bundle than the one pinned") {
        const Consent other = consent(m.supplier, terms);
        auto digest = provider().digest(m.home.hash(), other.bundle);
        REQUIRE(digest);
        CHECK_FALSE(protocol::check_consent(provider(),
                                            {m.supplier.ledger().id(), given.record, *digest},
                                            other.bundle, terms, at, m.home.hash()));
    }
}

TEST_CASE("a receivable's life: transfer, payment, dispute, settlement", "[assets]") {
    Market m;
    auto transfer = m.action(protocol::AssetAction::transfer, m.buyer.ledger().id());
    auto bundles = m.consent_to(transfer, {&m.supplier, &m.buyer});
    REQUIRE(m.record(transfer));
    m.home.clock().advance(1000);
    CHECK(m.asset().holder == m.buyer.ledger().id());

    // The debtor's word alone: it cites no consents.
    auto pay = m.action(protocol::AssetAction::pay);
    pay.reference = "CNAPS 2026101500001";
    REQUIRE(m.record(pay));
    m.home.clock().advance(1000);
    CHECK(m.status() == "paid");
    CHECK(*m.asset().payee == m.buyer.ledger().id());

    auto dispute = m.action(protocol::AssetAction::dispute);
    auto more = m.consent_to(dispute, {&m.buyer});
    bundles.insert(bundles.end(), more.begin(), more.end());
    REQUIRE(m.record(dispute));
    m.home.clock().advance(1000);
    CHECK(m.status() == "disputed");

    auto freeze = m.action(protocol::AssetAction::freeze);
    REQUIRE(m.record(freeze));
    m.home.clock().advance(1000);
    CHECK(m.status() == "frozen");
    CHECK_FALSE(m.record(m.action(protocol::AssetAction::pay)));
    REQUIRE(m.record(m.action(protocol::AssetAction::unfreeze)));
    m.home.clock().advance(1000);
    CHECK(m.status() == "disputed");

    REQUIRE(m.record(m.action(protocol::AssetAction::pay)));
    m.home.clock().advance(1000);
    auto confirm = m.action(protocol::AssetAction::confirm);
    more = m.consent_to(confirm, {&m.buyer});
    bundles.insert(bundles.end(), more.begin(), more.end());
    REQUIRE(m.record(confirm));
    m.home.clock().advance(1000);
    CHECK(m.status() == "settled");
    CHECK_FALSE(m.record(m.action(protocol::AssetAction::freeze)));

    auto report = m.verify(m.evidence(bundles));
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->asset.state == "settled");
    CHECK(report->steps.size() == 7);
}

TEST_CASE("a warehouse receipt is redeemed in parts under its pledge", "[assets]") {
    World warehouse{crypto::HashAlg::sha256, "Warehouse"};
    World depositor{crypto::HashAlg::sha256, "Depositor"};
    World bank{crypto::HashAlg::sha256, "Bank"};
    auto metadata = protocol::encode_asset_metadata(protocol::AssetKind::warehouse_receipt,
                                                    {depositor.ledger().id(), 100, "t", {}});
    REQUIRE(metadata);
    const protocol::Id receipt =
        warehouse.ok(warehouse.org(),
                     warehouse.statement(warehouse.org_id(), std::nullopt,
                                         body_with(std::string(protocol::warehouse_receipt_type),
                                                   std::move(*metadata))));
    auto act = [&](protocol::AssetAction what, std::optional<protocol::Id> to,
                   std::optional<std::uint64_t> quantity, std::vector<World*> parties) {
        protocol::AssetActionBody b;
        b.asset = receipt;
        b.action = what;
        b.head = warehouse.ledger().state().asset(receipt)->head;
        b.to = std::move(to);
        b.quantity = quantity;
        const auto terms = protocol::terms_of(b, warehouse.ledger().id());
        std::vector<protocol::ConsentRef> refs;
        for (World* party : parties) {
            Consent c = consent(*party, terms);
            refs.push_back(
                {party->ledger().id(), c.record, *provider().digest(warehouse.hash(), c.bundle)});
        }
        std::ranges::sort(refs, [](const auto& x, const auto& y) {
            return std::ranges::lexicographical_compare(x.ledger.bytes(), y.ledger.bytes());
        });
        b.consents = std::move(refs);
        auto done = warehouse.submit(warehouse.org(),
                                     warehouse.statement(warehouse.org_id(), std::nullopt, b));
        warehouse.clock().advance(1000);
        return done.has_value();
    };
    auto status = [&] {
        return warehouse.ledger().state().record(receipt)->state;
    };
    auto units = [&] {
        return warehouse.ledger().state().asset(receipt)->units;
    };

    REQUIRE(act(protocol::AssetAction::pledge, bank.ledger().id(), {}, {&depositor, &bank}));
    // Under the pledge, redeeming needs the pledgee too.
    CHECK_FALSE(act(protocol::AssetAction::redeem, {}, 40, {&depositor}));
    CHECK_FALSE(act(protocol::AssetAction::redeem, {}, 101, {&depositor, &bank}));
    REQUIRE(act(protocol::AssetAction::redeem, {}, 40, {&depositor, &bank}));
    CHECK(status() == "pledged");
    CHECK(units() == 60);
    // Receivables' actions are not a receipt's.
    CHECK_FALSE(act(protocol::AssetAction::pay, {}, {}, {}));
    // The bank enforces its pledge: it holds the rest.
    REQUIRE(act(protocol::AssetAction::enforce, {}, {}, {&bank}));
    CHECK(status() == "active");
    CHECK(warehouse.ledger().state().asset(receipt)->holder == bank.ledger().id());
    REQUIRE(act(protocol::AssetAction::redeem, {}, 60, {&bank}));
    CHECK(status() == "redeemed");
    CHECK(units() == 0);
    CHECK_FALSE(act(protocol::AssetAction::cancel, {}, {}, {&bank}));
}

TEST_CASE("asset registrations carry well-formed metadata", "[assets]") {
    World home{crypto::HashAlg::sha256, "Core Enterprise"};
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    auto issue = [&](std::string_view type, cbor::Value metadata) {
        return home.submit(home.org(),
                           home.statement(home.org_id(), std::nullopt,
                                          body_with(std::string(type), std::move(metadata))));
    };
    const auto holder = cbor::Value::bytes(supplier.ledger().id().bytes());
    auto receivable = [&](cbor::Value h, cbor::Value amount, std::string currency) {
        return cbor::Value::map({{cbor::Value::text("holder"), std::move(h)},
                                 {cbor::Value::text("amount"), std::move(amount)},
                                 {cbor::Value::text("currency"), cbor::Value::text(currency)},
                                 {cbor::Value::text("due"), cbor::Value::unsigned_integer(t0)}});
    };
    CHECK(issue(protocol::receivable_type,
                receivable(holder, cbor::Value::unsigned_integer(1), "CNY")));
    CHECK_FALSE(
        issue(protocol::receivable_type, receivable(cbor::Value::bytes(home.ledger().id().bytes()),
                                                    cbor::Value::unsigned_integer(1), "CNY")));
    CHECK_FALSE(issue(protocol::receivable_type,
                      receivable(holder, cbor::Value::unsigned_integer(0), "CNY")));
    CHECK_FALSE(issue(protocol::receivable_type,
                      receivable(holder, cbor::Value::unsigned_integer(1), "RMB ")));
    CHECK_FALSE(
        issue(protocol::receivable_type, receivable(holder, cbor::Value::text("1"), "CNY")));
    CHECK_FALSE(issue(protocol::receivable_type,
                      cbor::Value::map({{cbor::Value::text("holder"), holder}})));
    // Without metadata at all.
    CHECK_FALSE(home.submit(
        home.org(), home.statement(home.org_id(), std::nullopt,
                                   home.record_body(std::string(protocol::receivable_type)))));
    CHECK_FALSE(issue(
        protocol::warehouse_receipt_type,
        cbor::Value::map({{cbor::Value::text("holder"), holder},
                          {cbor::Value::text("quantity"), cbor::Value::unsigned_integer(5)},
                          {cbor::Value::text("unit"), cbor::Value::text(std::string(17, 'k'))}})));
}
