// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Access across two ledgers: a bank asks a factory for a certificate.

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/access.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

const protocol::Nonce salt_a{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
const Bytes report_content{'r', 'e', 'p', 'o', 'r', 't'};

/// The factory's certificate, with real field commitments and an attachment.
struct Certificate {
    protocol::Id id;
    protocol::FieldCommitment commitment;
};

Certificate issue_certificate(World& w) {
    std::vector<protocol::RecordField> fields{
        {"price", salt_a, cbor::Value::text("1200")},
        {"result", salt_a, cbor::Value::text("pass")},
    };
    auto commitment = protocol::commit_fields(provider(), w.hash(), fields);
    REQUIRE(commitment);
    auto attachment = protocol::attachment_commitment(provider(), w.hash(), salt_a, report_content);
    REQUIRE(attachment);
    protocol::RecordRegisterBody body{
        certificate,
        Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end()),
        commitment->leaves.size(),
        {{"report.pdf", "application/pdf", report_content.size(),
          Bytes(attachment->bytes().begin(), attachment->bytes().end())}},
        std::nullopt};
    const auto id = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, body));
    return {id, std::move(*commitment)};
}

protocol::Id issue_access(World& w, std::string_view type, cbor::Value metadata) {
    auto commitment = protocol::commit_fields(provider(), w.hash(),
                                              {{"note", salt_a, cbor::Value::text("access")}});
    REQUIRE(commitment);
    protocol::RecordRegisterBody body{
        std::string(type),
        Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end()),
        1,
        {},
        std::move(metadata)};
    return w.ok(w.org(), w.statement(w.org_id(), std::nullopt, body));
}

/// The evidence of `record`, after a fresh checkpoint.
Bytes evidence(World& w, const protocol::Id& record,
               std::vector<protocol::FieldDisclosure> disclosures = {},
               std::vector<protocol::AttachmentOpening> openings = {}) {
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    auto bundle = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(bundle);
    bundle->disclosures = std::move(disclosures);
    bundle->attachments = std::move(openings);
    auto encoded = protocol::encode_bundle(*bundle);
    REQUIRE(encoded);
    return *encoded;
}

struct Parties {
    World factory{crypto::HashAlg::sha256};
    World bank{crypto::HashAlg::sm3}; // same keys, another ledger
    Certificate cert = issue_certificate(factory);
    Bytes recipient = Bytes(32, 0x77);
    protocol::Timestamp now = t0 + day / 2;

    protocol::AccessRequest request() {
        return {factory.ledger().id(),
                cert.id,
                "loan collateral",
                t0 + 10 * day,
                recipient,
                std::vector<std::string>{"result"},
                std::vector<std::string>{"report.pdf"}};
    }

    protocol::AccessGrant grant(const protocol::Id& request_id) {
        return {bank.ledger().id(), request_id,   cert.id,  {"result"},
                {"report.pdf"},     t0 + 5 * day, recipient};
    }
};

} // namespace

TEST_CASE("access metadata round-trips and is strict", "[access]") {
    Parties p;
    const auto request = p.request();
    const auto encoded = protocol::encode_access_request(request);
    REQUIRE(encoded);
    CHECK(*protocol::decode_access_request(*encoded) == request);

    auto open_request = request;
    open_request.fields.reset();
    open_request.attachments.reset();
    CHECK(*protocol::decode_access_request(*protocol::encode_access_request(open_request)) ==
          open_request);

    const auto grant = p.grant(p.cert.id);
    CHECK(*protocol::decode_access_grant(*protocol::encode_access_grant(grant)) == grant);
    const protocol::AccessReceipt receipt{p.factory.ledger().id(), p.cert.id, Bytes(32, 9)};
    CHECK(*protocol::decode_access_receipt(*protocol::encode_access_receipt(receipt)) == receipt);

    auto bad = request;
    bad.recipient = Bytes(31, 1);
    CHECK_FALSE(protocol::encode_access_request(bad));
    bad = request;
    bad.fields = std::vector<std::string>{"a", "a"};
    CHECK_FALSE(protocol::encode_access_request(bad));
    bad = request;
    bad.purpose.clear();
    CHECK_FALSE(protocol::encode_access_request(bad));

    // Unknown keys and wrong types are refused.
    cbor::Map extra = *encoded->as_map();
    extra.push_back({cbor::Value::text("zzz"), cbor::Value::integer(1)});
    CHECK_FALSE(protocol::decode_access_request(cbor::Value::map(extra)));
    CHECK_FALSE(protocol::decode_access_grant(*encoded));
    CHECK_FALSE(protocol::decode_access_receipt(cbor::Value::text("x")));

    const protocol::Delivery sample{Bytes{1, 2}, Bytes(32, 3), Bytes{4, 5, 6}};
    const auto sample_bytes = protocol::encode_delivery(sample);
    REQUIRE(sample_bytes);
    CHECK(*protocol::decode_delivery(*sample_bytes) == sample);
    CHECK_FALSE(protocol::decode_delivery(Bytes{0xa0}));
    const protocol::DeliveryContents contents{Bytes{7}, {{"a.pdf", Bytes{8}}}};
    CHECK(*protocol::decode_delivery_contents(*protocol::encode_delivery_contents(contents)) ==
          contents);
}

TEST_CASE("a request, a grant, a delivery, a receipt", "[access]") {
    Parties p;
    const protocol::Id request_id = issue_access(p.bank, protocol::access_request_type,
                                                 *protocol::encode_access_request(p.request()));
    const Bytes request_bundle = evidence(p.bank, request_id);

    // The factory checks the request, pinned to the bank's ledger.
    const auto checked = protocol::check_access_request(
        provider(), request_bundle, p.bank.ledger().id(), p.factory.ledger().id(), p.now);
    REQUIRE(checked);
    CHECK(checked->value == p.request());
    CHECK(checked->report.record == request_id);
    // Not from another ledger, not for another, not expired.
    CHECK(protocol::check_access_request(provider(), request_bundle, p.factory.ledger().id(),
                                         p.factory.ledger().id(), p.now)
              .error()
              .code == Errc::verification_failed);
    CHECK(protocol::check_access_request(provider(), request_bundle, p.bank.ledger().id(),
                                         p.bank.ledger().id(), p.now)
              .error()
              .code == Errc::rejected);
    CHECK(protocol::check_access_request(provider(), request_bundle, p.bank.ledger().id(),
                                         p.factory.ledger().id(), t0 + 11 * day)
              .error()
              .code == Errc::rejected);

    // The factory grants the result and the report.
    const protocol::Id grant_id = issue_access(p.factory, protocol::access_grant_type,
                                               *protocol::encode_access_grant(p.grant(request_id)));
    const Bytes grant_bundle = evidence(p.factory, grant_id);
    const auto grant =
        protocol::check_access_grant(provider(), grant_bundle, p.factory.ledger().id(),
                                     p.bank.ledger().id(), request_id, p.request(), p.now);
    REQUIRE(grant);
    CHECK(grant->value == p.grant(request_id));
    // The grant must answer what was asked, as it was asked.
    auto refused = [&](protocol::AccessRequest asked, const protocol::Id& id) {
        const auto outcome =
            protocol::check_access_grant(provider(), grant_bundle, p.factory.ledger().id(),
                                         p.bank.ledger().id(), id, asked, p.now);
        return !outcome && outcome.error().code == Errc::rejected;
    };
    auto asked = p.request();
    asked.recipient = Bytes(32, 1);
    CHECK(refused(asked, request_id));
    CHECK(refused(p.request(), p.cert.id)); // another request
    asked = p.request();
    asked.record = grant_id; // another record than the one granted
    CHECK(refused(asked, request_id));
    asked = p.request();
    asked.ledger = p.bank.ledger().id(); // asked another ledger than the granter
    CHECK(refused(asked, request_id));
    asked = p.request();
    asked.fields = std::vector<std::string>{"price"}; // granted more than asked
    CHECK(refused(asked, request_id));
    asked = p.request();
    asked.attachments = std::vector<std::string>{};
    CHECK(refused(asked, request_id));
    asked = p.request();
    asked.until = t0 + 2 * day; // granted for longer than asked
    CHECK(refused(asked, request_id));
    asked = p.request();
    asked.fields.reset(); // asked for everything: any granted fields are within it
    asked.attachments.reset();
    CHECK(protocol::check_access_grant(provider(), grant_bundle, p.factory.ledger().id(),
                                       p.bank.ledger().id(), request_id, asked, p.now));

    // What is delivered must be the granted record, within the grant.
    auto disclose = [&](std::string_view name) {
        auto d = protocol::disclose_field(provider(), p.factory.hash(), p.cert.commitment, name);
        REQUIRE(d);
        return *d;
    };
    // Delivered bundles must be at the grant's checkpoint, as a granter
    // exports them both after one checkpoint.
    auto at_grant = [&](const protocol::Id& record,
                        std::vector<protocol::FieldDisclosure> disclosures = {},
                        std::vector<protocol::AttachmentOpening> openings = {}) {
        auto bundle = p.factory.ledger().export_evidence(p.factory.log_key(), record);
        REQUIRE(bundle);
        REQUIRE(
            bundle->checkpoint ==
            *protocol::decode_bundle(grant_bundle).transform([](const protocol::EvidenceBundle& b) {
                return b.checkpoint;
            }));
        bundle->disclosures = std::move(disclosures);
        bundle->attachments = std::move(openings);
        return *protocol::encode_bundle(*bundle);
    };
    const protocol::DeliveryContents good{
        at_grant(p.cert.id, {disclose("result")}, {{"report.pdf", salt_a}}),
        {{"report.pdf", report_content}}};
    const auto delivered =
        protocol::check_delivered_record(provider(), good, p.factory.ledger().id(), *grant);
    REQUIRE(delivered);
    REQUIRE(delivered->disclosed_fields.size() == 1);
    CHECK(delivered->disclosed_fields[0].name == "result");
    CHECK(delivered->attachments[0].status == protocol::AttachmentStatus::verified);

    auto not_verified = [&](const protocol::DeliveryContents& contents) {
        const auto outcome =
            protocol::check_delivered_record(provider(), contents, p.factory.ledger().id(), *grant);
        return !outcome && outcome.error().code == Errc::verification_failed;
    };
    SECTION("more than granted") {
        CHECK(not_verified(
            {at_grant(p.cert.id, {disclose("result"), disclose("price")}, {{"report.pdf", salt_a}}),
             {{"report.pdf", report_content}}}));
    }
    SECTION("less than granted") {
        CHECK(not_verified(
            {at_grant(p.cert.id, {}, {{"report.pdf", salt_a}}), {{"report.pdf", report_content}}}));
        CHECK(not_verified({at_grant(p.cert.id, {disclose("result")}), {}}));
        CHECK(not_verified({at_grant(p.cert.id, {disclose("result"), disclose("result")},
                                     {{"report.pdf", salt_a}}),
                            {{"report.pdf", report_content}}}));
    }
    SECTION("a file that is not the record's, or not checked against it") {
        protocol::DeliveryContents forged = good;
        forged.attachments["report.pdf"] = Bytes{'f', 'a', 'k', 'e'};
        CHECK(not_verified(forged));
        // Content without the opening to check it by is not accepted either.
        CHECK(not_verified({at_grant(p.cert.id, {disclose("result")}),
                            {{"report.pdf", Bytes{'f', 'a', 'k', 'e'}}}}));
        protocol::DeliveryContents extra = good;
        extra.attachments["invoice.pdf"] = Bytes{'x'};
        CHECK(not_verified(extra));
    }
    SECTION("another record, or one proven at another checkpoint") {
        CHECK(not_verified({at_grant(grant_id), {}}));
        static_cast<void>(issue_certificate(p.factory)); // the log moves on
        CHECK(not_verified(
            {evidence(p.factory, p.cert.id, {disclose("result")}, {{"report.pdf", salt_a}}),
             {{"report.pdf", report_content}}}));
    }
    SECTION("a revoked grant") {
        p.factory.ok(p.factory.org(),
                     p.factory.statement(p.factory.org_id(), std::nullopt,
                                         protocol::RecordRevokeBody{grant_id, "ended"}));
        CHECK(protocol::check_access_grant(provider(), evidence(p.factory, grant_id),
                                           p.factory.ledger().id(), p.bank.ledger().id(),
                                           request_id, p.request(), p.now)
                  .error()
                  .code == Errc::rejected);
    }
    SECTION("the bank acknowledges, and the factory checks it") {
        const Bytes delivery_hash(32, 0x42);
        const protocol::Id receipt_id = issue_access(
            p.bank, protocol::access_receipt_type,
            *protocol::encode_access_receipt({p.factory.ledger().id(), grant_id, delivery_hash}));
        const Bytes receipt_bundle = evidence(p.bank, receipt_id);
        const auto made = p.grant(request_id);
        CHECK(protocol::check_access_receipt(provider(), receipt_bundle, p.bank.ledger().id(),
                                             p.factory.ledger().id(), grant_id, made,
                                             delivery_hash));
        CHECK(protocol::check_access_receipt(provider(), receipt_bundle, p.bank.ledger().id(),
                                             p.factory.ledger().id(), grant_id, made, Bytes(32, 0))
                  .error()
                  .code == Errc::rejected);
        // Only the ledger the grant was made to may acknowledge it.
        auto to_another = made;
        to_another.ledger = p.cert.id;
        CHECK(protocol::check_access_receipt(provider(), receipt_bundle, p.bank.ledger().id(),
                                             p.factory.ledger().id(), grant_id, to_another,
                                             delivery_hash)
                  .error()
                  .code == Errc::rejected);
        // A receipt is not a request.
        CHECK(protocol::check_access_request(provider(), receipt_bundle, p.bank.ledger().id(),
                                             p.factory.ledger().id(), p.now)
                  .error()
                  .code == Errc::verification_failed);
    }
}

TEST_CASE("a withdrawn request is refused", "[access]") {
    Parties p;
    const protocol::Id request_id = issue_access(p.bank, protocol::access_request_type,
                                                 *protocol::encode_access_request(p.request()));
    p.bank.ok(p.bank.org(), p.bank.statement(p.bank.org_id(), std::nullopt,
                                             protocol::RecordTransitionBody{request_id, "requested",
                                                                            "withdrawn"}));
    CHECK(protocol::check_access_request(provider(), evidence(p.bank, request_id),
                                         p.bank.ledger().id(), p.factory.ledger().id(), p.now)
              .error()
              .code == Errc::rejected);
}
