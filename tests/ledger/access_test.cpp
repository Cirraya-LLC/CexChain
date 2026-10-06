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
                                     p.bank.ledger().id(), request_id, p.recipient, p.now);
    REQUIRE(grant);
    CHECK(grant->value == p.grant(request_id));
    CHECK(protocol::check_access_grant(provider(), grant_bundle, p.factory.ledger().id(),
                                       p.bank.ledger().id(), request_id, Bytes(32, 1), p.now)
              .error()
              .code == Errc::rejected);
    CHECK(protocol::check_access_grant(provider(), grant_bundle, p.factory.ledger().id(),
                                       p.bank.ledger().id(), p.cert.id, p.recipient, p.now)
              .error()
              .code == Errc::rejected);

    // What is delivered must be the granted record, within the grant.
    auto disclose = [&](std::string_view name) {
        auto d = protocol::disclose_field(provider(), p.factory.hash(), p.cert.commitment, name);
        REQUIRE(d);
        return *d;
    };
    const protocol::DeliveryContents good{
        evidence(p.factory, p.cert.id, {disclose("result")}, {{"report.pdf", salt_a}}),
        {{"report.pdf", report_content}}};
    const auto delivered =
        protocol::check_delivered_record(provider(), good, p.factory.ledger().id(), grant->value);
    REQUIRE(delivered);
    REQUIRE(delivered->disclosed_fields.size() == 1);
    CHECK(delivered->disclosed_fields[0].name == "result");
    CHECK(delivered->attachments[0].status == protocol::AttachmentStatus::verified);

    SECTION("more than granted") {
        const protocol::DeliveryContents too_much{
            evidence(p.factory, p.cert.id, {disclose("result"), disclose("price")}), {}};
        CHECK(protocol::check_delivered_record(provider(), too_much, p.factory.ledger().id(),
                                               grant->value)
                  .error()
                  .code == Errc::verification_failed);
    }
    SECTION("a file that is not the record's") {
        protocol::DeliveryContents forged = good;
        forged.attachments["report.pdf"] = Bytes{'f', 'a', 'k', 'e'};
        CHECK_FALSE(protocol::check_delivered_record(provider(), forged, p.factory.ledger().id(),
                                                     grant->value));
    }
    SECTION("another record") {
        const protocol::DeliveryContents other{evidence(p.factory, grant_id), {}};
        CHECK(protocol::check_delivered_record(provider(), other, p.factory.ledger().id(),
                                               grant->value)
                  .error()
                  .code == Errc::verification_failed);
    }
    SECTION("a revoked grant") {
        p.factory.ok(p.factory.org(),
                     p.factory.statement(p.factory.org_id(), std::nullopt,
                                         protocol::RecordRevokeBody{grant_id, "ended"}));
        CHECK(protocol::check_access_grant(provider(), evidence(p.factory, grant_id),
                                           p.factory.ledger().id(), p.bank.ledger().id(),
                                           request_id, p.recipient, p.now)
                  .error()
                  .code == Errc::rejected);
    }
    SECTION("the bank acknowledges, and the factory checks it") {
        const Bytes delivery_hash(32, 0x42);
        const protocol::Id receipt_id = issue_access(
            p.bank, protocol::access_receipt_type,
            *protocol::encode_access_receipt({p.factory.ledger().id(), grant_id, delivery_hash}));
        const Bytes receipt_bundle = evidence(p.bank, receipt_id);
        CHECK(protocol::check_access_receipt(provider(), receipt_bundle, p.bank.ledger().id(),
                                             p.factory.ledger().id(), grant_id, delivery_hash));
        CHECK(protocol::check_access_receipt(provider(), receipt_bundle, p.bank.ledger().id(),
                                             p.factory.ledger().id(), grant_id, Bytes(32, 0))
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
