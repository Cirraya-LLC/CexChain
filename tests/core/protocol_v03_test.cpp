// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The objects of specification revision v0.3 (access across organizations),
// as built by an independent Python encoder with its own HPKE, must be read
// and reproduced byte for byte, and its sealed delivery must open.

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace {

namespace protocol = cexchain::protocol;
using cexchain::Bytes;
using cexchain::test::hex;
using cexchain::test::load_vectors;

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

protocol::Id id(const nlohmann::json& value) {
    return *protocol::to_id(hex(text(value)));
}

std::vector<std::string> names(const nlohmann::json& value) {
    return value.get<std::vector<std::string>>();
}

cexchain::cbor::Value metadata(const nlohmann::json& section) {
    auto value = cexchain::cbor::decode(hex(text(section["metadata"])));
    REQUIRE(value);
    return std::move(*value);
}

Bytes encoded(const cexchain::Result<cexchain::cbor::Value>& value) {
    REQUIRE(value);
    return *cexchain::cbor::encode(*value);
}

} // namespace

TEST_CASE("v0.3 objects from an independent encoder", "[protocol][vectors][access]") {
    const auto document = load_vectors("protocol-v0.3.json");

    const auto& r = document["access_request"];
    const auto request = protocol::decode_access_request(metadata(r));
    REQUIRE(request);
    const auto& rv = r["values"];
    CHECK(request->ledger == id(rv["ledger"]));
    CHECK(request->record == id(rv["record"]));
    CHECK(request->purpose == text(rv["purpose"]));
    CHECK(request->until == rv["until"].get<protocol::Timestamp>());
    CHECK(request->recipient == hex(text(rv["recipient"])));
    CHECK(request->fields == names(rv["fields"]));
    CHECK(request->attachments == names(rv["attachments"]));
    CHECK(encoded(protocol::encode_access_request(*request)) == hex(text(r["metadata"])));

    const auto& g = document["access_grant"];
    const auto grant = protocol::decode_access_grant(metadata(g));
    REQUIRE(grant);
    CHECK(grant->ledger == id(g["values"]["ledger"]));
    CHECK(grant->request == id(g["values"]["request"]));
    CHECK(grant->fields == names(g["values"]["fields"]));
    CHECK(encoded(protocol::encode_access_grant(*grant)) == hex(text(g["metadata"])));

    const auto& c = document["access_receipt"];
    const auto receipt = protocol::decode_access_receipt(metadata(c));
    REQUIRE(receipt);
    CHECK(receipt->grant == id(c["values"]["grant"]));
    CHECK(encoded(protocol::encode_access_receipt(*receipt)) == hex(text(c["metadata"])));

    // The delivery: its structure, then its contents, sealed by the other
    // implementation's HPKE, opened by ours.
    const auto& d = document["delivery"];
    const Bytes delivery_bytes = hex(text(d["encoded"]));
    const auto delivery = protocol::decode_delivery(delivery_bytes);
    REQUIRE(delivery);
    CHECK(delivery->grant_bundle == hex(text(d["grant_bundle"])));
    CHECK(delivery->encapsulated_key == hex(text(d["encapsulated_key"])));
    CHECK(*protocol::encode_delivery(*delivery) == delivery_bytes);

    const auto key =
        cexchain::crypto::openssl::HpkeKey::from_pkcs8(hex(text(d["recipient_pkcs8"])));
    REQUIRE(key);
    CHECK(Bytes(key->public_key().begin(), key->public_key().end()) ==
          hex(text(d["recipient_public_key"])));
    const Bytes grant_id = hex(text(d["grant_id"]));
    const auto opened = key->open({delivery->encapsulated_key, delivery->ciphertext},
                                  cexchain::as_bytes(protocol::delivery_info), grant_id);
    REQUIRE(opened);
    CHECK(Bytes(opened->view().begin(), opened->view().end()) == hex(text(d["contents"])));
    // Bound to the grant: another grant id does not open it.
    CHECK_FALSE(key->open({delivery->encapsulated_key, delivery->ciphertext},
                          cexchain::as_bytes(protocol::delivery_info), Bytes(32, 0)));

    const auto contents = protocol::decode_delivery_contents(opened->view());
    REQUIRE(contents);
    CHECK(contents->record_bundle == hex(text(d["record_bundle"])));
    REQUIRE(contents->attachments.size() == 1);
    CHECK(contents->attachments.at("report.pdf") == hex(text(d["attachments"]["report.pdf"])));
    CHECK(*protocol::encode_delivery_contents(*contents) == hex(text(d["contents"])));
}
