// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.15 (asking about a condition) against objects built by an
// independent Python encoder (tools/testvectors/generate.py): access
// request metadata of both forms read and encoded byte for byte, the refused
// shapes, and claims checked as answers to a request, accepted or refused
// for the one rule they break.

#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/claims.hpp>

#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace cbor = cexchain::cbor;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::load_vectors;

namespace {

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.15.json");
    return document;
}

protocol::Id id_of(const nlohmann::json& value) {
    return *protocol::to_id(hex(value.get<std::string>()));
}

std::optional<std::vector<std::string>> names_of(const nlohmann::json& value) {
    if (value.is_null()) {
        return std::nullopt;
    }
    return value.get<std::vector<std::string>>();
}

cbor::Value decoded(const nlohmann::json& value) {
    return *cbor::decode(hex(value.get<std::string>()));
}

} // namespace

TEST_CASE("v0.15 access requests: both forms read and written, the others refused",
          "[protocol][vectors][v015]") {
    const auto& requests = vectors()["access_requests"];
    REQUIRE(requests["valid"].size() >= 6);
    std::size_t conditions = 0;
    for (const auto& c : requests["valid"]) {
        INFO(c["name"].get<std::string>());
        const auto request = protocol::decode_access_request(decoded(c["metadata"]));
        REQUIRE(request);
        CHECK(request->ledger == id_of(c["ledger"]));
        CHECK(request->record == id_of(c["record"]));
        CHECK(request->purpose == c["purpose"].get<std::string>());
        CHECK(request->until == c["until"].get<std::uint64_t>());
        CHECK(to_hex(request->recipient) ==
              (c["recipient"].is_null() ? "" : c["recipient"].get<std::string>()));
        CHECK(request->fields == names_of(c["fields"]));
        CHECK(request->attachments == names_of(c["attachments"]));
        if (c["condition"].is_null()) {
            CHECK_FALSE(request->condition);
            CHECK(c["text"].is_null());
        } else {
            ++conditions;
            REQUIRE(request->condition);
            CHECK(to_hex(*cbor::encode(protocol::encode_claim_condition(*request->condition))) ==
                  c["condition"].get<std::string>());
            CHECK(protocol::condition_text(*request->condition) == c["text"].get<std::string>());
        }
        // Encoded again, byte for byte.
        const auto again = protocol::encode_access_request(*request);
        REQUIRE(again);
        CHECK(to_hex(*cbor::encode(*again)) == c["metadata"].get<std::string>());
    }
    CHECK(conditions >= 3);
    REQUIRE(requests["refused"].size() >= 10);
    for (const auto& c : requests["refused"]) {
        INFO(c["name"].get<std::string>() + " (" + c["why"].get<std::string>() + ")");
        const auto value = cbor::decode(hex(c["metadata"].get<std::string>()));
        CHECK((!value || !protocol::decode_access_request(*value)));
    }
}

TEST_CASE("v0.15 answers: a claim answers the request it names, about its record, with its "
          "condition",
          "[protocol][vectors][v015]") {
    const auto& answers = vectors()["answers"];
    REQUIRE(answers.size() >= 6);
    bool accepted = false;
    bool refused = false;
    for (const auto& c : answers) {
        INFO(c["name"].get<std::string>());
        const auto request = protocol::decode_access_request(decoded(c["request"]));
        REQUIRE(request);
        const auto claim = protocol::decode_claim(decoded(c["claim"]));
        REQUIRE(claim);
        const auto answers_it = protocol::claim_answers(*claim, id_of(c["requester_ledger"]),
                                                        id_of(c["request_id"]), *request);
        CHECK(answers_it.has_value() == c["accepted"].get<bool>());
        (c["accepted"].get<bool>() ? accepted : refused) = true;
    }
    CHECK(accepted);
    CHECK(refused);
}
