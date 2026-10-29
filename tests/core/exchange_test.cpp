// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Proposal and consent files against vectors encoded independently
// (testvectors/exchange-v1.json, tools/testvectors/exchange_vectors.py):
// each accepted file reads to its fields and encodes back to the same
// bytes; each refused one is refused.

#include <string>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/exchange.hpp>

#include "support/vectors.hpp"

using namespace cexchain;

TEST_CASE("exchange files: accepted files read to their fields and back to their bytes",
          "[protocol][exchange]") {
    const auto vectors = test::load_vectors("exchange-v1.json");
    REQUIRE(vectors["accepted"].size() >= 4);
    for (const auto& v : vectors["accepted"]) {
        INFO(v["name"].get<std::string>());
        const Bytes encoded = test::hex_field(v["encoded"]);
        const auto file = protocol::decode_exchange_file(encoded);
        REQUIRE(file);
        CHECK(protocol::name(file->kind) == v["kind"].get<std::string>());
        CHECK(to_hex(file->home.bytes()) == v["home"].get<std::string>());
        CHECK(to_hex(file->instance.bytes()) == v["instance"].get<std::string>());
        CHECK(file->head == v["head"].get<std::uint64_t>());
        CHECK(file->function == v["function"].get<std::string>());
        CHECK(to_hex(*cbor::encode(file->arguments)) == v["arguments"].get<std::string>());
        CHECK(crypto::cose_id(file->hash) == v["hash"].get<std::int64_t>());
        CHECK(to_hex(file->evidence) == v["evidence"].get<std::string>());
        REQUIRE(file->needs.size() == v["needs"].size());
        for (std::size_t i = 0; i < file->needs.size(); ++i) {
            CHECK(to_hex(file->needs[i].bytes()) == v["needs"][i].get<std::string>());
        }
        CHECK(file->note.has_value() == !v["note"].is_null());
        const auto again = protocol::encode_exchange_file(*file);
        REQUIRE(again);
        CHECK(*again == encoded);
    }
}

TEST_CASE("exchange files: refused files are refused", "[protocol][exchange]") {
    const auto vectors = test::load_vectors("exchange-v1.json");
    REQUIRE(vectors["refused"].size() >= 18);
    for (const auto& v : vectors["refused"]) {
        INFO(v["name"].get<std::string>());
        CHECK_FALSE(protocol::decode_exchange_file(test::hex_field(v["encoded"])));
    }
    // And the writer refuses what the reader would.
    protocol::ExchangeFile file;
    file.function = "lend";
    file.arguments = cbor::Value::null();
    file.evidence = Bytes{1};
    CHECK_FALSE(protocol::encode_exchange_file(file)); // a proposal without its ledgers
    file.kind = protocol::ExchangeKind::consent;
    CHECK(protocol::encode_exchange_file(file));
    file.note = std::string(protocol::max_exchange_note + 1, 'n');
    CHECK_FALSE(protocol::encode_exchange_file(file));
    file.note.reset();
    file.hash = crypto::HashAlg::sha384;
    CHECK_FALSE(protocol::encode_exchange_file(file));
}
