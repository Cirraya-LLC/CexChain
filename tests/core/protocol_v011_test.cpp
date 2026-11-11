// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.11 (time-stamp tokens over checkpoints) against tokens made by
// OpenSSL's command-line responder over the checkpoints of the v0.10
// vectors, under a root made by Python's `cryptography`
// (tools/testvectors/generate.py). Each token's imprint is the ledger's hash
// of its checkpoint's payload, it chains to the root, and it says when.

#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/protocol/log.hpp>
#include <kanhe/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = kanhe::protocol;
namespace crypto = kanhe::crypto;
using kanhe::as_bytes;
using kanhe::Bytes;
using kanhe::to_hex;
using kanhe::test::hex;
using kanhe::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

} // namespace

TEST_CASE("v0.11 vectors: time-stamp tokens over checkpoints", "[protocol][v0.11][timestamp]") {
    const auto vectors = load_vectors("protocol-v0.11.json");
    const auto roots =
        crypto::openssl::read_certificates(as_bytes(vectors["root"].get<std::string>()));
    REQUIRE(roots);
    REQUIRE(roots->size() == 1);
    std::vector<Bytes> imprints;
    for (const auto& c : vectors["cases"]) {
        const auto hash = crypto::hash_alg_from_cose(c["hash"].get<std::int64_t>());
        REQUIRE(hash);
        const auto checkpoint = protocol::parse_checkpoint(hex(c["checkpoint"].get<std::string>()));
        REQUIRE(checkpoint);
        CHECK(to_hex(checkpoint->checkpoint.ledger_id.bytes()) ==
              c["ledger_id"].get<std::string>());
        const auto imprint = provider().digest(*hash, *checkpoint->envelope.payload);
        REQUIRE(imprint);
        CHECK(to_hex(imprint->bytes()) == c["imprint"].get<std::string>());

        const Bytes token = hex(c["token"].get<std::string>());
        auto read = provider().read_timestamp(token, *roots);
        INFO((read ? std::string() : std::string(read.error().detail)));
        REQUIRE(read);
        CHECK(read->trusted);
        CHECK(read->time == c["time"].get<std::uint64_t>());
        CHECK(read->accuracy == c["accuracy"].get<std::uint64_t>());
        CHECK(read->authority == c["authority"].get<std::string>());
        CHECK(read->imprint_alg == *hash);
        CHECK(read->imprint == Bytes(imprint->bytes().begin(), imprint->bytes().end()));
        CHECK(read->time > checkpoint->checkpoint.timestamp);
        // Without the root, it verifies but is not trusted.
        auto untrusted = provider().read_timestamp(token, {});
        REQUIRE(untrusted);
        CHECK_FALSE(untrusted->trusted);
        imprints.push_back(read->imprint);
    }
    // Each token stamps its own checkpoint only.
    REQUIRE(imprints.size() == 2);
    CHECK(imprints[0] != imprints[1]);
}
