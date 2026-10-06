// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <optional>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/witness.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

void grow(World& w, int records) {
    for (int i = 0; i < records; ++i) {
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body("other/1")));
    }
}

protocol::CosignRequest request(World& w, std::uint64_t old_size) {
    auto checkpoint = w.ledger().checkpoint(w.log_key());
    REQUIRE(checkpoint);
    auto proof = w.ledger().consistency_proof(old_size, checkpoint->checkpoint.tree_size);
    REQUIRE(proof);
    return {checkpoint->encoded, old_size, *proof};
}

protocol::WitnessedLog fresh(World& w) {
    return protocol::WitnessedLog{w.ledger().id(), w.log_key().public_key(), std::nullopt, 0, {}};
}

/// Cosigns, as a witness would, and returns the advanced state.
protocol::WitnessedLog cosign(const protocol::WitnessedLog& log, const protocol::CosignRequest& r) {
    auto checked = protocol::check_cosign_request(provider(), log, r);
    INFO((checked ? std::string() : std::string(checked.error().detail)));
    REQUIRE(checked);
    return protocol::advance(log, checked->checkpoint);
}

Errc refusal(const protocol::WitnessedLog& log, const protocol::CosignRequest& r) {
    auto checked = protocol::check_cosign_request(provider(), log, r);
    REQUIRE_FALSE(checked);
    return checked.error().code;
}

} // namespace

TEST_CASE("a witness follows a growing ledger", "[witness]") {
    World w;
    grow(w, 2);
    auto log = cosign(fresh(w), request(w, 0));
    CHECK(log.size == 3);
    CHECK(log.tree_hash == crypto::HashAlg::sha256);

    grow(w, 5);
    log = cosign(log, request(w, log.size));
    CHECK(log.size == 8);
    CHECK(log.root == *w.ledger().root(8));

    // The same size again (a newer checkpoint of an unchanged log) is fine.
    log = cosign(log, request(w, log.size));
    CHECK(log.size == 8);
}

TEST_CASE("a witness refuses what does not extend what it saw", "[witness]") {
    World w;
    grow(w, 3);
    const auto log = cosign(fresh(w), request(w, 0));

    SECTION("a proof from the wrong size is a conflict, not an attack") {
        grow(w, 1);
        CHECK(refusal(log, request(w, 2)) == Errc::rejected);
        CHECK(refusal(log, request(w, 0)) == Errc::rejected);
    }
    SECTION("a tampered proof") {
        grow(w, 4);
        auto r = request(w, log.size);
        REQUIRE_FALSE(r.proof.empty());
        r.proof.front() = *w.ledger().root(1);
        CHECK(refusal(log, r) == Errc::verification_failed);
    }
    SECTION("a checkpoint not signed by the log key") {
        grow(w, 1);
        auto r = request(w, log.size);
        const auto checkpoint = protocol::parse_checkpoint(r.checkpoint);
        r.checkpoint =
            protocol::sign_checkpoint(w.org(), provider(), checkpoint->checkpoint)->encoded;
        CHECK(refusal(log, r) == Errc::verification_failed);
    }
    SECTION("another ledger's checkpoint") {
        World other(crypto::HashAlg::sm3);
        grow(other, 5);
        auto foreign = log;
        foreign.log_key = other.log_key().public_key();
        CHECK(refusal(foreign, request(other, log.size)) == Errc::verification_failed);
    }
    SECTION("a ledger that went backwards") {
        const auto old = request(w, 0); // size 4, cosigned below
        auto ahead = cosign(log, request(w, log.size));
        grow(w, 2);
        ahead = cosign(ahead, request(w, ahead.size));
        auto stale = old;
        stale.old_size = ahead.size;
        CHECK(refusal(ahead, stale) == Errc::verification_failed);
    }
    SECTION("a fork: the same ledger, a different history") {
        // Same seed and keys: the twin has the same genesis and ledger id,
        // then diverges. A witness that cosigned one refuses the other.
        World twin;
        REQUIRE(twin.ledger().id() == w.ledger().id());
        twin.ok(twin.org(),
                twin.statement(twin.org_id(), std::nullopt, twin.record_body("forged/1")));
        grow(twin, 5);
        auto checked = protocol::check_cosign_request(provider(), log, request(twin, log.size));
        REQUIRE_FALSE(checked);
        CHECK(checked.error().code == Errc::verification_failed);
        INFO(checked.error().detail);
        CHECK(std::string(checked.error().detail).find("INCONSISTENT") != std::string::npos);
    }
}

TEST_CASE("cosign requests round-trip and are parsed strictly", "[witness]") {
    World w;
    grow(w, 6);
    const auto r = request(w, 3);
    const auto encoded = protocol::encode_cosign_request(r);
    REQUIRE(encoded);
    const auto decoded = protocol::decode_cosign_request(*encoded);
    REQUIRE(decoded);
    CHECK(*decoded == r);

    CHECK_FALSE(protocol::decode_cosign_request(Bytes{0xa0}));
    auto value = *cbor::decode(*encoded);
    auto map = *value.as_map();
    map.push_back({cbor::Value::integer(9), cbor::Value::integer(0)});
    CHECK_FALSE(protocol::decode_cosign_request(*cbor::encode(cbor::Value::map(map))));
    auto long_proof = r;
    long_proof.proof.assign(66, r.proof.front());
    CHECK_FALSE(protocol::encode_cosign_request(long_proof));
}

TEST_CASE("the ledger keeps witness cosignatures", "[witness][ledger]") {
    World w;
    grow(w, 2);
    const auto witness = key("witness");
    const auto other = key("other witness");
    auto checkpoint = w.ledger().checkpoint(w.log_key());
    REQUIRE(checkpoint);
    const auto cosignature =
        protocol::cosign_checkpoint(witness, provider(), checkpoint->checkpoint);
    REQUIRE(cosignature);

    CHECK(w.ledger().add_cosignature(cosignature->encoded, other.public_key()).error().code ==
          Errc::verification_failed);
    CHECK(w.ledger().add_cosignature(cosignature->encoded, w.log_key().public_key()).error().code ==
          Errc::rejected);
    REQUIRE(w.ledger().add_cosignature(cosignature->encoded, witness.public_key()));
    REQUIRE(w.ledger().add_cosignature(cosignature->encoded, witness.public_key())); // no-op
    CHECK(w.ledger().cosignatures()->size() == 1);
    CHECK(w.ledger().last_cosigned(witness.public_key())->value() == checkpoint->checkpoint);
    CHECK_FALSE(w.ledger().last_cosigned(other.public_key())->has_value());

    // A cosignature of a checkpoint the ledger never made is refused.
    auto invented = checkpoint->checkpoint;
    invented.timestamp += 1;
    CHECK(w.ledger()
              .add_cosignature(protocol::cosign_checkpoint(witness, provider(), invented)->encoded,
                               witness.public_key())
              .error()
              .code == Errc::not_found);

    // Exports carry the cosignatures of their checkpoint, and verify with the
    // witness trusted.
    const auto record =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body("cert/1")));
    auto newer = w.ledger().checkpoint(w.log_key());
    REQUIRE(newer);
    REQUIRE(w.ledger().add_cosignature(
        protocol::cosign_checkpoint(witness, provider(), newer->checkpoint)->encoded,
        witness.public_key()));
    auto bundle = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(bundle);
    REQUIRE(bundle->cosignatures.size() == 1);
    protocol::VerifyOptions options;
    options.trusted_witnesses.push_back(witness.public_key());
    const auto report =
        protocol::verify_bundle(provider(), *protocol::encode_bundle(*bundle), options);
    REQUIRE(report);
    CHECK(report->trusted_cosignatures == 1);

    // Cosignatures survive reopening, and the audit checks them.
    auto reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(reopened);
    CHECK(reopened->cosignatures()->size() == 2);
    const auto audit = reopened->audit();
    REQUIRE(audit);
    CHECK(audit->cosignatures == 2);
}
