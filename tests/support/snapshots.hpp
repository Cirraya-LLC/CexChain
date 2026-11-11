// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <variant>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>

#include "support/ledger_world.hpp"

// Checks that a ledger's state survives a snapshot: written whole and read
// back, it is the same state; and the ledger opened from a snapshot is the
// same ledger as one that replays its whole log.
namespace kanhe::test {

/// The code of the deploy statement at `index` of `ledger`'s log.
inline Result<Bytes> deploy_code(const ledger::Ledger& ledger, std::uint64_t index) {
    auto bytes = ledger.entry(index);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    auto entry = protocol::decode_log_entry(*bytes);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    auto statement = protocol::parse_statement(provider(), entry->statement, ledger.hash());
    if (!statement) {
        return std::unexpected(statement.error());
    }
    const auto* deploy = std::get_if<protocol::ContractDeployBody>(&statement->statement.body);
    if (deploy == nullptr) {
        return fail(Errc::malformed, "not a deploy");
    }
    return deploy->code;
}

/// After a checkpoint, a snapshot; a ledger opened from it has the state of
/// one that replays its whole log, and checks against it.
inline void check_snapshot(World& w) {
    const auto encoded = w.ledger().state().encode();
    REQUIRE(encoded);
    auto decoded = protocol::LedgerState::decode(
        *encoded, [&](std::uint64_t index) { return deploy_code(w.ledger(), index); });
    INFO((decoded ? std::string() : std::string(decoded.error().detail)));
    REQUIRE(decoded);
    CHECK(*decoded->encode() == *encoded);

    REQUIRE(w.ledger().checkpoint(w.log_key()));
    const auto written = w.ledger().write_snapshot();
    INFO((written ? std::string() : std::string(written.error().detail)));
    REQUIRE(written);
    auto from_snapshot = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(from_snapshot);
    REQUIRE(from_snapshot->opened_from_snapshot());
    CHECK(from_snapshot->opened_from_snapshot()->size == w.ledger().size());
    auto from_log = ledger::Ledger::open(w.fs(), w.clock(), provider(), {.use_snapshot = false});
    REQUIRE(from_log);
    CHECK_FALSE(from_log->opened_from_snapshot());
    CHECK(*from_snapshot->state().encode() == *from_log->state().encode());
    CHECK(*from_snapshot->root(w.ledger().size()) == *from_log->root(w.ledger().size()));
    CHECK(from_snapshot->state_commitment() == from_log->state_commitment());
    const auto verified = from_snapshot->verify_snapshot(w.fs());
    INFO((verified ? std::string() : std::string(verified.error().detail)));
    CHECK(verified);
}

} // namespace kanhe::test
