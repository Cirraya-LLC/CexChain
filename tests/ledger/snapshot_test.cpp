// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/state.hpp>

#include "support/ledger_world.hpp"
#include "support/snapshots.hpp"

namespace {

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::Errc;

/// A ledger with people, an agent, a device, delegations of several scopes,
/// records endorsed, revoked, and superseded, and a key rotation.
void populate(World& w, Cast& c) {
    const protocol::Id document = w.ok(c.agent, agent_record(w, c, document_type));
    for (int i = 0; i < 2; ++i) {
        w.ok(c.agent, agent_record(w, c, document_type));
    }
    const protocol::Id first =
        w.ok(c.alice, w.statement(c.alice_id, c.alice_delegation, w.record_body(note_type)));
    w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                            protocol::RecordEndorseBody{document, "inspector"}));
    w.ok(c.alice,
         w.statement(c.alice_id, c.alice_delegation, protocol::RecordRevokeBody{first, "error"}));
    auto newer = w.record_body(note_type);
    newer.supersedes = first;
    w.ok(c.alice, w.statement(c.alice_id, c.alice_delegation, std::move(newer)));
    const KeyPair device = key("device");
    w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::device, device);
    const KeyPair rotated = key("bob rotated");
    w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                              protocol::ActorRotateKeyBody{c.bob_id, rotated.public_key()}));
}

/// Rewrites a snapshot file with `change` applied and its digest made good
/// again: a snapshot that is whole, but not the log's.
void forge(World& w, const std::string& file, std::size_t offset) {
    Bytes bytes = w.fs().contents(file);
    REQUIRE(bytes.size() > offset + 32);
    bytes[offset] ^= 0x01;
    // The seal: the SHA-256 of the SHA-256s of its 4 MiB pieces.
    const kanhe::ByteView body = kanhe::ByteView(bytes).first(bytes.size() - 32);
    constexpr std::size_t piece = std::size_t{4} << 20;
    Bytes digests;
    for (std::size_t at = 0; at < body.size(); at += piece) {
        const auto d = provider().digest(crypto::HashAlg::sha256,
                                         body.subspan(at, std::min(piece, body.size() - at)));
        digests.insert(digests.end(), d->bytes().begin(), d->bytes().end());
    }
    const auto digest = provider().digest(crypto::HashAlg::sha256, digests);
    std::ranges::copy(digest->bytes(), bytes.end() - 32);
    auto handle = w.fs().open(file);
    REQUIRE(handle);
    REQUIRE((*handle)->truncate(0));
    REQUIRE((*handle)->append(bytes));
    REQUIRE((*handle)->sync());
}

} // namespace

TEST_CASE("a ledger opens from its snapshot as from its log", "[ledger][snapshot]") {
    World w;
    Cast c = build_cast(w);
    populate(w, c);
    check_snapshot(w);
    const std::uint64_t first_size = w.ledger().size();
    CHECK(w.ledger().snapshot()->size == first_size);

    // Later entries are replayed on top; the next snapshot takes the other
    // file, and the newest wins.
    w.ok(c.agent, agent_record(w, c, document_type));
    auto ahead = w.ledger().write_snapshot();
    REQUIRE_FALSE(ahead);
    CHECK(ahead.error().code == Errc::rejected); // not right after a checkpoint
    auto reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(reopened);
    CHECK(reopened->opened_from_snapshot()->size == first_size);
    CHECK(reopened->size() == w.ledger().size());
    check_snapshot(w);
    CHECK(w.ledger().snapshot()->size > first_size);
    CHECK_FALSE(w.fs().contents("snapshot-a").empty());
    CHECK_FALSE(w.fs().contents("snapshot-b").empty());

    // A damaged newest snapshot: the older one serves.
    const std::uint64_t newest = w.ledger().snapshot()->size;
    const std::string newest_file =
        w.fs().contents("snapshot-a").size() > w.fs().contents("snapshot-b").size() ? "snapshot-a"
                                                                                    : "snapshot-b";
    w.fs().corrupt(newest_file, 200);
    reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(reopened);
    REQUIRE(reopened->opened_from_snapshot());
    CHECK(reopened->opened_from_snapshot()->size < newest);
    // Both gone: the whole log is replayed.
    REQUIRE(w.ledger().remove_snapshots());
    reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(reopened);
    CHECK_FALSE(reopened->opened_from_snapshot());
    CHECK_FALSE(reopened->snapshot());
    CHECK(*reopened->state().encode() == *w.ledger().state().encode());
}

TEST_CASE("a snapshot that disagrees with its log is caught", "[ledger][snapshot]") {
    World w;
    Cast c = build_cast(w);
    populate(w, c);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    REQUIRE(w.ledger().write_snapshot());
    // A byte of the state near its end (the last records' counts, not in
    // the state tree's leaves) changed, the digest made good: it loads, and
    // the check finds it.
    const Bytes original = w.fs().contents("snapshot-a");
    forge(w, "snapshot-a", original.size() - 32 - 600);
    auto opened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(opened);
    if (opened->opened_from_snapshot()) {
        const auto verified = opened->verify_snapshot(w.fs());
        REQUIRE_FALSE(verified);
        CHECK(verified.error().code == Errc::verification_failed);
    } else {
        // The change broke one of the checks made when opening.
        CHECK(*opened->state().encode() == *w.ledger().state().encode());
    }

    // Another rules version: not taken.
    REQUIRE(w.ledger().remove_snapshots());
    REQUIRE(w.ledger().write_snapshot());
    forge(w, "snapshot-a", 23); // the rules version's last byte
    opened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(opened);
    CHECK_FALSE(opened->opened_from_snapshot());
    CHECK_FALSE(opened->snapshot());
}

TEST_CASE("a ledger writes a snapshot by itself as its log grows", "[ledger][snapshot]") {
    World w;
    Cast c = build_cast(w);
    w.ledger().set_snapshot_interval(10);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    CHECK_FALSE(w.ledger().snapshot()); // fewer than 10 entries yet
    for (int i = 0; i < 6; ++i) {
        w.ok(c.agent, agent_record(w, c, document_type));
    }
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    REQUIRE(w.ledger().snapshot());
    CHECK(w.ledger().snapshot()->size == w.ledger().size());
    const std::uint64_t at = w.ledger().size();
    w.ok(c.agent, agent_record(w, c, document_type));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    CHECK(w.ledger().snapshot()->size == at); // not grown enough since
    w.ledger().set_snapshot_interval(0);
    for (int i = 0; i < 12; ++i) {
        w.ok(c.agent, agent_record(w, c, document_type));
    }
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    CHECK(w.ledger().snapshot()->size == at); // never
}
