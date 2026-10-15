// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Several processes on one ledger (a server and the command line), and
// copies of a ledger (replicas, restores) that trust nothing they are given.

#include <cstdint>
#include <optional>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/log.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/record_log.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

ledger::Ledger open(World& w) {
    auto opened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(opened);
    return std::move(*opened);
}

std::vector<Bytes> entries(ledger::Ledger& l, std::uint64_t from, std::uint64_t to) {
    std::vector<Bytes> out;
    for (std::uint64_t i = from; i < to; ++i) {
        out.push_back(*l.entry(i));
    }
    return out;
}

/// A ledger with records, endorsements, and two checkpoints.
struct Source {
    World w;
    Cast c = build_cast(w);
    protocol::Id record;

    Source() {
        record = w.ok(c.agent, agent_record(w, c, document_type));
        REQUIRE(w.ledger().checkpoint(w.log_key()));
        w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                protocol::RecordEndorseBody{record, "inspector"}));
        w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                protocol::RecordEndorseBody{record, "reviewer"}));
        REQUIRE(w.ledger().checkpoint(w.log_key()));
        w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                protocol::RecordEndorseBody{record, "approver"}));
    }
};

/// Copies `from` the way a replica does: up to each checkpoint, then the
/// checkpoint, then the rest.
ledger::Ledger replicate(ledger::Ledger& from, ledger::MemoryFileSystem& fs,
                         ledger::ManualClock& clock) {
    auto replica = ledger::Ledger::create_replica(fs, clock, provider(), *from.entry(0));
    REQUIRE(replica);
    for (const auto& checkpoint : *from.checkpoints()) {
        REQUIRE(replica->append_entries(
            entries(from, replica->size(), checkpoint.checkpoint.tree_size)));
        REQUIRE(replica->store_checkpoint(checkpoint.encoded));
    }
    REQUIRE(replica->append_entries(entries(from, replica->size(), from.size())));
    return std::move(*replica);
}

} // namespace

TEST_CASE("a reader picks up what another process appended", "[ledger][refresh]") {
    World w;
    auto reader = open(w);
    Cast c = build_cast(w);
    const auto record = w.ok(c.agent, agent_record(w, c, document_type));
    REQUIRE(w.ledger().checkpoint(w.log_key()));

    const auto report = reader.refresh(w.fs(), false);
    REQUIRE(report);
    CHECK(report->entries == w.ledger().size() - 1);
    CHECK(report->checkpoints == 1);
    CHECK(reader.size() == w.ledger().size());
    CHECK(*reader.root(reader.size()) == *w.ledger().root(w.ledger().size()));
    CHECK(reader.state().record(record)->state == "registered");
    REQUIRE(reader.latest_checkpoint());
    CHECK(reader.latest_checkpoint()->encoded == w.ledger().latest_checkpoint()->encoded);
    // It saw the state commitment the checkpoint ends with, so it can prove.
    CHECK(reader.state_proof(record));
    CHECK(reader.state_commitment() == w.ledger().state_commitment());

    // Nothing new: nothing changes.
    const auto again = reader.refresh(w.fs(), false);
    REQUIRE(again);
    CHECK(again->entries == 0);
    CHECK(again->checkpoints == 0);
}

TEST_CASE("writers take turns on one ledger", "[ledger][refresh]") {
    World w;
    Cast c = build_cast(w);
    auto other = open(w);

    // The other process writes, refreshing first (as it would after taking
    // the lock); then the first one, likewise.
    REQUIRE(other.refresh(w.fs(), true));
    const auto record = agent_record(w, c, document_type);
    auto signed_record = protocol::sign_statement(c.agent, provider(), w.hash(), record);
    REQUIRE(signed_record);
    REQUIRE(other.submit(signed_record->encoded));
    REQUIRE(other.checkpoint(w.log_key()));

    REQUIRE(w.ledger().refresh(w.fs(), true));
    CHECK(w.ledger().size() == other.size());
    w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                            protocol::RecordEndorseBody{signed_record->id, "inspector"}));
    REQUIRE(w.ledger().checkpoint(w.log_key()));

    REQUIRE(other.refresh(w.fs(), true));
    CHECK(*other.root(other.size()) == *w.ledger().root(w.ledger().size()));
    auto reopened = open(w);
    CHECK(reopened.size() == w.ledger().size());
    CHECK(reopened.audit());
}

TEST_CASE("a refresh sees only what was acknowledged", "[ledger][refresh]") {
    World w;
    Cast c = build_cast(w);
    auto reader = open(w);

    // A writer died mid-append: bytes beyond the acknowledged size.
    {
        auto raw = w.fs().open("statements");
        REQUIRE(raw);
        REQUIRE((*raw)->append(Bytes{0, 0, 0, 9, 1, 2, 3}));
    }
    const auto with_tail = w.fs().contents("statements").size();
    const auto report = reader.refresh(w.fs(), false);
    REQUIRE(report);
    CHECK(report->entries == 0);
    // A reader does not touch the files; a writer holding the lock cuts the
    // tail off and can append again.
    CHECK(w.fs().contents("statements").size() == with_tail);
    REQUIRE(reader.refresh(w.fs(), true));
    CHECK(w.fs().contents("statements").size() == with_tail - 7);
    REQUIRE(reader.checkpoint(w.log_key()));
    CHECK(open(w).size() == reader.size());
}

TEST_CASE("a refresh reads the durable size from the sync file's tail", "[ledger][refresh]") {
    World w;
    Cast c = build_cast(w);
    auto reader = open(w);
    w.ok(c.agent, agent_record(w, c, document_type));
    // A writer died while recording a sync: a torn entry at the end, then
    // a whole but damaged one.
    {
        auto synced = w.fs().open("statements.synced");
        REQUIRE(synced);
        REQUIRE((*synced)->append(Bytes{0, 0, 0, 8, 1}));
    }
    auto report = reader.refresh(w.fs(), false);
    REQUIRE(report);
    CHECK(report->entries == 1);
    CHECK(reader.size() == w.ledger().size());
    {
        auto synced = w.fs().open("statements.synced");
        REQUIRE(synced);
        REQUIRE((*synced)->append(Bytes(11, 0xee)));
    }
    REQUIRE(reader.refresh(w.fs(), true)); // recovering cuts the damage off
    CHECK(w.fs().contents("statements.synced").size() % 16 == 0);
    REQUIRE(reader.checkpoint(w.log_key()));
    CHECK(open(w).size() == reader.size());
}

TEST_CASE("a refresh refuses entries that do not validate", "[ledger][refresh]") {
    World w;
    Cast c = build_cast(w);
    auto reader = open(w);
    // Someone appends a copy of an earlier statement behind the ledger's back.
    {
        auto log = ledger::RecordLog::open(w.fs(), "statements");
        REQUIRE(log);
        REQUIRE(log->append(*w.ledger().entry(3)));
    }
    const auto report = reader.refresh(w.fs(), false);
    REQUIRE_FALSE(report);
    CHECK(report.error().code == Errc::malformed);
    // The reader is now unusable rather than wrong.
    CHECK_FALSE(reader.checkpoint(w.log_key()));
    CHECK_FALSE(reader.refresh(w.fs(), false));
}

TEST_CASE("a replica copies a ledger and checks everything", "[ledger][replica]") {
    Source source;
    ledger::MemoryFileSystem fs;
    ledger::ManualClock clock(t0 + day);
    auto replica = replicate(source.w.ledger(), fs, clock);

    CHECK(replica.id() == source.w.ledger().id());
    CHECK(replica.size() == source.w.ledger().size());
    for (std::uint64_t i = 0; i < replica.size(); ++i) {
        CHECK(*replica.entry(i) == *source.w.ledger().entry(i));
    }
    REQUIRE(replica.latest_checkpoint());
    CHECK(replica.latest_checkpoint()->encoded == source.w.ledger().latest_checkpoint()->encoded);
    CHECK(replica.state_proof(source.record));
    const auto audit = replica.audit();
    REQUIRE(audit);
    CHECK(audit->checkpoints == 2);
    CHECK(audit->unchecked_entries == 1);
    // Storing the latest checkpoint again changes nothing.
    REQUIRE(replica.store_checkpoint(replica.latest_checkpoint()->encoded));
    CHECK(replica.checkpoints()->size() == 2);

    // The copy reopens like any ledger.
    auto reopened = ledger::Ledger::open(fs, clock, provider());
    REQUIRE(reopened);
    CHECK(reopened->size() == replica.size());
    CHECK(reopened->state_proof(source.record));
}

TEST_CASE("a replica refuses a forged history", "[ledger][replica][security]") {
    Source source;
    auto& original = source.w.ledger();
    ledger::MemoryFileSystem fs;
    ledger::ManualClock clock(t0 + day);

    SECTION("a ledger starts with genesis") {
        auto replica = ledger::Ledger::create_replica(fs, clock, provider(), *original.entry(1));
        REQUIRE_FALSE(replica);
        CHECK(replica.error().code == Errc::verification_failed);
        CHECK_FALSE(fs.exists("statements"));
    }

    auto replica = ledger::Ledger::create_replica(fs, clock, provider(), *original.entry(0));
    REQUIRE(replica);

    SECTION("entries out of order") {
        auto batch = entries(original, 1, 5);
        std::swap(batch[1], batch[2]);
        CHECK_FALSE(replica->append_entries(batch));
        CHECK(replica->size() == 2); // the first one was valid and is kept
    }
    SECTION("an altered entry") {
        auto batch = entries(original, 1, 4);
        batch[2][batch[2].size() - 5] ^= 1;
        CHECK_FALSE(replica->append_entries(batch));
        CHECK(replica->size() == 3);
    }
    SECTION("a dropped entry") {
        auto batch = entries(original, 1, original.size());
        batch.erase(batch.begin() + 3);
        const auto appended = replica->append_entries(batch);
        // Either an entry no longer validates or the state commitment no
        // longer matches: a gap never goes unnoticed.
        CHECK_FALSE(appended);
        CHECK(replica->size() < original.size() - 1);
    }
    SECTION("a checkpoint that disagrees with the log") {
        const auto checkpoints = *original.checkpoints();
        REQUIRE(
            replica->append_entries(entries(original, 1, checkpoints[1].checkpoint.tree_size - 1)));
        // Ahead of the log, then behind the latest.
        CHECK(replica->store_checkpoint(checkpoints[1].encoded).error().code ==
              Errc::verification_failed);
        REQUIRE(replica->append_entries(
            entries(original, replica->size(), checkpoints[1].checkpoint.tree_size)));
        REQUIRE(replica->store_checkpoint(checkpoints[1].encoded));
        CHECK(replica->store_checkpoint(checkpoints[0].encoded).error().code ==
              Errc::verification_failed);
    }
    SECTION("a checkpoint of another ledger") {
        World other(crypto::HashAlg::sm3); // same keys, another ledger
        REQUIRE(other.ledger().checkpoint(other.log_key()));
        CHECK(replica->store_checkpoint(other.ledger().latest_checkpoint()->encoded).error().code ==
              Errc::verification_failed);
    }
}

TEST_CASE("checkpoints never go back, so old ones cannot be replayed",
          "[ledger][replica][security]") {
    Source s;
    // Two genuine checkpoints of one size, a moment apart.
    REQUIRE(s.w.ledger().checkpoint(s.w.log_key()));
    const auto first = *s.w.ledger().latest_checkpoint();
    s.w.clock().advance(1000);
    REQUIRE(s.w.ledger().checkpoint(s.w.log_key()));
    const auto second = *s.w.ledger().latest_checkpoint();
    REQUIRE(first.checkpoint.tree_size == second.checkpoint.tree_size);
    REQUIRE(first.checkpoint.timestamp < second.checkpoint.timestamp);
    // Signing again with nothing new and no time passed adds nothing.
    const std::size_t stored = s.w.ledger().checkpoints()->size();
    REQUIRE(s.w.ledger().checkpoint(s.w.log_key()));
    CHECK(s.w.ledger().checkpoints()->size() == stored);
    CHECK(s.w.ledger().latest_checkpoint()->encoded == second.encoded);

    ledger::MemoryFileSystem fs;
    ledger::ManualClock clock(t0);
    auto replica = replicate(s.w.ledger(), fs, clock);
    CHECK(replica.latest_checkpoint()->encoded == second.encoded);
    // The older one again, after the newer: refused, as checked ahead and
    // when stored. The newer again changes nothing.
    CHECK(replica.verify_checkpoint(first.encoded).error().code == Errc::verification_failed);
    CHECK(replica.store_checkpoint(first.encoded).error().code == Errc::verification_failed);
    CHECK(replica.store_checkpoint(second.encoded));
    CHECK(replica.checkpoints()->size() == s.w.ledger().checkpoints()->size());
}
