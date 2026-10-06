// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// One writer and many readers on one ledger (D-048): readers never see an
// entry before it is durable, and everything they read is consistent.

#include <array>
#include <atomic>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/state_tree.hpp>

#include "support/ledger_world.hpp"

using namespace cexchain::test;
using cexchain::Bytes;

TEST_CASE("readers run alongside the writer", "[ledger][concurrency]") {
    World w;
    Cast c = build_cast(w);
    const protocol::Id first_record = w.ok(c.agent, agent_record(w, c, certificate));
    REQUIRE(w.ledger().checkpoint(w.log_key()));

    // Statements signed up front, submitted in batches with checkpoints.
    std::vector<Bytes> statements;
    for (int i = 0; i < 300; ++i) {
        statements.push_back(w.sign(c.agent, agent_record(w, c, certificate)));
        w.clock().advance(1);
    }

    std::atomic<bool> done = false;
    std::atomic<std::uint64_t> reads = 0;
    std::atomic<int> failures = 0;
    std::array<std::atomic<int>, 8> where{};
    auto expect = [&](bool ok, int line = 0) {
        if (!ok) {
            failures.fetch_add(1);
            where[static_cast<std::size_t>(line)].fetch_add(1);
        }
    };
    const ledger::Ledger& ledger = w.ledger();
    std::vector<std::jthread> readers;
    for (int r = 0; r < 4; ++r) {
        readers.emplace_back([&, r] {
            while (!done.load()) {
                const std::uint64_t size = ledger.size();
                // Every entry up to the durable size can be read and proven.
                const std::uint64_t index =
                    (reads.load() * 7 + static_cast<std::uint64_t>(r)) % size;
                expect(ledger.entry(index).has_value(), 1);
                expect(ledger.inclusion_proof(index, size).has_value(), 2);
                expect(ledger.root(size).has_value(), 3);
                if (const auto checkpoint = ledger.latest_checkpoint()) {
                    expect(checkpoint->checkpoint.tree_size <= ledger.size(), 4);
                    // Proofs verify against the commitment they come with.
                    const auto committed = ledger.committed_state_proof(first_record);
                    expect(committed &&
                               protocol::verify_state_proof(provider(), w.hash(), committed->proof,
                                                            committed->commitment.state_root),
                           5);
                    if (r == 0) {
                        const auto bundle = ledger.export_evidence(w.log_key(), first_record);
                        expect(bundle && protocol::verify_bundle(provider(),
                                                                 *protocol::encode_bundle(*bundle)),
                               6);
                    }
                }
                expect(ledger.statement_index(first_record).has_value(), 7);
                reads.fetch_add(1);
            }
        });
    }

    for (std::size_t i = 0; i < statements.size(); i += 25) {
        std::vector<cexchain::ByteView> batch;
        for (std::size_t j = i; j < std::min(statements.size(), i + 25); ++j) {
            batch.push_back(statements[j]);
        }
        for (const auto& result : w.ledger().submit_batch(batch)) {
            REQUIRE(result);
            REQUIRE(result->newly_registered);
        }
        if (i % 75 == 0) {
            REQUIRE(w.ledger().checkpoint(w.log_key()));
        }
    }
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    // Let the readers see the final state too.
    const std::uint64_t seen = reads.load();
    while (reads.load() < seen + 20) {
        std::this_thread::yield();
    }
    done = true;
    readers.clear();
    for (std::size_t i = 0; i < where.size(); ++i) {
        INFO("check " << i << ": " << where[i].load());
        CHECK(where[i].load() == 0);
    }
    CHECK(failures.load() == 0);
    CHECK(reads.load() > 0);
    CHECK(w.ledger().size() >= statements.size());
    CHECK(w.ledger().audit());
}
