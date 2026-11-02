// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The search index: how fast it takes in a ledger's records, and how long a
// search and a report take over them. Records only: their rows are what a
// large ledger holds most of.

#include <filesystem>
#include <format>
#include <thread>
#include <unistd.h>
#include <vector>

#include <cexchain/core/protocol/log.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/search/index.hpp>

#include "bench.hpp"

namespace cexchain::bench {

int search_bench(const Options& options) {
    const std::uint64_t n = options.number("records", 100'000);
    const std::uint64_t repeat = std::max<std::uint64_t>(1, options.number("repeat", 20));
    Results results;

    const crypto::openssl::Provider provider;
    auto org = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto log = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::ManualClock clock(1'793'491'200'000);
    ledger::SeededEntropy entropy(1);
    ledger::MemoryFileSystem memory;
    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Benchmark", org.public_key(),
                                         log.public_key()};
    auto ledger = must(
        ledger::Ledger::create(
            memory, clock, provider,
            must(protocol::sign_statement(org, provider, crypto::HashAlg::sha256, genesis), "sign")
                .encoded),
        "create");

    // Records of two types over 100 days, each with a class, a year, and a
    // name in its public metadata.
    constexpr std::uint64_t batch = 1000;
    for (std::uint64_t i = 0; i < n; i += batch) {
        std::vector<Bytes> statements;
        for (std::uint64_t j = i; j < std::min(n, i + batch); ++j) {
            protocol::Statement s;
            s.ledger_id = ledger.id();
            s.actor_id = ledger.id();
            s.issued_at = clock.now();
            s.nonce = entropy.bytes<16>();
            cbor::Map metadata{
                {cbor::Value::text("class"), cbor::Value::text(std::format("S{}", j % 20))},
                {cbor::Value::text("year"), cbor::Value::text(std::to_string(2020 + j % 7))},
                {cbor::Value::text("student"), cbor::Value::text(std::format("學生 {:06}", j))}};
            s.body = protocol::RecordRegisterBody{j % 3 == 0 ? "example.school.application/1"
                                                             : "example.school.report/1",
                                                  Bytes(32, static_cast<std::uint8_t>(j)),
                                                  3,
                                                  {},
                                                  cbor::Value::map(std::move(metadata)),
                                                  std::nullopt};
            statements.push_back(
                must(protocol::sign_statement(org, provider, crypto::HashAlg::sha256, s), "sign")
                    .encoded);
        }
        const std::vector<ByteView> views(statements.begin(), statements.end());
        for (auto& r : ledger.submit_batch(views)) {
            must(std::move(r), "submit");
        }
        clock.advance(86'400'000 * batch * 100 / std::max<std::uint64_t>(n, 1));
    }

    const std::filesystem::path file = std::filesystem::temp_directory_path() /
                                       std::format("cexchain-search-bench-{}.sqlite", ::getpid());
    auto remove = [&] {
        for (const char* suffix : {"", "-wal", "-shm"}) {
            std::filesystem::remove(file.string() + suffix);
        }
    };
    remove();
    {
        // What reading the log alone costs: each entry read and parsed.
        auto t = Clock::now();
        for (std::uint64_t i = 0; i < ledger.size(); ++i) {
            const Bytes bytes = must(ledger.entry(i), "entry");
            const auto entry = must(protocol::decode_log_entry(bytes), "decode");
            if (!entry.is_state_commitment()) {
                must(protocol::parse_statement(provider, entry.statement, ledger.hash()), "parse");
            }
        }
        results.add("read and parse the log", static_cast<double>(n) * 1000 / elapsed_ms(t),
                    "entries/s");
    }
    {
        auto index = must(search::Index::open(ledger, file), "index");
        auto t = Clock::now();
        must(index->update(), "update");
        const double ms = elapsed_ms(t);
        results.add("index records", static_cast<double>(n) * 1000 / ms, "records/s");
        results.add("index size",
                    static_cast<double>(must(index->status(), "status").bytes) /
                        static_cast<double>(std::max<std::uint64_t>(n, 1)),
                    "bytes/record");

        auto time = [&](const std::string& name, auto&& run) {
            Latencies l;
            for (std::uint64_t r = 0; r < repeat; ++r) {
                const auto start = Clock::now();
                run();
                l.add(elapsed_ms(start) * 1000);
            }
            results.add(name + " p50", l.percentile(0.5) / 1000, "ms");
        };
        const search::PageRequest page;
        time("page by type", [&] {
            must(index->records({.type = "example.school.application/1"}, page), "search");
        });
        time("page by metadata", [&] {
            using M = search::RecordFilter::Metadata;
            must(index->records({.metadata = {M{"class", "S7", {}, {}}}}, page), "search");
        });
        time("page by text", [&] { must(index->records({.text = "000123"}, page), "search"); });
        time("page by time", [&] {
            must(index->records({.since = clock.now() - 86'400'000 * 10}, page), "search");
        });
        time("report by type and state", [&] {
            must(index->report(search::RecordFilter{},
                               {.by = {search::Group::type, search::Group::state}}),
                 "report");
        });
        time("report by day", [&] {
            must(index->report(search::RecordFilter{}, {.by = {search::Group::day}}), "report");
        });
        // Many searching at once, each thread its own reader: searches a
        // second on one thread and on eight, after a round to warm them.
        auto searches = [&](std::uint64_t threads, std::uint64_t each) {
            const auto started = Clock::now();
            std::vector<std::jthread> workers;
            for (std::uint64_t w = 0; w < threads; ++w) {
                workers.emplace_back([&, w] {
                    using M = search::RecordFilter::Metadata;
                    for (std::uint64_t r = 0; r < each; ++r) {
                        must(index->records(
                                 {.metadata = {M{
                                      "class", std::format("S{}", (w + r) % 20), {}, {}}}},
                                 page),
                             "search");
                    }
                });
            }
            workers.clear();
            return static_cast<double>(threads * each) * 1000 / elapsed_ms(started);
        };
        const std::uint64_t each = std::max<std::uint64_t>(repeat * 4, 40);
        searches(8, 2);
        results.add("searches, 1 at a time", searches(1, each), "searches/s");
        results.add("searches, 8 at once", searches(8, each), "searches/s");
    }
    remove();
    results.print(options.flag("json"));
    return 0;
}

} // namespace cexchain::bench
