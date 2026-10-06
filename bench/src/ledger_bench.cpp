// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The ledger in-process: signing, submitting, checkpointing, reopening
// (full replay), exporting, and verifying evidence, at a chosen scale.

#include <filesystem>
#include <optional>
#include <print>
#include <stdexcept>
#include <sys/resource.h>
#include <vector>
#ifdef __APPLE__
#include <mach/mach.h>
#else
#include <fstream>
#include <unistd.h>
#endif

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/parallel.hpp>

#include "bench.hpp"

namespace cexchain::bench {

namespace {

template <class T>
T must(Result<T> result, const char* what) {
    if (!result) {
        throw std::runtime_error(std::string(what) + ": " + std::string(result.error().detail));
    }
    return std::move(*result);
}

double peak_rss_mb() {
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
#ifdef __APPLE__
    return static_cast<double>(usage.ru_maxrss) / (1024.0 * 1024.0);
#else
    return static_cast<double>(usage.ru_maxrss) / 1024.0;
#endif
}

/// Resident memory now (peak_rss_mb() never goes down).
double current_rss_mb() {
#ifdef __APPLE__
    mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info),
                  &count) != KERN_SUCCESS) {
        return 0;
    }
    return static_cast<double>(info.resident_size) / (1024.0 * 1024.0);
#else
    std::ifstream statm("/proc/self/statm");
    std::uint64_t size = 0;
    std::uint64_t resident = 0;
    statm >> size >> resident;
    return static_cast<double>(resident * static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE))) /
           (1024.0 * 1024.0);
#endif
}

} // namespace

int ledger_bench(const Options& options) {
    const std::uint64_t n = options.number("entries", 20000);
    const std::uint64_t every = options.number("checkpoint-every", 1000);
    const std::uint64_t batch = std::max<std::uint64_t>(1, options.number("batch", 1));
    const std::string disk = options.text("disk", "");
    Results results;

    const crypto::openssl::Provider provider;
    auto org = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto log = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::ManualClock clock(1'791'244'800'000);
    ledger::SeededEntropy entropy(1);
    ledger::MemoryFileSystem memory;
    std::optional<ledger::PosixFileSystem> posix;
    if (!disk.empty()) {
        std::filesystem::remove_all(disk);
        posix.emplace(must(ledger::PosixFileSystem::open_directory(disk), "directory"));
    }
    ledger::FileSystem& fs =
        posix ? static_cast<ledger::FileSystem&>(*posix) : static_cast<ledger::FileSystem&>(memory);

    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Benchmark", org.public_key(),
                                         log.public_key()};
    auto ledger = must(
        ledger::Ledger::create(
            fs, clock, provider,
            must(protocol::sign_statement(org, provider, crypto::HashAlg::sha256, genesis), "sign")
                .encoded),
        "create");

    // Signing is the clients' work: done up front and timed apart.
    auto t = Clock::now();
    std::vector<Bytes> statements;
    statements.reserve(n);
    for (std::uint64_t i = 0; i < n; ++i) {
        protocol::Statement s;
        s.ledger_id = ledger.id();
        s.actor_id = ledger.id();
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body = protocol::RecordRegisterBody{
            "cexchain.certificate/1", Bytes(32, 7), 3, {}, std::nullopt};
        statements.push_back(
            must(protocol::sign_statement(org, provider, crypto::HashAlg::sha256, s), "sign")
                .encoded);
    }
    results.add("sign (client side)", elapsed_ms(t) * 1000 / static_cast<double>(n),
                "us/statement");

    double submit_ms = 0;
    double checkpoint_ms = 0;
    double last_checkpoint_ms = 0;
    std::uint64_t checkpoints = 0;
    for (std::uint64_t i = 0; i < n; i += batch) {
        const std::uint64_t end = std::min(n, i + batch);
        t = Clock::now();
        if (batch == 1) {
            must(ledger.submit(statements[i]), "submit");
        } else {
            const std::vector<ByteView> views(statements.begin() + static_cast<std::ptrdiff_t>(i),
                                              statements.begin() +
                                                  static_cast<std::ptrdiff_t>(end));
            for (auto& result : ledger.submit_batch(views)) {
                must(std::move(result), "submit");
            }
        }
        submit_ms += elapsed_ms(t);
        clock.advance(1);
        if (every > 0 && end / every != i / every) {
            t = Clock::now();
            must(ledger.checkpoint(log), "checkpoint");
            last_checkpoint_ms = elapsed_ms(t);
            checkpoint_ms += last_checkpoint_ms;
            ++checkpoints;
        }
    }
    results.add("threads", static_cast<double>(ledger::parallelism()), "");
    results.add(disk.empty() ? "submit (memory)" : "submit (disk)",
                submit_ms * 1000 / static_cast<double>(n), "us/statement");
    results.add("submit throughput", static_cast<double>(n) / submit_ms * 1000, "statements/s");
    if (checkpoints > 0) {
        results.add("checkpoint (average)", checkpoint_ms / static_cast<double>(checkpoints), "ms");
        results.add("checkpoint (last)", last_checkpoint_ms, "ms");
    }

    t = Clock::now();
    const auto leaves = protocol::state_leaves(ledger.state());
    must(protocol::state_root(provider, crypto::HashAlg::sha256, leaves), "state root");
    results.add("state root from scratch (reference)", elapsed_ms(t), "ms");

    const double before_open = current_rss_mb();
    t = Clock::now();
    auto reopened = must(ledger::Ledger::open(fs, clock, provider), "open");
    const double open_ms = elapsed_ms(t);
    // What one more ledger costs: the reopened one, with every structure
    // rebuilt from the log (an upper bound: it includes allocator slack).
    results.add("ledger memory per entry",
                (current_rss_mb() - before_open) * 1024 * 1024 /
                    static_cast<double>(reopened.size()),
                "bytes/entry");
    results.add("open (full replay)", open_ms, "ms");
    results.add("open per entry", open_ms * 1000 / static_cast<double>(reopened.size()),
                "us/entry");

    if (ledger.latest_checkpoint()) {
        const protocol::Id record = ledger.state().records().begin()->second.id;
        t = Clock::now();
        const auto proof = must(reopened.state_proof(record), "state proof");
        results.add("state proof", elapsed_ms(t), "ms");
        t = Clock::now();
        const auto bundle = must(reopened.export_evidence(log, record), "export");
        results.add("export evidence", elapsed_ms(t), "ms");
        const Bytes encoded = must(protocol::encode_bundle(bundle), "encode");
        t = Clock::now();
        must(protocol::verify_bundle(provider, encoded), "verify");
        results.add("verify evidence", elapsed_ms(t), "ms");
        static_cast<void>(proof);
    }
    results.add("entries", static_cast<double>(reopened.size()), "");
    results.add("peak memory", peak_rss_mb(), "MB");
    results.print(options.flag("json"));
    return 0;
}

} // namespace cexchain::bench
