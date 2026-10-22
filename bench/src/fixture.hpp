// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

// What the contract scenarios share: a home ledger and its organization
// (deterministic keys, a manual clock, seeded nonces), Bo builds, and the
// three contract workloads.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/ledger.hpp>

#include "bench.hpp"

namespace cexchain::bench {

/// 2026-10-06T00:00:00Z, as the tests' t0.
inline constexpr protocol::Timestamp t0 = 1'791'244'800'000;
inline constexpr protocol::Timestamp day = 86'400'000;

[[nodiscard]] const crypto::openssl::Provider& provider();

/// An Ed25519 key derived from `name`: the same in every run.
[[nodiscard]] crypto::openssl::KeyPair named_key(const std::string& name);

/// A ledger with its organization, in memory or in a directory, on a manual
/// clock: every statement is issued and registered at the clock's time.
class Home {
public:
    explicit Home(const std::string& name, const std::filesystem::path& directory = {},
                  protocol::Timestamp start = t0);
    Home(const Home&) = delete;
    Home& operator=(const Home&) = delete;

    [[nodiscard]] ledger::Ledger& ledger() { return *ledger_; }
    [[nodiscard]] const protocol::LedgerState& state() const { return ledger_->state(); }
    [[nodiscard]] const protocol::Id& id() const noexcept { return id_; }
    [[nodiscard]] ledger::ManualClock& clock() noexcept { return clock_; }
    [[nodiscard]] ledger::FileSystem& fs();
    [[nodiscard]] const std::filesystem::path& directory() const noexcept { return directory_; }
    [[nodiscard]] const crypto::openssl::KeyPair& org() const noexcept { return org_; }
    [[nodiscard]] const crypto::openssl::KeyPair& log_key() const noexcept { return log_; }
    [[nodiscard]] ledger::SeededEntropy& entropy() noexcept { return entropy_; }

    /// Signed by the organization, or by `signer` as `actor` under
    /// `delegation`; issued at the clock's time.
    [[nodiscard]] protocol::SignedStatement
    sign(protocol::Body body, const crypto::Signer* signer = nullptr,
         const std::optional<protocol::Id>& actor = std::nullopt,
         const std::optional<protocol::Id>& delegation = std::nullopt);
    /// Signs and registers; throws if refused.
    ledger::Registration submit(protocol::Body body);
    /// Registers signed statements in batches of `batch` (one `submit` each
    /// for 1), adding each statement's share of its call's time to
    /// `latencies`; throws if any is refused.
    void submit_all(std::span<const Bytes> statements, std::size_t batch, Latencies* latencies);
    /// Opens the ledger again from its log (a full replay); milliseconds.
    double reopen();
    /// Closes the ledger, for a server to open its directory.
    void close() { ledger_.reset(); }

private:
    std::filesystem::path directory_;
    crypto::openssl::KeyPair org_;
    crypto::openssl::KeyPair log_;
    ledger::ManualClock clock_;
    ledger::SeededEntropy entropy_;
    std::unique_ptr<ledger::MemoryFileSystem> memory_;
    std::optional<ledger::PosixFileSystem> posix_;
    std::optional<ledger::Ledger> ledger_;
    protocol::Id id_;
};

/// True if this build has the Bo compiler (GCC 16).
[[nodiscard]] bool have_bo();
/// Builds a Bo source to a deploy (language bo, with its source bundle),
/// as `contract deploy --bo` does, with the official packs and the
/// vocabulary packs given (their text); `build_ms` gets the build's time
/// (the compile, without the source bundle). Throws if it does not build,
/// or this build has no Bo compiler.
[[nodiscard]] protocol::ContractDeployBody
bo_deploy(std::string_view source, double* build_ms = nullptr,
          const std::vector<std::string>& vocabularies = {});
/// The examples directory: --examples, else the source tree's.
[[nodiscard]] std::filesystem::path examples_directory(const Options& options);
[[nodiscard]] std::string read_text(const std::filesystem::path& file);
/// The heavy workload's contract: a bill of up to `max_lines` lines, a
/// charge on each line and a tax on both.
[[nodiscard]] std::string bill_source(std::uint64_t max_lines);

[[nodiscard]] cbor::Value text(std::string value);
[[nodiscard]] cbor::Value id_value(const protocol::Id& id);
[[nodiscard]] cbor::Value number(std::uint64_t value);
[[nodiscard]] cbor::Value object(std::vector<std::pair<std::string, cbor::Value>> entries);

/// One of the contract workloads: what creates an instance and what each
/// round calls on it. Every party is the home itself, so no call waits for
/// a consent.
///   small: examples/lending (lend and bring back, in turn);
///   heavy: a bill of `lines` lines, reviewed (every charge and tax worked
///          out over every line) in each round;
///   split: examples/multi-tier-split, issued and then split in two (one
///          round: a split instance takes no more calls).
struct Workload {
    std::string name;
    std::string title;
    protocol::ContractDeployBody deploy;
    double build_ms = 0;
    std::uint64_t lines = 0;
    /// Rounds after which instances take no more calls (0: unbounded).
    std::uint64_t max_rounds = 0;

    [[nodiscard]] protocol::ContractCallBody create(const protocol::Id& contract,
                                                    const protocol::Id& home) const;
    /// The call of round `round` on an instance at `head`.
    [[nodiscard]] protocol::ContractCallBody call(const protocol::Id& instance, std::uint64_t head,
                                                  const protocol::Id& home,
                                                  std::uint64_t round) const;
};

[[nodiscard]] Workload make_workload(std::string_view name, const Options& options);
/// The workload names in `--contract` (comma-separated), else `fallback`.
[[nodiscard]] std::vector<std::string> workload_names(const Options& options,
                                                      const std::string& fallback);

/// Signs one call per instance for round `round`, each at the instance's
/// current head; instances with no more calls are skipped.
[[nodiscard]] std::vector<Bytes> sign_round(Home& home, const Workload& workload,
                                            std::span<const protocol::Id> instances,
                                            std::uint64_t round);

} // namespace cexchain::bench
