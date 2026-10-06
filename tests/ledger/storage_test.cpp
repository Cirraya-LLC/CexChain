// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/record_log.hpp>
#include <cexchain/ledger/storage.hpp>

#include "crc32c.hpp"

namespace ledger = cexchain::ledger;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using cexchain::Status;

namespace {

/// Wraps a file system so that the process "dies" after a fixed number of
/// appends and syncs: every later operation fails, as if nothing after that
/// point ever reached the kernel.
class CrashingFileSystem final : public ledger::FileSystem {
public:
    CrashingFileSystem(ledger::FileSystem& inner, std::uint64_t budget)
        : inner_(inner), budget_(std::make_shared<std::uint64_t>(budget)) {}

    cexchain::Result<std::unique_ptr<ledger::AppendFile>> open(std::string_view name) override {
        auto file = inner_.open(name);
        if (!file) {
            return file;
        }
        return std::unique_ptr<ledger::AppendFile>(
            std::make_unique<CrashingFile>(std::move(*file), budget_));
    }
    bool exists(std::string_view name) const override { return inner_.exists(name); }

private:
    class CrashingFile final : public ledger::AppendFile {
    public:
        CrashingFile(std::unique_ptr<ledger::AppendFile> inner,
                     std::shared_ptr<std::uint64_t> budget)
            : inner_(std::move(inner)), budget_(std::move(budget)) {}
        std::uint64_t size() const override { return inner_->size(); }
        cexchain::Result<Bytes> read(std::uint64_t offset, std::size_t length) const override {
            return inner_->read(offset, length);
        }
        Status append(ByteView data) override {
            if (!spend()) {
                return cexchain::fail(Errc::invalid_argument, "crashed");
            }
            return inner_->append(data);
        }
        Status sync() override {
            if (!spend()) {
                return cexchain::fail(Errc::invalid_argument, "crashed");
            }
            return inner_->sync();
        }
        Status truncate(std::uint64_t size) override { return inner_->truncate(size); }

    private:
        bool spend() {
            if (*budget_ == 0) {
                return false;
            }
            --*budget_;
            return true;
        }
        std::unique_ptr<ledger::AppendFile> inner_;
        std::shared_ptr<std::uint64_t> budget_;
    };

    ledger::FileSystem& inner_;
    std::shared_ptr<std::uint64_t> budget_;
};

Bytes record_bytes(std::uint64_t n, ledger::SeededEntropy& entropy) {
    Bytes out(static_cast<std::size_t>(entropy.below(64)) + 1);
    entropy.fill(out);
    out[0] = static_cast<std::uint8_t>(n);
    return out;
}

} // namespace

TEST_CASE("CRC-32C matches the standard check value", "[ledger][storage]") {
    CHECK(cexchain::ledger::detail::crc32c(as_bytes("123456789")) == 0xe3069283U);
    CHECK(cexchain::ledger::detail::crc32c({}) == 0U);
}

TEST_CASE("seeded entropy is reproducible and bounded", "[ledger][environment]") {
    ledger::SeededEntropy a(42);
    ledger::SeededEntropy b(42);
    ledger::SeededEntropy c(43);
    CHECK(a.bytes<32>() == b.bytes<32>());
    CHECK(a.next() != c.next());
    for (int i = 0; i < 1000; ++i) {
        CHECK(a.below(7) < 7);
    }
    ledger::ManualClock clock(1000);
    clock.advance(5);
    CHECK(clock.now() == 1005);
}

TEST_CASE("record log appends, reads, and reopens", "[ledger][storage]") {
    ledger::MemoryFileSystem fs;
    {
        auto log = ledger::RecordLog::open(fs, "log");
        REQUIRE(log);
        CHECK(log->count() == 0);
        REQUIRE(log->append(as_bytes("first")));
        const ByteView batch[] = {as_bytes("second"), as_bytes(""), as_bytes("fourth")};
        REQUIRE(log->append(batch));
        CHECK(log->count() == 4);
        CHECK(*log->read(0) == Bytes{'f', 'i', 'r', 's', 't'});
        CHECK(log->read(2)->empty());
        CHECK(log->read(4).error().code == Errc::invalid_argument);
    }
    ledger::RecoveryReport report;
    auto reopened = ledger::RecordLog::open(fs, "log", &report);
    REQUIRE(reopened);
    CHECK(report.records == 4);
    CHECK(report.truncated_bytes == 0);
    CHECK(*reopened->read(3) == Bytes{'f', 'o', 'u', 'r', 't', 'h'});
}

TEST_CASE("crash at any point keeps every acknowledged record", "[ledger][storage][simulation]") {
    for (std::uint64_t seed = 1; seed <= 1000; ++seed) {
        INFO("seed " << seed);
        ledger::SeededEntropy entropy(seed);
        ledger::MemoryFileSystem memory;
        std::vector<Bytes> attempted;
        std::size_t acknowledged = 0;

        // Run until the simulated process dies.
        {
            CrashingFileSystem fs(memory, entropy.below(40));
            auto log = ledger::RecordLog::open(fs, "log");
            REQUIRE(log);
            for (int round = 0; round < 20; ++round) {
                const std::size_t batch_size = static_cast<std::size_t>(entropy.below(3)) + 1;
                std::vector<Bytes> batch;
                for (std::size_t i = 0; i < batch_size; ++i) {
                    batch.push_back(record_bytes(attempted.size() + i, entropy));
                }
                std::vector<ByteView> views(batch.begin(), batch.end());
                attempted.insert(attempted.end(), batch.begin(), batch.end());
                if (!log->append(views)) {
                    break;
                }
                acknowledged = attempted.size();
            }
        }
        memory.crash(entropy);

        ledger::RecoveryReport report;
        auto recovered = ledger::RecordLog::open(memory, "log", &report);
        REQUIRE(recovered); // a crash alone must never look like corruption
        REQUIRE(recovered->count() >= acknowledged);
        REQUIRE(recovered->count() <= attempted.size());
        for (std::uint64_t i = 0; i < recovered->count(); ++i) {
            REQUIRE(*recovered->read(i) == attempted[static_cast<std::size_t>(i)]);
        }
        // The recovered log keeps working.
        REQUIRE(recovered->append(as_bytes("after recovery")));
        auto again = ledger::RecordLog::open(memory, "log");
        REQUIRE(again);
        CHECK(again->count() == recovered->count());
    }
}

TEST_CASE("damage to acknowledged records refuses to open", "[ledger][storage]") {
    ledger::MemoryFileSystem fs;
    {
        auto log = ledger::RecordLog::open(fs, "log");
        REQUIRE(log);
        REQUIRE(log->append(as_bytes("one")));
        REQUIRE(log->append(as_bytes("two")));
        REQUIRE(log->append(as_bytes("three")));
    }
    // Flip a payload byte of the middle record (8-byte header + "one" = 11).
    fs.corrupt("log", 11 + 8 + 1);
    CHECK(ledger::RecordLog::open(fs, "log").error().code == Errc::malformed);

    ledger::MemoryFileSystem fs2;
    {
        auto log = ledger::RecordLog::open(fs2, "log");
        REQUIRE(log);
        REQUIRE(log->append(as_bytes("one")));
        REQUIRE(log->append(as_bytes("two")));
    }
    // Damage the first entry of the sync record file.
    fs2.corrupt("log.synced", 3);
    CHECK(ledger::RecordLog::open(fs2, "log").error().code == Errc::malformed);
}

TEST_CASE("record log works on a POSIX directory", "[ledger][storage]") {
    const auto directory = std::filesystem::temp_directory_path() /
                           ("cexchain-test-" + std::to_string(ledger::SystemClock{}.now()));
    {
        auto fs = ledger::PosixFileSystem::open_directory(directory);
        REQUIRE(fs);
        {
            auto log = ledger::RecordLog::open(*fs, "log");
            REQUIRE(log);
            REQUIRE(log->append(as_bytes("persisted")));
        }
        auto reopened = ledger::RecordLog::open(*fs, "log");
        REQUIRE(reopened);
        REQUIRE(reopened->count() == 1);
        CHECK(*reopened->read(0) == Bytes{'p', 'e', 'r', 's', 'i', 's', 't', 'e', 'd'});
        CHECK(fs->open("../escape").error().code == Errc::invalid_argument);
    }
    std::filesystem::remove_all(directory);
}
