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
#include "support/crashing_fs.hpp"

namespace ledger = cexchain::ledger;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using cexchain::Status;

namespace {

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
            cexchain::test::CrashingFileSystem fs(memory, entropy.below(40));
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

TEST_CASE("a whole record never acknowledged is cut off, and refresh agrees", "[ledger][storage]") {
    ledger::MemoryFileSystem memory;
    {
        auto log = ledger::RecordLog::open(memory, "log");
        REQUIRE(log);
        REQUIRE(log->append(as_bytes("acknowledged")));
    }
    // A writer that died after syncing a record but before recording the
    // sync: the record is whole, and was never acknowledged.
    {
        auto raw = memory.open("log");
        REQUIRE(raw);
        const Bytes payload{'l', 'o', 's', 't'};
        const std::uint32_t crc = cexchain::ledger::detail::crc32c(payload);
        Bytes frame{0,
                    0,
                    0,
                    4,
                    static_cast<std::uint8_t>(crc >> 24),
                    static_cast<std::uint8_t>(crc >> 16),
                    static_cast<std::uint8_t>(crc >> 8),
                    static_cast<std::uint8_t>(crc)};
        frame.insert(frame.end(), payload.begin(), payload.end());
        REQUIRE((*raw)->append(frame));
        REQUIRE((*raw)->sync());
    }
    ledger::RecoveryReport report;
    auto reopened = ledger::RecordLog::open(memory, "log", &report);
    REQUIRE(reopened);
    CHECK(reopened->count() == 1);
    CHECK(report.truncated_bytes == 12);
    // Once, open kept such a record and refresh(recover) called it a shrunk
    // log: a server then refused every write until it was rebuilt.
    REQUIRE(reopened->refresh(memory, "log", true));
    CHECK(reopened->count() == 1);
    REQUIRE(reopened->append(as_bytes("next")));
    CHECK(*reopened->read(1) == Bytes{'n', 'e', 'x', 't'});
    auto again = ledger::RecordLog::open(memory, "log");
    REQUIRE(again);
    CHECK(again->count() == 2);
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

TEST_CASE("POSIX files lend mapped views that see later appends", "[ledger][storage]") {
    const auto directory = std::filesystem::temp_directory_path() /
                           ("cexchain-view-test-" + std::to_string(ledger::SystemClock{}.now()));
    {
        auto fs = ledger::PosixFileSystem::open_directory(directory);
        REQUIRE(fs);
        auto file = fs->open("data");
        REQUIRE(file);
        REQUIRE((*file)->append(as_bytes("first")));
        // Mapping the segment now: the file is 5 bytes long.
        const auto first = (*file)->view(0, 5);
        REQUIRE(first);
        CHECK(Bytes(first->begin(), first->end()) == Bytes{'f', 'i', 'r', 's', 't'});
        // The mapping grows with the file: no remapping, no copy.
        Bytes more(10000, 0x5a);
        REQUIRE((*file)->append(more));
        const auto later = (*file)->view(5, more.size());
        REQUIRE(later);
        CHECK(Bytes(later->begin(), later->end()) == more);
        CHECK(first->data() + 5 == later->data());
        // Nothing past what this handle knows of.
        CHECK(!(*file)->view(5, more.size() + 1));
        CHECK(!(*file)->view((*file)->size() + 1, 0));
        CHECK((*file)->view((*file)->size(), 0));

        // The record log reads through views, and still checks every CRC.
        auto log = ledger::RecordLog::open(*fs, "log");
        REQUIRE(log);
        ledger::SeededEntropy entropy(9);
        std::vector<Bytes> written;
        for (std::uint64_t i = 0; i < 200; ++i) {
            written.push_back(record_bytes(i, entropy));
            REQUIRE(log->append(written.back()));
            Bytes scratch;
            const auto view = log->view(i, scratch);
            REQUIRE(view);
            CHECK(scratch.empty()); // lent, not copied
            CHECK(Bytes(view->begin(), view->end()) == written.back());
        }
        for (std::uint64_t i = 0; i < written.size(); ++i) {
            CHECK(*log->read(i) == written[i]);
        }
    }
    std::filesystem::remove_all(directory);
}

TEST_CASE("only one process at a time holds a ledger directory", "[ledger][storage]") {
    const auto directory = std::filesystem::temp_directory_path() /
                           ("cexchain-lock-" + std::to_string(ledger::SystemClock{}.now()));
    std::filesystem::create_directories(directory);
    {
        auto first = ledger::DirectoryLock::acquire(directory);
        REQUIRE(first);
        // flock locks belong to open file descriptions, so a second
        // acquisition, even in the same process, must wait and then fail.
        CHECK(ledger::DirectoryLock::acquire(directory, 100).error().code == Errc::rejected);
        auto moved = std::move(*first);
        CHECK(ledger::DirectoryLock::acquire(directory, 100).error().code == Errc::rejected);
    }
    CHECK(ledger::DirectoryLock::acquire(directory, 100));
    std::filesystem::remove_all(directory);
}
