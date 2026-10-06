// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <sstream>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/ledger/backup.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

std::string backup_of(World& w, const std::vector<ledger::BackupFile>& files) {
    std::ostringstream out;
    const auto summary = ledger::write_backup(w.ledger(), provider(), files, t0 + day, out);
    REQUIRE(summary);
    CHECK(summary->entries == w.ledger().size());
    return out.str();
}

cexchain::Result<ledger::BackupSummary> restore(const std::string& backup,
                                                ledger::MemoryFileSystem& fs,
                                                std::vector<ledger::BackupFile>* files = nullptr) {
    std::istringstream in(backup);
    ledger::ManualClock clock(t0 + day);
    return ledger::restore_backup(in, fs, clock, provider(),
                                  [&](const ledger::BackupFile& f) -> cexchain::Status {
                                      if (files != nullptr) {
                                          files->push_back(f);
                                      }
                                      return {};
                                  });
}

} // namespace

TEST_CASE("a backup restores to the same ledger", "[ledger][backup]") {
    World w;
    Cast c = build_cast(w);
    const auto record = w.ok(c.agent, agent_record(w, c, certificate));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    w.ok(c.bob,
         w.statement(c.bob_id, c.bob_delegation, protocol::RecordEndorseBody{record, "inspector"}));
    const std::vector<ledger::BackupFile> files{{"vault/vault.pub", Bytes{1, 2, 3}},
                                                {"api-tokens", Bytes{'{', '}'}}};
    const std::string backup = backup_of(w, files);

    ledger::MemoryFileSystem fs;
    std::vector<ledger::BackupFile> restored_files;
    const auto summary = restore(backup, fs, &restored_files);
    REQUIRE(summary);
    CHECK(summary->ledger_id == w.ledger().id());
    CHECK(summary->created == t0 + day);
    CHECK(summary->checkpoints == 1);
    REQUIRE(restored_files.size() == 2);
    CHECK(restored_files[0].path == "vault/vault.pub");
    CHECK(restored_files[0].content == Bytes{1, 2, 3});

    ledger::ManualClock clock(t0 + day);
    auto reopened = ledger::Ledger::open(fs, clock, provider());
    REQUIRE(reopened);
    CHECK(*reopened->root(reopened->size()) == *w.ledger().root(w.ledger().size()));
    CHECK(reopened->state_proof(record));
    CHECK(reopened->audit());
}

TEST_CASE("a damaged backup is refused", "[ledger][backup][security]") {
    World w;
    Cast c = build_cast(w);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    const std::string backup = backup_of(w, {{"vault/vault.pub", Bytes(40, 7)}});

    SECTION("truncated") {
        for (const std::size_t cut : {std::size_t{3}, backup.size() / 2, backup.size() - 1}) {
            ledger::MemoryFileSystem fs;
            CHECK_FALSE(restore(backup.substr(0, cut), fs));
        }
    }
    SECTION("a file altered") {
        std::string altered = backup;
        const std::size_t at = altered.find(std::string(40, '\x07'));
        REQUIRE(at != std::string::npos);
        altered[at + 5] ^= 1;
        ledger::MemoryFileSystem fs;
        std::vector<ledger::BackupFile> files;
        const auto restored = restore(altered, fs, &files);
        REQUIRE_FALSE(restored);
        CHECK(restored.error().code == Errc::verification_failed);
        CHECK(files.empty()); // nothing handed over before the chain matched
    }
    SECTION("an entry altered") {
        std::string altered = backup;
        altered[altered.size() / 3] ^= 1;
        ledger::MemoryFileSystem fs;
        CHECK_FALSE(restore(altered, fs));
    }
    SECTION("something else") {
        ledger::MemoryFileSystem fs;
        CHECK(restore(std::string("\0\0\0\x01\xa0", 5), fs).error().code == Errc::malformed);
        CHECK(restore(backup + "x", fs).error().code != Errc{});
    }
}
