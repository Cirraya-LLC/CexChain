// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A backup file may be damaged or forged. Restoring it must never crash, and
// files are handed over only from a backup that verified.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>

#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/backup.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    std::istringstream in(std::string(reinterpret_cast<const char*>(data), size));
    cexchain::ledger::MemoryFileSystem fs;
    cexchain::ledger::ManualClock clock(1'791'244'800'000);
    bool handed_over = false;
    const auto restored = cexchain::ledger::restore_backup(
        in, fs, clock, provider, [&](const cexchain::ledger::BackupFile&) -> cexchain::Status {
            handed_over = true;
            return {};
        });
    if (!restored && handed_over) {
        std::abort();
    }
    return 0;
}
