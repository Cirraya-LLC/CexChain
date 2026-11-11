// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A console's sealed backup comes from a folder anyone with access to it
// (a synced folder, a shared disk) may have changed: reading what it says
// of itself, and opening it with a recovery code, must refuse anything
// that is not one, never crash, and never open with another code than the
// one it was sealed for. The backup paths a restore writes are an
// allow-list: no path it accepts leaves the ledger's directory.

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

#include <kanhe/client/backups.hpp>
#include <kanhe/console/backups.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const kanhe::ByteView bytes(data, size);
    try {
        static_cast<void>(kanhe::console::sealed_backup_info(bytes));
        static_cast<void>(
            kanhe::console::open_sealed_backup(bytes, "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"));
    } catch (const std::runtime_error&) {
        // Refused: not a sealed backup, or not that code's.
    }
    const std::string_view path(reinterpret_cast<const char*>(data), size);
    if (kanhe::client::backup_path_allowed(path)) {
        if (path.empty() || path.front() == '/' || path.find("..") != std::string_view::npos ||
            path.find('\\') != std::string_view::npos ||
            path.find('\0') != std::string_view::npos) {
            __builtin_trap();
        }
    }
    return 0;
}
