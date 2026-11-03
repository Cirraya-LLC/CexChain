// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/failure.hpp>

/// What the bo program needs of files and parsing, without the chain's
/// client library (the chain's programs have its own).
namespace cexchain::cli {

[[nodiscard]] Bytes read_file(const std::filesystem::path& path);
/// Writes atomically (a temporary file beside it, then a rename);
/// `private_file` makes it owner-only.
void write_file(const std::filesystem::path& path, ByteView data, bool private_file);
[[nodiscard]] std::uint64_t parse_number(std::string_view text, std::string_view what);
/// sha256 or sm3.
[[nodiscard]] crypto::HashAlg parse_hash(std::string_view name);

} // namespace cexchain::cli
