// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>

namespace cexchain::node::detail {

/// The whole file; Errc::not_found if it does not exist.
[[nodiscard]] Result<Bytes> read_file(const std::filesystem::path& path);

/// Writes atomically: a temporary file, fsync, rename, then fsync of the
/// directory. `private_file` makes it owner-only.
[[nodiscard]] Status write_file(const std::filesystem::path& path, ByteView data,
                                bool private_file);

} // namespace cexchain::node::detail
