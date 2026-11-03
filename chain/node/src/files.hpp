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
/// directory (unless `sync_parent` is false: the caller syncs it once
/// for several files). `private_file` makes it owner-only.
[[nodiscard]] Status write_file(const std::filesystem::path& path, ByteView data, bool private_file,
                                bool sync_parent = true);

/// Syncs a directory, so that the files renamed into it are durable.
void sync_directory(const std::filesystem::path& directory);

} // namespace cexchain::node::detail
