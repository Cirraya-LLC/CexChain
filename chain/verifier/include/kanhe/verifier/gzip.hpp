// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/error.hpp>

/// GZIP (RFC 1952) over DEFLATE (RFC 1951), as a status list's bitstring
/// travels (credentials.hpp). Portable C++23, like core.
namespace kanhe::verifier {

/// One GZIP member: no name, no time, DEFLATE with the fixed codes, each run
/// of a repeated byte as matches at distance 1. Deterministic, and small for
/// what it is made for: a mostly empty bitstring.
[[nodiscard]] Bytes gzip_compress(ByteView data);

/// Decompresses exactly one GZIP member, any valid DEFLATE stream (stored,
/// fixed, and dynamic blocks), checking its CRC-32 and size. Fails on
/// trailing bytes, on reserved flags, and once the output would pass
/// `max_output` bytes.
[[nodiscard]] Result<Bytes> gzip_decompress(ByteView data, std::size_t max_output);

/// The CRC-32 GZIP uses (ISO 3309, reflected, 0xEDB88320).
[[nodiscard]] std::uint32_t crc32(ByteView data) noexcept;

} // namespace kanhe::verifier
