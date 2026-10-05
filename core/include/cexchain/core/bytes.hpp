// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/error.hpp>

namespace cexchain {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

/// Views the bytes of a string without copying.
[[nodiscard]] inline ByteView as_bytes(std::string_view text) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

/// Encodes bytes as lowercase hexadecimal.
[[nodiscard]] std::string to_hex(ByteView bytes);

/// Decodes hexadecimal (either case). Fails on odd length or non-hex characters.
[[nodiscard]] Result<Bytes> from_hex(std::string_view hex);

} // namespace cexchain
