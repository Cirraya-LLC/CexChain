// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cexchain/core/bytes.hpp>

#include <optional>

namespace cexchain {

namespace {

constexpr std::string_view digits = "0123456789abcdef";

constexpr std::optional<std::uint8_t> nibble(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return static_cast<std::uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<std::uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<std::uint8_t>(c - 'A' + 10);
    }
    return std::nullopt;
}

} // namespace

std::string to_hex(ByteView bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

Result<Bytes> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return fail(Errc::malformed, "hex string has odd length");
    }
    Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const auto hi = nibble(hex[i]);
        const auto lo = nibble(hex[i + 1]);
        if (!hi || !lo) {
            return fail(Errc::malformed, "hex string contains a non-hex character");
        }
        out.push_back(static_cast<std::uint8_t>((*hi << 4) | *lo));
    }
    return out;
}

} // namespace cexchain
