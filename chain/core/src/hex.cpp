// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <optional>

#include <cexchain/core/bytes.hpp>

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

namespace {

constexpr std::string_view base64url_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int base64url_value(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '-') {
        return 62;
    }
    if (c == '_') {
        return 63;
    }
    return -1;
}

} // namespace

std::string to_base64url(ByteView bytes) {
    std::string out;
    out.reserve((bytes.size() * 4 + 2) / 3);
    std::size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        const std::uint32_t n =
            (std::uint32_t{bytes[i]} << 16U) | (std::uint32_t{bytes[i + 1]} << 8U) | bytes[i + 2];
        out.push_back(base64url_alphabet[(n >> 18U) & 63U]);
        out.push_back(base64url_alphabet[(n >> 12U) & 63U]);
        out.push_back(base64url_alphabet[(n >> 6U) & 63U]);
        out.push_back(base64url_alphabet[n & 63U]);
    }
    if (const std::size_t rest = bytes.size() - i; rest > 0) {
        std::uint32_t n = std::uint32_t{bytes[i]} << 16U;
        if (rest == 2) {
            n |= std::uint32_t{bytes[i + 1]} << 8U;
        }
        out.push_back(base64url_alphabet[(n >> 18U) & 63U]);
        out.push_back(base64url_alphabet[(n >> 12U) & 63U]);
        if (rest == 2) {
            out.push_back(base64url_alphabet[(n >> 6U) & 63U]);
        }
    }
    return out;
}

Result<Bytes> from_base64url(std::string_view text) {
    if (text.size() % 4 == 1) {
        return fail(Errc::malformed, "base64url text has an impossible length");
    }
    Bytes out;
    out.reserve(text.size() * 3 / 4);
    std::uint32_t buffer = 0;
    unsigned bits = 0;
    for (const char c : text) {
        const int value = base64url_value(c);
        if (value < 0) {
            return fail(Errc::malformed, "invalid base64url character");
        }
        buffer = (buffer << 6U) | static_cast<std::uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFFU));
        }
    }
    if ((buffer & ((1U << bits) - 1U)) != 0) {
        return fail(Errc::non_canonical, "base64url text has nonzero trailing bits");
    }
    return out;
}

} // namespace cexchain
