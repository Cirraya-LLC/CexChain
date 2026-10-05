// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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

/// Overwrites `bytes` with zeros in a way the compiler cannot optimize away.
void secure_wipe(std::span<std::uint8_t> bytes) noexcept;

/// Owns secret material such as private keys and wipes it on destruction.
/// Copying is disabled so that secrets are not duplicated by accident.
class SecureBytes {
public:
    SecureBytes() noexcept = default;
    explicit SecureBytes(Bytes bytes) noexcept : bytes_(std::move(bytes)) {}
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& other) noexcept = default;
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            secure_wipe(bytes_);
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }
    ~SecureBytes() { secure_wipe(bytes_); }

    [[nodiscard]] ByteView view() const noexcept { return bytes_; }
    [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
    [[nodiscard]] bool empty() const noexcept { return bytes_.empty(); }

private:
    Bytes bytes_;
};

} // namespace cexchain
