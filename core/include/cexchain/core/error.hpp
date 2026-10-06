// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <expected>
#include <string_view>

namespace cexchain {

/// Error categories shared by every CexChain module.
enum class Errc : std::uint8_t {
    invalid_argument = 1, ///< A caller-supplied argument is out of range or inconsistent.
    truncated,            ///< Input ended before a complete item was read.
    malformed,            ///< Input is structurally invalid.
    non_canonical,        ///< Input is well-formed but not in its required deterministic form.
    unsupported,          ///< Input is valid but outside the CexChain profile.
    limit_exceeded,       ///< A size or nesting limit was exceeded.
    verification_failed,  ///< A signature, proof, or digest did not verify.
    crypto_failure,       ///< The cryptographic backend reported an internal failure.
    rejected,             ///< The ledger's rules do not allow this action.
    not_found,            ///< A referenced object does not exist.
};

/// An error value. `detail` must refer to storage with static duration
/// (typically a string literal) so that errors never allocate.
struct Error {
    Errc code;
    std::string_view detail;

    friend bool operator==(const Error&, const Error&) = default;
};

template <class T>
using Result = std::expected<T, Error>;

/// Result of an operation that produces no value.
using Status = std::expected<void, Error>;

[[nodiscard]] constexpr std::unexpected<Error> fail(Errc code, std::string_view detail) noexcept {
    return std::unexpected<Error>(Error{code, detail});
}

[[nodiscard]] std::string_view to_string(Errc code) noexcept;

} // namespace cexchain
