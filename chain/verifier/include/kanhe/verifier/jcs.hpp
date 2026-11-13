// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>

#include <kanhe/core/error.hpp>
#include <kanhe/verifier/report.hpp>

/// JSON Canonicalization (RFC 8785, JCS) for the JSON credentials are made of
/// (credentials.hpp). Portable C++23, like core.
namespace kanhe::verifier {

/// The largest integer JCS writes exactly (2^53 - 1).
inline constexpr std::int64_t max_json_integer = 9'007'199'254'740'991;

/// The JCS serialization of `value`: members sorted by their names' UTF-16
/// code units, no whitespace, the shortest string escapes. Fails on a
/// number that is not an integer of at most 2^53 - 1 in magnitude (credentials
/// carry no others) and on text that is not UTF-8.
[[nodiscard]] Result<std::string> jcs(const Json& value);

/// Parses `text` as JSON and requires it to be the JCS serialization of what
/// it parses to: so no repeated member name, no whitespace, and nothing
/// written two ways.
[[nodiscard]] Result<Json> parse_jcs(std::string_view text);

} // namespace kanhe::verifier
