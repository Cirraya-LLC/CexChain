// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// JSON for executors and connectors (6b): integers only, bounded nesting,
/// and the CBOR it maps to.
namespace cexchain::node::detail {

using json = nlohmann::json;

/// Parses one JSON text: at most cbor::max_nesting_depth nested arrays and
/// objects, and no number with a fraction or exponent (nor one beyond 64
/// bits). nullopt otherwise.
[[nodiscard]] std::optional<json> parse_integral_json(std::string_view text);

/// CBOR as JSON: maps with text keys, byte strings as hex text, integers
/// within 64 bits. nullopt for tags and other map keys.
[[nodiscard]] std::optional<json> cbor_json(const cbor::Value& value, std::size_t depth = 0);

/// JSON as CBOR; fails on floating-point numbers.
[[nodiscard]] Result<cbor::Value> json_cbor(const json& value, std::size_t depth = 0);

/// A full id in lowercase or uppercase hex.
[[nodiscard]] std::optional<protocol::Id> id_from_hex(std::string_view hex);

} // namespace cexchain::node::detail
