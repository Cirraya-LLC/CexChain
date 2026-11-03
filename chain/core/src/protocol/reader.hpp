// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

// Internal error-propagation helpers for the protocol decoders, which check
// dozens of fields each. Not part of the public API.
#define CEXCHAIN_CONCAT_INNER(a, b) a##b
#define CEXCHAIN_CONCAT(a, b) CEXCHAIN_CONCAT_INNER(a, b)

/// Evaluates `expr` (a Result<T>); returns its error from the enclosing
/// function, or moves its value into `decl`.
#define CEXCHAIN_TRY(decl, expr)                                                                   \
    auto CEXCHAIN_CONCAT(cexchain_try_, __LINE__) = (expr);                                        \
    if (!CEXCHAIN_CONCAT(cexchain_try_, __LINE__)) {                                               \
        return std::unexpected(CEXCHAIN_CONCAT(cexchain_try_, __LINE__).error());                  \
    }                                                                                              \
    decl = std::move(*CEXCHAIN_CONCAT(cexchain_try_, __LINE__))

/// Evaluates `expr` (a Status) and returns its error from the enclosing
/// function.
#define CEXCHAIN_CHECK(expr)                                                                       \
    if (auto CEXCHAIN_CONCAT(cexchain_check_, __LINE__) = (expr);                                  \
        !CEXCHAIN_CONCAT(cexchain_check_, __LINE__)) {                                             \
        return std::unexpected(CEXCHAIN_CONCAT(cexchain_check_, __LINE__).error());                \
    }

namespace cexchain::protocol::detail {

/// Reads an integer-keyed protocol map strictly: every accessor marks its key
/// as seen, and `finish` fails if the map holds any key nobody asked for.
class MapReader {
public:
    /// Fails unless `value` is a map. The map must outlive the reader.
    [[nodiscard]] static Result<MapReader> open(const cbor::Value& value);

    /// The value at `key`, or nullptr if absent.
    [[nodiscard]] const cbor::Value* get(std::int64_t key);
    [[nodiscard]] Result<const cbor::Value*> need(std::int64_t key);

    [[nodiscard]] Result<std::uint64_t> need_uint(std::int64_t key);
    [[nodiscard]] Result<std::int64_t> need_int(std::int64_t key);
    [[nodiscard]] Result<std::string> need_text(std::int64_t key);
    [[nodiscard]] Result<Bytes> need_bytes(std::int64_t key);
    [[nodiscard]] Result<Id> need_id(std::int64_t key);

    [[nodiscard]] Result<std::optional<std::uint64_t>> opt_uint(std::int64_t key);
    [[nodiscard]] Result<std::optional<std::string>> opt_text(std::int64_t key);
    [[nodiscard]] Result<std::optional<Bytes>> opt_bytes(std::int64_t key);
    [[nodiscard]] Result<std::optional<Id>> opt_id(std::int64_t key);
    [[nodiscard]] Result<std::optional<bool>> opt_bool(std::int64_t key);

    /// Fails if any key was not read, or if any key is not an integer.
    [[nodiscard]] Status finish() const;

private:
    explicit MapReader(const cbor::Map& map) : map_(&map), seen_(map.size(), false) {}

    const cbor::Map* map_;
    std::vector<bool> seen_;
};

/// Text value or a malformed error.
[[nodiscard]] Result<std::string> as_text(const cbor::Value& value);
/// Byte string value or a malformed error.
[[nodiscard]] Result<Bytes> as_bytes_value(const cbor::Value& value);
/// Unsigned integer value or a malformed error.
[[nodiscard]] Result<std::uint64_t> as_uint(const cbor::Value& value);
/// Array value or a malformed error.
[[nodiscard]] Result<const cbor::Array*> as_array(const cbor::Value& value);

/// Shorthand for building integer-keyed maps.
[[nodiscard]] inline cbor::MapEntry entry(std::int64_t key, cbor::Value value) {
    return {cbor::Value::integer(key), std::move(value)};
}

} // namespace cexchain::protocol::detail
