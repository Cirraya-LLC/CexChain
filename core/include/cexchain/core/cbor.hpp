// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>

/// Deterministic CBOR (RFC 8949) restricted to the CexChain profile.
///
/// Encoding always produces the Core Deterministic Encoding of RFC 8949
/// §4.2.1: shortest-form integers and lengths, definite lengths only, and map
/// keys sorted by the bytewise lexicographic order of their encodings.
///
/// Decoding is strict. Input is accepted only if it is exactly what `encode`
/// would produce for the decoded value, so `encode(decode(x)) == x` holds for
/// every accepted input. In addition, the profile excludes:
///   - floating-point numbers (non-deterministic arithmetic has no place in
///     hashed or signed data),
///   - simple values other than false, true, and null,
///   - bignums (tags 2 and 3), which have alternative encodings,
///   - duplicate map keys and invalid UTF-8 in text strings.
namespace cexchain::cbor {

enum class Type : std::uint8_t {
    unsigned_integer,
    negative_integer,
    bytes,
    text,
    array,
    map,
    tag,
    boolean,
    null,
};

class Value;
struct MapEntry;
struct Tagged;

using Array = std::vector<Value>;

/// Map entries. Maps built in memory keep insertion order; `encode` sorts them.
/// Decoded maps are always in canonical order.
using Map = std::vector<MapEntry>;

/// A negative integer as CBOR represents it: the value is -1 - n. This covers
/// the full CBOR range down to -2^64.
struct NegativeInt {
    std::uint64_t n;

    friend bool operator==(const NegativeInt&, const NegativeInt&) = default;
};

namespace detail {

/// Owning pointer with value semantics. It lets Value hold a Tagged (which
/// itself contains a Value) while Tagged is still an incomplete type.
template <class T>
class Box {
public:
    explicit Box(T value) : ptr_(std::make_unique<T>(std::move(value))) {}
    Box(const Box& other) : ptr_(std::make_unique<T>(*other.ptr_)) {}
    Box(Box&&) noexcept = default;
    Box& operator=(const Box& other) {
        if (this != &other) {
            ptr_ = std::make_unique<T>(*other.ptr_);
        }
        return *this;
    }
    Box& operator=(Box&&) noexcept = default;
    ~Box() = default;

    const T& operator*() const noexcept { return *ptr_; }
    const T* operator->() const noexcept { return ptr_.get(); }

    friend bool operator==(const Box& a, const Box& b) { return *a.ptr_ == *b.ptr_; }

private:
    std::unique_ptr<T> ptr_;
};

} // namespace detail

/// A CBOR data item.
class Value {
public:
    /// Constructs null.
    Value() noexcept = default;
    Value(const Value&) = default;
    Value& operator=(const Value&) = default;
    /// Moving leaves `other` null.
    Value(Value&& other) noexcept;
    Value& operator=(Value&& other) noexcept;
    ~Value() = default;

    [[nodiscard]] static Value unsigned_integer(std::uint64_t value) noexcept;
    [[nodiscard]] static Value integer(std::int64_t value) noexcept;
    /// Constructs the negative integer -1 - n.
    [[nodiscard]] static Value negative(std::uint64_t n) noexcept;
    [[nodiscard]] static Value bytes(ByteView value);
    [[nodiscard]] static Value bytes(Bytes value) noexcept;
    [[nodiscard]] static Value text(std::string value) noexcept;
    [[nodiscard]] static Value array(Array items) noexcept;
    [[nodiscard]] static Value map(Map entries) noexcept;
    [[nodiscard]] static Value tagged(std::uint64_t tag, Value item);
    [[nodiscard]] static Value boolean(bool value) noexcept;
    [[nodiscard]] static Value null() noexcept;

    [[nodiscard]] Type type() const noexcept;

    [[nodiscard]] bool is_null() const noexcept;
    /// The integer value if this is an integer that fits in int64_t.
    [[nodiscard]] std::optional<std::int64_t> as_int64() const noexcept;
    /// The value if this is a non-negative integer.
    [[nodiscard]] std::optional<std::uint64_t> as_uint64() const noexcept;
    [[nodiscard]] std::optional<bool> as_bool() const noexcept;
    [[nodiscard]] const Bytes* as_bytes() const noexcept;
    [[nodiscard]] const std::string* as_text() const noexcept;
    [[nodiscard]] const Array* as_array() const noexcept;
    [[nodiscard]] const Map* as_map() const noexcept;
    [[nodiscard]] const Tagged* as_tagged() const noexcept;
    /// The raw (-1 - n) form if this is a negative integer.
    [[nodiscard]] std::optional<NegativeInt> as_negative() const noexcept;

    /// Looks up a map entry by key. Returns nullptr if this is not a map or the
    /// key is absent.
    [[nodiscard]] const Value* find(const Value& key) const noexcept;
    [[nodiscard]] const Value* find(std::int64_t key) const noexcept;
    [[nodiscard]] const Value* find(std::string_view key) const noexcept;

    /// Structural equality. Map entries are compared in order.
    friend bool operator==(const Value& a, const Value& b);

private:
    struct Null {
        friend bool operator==(Null, Null) noexcept { return true; }
    };

    using Storage = std::variant<Null, std::uint64_t, NegativeInt, Bytes, std::string, Array, Map,
                                 detail::Box<Tagged>, bool>;

    template <class T>
    explicit Value(std::in_place_type_t<T> type, T&& value)
        : storage_(type, std::forward<T>(value)) {}

    Storage storage_;
};

struct MapEntry {
    Value key;
    Value value;

    friend bool operator==(const MapEntry&, const MapEntry&) = default;
};

struct Tagged {
    std::uint64_t tag;
    Value item;

    friend bool operator==(const Tagged&, const Tagged&) = default;
};

/// Hard limit on the nesting of arrays, maps, and tags, for both encoding and
/// decoding. It bounds recursion depth and keeps encode and decode symmetric.
inline constexpr std::size_t max_nesting_depth = 64;

/// Encodes a value in deterministic form. Fails if a map has duplicate keys,
/// a text string is not valid UTF-8, a bignum tag is used, or nesting exceeds
/// `max_nesting_depth`.
[[nodiscard]] Result<Bytes> encode(const Value& value);

struct DecodeOptions {
    /// Maximum nesting of arrays, maps, and tags. Values above
    /// `max_nesting_depth` are treated as `max_nesting_depth`.
    std::size_t max_depth = 32;
    /// Maximum number of data items (every integer, string, container, tag,
    /// and simple value counts as one). Each decoded item costs about 40 bytes
    /// of memory however small its encoding, so this bounds memory use on
    /// hostile input. The default allows about 5 MB.
    std::size_t max_items = std::size_t{1} << 17;
};

/// Decodes exactly one data item spanning the whole input.
[[nodiscard]] Result<Value> decode(ByteView input, const DecodeOptions& options = {});

/// Renders a value in RFC 8949 §8 diagnostic notation, for logs and tests.
[[nodiscard]] std::string diagnostic(const Value& value);

/// Parses diagnostic notation (RFC 8949 §8), as people and programs type
/// values: JSON without floating point, plus byte strings and integer keys.
///   integers      0, 42, -1, down to -18446744073709551616
///   text strings  "a\"bé" (JSON's escapes; UTF-8)
///   byte strings  h'00ff' (hex; spaces allowed), and <<1, "a">>: the
///                 encodings of the items, in turn (RFC 8610, Appendix G.3)
///   arrays, maps  [1, 2], {1: "a", "b": [true, false, null]}
///   tags          1(1700000000)
/// Whatever `diagnostic` writes parses back to the same value. The result is
/// canonical (maps in deterministic order) and encodes: duplicate map keys,
/// bignum tags, nesting deeper than max_nesting_depth, and more items than
/// DecodeOptions allows by default are refused (Errc::malformed).
[[nodiscard]] Result<Value> parse_diagnostic(std::string_view text);

/// True if `text` is valid UTF-8 (RFC 3629): no overlong forms, no surrogates,
/// no code points above U+10FFFF.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

} // namespace cexchain::cbor
