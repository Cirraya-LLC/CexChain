// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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

/// Appends the deterministic encoding of `value` to `out`, as an item that
/// sits inside `depth` containers (arrays, maps, tags): `encode` is
/// `encode_to` at depth 0 on an empty buffer. Fails as `encode` does; `out`
/// is then left with part of the encoding.
[[nodiscard]] Status encode_to(Bytes& out, const Value& value, std::size_t depth = 0);

/// The major types of RFC 8949 §3.1.
enum class Major : std::uint8_t {
    unsigned_integer = 0,
    negative_integer = 1,
    bytes = 2,
    text = 3,
    array = 4,
    map = 5,
    tag = 6,
    simple = 7,
};

/// Appends a head in its shortest form: an integer, a string's length, an
/// array's or a map's count, or a tag. Writers of fixed shapes (the contract
/// input) write heads and splice `Encoded` items directly; they keep map keys
/// in canonical order and text valid UTF-8 themselves.
void append_head(Bytes& out, Major major, std::uint64_t argument);

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

/// Checks that `input` is exactly one data item that `decode` accepts with
/// `options`, without building it (no allocation): the same checks in the
/// same order, so the same error when it refuses.
[[nodiscard]] Status validate(ByteView input, const DecodeOptions& options = {});

/// One data item kept as its deterministic encoding: what `encode` writes and
/// `decode` accepts. It is copied into other encodings, compared, and hashed
/// as bytes; a tree is built only for a reader that needs one (`value`).
/// Equal values have equal encodings, so `==` is the values' equality.
class Encoded {
public:
    /// null.
    Encoded() noexcept;

    /// The encoding of `value`; fails as `encode` does.
    [[nodiscard]] static Result<Encoded> encode(const Value& value);
    /// `bytes`, if they are one data item that `decode` accepts with
    /// `options`; fails as `decode` does otherwise.
    [[nodiscard]] static Result<Encoded> from_bytes(ByteView bytes,
                                                    const DecodeOptions& options = {});
    /// `bytes` as they are. The caller vouches that they are one data item
    /// that `encode` wrote or `validate` accepted (say, an item sliced from an
    /// encoding `validate` accepted as a whole). Debug builds check it.
    [[nodiscard]] static Encoded trusted(ByteView bytes);

    [[nodiscard]] ByteView bytes() const noexcept {
        return bytes_.empty() ? ByteView(null_encoding) : ByteView(bytes_);
    }
    [[nodiscard]] std::size_t size() const noexcept { return bytes().size(); }
    /// The value. It never fails: the bytes are always an item that
    /// `encode` wrote or `decode` accepts (decoded here without item limits).
    [[nodiscard]] Value value() const;

    friend bool operator==(const Encoded& a, const Encoded& b) noexcept {
        return std::ranges::equal(a.bytes(), b.bytes());
    }

private:
    static constexpr std::uint8_t null_encoding[1] = {0xf6};

    explicit Encoded(Bytes bytes) noexcept : bytes_(std::move(bytes)) {}
    /// Empty for null, so that null (also what a move leaves) allocates
    /// nothing.
    Bytes bytes_;
};

/// Renders a value in RFC 8949 §8 diagnostic notation, for logs and tests.
[[nodiscard]] std::string diagnostic(const Value& value);
[[nodiscard]] std::string diagnostic(const Encoded& value);

/// Parses diagnostic notation (RFC 8949 §8), as people and programs type
/// values: JSON without floating point, plus byte strings and integer keys.
///   integers      0, 42, -1, down to -18446744073709551616
///   text strings  "a\"bé" (JSON's escapes; UTF-8)
///   byte strings  h'00ff' (hex; spaces allowed), and <<1, "a">>: the
///                 encodings of the items, in turn (RFC 8610, Appendix G.3)
///   arrays, maps  [1, 2], {1: "a", "b": [true, false, null]}
///   tags          1(1700000000)
///   comments      / a comment / (RFC 8610, Appendix G.6), and # to the end
///                 of the line (EDN), wherever white space may go
/// Whatever `diagnostic` writes parses back to the same value. The result is
/// canonical (maps in deterministic order) and encodes: duplicate map keys,
/// bignum tags, nesting deeper than max_nesting_depth, and more items than
/// DecodeOptions allows by default are refused (Errc::malformed).
[[nodiscard]] Result<Value> parse_diagnostic(std::string_view text);

/// True if `text` is valid UTF-8 (RFC 3629): no overlong forms, no surrogates,
/// no code points above U+10FFFF.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

} // namespace cexchain::cbor
