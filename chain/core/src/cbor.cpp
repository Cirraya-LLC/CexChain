// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <compare>
#include <cstdlib>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>

#include <cexchain/core/cbor.hpp>

namespace cexchain::cbor {

namespace {

enum MajorCode : std::uint8_t {
    major_unsigned = 0,
    major_negative = 1,
    major_bytes = 2,
    major_text = 3,
    major_array = 4,
    major_map = 5,
    major_tag = 6,
    major_simple = 7,
};

constexpr std::uint8_t simple_false = 20;
constexpr std::uint8_t simple_true = 21;
constexpr std::uint8_t simple_null = 22;

constexpr std::uint64_t tag_positive_bignum = 2;
constexpr std::uint64_t tag_negative_bignum = 3;

/// Upper bound on capacity reserved from an untrusted item count. Larger
/// containers grow as items actually arrive, so memory stays proportional to
/// the input rather than to claimed counts at every nesting level.
constexpr std::size_t max_reserved_items = 256;

bool is_bignum_tag(std::uint64_t tag) noexcept {
    return tag == tag_positive_bignum || tag == tag_negative_bignum;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

void write_head(Bytes& out, std::uint8_t major, std::uint64_t argument) {
    const auto initial = static_cast<std::uint8_t>(major << 5);
    if (argument < 24) {
        out.push_back(static_cast<std::uint8_t>(initial | argument));
        return;
    }
    int width = 0;
    std::uint8_t info = 0;
    if (argument <= 0xff) {
        width = 1;
        info = 24;
    } else if (argument <= 0xffff) {
        width = 2;
        info = 25;
    } else if (argument <= 0xffff'ffff) {
        width = 4;
        info = 26;
    } else {
        width = 8;
        info = 27;
    }
    out.push_back(static_cast<std::uint8_t>(initial | info));
    for (int i = width - 1; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>(argument >> (8 * i)));
    }
}

void append(Bytes& out, ByteView bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

Status encode_into(Bytes& out, const Value& value, std::size_t depth);

Status encode_map(Bytes& out, const Map& map, std::size_t depth) {
    struct EncodedEntry {
        Bytes key;
        Bytes value;
    };
    std::vector<EncodedEntry> entries;
    entries.reserve(map.size());
    for (const MapEntry& entry : map) {
        EncodedEntry encoded;
        if (auto s = encode_into(encoded.key, entry.key, depth + 1); !s) {
            return s;
        }
        if (auto s = encode_into(encoded.value, entry.value, depth + 1); !s) {
            return s;
        }
        entries.push_back(std::move(encoded));
    }
    std::ranges::sort(entries, std::ranges::less{}, &EncodedEntry::key);
    const auto duplicate =
        std::ranges::adjacent_find(entries, std::ranges::equal_to{}, &EncodedEntry::key);
    if (duplicate != entries.end()) {
        return fail(Errc::invalid_argument, "map has duplicate keys");
    }
    write_head(out, major_map, entries.size());
    for (const EncodedEntry& entry : entries) {
        append(out, entry.key);
        append(out, entry.value);
    }
    return {};
}

bool is_container(Type type) noexcept {
    return type == Type::array || type == Type::map || type == Type::tag;
}

Status encode_into(Bytes& out, const Value& value, std::size_t depth) {
    // Mirrors the decoder: a container at `depth` holds items at `depth + 1`.
    if (is_container(value.type()) && depth + 1 > max_nesting_depth) {
        return fail(Errc::limit_exceeded, "value nesting exceeds the limit");
    }
    switch (value.type()) {
    case Type::unsigned_integer:
        write_head(out, major_unsigned, *value.as_uint64());
        return {};
    case Type::negative_integer:
        write_head(out, major_negative, value.as_negative()->n);
        return {};
    case Type::bytes: {
        const Bytes& bytes = *value.as_bytes();
        write_head(out, major_bytes, bytes.size());
        append(out, bytes);
        return {};
    }
    case Type::text: {
        const std::string& text = *value.as_text();
        if (!is_valid_utf8(text)) {
            return fail(Errc::invalid_argument, "text string is not valid UTF-8");
        }
        write_head(out, major_text, text.size());
        append(out, as_bytes(text));
        return {};
    }
    case Type::array: {
        const Array& items = *value.as_array();
        write_head(out, major_array, items.size());
        for (const Value& item : items) {
            if (auto s = encode_into(out, item, depth + 1); !s) {
                return s;
            }
        }
        return {};
    }
    case Type::map:
        return encode_map(out, *value.as_map(), depth);
    case Type::tag: {
        const Tagged& tagged = *value.as_tagged();
        if (is_bignum_tag(tagged.tag)) {
            return fail(Errc::unsupported, "bignums are not allowed");
        }
        write_head(out, major_tag, tagged.tag);
        return encode_into(out, tagged.item, depth + 1);
    }
    case Type::boolean:
        write_head(out, major_simple, *value.as_bool() ? simple_true : simple_false);
        return {};
    case Type::null:
        write_head(out, major_simple, simple_null);
        return {};
    }
    return fail(Errc::invalid_argument, "unknown value type");
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

struct Head {
    std::uint8_t major;
    std::uint8_t info;
    std::uint64_t argument;
};

/// What the checking decoder makes of an item: nothing.
struct Checked {};

/// Decodes one item strictly. `Build` makes the Value; without it the same
/// checks run in the same order and nothing is allocated (`validate`), so
/// both accept and refuse exactly the same inputs, with the same errors.
template <bool Build>
class Decoder {
public:
    using Item = std::conditional_t<Build, Value, Checked>;

    Decoder(ByteView input, const DecodeOptions& options) : input_(input), options_(options) {}

    Result<Item> decode_top_level() {
        auto value = decode_item(0);
        if (!value) {
            return value;
        }
        if (pos_ != input_.size()) {
            return fail(Errc::malformed, "trailing bytes after the data item");
        }
        return value;
    }

private:
    [[nodiscard]] std::size_t remaining() const noexcept { return input_.size() - pos_; }

    Result<Head> read_head() {
        if (remaining() == 0) {
            return fail(Errc::truncated, "unexpected end of input");
        }
        const std::uint8_t initial = input_[pos_++];
        const auto major = static_cast<std::uint8_t>(initial >> 5);
        const auto info = static_cast<std::uint8_t>(initial & 0x1f);

        if (info < 24) {
            return Head{major, info, info};
        }
        if (info == 31) {
            if (major == major_simple) {
                return fail(Errc::malformed, "unexpected break stop code");
            }
            if (major >= major_bytes && major <= major_map) {
                return fail(Errc::non_canonical, "indefinite-length items are not allowed");
            }
            return fail(Errc::malformed, "indefinite length is invalid for this major type");
        }
        if (info > 27) {
            return fail(Errc::malformed, "reserved additional information value");
        }

        const std::size_t width = std::size_t{1} << (info - 24);
        if (remaining() < width) {
            return fail(Errc::truncated, "unexpected end of input in item head");
        }
        std::uint64_t argument = 0;
        for (std::size_t i = 0; i < width; ++i) {
            argument = (argument << 8) | input_[pos_++];
        }

        // Simple values and floats have their own rules; everything else must
        // use the shortest possible argument encoding.
        if (major != major_simple) {
            static constexpr std::uint64_t minimum[] = {24, 0x100, 0x1'0000, 0x1'0000'0000};
            if (argument < minimum[info - 24]) {
                return fail(Errc::non_canonical, "integer or length is not in shortest form");
            }
        }
        return Head{major, info, argument};
    }

    Result<Item> decode_item(std::size_t depth) {
        if (++items_ > options_.max_items) {
            return fail(Errc::limit_exceeded, "input has too many data items");
        }
        auto head = read_head();
        if (!head) {
            return std::unexpected(head.error());
        }
        switch (head->major) {
        case major_unsigned:
            if constexpr (Build) {
                return Value::unsigned_integer(head->argument);
            } else {
                return Checked{};
            }
        case major_negative:
            if constexpr (Build) {
                return Value::negative(head->argument);
            } else {
                return Checked{};
            }
        case major_bytes:
        case major_text:
            return decode_string(*head);
        case major_array:
            return decode_array(*head, depth);
        case major_map:
            return decode_map(*head, depth);
        case major_tag:
            return decode_tag(*head, depth);
        default:
            return decode_simple(*head);
        }
    }

    Result<Item> decode_string(const Head& head) {
        if (head.argument > remaining()) {
            return fail(Errc::truncated, "string length exceeds the remaining input");
        }
        const auto length = static_cast<std::size_t>(head.argument);
        const ByteView content = input_.subspan(pos_, length);
        pos_ += length;
        if constexpr (Build) {
            if (head.major == major_bytes) {
                return Value::bytes(content);
            }
            std::string text(content.begin(), content.end());
            if (!is_valid_utf8(text)) {
                return fail(Errc::malformed, "text string is not valid UTF-8");
            }
            return Value::text(std::move(text));
        } else {
            if (head.major == major_text &&
                !is_valid_utf8(std::string_view(reinterpret_cast<const char*>(content.data()),
                                                content.size()))) {
                return fail(Errc::malformed, "text string is not valid UTF-8");
            }
            return Checked{};
        }
    }

    Status enter(std::size_t depth) const {
        if (depth + 1 > std::min(options_.max_depth, max_nesting_depth)) {
            return fail(Errc::limit_exceeded, "nesting depth exceeds the decoding limit");
        }
        return {};
    }

    Result<Item> decode_array(const Head& head, std::size_t depth) {
        if (auto s = enter(depth); !s) {
            return std::unexpected(s.error());
        }
        // Every item occupies at least one byte, so a count larger than the
        // remaining input cannot be valid. Checking first also bounds memory.
        if (head.argument > remaining()) {
            return fail(Errc::truncated, "array count exceeds the remaining input");
        }
        [[maybe_unused]] Array items;
        if constexpr (Build) {
            items.reserve(std::min(static_cast<std::size_t>(head.argument), max_reserved_items));
        }
        for (std::uint64_t i = 0; i < head.argument; ++i) {
            auto item = decode_item(depth + 1);
            if (!item) {
                return item;
            }
            if constexpr (Build) {
                items.push_back(std::move(*item));
            }
        }
        if constexpr (Build) {
            return Value::array(std::move(items));
        } else {
            return Checked{};
        }
    }

    Result<Item> decode_map(const Head& head, std::size_t depth) {
        if (auto s = enter(depth); !s) {
            return std::unexpected(s.error());
        }
        if (head.argument > remaining() / 2) {
            return fail(Errc::truncated, "map count exceeds the remaining input");
        }
        [[maybe_unused]] Map entries;
        if constexpr (Build) {
            entries.reserve(std::min(static_cast<std::size_t>(head.argument), max_reserved_items));
        }
        ByteView previous_key;
        for (std::uint64_t i = 0; i < head.argument; ++i) {
            const std::size_t key_start = pos_;
            auto key = decode_item(depth + 1);
            if (!key) {
                return key;
            }
            // Because the key itself decoded strictly, its input bytes are its
            // deterministic encoding and can be compared directly.
            const ByteView key_bytes = input_.subspan(key_start, pos_ - key_start);
            if (i > 0) {
                const auto order = std::lexicographical_compare_three_way(
                    previous_key.begin(), previous_key.end(), key_bytes.begin(), key_bytes.end());
                if (order == std::strong_ordering::equal) {
                    return fail(Errc::malformed, "map has duplicate keys");
                }
                if (order == std::strong_ordering::greater) {
                    return fail(Errc::non_canonical, "map keys are not in canonical order");
                }
            }
            previous_key = key_bytes;
            auto value = decode_item(depth + 1);
            if (!value) {
                return value;
            }
            if constexpr (Build) {
                entries.push_back(MapEntry{std::move(*key), std::move(*value)});
            }
        }
        if constexpr (Build) {
            return Value::map(std::move(entries));
        } else {
            return Checked{};
        }
    }

    Result<Item> decode_tag(const Head& head, std::size_t depth) {
        if (auto s = enter(depth); !s) {
            return std::unexpected(s.error());
        }
        if (is_bignum_tag(head.argument)) {
            return fail(Errc::unsupported, "bignums are not allowed");
        }
        auto item = decode_item(depth + 1);
        if (!item) {
            return item;
        }
        if constexpr (Build) {
            return Value::tagged(head.argument, std::move(*item));
        } else {
            return Checked{};
        }
    }

    static Result<Item> decode_simple(const Head& head) {
        switch (head.info) {
        case simple_false:
        case simple_true:
        case simple_null:
            if constexpr (Build) {
                return head.info == simple_null ? Value::null()
                                                : Value::boolean(head.info == simple_true);
            } else {
                return Checked{};
            }
        case 24:
            if (head.argument < 32) {
                return fail(Errc::malformed, "two-byte encoding of a simple value below 32");
            }
            return fail(Errc::unsupported,
                        "simple values other than false, true, null are not allowed");
        case 25:
        case 26:
        case 27:
            return fail(Errc::unsupported, "floating-point values are not allowed");
        default:
            return fail(Errc::unsupported,
                        "simple values other than false, true, null are not allowed");
        }
    }

    ByteView input_;
    const DecodeOptions& options_;
    std::size_t pos_ = 0;
    std::size_t items_ = 0;
};

/// Limits under which every item `encode` writes decodes: the encoder's own
/// nesting limit, and no limit on the number of items.
constexpr DecodeOptions unlimited{.max_depth = max_nesting_depth,
                                  .max_items = std::numeric_limits<std::size_t>::max()};

// ---------------------------------------------------------------------------
// Diagnostic notation
// ---------------------------------------------------------------------------

void append_quoted(std::string& out, std::string_view text) {
    static constexpr std::string_view hex = "0123456789abcdef";
    out.push_back('"');
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (byte < 0x20) {
            out += "\\u00";
            out.push_back(hex[byte >> 4]);
            out.push_back(hex[byte & 0x0f]);
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
}

void append_diagnostic(std::string& out, const Value& value) {
    switch (value.type()) {
    case Type::unsigned_integer:
        out += std::to_string(*value.as_uint64());
        return;
    case Type::negative_integer: {
        const std::uint64_t n = value.as_negative()->n;
        if (n == std::numeric_limits<std::uint64_t>::max()) {
            out += "-18446744073709551616";
        } else {
            out += "-" + std::to_string(n + 1);
        }
        return;
    }
    case Type::bytes:
        out += "h'" + to_hex(*value.as_bytes()) + "'";
        return;
    case Type::text:
        append_quoted(out, *value.as_text());
        return;
    case Type::array: {
        out.push_back('[');
        bool first = true;
        for (const Value& item : *value.as_array()) {
            if (!first) {
                out += ", ";
            }
            first = false;
            append_diagnostic(out, item);
        }
        out.push_back(']');
        return;
    }
    case Type::map: {
        out.push_back('{');
        bool first = true;
        for (const MapEntry& entry : *value.as_map()) {
            if (!first) {
                out += ", ";
            }
            first = false;
            append_diagnostic(out, entry.key);
            out += ": ";
            append_diagnostic(out, entry.value);
        }
        out.push_back('}');
        return;
    }
    case Type::tag: {
        const Tagged& tagged = *value.as_tagged();
        out += std::to_string(tagged.tag) + "(";
        append_diagnostic(out, tagged.item);
        out.push_back(')');
        return;
    }
    case Type::boolean:
        out += *value.as_bool() ? "true" : "false";
        return;
    case Type::null:
        out += "null";
        return;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------

Value::Value(Value&& other) noexcept : storage_(std::move(other.storage_)) {
    other.storage_.emplace<Null>();
}

Value& Value::operator=(Value&& other) noexcept {
    if (this != &other) {
        storage_ = std::move(other.storage_);
        other.storage_.emplace<Null>();
    }
    return *this;
}

Value Value::unsigned_integer(std::uint64_t value) noexcept {
    return Value(std::in_place_type<std::uint64_t>, std::move(value));
}

Value Value::integer(std::int64_t value) noexcept {
    if (value >= 0) {
        return unsigned_integer(static_cast<std::uint64_t>(value));
    }
    // -1 - value is non-negative and cannot overflow for any negative int64_t.
    return negative(static_cast<std::uint64_t>(-(value + 1)));
}

Value Value::negative(std::uint64_t n) noexcept {
    return Value(std::in_place_type<NegativeInt>, NegativeInt{n});
}

Value Value::bytes(ByteView value) {
    return Value(std::in_place_type<Bytes>, Bytes(value.begin(), value.end()));
}

Value Value::bytes(Bytes value) noexcept {
    return Value(std::in_place_type<Bytes>, std::move(value));
}

Value Value::text(std::string value) noexcept {
    return Value(std::in_place_type<std::string>, std::move(value));
}

Value Value::array(Array items) noexcept {
    return Value(std::in_place_type<Array>, std::move(items));
}

Value Value::map(Map entries) noexcept {
    return Value(std::in_place_type<Map>, std::move(entries));
}

Value Value::tagged(std::uint64_t tag, Value item) {
    return Value(std::in_place_type<detail::Box<Tagged>>,
                 detail::Box<Tagged>(Tagged{tag, std::move(item)}));
}

Value Value::null() noexcept {
    return {};
}

Value Value::boolean(bool value) noexcept {
    return Value(std::in_place_type<bool>, std::move(value));
}

Type Value::type() const noexcept {
    switch (storage_.index()) {
    case 1:
        return Type::unsigned_integer;
    case 2:
        return Type::negative_integer;
    case 3:
        return Type::bytes;
    case 4:
        return Type::text;
    case 5:
        return Type::array;
    case 6:
        return Type::map;
    case 7:
        return Type::tag;
    case 8:
        return Type::boolean;
    default:
        return Type::null;
    }
}

bool Value::is_null() const noexcept {
    return std::holds_alternative<Null>(storage_);
}

std::optional<std::int64_t> Value::as_int64() const noexcept {
    constexpr auto max = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (const auto* u = std::get_if<std::uint64_t>(&storage_); u && *u <= max) {
        return static_cast<std::int64_t>(*u);
    }
    if (const auto* neg = std::get_if<NegativeInt>(&storage_); neg && neg->n <= max) {
        return -1 - static_cast<std::int64_t>(neg->n);
    }
    return std::nullopt;
}

std::optional<std::uint64_t> Value::as_uint64() const noexcept {
    if (const auto* u = std::get_if<std::uint64_t>(&storage_)) {
        return *u;
    }
    return std::nullopt;
}

std::optional<bool> Value::as_bool() const noexcept {
    if (const auto* b = std::get_if<bool>(&storage_)) {
        return *b;
    }
    return std::nullopt;
}

const Bytes* Value::as_bytes() const noexcept {
    return std::get_if<Bytes>(&storage_);
}

const std::string* Value::as_text() const noexcept {
    return std::get_if<std::string>(&storage_);
}

const Array* Value::as_array() const noexcept {
    return std::get_if<Array>(&storage_);
}

const Map* Value::as_map() const noexcept {
    return std::get_if<Map>(&storage_);
}

const Tagged* Value::as_tagged() const noexcept {
    const auto* boxed = std::get_if<detail::Box<Tagged>>(&storage_);
    return boxed == nullptr ? nullptr : &**boxed;
}

std::optional<NegativeInt> Value::as_negative() const noexcept {
    if (const auto* neg = std::get_if<NegativeInt>(&storage_)) {
        return *neg;
    }
    return std::nullopt;
}

const Value* Value::find(const Value& key) const noexcept {
    const Map* map = as_map();
    if (map == nullptr) {
        return nullptr;
    }
    const auto it = std::ranges::find(*map, key, &MapEntry::key);
    return it == map->end() ? nullptr : &it->value;
}

const Value* Value::find(std::int64_t key) const noexcept {
    const Map* map = as_map();
    if (map == nullptr) {
        return nullptr;
    }
    const auto it = std::ranges::find_if(
        *map, [key](const MapEntry& entry) { return entry.key.as_int64() == key; });
    return it == map->end() ? nullptr : &it->value;
}

const Value* Value::find(std::string_view key) const noexcept {
    const Map* map = as_map();
    if (map == nullptr) {
        return nullptr;
    }
    const auto it = std::ranges::find_if(*map, [key](const MapEntry& entry) {
        const std::string* text = entry.key.as_text();
        return text != nullptr && *text == key;
    });
    return it == map->end() ? nullptr : &it->value;
}

bool operator==(const Value& a, const Value& b) {
    return a.storage_ == b.storage_;
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

Result<Bytes> encode(const Value& value) {
    Bytes out;
    if (auto s = encode_into(out, value, 0); !s) {
        return std::unexpected(s.error());
    }
    return out;
}

Status encode_to(Bytes& out, const Value& value, std::size_t depth) {
    return encode_into(out, value, depth);
}

void append_head(Bytes& out, Major major, std::uint64_t argument) {
    write_head(out, static_cast<std::uint8_t>(major), argument);
}

Result<Value> decode(ByteView input, const DecodeOptions& options) {
    return Decoder<true>(input, options).decode_top_level();
}

Status validate(ByteView input, const DecodeOptions& options) {
    if (auto checked = Decoder<false>(input, options).decode_top_level(); !checked) {
        return std::unexpected(checked.error());
    }
    return {};
}

Encoded::Encoded() noexcept = default;

Result<Encoded> Encoded::encode(const Value& value) {
    auto bytes = cbor::encode(value);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    return Encoded(std::move(*bytes));
}

Result<Encoded> Encoded::from_bytes(ByteView bytes, const DecodeOptions& options) {
    if (auto s = validate(bytes, options); !s) {
        return std::unexpected(s.error());
    }
    return Encoded(Bytes(bytes.begin(), bytes.end()));
}

Encoded Encoded::trusted(ByteView bytes) {
#ifndef NDEBUG
    if (!validate(bytes, unlimited)) {
        std::abort();
    }
#endif
    return Encoded(Bytes(bytes.begin(), bytes.end()));
}

Value Encoded::value() const {
    auto value = decode(bytes_, unlimited);
    return value ? std::move(*value) : Value::null();
}

std::string diagnostic(const Value& value) {
    std::string out;
    append_diagnostic(out, value);
    return out;
}

std::string diagnostic(const Encoded& value) {
    return diagnostic(value.value());
}

bool is_valid_utf8(std::string_view text) noexcept {
    std::size_t i = 0;
    while (i < text.size()) {
        const auto lead = static_cast<unsigned char>(text[i]);
        std::size_t length = 0;
        std::uint32_t code_point = 0;
        std::uint32_t minimum = 0;
        if (lead < 0x80) {
            ++i;
            continue;
        }
        if ((lead & 0xe0) == 0xc0) {
            length = 2;
            code_point = lead & 0x1fU;
            minimum = 0x80;
        } else if ((lead & 0xf0) == 0xe0) {
            length = 3;
            code_point = lead & 0x0fU;
            minimum = 0x800;
        } else if ((lead & 0xf8) == 0xf0) {
            length = 4;
            code_point = lead & 0x07U;
            minimum = 0x1'0000;
        } else {
            return false;
        }
        if (text.size() - i < length) {
            return false;
        }
        for (std::size_t k = 1; k < length; ++k) {
            const auto continuation = static_cast<unsigned char>(text[i + k]);
            if ((continuation & 0xc0) != 0x80) {
                return false;
            }
            code_point = (code_point << 6) | (continuation & 0x3fU);
        }
        if (code_point < minimum || code_point > 0x10'ffff ||
            (code_point >= 0xd800 && code_point <= 0xdfff)) {
            return false;
        }
        i += length;
    }
    return true;
}

} // namespace cexchain::cbor
