// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Parsing diagnostic notation (RFC 8949 section 8): how people and programs
// type CBOR values, such as a contract call's arguments, on a command line.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

#include <cexchain/core/cbor.hpp>

namespace cexchain::cbor {

namespace {

constexpr std::string_view two_to_the_64 = "18446744073709551616";

bool is_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}

int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

void append_utf8(std::string& out, std::uint32_t code_point) {
    if (code_point < 0x80) {
        out.push_back(static_cast<char>(code_point));
    } else if (code_point < 0x800) {
        out.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    } else if (code_point < 0x10000) {
        out.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    } else {
        out.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    }
}

/// A recursive-descent parser. Every error is Errc::malformed with a static
/// message; recursion is bounded by max_nesting_depth, and memory by the
/// item budget of DecodeOptions.
class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    Result<Value> parse() {
        skip_space();
        auto value = item();
        if (!value) {
            return value;
        }
        skip_space();
        if (pos_ != text_.size()) {
            return fail(Errc::malformed, "diagnostic notation: unexpected text after the value");
        }
        return value;
    }

private:
    [[nodiscard]] bool at_end() const noexcept { return pos_ >= text_.size(); }
    [[nodiscard]] char peek() const noexcept { return at_end() ? '\0' : text_[pos_]; }

    void skip_space() noexcept {
        while (!at_end() && is_space(text_[pos_])) {
            ++pos_;
        }
    }

    bool consume(std::string_view word) noexcept {
        if (text_.substr(pos_).starts_with(word)) {
            pos_ += word.size();
            return true;
        }
        return false;
    }

    Result<Value> item() {
        if (++items_ > DecodeOptions{}.max_items) {
            return fail(Errc::malformed, "diagnostic notation: too many items");
        }
        const char c = peek();
        if (c == '"') {
            return text();
        }
        if (c == '[' || c == '{' || c == '<') {
            if (depth_ >= max_nesting_depth) {
                return fail(Errc::malformed, "diagnostic notation: nested too deeply");
            }
            ++depth_;
            auto value = c == '[' ? array() : c == '{' ? map() : embedded();
            --depth_;
            return value;
        }
        if (c == 'h' && text_.substr(pos_).starts_with("h'")) {
            return hex_bytes();
        }
        if (c == '-' || is_digit(c)) {
            return number();
        }
        if (consume("true")) {
            return Value::boolean(true);
        }
        if (consume("false")) {
            return Value::boolean(false);
        }
        if (consume("null")) {
            return Value::null();
        }
        if (at_end()) {
            return fail(Errc::malformed, "diagnostic notation: a value is missing");
        }
        return fail(Errc::malformed, "diagnostic notation: unexpected character");
    }

    /// Digits as an unsigned integer; `overflow` if they exceed 2^64 - 1.
    struct Digits {
        std::string_view text;
        std::uint64_t value = 0;
        bool overflow = false;
    };

    Result<Digits> digits() {
        const std::size_t start = pos_;
        Digits out;
        while (!at_end() && is_digit(text_[pos_])) {
            const auto digit = static_cast<std::uint64_t>(text_[pos_] - '0');
            if (out.value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
                out.overflow = true;
            } else {
                out.value = out.value * 10 + digit;
            }
            ++pos_;
        }
        out.text = text_.substr(start, pos_ - start);
        if (out.text.empty()) {
            return fail(Errc::malformed, "diagnostic notation: a number needs digits");
        }
        if (out.text.size() > 1 && out.text.front() == '0') {
            return fail(Errc::malformed, "diagnostic notation: numbers have no leading zeros");
        }
        if (peek() == '.' || peek() == 'e' || peek() == 'E') {
            return fail(Errc::malformed,
                        "diagnostic notation: floating-point numbers are not allowed");
        }
        return out;
    }

    Result<Value> number() {
        const bool negative = consume("-");
        auto n = digits();
        if (!n) {
            return std::unexpected(n.error());
        }
        if (!negative && peek() == '(') {
            if (n->overflow) {
                return fail(Errc::malformed, "diagnostic notation: a tag number is too large");
            }
            return tagged(n->value);
        }
        if (!negative) {
            if (n->overflow) {
                return fail(Errc::malformed, "diagnostic notation: an integer is too large");
            }
            return Value::unsigned_integer(n->value);
        }
        if (n->overflow) {
            if (n->text != two_to_the_64) {
                return fail(Errc::malformed, "diagnostic notation: an integer is too small");
            }
            return Value::negative(std::numeric_limits<std::uint64_t>::max());
        }
        // -0 is 0; otherwise -v is CBOR's -1 - (v - 1).
        return n->value == 0 ? Value::unsigned_integer(0) : Value::negative(n->value - 1);
    }

    Result<Value> tagged(std::uint64_t tag) {
        if (depth_ >= max_nesting_depth) {
            return fail(Errc::malformed, "diagnostic notation: nested too deeply");
        }
        ++pos_; // '('
        ++depth_;
        skip_space();
        auto inner = item();
        --depth_;
        if (!inner) {
            return inner;
        }
        skip_space();
        if (!consume(")")) {
            return fail(Errc::malformed, "diagnostic notation: a tag's value needs ')'");
        }
        return Value::tagged(tag, std::move(*inner));
    }

    Result<std::uint32_t> hex4() {
        if (text_.size() - pos_ < 4) {
            return fail(Errc::malformed, "diagnostic notation: \\u needs four hex digits");
        }
        std::uint32_t out = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            const int digit = hex_value(text_[pos_ + i]);
            if (digit < 0) {
                return fail(Errc::malformed, "diagnostic notation: \\u needs four hex digits");
            }
            out = out * 16 + static_cast<std::uint32_t>(digit);
        }
        pos_ += 4;
        return out;
    }

    Result<Value> text() {
        ++pos_; // '"'
        std::string out;
        while (true) {
            if (at_end()) {
                return fail(Errc::malformed, "diagnostic notation: a text string is not closed");
            }
            const char c = text_[pos_++];
            if (c == '"') {
                break;
            }
            if (static_cast<unsigned char>(c) < 0x20) {
                return fail(Errc::malformed,
                            "diagnostic notation: control characters in text must be escaped");
            }
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (at_end()) {
                return fail(Errc::malformed, "diagnostic notation: a text string is not closed");
            }
            const char e = text_[pos_++];
            switch (e) {
            case '"':
            case '\\':
            case '/':
                out.push_back(e);
                break;
            case 'b':
                out.push_back('\b');
                break;
            case 'f':
                out.push_back('\f');
                break;
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case 't':
                out.push_back('\t');
                break;
            case 'u': {
                auto unit = hex4();
                if (!unit) {
                    return std::unexpected(unit.error());
                }
                std::uint32_t code_point = *unit;
                if (code_point >= 0xdc00 && code_point <= 0xdfff) {
                    return fail(Errc::malformed, "diagnostic notation: a lone surrogate in \\u");
                }
                if (code_point >= 0xd800 && code_point <= 0xdbff) {
                    if (!consume("\\u")) {
                        return fail(Errc::malformed,
                                    "diagnostic notation: a lone surrogate in \\u");
                    }
                    auto low = hex4();
                    if (!low) {
                        return std::unexpected(low.error());
                    }
                    if (*low < 0xdc00 || *low > 0xdfff) {
                        return fail(Errc::malformed,
                                    "diagnostic notation: a lone surrogate in \\u");
                    }
                    code_point = 0x10000 + ((code_point - 0xd800) << 10U) + (*low - 0xdc00);
                }
                append_utf8(out, code_point);
                break;
            }
            default:
                return fail(Errc::malformed, "diagnostic notation: unknown escape in text");
            }
        }
        if (!is_valid_utf8(out)) {
            return fail(Errc::malformed, "diagnostic notation: text is not valid UTF-8");
        }
        return Value::text(std::move(out));
    }

    Result<Value> hex_bytes() {
        pos_ += 2; // "h'"
        Bytes out;
        int high = -1;
        while (true) {
            if (at_end()) {
                return fail(Errc::malformed, "diagnostic notation: a byte string is not closed");
            }
            const char c = text_[pos_++];
            if (c == '\'') {
                break;
            }
            if (is_space(c)) {
                continue;
            }
            const int digit = hex_value(c);
            if (digit < 0) {
                return fail(Errc::malformed, "diagnostic notation: h'...' holds hex digits only");
            }
            if (high < 0) {
                high = digit;
            } else {
                out.push_back(static_cast<std::uint8_t>((high << 4) | digit));
                high = -1;
            }
        }
        if (high >= 0) {
            return fail(Errc::malformed, "diagnostic notation: h'...' needs an even number of "
                                         "hex digits");
        }
        return Value::bytes(std::move(out));
    }

    /// Items separated by commas up to `close`, each passed to `take`.
    template <class Take>
    Status sequence(char close, Take&& take) {
        skip_space();
        if (consume(std::string_view(&close, 1))) {
            return {};
        }
        while (true) {
            if (auto s = take(); !s) {
                return s;
            }
            skip_space();
            if (consume(std::string_view(&close, 1))) {
                return {};
            }
            if (!consume(",")) {
                return fail(Errc::malformed, "diagnostic notation: expected ',' between items");
            }
            skip_space();
            if (peek() == close) {
                return fail(Errc::malformed, "diagnostic notation: a trailing ',' is not allowed");
            }
        }
    }

    Result<Value> array() {
        ++pos_; // '['
        Array items;
        auto s = sequence(']', [&]() -> Status {
            auto value = item();
            if (!value) {
                return std::unexpected(value.error());
            }
            items.push_back(std::move(*value));
            return {};
        });
        if (!s) {
            return std::unexpected(s.error());
        }
        return Value::array(std::move(items));
    }

    Result<Value> map() {
        ++pos_; // '{'
        Map entries;
        auto s = sequence('}', [&]() -> Status {
            auto key = item();
            if (!key) {
                return std::unexpected(key.error());
            }
            skip_space();
            if (!consume(":")) {
                return fail(Errc::malformed, "diagnostic notation: a map key needs ':'");
            }
            skip_space();
            auto value = item();
            if (!value) {
                return std::unexpected(value.error());
            }
            entries.push_back({std::move(*key), std::move(*value)});
            return {};
        });
        if (!s) {
            return std::unexpected(s.error());
        }
        return Value::map(std::move(entries));
    }

    /// <<a, b>>: a byte string holding the encodings of a and b, in turn
    /// (RFC 8610, Appendix G.3).
    Result<Value> embedded() {
        if (!consume("<<")) {
            return fail(Errc::malformed, "diagnostic notation: unexpected character");
        }
        Bytes out;
        skip_space();
        if (consume(">>")) {
            return Value::bytes(std::move(out));
        }
        while (true) {
            auto value = item();
            if (!value) {
                return value;
            }
            auto encoded = encode(*value);
            if (!encoded) {
                return fail(Errc::malformed, encoded.error().detail);
            }
            out.insert(out.end(), encoded->begin(), encoded->end());
            skip_space();
            if (consume(">>")) {
                return Value::bytes(std::move(out));
            }
            if (!consume(",")) {
                return fail(Errc::malformed, "diagnostic notation: expected ',' or '>>'");
            }
            skip_space();
        }
    }

    std::string_view text_;
    std::size_t pos_ = 0;
    std::size_t depth_ = 0;
    std::size_t items_ = 0;
};

} // namespace

Result<Value> parse_diagnostic(std::string_view text) {
    auto value = Parser(text).parse();
    if (!value) {
        return value;
    }
    // Canonical, and only what encodes: no duplicate map keys or bignums.
    auto encoded = encode(*value);
    if (!encoded) {
        return fail(Errc::malformed, encoded.error().detail);
    }
    DecodeOptions options;
    options.max_depth = max_nesting_depth;
    return decode(*encoded, options);
}

} // namespace cexchain::cbor
