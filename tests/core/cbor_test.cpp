// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <random>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>

using cexchain::Bytes;
using cexchain::Errc;
using cexchain::from_hex;
using cexchain::to_hex;
namespace cbor = cexchain::cbor;
using cbor::Value;

namespace {

Bytes hex(std::string_view text) {
    auto bytes = from_hex(text);
    REQUIRE(bytes);
    return *bytes;
}

/// Asserts that `value` encodes to exactly `expected_hex` and that decoding
/// those bytes yields `value` back.
void check_round_trip(const Value& value, std::string_view expected_hex) {
    INFO("expected " << expected_hex);
    const auto encoded = cbor::encode(value);
    REQUIRE(encoded);
    CHECK(to_hex(*encoded) == expected_hex);
    const auto decoded = cbor::decode(hex(expected_hex));
    REQUIRE(decoded);
    CHECK(*decoded == value);
}

Errc decode_error(std::string_view input_hex, const cbor::DecodeOptions& options = {}) {
    const auto decoded = cbor::decode(hex(input_hex), options);
    REQUIRE_FALSE(decoded);
    return decoded.error().code;
}

Value text(const char* s) {
    return Value::text(s);
}

} // namespace

// RFC 8949 Appendix A, restricted to items the CexChain profile accepts.
TEST_CASE("RFC 8949 appendix A integers", "[core][cbor]") {
    check_round_trip(Value::unsigned_integer(0), "00");
    check_round_trip(Value::unsigned_integer(1), "01");
    check_round_trip(Value::unsigned_integer(10), "0a");
    check_round_trip(Value::unsigned_integer(23), "17");
    check_round_trip(Value::unsigned_integer(24), "1818");
    check_round_trip(Value::unsigned_integer(25), "1819");
    check_round_trip(Value::unsigned_integer(100), "1864");
    check_round_trip(Value::unsigned_integer(1000), "1903e8");
    check_round_trip(Value::unsigned_integer(1000000), "1a000f4240");
    check_round_trip(Value::unsigned_integer(1000000000000), "1b000000e8d4a51000");
    check_round_trip(Value::unsigned_integer(18446744073709551615ULL), "1bffffffffffffffff");
    check_round_trip(Value::integer(-1), "20");
    check_round_trip(Value::integer(-10), "29");
    check_round_trip(Value::integer(-100), "3863");
    check_round_trip(Value::integer(-1000), "3903e7");
    check_round_trip(Value::negative(18446744073709551615ULL), "3bffffffffffffffff");
}

TEST_CASE("RFC 8949 appendix A simple values and strings", "[core][cbor]") {
    check_round_trip(Value::boolean(false), "f4");
    check_round_trip(Value::boolean(true), "f5");
    check_round_trip(Value::null(), "f6");
    check_round_trip(Value::bytes(Bytes{}), "40");
    check_round_trip(Value::bytes(hex("01020304")), "4401020304");
    check_round_trip(text(""), "60");
    check_round_trip(text("a"), "6161");
    check_round_trip(text("IETF"), "6449455446");
    check_round_trip(text("\"\\"), "62225c");
    check_round_trip(text("ü"), "62c3bc");
    check_round_trip(text("水"), "63e6b0b4");
    check_round_trip(text("\U00010151"), "64f0908591");
}

TEST_CASE("RFC 8949 appendix A containers and tags", "[core][cbor]") {
    using cbor::Array;
    using cbor::Map;
    auto u = [](std::uint64_t v) {
        return Value::unsigned_integer(v);
    };

    check_round_trip(Value::array({}), "80");
    check_round_trip(Value::array({u(1), u(2), u(3)}), "83010203");
    check_round_trip(Value::array({u(1), Value::array({u(2), u(3)}), Value::array({u(4), u(5)})}),
                     "8301820203820405");

    Array twenty_five;
    for (std::uint64_t i = 1; i <= 25; ++i) {
        twenty_five.push_back(u(i));
    }
    check_round_trip(Value::array(twenty_five),
                     "98190102030405060708090a0b0c0d0e0f101112131415161718181819");

    check_round_trip(Value::map({}), "a0");
    check_round_trip(Value::map({{u(1), u(2)}, {u(3), u(4)}}), "a201020304");
    check_round_trip(Value::map({{text("a"), u(1)}, {text("b"), Value::array({u(2), u(3)})}}),
                     "a26161016162820203");
    check_round_trip(Value::array({text("a"), Value::map({{text("b"), text("c")}})}),
                     "826161a161626163");

    check_round_trip(Value::tagged(1, u(1363896240)), "c11a514b67b0");
    check_round_trip(Value::tagged(23, Value::bytes(hex("01020304"))), "d74401020304");
    check_round_trip(Value::tagged(24, Value::bytes(hex("6449455446"))), "d818456449455446");
    check_round_trip(Value::tagged(32, text("http://www.example.com")),
                     "d82076687474703a2f2f7777772e6578616d706c652e636f6d");
}

TEST_CASE("encoder sorts map keys bytewise, not length-first", "[core][cbor]") {
    // Bytewise order puts 24 (0x1818) before -1 (0x20); the older RFC 7049
    // length-first rule would put -1 first.
    const Value map = Value::map({{Value::integer(-1), Value::null()},
                                  {Value::unsigned_integer(24), Value::null()},
                                  {text("a"), Value::null()},
                                  {Value::unsigned_integer(10), Value::null()}});
    const auto encoded = cbor::encode(map);
    REQUIRE(encoded);
    CHECK(to_hex(*encoded) == "a40af61818f620f66161f6");

    // The canonical form decodes; the length-first form is rejected.
    CHECK(cbor::decode(hex("a21818f620f6")));
    CHECK(decode_error("a220f61818f6") == Errc::non_canonical);
}

TEST_CASE("encoder rejects values outside the profile", "[core][cbor]") {
    const Value duplicate = Value::map({{Value::unsigned_integer(1), Value::null()},
                                        {Value::unsigned_integer(1), Value::boolean(true)}});
    CHECK(cbor::encode(duplicate).error().code == Errc::invalid_argument);

    CHECK(cbor::encode(Value::text(std::string("\xff"))).error().code == Errc::invalid_argument);
    CHECK(cbor::encode(Value::tagged(2, Value::bytes(hex("01")))).error().code ==
          Errc::unsupported);

    Value deep = Value::null();
    for (int i = 0; i < 100; ++i) {
        deep = Value::array({deep});
    }
    CHECK(cbor::encode(deep).error().code == Errc::limit_exceeded);
}

TEST_CASE("decoder rejects non-shortest heads", "[core][cbor]") {
    CHECK(decode_error("1800") == Errc::non_canonical);
    CHECK(decode_error("1817") == Errc::non_canonical);
    CHECK(decode_error("190001") == Errc::non_canonical);
    CHECK(decode_error("1a0000ffff") == Errc::non_canonical);
    CHECK(decode_error("1b00000000ffffffff") == Errc::non_canonical);
    CHECK(decode_error("3800") == Errc::non_canonical);
    CHECK(decode_error("5800") == Errc::non_canonical);
    CHECK(decode_error("980100") == Errc::non_canonical);
    CHECK(decode_error("d80100") == Errc::non_canonical);
}

TEST_CASE("decoder rejects indefinite lengths and stray breaks", "[core][cbor]") {
    CHECK(decode_error("5f4101ff") == Errc::non_canonical);
    CHECK(decode_error("7f6161ff") == Errc::non_canonical);
    CHECK(decode_error("9fff") == Errc::non_canonical);
    CHECK(decode_error("bfff") == Errc::non_canonical);
    CHECK(decode_error("1f") == Errc::malformed);
    CHECK(decode_error("3f") == Errc::malformed);
    CHECK(decode_error("df00") == Errc::malformed);
    CHECK(decode_error("ff") == Errc::malformed);
    CHECK(decode_error("1c") == Errc::malformed);
    CHECK(decode_error("fe") == Errc::malformed);
}

TEST_CASE("decoder rejects floats and other simple values", "[core][cbor]") {
    CHECK(decode_error("f93c00") == Errc::unsupported);
    CHECK(decode_error("fa47c35000") == Errc::unsupported);
    CHECK(decode_error("fb3ff199999999999a") == Errc::unsupported);
    CHECK(decode_error("f7") == Errc::unsupported);
    CHECK(decode_error("e0") == Errc::unsupported);
    CHECK(decode_error("f0") == Errc::unsupported);
    CHECK(decode_error("f818") == Errc::malformed);
    CHECK(decode_error("f820") == Errc::unsupported);
    CHECK(decode_error("f8ff") == Errc::unsupported);
}

TEST_CASE("decoder rejects truncated input without large allocations", "[core][cbor]") {
    CHECK(decode_error("") == Errc::truncated);
    CHECK(decode_error("19") == Errc::truncated);
    CHECK(decode_error("1901") == Errc::truncated);
    CHECK(decode_error("6261") == Errc::truncated);
    CHECK(decode_error("8201") == Errc::truncated);
    CHECK(decode_error("a101") == Errc::truncated);
    CHECK(decode_error("c1") == Errc::truncated);
    CHECK(decode_error("5bffffffffffffffff") == Errc::truncated);
    CHECK(decode_error("9bffffffffffffffff") == Errc::truncated);
    CHECK(decode_error("bbffffffffffffffff") == Errc::truncated);
}

TEST_CASE("decoder rejects trailing bytes", "[core][cbor]") {
    CHECK(decode_error("0000") == Errc::malformed);
    CHECK(decode_error("f6f6") == Errc::malformed);
}

TEST_CASE("decoder enforces map key rules", "[core][cbor]") {
    CHECK(decode_error("a201020103") == Errc::malformed);     // duplicate key 1
    CHECK(decode_error("a203040102") == Errc::non_canonical); // 3 before 1
    CHECK(decode_error("a2616201616101") == Errc::non_canonical);
    CHECK(cbor::decode(hex("a2616101616201")));
}

TEST_CASE("decoder validates UTF-8 strictly", "[core][cbor]") {
    CHECK(decode_error("61ff") == Errc::malformed);
    CHECK(decode_error("62c080") == Errc::malformed);     // overlong NUL
    CHECK(decode_error("63eda080") == Errc::malformed);   // surrogate U+D800
    CHECK(decode_error("64f4908080") == Errc::malformed); // above U+10FFFF
    CHECK(decode_error("62e282") == Errc::malformed);     // truncated sequence
    CHECK(decode_error("6180") == Errc::malformed);       // lone continuation byte
}

TEST_CASE("decoder rejects bignums", "[core][cbor]") {
    CHECK(decode_error("c24101") == Errc::unsupported);
    CHECK(decode_error("c34101") == Errc::unsupported);
}

TEST_CASE("decoder enforces the nesting limit", "[core][cbor]") {
    std::string nested(32 * 2, '8');
    for (std::size_t i = 1; i < nested.size(); i += 2) {
        nested[i] = '1';
    }
    nested += "00"; // 32 nested single-element arrays around 0
    CHECK(cbor::decode(hex(nested)));
    CHECK(decode_error("81" + nested) == Errc::limit_exceeded);

    cbor::DecodeOptions relaxed;
    relaxed.max_depth = 40;
    CHECK(cbor::decode(hex("81" + nested), relaxed));
}

TEST_CASE("integer accessors respect ranges", "[core][cbor]") {
    CHECK(Value::integer(INT64_MIN).as_int64() == INT64_MIN);
    CHECK(Value::integer(INT64_MAX).as_int64() == INT64_MAX);
    CHECK_FALSE(Value::unsigned_integer(UINT64_MAX).as_int64());
    CHECK_FALSE(Value::negative(UINT64_MAX).as_int64());
    CHECK(Value::integer(-19).as_negative()->n == 18);
    CHECK_FALSE(Value::integer(-1).as_uint64());
}

TEST_CASE("map lookup by key", "[core][cbor]") {
    const Value map = Value::map(
        {{Value::integer(1), Value::integer(-19)}, {text("kid"), Value::bytes(hex("0102"))}});
    REQUIRE(map.find(1) != nullptr);
    CHECK(map.find(1)->as_int64() == -19);
    REQUIRE(map.find("kid") != nullptr);
    CHECK(*map.find("kid")->as_bytes() == hex("0102"));
    CHECK(map.find(2) == nullptr);
    CHECK(Value::null().find(1) == nullptr);
}

TEST_CASE("diagnostic notation", "[core][cbor]") {
    const Value value =
        Value::map({{Value::integer(1), Value::integer(-19)},
                    {text("a\"b"), Value::bytes(hex("01ff"))},
                    {Value::integer(-1),
                     Value::tagged(18, Value::array({Value::boolean(true), Value::null()}))}});
    CHECK(cbor::diagnostic(value) == R"({1: -19, "a\"b": h'01ff', -1: 18([true, null])})");
    CHECK(cbor::diagnostic(Value::negative(UINT64_MAX)) == "-18446744073709551616");
}

TEST_CASE("diagnostic notation parses back, as people type it", "[core][cbor]") {
    const auto parsed = [](std::string_view text) {
        auto value = cbor::parse_diagnostic(text);
        INFO(text << ": " << (value ? std::string() : std::string(value.error().detail)));
        REQUIRE(value);
        return *value;
    };
    const auto encoded = [&](std::string_view text) {
        auto bytes = cbor::encode(parsed(text));
        REQUIRE(bytes);
        return to_hex(*bytes);
    };
    // What diagnostic() writes, and JSON without floating point.
    const std::string written = R"({1: -19, -1: 18([true, null]), "a\"b": h'01ff'})";
    CHECK(cbor::diagnostic(parsed(written)) == written);
    CHECK(cbor::diagnostic(parsed(R"({"a\"b": h'01FF', -1: 18([true, null]), 1: -19})")) ==
          written);
    CHECK(encoded(R"( {"b": [1, 2, {"c": null}], "a": false} )") ==
          "a26161f46162830102a16163f6"); // maps come out canonical
    CHECK(encoded("0") == "00");
    CHECK(encoded("-0") == "00");
    CHECK(encoded("18446744073709551615") == "1bffffffffffffffff");
    CHECK(encoded("-18446744073709551616") == "3bffffffffffffffff");
    CHECK(encoded("-1") == "20");
    CHECK(encoded(R"("\u00e9\ud83d\ude00\n\/")") == "68c3a9f09f98800a2f");
    CHECK(encoded("\"水\"") == "63e6b0b4");
    CHECK(encoded("h''") == "40");
    CHECK(encoded("h'00 FF\n0a'") == "4300ff0a");
    CHECK(encoded("<<>>") == "40");
    CHECK(encoded("<<1, \"a\">>") == "4301"
                                     "6161");
    CHECK(encoded("[<<[2, [h'01']]>>]") == "81"
                                           "45"
                                           "82028141"
                                           "01");
    CHECK(encoded("1(1700000000)") == "c11a6553f100");
    CHECK(encoded("{}") == "a0");
    CHECK(encoded("[ ]") == "80");
    // Comments, wherever white space may go.
    CHECK(encoded("/ a comment / [1, / two / 2] # the end") == "820102");
    CHECK(encoded("# a file's header\n{\"a\": 1, # one\n \"b\": 2}\n# done") == "a2616101616202");
    CHECK(encoded("[\"/ not a comment /\", \"# nor this\"]") ==
          "82"
          "712f206e6f74206120636f6d6d656e74202f"
          "6a23206e6f722074686973");
    CHECK(encoded("h'00 01'#\n") == "420001");

    for (const std::string_view bad : {"",
                                       " ",
                                       "1.5",
                                       "1e3",
                                       "01",
                                       "-",
                                       "18446744073709551616",
                                       "-18446744073709551617",
                                       "[1,]",
                                       "[1 2]",
                                       "{1: 2, 1: 3}",
                                       "{1 2}",
                                       "{1: }",
                                       "h'0'",
                                       "h'0g'",
                                       "h'00",
                                       "\"abc",
                                       "\"a\\x\"",
                                       "\"\\ud800\"",
                                       "\"\\udc00\"",
                                       "\"\\u12\"",
                                       "\"tab\there\"",
                                       "2(h'01')",
                                       "3(h'01')",
                                       "tru",
                                       "undefined",
                                       "NaN",
                                       "1 2",
                                       "[1]]",
                                       "<<1",
                                       "<1>",
                                       "18446744073709551616(1)",
                                       "simple(1)",
                                       "'a'",
                                       "/ open",
                                       "[1, / open]",
                                       "1 / open",
                                       "#",
                                       "[1 # 2]",
                                       "h'00 / no comments in bytes / 01'"}) {
        INFO(bad);
        const auto value = cbor::parse_diagnostic(bad);
        CHECK_FALSE(value);
        if (!value) {
            CHECK(value.error().code == Errc::malformed);
        }
    }
    CHECK_FALSE(cbor::parse_diagnostic("\"\xff\""));

    // Nesting is bounded, so recursion is.
    std::string deep(cbor::max_nesting_depth, '[');
    deep += std::string(cbor::max_nesting_depth, ']');
    CHECK(cbor::parse_diagnostic(deep));
    CHECK_FALSE(cbor::parse_diagnostic("[" + deep + "]"));
    CHECK_FALSE(cbor::parse_diagnostic(std::string(100'000, '[')));
}

namespace {

Value random_value(std::mt19937_64& rng, int depth) {
    std::uniform_int_distribution<int> kind_dist(0, depth > 3 ? 5 : 8);
    std::uniform_int_distribution<std::uint64_t> any;
    std::uniform_int_distribution<std::size_t> size_dist(0, 6);
    switch (kind_dist(rng)) {
    case 0:
        return Value::unsigned_integer(any(rng) >> (any(rng) % 64));
    case 1:
        return Value::negative(any(rng) >> (any(rng) % 64));
    case 2: {
        Bytes bytes(size_dist(rng) * 7);
        for (auto& b : bytes) {
            b = static_cast<std::uint8_t>(any(rng));
        }
        return Value::bytes(std::move(bytes));
    }
    case 3: {
        std::string s;
        for (std::size_t i = 0, n = size_dist(rng); i < n; ++i) {
            s.push_back(static_cast<char>('a' + any(rng) % 26));
        }
        s += "é水";
        return Value::text(std::move(s));
    }
    case 4:
        return Value::boolean(any(rng) % 2 == 0);
    case 5:
        return Value::null();
    case 6: {
        cbor::Array items;
        for (std::size_t i = 0, n = size_dist(rng); i < n; ++i) {
            items.push_back(random_value(rng, depth + 1));
        }
        return Value::array(std::move(items));
    }
    case 7: {
        // Distinct integer keys guarantee no duplicates.
        cbor::Map entries;
        const std::size_t n = size_dist(rng);
        for (std::size_t i = 0; i < n; ++i) {
            const auto key = static_cast<std::int64_t>(i * 37) - 100;
            entries.push_back({Value::integer(key), random_value(rng, depth + 1)});
        }
        return Value::map(std::move(entries));
    }
    default:
        return Value::tagged(any(rng) % 1000 + 4, random_value(rng, depth + 1));
    }
}

} // namespace

TEST_CASE("random values round-trip through canonical form", "[core][cbor][property]") {
    std::mt19937_64 rng(0xCE7C4A11u);
    for (int i = 0; i < 2000; ++i) {
        const Value value = random_value(rng, 0);
        const auto encoded = cbor::encode(value);
        REQUIRE(encoded);
        const auto decoded = cbor::decode(*encoded);
        REQUIRE(decoded);
        const auto reencoded = cbor::encode(*decoded);
        REQUIRE(reencoded);
        CHECK(*reencoded == *encoded);
        // Diagnostic notation is a faithful text form.
        const auto parsed = cbor::parse_diagnostic(cbor::diagnostic(*decoded));
        REQUIRE(parsed);
        CHECK(*parsed == *decoded);
    }
}

TEST_CASE("nesting limit is symmetric and capped", "[core][cbor]") {
    const auto nested = [](std::size_t levels) {
        Value value = Value::unsigned_integer(0);
        for (std::size_t i = 0; i < levels; ++i) {
            value = Value::array({value});
        }
        return value;
    };
    cbor::DecodeOptions generous;
    generous.max_depth = 1000; // clamped to max_nesting_depth

    const auto at_limit = cbor::encode(nested(cbor::max_nesting_depth));
    REQUIRE(at_limit);
    CHECK(cbor::decode(*at_limit, generous));

    CHECK(cbor::encode(nested(cbor::max_nesting_depth + 1)).error().code == Errc::limit_exceeded);
    Bytes beyond = *at_limit;
    beyond.insert(beyond.begin(), 0x81);
    CHECK(cbor::decode(beyond, generous).error().code == Errc::limit_exceeded);

    // An empty container at the deepest level follows the same rule both ways.
    Value deepest_empty = Value::array({});
    for (std::size_t i = 0; i < cbor::max_nesting_depth; ++i) {
        deepest_empty = Value::array({deepest_empty});
    }
    CHECK(cbor::encode(deepest_empty).error().code == Errc::limit_exceeded);
}

TEST_CASE("a moved-from value is null", "[core][cbor]") {
    Value tagged = Value::tagged(42, Value::text("x"));
    const Value moved = std::move(tagged);
    REQUIRE(moved.as_tagged() != nullptr);
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from state is under test.
    CHECK(tagged.is_null());
    CHECK(to_hex(*cbor::encode(tagged)) == "f6");

    Value target = Value::text("old");
    Value source = Value::tagged(7, Value::null());
    target = std::move(source);
    CHECK(target.as_tagged()->tag == 7);
    CHECK(source.is_null()); // NOLINT(bugprone-use-after-move)
}

TEST_CASE("huge claimed counts at every level stay cheap", "[core][cbor]") {
    // 32 nested arrays, each claiming as many items as bytes remain.
    Bytes input;
    for (int i = 0; i < 32; ++i) {
        input.push_back(0x9a); // array, 4-byte count
        input.insert(input.end(), {0x00, 0x00, 0x10, 0x00});
    }
    input.resize(input.size() + 4096, 0x00);
    // Rejected (the counts are not satisfied) without reserving gigabytes.
    CHECK_FALSE(cbor::decode(input));
}

TEST_CASE("decoding is bounded by an item budget", "[core][cbor]") {
    // An array of 200,000 single-byte items.
    Bytes input{0x1a, 0x00, 0x03, 0x0d, 0x40};
    input[0] = 0x9a;
    input.resize(input.size() + 200'000, 0x00);
    CHECK(cbor::decode(input).error().code == Errc::limit_exceeded);

    cbor::DecodeOptions larger;
    larger.max_items = 300'000;
    const auto decoded = cbor::decode(input, larger);
    REQUIRE(decoded);
    CHECK(decoded->as_array()->size() == 200'000);
}
