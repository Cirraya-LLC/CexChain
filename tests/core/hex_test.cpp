// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/bytes.hpp>

using kanhe::Bytes;
using kanhe::Errc;

TEST_CASE("to_hex encodes lowercase", "[core][hex]") {
    const Bytes bytes{0x00, 0x01, 0xab, 0xff};
    CHECK(kanhe::to_hex(bytes) == "0001abff");
    CHECK(kanhe::to_hex({}).empty());
}

TEST_CASE("from_hex accepts both cases", "[core][hex]") {
    const auto lower = kanhe::from_hex("0001abff");
    const auto upper = kanhe::from_hex("0001ABFF");
    REQUIRE(lower);
    REQUIRE(upper);
    CHECK(*lower == Bytes{0x00, 0x01, 0xab, 0xff});
    CHECK(*upper == *lower);
}

TEST_CASE("from_hex rejects invalid input", "[core][hex]") {
    CHECK(kanhe::from_hex("abc").error().code == Errc::malformed);
    CHECK(kanhe::from_hex("zz").error().code == Errc::malformed);
    CHECK(kanhe::from_hex("0g").error().code == Errc::malformed);
}

TEST_CASE("hex round-trips every byte value", "[core][hex]") {
    Bytes all;
    for (int i = 0; i < 256; ++i) {
        all.push_back(static_cast<std::uint8_t>(i));
    }
    const auto decoded = kanhe::from_hex(kanhe::to_hex(all));
    REQUIRE(decoded);
    CHECK(*decoded == all);
}
