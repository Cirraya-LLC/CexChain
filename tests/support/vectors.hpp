// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <fstream>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/bytes.hpp>

namespace cexchain::test {

/// Loads a JSON file from the shared testvectors/ directory.
inline nlohmann::json load_vectors(std::string_view file) {
    const std::string path = std::string(CEXCHAIN_TESTVECTORS_DIR) + "/" + std::string(file);
    std::ifstream in(path);
    REQUIRE(in.good());
    return nlohmann::json::parse(in);
}

/// Decodes hex, failing the current test on invalid input.
inline Bytes hex(std::string_view text) {
    auto bytes = from_hex(text);
    REQUIRE(bytes);
    return *bytes;
}

/// Decodes a hex string field of a test vector.
inline Bytes hex_field(const nlohmann::json& value) {
    return hex(value.get<std::string>());
}

} // namespace cexchain::test
