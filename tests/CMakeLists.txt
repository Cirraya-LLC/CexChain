# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

add_executable(cexchain_tests
    core/cbor_test.cpp
    core/hex_test.cpp)

target_link_libraries(cexchain_tests PRIVATE
    cexchain::core
    Catch2::Catch2WithMain
    nlohmann_json::nlohmann_json)
target_compile_definitions(cexchain_tests PRIVATE
    CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
target_compile_features(cexchain_tests PRIVATE cxx_std_23)
cexchain_target_defaults(cexchain_tests)

list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)
catch_discover_tests(cexchain_tests)
