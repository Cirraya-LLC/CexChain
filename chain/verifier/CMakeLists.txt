# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Rendering of verification results, shared by the command line and the
# browser verifier. Portable C++23 like core; JSON via nlohmann/json.
add_library(kanhe_verifier
    src/report.cpp)
add_library(kanhe::verifier ALIAS kanhe_verifier)

target_include_directories(kanhe_verifier PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(kanhe_verifier PUBLIC kanhe::core nlohmann_json::nlohmann_json)
target_compile_features(kanhe_verifier PUBLIC cxx_std_23)
kanhe_target_defaults(kanhe_verifier)
