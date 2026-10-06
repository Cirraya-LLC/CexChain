# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Rendering of verification results, shared by the command line and the
# browser verifier. Portable C++23 like core; JSON via nlohmann/json.
add_library(cexchain_verifier
    src/report.cpp)
add_library(cexchain::verifier ALIAS cexchain_verifier)

target_include_directories(cexchain_verifier PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(cexchain_verifier PUBLIC cexchain::core nlohmann_json::nlohmann_json)
target_compile_features(cexchain_verifier PUBLIC cxx_std_23)
cexchain_target_defaults(cexchain_verifier)
