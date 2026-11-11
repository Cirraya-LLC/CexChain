# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Crypto provider backed by OpenSSL 3.5+. Implements the interfaces declared in
# <kanhe/core/crypto.hpp>.
add_library(kanhe_crypto_openssl
    src/openssl.cpp
    src/timestamp.cpp)
add_library(kanhe::crypto_openssl ALIAS kanhe_crypto_openssl)

target_include_directories(kanhe_crypto_openssl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(kanhe_crypto_openssl
    PUBLIC kanhe::core
    PRIVATE OpenSSL::Crypto)
target_compile_features(kanhe_crypto_openssl PUBLIC cxx_std_23)
kanhe_target_defaults(kanhe_crypto_openssl)
