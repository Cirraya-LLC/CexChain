# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Crypto provider backed by OpenSSL 3.5+. Implements the interfaces declared in
# <cexchain/core/crypto.hpp>.
add_library(cexchain_crypto_openssl
    src/openssl.cpp)
add_library(cexchain::crypto_openssl ALIAS cexchain_crypto_openssl)

target_include_directories(cexchain_crypto_openssl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(cexchain_crypto_openssl
    PUBLIC cexchain::core
    PRIVATE OpenSSL::Crypto)
target_compile_features(cexchain_crypto_openssl PUBLIC cxx_std_23)
cexchain_target_defaults(cexchain_crypto_openssl)
