# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Keys on PKCS #11 tokens (USB keys, smart cards, HSMs), loaded at run time
# with dlopen. Built when the PKCS #11 header (from p11-kit) is available.
find_path(KANHE_PKCS11_INCLUDE_DIR p11-kit/pkcs11.h PATH_SUFFIXES p11-kit-1)
if(NOT KANHE_PKCS11_INCLUDE_DIR)
    message(STATUS "PKCS #11 header not found (install p11-kit): building without token support")
    return()
endif()

add_library(kanhe_crypto_pkcs11 src/pkcs11.cpp)
add_library(kanhe::crypto_pkcs11 ALIAS kanhe_crypto_pkcs11)
target_include_directories(kanhe_crypto_pkcs11 PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(kanhe_crypto_pkcs11 SYSTEM PRIVATE ${KANHE_PKCS11_INCLUDE_DIR})
target_link_libraries(kanhe_crypto_pkcs11 PUBLIC kanhe::core PRIVATE ${CMAKE_DL_LIBS})
target_compile_features(kanhe_crypto_pkcs11 PUBLIC cxx_std_23)
kanhe_target_defaults(kanhe_crypto_pkcs11)
set(KANHE_HAVE_PKCS11 ON PARENT_SCOPE)
