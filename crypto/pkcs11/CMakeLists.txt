# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Keys on PKCS #11 tokens (USB keys, smart cards, HSMs), loaded at run time
# with dlopen. Built when the PKCS #11 header (from p11-kit) is available.
find_path(CEXCHAIN_PKCS11_INCLUDE_DIR p11-kit/pkcs11.h PATH_SUFFIXES p11-kit-1)
if(NOT CEXCHAIN_PKCS11_INCLUDE_DIR)
    message(STATUS "PKCS #11 header not found (install p11-kit): building without token support")
    return()
endif()

add_library(cexchain_crypto_pkcs11 src/pkcs11.cpp)
add_library(cexchain::crypto_pkcs11 ALIAS cexchain_crypto_pkcs11)
target_include_directories(cexchain_crypto_pkcs11 PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(cexchain_crypto_pkcs11 SYSTEM PRIVATE ${CEXCHAIN_PKCS11_INCLUDE_DIR})
target_link_libraries(cexchain_crypto_pkcs11 PUBLIC cexchain::core PRIVATE ${CMAKE_DL_LIBS})
target_compile_features(cexchain_crypto_pkcs11 PUBLIC cxx_std_23)
cexchain_target_defaults(cexchain_crypto_pkcs11)
set(CEXCHAIN_HAVE_PKCS11 ON PARENT_SCOPE)
