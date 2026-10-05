# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzz targets require Clang with libFuzzer.")
endif()

function(cexchain_add_fuzzer name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE cexchain::core ${ARGN})
    target_compile_features(${name} PRIVATE cxx_std_23)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
    cexchain_target_defaults(${name})
endfunction()

cexchain_add_fuzzer(cbor_decode_fuzz)
cexchain_add_fuzzer(cose_parse_fuzz)
cexchain_add_fuzzer(merkle_verify_fuzz cexchain::crypto_openssl)
