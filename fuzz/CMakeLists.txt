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
cexchain_add_fuzzer(protocol_parse_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(access_parse_fuzz)
cexchain_add_fuzzer(asset_parse_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(webauthn_registration_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(vm_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(contract_parse_fuzz cexchain::crypto_openssl)
# The interpreter's internals (core/src/vm/internal.hpp), for a lower fuel limit.
target_include_directories(vm_fuzz PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
if(TARGET cexchain_crypto_pkcs11)
    cexchain_add_fuzzer(pkcs11_uri_fuzz cexchain::crypto_pkcs11)
endif()
if(TARGET cexchain_node)
    cexchain_add_fuzzer(http_parse_fuzz cexchain::node)
    cexchain_add_fuzzer(backup_restore_fuzz cexchain::ledger)
    cexchain_add_fuzzer(pending_call_fuzz cexchain::node)
    # The cluster's internals (node/src/cluster_parts.hpp).
    cexchain_add_fuzzer(cluster_entry_fuzz cexchain::node cexchain::crypto_openssl cexchain_nuraft)
    target_include_directories(cluster_entry_fuzz PRIVATE
        ${PROJECT_SOURCE_DIR}/node/src ${PROJECT_SOURCE_DIR}/ledger/src)
    target_compile_features(cluster_entry_fuzz PRIVATE cxx_std_26)
endif()

# Valid inputs to start the corpora from (an ordinary program, not a fuzzer).
add_executable(make_seeds make_seeds.cpp)
target_link_libraries(make_seeds PRIVATE cexchain::ledger cexchain::crypto_openssl
    nlohmann_json::nlohmann_json)
target_compile_definitions(make_seeds PRIVATE
    CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
target_compile_features(make_seeds PRIVATE cxx_std_23)
cexchain_target_defaults(make_seeds)
