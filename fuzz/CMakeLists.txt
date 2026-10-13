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
cexchain_add_fuzzer(diagnostic_fuzz)
cexchain_add_fuzzer(cose_parse_fuzz)
cexchain_add_fuzzer(merkle_verify_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(protocol_parse_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(access_parse_fuzz)
cexchain_add_fuzzer(asset_parse_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(webauthn_registration_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(vm_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(contract_parse_fuzz cexchain::crypto_openssl)
# The Bo compiler's front end: everything that reads untrusted source.
if(TARGET cexchain_bo_front)
    cexchain_add_fuzzer(bo_pack_fuzz cexchain::bo_front)
    cexchain_add_fuzzer(bo_lex_fuzz cexchain::bo_front)
    cexchain_add_fuzzer(bo_parse_fuzz cexchain::bo_front)
    cexchain_add_fuzzer(bo_check_fuzz cexchain::bo_front)
endif()
# The Bo runtime's CBOR reader, in the harness module the GCC tests keep equal
# to the emitter's output (tests/bo/golden/runtime/cbor-copy.wasm). The
# emitter needs C++26 reflection (GCC only) and libFuzzer needs Clang, so the
# module's bytes are embedded here instead of generated.
set(bo_harness ${PROJECT_SOURCE_DIR}/tests/bo/golden/runtime/cbor-copy.wasm)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${bo_harness})
file(READ ${bo_harness} bo_harness_hex HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bo_harness_hex "${bo_harness_hex}")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/bo_runtime/cbor-copy.wasm.inc.new "${bo_harness_hex}\n")
configure_file(${CMAKE_CURRENT_BINARY_DIR}/bo_runtime/cbor-copy.wasm.inc.new
    ${CMAKE_CURRENT_BINARY_DIR}/bo_runtime/cbor-copy.wasm.inc COPYONLY)
cexchain_add_fuzzer(bo_runtime_fuzz cexchain::crypto_openssl)
target_include_directories(bo_runtime_fuzz PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/bo_runtime)
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
if(TARGET cexchain_bo_front)
    target_link_libraries(make_seeds PRIVATE cexchain::bo_front)
    target_compile_definitions(make_seeds PRIVATE CEXCHAIN_HAVE_BO_FRONT=1
        CEXCHAIN_BO_GOLDEN_DIR="${PROJECT_SOURCE_DIR}/tests/bo/golden")
endif()
target_compile_definitions(make_seeds PRIVATE
    CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
target_compile_features(make_seeds PRIVATE cxx_std_23)
cexchain_target_defaults(make_seeds)
