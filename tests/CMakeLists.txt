# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

add_executable(cexchain_tests
    core/cbor_test.cpp
    core/cose_test.cpp
    core/crypto_test.cpp
    core/hex_test.cpp
    core/merkle_test.cpp
    core/protocol_test.cpp
    core/protocol_v02_test.cpp
    crypto/openssl_test.cpp
    ledger/backup_test.cpp
    ledger/evidence_test.cpp
    ledger/ledger_test.cpp
    ledger/presence_test.cpp
    ledger/replica_test.cpp
    ledger/state_tree_test.cpp
    ledger/storage_test.cpp
    ledger/witness_test.cpp
    node/api_test.cpp
    node/http_test.cpp)

target_link_libraries(cexchain_tests PRIVATE
    cexchain::core
    cexchain::crypto_openssl
    cexchain::ledger
    cexchain::node
    Catch2::Catch2WithMain
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto)
# Tests may reach into internal headers (e.g. ledger/src/crc32c.hpp).
target_include_directories(cexchain_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/ledger/src)
target_compile_definitions(cexchain_tests PRIVATE
    CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
target_compile_features(cexchain_tests PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain_tests)

list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)
catch_discover_tests(cexchain_tests)

# The command-line tool, end to end, as a user would run it.
add_test(NAME cli_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/end_to_end.sh $<TARGET_FILE:cexchain>)
add_test(NAME mcp_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/mcp.sh $<TARGET_FILE:cexchain>)
add_test(NAME serve_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/serve.sh $<TARGET_FILE:cexchain>)

# Keys on tokens (HSMs, USB keys), when SoftHSM is installed to stand in.
if(TARGET cexchain_crypto_pkcs11)
    find_program(CEXCHAIN_SOFTHSM_UTIL softhsm2-util)
    find_file(CEXCHAIN_SOFTHSM_MODULE libsofthsm2.so
        PATHS /usr/lib/softhsm /usr/local/lib/softhsm /opt/homebrew/lib/softhsm
              /usr/lib/x86_64-linux-gnu/softhsm /usr/lib/aarch64-linux-gnu/softhsm
        NO_DEFAULT_PATH)
    if(CEXCHAIN_SOFTHSM_UTIL AND CEXCHAIN_SOFTHSM_MODULE)
        add_test(NAME cli_pkcs11
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/pkcs11.sh $<TARGET_FILE:cexchain>
                    ${CEXCHAIN_SOFTHSM_MODULE})
    else()
        message(STATUS "SoftHSM not found: skipping the token tests")
    endif()
endif()
