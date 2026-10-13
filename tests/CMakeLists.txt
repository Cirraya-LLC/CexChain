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
    core/protocol_v03_test.cpp
    core/protocol_v04_test.cpp
    core/protocol_v05_test.cpp
    core/protocol_v06_test.cpp
    core/vm_test.cpp
    crypto/openssl_test.cpp
    ledger/access_test.cpp
    ledger/assets_test.cpp
    ledger/contracts_test.cpp
    ledger/backup_test.cpp
    ledger/concurrency_test.cpp
    ledger/evidence_test.cpp
    ledger/ledger_test.cpp
    ledger/presence_test.cpp
    ledger/replica_test.cpp
    ledger/rotation_test.cpp
    ledger/state_tree_test.cpp
    ledger/storage_test.cpp
    ledger/witness_test.cpp
    node/api_test.cpp
    node/assets_api_test.cpp
    node/contracts_api_test.cpp
    node/cluster_test.cpp
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
    ${PROJECT_SOURCE_DIR}/ledger/src
    ${PROJECT_SOURCE_DIR}/node/src)
# The cluster's internals (node/src/cluster_parts.hpp) use NuRaft's headers.
target_link_libraries(cexchain_tests PRIVATE cexchain_nuraft)
target_compile_definitions(cexchain_tests PRIVATE
    CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
target_compile_features(cexchain_tests PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain_tests)

list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)
catch_discover_tests(cexchain_tests)

# The Bo compiler (D-053): its front end with any compiler, the rest where it
# builds (GCC 16). Labelled "bo": the GCC ASan+UBSan configuration builds and
# runs these alone.
add_executable(cexchain_bo_tests bo/check_test.cpp bo/lexer_test.cpp bo/packs_test.cpp
    bo/parser_test.cpp)
target_link_libraries(cexchain_bo_tests PRIVATE
    cexchain::bo_front
    cexchain::crypto_openssl
    Catch2::Catch2WithMain)
target_include_directories(cexchain_bo_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(cexchain_bo_tests PRIVATE
    CEXCHAIN_BO_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/bo/golden")
target_compile_features(cexchain_bo_tests PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain_bo_tests)
if(TARGET cexchain_bo)
    target_sources(cexchain_bo_tests PRIVATE bo/names_test.cpp)
    target_link_libraries(cexchain_bo_tests PRIVATE cexchain::bo)
endif()
catch_discover_tests(cexchain_bo_tests PROPERTIES LABELS bo)

# The command-line tool, end to end, as a user would run it.
add_test(NAME cli_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/end_to_end.sh $<TARGET_FILE:cexchain>)
add_test(NAME mcp_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/mcp.sh $<TARGET_FILE:cexchain>)
add_test(NAME serve_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/serve.sh $<TARGET_FILE:cexchain>)
add_test(NAME access_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/access.sh $<TARGET_FILE:cexchain>)
add_test(NAME assets_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/assets.sh $<TARGET_FILE:cexchain>)
add_test(NAME contracts_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/contracts.sh $<TARGET_FILE:cexchain>)
# The demos, so they keep working.
add_test(NAME demo_supply_chain_finance
    COMMAND bash ${PROJECT_SOURCE_DIR}/deploy/demo/supply-chain-finance.sh $<TARGET_FILE:cexchain>)
add_test(NAME demo_supply_agreement
    COMMAND bash ${PROJECT_SOURCE_DIR}/deploy/demo/supply-agreement.sh $<TARGET_FILE:cexchain>)
add_test(NAME client_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/client.sh $<TARGET_FILE:cexchain>)
add_test(NAME cluster_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/cluster.sh $<TARGET_FILE:cexchain>)
add_test(NAME rotation_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/rotation.sh $<TARGET_FILE:cexchain>)
# The Bo commands exist where the compiler does.
if(TARGET cexchain_bo)
    add_test(NAME bo_end_to_end
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/bo.sh $<TARGET_FILE:cexchain>)
endif()

# Keys on tokens (HSMs, USB keys), when SoftHSM is installed to stand in.
if(TARGET cexchain_crypto_pkcs11)
    target_sources(cexchain_tests PRIVATE crypto/pkcs11_uri_test.cpp)
    target_link_libraries(cexchain_tests PRIVATE cexchain::crypto_pkcs11)
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
