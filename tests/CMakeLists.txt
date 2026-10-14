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
    core/protocol_v07_test.cpp
    core/vm_test.cpp
    crypto/openssl_test.cpp
    ledger/access_test.cpp
    ledger/assets_test.cpp
    ledger/contracts_test.cpp
    ledger/backup_test.cpp
    ledger/children_test.cpp
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
add_executable(cexchain_bo_tests bo/check_test.cpp bo/explain_test.cpp bo/format_test.cpp
    bo/lexer_test.cpp
    bo/packs_test.cpp bo/parser_test.cpp bo/source_test.cpp bo/stdlib_test.cpp)
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
    target_sources(cexchain_bo_tests PRIVATE bo/assets_test.cpp bo/build_test.cpp bo/codegen_test.cpp
        bo/names_test.cpp bo/runtime_harness.cpp bo/runtime_test.cpp bo/scenario_test.cpp)
    target_link_libraries(cexchain_bo_tests PRIVATE cexchain::bo nlohmann_json::nlohmann_json)
    target_compile_definitions(cexchain_bo_tests PRIVATE
        CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
    # The interpreter's internals (core/src/vm/internal.hpp): its measure of
    # each function's operand stack, against the emitter's.
    target_include_directories(cexchain_bo_tests PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
endif()
catch_discover_tests(cexchain_bo_tests PROPERTIES LABELS bo)

# Fuzzing lowering (D-053, M6). cexchain::bo needs C++26 reflection (GCC) and
# libFuzzer needs Clang, so bo_build_fuzz is built here with GCC and drives
# itself from a contract generator (fuzz/bo_build_fuzz.cpp says how); CTest
# runs a short round of it, under ASan and UBSan in gcc-asan.
if(TARGET cexchain_bo)
    add_executable(bo_build_fuzz ${PROJECT_SOURCE_DIR}/fuzz/bo_build_fuzz.cpp)
    target_link_libraries(bo_build_fuzz PRIVATE cexchain::bo cexchain::crypto_openssl)
    target_compile_definitions(bo_build_fuzz PRIVATE CEXCHAIN_BO_FUZZ_DRIVER=1
        CEXCHAIN_BO_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/bo/golden")
    target_compile_features(bo_build_fuzz PRIVATE cxx_std_26)
    cexchain_target_defaults(bo_build_fuzz)
    add_test(NAME bo_build_fuzz COMMAND bo_build_fuzz -runs=400 -seed=6)
    set_tests_properties(bo_build_fuzz PROPERTIES LABELS bo)
endif()

# The Bo runtime on two engines (D-053, M5): a hidden case writes every run of
# the runtime's harness modules (module, input, outcome, output, fuel), and
# the independent Python interpreter must reproduce each exactly. Skipped
# where there is no Python 3 (it needs the standard library only).
if(TARGET cexchain_bo)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        set(bo_reference_file ${CMAKE_CURRENT_BINARY_DIR}/bo-reference.json)
        add_test(NAME bo_reference_runs COMMAND cexchain_bo_tests "[.reference]")
        set_tests_properties(bo_reference_runs PROPERTIES LABELS bo
            FIXTURES_SETUP bo_reference ENVIRONMENT CEXCHAIN_BO_REFERENCE=${bo_reference_file})
        add_test(NAME bo_reference COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tools/testvectors/wasm_ref.py --check ${bo_reference_file})
        set_tests_properties(bo_reference PROPERTIES LABELS bo FIXTURES_REQUIRED bo_reference)
        # Compiled contracts (M6): every run of the codegen tests' scenarios.
        set(bo_codegen_file ${CMAKE_CURRENT_BINARY_DIR}/bo-codegen-reference.json)
        add_test(NAME bo_codegen_reference_runs COMMAND cexchain_bo_tests "[.codegen-reference]")
        set_tests_properties(bo_codegen_reference_runs PROPERTIES LABELS bo
            FIXTURES_SETUP bo_codegen_reference
            ENVIRONMENT CEXCHAIN_BO_CODEGEN_REFERENCE=${bo_codegen_file})
        add_test(NAME bo_codegen_reference COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tools/testvectors/wasm_ref.py --check ${bo_codegen_file})
        set_tests_properties(bo_codegen_reference PROPERTIES LABELS bo
            FIXTURES_REQUIRED bo_codegen_reference)
    else()
        message(STATUS "bo_reference: no Python 3, so the runtime is not checked on the "
            "Python reference interpreter")
    endif()
endif()

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
    # The contract demo is written in Bo.
    add_test(NAME demo_supply_agreement
        COMMAND bash ${PROJECT_SOURCE_DIR}/deploy/demo/supply-agreement.sh $<TARGET_FILE:cexchain>)
    # Multi-tier supply-chain finance: a receivable split down a supply chain.
    add_test(NAME demo_multi_tier_split
        COMMAND bash ${PROJECT_SOURCE_DIR}/deploy/demo/multi-tier-split.sh $<TARGET_FILE:cexchain>)
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
