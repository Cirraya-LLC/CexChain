# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

add_executable(cexchain_tests
    core/cbor_test.cpp
    core/contract_bytes_test.cpp
    core/cose_test.cpp
    core/crypto_test.cpp
    core/hex_test.cpp
    core/merkle_test.cpp
    core/protocol_test.cpp
    core/protocol_v02_test.cpp
    core/protocol_v03_test.cpp
    core/protocol_v04_test.cpp
    core/protocol_v06_test.cpp
    core/protocol_v07_test.cpp
    core/protocol_v08_test.cpp
    core/protocol_v09_test.cpp
    core/vm_test.cpp
    crypto/openssl_test.cpp
    ledger/access_test.cpp
    ledger/contracts_test.cpp
    ledger/backup_test.cpp
    ledger/children_test.cpp
    ledger/requests_test.cpp
    ledger/concurrency_test.cpp
    ledger/evidence_test.cpp
    ledger/ledger_test.cpp
    ledger/parallel_test.cpp
    ledger/presence_test.cpp
    ledger/replica_test.cpp
    ledger/rotation_test.cpp
    ledger/state_tree_test.cpp
    ledger/storage_test.cpp
    ledger/verify_test.cpp
    ledger/witness_test.cpp
    node/api_test.cpp
    node/record_files_test.cpp
    node/contracts_api_test.cpp
    node/requests_api_test.cpp
    node/cluster_test.cpp
    node/connector_test.cpp
    node/connectors_test.cpp
    node/executor_test.cpp
    node/http_test.cpp
    node/keeper_api_test.cpp
    console/console_test.cpp)

target_link_libraries(cexchain_tests PRIVATE
    cexchain::console
    cexchain::core
    cexchain::crypto_openssl
    cexchain::ledger
    cexchain::node
    cexchain::verifier
    Catch2::Catch2WithMain
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto)
# Tests may reach into internal headers (e.g. ledger/src/crc32c.hpp,
# core/src/vm/internal.hpp).
target_include_directories(cexchain_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/core/src
    ${PROJECT_SOURCE_DIR}/ledger/src
    ${PROJECT_SOURCE_DIR}/node/src)
# The cluster's internals (node/src/cluster_parts.hpp) use NuRaft's headers.
target_link_libraries(cexchain_tests PRIVATE cexchain_nuraft)
target_compile_definitions(cexchain_tests PRIVATE
    CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
# The console's rules routes run the compiler as `cexchain bo ...`: the
# tests run this build's, where it has the compiler.
if(TARGET cexchain_bo AND TARGET cexchain)
    add_dependencies(cexchain_tests cexchain)
    target_compile_definitions(cexchain_tests PRIVATE
        CEXCHAIN_CLI_PROGRAM="$<TARGET_FILE:cexchain>")
endif()
target_compile_features(cexchain_tests PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain_tests)

list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)
catch_discover_tests(cexchain_tests)

# The interpreter's fuel at every instruction: a hidden case
# writes runs of vm-v1.json and bo-v1.json with less fuel than they use, and
# the independent Python interpreter must reproduce each exactly. Skipped
# where there is no Python 3.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    set(vm_fuel_file ${CMAKE_CURRENT_BINARY_DIR}/vm-fuel-reference.json)
    add_test(NAME vm_fuel_reference_runs COMMAND cexchain_tests "[.fuel-reference]")
    set_tests_properties(vm_fuel_reference_runs PROPERTIES FIXTURES_SETUP vm_fuel_reference
        ENVIRONMENT CEXCHAIN_VM_FUEL_REFERENCE=${vm_fuel_file})
    add_test(NAME vm_fuel_reference COMMAND ${Python3_EXECUTABLE}
        ${PROJECT_SOURCE_DIR}/tools/testvectors/wasm_ref.py --check ${vm_fuel_file})
    set_tests_properties(vm_fuel_reference PROPERTIES FIXTURES_REQUIRED vm_fuel_reference)
else()
    message(STATUS "vm_fuel_reference: no Python 3, so the interpreter's fuel is not checked "
        "on the Python reference interpreter")
endif()

# The Bo compiler: its front end with any compiler, the rest where it
# builds (GCC 16). Labelled "bo": the GCC ASan+UBSan configuration builds and
# runs these alone.
add_executable(cexchain_bo_tests bo/calls_test.cpp bo/check_test.cpp bo/explain_test.cpp bo/form_test.cpp bo/format_test.cpp
    bo/lexer_test.cpp
    bo/packs_test.cpp bo/parser_test.cpp bo/source_test.cpp bo/stdlib_test.cpp bo/vocab_test.cpp)
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
    target_sources(cexchain_bo_tests PRIVATE bo/build_test.cpp bo/codegen_test.cpp
        bo/finance_terms_test.cpp bo/names_test.cpp bo/runtime_harness.cpp bo/runtime_test.cpp
        bo/scenario_test.cpp bo/form_build_test.cpp)
    target_link_libraries(cexchain_bo_tests PRIVATE cexchain::bo nlohmann_json::nlohmann_json)
    target_compile_definitions(cexchain_bo_tests PRIVATE
        CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
    # The interpreter's internals (core/src/vm/internal.hpp): its measure of
    # each function's operand stack, against the emitter's.
    target_include_directories(cexchain_bo_tests PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
endif()
catch_discover_tests(cexchain_bo_tests PROPERTIES LABELS bo)

# Fuzzing lowering. cexchain::bo needs C++26 reflection (GCC) and
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

# The Bo runtime on two engines: a hidden case writes every run of
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
        # Compiled contracts: every run of the codegen tests' scenarios.
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
add_test(NAME console_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/console.sh $<TARGET_FILE:cexchain>)
add_test(NAME access_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/access.sh $<TARGET_FILE:cexchain>)
add_test(NAME contracts_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/contracts.sh $<TARGET_FILE:cexchain>)
add_test(NAME requests_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/requests.sh $<TARGET_FILE:cexchain>)
add_test(NAME keeper_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/keeper.sh $<TARGET_FILE:cexchain>)
add_test(NAME executor_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/executor.sh $<TARGET_FILE:cexchain>)
add_test(NAME files_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/files.sh $<TARGET_FILE:cexchain>)
add_test(NAME client_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/client.sh $<TARGET_FILE:cexchain>)
add_test(NAME cluster_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/cluster.sh $<TARGET_FILE:cexchain>)
# An executor as a service while the cluster's members restart.
add_test(NAME executor_cluster_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/executor_cluster.sh $<TARGET_FILE:cexchain>)
# An executor working requests at once, killed and restarted.
add_test(NAME executor_concurrency_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/executor_concurrency.sh $<TARGET_FILE:cexchain>)
# The product's own texts are generic: no industry words in help,
# completion, MCP descriptions, or the browser page.
add_test(NAME generic_words
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/generic_words.sh $<TARGET_FILE:cexchain>)
add_test(NAME rotation_end_to_end
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/rotation.sh $<TARGET_FILE:cexchain>)
# The Bo commands exist where the compiler does.
if(TARGET cexchain_bo)
    add_test(NAME bo_end_to_end
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli/bo.sh $<TARGET_FILE:cexchain>)
    # The examples library (examples/), so every example keeps working; their
    # contracts are written in Bo. A camera lent between two people.
    add_test(NAME demo_lending
        COMMAND bash ${PROJECT_SOURCE_DIR}/examples/lending/lending.sh $<TARGET_FILE:cexchain>)
    # A supply agreement signed by three organizations.
    add_test(NAME demo_supply_agreement
        COMMAND bash ${PROJECT_SOURCE_DIR}/examples/supply-agreement/supply-agreement.sh $<TARGET_FILE:cexchain>)
    # Multi-tier supply-chain finance: a receivable split down a supply chain.
    add_test(NAME demo_multi_tier_split
        COMMAND bash ${PROJECT_SOURCE_DIR}/examples/multi-tier-split/multi-tier-split.sh $<TARGET_FILE:cexchain>)
    # A receivable pledged to a bank, released, sold, and paid.
    add_test(NAME demo_receivable_financing
        COMMAND bash ${PROJECT_SOURCE_DIR}/examples/receivable-financing/receivable-financing.sh $<TARGET_FILE:cexchain>)
    # A concert ticket in the words of a vocabulary pack of one's own.
    add_test(NAME demo_events
        COMMAND bash ${PROJECT_SOURCE_DIR}/examples/events/events.sh $<TARGET_FILE:cexchain>)
    # A server rented and billed each month: a cluster with its keeper, an
    # executor with two webhooks, an AI agent through MCP, a payment by hand.
    add_test(NAME demo_idc_hosting
        COMMAND bash ${PROJECT_SOURCE_DIR}/examples/idc-hosting/idc-hosting.sh $<TARGET_FILE:cexchain>)
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
        # A shipment's chain of custody (examples/), whose driver proves
        # presence with a hardware key: SoftHSM stands in for it.
        if(TARGET cexchain_bo)
            add_test(NAME demo_shipment
                COMMAND bash ${PROJECT_SOURCE_DIR}/examples/shipment/shipment.sh $<TARGET_FILE:cexchain>)
            set_tests_properties(demo_shipment PROPERTIES
                ENVIRONMENT "PKCS11_MODULE=${CEXCHAIN_SOFTHSM_MODULE}")
        endif()
    else()
        message(STATUS "SoftHSM not found: skipping the token tests")
    endif()
endif()

# The benchmark's scenarios at a small scale, so that they keep
# working; their numbers are not checked here. Contracts are Bo builds, so
# most need the compiler.
set(bench_smoke
    "ledger\;--entries\;300\;--checkpoint-every\;100"
    "http\;--mode\;submit\;--requests\;100\;--connections\;4\;--server-threads\;1\;--client-threads\;1"
    "executor\;--requests\;3"
    "executor\;--requests\;3\;--connector\;webhook\;--concurrency\;2")
if(TARGET cexchain_bo)
    list(APPEND bench_smoke
        "contracts\;--instances\;10\;--calls\;2\;--lines\;10\;--repeat\;2"
        "evidence\;--history\;6\;--entries\;20\;--repeat\;1"
        "keeper\;--instances\;10\;--record"
        "registrar\;--instances\;4\;--calls\;2\;--client-threads\;2"
        "http\;--mode\;call\;--instances\;10\;--calls\;2\;--connections\;4\;--server-threads\;1\;--client-threads\;1"
        "http\;--mode\;create\;--requests\;20\;--connections\;4\;--server-threads\;1\;--client-threads\;1"
        "bo\;--repeat\;1")
endif()
foreach(arguments IN LISTS bench_smoke)
    # bench_SCENARIO, and _MODE for http (_CONNECTOR for the executor).
    string(REPLACE ";" "_" flat "${arguments}")
    string(REGEX REPLACE "_--.*" "" name "${flat}")
    string(REGEX MATCH "--(mode|connector)_[a-z]+" mode "${flat}")
    string(REGEX REPLACE "--(mode|connector)_" "_" mode "${mode}")
    add_test(NAME bench_${name}${mode} COMMAND cexchain-bench ${arguments})
    set_tests_properties(bench_${name}${mode} PROPERTIES LABELS bench)
endforeach()
