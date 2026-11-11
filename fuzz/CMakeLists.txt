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
# Time-stamp authorities' tokens, answers, and certificate files (RFC 3161).
cexchain_add_fuzzer(timestamp_fuzz cexchain::crypto_openssl)
# Open-network witnesses' verifier keys, answers, and sizes (C2SP).
cexchain_add_fuzzer(network_parse_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(protocol_parse_fuzz cexchain::crypto_openssl cexchain::ledger)
# Claims' metadata (spec v0.14), from whoever registers a record.
cexchain_add_fuzzer(claim_fuzz)
# Memberships' metadata (spec v0.16), inside every membership proof.
cexchain_add_fuzzer(membership_fuzz)
# The state in a snapshot file, its contracts' code the v0.6 vectors' contract.
cexchain_add_fuzzer(state_snapshot_fuzz)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${PROJECT_SOURCE_DIR}/testvectors/protocol-v0.6.json)
file(READ ${PROJECT_SOURCE_DIR}/testvectors/protocol-v0.6.json protocol_v06_json)
string(JSON fuzz_test_contract GET "${protocol_v06_json}" contract)
target_compile_definitions(state_snapshot_fuzz PRIVATE
    CEXCHAIN_FUZZ_TEST_CONTRACT="${fuzz_test_contract}")
cexchain_add_fuzzer(access_parse_fuzz)
cexchain_add_fuzzer(webauthn_registration_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(vm_fuzz cexchain::crypto_openssl)
cexchain_add_fuzzer(contract_parse_fuzz cexchain::crypto_openssl cexchain::verifier
    cexchain::ledger)
# Searches and reports from untrusted query parameters, run against an index.
cexchain_add_fuzzer(search_query_fuzz cexchain::crypto_openssl cexchain::ledger cexchain::search)
target_compile_features(search_query_fuzz PRIVATE cxx_std_26)
# The check without building against the decoder, and contract outputs and
# inputs from bytes against the trees (tests/support).
cexchain_add_fuzzer(cbor_validate_fuzz)
target_include_directories(cbor_validate_fuzz PRIVATE
    ${PROJECT_SOURCE_DIR}/tests ${PROJECT_SOURCE_DIR}/chain/core/src)
# The Bo compiler's front end: everything that reads untrusted source.
if(TARGET cexchain_bo_front)
    cexchain_add_fuzzer(bo_pack_fuzz cexchain::bo_front)
    cexchain_add_fuzzer(bo_lex_fuzz cexchain::bo_front)
    cexchain_add_fuzzer(bo_parse_fuzz cexchain::bo_front)
    cexchain_add_fuzzer(bo_check_fuzz cexchain::bo_front)
    # The form that writes Bo: rules sheets, and sources read back into them.
    cexchain_add_fuzzer(bo_form_fuzz cexchain::bo_front)
    # A form's values for a contract's calls: JSON, and values Bo's lexer reads.
    cexchain_add_fuzzer(bo_calls_fuzz cexchain::bo_front)
    # A deploy's bo-source bundle, the packs it names, and .boc files.
    cexchain_add_fuzzer(bo_source_fuzz cexchain::bo_front cexchain::crypto_openssl)
    # Vocabulary pack files of users', and the CBOR a bundle embeds.
    cexchain_add_fuzzer(bo_vocab_fuzz cexchain::bo_front)
endif()
# The Bo runtime's CBOR reader, in the harness module the GCC tests keep equal
# to the emitter's output (tests/bo/golden/runtime/cbor-copy.wasm). The
# emitter needs C++26 reflection (GCC only) and libFuzzer needs Clang, so the
# module's bytes are embedded here instead of generated.
# The reader alone (read-only.wasm) shows what reading costs, against the
# bound the compiler counts (bo/include/cexchain/bo/read_bound.hpp).
foreach(bo_harness_name cbor-copy read-only)
    set(bo_harness ${PROJECT_SOURCE_DIR}/tests/bo/golden/runtime/${bo_harness_name}.wasm)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${bo_harness})
    file(READ ${bo_harness} bo_harness_hex HEX)
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bo_harness_hex "${bo_harness_hex}")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/bo_runtime/${bo_harness_name}.wasm.inc.new
        "${bo_harness_hex}\n")
    configure_file(${CMAKE_CURRENT_BINARY_DIR}/bo_runtime/${bo_harness_name}.wasm.inc.new
        ${CMAKE_CURRENT_BINARY_DIR}/bo_runtime/${bo_harness_name}.wasm.inc COPYONLY)
endforeach()
cexchain_add_fuzzer(bo_runtime_fuzz cexchain::crypto_openssl)
target_include_directories(bo_runtime_fuzz PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/bo_runtime
    ${PROJECT_SOURCE_DIR}/bo/include)
# The interpreter's internals (core/src/vm/internal.hpp), for a lower fuel limit.
target_include_directories(vm_fuzz PRIVATE ${PROJECT_SOURCE_DIR}/chain/core/src)
if(TARGET cexchain_crypto_pkcs11)
    cexchain_add_fuzzer(pkcs11_uri_fuzz cexchain::crypto_pkcs11)
endif()
if(TARGET cexchain_node)
    cexchain_add_fuzzer(http_parse_fuzz cexchain::node)
    # The requests and due routes' queries (node/src/request_query.hpp).
    target_include_directories(http_parse_fuzz PRIVATE ${PROJECT_SOURCE_DIR}/chain/node/src)
    # The connector protocol's JSON lines (node/connector.hpp).
    cexchain_add_fuzzer(connector_line_fuzz cexchain::node)
    target_compile_features(connector_line_fuzz PRIVATE cxx_std_26)
    # An executor's config and state files: journal, cursor, sealed secrets.
    cexchain_add_fuzzer(executor_state_fuzz cexchain::node cexchain::crypto_openssl)
    target_compile_features(executor_state_fuzz PRIVATE cxx_std_26)
    cexchain_add_fuzzer(backup_restore_fuzz cexchain::ledger)
    cexchain_add_fuzzer(pending_call_fuzz cexchain::node)
    # Kept files: sealed files and a submission's list of them.
    cexchain_add_fuzzer(record_files_fuzz cexchain::node)
    # Published records' files and requests to publish one.
    cexchain_add_fuzzer(published_fuzz cexchain::node)
    # Proposal and consent files (.cexchain) between ledgers.
    cexchain_add_fuzzer(exchange_file_fuzz cexchain::core)
    # Invitation codes between organizations (cxp_...).
    cexchain_add_fuzzer(invitation_fuzz cexchain::client)
    # A public witness's registrations and cosign requests, from anyone.
    cexchain_add_fuzzer(witness_registration_fuzz cexchain::client cexchain::crypto_openssl)
    # Relay messages and signed fetches, from anyone; what a mailbox holds.
    cexchain_add_fuzzer(relay_message_fuzz cexchain::client cexchain::crypto_openssl)
    # The web console's Host, Origin, and session checks (C++26, like the console).
    if(TARGET cexchain_console)
        cexchain_add_fuzzer(console_request_fuzz cexchain::console cexchain::crypto_openssl)
        target_compile_features(console_request_fuzz PRIVATE cxx_std_26)
        # Sealed backups read from a folder, and the paths a restore writes.
        cexchain_add_fuzzer(sealed_backup_fuzz cexchain::console cexchain::client)
        target_compile_features(sealed_backup_fuzz PRIVATE cxx_std_26)
        # Kind sheets from a person's page or a shared file.
        cexchain_add_fuzzer(kind_sheet_fuzz cexchain::console)
        target_compile_features(kind_sheet_fuzz PRIVATE cxx_std_26)
        # Tables of certificates and their templates, from people's files.
        cexchain_add_fuzzer(certificate_table_fuzz cexchain::console)
        target_compile_features(certificate_table_fuzz PRIVATE cxx_std_26)
    endif()
    # The cluster's internals (node/src/cluster_parts.hpp).
    cexchain_add_fuzzer(cluster_entry_fuzz cexchain::node cexchain::crypto_openssl cexchain_nuraft)
    target_include_directories(cluster_entry_fuzz PRIVATE
        ${PROJECT_SOURCE_DIR}/chain/node/src ${PROJECT_SOURCE_DIR}/chain/ledger/src)
    target_compile_features(cluster_entry_fuzz PRIVATE cxx_std_26)
endif()

# Valid inputs to start the corpora from (an ordinary program, not a fuzzer).
add_executable(make_seeds make_seeds.cpp)
target_link_libraries(make_seeds PRIVATE cexchain::ledger cexchain::crypto_openssl
    nlohmann_json::nlohmann_json OpenSSL::Crypto)
# The test time-stamp authority (tests/support).
target_include_directories(make_seeds PRIVATE ${PROJECT_SOURCE_DIR}/tests)
if(TARGET cexchain_bo_front)
    target_link_libraries(make_seeds PRIVATE cexchain::bo_front)
    target_compile_definitions(make_seeds PRIVATE CEXCHAIN_HAVE_BO_FRONT=1
        CEXCHAIN_BO_GOLDEN_DIR="${PROJECT_SOURCE_DIR}/tests/bo/golden")
endif()
target_compile_definitions(make_seeds PRIVATE
    CEXCHAIN_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors")
target_compile_features(make_seeds PRIVATE cxx_std_23)
cexchain_target_defaults(make_seeds)
