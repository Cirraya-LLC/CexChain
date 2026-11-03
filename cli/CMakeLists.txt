# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Four programs, each with its own command table on one shared command line:
# cexchain (the chain), bo (the Bo language), cexchain-console (the web
# console), and cexchain-index (searches and reports). They are written to
# the build's bin/ directory, side by side, as packages install them.

# What every program's command line shares: arguments, JSON output, the
# registry (dispatch, help, completion), and the general commands.
add_library(cexchain_cli_base STATIC
    src/args.cpp
    src/cmd_general.cpp
    src/json_output.cpp
    src/registry.cpp)
target_include_directories(cexchain_cli_base PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(cexchain_cli_base
    PUBLIC cexchain::core cexchain::crypto_openssl nlohmann_json::nlohmann_json)
target_compile_definitions(cexchain_cli_base PUBLIC CEXCHAIN_VERSION="${PROJECT_VERSION}")
target_compile_features(cexchain_cli_base PUBLIC cxx_std_26)
cexchain_target_defaults(cexchain_cli_base)

# What the chain's programs share: sessions on a ledger or a server's
# mirror (the app library), prompts and the passkey page, serving the API.
add_library(cexchain_cli_chain STATIC
    src/clock_offset.cpp
    src/contracts.cpp
    src/output.cpp
    src/records.cpp
    src/requests.cpp
    src/serve.cpp
    src/support.cpp
    src/webauthn.cpp)
target_link_libraries(cexchain_cli_chain
    PUBLIC cexchain_cli_base cexchain::app cexchain::ledger cexchain::node cexchain::verifier)
cexchain_target_defaults(cexchain_cli_chain)
# Keys on PKCS #11 tokens, when the build has them.
if(TARGET cexchain_crypto_pkcs11)
    target_link_libraries(cexchain_cli_chain PUBLIC cexchain::crypto_pkcs11)
    target_compile_definitions(cexchain_cli_chain PUBLIC CEXCHAIN_HAVE_PKCS11=1)
endif()

function(cexchain_program name)
    add_executable(${name} src/main.cpp ${ARGN})
    set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    cexchain_target_defaults(${name})
endfunction()

# The chain.
cexchain_program(cexchain
    src/program_chain.cpp
    src/commands_chain.cpp
    src/cmd_access.cpp
    src/cmd_actors.cpp
    src/cmd_cluster.cpp
    src/cmd_contracts.cpp
    src/cmd_evidence.cpp
    src/cmd_executor.cpp
    src/cmd_keeper.cpp
    src/cmd_keys.cpp
    src/cmd_ledger.cpp
    src/cmd_node.cpp
    src/cmd_presence.cpp
    src/cmd_qr.cpp
    src/cmd_records.cpp
    src/cmd_relay.cpp
    src/cmd_requests.cpp
    src/cmd_vault.cpp
    src/cmd_witness.cpp
    src/mcp.cpp)
target_link_libraries(cexchain PRIVATE cexchain_cli_chain cexchain_qrcodegen)

# The web console, with the search index beside its ledger.
if(TARGET cexchain_console)
    cexchain_program(cexchain-console
        src/program_console.cpp
        src/commands_console.cpp
        src/cmd_console.cpp)
    target_link_libraries(cexchain-console PRIVATE cexchain_cli_chain cexchain::console
                                                   cexchain::search)
endif()

# Searches and reports.
cexchain_program(cexchain-index
    src/program_index.cpp
    src/commands_index.cpp
    src/cmd_search.cpp)
target_link_libraries(cexchain-index PRIVATE cexchain_cli_chain cexchain::search)

# The Bo language, when the build has its compiler (GCC 16: C++26
# reflection and contracts).
if(TARGET cexchain_bo)
    cexchain_program(bo
        src/program_bo.cpp
        src/commands_bo.cpp
        src/bo_support.cpp
        src/cmd_bo.cpp
        src/tool_support.cpp)
    target_link_libraries(bo PRIVATE cexchain_cli_base cexchain::bo cexchain::bo_front
                                     cexchain::verifier)
    target_compile_definitions(bo PRIVATE CEXCHAIN_HAVE_BO=1)
endif()
