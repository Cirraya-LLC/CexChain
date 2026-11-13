# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The shared command line, and the chain's program. Four programs, each with
# its own command table, stand on it: kanhe (here), bo (bo/cli),
# kanhe-console (apps/console/cli), and kanhe-index (apps/index/cli).
# They are written to the build's bin/ directory, side by side, as packages
# install them.

# What every program's command line shares: arguments, JSON output, the
# registry (dispatch, help, completion), and the general commands.
add_library(kanhe_cli_base STATIC
    src/args.cpp
    src/cmd_general.cpp
    src/json_output.cpp
    src/registry.cpp)
target_include_directories(kanhe_cli_base PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(kanhe_cli_base
    PUBLIC kanhe::core kanhe::crypto_openssl nlohmann_json::nlohmann_json)
target_compile_definitions(kanhe_cli_base PUBLIC KANHE_VERSION="${PROJECT_VERSION}")
target_compile_features(kanhe_cli_base PUBLIC cxx_std_26)
kanhe_target_defaults(kanhe_cli_base)

# What the chain's programs share: sessions on a ledger or a server's
# mirror (the app library), prompts and the passkey page, serving the API.
add_library(kanhe_cli_chain STATIC
    src/clock_offset.cpp
    src/contracts.cpp
    src/output.cpp
    src/records.cpp
    src/requests.cpp
    src/serve.cpp
    src/support.cpp
    src/webauthn.cpp)
target_link_libraries(kanhe_cli_chain
    PUBLIC kanhe_cli_base kanhe::client kanhe::ledger kanhe::node kanhe::verifier)
kanhe_target_defaults(kanhe_cli_chain)
# Keys on PKCS #11 tokens, when the build has them.
if(TARGET kanhe_crypto_pkcs11)
    target_link_libraries(kanhe_cli_chain PUBLIC kanhe::crypto_pkcs11)
    target_compile_definitions(kanhe_cli_chain PUBLIC KANHE_HAVE_PKCS11=1)
endif()

# A program: the shared main, and its own table and commands.
function(kanhe_program name)
    add_executable(${name} ${PROJECT_SOURCE_DIR}/chain/cli/src/main.cpp ${ARGN})
    set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    kanhe_target_defaults(${name})
endfunction()

# The chain.
kanhe_program(kanhe
    src/program_chain.cpp
    src/commands_chain.cpp
    src/cmd_access.cpp
    src/cmd_actors.cpp
    src/cmd_cluster.cpp
    src/cmd_contracts.cpp
    src/cmd_credentials.cpp
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
    src/cmd_timestamps.cpp
    src/cmd_network.cpp
    src/cmd_publish.cpp
    src/cmd_claims.cpp
    src/cmd_trust.cpp
    src/cmd_witness.cpp
    src/mcp.cpp)
target_link_libraries(kanhe PRIVATE kanhe_cli_chain kanhe_qrcodegen)
