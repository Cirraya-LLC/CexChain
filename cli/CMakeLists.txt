# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

add_executable(cexchain
    src/args.cpp
    src/bo_support.cpp
    src/cmd_access.cpp
    src/cmd_actors.cpp
    src/cmd_cluster.cpp
    src/cmd_contracts.cpp
    src/cmd_evidence.cpp
    src/cmd_general.cpp
    src/cmd_keeper.cpp
    src/cmd_keys.cpp
    src/cmd_ledger.cpp
    src/cmd_node.cpp
    src/cmd_presence.cpp
    src/cmd_qr.cpp
    src/cmd_records.cpp
    src/cmd_requests.cpp
    src/cmd_vault.cpp
    src/cmd_witness.cpp
    src/contracts.cpp
    src/main.cpp
    src/mcp.cpp
    src/output.cpp
    src/records.cpp
    src/registry.cpp
    src/requests.cpp
    src/support.cpp
    src/webauthn.cpp)
target_link_libraries(cexchain PRIVATE cexchain::ledger cexchain::node cexchain::verifier cexchain_qrcodegen nlohmann_json::nlohmann_json)
# The Bo front end, in every build: it reads a Bo deploy's source bundle, so
# contract show and contract verify can say what they can of it without the
# compiler.
target_link_libraries(cexchain PRIVATE cexchain::bo_front)
target_compile_definitions(cexchain PRIVATE CEXCHAIN_VERSION="${PROJECT_VERSION}")
target_compile_features(cexchain PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain)

# The Bo compiler's commands, when the build has it (GCC 16: C++26 reflection
# and contracts).
if(TARGET cexchain_bo)
    target_sources(cexchain PRIVATE src/cmd_bo.cpp)
    target_link_libraries(cexchain PRIVATE cexchain::bo)
    target_compile_definitions(cexchain PRIVATE CEXCHAIN_HAVE_BO=1)
endif()

# Keys on PKCS #11 tokens, when the build has them.
if(TARGET cexchain_crypto_pkcs11)
    target_link_libraries(cexchain PRIVATE cexchain::crypto_pkcs11)
    target_compile_definitions(cexchain PRIVATE CEXCHAIN_HAVE_PKCS11=1)
endif()
