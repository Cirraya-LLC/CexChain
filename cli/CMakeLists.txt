# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

add_executable(cexchain
    src/args.cpp
    src/cmd_actors.cpp
    src/cmd_evidence.cpp
    src/cmd_general.cpp
    src/cmd_keys.cpp
    src/cmd_ledger.cpp
    src/cmd_qr.cpp
    src/cmd_records.cpp
    src/cmd_vault.cpp
    src/main.cpp
    src/mcp.cpp
    src/output.cpp
    src/records.cpp
    src/registry.cpp
    src/support.cpp)
target_link_libraries(cexchain PRIVATE cexchain::ledger cexchain::verifier cexchain_qrcodegen nlohmann_json::nlohmann_json)
target_compile_definitions(cexchain PRIVATE CEXCHAIN_VERSION="${PROJECT_VERSION}")
target_compile_features(cexchain PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain)
