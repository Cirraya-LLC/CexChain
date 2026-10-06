# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

add_executable(cexchain
    src/args.cpp
    src/commands.cpp
    src/main.cpp
    src/mcp.cpp
    src/records.cpp
    src/support.cpp)
target_link_libraries(cexchain PRIVATE cexchain::ledger nlohmann_json::nlohmann_json)
target_compile_definitions(cexchain PRIVATE CEXCHAIN_VERSION="${PROJECT_VERSION}")
target_compile_features(cexchain PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain)
