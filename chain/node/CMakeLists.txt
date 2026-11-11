# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The ledger node: the HTTP API, replicas, and backups (C++26).
find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL)

add_library(kanhe_node
    src/api.cpp
    src/client.cpp
    src/contracts.cpp
    src/record_files.cpp
    src/cluster.cpp
    src/executor.cpp
    src/connector.cpp
    src/connectors.cpp
    src/files.cpp
    src/http.cpp
    src/keeper.cpp
    src/peers.cpp
    src/process.cpp
    src/published.cpp
    src/trust.cpp
    src/replica.cpp
    src/request_query.cpp
    src/server.cpp
    src/timestamps.cpp
    src/network_witnesses.cpp
    src/responses.cpp
    src/tokens.cpp)
add_library(kanhe::node ALIAS kanhe_node)
target_include_directories(kanhe_node PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(kanhe_node
    PUBLIC kanhe::ledger nlohmann_json::nlohmann_json
    PRIVATE kanhe_asio kanhe_nuraft OpenSSL::SSL)
# The ledger's record checksum, for the Raft log.
target_include_directories(kanhe_node PRIVATE "${PROJECT_SOURCE_DIR}/chain/ledger/src")
target_compile_features(kanhe_node PUBLIC cxx_std_26)
kanhe_target_defaults(kanhe_node)
