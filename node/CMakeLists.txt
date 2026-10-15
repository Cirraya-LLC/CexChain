# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The ledger node: the HTTP API, replicas, and backups (C++26).
find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL)

add_library(cexchain_node
    src/api.cpp
    src/client.cpp
    src/contracts.cpp
    src/cluster.cpp
    src/files.cpp
    src/http.cpp
    src/peers.cpp
    src/replica.cpp
    src/request_query.cpp
    src/server.cpp
    src/tokens.cpp)
add_library(cexchain::node ALIAS cexchain_node)
target_include_directories(cexchain_node PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(cexchain_node
    PUBLIC cexchain::ledger
    PRIVATE cexchain_asio cexchain_nuraft OpenSSL::SSL nlohmann_json::nlohmann_json)
# The ledger's record checksum, for the Raft log.
target_include_directories(cexchain_node PRIVATE "${PROJECT_SOURCE_DIR}/ledger/src")
target_compile_features(cexchain_node PUBLIC cxx_std_26)
cexchain_target_defaults(cexchain_node)
