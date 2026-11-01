# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The search index (C++26): what a ledger holds in the clear (records'
# types, states, registrants, times, versions, public metadata; instances'
# contracts, states, parties, fields), kept in SQLite beside the ledger and
# derived from its log, for searches and reports. It is never the ledger's
# truth and holds no private data.
add_library(cexchain_search
    src/index.cpp
    src/query.cpp
    src/sqlite.cpp)
add_library(cexchain::search ALIAS cexchain_search)
target_include_directories(cexchain_search PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(cexchain_search PUBLIC cexchain::ledger nlohmann_json::nlohmann_json
    PRIVATE cexchain_sqlite)
target_compile_features(cexchain_search PUBLIC cxx_std_26)
cexchain_target_defaults(cexchain_search)
