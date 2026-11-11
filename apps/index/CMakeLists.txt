# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The search index (C++26): what a ledger holds in the clear (records'
# types, states, registrants, times, versions, public metadata; instances'
# contracts, states, parties, fields), kept in SQLite beside the ledger and
# derived from its log, for searches and reports. It is never the ledger's
# truth and holds no private data. Served beside a ledger as an extension of
# its server (served.hpp).
add_library(kanhe_search
    src/index.cpp
    src/query.cpp
    src/served.cpp
    src/sqlite.cpp)
add_library(kanhe::search ALIAS kanhe_search)
target_include_directories(kanhe_search PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(kanhe_search PUBLIC kanhe::ledger kanhe::node nlohmann_json::nlohmann_json
    PRIVATE kanhe_sqlite)
target_compile_features(kanhe_search PUBLIC cxx_std_26)
kanhe_target_defaults(kanhe_search)
