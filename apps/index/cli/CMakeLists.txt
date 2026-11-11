# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The kanhe-index program: searches, reports, and a read-only server of a
# ledger with its index.
kanhe_program(kanhe-index
    program_index.cpp
    commands_index.cpp
    cmd_search.cpp)
target_include_directories(kanhe-index PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kanhe-index PRIVATE kanhe_cli_chain kanhe::search)
