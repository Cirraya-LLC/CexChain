# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The cexchain-index program: searches, reports, and a read-only server of a
# ledger with its index.
cexchain_program(cexchain-index
    program_index.cpp
    commands_index.cpp
    cmd_search.cpp)
target_include_directories(cexchain-index PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cexchain-index PRIVATE cexchain_cli_chain cexchain::search)
