# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The cexchain-console program: the web console beside a ledger's API, with
# the search index; it runs bo beside it for rules.
cexchain_program(cexchain-console
    program_console.cpp
    commands_console.cpp
    cmd_console.cpp
    cmd_certificates.cpp)
target_include_directories(cexchain-console PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cexchain-console PRIVATE cexchain_cli_chain cexchain::console cexchain::search)
