# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The kanhe-console program: the web console beside a ledger's API, with
# the search index; it runs bo beside it for rules.
kanhe_program(kanhe-console
    program_console.cpp
    commands_console.cpp
    cmd_console.cpp
    cmd_certificates.cpp)
target_include_directories(kanhe-console PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kanhe-console PRIVATE kanhe_cli_chain kanhe::console kanhe::search)
