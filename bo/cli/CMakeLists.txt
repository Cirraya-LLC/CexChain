# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The bo program, when the build has the compiler (GCC 16: C++26 reflection
# and contracts). It stands on the shared command line and the chain's
# verification layer only (cmake/CexChainLayers.cmake).
if(TARGET cexchain_bo)
    cexchain_program(bo
        program_bo.cpp
        commands_bo.cpp
        bo_support.cpp
        cmd_bo.cpp
        tool_support.cpp)
    target_include_directories(bo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(bo PRIVATE cexchain_cli_base cexchain::bo cexchain::bo_front
                                     cexchain::verifier)
    target_compile_definitions(bo PRIVATE CEXCHAIN_HAVE_BO=1)
endif()
