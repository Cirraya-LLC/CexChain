# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

cmake_minimum_required(VERSION 3.28)

project(CexChain
    VERSION 0.0.1
    DESCRIPTION "Verifiable records for business, built for the age of AI agents"
    LANGUAGES CXX)

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed. Use a preset, e.g. `cmake --preset gcc-debug`.")
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

if(EMSCRIPTEN)
    set(default_tests OFF)
else()
    set(default_tests ${PROJECT_IS_TOP_LEVEL})
endif()
option(CEXCHAIN_BUILD_TESTS "Build unit tests" ${default_tests})
option(CEXCHAIN_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(CEXCHAIN_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(CEXCHAIN_SANITIZERS "" CACHE STRING "Sanitizers to enable, e.g. \"address;undefined\"")
# The Bo compiler needs C++26 static reflection and contracts (GCC 16). AUTO
# builds it when the compiler has both; ON requires it; OFF leaves it out.
# Its front end (packs, lexer, parser) is built either way.
set(CEXCHAIN_BO "AUTO" CACHE STRING "Build the Bo compiler: AUTO, ON, or OFF")
set_property(CACHE CEXCHAIN_BO PROPERTY STRINGS AUTO ON OFF)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CexChainCompilerOptions)
include(CexChainDependencies)

add_subdirectory(core)
add_subdirectory(crypto/openssl)
add_subdirectory(verifier)
if(EMSCRIPTEN)
    # The browser verifier needs no ledger node and no command line.
    add_subdirectory(verifier/wasm)
else()
    add_subdirectory(crypto/pkcs11)
    add_subdirectory(ledger)
    add_subdirectory(node)
    # The Bo compiler: not in the browser (verifying a contract replays its
    # code; rebuilding it from source is the command line's job).
    add_subdirectory(bo)
    # The command line's actions, shared with the web console.
    add_subdirectory(app)
    # The web console's server side, which the command line serves.
    add_subdirectory(console)
    add_subdirectory(cli)
    add_subdirectory(bench)
endif()

if(CEXCHAIN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(CEXCHAIN_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
