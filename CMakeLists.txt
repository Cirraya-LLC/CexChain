# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

cmake_minimum_required(VERSION 3.28)

project(Kanhe
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
option(KANHE_BUILD_TESTS "Build unit tests" ${default_tests})
option(KANHE_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(KANHE_CORE_ONLY
    "Build only the core, its OpenSSL backend, the verifier, and their tests (Windows, so far)"
    OFF)
option(KANHE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(KANHE_SANITIZERS "" CACHE STRING "Sanitizers to enable, e.g. \"address;undefined\"")
set(KANHE_PUBLIC_WITNESSES "" CACHE STRING
    "Public witnesses offered to people: name|https://...|keyhex,... (none by default)")
# The Bo compiler needs C++26 static reflection and contracts (GCC 16). AUTO
# builds it when the compiler has both; ON requires it; OFF leaves it out.
# Its front end (packs, lexer, parser) is built either way.
set(KANHE_BO "AUTO" CACHE STRING "Build the Bo compiler: AUTO, ON, or OFF")
set_property(CACHE KANHE_BO PROPERTY STRINGS AUTO ON OFF)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(KanheCompilerOptions)
include(KanheDependencies)

# The chain: the protocol's implementation.
add_subdirectory(chain/core)
add_subdirectory(chain/crypto/openssl)
add_subdirectory(chain/verifier)
if(EMSCRIPTEN)
    # The browser verifier needs no ledger node and no command line; nor do
    # the console's checks in the browser.
    add_subdirectory(chain/verifier/wasm)
    add_subdirectory(apps/console/wasm)
elseif(NOT KANHE_CORE_ONLY)
    add_subdirectory(chain/crypto/pkcs11)
    add_subdirectory(chain/ledger)
    add_subdirectory(chain/node)
    # The chain's client library, shared by its command line and the console.
    add_subdirectory(chain/client)
    # The shared command line, and the kanhe program.
    add_subdirectory(chain/cli)
    # The Bo language: its compiler (not in the browser: verifying a contract
    # replays its code; rebuilding it from source is the bo program's job).
    add_subdirectory(bo)
    add_subdirectory(bo/cli)
    # The applications: the search index (kanhe-index) and the web
    # console (kanhe-console).
    add_subdirectory(apps/index)
    add_subdirectory(apps/index/cli)
    add_subdirectory(apps/console)
    add_subdirectory(apps/console/cli)
    add_subdirectory(bench)
endif()

if(KANHE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(KANHE_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()

# The dependency direction, the tests' included (cmake/KanheLayers.cmake).
if(NOT EMSCRIPTEN AND NOT KANHE_CORE_ONLY)
    include(KanheLayers)
    kanhe_check_layers()
endif()
