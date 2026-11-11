# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The ledger node: storage, state, and the registration engine. It may use
# C++26; code that verifiers need belongs in core instead.
add_library(kanhe_ledger
    src/backup.cpp
    src/crc32c.cpp
    src/environment.cpp
    src/ledger.cpp
    src/parallel.cpp
    src/record_log.cpp
    src/storage.cpp
    src/verify.cpp)
add_library(kanhe::ledger ALIAS kanhe_ledger)

target_include_directories(kanhe_ledger PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
find_package(Threads REQUIRED)
target_link_libraries(kanhe_ledger PUBLIC kanhe::core kanhe::crypto_openssl
    PRIVATE Threads::Threads)
target_compile_features(kanhe_ledger PUBLIC cxx_std_26)
kanhe_target_defaults(kanhe_ledger)
