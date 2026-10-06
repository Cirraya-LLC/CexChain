# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The core library holds everything an independent verifier needs. It must stay
# dependency-free, portable C++23 so it can be built for WebAssembly and with any
# mainstream compiler. Do not raise its language standard.
add_library(cexchain_core
    src/bytes.cpp
    src/cbor.cpp
    src/cose.cpp
    src/crypto.cpp
    src/error.cpp
    src/hex.cpp
    src/merkle.cpp
    src/protocol/common.cpp
    src/protocol/envelope.cpp
    src/protocol/evidence.cpp
    src/protocol/log.cpp
    src/protocol/presence.cpp
    src/protocol/reader.cpp
    src/protocol/record.cpp
    src/protocol/record_types.cpp
    src/protocol/state.cpp
    src/protocol/statement.cpp
    src/protocol/witness.cpp)
add_library(cexchain::core ALIAS cexchain_core)

target_include_directories(cexchain_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_compile_features(cexchain_core PUBLIC cxx_std_23)
cexchain_target_defaults(cexchain_core)
