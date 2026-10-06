# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

include_guard(GLOBAL)
include(FetchContent)

# OpenSSL 3.5+ provides every algorithm family CexChain needs in one library:
# SHA-2, SM3, Ed25519, ECDSA P-256, SM2, and ML-DSA.
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
endif()
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

# Build-time dependencies come from pinned, hash-verified sources and are built
# with the same compiler and standard library as the project.

# nlohmann/json (header-only): JSON for the MCP server and test vectors.
FetchContent_Declare(nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SYSTEM)
FetchContent_MakeAvailable(nlohmann_json)

if(CEXCHAIN_BUILD_TESTS)
    FetchContent_Declare(Catch2
        URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.16.0.tar.gz
        URL_HASH SHA256=0957cae5821b17ce07f0833aaa52b5137643a8382203221f363a8303c109af34
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        SYSTEM)
    FetchContent_MakeAvailable(Catch2)
endif()
