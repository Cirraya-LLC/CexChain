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

# Asio (standalone, header-only, Boost Software License): networking for the
# ledger node's HTTP API and replicas.
if(NOT EMSCRIPTEN)
    FetchContent_Declare(asio
        URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-38-2.tar.gz
        URL_HASH SHA256=9f2648fa483e58a6bf848d970ee0ea650ca19ed7769dfa520ed4f7b8d27af1db
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(asio)
    find_package(Threads REQUIRED)
    add_library(cexchain_asio INTERFACE)
    target_include_directories(cexchain_asio SYSTEM INTERFACE "${asio_SOURCE_DIR}/include")
    # Frame recycling pairs aligned_alloc with operator delete in a way GCC's
    # optimized builds flag (-Wmismatched-new-delete); plain allocation costs
    # nothing that matters here.
    target_compile_definitions(cexchain_asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED
        ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING)
    target_link_libraries(cexchain_asio INTERFACE Threads::Threads)
endif()

# NuRaft (eBay, Apache-2.0): Raft for clustered nodes with automatic failover
# (D-051). Built here from its sources, with the project's compiler, standard
# library, and Asio, as a library apart: its own code is not held to the
# project's warnings, and its headers are included as system headers.
if(NOT EMSCRIPTEN)
    FetchContent_Declare(nuraft
        URL https://github.com/eBay/NuRaft/archive/refs/tags/v3.0.0.tar.gz
        URL_HASH SHA256=073c3b321efec9ce6b2bc487c283e493a1b2dd41082c5e9ac0b8f00f9b73832d
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        # Sources only: its own build would add examples, tests, and flags.
        SOURCE_SUBDIR do-not-build)
    FetchContent_MakeAvailable(nuraft)
    find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL)
    set(nuraft_sources
        asio_service buffer buffer_serializer cluster_config crc32 error_code global_mgr
        handle_append_entries handle_client_request handle_custom_notification handle_commit
        handle_join_leave handle_priority handle_snapshot_sync handle_timeout handle_user_cmd
        handle_vote launcher log_entry peer raft_server snapshot snapshot_sync_ctx
        snapshot_sync_req srv_config stat_mgr)
    list(TRANSFORM nuraft_sources PREPEND "${nuraft_SOURCE_DIR}/src/")
    list(TRANSFORM nuraft_sources APPEND ".cxx")
    add_library(cexchain_nuraft STATIC ${nuraft_sources})
    target_include_directories(cexchain_nuraft SYSTEM PUBLIC
        "${nuraft_SOURCE_DIR}/include" "${nuraft_SOURCE_DIR}/include/libnuraft")
    target_include_directories(cexchain_nuraft PRIVATE "${nuraft_SOURCE_DIR}/src")
    target_include_directories(cexchain_nuraft SYSTEM PRIVATE "${asio_SOURCE_DIR}/include")
    target_compile_definitions(cexchain_nuraft PRIVATE ASIO_STANDALONE)
    target_compile_options(cexchain_nuraft PRIVATE -w)
    target_compile_features(cexchain_nuraft PUBLIC cxx_std_17)
    target_link_libraries(cexchain_nuraft PUBLIC OpenSSL::SSL Threads::Threads)
endif()

# Nayuki's QR Code generator (MIT): QR codes that open the browser verifier.
if(NOT EMSCRIPTEN)
    FetchContent_Declare(qrcodegen
        URL https://github.com/nayuki/QR-Code-generator/archive/refs/tags/v1.8.0.tar.gz
        URL_HASH SHA256=2ec0a4d33d6f521c942eeaf473d42d5fe139abcfa57d2beffe10c5cf7d34ae60
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(qrcodegen)
    add_library(cexchain_qrcodegen STATIC "${qrcodegen_SOURCE_DIR}/cpp/qrcodegen.cpp")
    target_include_directories(cexchain_qrcodegen SYSTEM PUBLIC "${qrcodegen_SOURCE_DIR}/cpp")
    target_compile_features(cexchain_qrcodegen PUBLIC cxx_std_11)
endif()

if(CEXCHAIN_BUILD_TESTS)
    FetchContent_Declare(Catch2
        URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.16.0.tar.gz
        URL_HASH SHA256=0957cae5821b17ce07f0833aaa52b5137643a8382203221f363a8303c109af34
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        SYSTEM)
    FetchContent_MakeAvailable(Catch2)
endif()
