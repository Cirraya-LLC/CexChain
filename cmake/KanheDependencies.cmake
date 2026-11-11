# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

include_guard(GLOBAL)
include(FetchContent)

# OpenSSL 3.5+ provides every algorithm family Kanhe needs in one library:
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
if(NOT EMSCRIPTEN AND NOT KANHE_CORE_ONLY)
    FetchContent_Declare(asio
        URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-38-2.tar.gz
        URL_HASH SHA256=9f2648fa483e58a6bf848d970ee0ea650ca19ed7769dfa520ed4f7b8d27af1db
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(asio)
    find_package(Threads REQUIRED)
    add_library(kanhe_asio INTERFACE)
    target_include_directories(kanhe_asio SYSTEM INTERFACE "${asio_SOURCE_DIR}/include")
    # Frame recycling pairs aligned_alloc with operator delete in a way GCC's
    # optimized builds flag (-Wmismatched-new-delete); plain allocation costs
    # nothing that matters here.
    target_compile_definitions(kanhe_asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED
        ASIO_DISABLE_AWAITABLE_FRAME_RECYCLING)
    target_link_libraries(kanhe_asio INTERFACE Threads::Threads)
endif()

# NuRaft (eBay, Apache-2.0): Raft for clustered nodes with automatic failover.
# Built here from its sources, with the project's compiler, standard
# library, and Asio, as a library apart: its own code is not held to the
# project's warnings, and its headers are included as system headers.
if(NOT EMSCRIPTEN AND NOT KANHE_CORE_ONLY)
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
    add_library(kanhe_nuraft STATIC ${nuraft_sources})
    target_include_directories(kanhe_nuraft SYSTEM PUBLIC
        "${nuraft_SOURCE_DIR}/include" "${nuraft_SOURCE_DIR}/include/libnuraft")
    target_include_directories(kanhe_nuraft PRIVATE "${nuraft_SOURCE_DIR}/src")
    target_include_directories(kanhe_nuraft SYSTEM PRIVATE "${asio_SOURCE_DIR}/include")
    target_compile_definitions(kanhe_nuraft PRIVATE ASIO_STANDALONE)
    target_compile_options(kanhe_nuraft PRIVATE -w)
    target_compile_features(kanhe_nuraft PUBLIC cxx_std_17)
    target_link_libraries(kanhe_nuraft PUBLIC OpenSSL::SSL Threads::Threads)
endif()

# Nayuki's QR Code generator (MIT): QR codes that open the browser verifier.
if(NOT EMSCRIPTEN AND NOT KANHE_CORE_ONLY)
    FetchContent_Declare(qrcodegen
        URL https://github.com/nayuki/QR-Code-generator/archive/refs/tags/v1.8.0.tar.gz
        URL_HASH SHA256=2ec0a4d33d6f521c942eeaf473d42d5fe139abcfa57d2beffe10c5cf7d34ae60
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(qrcodegen)
    add_library(kanhe_qrcodegen STATIC "${qrcodegen_SOURCE_DIR}/cpp/qrcodegen.cpp")
    target_include_directories(kanhe_qrcodegen SYSTEM PUBLIC "${qrcodegen_SOURCE_DIR}/cpp")
    target_compile_features(kanhe_qrcodegen PUBLIC cxx_std_11)
endif()

# SQLite (public domain): the search index, derived from the log and
# rebuilt from it at will (never the ledger's truth). The amalgamation, built
# here as a C library with FTS5 (text search, its trigram tokenizer for
# Chinese), and none of the project's warnings.
if(NOT EMSCRIPTEN AND NOT KANHE_CORE_ONLY)
    # The C compiler of the C++ compiler's family (clang++-23 with clang-23,
    # g++-16 with gcc-16), so that sanitizers and libFuzzer flags fit both.
    if(NOT CMAKE_C_COMPILER AND NOT DEFINED ENV{CC})
        get_filename_component(_kanhe_cxx "${CMAKE_CXX_COMPILER}" NAME)
        get_filename_component(_kanhe_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
        string(REGEX REPLACE "clang\\+\\+" "clang" _kanhe_c "${_kanhe_cxx}")
        string(REGEX REPLACE "g\\+\\+" "gcc" _kanhe_c "${_kanhe_c}")
        string(REGEX REPLACE "^c\\+\\+" "cc" _kanhe_c "${_kanhe_c}")
        if(_kanhe_dir AND EXISTS "${_kanhe_dir}/${_kanhe_c}")
            set(CMAKE_C_COMPILER "${_kanhe_dir}/${_kanhe_c}")
        endif()
    endif()
    enable_language(C)
    FetchContent_Declare(sqlite
        URL https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
        URL_HASH SHA3_256=92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(sqlite)
    add_library(kanhe_sqlite STATIC "${sqlite_SOURCE_DIR}/sqlite3.c")
    target_include_directories(kanhe_sqlite SYSTEM PUBLIC "${sqlite_SOURCE_DIR}")
    target_compile_definitions(kanhe_sqlite PRIVATE
        SQLITE_ENABLE_FTS5 SQLITE_THREADSAFE=1 SQLITE_DQS=0 SQLITE_OMIT_LOAD_EXTENSION
        SQLITE_DEFAULT_WAL_SYNCHRONOUS=1 SQLITE_LIKE_DOESNT_MATCH_BLOBS
        SQLITE_OMIT_DEPRECATED SQLITE_OMIT_SHARED_CACHE SQLITE_USE_ALLOCA
        SQLITE_DEFAULT_MEMSTATUS=0)
    target_compile_options(kanhe_sqlite PRIVATE -w)
    find_package(Threads REQUIRED)
    target_link_libraries(kanhe_sqlite PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
    if(UNIX AND NOT APPLE)
        target_link_libraries(kanhe_sqlite PUBLIC m)
    endif()
endif()

if(KANHE_BUILD_TESTS)
    FetchContent_Declare(Catch2
        URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.16.0.tar.gz
        URL_HASH SHA256=0957cae5821b17ce07f0833aaa52b5137643a8382203221f363a8303c109af34
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        SYSTEM)
    FetchContent_MakeAvailable(Catch2)
endif()
