# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The Bo compiler (D-053), in two libraries:
#   cexchain::bo_front  everything that reads untrusted text (language packs,
#                       the lexer, the parser). C++26 without reflection,
#                       contracts only through BO_PRE, BO_POST, and BO_ASSERT,
#                       so that Clang builds it too and libFuzzer can fuzz it.
#   cexchain::bo        the rest of the compiler, in C++26 with static
#                       reflection and contracts. GCC 16 builds it; Clang 23
#                       and Emscripten support neither feature yet.
# Neither is in core: a verifier needs no compiler, and core stays C++23.

include(CheckCXXSourceCompiles)

# The checks below compile as C++26. (With CMAKE_CXX_EXTENSIONS off and no
# standard set, try_compile would pass the compiler's default, -std=c++20.)
set(CMAKE_CXX_STANDARD 26)

# The official language packs are compiled in with #embed. Clang 23 calls it
# an extension in C++ (the sources silence that); a compiler without it gets
# the bytes from a file CMake writes.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/embed_probe.txt" "ab")
check_cxx_source_compiles("
static const unsigned char probe[] = {
#embed \"${CMAKE_CURRENT_BINARY_DIR}/embed_probe.txt\"
};
int main() { return sizeof probe == 2 ? 0 : 1; }" CEXCHAIN_HAVE_EMBED)

# The rest of the compiler needs C++26 static reflection and contracts.
set(CMAKE_REQUIRED_FLAGS "-freflection -fcontracts")
check_cxx_source_compiles("
#include <meta>
enum class E { a, b };
constexpr int count() pre(true) post(r: r == 2) {
    int n = 0;
    template for (constexpr auto e : std::define_static_array(std::meta::enumerators_of(^^E))) {
        n += static_cast<int>([:e:]) >= 0 ? 1 : 0;
    }
    contract_assert(n == 2);
    return n;
}
static_assert(std::meta::identifier_of(^^E) == \"E\");
int main() { return count() == 2 ? 0 : 1; }" CEXCHAIN_HAVE_REFLECTION_AND_CONTRACTS)
unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_CXX_STANDARD)

set(official_packs en zh-Hant-HK zh-Hans-CN)

add_library(cexchain_bo_front
    src/front/checker.cpp
    src/front/concepts.cpp
    src/front/explain.cpp
    src/front/format.cpp
    src/front/identifiers.cpp
    src/front/lexer.cpp
    src/front/messages.cpp
    src/front/model.cpp
    src/front/official.cpp
    src/front/pack.cpp
    src/front/pack_set.cpp
    src/front/parser.cpp
    src/front/source.cpp
    src/front/spelling.cpp
    src/front/stdlib.cpp
    src/front/values.cpp
    src/front/vocab.cpp)
add_library(cexchain::bo_front ALIAS cexchain_bo_front)
target_include_directories(cexchain_bo_front PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(cexchain_bo_front PUBLIC cexchain::core)
target_compile_features(cexchain_bo_front PUBLIC cxx_std_26)
# GCC 16 turns contracts on with -std=c++26 already; say so, for whoever reads
# the command line. Everything that includes the headers sees the same
# contracts, so the flag is public. Linking with it brings in the default
# violation handler (libstdc++exp), which prints the broken condition and
# terminates.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(cexchain_bo_front PUBLIC -fcontracts)
    target_link_options(cexchain_bo_front PUBLIC -fcontracts)
endif()
cexchain_target_defaults(cexchain_bo_front)

# Files compiled in: the official packs (and, in packs/history/, every
# earlier version), and the standard library (the core's terms and the
# vocabulary packs').
set(pack_files)
foreach(pack IN LISTS official_packs)
    list(APPEND pack_files "packs/${pack}.pack" "packs/history/${pack}-1.pack")
endforeach()
set(stdlib_files stdlib/core.bo stdlib/finance.bo stdlib/services.bo)
if(CEXCHAIN_HAVE_EMBED)
    target_compile_definitions(cexchain_bo_front PRIVATE CEXCHAIN_BO_EMBED=1)
else()
    # Without #embed: each file as a list of bytes, packs/X.pack as
    # X.pack.inc, stdlib/X.bo as X.bo.inc.
    set(generated "${CMAKE_CURRENT_BINARY_DIR}/packs")
    foreach(file IN LISTS pack_files stdlib_files)
        set(source "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
        string(REGEX REPLACE "^(packs|stdlib)/" "" name "${file}")
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
        file(READ "${source}" bytes HEX)
        string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${bytes}")
        file(WRITE "${generated}/${name}.inc" "${bytes}\n")
    endforeach()
    target_compile_definitions(cexchain_bo_front PRIVATE CEXCHAIN_BO_EMBED=0)
    target_include_directories(cexchain_bo_front PRIVATE "${generated}")
endif()
# Rebuild the embedding sources whenever a pack or the standard library changes.
list(TRANSFORM pack_files PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
list(TRANSFORM stdlib_files PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
set_source_files_properties(src/front/official.cpp PROPERTIES OBJECT_DEPENDS "${pack_files}")
set_source_files_properties(src/front/stdlib.cpp PROPERTIES OBJECT_DEPENDS "${stdlib_files}")

if(CEXCHAIN_BO STREQUAL "OFF")
    message(STATUS "Bo compiler: off (CEXCHAIN_BO=OFF); only its front end is built")
elseif(NOT CEXCHAIN_HAVE_REFLECTION_AND_CONTRACTS)
    if(CEXCHAIN_BO STREQUAL "ON")
        message(FATAL_ERROR "CEXCHAIN_BO=ON, but ${CMAKE_CXX_COMPILER} does not compile C++26 "
            "static reflection and contracts (-std=c++26 -freflection -fcontracts); use GCC 16")
    endif()
    message(STATUS "Bo compiler: not built (${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} "
        "lacks C++26 reflection or contracts); only its front end is built")
else()
    add_library(cexchain_bo
        src/build.cpp
        src/checked.cpp
        src/cost.cpp
        src/lower.cpp
        src/names.cpp
        src/runtime.cpp
        src/runtime_cbor.cpp
        src/runtime_contract.cpp
        src/runtime_math.cpp
        src/scenario.cpp
        src/tree.cpp
        src/wasm.cpp)
    add_library(cexchain::bo ALIAS cexchain_bo)
    target_link_libraries(cexchain_bo PUBLIC cexchain::bo_front)
    target_compile_options(cexchain_bo PRIVATE -freflection)
    # A deploy records the compiler's release: "cexchain-bo 0.0.1; codegen 3;
    # edition 1" (build.hpp).
    target_compile_definitions(cexchain_bo PRIVATE CEXCHAIN_BO_RELEASE="${PROJECT_VERSION}")
    cexchain_target_defaults(cexchain_bo)
    message(STATUS "Bo compiler: built (C++26 reflection and contracts)")
endif()
