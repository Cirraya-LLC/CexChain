# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

include_guard(GLOBAL)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    message(FATAL_ERROR "CexChain currently supports GCC and Clang only (found ${CMAKE_CXX_COMPILER_ID}).")
endif()

# Apple's linker warns when a static library reaches a target through more than
# one dependency path, which is normal in a layered build.
if(APPLE)
    add_link_options(LINKER:-no_warn_duplicate_libraries)
endif()

# Sanitizers apply to every target, including third-party code, so that
# instrumented and uninstrumented code never mix.
if(CEXCHAIN_SANITIZERS)
    list(JOIN CEXCHAIN_SANITIZERS "," _cexchain_sanitizers)
    add_compile_options(-fsanitize=${_cexchain_sanitizers} -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=${_cexchain_sanitizers})
endif()

# Applies the project's warning policy to a first-party target.
function(cexchain_target_defaults target)
    set(warnings
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Woverloaded-virtual
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
        -Wunused)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        list(APPEND warnings -Wduplicated-cond -Wduplicated-branches -Wlogical-op)
    endif()
    if(CEXCHAIN_WARNINGS_AS_ERRORS)
        list(APPEND warnings -Werror)
    endif()
    target_compile_options(${target} PRIVATE ${warnings})
endfunction()
