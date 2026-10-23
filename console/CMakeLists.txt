# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The web console's server side (C++26): the page's files, compiled into the
# binary, the headers every answer carries, and the Host and Origin checks.
# The node serves it beside its API through a hook (ApiOptions::console), so
# the node does not depend on this library.
add_library(cexchain_console src/console.cpp src/passkeys.cpp src/sessions.cpp src/users.cpp src/views.cpp)
add_library(cexchain::console ALIAS cexchain_console)
target_include_directories(cexchain_console PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(cexchain_console
    PUBLIC cexchain::app cexchain::node nlohmann_json::nlohmann_json)
target_compile_features(cexchain_console PUBLIC cxx_std_26)
cexchain_target_defaults(cexchain_console)

# The page's files are compiled in with #embed where the compiler has it
# (bo/ probes for it), and otherwise from byte lists CMake writes.
set(web_files web/index.html web/console.css web/console.js web/i18n/en.json
    web/i18n/zh-Hant-HK.json web/i18n/zh-Hans-CN.json)
if(CEXCHAIN_HAVE_EMBED)
    target_compile_definitions(cexchain_console PRIVATE CEXCHAIN_CONSOLE_EMBED=1)
else()
    set(generated "${CMAKE_CURRENT_BINARY_DIR}/web")
    foreach(file IN LISTS web_files)
        set(source "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
        get_filename_component(name "${file}" NAME)
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
        file(READ "${source}" bytes HEX)
        string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${bytes}")
        file(WRITE "${generated}/${name}.inc" "${bytes}\n")
    endforeach()
    target_compile_definitions(cexchain_console PRIVATE CEXCHAIN_CONSOLE_EMBED=0)
    target_include_directories(cexchain_console PRIVATE "${generated}")
endif()
list(TRANSFORM web_files PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
set_source_files_properties(src/console.cpp PROPERTIES OBJECT_DEPENDS "${web_files}")
