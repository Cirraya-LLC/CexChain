# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The web console's server side (C++26): the page's files, compiled into the
# binary, the headers every answer carries, and the Host and Origin checks.
# The node serves it beside its API through a hook (ApiOptions::console), so
# the node does not depend on this library.
add_library(kanhe_console src/console.cpp src/passkeys.cpp src/sessions.cpp src/users.cpp src/views.cpp src/keystore.cpp src/unlock.cpp src/approve.cpp src/setup.cpp src/deferred.cpp src/recover.cpp src/settings.cpp src/kinds.cpp src/documents.cpp
    src/access.cpp src/exchange.cpp src/instances.cpp src/parties.cpp src/things.cpp src/search.cpp src/rules.cpp src/witnessing.cpp src/relaying.cpp
    src/people.cpp src/activity.cpp src/qr.cpp src/certificates.cpp src/certifying.cpp src/claiming.cpp src/automation.cpp
    src/backups.cpp)
add_library(kanhe::console ALIAS kanhe_console)
target_include_directories(kanhe_console PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(kanhe_console
    PUBLIC kanhe::client kanhe::bo_front kanhe::node kanhe::search
           nlohmann_json::nlohmann_json
    PRIVATE kanhe_qrcodegen)
target_compile_features(kanhe_console PUBLIC cxx_std_26)
kanhe_target_defaults(kanhe_console)

# The page's files are compiled in with #embed where the compiler has it
# (bo/ probes for it), and otherwise from byte lists CMake writes.
set(web_files web/index.html web/console.css web/console.js web/i18n/en.json
    web/i18n/zh-Hant-HK.json web/i18n/zh-Hans-CN.json)
if(KANHE_HAVE_EMBED)
    target_compile_definitions(kanhe_console PRIVATE KANHE_CONSOLE_EMBED=1)
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
    target_compile_definitions(kanhe_console PRIVATE KANHE_CONSOLE_EMBED=0)
    target_include_directories(kanhe_console PRIVATE "${generated}")
endif()
list(TRANSFORM web_files PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
set_source_files_properties(src/console.cpp PROPERTIES OBJECT_DEPENDS "${web_files}")

# The console's checks in the browser, built by tools/wasm/build.sh: embedded
# when KANHE_CONSOLE_WASM_DIR names a directory holding them. Without them
# the console works, and its page says that its approvals are checked by the
# console only.
set(KANHE_CONSOLE_WASM_DIR "" CACHE PATH
    "Directory with kanhe-console.mjs and kanhe-console.wasm (tools/wasm/build.sh)")
set(console_wasm OFF)
if(KANHE_CONSOLE_WASM_DIR AND KANHE_HAVE_EMBED)
    set(wasm_js "${KANHE_CONSOLE_WASM_DIR}/kanhe-console.mjs")
    set(wasm_bin "${KANHE_CONSOLE_WASM_DIR}/kanhe-console.wasm")
    if(EXISTS "${wasm_js}" AND EXISTS "${wasm_bin}")
        configure_file("${wasm_js}" "${CMAKE_CURRENT_BINARY_DIR}/wasm/kanhe-console.mjs" COPYONLY)
        configure_file("${wasm_bin}" "${CMAKE_CURRENT_BINARY_DIR}/wasm/kanhe-console.wasm" COPYONLY)
        # #embed looks in --embed-dir directories, not in include directories.
        target_compile_options(kanhe_console PRIVATE
            "--embed-dir=${CMAKE_CURRENT_BINARY_DIR}/wasm")
        set(console_wasm ON)
    else()
        message(WARNING "KANHE_CONSOLE_WASM_DIR has no kanhe-console.mjs and .wasm")
    endif()
endif()
if(console_wasm)
    target_compile_definitions(kanhe_console PRIVATE KANHE_CONSOLE_WASM=1)
    message(STATUS "Console: with its checks in the browser (${KANHE_CONSOLE_WASM_DIR})")
else()
    target_compile_definitions(kanhe_console PRIVATE KANHE_CONSOLE_WASM=0)
endif()
