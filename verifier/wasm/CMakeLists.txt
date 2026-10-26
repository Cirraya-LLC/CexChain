# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The browser verifier: core, the OpenSSL provider, and report rendering
# compiled to WebAssembly, then packaged into one self-contained HTML page
# (cexchain-verify.html) that works offline, even when opened from disk.
add_executable(cexchain_verifier_wasm verifier_wasm.cpp)
set_target_properties(cexchain_verifier_wasm PROPERTIES OUTPUT_NAME cexchain-verifier SUFFIX ".js")
target_link_libraries(cexchain_verifier_wasm PRIVATE cexchain::verifier cexchain::crypto_openssl)
target_compile_definitions(cexchain_verifier_wasm PRIVATE CEXCHAIN_VERSION="${PROJECT_VERSION}")
target_compile_features(cexchain_verifier_wasm PRIVATE cxx_std_23)
target_link_options(cexchain_verifier_wasm PRIVATE
    -sMODULARIZE=1
    -sEXPORT_NAME=CexChainVerifier
    -sSINGLE_FILE=1
    # Base64, not the default binary-in-UTF-8 string: the page must stay pure
    # ASCII to survive being emailed, re-encoded, or served without a charset.
    -sSINGLE_FILE_BINARY_ENCODE=0
    -sENVIRONMENT=web,node
    -sALLOW_MEMORY_GROWTH=1
    -sDYNAMIC_EXECUTION=0
    -sFILESYSTEM=0
    "-sEXPORTED_FUNCTIONS=_malloc,_free,_cexchain_version,_cexchain_reset,_cexchain_set_expected_ledger,_cexchain_add_witness,_cexchain_add_attachment,_cexchain_verify,_cexchain_free"
    "-sEXPORTED_RUNTIME_METHODS=HEAPU8,UTF8ToString,stringToUTF8,lengthBytesUTF8")

set(page "${CMAKE_CURRENT_BINARY_DIR}/cexchain-verify.html")
add_custom_command(
    OUTPUT "${page}"
    COMMAND "${CMAKE_COMMAND}"
        "-DMODULE=$<TARGET_FILE:cexchain_verifier_wasm>"
        "-DAPI=${CMAKE_CURRENT_SOURCE_DIR}/verifier-api.js"
        "-DTEMPLATE=${CMAKE_CURRENT_SOURCE_DIR}/page.html"
        "-DOUT=${page}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/assemble.cmake"
    DEPENDS cexchain_verifier_wasm verifier-api.js page.html assemble.cmake
    COMMENT "Assembling cexchain-verify.html")
add_custom_target(cexchain_verify_page ALL DEPENDS "${page}")

# The web console's checks in the browser (decoding a payload, computing its
# presence challenge): an ES module and a separate .wasm file, which a native
# build embeds in the console when CEXCHAIN_CONSOLE_WASM_DIR names them.
add_executable(cexchain_console_wasm console_wasm.cpp)
set_target_properties(cexchain_console_wasm PROPERTIES OUTPUT_NAME cexchain-console SUFFIX ".mjs")
target_link_libraries(cexchain_console_wasm PRIVATE cexchain::verifier cexchain::crypto_openssl)
target_compile_features(cexchain_console_wasm PRIVATE cxx_std_23)
target_link_options(cexchain_console_wasm PRIVATE
    -sMODULARIZE=1
    -sEXPORT_ES6=1
    -sEXPORT_NAME=CexChainConsole
    -sENVIRONMENT=web
    -sALLOW_MEMORY_GROWTH=1
    -sDYNAMIC_EXECUTION=0
    -sFILESYSTEM=0
    "-sEXPORTED_FUNCTIONS=_malloc,_free,_cexchain_describe_payload,_cexchain_presence_challenge,_cexchain_field_root,_cexchain_attachment_commitment,_cexchain_free"
    "-sEXPORTED_RUNTIME_METHODS=HEAPU8,UTF8ToString")
