# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The web console's checks in the browser (decoding a payload, computing its
# presence challenge): an ES module and a separate .wasm file, which a native
# build embeds in the console when KANHE_CONSOLE_WASM_DIR names them.
add_executable(kanhe_console_wasm console_wasm.cpp)
set_target_properties(kanhe_console_wasm PROPERTIES OUTPUT_NAME kanhe-console SUFFIX ".mjs")
target_link_libraries(kanhe_console_wasm PRIVATE kanhe::verifier kanhe::crypto_openssl)
target_compile_features(kanhe_console_wasm PRIVATE cxx_std_23)
target_link_options(kanhe_console_wasm PRIVATE
    -sMODULARIZE=1
    -sEXPORT_ES6=1
    -sEXPORT_NAME=KanheConsole
    -sENVIRONMENT=web
    -sALLOW_MEMORY_GROWTH=1
    -sDYNAMIC_EXECUTION=0
    -sFILESYSTEM=0
    "-sEXPORTED_FUNCTIONS=_malloc,_free,_kanhe_describe_payload,_kanhe_presence_challenge,_kanhe_field_root,_kanhe_attachment_commitment,_kanhe_proof_reset,_kanhe_proof_attachment,_kanhe_proof_verify,_kanhe_free"
    "-sEXPORTED_RUNTIME_METHODS=HEAPU8,UTF8ToString")
