# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

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
    "-sEXPORTED_FUNCTIONS=_malloc,_free,_cexchain_describe_payload,_cexchain_presence_challenge,_cexchain_field_root,_cexchain_attachment_commitment,_cexchain_proof_reset,_cexchain_proof_attachment,_cexchain_proof_verify,_cexchain_free"
    "-sEXPORTED_RUNTIME_METHODS=HEAPU8,UTF8ToString")
