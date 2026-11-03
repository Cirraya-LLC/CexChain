# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Inlines the WebAssembly module (already embedded in its JavaScript loader)
# and the API wrapper into the page template.
file(READ "${MODULE}" module_js)
file(READ "${API}" api_js)
file(READ "${TEMPLATE}" page)
set(script "${module_js}\n${api_js}")
# A literal "</script" would end the inline script early.
string(REPLACE "</script" "<\\/script" script "${script}")
string(REPLACE "/* CEXCHAIN_SCRIPT */" "${script}" page "${page}")
file(WRITE "${OUT}" "${page}")
