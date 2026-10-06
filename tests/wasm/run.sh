#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Tests the browser verifier against evidence made by the native tool.
# Usage: run.sh CEXCHAIN WASM_BUILD_DIR
#   CEXCHAIN        the native command-line tool
#   WASM_BUILD_DIR  output of tools/wasm/build.sh
# The browser test needs `npm ci` in tests/wasm and a Playwright Chromium; set
# REQUIRE_BROWSER=1 to fail instead of skipping it when they are missing.
set -euo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CEXCHAIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
BUILD="$(cd "$2" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$HERE/make_evidence.sh" "$CEXCHAIN" "$WORK"
node "$HERE/verifier_node.js" "$BUILD/cexchain-verifier.js" "$ROOT/verifier/wasm/verifier-api.js" "$WORK"
if [ -d "$HERE/node_modules/playwright" ]; then
    (cd "$HERE" && node page_test.js "$BUILD/cexchain-verify.html" "$WORK" "$CEXCHAIN")
elif [ "${REQUIRE_BROWSER:-0}" = 1 ]; then
    echo "Playwright is missing: run npm ci in tests/wasm" >&2
    exit 1
else
    echo "wasm verifier (browser): SKIPPED (run npm ci in tests/wasm)"
fi
