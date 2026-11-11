#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Browser tests: the WebAssembly verifier against evidence made by the native
# tool, proof of presence with passkeys (Chromium's virtual authenticator), and
# the web console.
# Usage: run.sh KANHE WASM_BUILD_DIR
#   KANHE        the native command-line tool
#   WASM_BUILD_DIR  output of tools/wasm/build.sh
# The browser test needs `npm ci` in tests/browser and a Playwright Chromium; set
# REQUIRE_BROWSER=1 to fail instead of skipping it when they are missing.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
KANHE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
BUILD="$(cd "$2" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$HERE/make_evidence.sh" "$KANHE" "$WORK"
node "$HERE/verifier_node.js" "$BUILD/kanhe-verifier.js" "$ROOT/chain/verifier/wasm/verifier-api.js" "$WORK"
if [ -d "$HERE/node_modules/playwright" ]; then
    (cd "$HERE" && node page_test.js "$BUILD/kanhe-verify.html" "$WORK" "$KANHE")
    (cd "$HERE" && node presence_test.js "$KANHE" "$BUILD/kanhe-verify.html")
    (cd "$HERE" && node console_test.js "$KANHE")
    (cd "$HERE" && node console_first_run_test.js "$KANHE")
    (cd "$HERE" && node console_documents_test.js "$KANHE" "$BUILD/kanhe-verify.html")
    (cd "$HERE" && node console_rules_test.js "$KANHE" "$ROOT/examples")
    (cd "$HERE" && node console_things_test.js "$KANHE" "$ROOT")
    (cd "$HERE" && node console_consent_test.js "$KANHE" "$ROOT")
    (cd "$HERE" && node console_parties_test.js "$KANHE" "$ROOT")
    (cd "$HERE" && node console_parties_test.js "$KANHE" "$ROOT" --relay)
    (cd "$HERE" && node console_access_test.js "$KANHE")
    (cd "$HERE" && node console_people_test.js "$KANHE")
    (cd "$HERE" && node console_automation_test.js "$KANHE")
    (cd "$HERE" && node console_phone_test.js "$KANHE")
    (cd "$HERE" && node console_certificates_test.js "$KANHE")
elif [ "${REQUIRE_BROWSER:-0}" = 1 ]; then
    echo "Playwright is missing: run npm ci in tests/browser" >&2
    exit 1
else
    echo "browser tests: SKIPPED (run npm ci in tests/browser)"
fi
