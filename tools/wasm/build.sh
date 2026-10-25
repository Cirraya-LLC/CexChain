#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Builds the browser verifier with Emscripten. Usage: build.sh [BUILD_DIR]
# Produces BUILD_DIR/cexchain-verify.html (self-contained: open it from disk or
# host it anywhere), BUILD_DIR/cexchain-verifier.js (the module, for Node.js),
# and the web console's checks, BUILD_DIR/cexchain-console.mjs and .wasm.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${1:-$ROOT/build/wasm}"
# CMake resolves relative paths against the source tree, so use absolute ones.
mkdir -p "$BUILD"
BUILD="$(cd "$BUILD" && pwd)"
OPENSSL="$BUILD/openssl"

"$ROOT/tools/wasm/build-openssl.sh" "$OPENSSL"
emcmake cmake -S "$ROOT" -B "$BUILD/cmake" -G Ninja \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCEXCHAIN_WARNINGS_AS_ERRORS=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL" \
    -DOPENSSL_INCLUDE_DIR="$OPENSSL/include" \
    -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL/lib/libcrypto.a" \
    -DCMAKE_CXX_FLAGS="-fwasm-exceptions" \
    -DCMAKE_EXE_LINKER_FLAGS="-fwasm-exceptions" > /dev/null
cmake --build "$BUILD/cmake"
cp "$BUILD/cmake/verifier/wasm/cexchain-verify.html" "$BUILD/cmake/verifier/wasm/cexchain-verifier.js" "$BUILD/"
# The console's checks, for a native build: -DCEXCHAIN_CONSOLE_WASM_DIR="$BUILD".
cp "$BUILD/cmake/verifier/wasm/cexchain-console.mjs" "$BUILD/cmake/verifier/wasm/cexchain-console.wasm" "$BUILD/"
ls -l "$BUILD/cexchain-verify.html"
