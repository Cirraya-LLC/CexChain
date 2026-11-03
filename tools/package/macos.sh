#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# CexChain's macOS package: the cexchain tool in /usr/local/bin, in a .pkg;
# and the tool alone in a tarball. Run on a Mac with Homebrew's gcc (16),
# ninja, and openssl@3:
#
#   tools/package/macos.sh [OUT_DIR]
#
# OpenSSL is linked in statically: Homebrew's path is not on other Macs. GCC's
# C++ library is too, and it needs the system's iconv (std::format).
# CEXCHAIN_DEVELOPER_ID, if set (a "Developer ID Installer: ..." identity in
# the keychain), signs the package, and CEXCHAIN_DEVELOPER_APP_ID the tool;
# otherwise they are unsigned (the tool ad hoc), and macOS asks the person to
# allow them. WASM_DIR as in linux.sh.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$(mkdir -p "${1:-$ROOT/build/packages}" && cd "${1:-$ROOT/build/packages}" && pwd)"
BUILD="$ROOT/build/package-macos"
VERSION="$(sed -n 's/^ *VERSION \([0-9][0-9.]*\)$/\1/p' "$ROOT/CMakeLists.txt" | head -1)"
ARCH="$(uname -m)"
OPENSSL="$(brew --prefix openssl@3)"

cmake -S "$ROOT" -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++-16 \
    -DCEXCHAIN_BUILD_TESTS=OFF -DCEXCHAIN_BO=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL" -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc -liconv" \
    ${WASM_DIR:+-DCEXCHAIN_CONSOLE_WASM_DIR="$WASM_DIR"} > /dev/null
cmake --build "$BUILD" --target cexchain
strip "$BUILD/cli/cexchain"
"$BUILD/cli/cexchain" version
if otool -L "$BUILD/cli/cexchain" | grep -qE "openssl|homebrew|libstdc\+\+"; then
    otool -L "$BUILD/cli/cexchain"
    echo "the tool links a library other Macs do not have" >&2
    exit 1
fi

# The package: the tool in /usr/local/bin, its completions, notices, and the
# standalone verifier page beside it. With CEXCHAIN_DEVELOPER_APP_ID (a
# "Developer ID Application: ..." identity) the tool is signed; otherwise
# ad hoc.
PAYLOAD="$BUILD/root"
rm -rf "$PAYLOAD"
install -d "$PAYLOAD/usr/local/bin" "$PAYLOAD/usr/local/share/doc/cexchain" \
    "$PAYLOAD/usr/local/share/zsh/site-functions"
install -m755 "$BUILD/cli/cexchain" "$PAYLOAD/usr/local/bin/cexchain"
codesign --force --options runtime --timestamp=none \
    --sign "${CEXCHAIN_DEVELOPER_APP_ID:--}" "$PAYLOAD/usr/local/bin/cexchain"
codesign --verify --strict "$PAYLOAD/usr/local/bin/cexchain"
"$PAYLOAD/usr/local/bin/cexchain" completion zsh > "$PAYLOAD/usr/local/share/zsh/site-functions/_cexchain"
install -m644 "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_NOTICES.md" "$PAYLOAD/usr/local/share/doc/cexchain/"
if [ -n "${WASM_DIR:-}" ] && [ -f "$WASM_DIR/cexchain-verify.html" ]; then
    install -d "$PAYLOAD/usr/local/share/cexchain"
    install -m644 "$WASM_DIR/cexchain-verify.html" "$PAYLOAD/usr/local/share/cexchain/"
fi

pkgbuild --root "$PAYLOAD" --identifier com.cirraya.cexchain --version "$VERSION" \
    --install-location / "$BUILD/component.pkg" > /dev/null
productbuild --package "$BUILD/component.pkg" \
    ${CEXCHAIN_DEVELOPER_ID:+--sign "$CEXCHAIN_DEVELOPER_ID"} \
    "$OUT/CexChain-$VERSION-macos-$ARCH.pkg" > /dev/null
echo "wrote $OUT/CexChain-$VERSION-macos-$ARCH.pkg${CEXCHAIN_DEVELOPER_ID:+ (signed)}"
tar -C "$PAYLOAD/usr/local/bin" -czf "$OUT/cexchain-$VERSION-macos-$ARCH.tar.gz" cexchain
echo "wrote $OUT/cexchain-$VERSION-macos-$ARCH.tar.gz"
