#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# CexChain's macOS package: CexChain.app (which opens the console; .cexchain
# files are its documents, and open in it) with the cexchain tool inside it,
# linked from /usr/local/bin, in a .pkg; and the tool alone in a tarball. Run on a Mac
# with Homebrew's gcc (16), ninja, and openssl@3:
#
#   tools/package/macos.sh [OUT_DIR]
#
# OpenSSL is linked in statically: Homebrew's path is not on other Macs. GCC's
# C++ library is too, and it needs the system's iconv (std::format).
# CEXCHAIN_DEVELOPER_ID, if set (a "Developer ID Installer: ..." identity in
# the keychain), signs the package, and CEXCHAIN_DEVELOPER_APP_ID the app;
# otherwise they are unsigned (the app ad hoc), and macOS asks the person to
# allow them. WASM_DIR, CEXCHAIN_RELEASE_KEY, and
# CEXCHAIN_UPDATE_URL as in linux.sh.
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
    ${WASM_DIR:+-DCEXCHAIN_CONSOLE_WASM_DIR="$WASM_DIR"} \
    ${CEXCHAIN_RELEASE_KEY:+-DCEXCHAIN_RELEASE_KEY="$CEXCHAIN_RELEASE_KEY"} \
    ${CEXCHAIN_UPDATE_URL:+-DCEXCHAIN_UPDATE_URL="$CEXCHAIN_UPDATE_URL"} > /dev/null
cmake --build "$BUILD" --target cexchain
strip "$BUILD/cli/cexchain"
"$BUILD/cli/cexchain" version
if otool -L "$BUILD/cli/cexchain" | grep -qE "openssl|homebrew|libstdc\+\+"; then
    otool -L "$BUILD/cli/cexchain"
    echo "the tool links a library other Macs do not have" >&2
    exit 1
fi

# The app: an AppleScript applet, since macOS hands a double-clicked
# document to an app as an event, not on its command line. Opened, it runs
# the tool beside it: `console open`, or `console open FILE` for each file.
PAYLOAD="$BUILD/root"
APP="$PAYLOAD/Applications/CexChain.app"
rm -rf "$PAYLOAD" "$BUILD/scripts"
install -d "$PAYLOAD/Applications" "$BUILD/scripts"
osacompile -o "$APP" "$ROOT/tools/package/macos/CexChain.applescript"
install -m755 "$BUILD/cli/cexchain" "$APP/Contents/MacOS/cexchain"
sed "s/@VERSION@/$VERSION/g" "$ROOT/tools/package/macos/Info.plist" > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" > /dev/null
install -m644 "$ROOT/LICENSE" "$APP/Contents/Resources/LICENSE"
install -m644 "$ROOT/THIRD_PARTY_NOTICES.md" "$APP/Contents/Resources/THIRD_PARTY_NOTICES.md"
if [ -n "${WASM_DIR:-}" ] && [ -f "$WASM_DIR/cexchain-verify.html" ]; then
    install -m644 "$WASM_DIR/cexchain-verify.html" "$APP/Contents/Resources/cexchain-verify.html"
fi
# Sealed again, its contents changed: with CEXCHAIN_DEVELOPER_APP_ID (a
# "Developer ID Application: ..." identity), or ad hoc.
codesign --force --deep --options runtime --timestamp=none \
    --sign "${CEXCHAIN_DEVELOPER_APP_ID:--}" "$APP"
codesign --verify --deep --strict "$APP"
cat > "$BUILD/scripts/postinstall" << 'POSTINSTALL'
#!/bin/sh
# The tool on the command line, from the app.
mkdir -p /usr/local/bin
ln -sf /Applications/CexChain.app/Contents/MacOS/cexchain /usr/local/bin/cexchain
exit 0
POSTINSTALL
chmod 755 "$BUILD/scripts/postinstall"

pkgbuild --root "$PAYLOAD" --identifier com.cirraya.cexchain --version "$VERSION" \
    --scripts "$BUILD/scripts" --install-location / "$BUILD/component.pkg" > /dev/null
productbuild --package "$BUILD/component.pkg" \
    ${CEXCHAIN_DEVELOPER_ID:+--sign "$CEXCHAIN_DEVELOPER_ID"} \
    "$OUT/CexChain-$VERSION-macos-$ARCH.pkg" > /dev/null
echo "wrote $OUT/CexChain-$VERSION-macos-$ARCH.pkg${CEXCHAIN_DEVELOPER_ID:+ (signed)}"
tar -C "$APP/Contents/MacOS" -czf "$OUT/cexchain-$VERSION-macos-$ARCH.tar.gz" cexchain
echo "wrote $OUT/cexchain-$VERSION-macos-$ARCH.tar.gz"
