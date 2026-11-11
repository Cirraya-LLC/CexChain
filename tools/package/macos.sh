#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Kanhe's macOS package: the programs (kanhe, bo, kanhe-console,
# kanhe-index) in /usr/local/bin, in a .pkg; and the programs alone in a
# tarball. Run on a Mac with Homebrew's gcc (16),
# ninja, and openssl@3:
#
#   tools/package/macos.sh [OUT_DIR]
#
# OpenSSL is linked in statically: Homebrew's path is not on other Macs. GCC's
# C++ library is too, and it needs the system's iconv (std::format).
# KANHE_DEVELOPER_ID, if set (a "Developer ID Installer: ..." identity in
# the keychain), signs the package, and KANHE_DEVELOPER_APP_ID the tool;
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
    -DKANHE_BUILD_TESTS=OFF -DKANHE_BO=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL" -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc -liconv" \
    ${WASM_DIR:+-DKANHE_CONSOLE_WASM_DIR="$WASM_DIR"} > /dev/null
PROGRAMS=(kanhe bo kanhe-console kanhe-index)
cmake --build "$BUILD" --target "${PROGRAMS[@]}"
for p in "${PROGRAMS[@]}"; do
    strip "$BUILD/bin/$p"
    "$BUILD/bin/$p" version > /dev/null
    if otool -L "$BUILD/bin/$p" | grep -qE "openssl|homebrew|libstdc\+\+"; then
        otool -L "$BUILD/bin/$p"
        echo "$p links a library other Macs do not have" >&2
        exit 1
    fi
done

# The package: the tool in /usr/local/bin, its completions, notices, and the
# standalone verifier page beside it. With KANHE_DEVELOPER_APP_ID (a
# "Developer ID Application: ..." identity) the tool is signed; otherwise
# ad hoc.
PAYLOAD="$BUILD/root"
rm -rf "$PAYLOAD"
install -d "$PAYLOAD/usr/local/bin" "$PAYLOAD/usr/local/share/doc/kanhe" \
    "$PAYLOAD/usr/local/share/zsh/site-functions"
for p in "${PROGRAMS[@]}"; do
    install -m755 "$BUILD/bin/$p" "$PAYLOAD/usr/local/bin/$p"
    codesign --force --options runtime --timestamp=none \
        --sign "${KANHE_DEVELOPER_APP_ID:--}" "$PAYLOAD/usr/local/bin/$p"
    codesign --verify --strict "$PAYLOAD/usr/local/bin/$p"
    "$PAYLOAD/usr/local/bin/$p" completion zsh > "$PAYLOAD/usr/local/share/zsh/site-functions/_$p"
done
install -m644 "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_NOTICES.md" "$PAYLOAD/usr/local/share/doc/kanhe/"
if [ -n "${WASM_DIR:-}" ] && [ -f "$WASM_DIR/kanhe-verify.html" ]; then
    install -d "$PAYLOAD/usr/local/share/kanhe"
    install -m644 "$WASM_DIR/kanhe-verify.html" "$PAYLOAD/usr/local/share/kanhe/"
fi

pkgbuild --root "$PAYLOAD" --identifier com.cirraya.kanhe --version "$VERSION" \
    --install-location / "$BUILD/component.pkg" > /dev/null
productbuild --package "$BUILD/component.pkg" \
    ${KANHE_DEVELOPER_ID:+--sign "$KANHE_DEVELOPER_ID"} \
    "$OUT/Kanhe-$VERSION-macos-$ARCH.pkg" > /dev/null
echo "wrote $OUT/Kanhe-$VERSION-macos-$ARCH.pkg${KANHE_DEVELOPER_ID:+ (signed)}"
tar -C "$PAYLOAD/usr/local/bin" -czf "$OUT/kanhe-$VERSION-macos-$ARCH.tar.gz" "${PROGRAMS[@]}"
echo "wrote $OUT/kanhe-$VERSION-macos-$ARCH.tar.gz"
