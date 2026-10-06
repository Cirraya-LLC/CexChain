#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Builds OpenSSL's libcrypto for WebAssembly with Emscripten, for the browser
# verifier. Usage: build-openssl.sh PREFIX
# Installs PREFIX/include/openssl and PREFIX/lib/libcrypto.a.
set -euo pipefail

VERSION=3.5.9
SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

PREFIX="${1:?usage: build-openssl.sh PREFIX}"
# The build is cached under a stamp that changes with this script.
if command -v sha256sum > /dev/null; then
    STAMP="$(sha256sum "$0" | cut -c1-16)"
else
    STAMP="$(shasum -a 256 "$0" | cut -c1-16)"
fi
if [ -f "$PREFIX/lib/libcrypto.a" ] && [ -f "$PREFIX/.built-$STAMP" ]; then
    echo "OpenSSL $VERSION for WebAssembly is already built in $PREFIX"
    exit 0
fi
command -v emconfigure > /dev/null || { echo "Emscripten (emconfigure) is not on PATH" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -fsSL -o "$WORK/openssl.tar.gz" \
    "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
if command -v sha256sum > /dev/null; then
    echo "$SHA256  $WORK/openssl.tar.gz" | sha256sum -c -
else
    echo "$SHA256  $WORK/openssl.tar.gz" | shasum -a 256 -c -
fi
tar xzf "$WORK/openssl.tar.gz" -C "$WORK"
cd "$WORK/openssl-$VERSION"

# A verifier needs digests and signature verification only: no TLS, no
# threads, no assembly (WebAssembly has none), no files or sockets at runtime,
# and none of the legacy algorithms.
emconfigure ./Configure linux-generic32 \
    no-asm no-threads no-shared no-dso no-engine no-module no-afalgeng no-async \
    no-sock no-ui-console no-autoload-config no-secure-memory no-tests no-apps no-docs \
    no-legacy no-deprecated no-ssl no-tls no-dtls no-srp no-psk no-cms no-ts no-ocsp no-ct \
    no-comp no-srtp no-nextprotoneg no-quic \
    no-idea no-rc2 no-rc4 no-rc5 no-md4 no-mdc2 no-whirlpool no-rmd160 no-des no-bf no-cast \
    no-seed no-camellia no-aria no-sm4 no-siphash no-ocb no-dsa no-dh no-gost \
    -Os -DOPENSSL_NO_SECURE_MEMORY
# emconfigure sets CROSS_COMPILE, which OpenSSL prefixes onto the absolute
# path of emcc; clear it.
sed -i.bak 's|^CROSS_COMPILE=.*$|CROSS_COMPILE=|' Makefile
emmake make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" build_generated libcrypto.a > "$WORK/make.log" 2>&1 \
    || { tail -40 "$WORK/make.log"; exit 1; }

mkdir -p "$PREFIX/include" "$PREFIX/lib"
rm -rf "$PREFIX/include/openssl"
cp -R include/openssl "$PREFIX/include/openssl"
cp libcrypto.a "$PREFIX/lib/libcrypto.a"
rm -f "$PREFIX"/.built-*
touch "$PREFIX/.built-$STAMP"
echo "OpenSSL $VERSION for WebAssembly installed in $PREFIX"
