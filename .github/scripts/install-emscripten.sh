#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Installs a pinned Emscripten (with its Node.js) into /opt/emsdk.
# Activate it with: . /opt/emsdk/emsdk_env.sh
set -eu

VERSION=6.0.10
COMMIT=a2b92777574c2feda07994cd4f1079a3dfc151f8

apt-get install -y --no-install-recommends git python3 xz-utils
git clone --quiet https://github.com/emscripten-core/emsdk.git /opt/emsdk
cd /opt/emsdk
git -c advice.detachedHead=false checkout --quiet "$COMMIT"
./emsdk install "$VERSION"
./emsdk activate "$VERSION"
. ./emsdk_env.sh
emcc --version | head -1
node --version
