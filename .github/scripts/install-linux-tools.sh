#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Installs the build tools on Debian trixie (the gcc:16-trixie image), plus
# Clang 23 and its sanitizer and libFuzzer runtimes from apt.llvm.org.
# SoftHSM stands in for hardware tokens (USB keys, HSMs) in the tests.
set -eu

apt-get update
apt-get install -y --no-install-recommends ca-certificates cmake gnupg libp11-kit-dev libssl-dev ninja-build \
    softhsm2 wget

install -d -m 0755 /etc/apt/keyrings
wget -qO /etc/apt/keyrings/apt.llvm.org.asc https://apt.llvm.org/llvm-snapshot.gpg.key
echo "deb [signed-by=/etc/apt/keyrings/apt.llvm.org.asc] https://apt.llvm.org/trixie/ llvm-toolchain-trixie-23 main" \
    > /etc/apt/sources.list.d/llvm.list
apt-get update
apt-get install -y --no-install-recommends clang-23 clang-format-23 libclang-rt-23-dev

cmake --version | head -1
g++ --version | head -1
clang++-23 --version | head -1
dpkg-query -W -f 'libssl-dev ${Version}\n' libssl-dev
softhsm2-util --version
