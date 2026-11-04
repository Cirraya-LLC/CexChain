#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Installs the build tools on Debian trixie (the gcc:16-trixie image), plus
# Clang 23 and its sanitizer and libFuzzer runtimes from apt.llvm.org.
# SoftHSM stands in for hardware tokens (USB keys, HSMs) in the tests.
# Python 3 runs the reference interpreter that checks the Bo runtime's runs
# (CTest bo_reference; the standard library only), and the independent
# verifier (verifiers/python), whose packages go in a virtual environment,
# /opt/python-verifier: Debian's python3-cryptography has no ML-DSA.
# Usage: install-linux-tools.sh [REQUIREMENTS]  (default: the verifier's)
set -eu

requirements="${1:-$(dirname "$0")/../../verifiers/python/requirements.txt}"

apt-get update
apt-get install -y --no-install-recommends ca-certificates cmake gnupg libp11-kit-dev libssl-dev ninja-build \
    python3 python3-venv softhsm2 wget
python3 -m venv /opt/python-verifier
/opt/python-verifier/bin/pip install --quiet --no-cache-dir --disable-pip-version-check -r "$requirements"

install -d -m 0755 /etc/apt/keyrings
wget -qO /etc/apt/keyrings/apt.llvm.org.asc https://apt.llvm.org/llvm-snapshot.gpg.key
echo "deb [signed-by=/etc/apt/keyrings/apt.llvm.org.asc] https://apt.llvm.org/trixie/ llvm-toolchain-trixie-23 main" \
    > /etc/apt/sources.list.d/llvm.list
apt-get update
apt-get install -y --no-install-recommends clang-23 clang-format-23 libclang-rt-23-dev llvm-23
# Sanitizers look for llvm-symbolizer on PATH; without it, reports have no
# function names or lines.
ln -sf /usr/lib/llvm-23/bin/llvm-symbolizer /usr/local/bin/llvm-symbolizer

cmake --version | head -1
g++ --version | head -1
clang++-23 --version | head -1
dpkg-query -W -f 'libssl-dev ${Version}\n' libssl-dev
softhsm2-util --version
llvm-symbolizer --version | head -1
python3 --version
/opt/python-verifier/bin/python -c 'import cryptography; print("cryptography", cryptography.__version__)'
