#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# CexChain's Linux packages: a tarball, a .deb, and, where rpmbuild is
# installed, an .rpm. Run in the gcc:16-trixie container (as CI and the
# Docker image build), from anywhere in the source tree:
#
#   tools/package/linux.sh [OUT_DIR]
#
# The release build links GCC's C++ library in (it is newer than the
# distributions'); OpenSSL 3.5 comes from the system. WASM_DIR, if set,
# names the built WebAssembly (tools/wasm/build.sh): the console then checks
# in the browser, and the standalone verifier page is installed.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$(mkdir -p "${1:-$ROOT/build/packages}" && cd "${1:-$ROOT/build/packages}" && pwd)"
BUILD="$ROOT/build/package-release"
VERSION="$(sed -n 's/^ *VERSION \([0-9][0-9.]*\)$/\1/p' "$ROOT/CMakeLists.txt" | head -1)"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) DEB_ARCH=amd64 ;;
    aarch64) DEB_ARCH=arm64 ;;
    *) DEB_ARCH="$ARCH" ;;
esac

cmake -S "$ROOT" -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++ \
    -DCEXCHAIN_BUILD_TESTS=OFF -DCEXCHAIN_BO=ON \
    -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    ${WASM_DIR:+-DCEXCHAIN_CONSOLE_WASM_DIR="$WASM_DIR"} > /dev/null
cmake --build "$BUILD" --target cexchain bo cexchain-console cexchain-index
PROGRAMS=(cexchain bo cexchain-console cexchain-index)
for p in "${PROGRAMS[@]}"; do
    strip "$BUILD/bin/$p"
    "$BUILD/bin/$p" version > /dev/null
done

# What the packages install, staged under /usr.
STAGE="$BUILD/stage"
rm -rf "$STAGE"
install -d "$STAGE/usr/share/bash-completion/completions" "$STAGE/usr/share/zsh/vendor-completions"
for p in "${PROGRAMS[@]}"; do
    install -Dm755 "$BUILD/bin/$p" "$STAGE/usr/bin/$p"
    "$BUILD/bin/$p" completion bash > "$STAGE/usr/share/bash-completion/completions/$p"
    "$BUILD/bin/$p" completion zsh > "$STAGE/usr/share/zsh/vendor-completions/_$p"
done
install -Dm644 "$ROOT/tools/package/linux/cexchain.desktop" \
    "$STAGE/usr/share/applications/cexchain.desktop"
install -Dm644 "$ROOT/tools/package/linux/cexchain.service" \
    "$STAGE/usr/lib/systemd/system/cexchain.service"
install -Dm644 "$ROOT/tools/package/linux/cexchain.sysusers" \
    "$STAGE/usr/lib/sysusers.d/cexchain.conf"
install -Dm644 "$ROOT/tools/package/linux/serve.env" "$STAGE/etc/cexchain/serve.env"
install -Dm644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/cexchain/LICENSE"
install -Dm644 "$ROOT/THIRD_PARTY_NOTICES.md" "$STAGE/usr/share/doc/cexchain/THIRD_PARTY_NOTICES.md"
if [ -n "${WASM_DIR:-}" ] && [ -f "$WASM_DIR/cexchain-verify.html" ]; then
    install -Dm644 "$WASM_DIR/cexchain-verify.html" "$STAGE/usr/share/cexchain/cexchain-verify.html"
fi

# The tarball: the same tree, to unpack under / or ~/.local.
tar -C "$STAGE" --owner=0 --group=0 -czf "$OUT/cexchain-$VERSION-linux-$ARCH.tar.gz" usr etc
echo "wrote $OUT/cexchain-$VERSION-linux-$ARCH.tar.gz"

# The .deb.
DEB="$BUILD/deb"
rm -rf "$DEB"
cp -a "$STAGE" "$DEB"
install -d "$DEB/DEBIAN"
SIZE="$(du -sk "$DEB" | cut -f1)"
cat > "$DEB/DEBIAN/control" << CONTROL
Package: cexchain
Version: $VERSION
Architecture: $DEB_ARCH
Maintainer: Cirraya <tech@cirraya.com>
Installed-Size: $SIZE
Depends: libssl3t64 (>= 3.5) | libssl3 (>= 3.5), ca-certificates
Section: utils
Priority: optional
Homepage: https://github.com/Cirraya-LLC/CexChain
Description: Verifiable records between organizations, people, and AI agents
 CexChain keeps an organization's records, rules, and approvals on its own
 ledger, so that anyone can verify them without trusting a platform. This
 package installs the cexchain tool, the bo compiler, the web console
 (cexchain-console open), the search index (cexchain-index), and a ledger
 server unit for companies (not enabled).
CONTROL
echo "/etc/cexchain/serve.env" > "$DEB/DEBIAN/conffiles"
cat > "$DEB/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
# The server unit's user (sysusers.d, or by hand where systemd is not).
if command -v systemd-sysusers > /dev/null; then
    systemd-sysusers cexchain.conf || true
elif ! id cexchain > /dev/null 2>&1 && command -v useradd > /dev/null; then
    useradd --system --home-dir /var/lib/cexchain --shell /usr/sbin/nologin \
        --comment "CexChain ledger server" cexchain || true
fi
command -v update-desktop-database > /dev/null && update-desktop-database -q || true
command -v systemctl > /dev/null && [ -d /run/systemd/system ] && systemctl daemon-reload || true
exit 0
POSTINST
cat > "$DEB/DEBIAN/postrm" << 'POSTRM'
#!/bin/sh
set -e
# Ledgers, consoles, and backups stay: only the program goes.
command -v systemctl > /dev/null && [ -d /run/systemd/system ] && systemctl daemon-reload || true
exit 0
POSTRM
chmod 755 "$DEB/DEBIAN/postinst" "$DEB/DEBIAN/postrm"
dpkg-deb --root-owner-group --build "$DEB" "$OUT/cexchain_${VERSION}_${DEB_ARCH}.deb" > /dev/null
echo "wrote $OUT/cexchain_${VERSION}_${DEB_ARCH}.deb"

# The .rpm, where rpmbuild is installed.
if command -v rpmbuild > /dev/null; then
    RPM="$BUILD/rpm"
    rm -rf "$RPM"
    mkdir -p "$RPM/SPECS" "$RPM/BUILDROOT"
    cat > "$RPM/SPECS/cexchain.spec" << SPEC
Name: cexchain
Version: $VERSION
Release: 1
Summary: Verifiable records between organizations, people, and AI agents
License: Apache-2.0
URL: https://github.com/Cirraya-LLC/CexChain
Requires: openssl-libs >= 3.5, ca-certificates
AutoReqProv: no

%description
CexChain keeps an organization's records, rules, and approvals on its own
ledger, so that anyone can verify them without trusting a platform. This
package installs the cexchain tool, the bo compiler, the web console
(cexchain-console open), the search index (cexchain-index), and a ledger
server unit for companies (not enabled).

%install
cp -a $STAGE/. %{buildroot}/

%post
if command -v systemd-sysusers > /dev/null; then
    systemd-sysusers cexchain.conf || true
elif ! id cexchain > /dev/null 2>&1 && command -v useradd > /dev/null; then
    useradd --system --home-dir /var/lib/cexchain --shell /usr/sbin/nologin cexchain || true
fi
exit 0


%files
/usr/bin/cexchain
/usr/bin/bo
/usr/bin/cexchain-console
/usr/bin/cexchain-index
/usr/share/bash-completion/completions/*
/usr/share/zsh/vendor-completions/*
/usr/share/applications/cexchain.desktop
/usr/lib/systemd/system/cexchain.service
/usr/lib/sysusers.d/cexchain.conf
%config(noreplace) /etc/cexchain/serve.env
/usr/share/doc/cexchain
$( [ -d "$STAGE/usr/share/cexchain" ] && echo /usr/share/cexchain )
SPEC
    rpmbuild --quiet -bb --define "_topdir $RPM" --define "_build_id_links none" \
        --target "$ARCH" "$RPM/SPECS/cexchain.spec"
    cp "$RPM"/RPMS/*/cexchain-*.rpm "$OUT/"
    echo "wrote $(ls "$OUT"/cexchain-*.rpm)"
fi
