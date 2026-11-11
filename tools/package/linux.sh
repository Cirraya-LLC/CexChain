#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Kanhe's Linux packages, each as a tarball, a .deb, and, where rpmbuild
# is installed, an .rpm: kanhe, the chain (the kanhe tool, the search
# index, and a ledger server unit), what a server needs; and kanhe-console,
# the web console and the bo compiler, with a menu entry and a unit for a
# company's console, which needs kanhe of the same version. Run in the
# gcc:16-trixie container (as CI and the Docker image build), from anywhere in
# the source tree:
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
    -DKANHE_BUILD_TESTS=OFF -DKANHE_BO=ON \
    -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    ${WASM_DIR:+-DKANHE_CONSOLE_WASM_DIR="$WASM_DIR"} > /dev/null
CHAIN=(kanhe kanhe-index)
CONSOLE=(kanhe-console bo)
cmake --build "$BUILD" --target "${CHAIN[@]}" "${CONSOLE[@]}"
for p in "${CHAIN[@]}" "${CONSOLE[@]}"; do
    strip "$BUILD/bin/$p"
    "$BUILD/bin/$p" version > /dev/null
done
LINUX="$ROOT/tools/package/linux"
DESCRIPTION="Kanhe keeps an organization's records, rules, and approvals on its own
ledger, so that anyone can verify them without trusting a platform."

# Stages a package's tree under $BUILD/stage/NAME/usr: programs and their
# completions, and the license.
stage() {
    local name="$1" dir="$BUILD/stage/$1"
    shift
    rm -rf "$dir"
    install -d "$dir/usr/share/bash-completion/completions" "$dir/usr/share/zsh/vendor-completions"
    for p in "$@"; do
        install -Dm755 "$BUILD/bin/$p" "$dir/usr/bin/$p"
        "$BUILD/bin/$p" completion bash > "$dir/usr/share/bash-completion/completions/$p"
        "$BUILD/bin/$p" completion zsh > "$dir/usr/share/zsh/vendor-completions/_$p"
    done
    install -Dm644 "$ROOT/LICENSE" "$dir/usr/share/doc/$name/LICENSE"
    install -Dm644 "$ROOT/THIRD_PARTY_NOTICES.md" "$dir/usr/share/doc/$name/THIRD_PARTY_NOTICES.md"
}

stage kanhe "${CHAIN[@]}"
STAGE="$BUILD/stage/kanhe"
install -Dm644 "$LINUX/kanhe.service" "$STAGE/usr/lib/systemd/system/kanhe.service"
install -Dm644 "$LINUX/kanhe.sysusers" "$STAGE/usr/lib/sysusers.d/kanhe.conf"
install -Dm644 "$LINUX/serve.env" "$STAGE/etc/kanhe/serve.env"
if [ -n "${WASM_DIR:-}" ] && [ -f "$WASM_DIR/kanhe-verify.html" ]; then
    install -Dm644 "$WASM_DIR/kanhe-verify.html" "$STAGE/usr/share/kanhe/kanhe-verify.html"
fi

stage kanhe-console "${CONSOLE[@]}"
STAGE="$BUILD/stage/kanhe-console"
install -Dm644 "$LINUX/kanhe-console.desktop" \
    "$STAGE/usr/share/applications/kanhe-console.desktop"
install -Dm644 "$LINUX/kanhe-console.service" \
    "$STAGE/usr/lib/systemd/system/kanhe-console.service"
install -Dm644 "$LINUX/console.env" "$STAGE/etc/kanhe/console.env"

# What each package's scripts do: the server units' user (sysusers.d, or by
# hand where systemd is not), the menu, and systemd's view of the units.
# Removing a package keeps every ledger, console, and backup.
ADD_USER='if command -v systemd-sysusers > /dev/null; then
    systemd-sysusers kanhe.conf || true
elif ! id kanhe > /dev/null 2>&1 && command -v useradd > /dev/null; then
    useradd --system --home-dir /var/lib/kanhe --shell /usr/sbin/nologin \
        --comment "Kanhe ledger server" kanhe || true
fi'
MENU='command -v update-desktop-database > /dev/null && update-desktop-database -q || true'
UNITS='command -v systemctl > /dev/null && [ -d /run/systemd/system ] && systemctl daemon-reload || true'

# package NAME SUMMARY WHAT DEPENDS RPM_REQUIRES CONFIG AFTER_REMOVAL: the
# tarball, the .deb, and the .rpm of a staged tree. AFTER_REMOVAL also runs
# after installing, after the server units' user.
package() {
    local name="$1" summary="$2" what="$3" depends="$4" requires="$5" config="$6" removed="$7"
    local post="$ADD_USER
$removed"
    local stage="$BUILD/stage/$name" text
    text="$DESCRIPTION $what"

    tar -C "$stage" --owner=0 --group=0 -czf "$OUT/$name-$VERSION-linux-$ARCH.tar.gz" \
        $(cd "$stage" && ls)
    echo "wrote $OUT/$name-$VERSION-linux-$ARCH.tar.gz"

    local deb="$BUILD/deb/$name"
    rm -rf "$deb"
    mkdir -p "$(dirname "$deb")"
    cp -a "$stage" "$deb"
    install -d "$deb/DEBIAN"
    cat > "$deb/DEBIAN/control" << CONTROL
Package: $name
Version: $VERSION
Architecture: $DEB_ARCH
Maintainer: Cirraya <tech@cirraya.com>
Installed-Size: $(du -sk "$deb" | cut -f1)
Depends: $depends
Section: utils
Priority: optional
Homepage: https://github.com/Cirraya-LLC/Kanhe
Description: $summary
$(fmt -w 74 <<< "$text" | sed 's/^/ /')
CONTROL
    echo "$config" > "$deb/DEBIAN/conffiles"
    printf '#!/bin/sh\nset -e\n%s\nexit 0\n' "$post" > "$deb/DEBIAN/postinst"
    printf '#!/bin/sh\nset -e\n%s\nexit 0\n' "$removed" > "$deb/DEBIAN/postrm"
    chmod 755 "$deb/DEBIAN/postinst" "$deb/DEBIAN/postrm"
    dpkg-deb --root-owner-group --build "$deb" "$OUT/${name}_${VERSION}_${DEB_ARCH}.deb" > /dev/null
    echo "wrote $OUT/${name}_${VERSION}_${DEB_ARCH}.deb"

    command -v rpmbuild > /dev/null || return 0
    local rpm="$BUILD/rpm/$name"
    rm -rf "$rpm"
    mkdir -p "$rpm/SPECS" "$rpm/BUILDROOT"
    cat > "$rpm/SPECS/$name.spec" << SPEC
Name: $name
Version: $VERSION
Release: 1
Summary: $summary
License: Apache-2.0
URL: https://github.com/Cirraya-LLC/Kanhe
Requires: $requires
AutoReqProv: no

%description
$(fmt -w 74 <<< "$text")

%install
cp -a $stage/. %{buildroot}/

%post
$post
exit 0

%files
$(cd "$stage" && find . -type f | sed 's|^\.||' | sort | while read -r f; do
        if [ "$f" = "$config" ]; then echo "%config(noreplace) $f"; else echo "$f"; fi
    done)
SPEC
    rpmbuild --quiet -bb --define "_topdir $rpm" --define "_build_id_links none" \
        --target "$ARCH" "$rpm/SPECS/$name.spec"
    cp "$rpm"/RPMS/*/"$name"-[0-9]*.rpm "$OUT/"
    echo "wrote $(ls "$OUT"/"$name"-[0-9]*.rpm)"
}

package kanhe "Verifiable records between organizations, people, and AI agents" \
    "This package installs the kanhe tool, the search index (kanhe-index), and a ledger server unit for companies (not enabled)." \
    "libssl3t64 (>= 3.5) | libssl3 (>= 3.5), ca-certificates" "openssl-libs >= 3.5, ca-certificates" \
    /etc/kanhe/serve.env "$UNITS"
package kanhe-console "Kanhe's web console and the bo compiler" \
    "This package installs the web console (kanhe-console open), the bo contract compiler, and a unit for a company's console (not enabled)." \
    "kanhe (= $VERSION)" "kanhe = $VERSION" \
    /etc/kanhe/console.env "$MENU
$UNITS"
