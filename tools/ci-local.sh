#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Runs the Linux jobs of .github/workflows/ci.yml locally, in CI's image
# (gcc:16-trixie) under Podman (or Docker: CI_LOCAL_ENGINE=docker), for when
# GitHub Actions cannot run them. Every job runs in one fresh container, one
# after another, on a copy of the source; each job's log goes to
# build/ci-local/JOB.log, and a summary to the terminal.
#
#   tools/ci-local.sh [--worktree] [--cpus N] [--memory SIZE] [JOB ...]
#
# Jobs (default: gcc release clang-asan format bo-asan):
#   gcc         GCC 16 debug: build, ctest
#   release     GCC 16 release, as the Docker image builds it: the CLI
#   clang-asan  Clang 23 with AddressSanitizer and UBSan: build, ctest
#   format      clang-format-23 on every tracked C++ file
#   bo-asan     GCC 16 with AddressSanitizer and UBSan: the Bo compiler's tests
#   tsan        Clang 23 with ThreadSanitizer: build, ctest
# The source is the committed tree (HEAD), or with --worktree the working
# tree's tracked and untracked files (not the ignored ones). The browser
# verifier's job (Emscripten, Chromium) is not run here.
set -Eeuo pipefail
trap 'echo "ci-local: failed at line $LINENO" >&2' ERR

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine=${CI_LOCAL_ENGINE:-podman}
image=docker.io/library/gcc:16-trixie
cpus=6
memory=7g
tree=head
jobs=()
while [ $# -gt 0 ]; do
    case "$1" in
        --worktree) tree=worktree ;;
        --cpus) cpus=$2; shift ;;
        --memory) memory=$2; shift ;;
        -h|--help) sed -n '4,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        gcc|release|clang-asan|format|bo-asan|tsan) jobs+=("$1") ;;
        *) echo "ci-local: unknown argument $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
if [ ${#jobs[@]} -eq 0 ]; then
    jobs=(gcc release clang-asan format bo-asan)
fi

# Under the home directory, which Podman's machine shares on macOS.
mkdir -p "$root/build"
work=$(mktemp -d "$root/build/ci-local-work.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
logs="$root/build/ci-local"
mkdir -p "$work/src" "$logs"
rm -f "$logs"/*.log

# macOS tar writes extended attributes that GNU tar warns about.
export COPYFILE_DISABLE=1
if [ "$tree" = head ]; then
    git -C "$root" archive --format=tar HEAD | tar -x -C "$work/src"
    git -C "$root" ls-tree -r --name-only HEAD > "$work/files.txt"
else
    # Files deleted in the working tree are still in the index: skip them.
    (cd "$root" && git ls-files -co --exclude-standard | while IFS= read -r f; do
        if [ -e "$f" ]; then printf '%s\n' "$f"; fi
    done) > "$work/files.txt"
    (cd "$root" && tar --no-xattrs -cf - -T "$work/files.txt") | tar -x -C "$work/src"
fi
grep -E '\.(cpp|hpp)$' "$work/files.txt" > "$work/cpp-files.txt" || true

cat > "$work/run.sh" <<'EOF'
#!/bin/bash
# Inside the container: the source at /mnt/src (read-only), logs to /logs.
set -u
cp -a /mnt/src /src
cd /src
if ! .github/scripts/install-linux-tools.sh > /logs/install.log 2>&1; then
    echo "install: FAILED (see install.log)"
    exit 1
fi
job() {
    case "$1" in
        gcc)
            cmake --preset gcc-debug -DCMAKE_CXX_COMPILER=g++ &&
                cmake --build --preset gcc-debug && ctest --preset gcc-debug ;;
        release)
            cmake --preset gcc-release -DCMAKE_CXX_COMPILER=g++ -DCEXCHAIN_BUILD_TESTS=OFF \
                -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" &&
                cmake --build --preset gcc-release --target cexchain &&
                build/gcc-release/cli/cexchain version &&
                build/gcc-release/cli/cexchain bo packs list ;;
        clang-asan)
            cmake --preset clang-asan -DCMAKE_CXX_COMPILER=clang++-23 &&
                cmake --build --preset clang-asan && ctest --preset clang-asan ;;
        format)
            xargs clang-format-23 --dry-run --Werror < /mnt/cpp-files.txt ;;
        bo-asan)
            cmake --preset gcc-asan -DCMAKE_CXX_COMPILER=g++ &&
                cmake --build --preset gcc-asan && ctest --preset gcc-asan ;;
        tsan)
            cmake --preset clang-tsan -DCMAKE_CXX_COMPILER=clang++-23 &&
                cmake --build --preset clang-tsan && ctest --preset clang-tsan ;;
    esac
}
status=0
for name in "$@"; do
    start=$(date +%s)
    if job "$name" > "/logs/$name.log" 2>&1; then
        result=ok
    else
        result="FAILED (see $name.log)"
        status=1
    fi
    tests=$(sed -n 's/^.*tests passed, \([0-9]* tests failed out of [0-9]*\)$/\1/p' "/logs/$name.log" | tail -1)
    echo "$name: $result, $(( $(date +%s) - start )) s${tests:+; $tests}"
done
exit $status
EOF
chmod +x "$work/run.sh"

echo "ci-local: ${jobs[*]} on $( [ "$tree" = head ] && git -C "$root" rev-parse --short HEAD || echo "the working tree"), in $image ($engine, $cpus CPUs, $memory)"
status=0
"$engine" run --rm --cpus "$cpus" --memory "$memory" -v "$work:/mnt:ro" -v "$logs:/logs" \
    "$image" /mnt/run.sh "${jobs[@]}" || status=$?
echo "ci-local: logs in $logs"
exit $status
