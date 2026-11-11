#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Which parts of the source a push or pull request changes since BASE, for
# CI to choose its jobs and tests. Prints name=value lines for $GITHUB_OUTPUT:
#   chain   anything but the language and the applications: the chain, the
#           build, the tests' support, the vectors, the tools, CI itself
#   bo      the Bo language: bo/, its tests, and the examples (Bo contracts)
#   apps    the applications: apps/ and their tests
#   tests   ctest's options for the jobs that run every test: none, or only
#           the applications' tests when nothing else changed (the chain and
#           the language link no application, cmake/KanheLayers.cmake)
#   tsan_tests  the same for ThreadSanitizer, which a change to the language
#           alone skips (the compiler runs in one thread, in its own process):
#           none when the chain changed, else the applications' tests
# Text (*.md) and LICENSE change no part. Without a BASE to compare with (a
# new branch, a run by hand, a history rewritten), every part has changed.
# Usage: changed-parts.sh [BASE]
set -euo pipefail

base="${1:-}"
if [[ -z "$base" || "$base" =~ ^0+$ ]] || ! git cat-file -e "$base^{commit}" 2> /dev/null; then
    printf 'chain=true\nbo=true\napps=true\ntests=\ntsan_tests=\n'
    exit 0
fi

chain=false
bo=false
apps=false
while IFS= read -r file; do
    case "$file" in
    *.md | LICENSE) ;;
    bo/* | tests/bo/* | tests/cli/bo.sh | examples/*) bo=true ;;
    apps/* | tests/console/* | tests/search/* | tests/cli/console.sh | tests/cli/search.sh | \
        tests/browser/console_*) apps=true ;;
    *) chain=true ;;
    esac
done < <(git diff --name-only "$base...HEAD")

tests=
tsan_tests=
if [ "$chain" = false ]; then
    tsan_tests="-L apps"
    [ "$bo" = true ] || tests="-L apps"
fi
printf 'chain=%s\nbo=%s\napps=%s\ntests=%s\ntsan_tests=%s\n' "$chain" "$bo" "$apps" "$tests" "$tsan_tests"
