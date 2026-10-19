#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Checks the Developer Certificate of Origin sign-off (CONTRIBUTING.md): every
# commit in BASE..HEAD, merges aside, must carry a "Signed-off-by:" trailer
# that names its author, name and email (compared without regard to case).
# Usage: check-dco.sh BASE HEAD
set -euo pipefail

base="${1:?usage: check-dco.sh BASE HEAD}"
head="${2:?usage: check-dco.sh BASE HEAD}"

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# Listed first, so that a range git cannot resolve fails the check.
commits="$(git rev-list --no-merges --reverse "$base..$head")"
checked=0
missing=0
for commit in $commits; do
    checked=$((checked + 1))
    author="$(git show -s --format='%an <%ae>' "$commit")"
    signed=0
    while IFS= read -r line; do
        if [ -n "$line" ] && [ "$(lower "$line")" = "$(lower "$author")" ]; then
            signed=1
        fi
    done < <(git show -s --format='%(trailers:key=Signed-off-by,valueonly,unfold)' "$commit")
    if [ "$signed" -eq 0 ]; then
        missing=$((missing + 1))
        echo "::error::$(git show -s --format='%h %s' "$commit"): no \"Signed-off-by: $author\""
    fi
done

if [ "$missing" -gt 0 ]; then
    cat << EOF

Commits without their author's sign-off: $missing of $checked. Each commit must
carry "Signed-off-by: Name <email>" matching its author, certifying the
Developer Certificate of Origin (see CONTRIBUTING.md). To add the sign-offs:

    git rebase --signoff $base
    git push --force-with-lease
EOF
    exit 1
fi
echo "DCO: $checked commits checked, every one signed off by its author."
