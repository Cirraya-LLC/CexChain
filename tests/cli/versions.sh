#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Versions: a record issued as the new version of another supersedes it. The
# old one shows as superseded in show, list, and versions, and its evidence
# says so (a verifier is told a newer version replaced it); the new one's
# evidence names the version it replaced. A record is superseded once, and
# a delegation must cover the old record's type too.
# Usage: versions.sh KANHE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

export KANHE_PASSPHRASE="versions test"
unset KANHE_SERVER KANHE_TOKEN
export KANHE_LEDGER="$WORK/ledger"

# A command line as typed: bo, kanhe-console, and kanhe-index are the
# programs beside kanhe.
run() {
    case "$1" in
    bo | kanhe-console | kanhe-index) "$(dirname "$KANHE")/$1" "${@:2}" ;;
    *) "$KANHE" "$@" ;;
    esac
}
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

for k in root log clerk; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --name "Versions School" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
CLERK="$(run actor add --as root.key --kind person --name "Form Clerk" --key clerk.key --json | json 'd["actor"]["id"]')"
run delegation grant --as root.key --to "$CLERK" --allow record-register \
    --record-types example.school.form/2 --days 30 > /dev/null

issue() { run record issue --as root.key "$@" --json | json 'd["record"]["id"]'; }
V1="$(issue --type example.school.form/1 --field text="version 1" --meta title="Day student application")"
V2="$(issue --type example.school.form/1 --field text="version 2" --meta title="Day student application" \
    --supersedes "${V1:0:12}")"
run record issue --as root.key --type example.school.form/2 --field text="version 3" \
    --supersedes "$V2" > out.txt
contains "supersedes: $V2 (now an old version)" out.txt
V3="$(run record list --type example.school.form/2 --json | json 'd[0]["id"]')"

# The old versions show as superseded; the latest as the latest.
run record show "$V1" > show.txt
contains "superseded: by $V2 at .*; the latest version is $V3" show.txt
contains 'version:    1 of 3' show.txt
run record show "$V3" | contains "supersedes: $V2"
SHOWN="$(run record show "$V2" --json)"
[ "$(echo "$SHOWN" | json 'd["supersedes"]')" = "$V1" ] || fail "show --json supersedes"
[ "$(echo "$SHOWN" | json 'd["superseded_by"]')" = "$V3" ] || fail "show --json superseded_by"
[ "$(echo "$SHOWN" | json 'd["latest"]')" = "$V3" ] || fail "show --json latest"
[ "$(echo "$SHOWN" | json 'd["version"], d["versions"]')" = "2 3" ] || fail "show --json version"
echo "$SHOWN" | json 'd["superseded_at"]' | contains -E '^20[0-9]{2}-'
run record list | contains "${V1:0:12} .*\[superseded\]"
[ "$(run record list --current --json | json '[r["id"] for r in d]')" = "['$V3']" ] || fail "list --current"
[ "$(run record list --json | json 'len(d)')" = 3 ] || fail "list keeps old versions"
run record versions "$V2" > versions.txt
[ "$(wc -l < versions.txt)" -eq 3 ] || fail "three versions"
contains -E "^  2  ${V2:0:12} .*<- this one" versions.txt
contains -E "^  3  ${V3:0:12} .*\[latest\]" versions.txt
[ "$(run record versions "$V3" --json | json '[r["id"] for r in d]')" = "['$V1', '$V2', '$V3']" ] ||
    fail "versions --json"
# The registration is about both records.
run record history "$V1" | contains "a new version of ${V1:0:12}"

# A record is superseded once.
expect_exit 2 record issue --as root.key --type example.school.form/2 --field text=again --supersedes "$V1"
contains 'superseded already' out.txt
# The clerk may register the second form only, so cannot replace the first.
expect_exit 2 record issue --as clerk.key --type example.school.form/2 --field text=x --supersedes "$V2"
contains 'type of the record it supersedes' out.txt
# But may replace one of its own type (V3 is the latest).
V4="$(run record issue --as clerk.key --type example.school.form/2 --field text="version 4" \
    --supersedes "$V3" --json | json 'd["record"]["id"]')"
run record versions "$V1" --json | json 'len(d)' | contains -x 4
expect_exit 2 record issue --as root.key --type example.school.form/2 --field text=x --supersedes 00000000000000000000
expect_exit 1 record versions

# Evidence: the old version's report says a newer one replaced it.
run checkpoint create --log-key log.key > /dev/null
run export "$V1" --log-key log.key --out old.cbor > /dev/null
run verify old.cbor --ledger-id "$LEDGER_ID" > old.txt
contains "Superseded   by a newer version, id ${V2:0:12}" old.txt
contains "superseded by a new version (example.school.form/1, id ${V2:0:12})" old.txt
REPORT="$(run verify old.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$REPORT" | json 'd["record"]["superseded_by"]')" = "$V2" ] || fail "report superseded_by"
[ "$(echo "$REPORT" | json 'd["complete"]')" = True ] || fail "the old version's report is complete"
[ "$(echo "$REPORT" | json '[e["new_version"] for e in d["events"]][-1]')" = "$V2" ] || fail "event new_version"
run export "$V4" --log-key log.key --out new.cbor > /dev/null
REPORT="$(run verify new.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$REPORT" | json 'd["record"]["supersedes"]')" = "$V3" ] || fail "report supersedes"
[ "$(echo "$REPORT" | json 'd["record"]["superseded_by"]')" = None ] || fail "the latest is not superseded"
run verify new.cbor --ledger-id "$LEDGER_ID" | contains "Supersedes   the earlier version, id ${V3:0:12}"

# Help and completion name the options.
run record issue --help | contains -- '--supersedes RECORD'
run record list --help | contains -- '--current'
run record versions --help | contains 'oldest first'
run completion bash | contains 'versions'
echo "versions: all checks passed"
