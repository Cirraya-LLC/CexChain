#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Snapshots of the state: written right after a checkpoint, opens start from
# the newest one that checks against the log, audit replays the whole log
# and requires the same state, a damaged one is passed over, and a server
# writes them by itself and checks the one it opened from in the background.
# Usage: snapshots.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="snapshots test"
unset CEXCHAIN_SERVER CEXCHAIN_TOKEN CEXCHAIN_CLOCK_OFFSET
export CEXCHAIN_LEDGER="$WORK/ledger"

# A command line as typed: bo, cexchain-console, and cexchain-index are the
# programs beside cexchain.
run() {
    case "$1" in
    bo | cexchain-console | cexchain-index) "$(dirname "$CEXCHAIN")/$1" "${@:2}" ;;
    *) "$CEXCHAIN" "$@" ;;
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
issue() { run record issue --as root.key --type example.document/1 --field n="$1" > /dev/null; }

for k in root log; do run key generate --out "$k.key" > /dev/null; done
run init --name "Snapshot Org" --root-key root.key --log-key log.key > /dev/null
for i in 1 2 3 4 5; do issue "$i"; done
run ledger snapshot show | contains 'no snapshot: opens replay the whole log'
[ "$(run ledger snapshot show --json | json 'd["snapshot"]')" = None ] || fail "none yet"

# Right after a checkpoint only.
expect_exit 2 ledger snapshot create
contains 'right after a checkpoint' out.txt
run checkpoint create --log-key log.key > /dev/null
SIZE="$(run ledger snapshot create --json | json 'd["size"]')"
[ "$SIZE" = "$(run status --json | json 'd["entries"]')" ] || fail "at the log's size"
[ -s ledger/snapshot-a ] || fail "the first snapshot goes in snapshot-a"
SHOWN="$(run ledger snapshot show --json)"
[ "$(echo "$SHOWN" | json 'd["snapshot"]["size"]')" = "$SIZE" ] || fail "show"
[ "$(echo "$SHOWN" | json 'd["opened_from"]["size"]')" = "$SIZE" ] || fail "opens start from it"
run ledger snapshot show | contains 'this open:  started from it'

# Later entries are replayed on top of it, and audit checks it against a
# replay of the whole log.
for i in 6 7; do issue "$i"; done
[ "$(run audit --json | json 'd["snapshot_checked"]')" = "$SIZE" ] || fail "audit checks it"
run audit | contains "the snapshot at log size $SIZE matches a replay of the whole log"
run record list --json | json 'len(d)' | contains -x 7

# The second goes in the other file; a damaged newest one is passed over.
run checkpoint create --log-key log.key > /dev/null
SECOND="$(run ledger snapshot create --json | json 'd["size"]')"
[ -s ledger/snapshot-b ] || fail "the second snapshot goes in snapshot-b"
python3 -c "
import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[300]^=1; open(p,'wb').write(b)" ledger/snapshot-b
[ "$(run ledger snapshot show --json | json 'd["opened_from"]["size"]')" = "$SIZE" ] ||
    fail "the older snapshot serves when the newer is damaged ($SECOND)"
run audit > /dev/null
run ledger snapshot remove | contains 'opens replay the whole log'
[ "$(run ledger snapshot show --json | json 'd["opened_from"]')" = None ] || fail "removed"

# A server writes them by itself, and checks the one it opened from.
serve() {
    run serve --listen 127.0.0.1:0 --json --log-key log.key --checkpoint-interval 1 \
        --snapshot-interval 1 > "$1" 2> "$1.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        python3 -c "import json; json.load(open('$1'))" 2> /dev/null && return 0
        sleep 0.1
    done
    fail "the server did not start"
}
serve first.json
issue 8
for _ in $(seq 1 100); do
    [ "$(run ledger snapshot show --json | json 'd["snapshot"] and d["snapshot"]["size"] or 0')" -gt 0 ] && break
    sleep 0.2
done
[ "$(run ledger snapshot show --json | json 'd["snapshot"]["size"]')" -gt 0 ] || fail "serve writes one"
kill "${SERVERS[-1]}"
wait "${SERVERS[-1]}" 2> /dev/null || true
serve second.json
for _ in $(seq 1 100); do
    contains '"event":"snapshot-verified"' second.json.log && break
    sleep 0.2
done
contains '"event":"snapshot-verified"' second.json.log || { cat second.json.log; fail "checked"; }
kill "${SERVERS[-1]}"
wait "${SERVERS[-1]}" 2> /dev/null || true

# Help and completion.
run ledger snapshot create --help | contains 'snapshot-a, snapshot-b'
run serve --help | contains -- '--snapshot-interval'
run completion bash | contains 'snapshot'

echo "snapshots end to end: passed"
