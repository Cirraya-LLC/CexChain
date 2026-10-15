#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Running a ledger as a service, end to end: API tokens, the HTTP API while
# the command line keeps writing, automatic checkpoints, a replica that
# copies and checks everything, backups, and promotion.
# Usage: serve.sh CEXCHAIN
set -Eeuo pipefail
dump_logs() {
    for log in "$WORK"/*.json.log; do
        [ -f "$log" ] && { echo "--- $log"; tail -n 20 "$log"; }
    done
    return 0
}
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2; dump_logs >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="service test"
export CEXCHAIN_LEDGER="$WORK/primary"
unset CEXCHAIN_TOKEN

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; dump_logs; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# http METHOD URL [TOKEN]: prints the status, then the body.
http() {
    python3 - "$@" << 'PY'
import sys, urllib.request, urllib.error
method, url = sys.argv[1], sys.argv[2]
token = sys.argv[3] if len(sys.argv) > 3 else ""
request = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
if token:
    request.add_header("Authorization", "Bearer " + token)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status, body = response.status, response.read()
except urllib.error.HTTPError as error:
    status, body = error.code, error.read()
print(status)
sys.stdout.write(body.decode("utf-8", "replace"))
PY
}
status_of() { http "$@" | sed -n 1p; }
body_of() { http "$@" | sed -n '2,$p'; }
# start_server FILE ARGS...: serves in the background; FILE gets its JSON.
start_server() {
    local out="$1"; shift
    "$CEXCHAIN" serve --listen 127.0.0.1:0 --json "$@" > "$out" 2> "$out.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        if [ -s "$out" ] && python3 -c "import json,sys; json.load(open('$out'))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    cat "$out.log"
    fail "the server did not start"
}
url_of() { json 'd["url"]' < "$1"; }

# --- A ledger with a record ----------------------------------------------------
run key generate --out root.key > /dev/null
run key generate --out log.key > /dev/null
run init --org "Service Org" --root-key root.key --log-key log.key > /dev/null
run record issue --as root.key --type example.document/1 --field result=pass > /dev/null

# --- Tokens ----------------------------------------------------------------------
run token create replica --scope read --out replica.token | contains 'written to replica.token'
[ "$(ls -l replica.token | cut -c1-10)" = "-rw-------" ] || fail "token files must be owner-only"
run token create ops --scope read,submit,admin --json | json 'd["token"]' > ops.token
run token create metrics > metrics.out
contains 'shown only once' metrics.out
expect_exit 2 token create replica
contains 'exists' out.txt
expect_exit 1 token create 'bad name'
expect_exit 2 token create x --scope write
run token list | contains 'ops .*read,submit,admin'
run token list --json | json 'len(d)' | contains -x 3
run token show ops --json | json 'len(d["sha256"])' | contains -x 64
if grep -F "$(cat ops.token)" "$CEXCHAIN_LEDGER/api-tokens" > /dev/null; then
    fail "only hashes of tokens may be stored"
fi
run token revoke metrics | contains 'revoked'
expect_exit 2 token show metrics
REPLICA_TOKEN="$(cat replica.token)"
OPS_TOKEN="$(cat ops.token)"

# --- The API -------------------------------------------------------------------
run serve --help | contains 'POST /v1/statements'
run serve --help | contains 'max-connections-per-ip'
expect_exit 1 serve --threads 0
contains 'threads' out.txt
start_server primary.json --log-key log.key --checkpoint-interval 1 --threads 4
URL="$(url_of primary.json)"
json 'd["role"]' < primary.json | contains -x primary
[ "$(status_of GET "$URL/healthz")" = 200 ]
[ "$(status_of GET "$URL/v1/status")" = 401 ]
[ "$(status_of GET "$URL/v1/status" cxt_wrong)" = 401 ]
body_of GET "$URL/v1/status" "$REPLICA_TOKEN" | json 'd["organization"]' | contains -x 'Service Org'
[ "$(status_of POST "$URL/v1/checkpoint" "$REPLICA_TOKEN")" = 403 ]
body_of GET "$URL/metrics" "$REPLICA_TOKEN" | contains '^cexchain_log_entries '

# The command line keeps working on the served ledger; the server sees it,
# and checkpoints on its own.
# (Measured before writing: a checkpoint may land at any moment. The next
# one after the write covers it and its own state commitment.)
BEFORE="$(run status --json | json 'd["entries"]')"
run record issue --as root.key --type example.document/1 --field result=fail > /dev/null
WANT=$((BEFORE + 2))
for _ in $(seq 1 150); do
    CHECKPOINTED="$(body_of GET "$URL/v1/status" "$REPLICA_TOKEN" | json '(d["checkpoint"] or {}).get("tree_size", 0)')"
    [ "$CHECKPOINTED" -ge "$WANT" ] && break
    sleep 0.1
done
[ "$CHECKPOINTED" -ge "$WANT" ] || fail "no automatic checkpoint"
contains '"event":"checkpoint"' primary.json.log
contains '"principal":"replica"' primary.json.log
run audit | contains 'audit passed'

# --- A replica -----------------------------------------------------------------
REPLICA="$WORK/replica"
LEDGER_ID="$(run status --json | json 'd["ledger_id"]')"
# Without TLS, the ledger must be pinned; and only that ledger is accepted.
expect_exit 1 replica init --from "$URL" --ledger "$REPLICA"
contains 'needs --ledger-id' out.txt
expect_exit 2 replica init --from "$URL" --ledger-id "$LEDGER_ID" --ledger "$REPLICA"
contains 'refused the API token' out.txt
[ ! -e "$REPLICA" ] || fail "a failed replica init must not leave a directory behind"
CEXCHAIN_TOKEN="$REPLICA_TOKEN" expect_exit 2 replica init --from "$URL" --ledger "$REPLICA" \
    --ledger-id "$(printf '%064d' 7)"
contains 'another ledger than the one expected' out.txt
[ ! -e "$REPLICA" ] || fail "a refused replica init must not leave a directory behind"
CEXCHAIN_TOKEN="$REPLICA_TOKEN" run replica init --from "$URL" --ledger-id "$LEDGER_ID" \
    --ledger "$REPLICA" | contains "replica of ledger $LEDGER_ID"
run replica status --ledger "$REPLICA" --token-file replica.token --json | json 'd["behind"]' | contains -x 0
run replica status --json | json 'd["replica"]' | contains -x False
run audit --ledger "$REPLICA" | contains 'audit passed'
run record list --ledger "$REPLICA" --json | json 'len(d)' | contains -x 2
expect_exit 2 record issue --ledger "$REPLICA" --as root.key --type example.document/1 --field a=b
contains 'this ledger is a replica' out.txt
expect_exit 2 checkpoint create --ledger "$REPLICA" --log-key log.key

run record issue --as root.key --type example.document/1 --field result=again > /dev/null
# A replica takes only what a checkpoint covers: checkpoint, then sync.
run checkpoint create --log-key log.key > /dev/null
run replica sync --ledger "$REPLICA" --token-file replica.token --json > sync.json
json 'd["entries"] >= 2 and d["size"] == d["primary_size"]' < sync.json | contains -x True
ls "$REPLICA/vault/records" | contains -c '\.cbor$'

# A replica serves reads, never writes. (Tokens are each server's own.)
run token create reader --ledger "$REPLICA" --scope read,submit,admin --out reader.token > /dev/null
start_server replica.json --ledger "$REPLICA"
json 'd["role"]' < replica.json | contains -x replica
REPLICA_URL="$(url_of replica.json)"
[ "$(status_of GET "$REPLICA_URL/v1/status" "$REPLICA_TOKEN")" = 401 ]
body_of GET "$REPLICA_URL/v1/status" "$(cat reader.token)" | json 'd["writable"]' | contains -x False
[ "$(status_of POST "$REPLICA_URL/v1/statements" "$(cat reader.token)")" = 403 ]
[ "$(status_of POST "$REPLICA_URL/v1/checkpoint" "$(cat reader.token)")" = 403 ]

# A revoked token stops the replica (the server rereads tokens within a second).
run token revoke replica > /dev/null
sleep 2
expect_exit 2 replica sync --ledger "$REPLICA" --token-file replica.token
contains 'refused the API token' out.txt

# --- Backups -------------------------------------------------------------------
run backup create --ledger "$REPLICA" --out replica.cxb | contains 'unsigned'
# Unsigned: the checkpointed log verifies, and the files would be left out.
run backup verify replica.cxb --json | json 'd["ok"] and not d["signed"] and d["skipped_files"] > 0' | contains -x True
run backup verify replica.cxb | contains 'compare it with a witness'
run backup create --out primary.cxb --log-key log.key --json | json 'd["files"] > 0 and d["signed"]' | contains -x True
expect_exit 2 backup create --out other.cxb --log-key root.key
contains "not this ledger's log key" out.txt
run backup restore primary.cxb --ledger "$WORK/restored" | contains 'audit passed'
[ "$(run status --ledger "$WORK/restored" --json | json 'd["ledger_id"]')" = "$(run status --json | json 'd["ledger_id"]')" ]
run record fields "$(run record list --json | json 'd[0]["id"]')" --ledger "$WORK/restored" | contains 'result'
expect_exit 2 backup restore primary.cxb --ledger "$WORK/restored"
python3 -c "
import sys
data = bytearray(open('primary.cxb', 'rb').read())
data[-1] ^= 1
open('damaged.cxb', 'wb').write(data)
"
expect_exit 3 backup verify damaged.cxb
contains 'NOT VERIFIED' out.txt
head -c 100 primary.cxb > truncated.cxb
expect_exit 2 backup verify truncated.cxb

# --- Promotion -----------------------------------------------------------------
run replica promote --ledger "$REPLICA" | contains 'must stay'
expect_exit 2 replica promote --ledger "$REPLICA"
run record issue --ledger "$REPLICA" --as root.key --type example.document/1 --field promoted=yes > /dev/null
run audit --ledger "$REPLICA" | contains 'audit passed'

# --- Graceful stop -------------------------------------------------------------
kill -TERM "${SERVERS[0]}"
wait "${SERVERS[0]}" || fail "the server did not stop cleanly"
SERVERS=("${SERVERS[@]:1}")
echo "serve end-to-end: ok"
