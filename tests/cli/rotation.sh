#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Rotating the organization's keys, end to end: the log key and the root key
# change, evidence verifies across the change, a witness follows it, and the
# server holds the old and new log key across the switch.
# Usage: rotation.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="rotation test"
export CEXCHAIN_LEDGER="$WORK/ledger"
unset CEXCHAIN_TOKEN

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
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
stop_servers() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do wait "$pid" 2> /dev/null || true; done
    SERVERS=()
}
# get URL TOKEN OUT: fetches a binary route to OUT; prints the status.
get() {
    python3 - "$@" << 'PY'
import sys, urllib.request, urllib.error
url, token, out = sys.argv[1], sys.argv[2], sys.argv[3]
request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status, body = response.status, response.read()
except urllib.error.HTTPError as error:
    status, body = error.code, error.read()
open(out, "wb").write(body)
print(status)
PY
}

# --- A ledger, witnessed from its genesis ----------------------------------------
for k in root log log2 root2 witness; do run key generate --out "$k.key" > /dev/null; done
run key public witness.key --out witness.pub > /dev/null
run key public log.key --out log.pub > /dev/null
LEDGER_ID="$(run init --org "Rotation Org" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
FIRST="$(run record issue --as root.key --type cexchain.certificate/1 --field result=pass --json | json 'd["statement_id"]')"
run checkpoint create --log-key log.key > /dev/null

run ledger genesis --help | contains 'witness add-log --genesis'
run ledger genesis --out genesis.entry | contains "$LEDGER_ID"
expect_exit 1 witness add-log --dir witness --genesis genesis.entry --log-key log.pub
expect_exit 2 witness add-log --dir witness --genesis genesis.entry --ledger-id "$(printf '%064d' 7)"
run witness add-log --dir witness --genesis genesis.entry --ledger-id "$LEDGER_ID" --name follower \
    --json | json 'd["follows_rotations"]' | contains -x True
# A second witness that knows only the log key.
run witness add-log --dir blind --ledger-id "$LEDGER_ID" --log-key log.pub --json \
    | json 'd["follows_rotations"]' | contains -x False
for dir in witness blind; do
    run checkpoint cosign-request --witness witness.pub --from 0 --out "request-$dir.cbor" > /dev/null
    run witness cosign "request-$dir.cbor" --dir "$dir" --key witness.key --out cosig.cbor > /dev/null
done
run checkpoint add-cosignature cosig.cbor --witness witness.pub > /dev/null

# --- The keys, and the log key rotated ------------------------------------------
run ledger keys | contains 'log keys'
run ledger keys --json | json 'len(d["log_keys"]) == 1 and d["log_keys"][0]["current"]' | contains -x True
run ledger rotate-log-key --help | contains 'Witnesses follow the rotation'
expect_exit 1 ledger rotate-log-key --as log.key --new-key log2.key
contains 'current root key' out.txt
expect_exit 2 ledger rotate-log-key --as root.key --new-key log.key
contains 'log key' out.txt
run ledger rotate-log-key --as root.key --new-key log2.key --json > rotated.json
ROTATED_AT="$(json 'd["index"]' < rotated.json)"
json "d['signs_from_size'] == $ROTATED_AT + 1" < rotated.json | contains -x True
run ledger keys --json | json 'len(d["log_keys"])' | contains -x 2
run ledger keys | contains "set at index $ROTATED_AT"
run log list --type ledger-rotate-log-key | contains 'rotate the log key'

# The old key no longer checkpoints; the new one does.
expect_exit 2 checkpoint create --log-key log.key
contains 'rotated' out.txt
run checkpoint create --log-key log2.key > /dev/null
run audit | contains 'audit passed'

# --- Then the root key ------------------------------------------------------------
run ledger rotate-root-key --as root.key --new-key root2.key | contains 'root key'
expect_exit 2 record issue --as root.key --type cexchain.certificate/1 --field result=late
SECOND="$(run record issue --as root2.key --type cexchain.certificate/1 --field result=again --json | json 'd["statement_id"]')"
run checkpoint create --log-key log2.key > /dev/null
run ledger keys --json | json 'len(d["root_keys"])' | contains -x 2

# --- Evidence across the rotations ------------------------------------------------
for record in "$FIRST" "$SECOND"; do
    expect_exit 2 export "$record" --log-key log.key --out old.cbor
    run export "$record" --log-key log2.key --out "$record.cbor" > /dev/null
    run verify "$record.cbor" --ledger-id "$LEDGER_ID" --json > report.json
    json 'd["keys"]["log_key_rotations"] == 1 and d["keys"]["root_key_rotations"] == 1' \
        < report.json | contains -x True
    run verify "$record.cbor" --ledger-id "$LEDGER_ID" | contains 'every rotation checked'
done

# --- Witnesses ---------------------------------------------------------------------
run checkpoint cosign-request --witness witness.pub --out request.cbor --json \
    | json 'd["key_rotations"]' | contains -x 2
run witness cosign request.cbor --dir witness --key witness.key --out cosig2.cbor | contains 'cosigned'
run witness status --dir witness --json > witness.json
python3 -c "
import json
d = json.load(open('witness.json'))[0]
assert d['last_rotation'] > 0, d
" || fail "the witness did not follow the rotations"
run checkpoint add-cosignature cosig2.cbor --witness witness.pub > /dev/null
# The witness that knows only the log key refuses.
run checkpoint cosign-request --witness witness.pub --from "$(run witness status --dir blind --json | json 'd[0]["size"]')" \
    --out blind-request.cbor > /dev/null
expect_exit 3 witness cosign blind-request.cbor --dir blind --key witness.key --out nope.cbor
contains 'root key' out.txt

# --- The server holds both log keys across the switch ------------------------------
run token create ops --scope read,submit,admin --json | json 'd["token"]' > ops.token
expect_exit 2 serve --listen 127.0.0.1:0 --log-key log.key
contains 'rotated' out.txt
run key generate --out log3.key > /dev/null
start_server server.json --log-key log2.key --log-key log3.key --checkpoint-interval 0
URL="$(json 'd["url"]' < server.json)"
[ "$(get "$URL/v1/evidence/$FIRST" "$(cat ops.token)" served.cbor)" = 200 ]
run verify served.cbor --ledger-id "$LEDGER_ID" > /dev/null
# Rotating to the next key while serving: the command line writes, the server
# picks it up and signs the next checkpoint with the new key.
run ledger rotate-log-key --as root2.key --new-key log3.key > /dev/null
python3 - "$URL" "$(cat ops.token)" << 'PY'
import sys, time, urllib.request, urllib.error
url, token = sys.argv[1], sys.argv[2]
for _ in range(100):
    request = urllib.request.Request(url + "/v1/checkpoint", method="POST", data=b"",
                                     headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status == 200:
                sys.exit(0)
    except urllib.error.HTTPError:
        pass
    time.sleep(0.1)
sys.exit("the server did not checkpoint with the new key")
PY
[ "$(get "$URL/v1/evidence/$SECOND" "$(cat ops.token)" served2.cbor)" = 200 ]
run verify served2.cbor --ledger-id "$LEDGER_ID" --json | json 'd["keys"]["log_key_rotations"]' | contains -x 2
stop_servers

# --- A backup signed with the newest key restores ----------------------------------
run backup create --out ledger.cxb --log-key log3.key > /dev/null
expect_exit 2 backup create --out stale.cxb --log-key log2.key
run backup restore ledger.cxb --ledger "$WORK/restored" | contains 'audit passed'
run ledger keys --ledger "$WORK/restored" --json | json 'len(d["log_keys"])' | contains -x 3

echo "rotation end-to-end: ok"
