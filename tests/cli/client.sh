#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The command line as a client of a server (--server): actors, delegations,
# records with private data, checkpoints, receipts, and evidence, all through
# the API, shown from a mirror this client verified; keys never leave it. A
# server that serves another ledger, or a forked history, is refused.
# Usage: client.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="client test"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN

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

# --- The operator: a ledger, served, with tokens -----------------------------------
for k in root log alice; do run key generate --out "$k.key" > /dev/null; done
run key public alice.key --out alice.pub > /dev/null
LEDGER_ID="$(run init --ledger primary --org "Client Org" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
run token create --ledger primary ops --scope read,submit,admin --out ops.token > /dev/null
run token create --ledger primary reader --scope read --out reader.token > /dev/null
start_server primary.json --ledger primary --log-key log.key --checkpoint-interval 0
URL="$(json 'd["url"]' < primary.json)"

# --- A client: the same commands, with --server ------------------------------------
export CEXCHAIN_SERVER="$URL"
export CEXCHAIN_TOKEN="$(cat ops.token)"
CACHE="$WORK/cache"
run status --help | contains -- '--server URL'
expect_exit 1 token list --server "$URL"
expect_exit 1 status --cache "$CACHE" --ledger primary --server "$URL"
# Plain HTTP: the ledger must be pinned on first use.
expect_exit 1 status --cache "$CACHE"
contains 'needs --ledger-id' out.txt
expect_exit 2 status --cache "$CACHE" --ledger-id "$(printf '%064d' 7)"
contains 'not the one expected' out.txt
run status --cache "$CACHE" --ledger-id "$LEDGER_ID" --json | json 'd["ledger_id"]' | contains -x "$LEDGER_ID"
# Pinned now: no --ledger-id needed.
run status --cache "$CACHE" | contains 'Client Org'
[ -d "$CACHE/$LEDGER_ID" ] || fail "no mirror in the cache"

ALICE="$(run actor add --cache "$CACHE" --as root.key --kind person --name Alice --key alice.pub --json | json 'd["statement_id"]')"
run actor list --cache "$CACHE" | contains 'Alice'
run delegation grant --cache "$CACHE" --as root.key --to "$ALICE" --allow record-register,record-transition \
    --record-types cexchain.certificate/1 > /dev/null
RECORD="$(run record issue --cache "$CACHE" --as alice.key --type cexchain.certificate/1 \
    --field result=pass --field batch=B-7 --json | json 'd["statement_id"]')"
# The private data went to the server's vault with the record.
[ -f "primary/vault/records/$RECORD.cbor" ] || fail "the server did not keep the record's private data"
run record fields "$RECORD" --cache "$CACHE" --vault-key primary/vault/vault.key | contains 'B-7'
run record transition "$RECORD" --cache "$CACHE" --as alice.key --to suspended > /dev/null
run record show "$RECORD" --cache "$CACHE" --json | json 'd["state"]' | contains -x suspended
run log list --cache "$CACHE" --json | json 'len(d)' | contains -x 5

# The server signs what the log key signs; this client checks it.
expect_exit 1 checkpoint create --cache "$CACHE" --log-key log.key
run checkpoint create --cache "$CACHE" --json | json 'd["tree_size"]' | contains -x 6
run export "$RECORD" --cache "$CACHE" --disclose result --vault-key primary/vault/vault.key --out record.cbor > /dev/null
run verify record.cbor --ledger-id "$LEDGER_ID" --json > report.json
json 'd["verified"] and d["complete"] and d["disclosed_fields"]["result"] == "pass"' < report.json | contains -x True
run receipt 1 --cache "$CACHE" --out receipt.cbor > /dev/null
run inspect receipt.cbor | contains 'receipt'
run audit --cache "$CACHE" | contains 'audit passed'
# The operator's own view agrees.
[ "$(run status --ledger primary --json | json 'd["root"]')" = "$(run status --cache "$CACHE" --json | json 'd["root"]')" ]

# A read token cannot write; the mirror itself is never written to directly.
CEXCHAIN_TOKEN="$(cat reader.token)" expect_exit 2 record issue --cache "$CACHE" --as alice.key \
    --type cexchain.certificate/1 --field result=fail
contains 'refused' out.txt
expect_exit 2 record issue --ledger "$CACHE/$LEDGER_ID" --as alice.key --type cexchain.certificate/1 \
    --field result=fail
contains 'replica' out.txt
expect_exit 2 checkpoint cosign-request --cache "$CACHE" --peer nobody --send

# --- Servers that lie ----------------------------------------------------------------
# Another ledger behind a URL pinned to this one: refused.
run key generate --out other.key > /dev/null
run init --ledger other --org "Other Org" --root-key other.key --log-key log.key > /dev/null
run token create --ledger other ops --scope read,submit,admin --out other.token > /dev/null
start_server other.json --ledger other
OTHER_URL="$(json 'd["url"]' < other.json)"
CEXCHAIN_TOKEN="$(cat other.token)" expect_exit 2 status --cache "$CACHE" --server "$OTHER_URL" \
    --ledger-id "$LEDGER_ID"
contains 'not the one expected' out.txt

# A fork of this ledger: same id, a different history after the copy.
cp -R primary fork
run record issue --ledger fork --as root.key --type cexchain.certificate/1 --field result=forked > /dev/null
run checkpoint create --ledger fork --log-key log.key > /dev/null
run record issue --cache "$CACHE" --as alice.key --type cexchain.certificate/1 --field result=real > /dev/null
run checkpoint create --cache "$CACHE" > /dev/null
start_server fork.json --ledger fork
FORK_URL="$(json 'd["url"]' < fork.json)"
expect_exit 2 status --cache "$CACHE" --server "$FORK_URL" --ledger-id "$LEDGER_ID"
contains 'does not show the history' out.txt
# The honest server still works.
run status --cache "$CACHE" > /dev/null

echo "client end-to-end: ok"
