#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Trust nodes (spec v0.16), end to end: a trust node registers a membership
# naming a school's ledger and serves its proof (GET /m/LEDGER); the school
# lists the trust node, fetches the proof, and the evidence it exports
# carries it; a verifier who chose the trust node sees whom the school is,
# and one who did not sees a node it relies on for nothing; a suspension
# shows in a fresher proof; the trust files go with backups.
# Usage: trust.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in "${SERVERS[@]}"; do kill "$pid" 2> /dev/null || true; done
    wait 2> /dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="trust test"
unset CEXCHAIN_SERVER CEXCHAIN_TOKEN CEXCHAIN_LEDGER

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
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
fetch() {
    curl -s -D headers.txt -o body.cbor -w '%{http_code}' "$1"
}

for k in n-root n-log s-root s-log; do run key generate --out "$k.key" > /dev/null; done
NODE="$(run init --ledger node --name "HK Trust" --root-key n-root.key --log-key n-log.key --json |
    json 'd["ledger_id"]')"
SCHOOL="$(run init --ledger school --name "Kowloon Example School" --root-key s-root.key \
    --log-key s-log.key --json | json 'd["ledger_id"]')"

# --- The trust node registers the membership ------------------------------------------
M="$(run trust member add "$SCHOOL" --ledger node --as n-root.key --name "Kowloon Example School" \
    --verified --registration 12345678 --jurisdiction HK --note "business registration seen" \
    --json | json 'd["membership"]')"
run trust member list --ledger node | contains "Kowloon Example School (organization, verified)"
S="$(run trust member show "$M" --ledger node --json)"
[ "$(echo "$S" | json 'd["status"]')" = active ] || fail "active when registered"
[ "$(echo "$S" | json 'd["jurisdiction"]')" = HK ] || fail "its jurisdiction"
[ "$(run trust member list --ledger node --member "$SCHOOL" --json | json 'len(d)')" = 1 ] ||
    fail "listed by member"
expect_exit 1 trust member add "$NODE" --ledger node --as n-root.key --name "Itself"
expect_exit 1 trust member add "$SCHOOL" --ledger node --as n-root.key --name X --jurisdiction hk
expect_exit 1 trust member add "$SCHOOL" --ledger node --as n-root.key --name X --kind company
expect_exit 1 trust member add "${SCHOOL:0:12}" --ledger node --as n-root.key --name X

# --- Served to anyone ------------------------------------------------------------------
start_server node.json --ledger node --log-key n-log.key --checkpoint-interval 0
URL="$(json 'd["url"]' < node.json)"
[ "$(fetch "$URL/m/$SCHOOL")" = 200 ] || fail "GET /m/LEDGER"
contains -i "^access-control-allow-origin: \*" headers.txt || fail "any page may read it"
contains -i "^cache-control: no-store" headers.txt || fail "never cached"
run verify body.cbor --ledger-id "$NODE" --json | json 'd["record"]["type"]' |
    contains -x "cexchain.membership/1"
[ "$(fetch "$URL/m/$NODE")" = 404 ] || fail "no membership names it"
[ "$(fetch "$URL/m/xyz")" = 400 ] || fail "not a ledger id"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/m/$SCHOOL")" = 405 ] || fail "GET only"

# --- The school lists the trust node and fetches its proof --------------------------------
run trust node add hktrust --ledger school --ledger-id "$NODE" --url "$URL" |
    contains "added trust node hktrust"
expect_exit 2 trust node add again --ledger school --ledger-id "$NODE" --url "$URL"
expect_exit 1 trust node add bad --ledger school --ledger-id "$NODE" --url "ftp://x"
expect_exit 1 trust node add self --ledger school --ledger-id "$SCHOOL" --url "$URL"
run trust node list --ledger school | contains "no proof yet"
run trust node fetch --ledger school | contains "Kowloon Example School is active"
[ "$(run trust node list --ledger school --json | json 'd[0]["proof"]["state"]')" = active ] ||
    fail "the proof kept"
[ -f "school/trust/proofs/$NODE.cbor" ] || fail "kept beside the ledger"

# --- The school's evidence carries it -------------------------------------------------------
CERT="$(run record issue --ledger school --as s-root.key --type example.org.diploma/1 \
    --field name="Chan Tai Man" --json | json 'd["record"]["id"]')"
run checkpoint create --ledger school --log-key s-log.key > /dev/null
run export "$CERT" --ledger school --log-key s-log.key --out cert.cbor > /dev/null
R="$(run verify cert.cbor --ledger-id "$SCHOOL" --trust-node "$NODE=HK Trust" --json)"
[ "$(echo "$R" | json 'd["verified"]')" = True ] || fail "verified"
[ "$(echo "$R" | json 'd["memberships"][0]["trusted"]')" = True ] || fail "trusted"
[ "$(echo "$R" | json 'd["memberships"][0]["trust_node_name"]')" = "HK Trust" ] || fail "named by the list"
[ "$(echo "$R" | json 'd["memberships"][0]["name"]')" = "Kowloon Example School" ] || fail "whom it names"
[ "$(echo "$R" | json 'd["memberships"][0]["at_record"]')" = active ] || fail "active then"
run verify cert.cbor --ledger-id "$SCHOOL" --trust-node "$NODE=HK Trust" |
    contains "Member       per HK Trust (trust node ${NODE:0:12}), which you trust"
run verify cert.cbor --ledger-id "$SCHOOL" | contains "which you have not chosen: not relied on"
[ "$(run verify cert.cbor --ledger-id "$SCHOOL" --json | json 'd["memberships"][0]["trust_node_name"]')" = None ] ||
    fail "named by nothing the evidence says"
expect_exit 1 verify cert.cbor --trust-node "$NODE"
expect_exit 1 verify cert.cbor --trust-node "xyz=HK Trust"
expect_exit 1 verify cert.cbor --trust-node "$NODE=HK Trust" --trust-node "$NODE=Other"
# The membership's own evidence carries no proofs, even on a ledger that keeps some.
run export "$M" --ledger node --log-key n-log.key --out m.cbor > /dev/null
[ "$(run verify m.cbor --json | json 'len(d["memberships"])')" = 0 ] || fail "a proof carries none"

# --- Suspended: a fresher proof says so -----------------------------------------------------
run trust member suspend "$M" --ledger node --as n-root.key | contains "suspended membership"
expect_exit 2 trust member suspend "$M" --ledger node --as n-root.key
run trust node fetch hktrust --ledger school | contains "is suspended"
run export "$CERT" --ledger school --log-key s-log.key --out cert2.cbor > /dev/null
R="$(run verify cert2.cbor --ledger-id "$SCHOOL" --trust-node "$NODE=HK Trust" --json)"
[ "$(echo "$R" | json 'd["memberships"][0]["at_record"]')" = active ] || fail "active when issued"
[ "$(echo "$R" | json 'd["memberships"][0]["at_checkpoint"]')" = suspended ] || fail "suspended since"
run trust member resume "$M" --ledger node --as n-root.key | contains "resumed membership"
run trust member end "$M" --ledger node --as n-root.key | contains "ended membership"
expect_exit 2 trust member resume "$M" --ledger node --as n-root.key
[ "$(run trust member show "$M" --ledger node --json | json 'd["status"]')" = ended ] || fail "ended"
M2="$(run trust member add "$SCHOOL" --ledger node --as n-root.key --name "Kowloon Example School" \
    --verified --json | json 'd["membership"]')"
run trust member revoke "$M2" --ledger node --as n-root.key --reason "forged papers" |
    contains "revoked membership"
expect_exit 2 trust member revoke "$M2" --ledger node --as n-root.key
run trust node fetch --ledger school | contains "is revoked"

# --- Backups keep the trust files; removing a node drops its proof --------------------------
run backup create --ledger school --log-key s-log.key --out b.cxb > /dev/null
run backup restore b.cxb --ledger restored > /dev/null
[ -f "restored/trust/nodes.json" ] && [ -f "restored/trust/proofs/$NODE.cbor" ] || fail "restored"
run trust node remove hktrust --ledger school | contains "removed trust node hktrust"
[ ! -f "school/trust/proofs/$NODE.cbor" ] || fail "its proof removed"
run export "$CERT" --ledger school --log-key s-log.key --out cert3.cbor > /dev/null
[ "$(run verify cert3.cbor --json | json 'len(d["memberships"])')" = 0 ] || fail "no proof goes"
expect_exit 2 trust node fetch --ledger school
expect_exit 2 trust node remove hktrust --ledger school

for command in "trust member add" "trust member list" "trust member show" "trust member suspend" \
    "trust member resume" "trust member end" "trust member revoke" "trust node add" \
    "trust node list" "trust node remove" "trust node fetch"; do
    read -r -a words <<< "$command"
    run "${words[@]}" --help | contains -- '--json'
done
run verify --help | contains -- '--trust-node'
run completion bash | contains 'trust'
run record types --json | contains "cexchain.membership/1"
echo "trust nodes: passed"
