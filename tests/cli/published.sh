#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Records published at a private address: a certificate's fields disclosed
# at GET /c/TOKEN for anyone (any page may read it), the evidence as it is
# when asked (revoked since, it says so at once), on a ledger directory and
# through a server, kept in backups, taken down again.
# Usage: published.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="published test"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN

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
# GET with curl: status, then the headers and body in files.
fetch() {
    curl -s -D headers.txt -o body.cbor -w '%{http_code}' "$1"
}

for k in root log; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --ledger local --name "School" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
CERT="$(run record issue --ledger local --as root.key --type example.org.diploma/1 \
    --field name="Chan Tai Man" --field degree="BSc" --field grades="A, A, B" --json | json 'd["record"]["id"]')"

# --- On the ledger directory: publish, list, refuse what is not a field ------------
P="$(run record publish --ledger local "$CERT" --disclose name,degree --url https://school.example/ --json)"
TOKEN="$(echo "$P" | json 'd["token"]')"
[ "${#TOKEN}" = 22 ] || fail "a token is 22 characters"
[ "$(echo "$P" | json 'd["address"]')" = "https://school.example/c/$TOKEN" ] || fail "the address"
[ "$(echo "$P" | json '[f["name"] for f in d["fields"]]')" = "['name', 'degree']" ] || fail "the fields, as asked"
[ "$(echo "$P" | json 'd["fields"][0]["value"]')" = "Chan Tai Man" ] || fail "the values shown"
expect_exit 2 record publish --ledger local "$CERT" --disclose nickname
run record published --ledger local | contains "$TOKEN"
[ "$(run record published --ledger local --json | json 'len(d)')" = 1 ] || fail "one published"
[ -f "local/published/$TOKEN.cbor" ] || fail "kept beside the ledger"
stat -c %a "local/published/$TOKEN.cbor" 2> /dev/null | contains -x 600 ||
    stat -f %Lp "local/published/$TOKEN.cbor" | contains -x 600 || fail "kept privately"

# --- Served: anyone with the address, any page ----------------------------------------
run token create --ledger local ops --scope read,submit,admin --out ops.token > /dev/null
start_server server.json --ledger local --log-key log.key --checkpoint-interval 0
URL="$(json 'd["url"]' < server.json)"
[ "$(fetch "$URL/c/$TOKEN")" = 200 ] || fail "GET /c/TOKEN"
contains -i "^access-control-allow-origin: \*" headers.txt || fail "any page may read it"
contains -i "^cache-control: no-store" headers.txt || fail "never cached"
REPORT="$(run verify body.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$REPORT" | json 'd["verified"]')" = True ] || fail "the evidence verifies"
echo "$REPORT" | json 'd["disclosed_fields"]' | contains "Chan Tai Man" || fail "the name disclosed"
! echo "$REPORT" | json 'd["disclosed_fields"]' | contains "A, A, B" || fail "the grades stay sealed"
[ "$(fetch "$URL/c/AAAAAAAAAAAAAAAAAAAAAA")" = 404 ] || fail "an unknown token"
[ "$(fetch "$URL/c/not-a-token")" = 404 ] || fail "not a token"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/c/$TOKEN")" = 405 ] || fail "GET only"
[ "$(fetch "$URL/v1/published")" = 401 ] || fail "the list needs an admin token"

# Revoked: the address says so at once, the server checkpointing first.
run record revoke --ledger local --as root.key "$CERT" --reason "issued in error" > /dev/null
[ "$(fetch "$URL/c/$TOKEN")" = 200 ] || fail "GET /c/TOKEN after a revocation"
run verify body.cbor --ledger-id "$LEDGER_ID" --json | json 'd["record"]["revoked"]' | contains -x True ||
    fail "the revocation shows"

# --- Through the server (client mode, an admin token) ----------------------------------
export CEXCHAIN_SERVER="$URL" CEXCHAIN_TOKEN="$(cat ops.token)"
CACHE="$WORK/cache"
run status --cache "$CACHE" --ledger-id "$LEDGER_ID" > /dev/null
SECOND="$(run record issue --cache "$CACHE" --as root.key --type example.org.diploma/1 \
    --field name="Wong Siu Ming" --field degree="MSc" --json | json 'd["record"]["id"]')"
P2="$(run record publish --cache "$CACHE" "$SECOND" --disclose name --vault-key local/vault/vault.key --json)"
T2="$(echo "$P2" | json 'd["token"]')"
[ "$(echo "$P2" | json 'd["address"]')" = "$URL/c/$T2" ] || fail "the whole address in client mode"
[ "$(run record published --cache "$CACHE" --json | json 'len(d)')" = 2 ] || fail "two listed through the server"
[ "$(fetch "$URL/c/$T2")" = 200 ] || fail "published through the server"
run record unpublish --cache "$CACHE" "$T2" | contains "took the address down"
[ "$(fetch "$URL/c/$T2")" = 404 ] || fail "taken down"
expect_exit 2 record unpublish --cache "$CACHE" "$T2"
CEXCHAIN_TOKEN="$(cat ops.token)" expect_exit 2 record publish --cache "$CACHE" "$SECOND" --disclose nickname \
    --vault-key local/vault/vault.key
unset CEXCHAIN_SERVER CEXCHAIN_TOKEN

# --- Backups keep them with the private data ----------------------------------------
run backup create --ledger local --log-key log.key --out b.cxb > /dev/null
run backup restore b.cxb --ledger restored > /dev/null
[ -f "restored/published/$TOKEN.cbor" ] || fail "restored"
run record published --ledger restored --json | json 'd[0]["token"]' | contains -x "$TOKEN"

run record unpublish --ledger local "$TOKEN" > /dev/null
[ "$(run record published --ledger local --json | json 'len(d)')" = 0 ] || fail "taken down"
for command in "record publish" "record published" "record unpublish"; do
    read -r -a words <<< "$command"
    run "${words[@]}" --help | contains -- '--json'
done
run completion bash | contains 'publish'
echo "published records: passed"
