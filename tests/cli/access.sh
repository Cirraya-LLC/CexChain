#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Two organizations, end to end: a bank asks a factory for a quality
# certificate and its report; the factory grants part of it; the bank checks
# what it gets against the factory's ledger and acknowledges it. First with
# files, then online through each other's servers, where they also witness
# each other's ledgers.
# Usage: access.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="access test"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN

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
    "$CEXCHAIN" serve --listen 127.0.0.1:0 --json --quiet "$@" > "$out" 2> "$out.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        if [ -s "$out" ] && python3 -c "import json; json.load(open('$out'))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    cat "$out.log"
    fail "the server did not start"
}

F="$WORK/factory"
B="$WORK/bank"
f() { run "$@" --ledger "$F"; }
b() { run "$@" --ledger "$B"; }

# --- Two organizations -------------------------------------------------------
for k in f-root f-log b-root b-log o-root o-log; do run key generate --out "$k.key" > /dev/null; done
run init --org "Example Factory" --root-key f-root.key --log-key f-log.key --ledger "$F" > /dev/null
run init --org "Example Bank" --root-key b-root.key --log-key b-log.key --ledger "$B" > /dev/null
run init --org "Someone Else" --root-key o-root.key --log-key o-log.key --ledger "$WORK/other" > /dev/null
printf 'test report: all dimensions within tolerance\n' > report.txt
RECORD="$(f record issue --as f-root.key --type cexchain.certificate/1 --field product=Flange \
    --field result=pass --field price=1200 --attach report.txt --json | json 'd["record"]["id"]')"
F_ID="$(f status --json | json 'd["ledger_id"]')"
B_ID="$(b status --json | json 'd["ledger_id"]')"
O_ID="$(run status --ledger "$WORK/other" --json | json 'd["ledger_id"]')"

# Each learns the other's ledger id out of band.
f peer add bank --ledger-id "$B_ID" | contains 'added peer bank'
b peer add factory --ledger-id "$F_ID" > /dev/null
f peer list | contains '^bank'
f peer show bank --json | json 'd["ledger_id"]' | contains -x "$B_ID"
expect_exit 1 peer add bad --ledger-id 1234 --ledger "$F"
expect_exit 1 peer add self --ledger-id "$F_ID" --ledger "$F"
expect_exit 2 peer add again --ledger-id "$B_ID" --ledger "$F"

# --- With files ----------------------------------------------------------------
# The bank asks for the result and the report (not the price).
b access request --peer factory --record "$RECORD" --purpose "loan collateral check" \
    --fields product,result --attachments report.txt --days 10 \
    --as b-root.key --log-key b-log.key --out request.cbor | contains 'requested access'
REQUEST="$(b access list --json | json '[i["id"] for i in d if i["kind"]=="request"][0]')"

# The factory checks who asks, and grants the result only, with the report.
f access grant request.cbor --fields result --attach report.txt=report.txt \
    --as f-root.key --log-key f-log.key --out delivery.cbor --json > grant.json
json 'd["fields"]' < grant.json | contains -x "\['result'\]"
GRANT="$(json 'd["grant"]' < grant.json)"
f record show "$GRANT" | contains 'cexchain.access-grant/1'

# The bank checks it all, gets the value and the file, and acknowledges.
b access accept delivery.cbor --as b-root.key --log-key b-log.key --save-dir received \
    --out receipt.cbor > accepted.txt
contains 'ACCEPTED: cexchain.certificate/1' accepted.txt
contains '^  result = pass$' accepted.txt
contains -v 'price' accepted.txt
cmp report.txt received/report.txt || fail "the delivered report differs"
f access receipt receipt.cbor | contains 'acknowledged the delivery'
f access list --json | json '[i["acknowledged"] for i in d if i["kind"]=="grant"][0]' | contains -x True
b access list --json | json 'sorted(i["kind"] for i in d)' | contains -x "\['receipt', 'request'\]"
f audit | contains 'audit passed'
b audit | contains 'audit passed'

# What must fail.
python3 -c "
data = bytearray(open('delivery.cbor', 'rb').read())
data[-20] ^= 1
open('tampered.cbor', 'wb').write(data)
"
expect_exit 3 access accept tampered.cbor --as b-root.key --log-key b-log.key --ledger "$B"
contains 'NOT ACCEPTED' out.txt
expect_exit 2 access accept delivery.cbor --as f-root.key --log-key f-log.key --ledger "$F"
contains 'not a peer' out.txt
run peer add factory --ledger-id "$F_ID" --ledger "$WORK/other" > /dev/null
run access request --peer factory --record "$RECORD" --purpose "curious" --as o-root.key \
    --log-key o-log.key --out stranger.cbor --ledger "$WORK/other" > /dev/null
expect_exit 2 access grant stranger.cbor --as f-root.key --log-key f-log.key --ledger "$F"
contains 'not a peer' out.txt
expect_exit 2 access grant request.cbor --fields nosuch --as f-root.key --log-key f-log.key --ledger "$F"
contains 'no field named nosuch' out.txt
expect_exit 2 access grant request.cbor --as f-root.key --log-key f-log.key --ledger "$F"
contains 'give its content with --attach' out.txt
expect_exit 2 access receipt receipt.cbor --ledger "$B"

# --- Online, through each other's servers ---------------------------------------
f token create bank --scope peer --out bank-at-factory.token > /dev/null
b token create factory --scope peer --out factory-at-bank.token > /dev/null
# The bank witnesses the factory's ledger.
run key public f-log.key --out f-log.pub > /dev/null
run key generate --out b-witness.key > /dev/null
run key public b-witness.key --out b-witness.pub > /dev/null
run witness add-log --dir b-witness --ledger-id "$F_ID" --log-key f-log.pub --name factory > /dev/null
start_server factory.json --ledger "$F" --log-key f-log.key
start_server bank.json --ledger "$B" --log-key b-log.key --witness-dir b-witness --witness-key b-witness.key
F_URL="$(json 'd["url"]' < factory.json)"
B_URL="$(json 'd["url"]' < bank.json)"
f peer remove bank > /dev/null
f peer add bank --ledger-id "$B_ID" --url "$B_URL" --token-file factory-at-bank.token \
    --witness-key b-witness.pub > /dev/null
b peer remove factory > /dev/null
b peer add factory --ledger-id "$F_ID" --url "$F_URL" --token-file bank-at-factory.token > /dev/null

b access request --peer factory --record "$RECORD" --purpose "annual review" \
    --as b-root.key --log-key b-log.key --send | contains 'sent to factory'
ONLINE="$(b access list --json | json '[i["id"] for i in d if i["kind"]=="request" and i["purpose"]=="annual review"][0]')"
expect_exit 2 access fetch --peer factory --request "$ONLINE" --out d2.cbor --ledger "$B"
contains 'has not granted' out.txt
f access inbox | contains 'annual review'
f access grant "${ONLINE:0:12}" --fields product --attachments '' \
    --as f-root.key --log-key f-log.key > /dev/null
f access inbox --json | json 'd[0]["granted"]' | contains -x True
b access fetch --peer factory --request "$ONLINE" --out d2.cbor | contains 'fetched'
b access accept d2.cbor --as b-root.key --log-key b-log.key --send --json > accepted2.json
json 'd["fields"]["product"]' < accepted2.json | contains Flange
for _ in $(seq 1 50); do
    [ "$(f access list --json | json 'sum(1 for i in d if i["kind"]=="grant" and i["acknowledged"])')" = 2 ] && break
    sleep 0.1
done
f access list --json | json 'sum(1 for i in d if i["kind"]=="grant" and i["acknowledged"])' | contains -x 2

# Mutual witnessing: the bank cosigns the factory's checkpoints online.
f checkpoint create --log-key f-log.key > /dev/null
f checkpoint cosign-request --peer bank --send | contains 'bank cosigned'
f checkpoint cosign-request --peer bank --send | contains 'bank cosigned' # a retry is fine
run witness status --dir b-witness --json | json 'd[0]["size"] > 0' | contains -x True
f export "$RECORD" --log-key f-log.key --out evidence.cbor > /dev/null
run verify evidence.cbor --ledger-id "$F_ID" --witness b-witness.pub --min-witnesses 1 | contains 'Witnesses    1 trusted'
expect_exit 1 checkpoint cosign-request --ledger "$F" --send
echo "access end-to-end: ok"
