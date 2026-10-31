#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Relays, end to end: a factory's ledger that no one reaches directly (it
# serves only on a port it tells no one) is reached through a relay, the
# server of a public witness. Its invitation code carries the relay and its
# relay key. The bank asks for a record, fetches the delivery, and sends
# its receipt, each sealed through the relay and answered by the factory's
# own API (the peer token decides, as directly). Without the log key the
# bank cannot use the relay; a request the relay did not see from the bank
# is refused; and `relay stop` takes the relay out of new codes.
# Usage: relay.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="relay test"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN

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
F="$WORK/factory"
B="$WORK/bank"
f() { run "$@" --ledger "$F"; }
b() { run "$@" --ledger "$B"; }

for command in "relay key init" "relay use" "relay show" "relay stop"; do
    # shellcheck disable=SC2086
    run $command --help | contains -F "cexchain $command" || fail "help for $command"
done
run completion bash | contains relay || fail "completion"

# --- The relay: a public witness's server ------------------------------------------
for k in w-root w-log witness f-root f-log b-root b-log; do
    run key generate --out "$k.key" > /dev/null
done
run key public witness.key --out witness.pub > /dev/null
run init --ledger relay-ledger --org "Relay Org" --root-key w-root.key --log-key w-log.key \
    > /dev/null
start_server relay.json --ledger relay-ledger --witness-dir wdir --witness-key witness.key \
    --witness-public --witness-name test-relay --relay-dir mailboxes --quiet
R="$(json 'd["url"]' < relay.json)"

# --- The factory: reached through the relay ----------------------------------------
run init --org "Example Factory" --root-key f-root.key --log-key f-log.key --ledger "$F" \
    > /dev/null
run init --org "Example Bank" --root-key b-root.key --log-key b-log.key --ledger "$B" > /dev/null
printf 'test report: all dimensions within tolerance\n' > report.txt
RECORD="$(f record issue --as f-root.key --type example.document/1 --field product=Flange \
    --field result=pass --attach report.txt --json | json 'd["record"]["id"]')"
f checkpoint create --log-key f-log.key > /dev/null
b checkpoint create --log-key b-log.key > /dev/null
run relay key init --out f-relay.key > /dev/null
f relay show | contains "reached directly" || fail "no relay at first"
# Not registered with the relay's witness, and no key given: refused.
expect_exit 1 relay use "$R" --relay-key f-relay.key --ledger "$F"
f relay use "$R" --relay-key f-relay.key --witness-key witness.pub | contains "reached through" ||
    fail "relay use"
f relay show --json | json 'd["relay"]["url"]' | contains -x "$R" || fail "relay show"
f witness registered --json | json 'len(d["witnesses"])' | contains -x 1 ||
    fail "registered with the relay's witness"
# The factory serves on a port it tells no one; its relay key answers what comes.
expect_exit 1 serve --ledger "$F" --relay-key f-relay.key
contains -- '--log-key' out.txt || fail "the relay key needs the log key"

# --- The two become parties, by codes ------------------------------------------------
CODE="$(f peer invite bank --json | json 'd["code"]')"
f peer invite bank2 --json | json 'd["relay"]' | contains -x "$R" || fail "codes carry the relay"
b peer accept "$CODE" --name factory > /dev/null
b peer show factory --json | json 'd["relay"]["url"]' | contains -x "$R" ||
    fail "the bank reaches the factory through the relay"
[ "$(b peer show factory --json | json 'd["url"]')" = None ] || fail "and has no URL for it"
BACK="$(b peer invite factory --json | json 'd["code"]')"
f peer accept "$BACK" --name bank > /dev/null
start_server factory.json --ledger "$F" --log-key f-log.key --relay-key f-relay.key

# --- Asked, delivered, and received, through the relay -------------------------------
b access request --peer factory --record "$RECORD" --purpose "annual review" \
    --as b-root.key --log-key b-log.key --send | contains 'sent to factory' ||
    fail "the request went through the relay"
REQUEST="$(b access list --json | json '[i["id"] for i in d if i["kind"]=="request"][0]')"
f access inbox | contains 'annual review' || fail "the factory received it"
# Without the log key, the bank cannot sign what goes through the relay.
expect_exit 2 access fetch --peer factory --request "$REQUEST" --out early.cbor --ledger "$B"
contains 'relay' out.txt || fail "says the relay needs the log key"
expect_exit 2 access fetch --peer factory --request "$REQUEST" --out early.cbor --log-key b-log.key \
    --ledger "$B"
contains 'has not granted' out.txt || fail "not granted yet"
f access grant "${REQUEST:0:12}" --fields product,result --attach report.txt=report.txt \
    --as f-root.key --log-key f-log.key > /dev/null
b access fetch --peer factory --request "$REQUEST" --out delivery.cbor --log-key b-log.key |
    contains 'fetched' || fail "the delivery came through the relay"
b access accept delivery.cbor --as b-root.key --log-key b-log.key --save-dir received --send \
    --json > accepted.json
json 'd["fields"]["product"]' < accepted.json | contains Flange || fail "the fields"
cmp received/report.txt report.txt || fail "the file"
for _ in $(seq 1 100); do
    [ "$(f access list --json | json 'sum(1 for i in d if i["kind"]=="grant" and i["acknowledged"])')" = 1 ] && break
    sleep 0.2
done
[ "$(f access list --json | json 'sum(1 for i in d if i["kind"]=="grant" and i["acknowledged"])')" = 1 ] ||
    fail "the receipt came back through the relay"
# Everything answered: the factory's mailbox is empty.
f relay show --log-key f-log.key --json | json 'd["mailbox"]["requests"]' | contains -x 0 ||
    fail "the mailbox"

# --- Stopped: new codes carry no relay -------------------------------------------------
f relay stop | contains "no longer" || fail "relay stop"
[ "$(f peer invite carol --json | json 'd["relay"]')" = None ] || fail "no relay in new codes"
expect_exit 2 relay stop --ledger "$F"

echo "relay: all checks passed"
