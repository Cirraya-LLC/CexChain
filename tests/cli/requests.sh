#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Requests and answers (spec v0.8), end to end across two
# organizations: Alpha (SHA-256) runs a contract whose calls ask executors
# for work, and Beta (SM3) is a party of one of its instances and runs one of
# its own. Alpha registers an executor device that answers only notify
# requests; the device finds requests at Alpha's server (the discovery route,
# a long poll, with an executor token) and answers through it; a person
# answers by hand, late; a request expires, another is cancelled, and an
# answer makes a new request. A final instance takes answers only. Refused on
# the way: a second answer, an early expiry, an answer of another kind, an
# executor token's other statements, a contract that refuses an answer, a
# revoked executor, and a delegation wider than its grantor's. Beta fetches
# Alpha's instance as its party and verifies every request and answer
# offline; Alpha verifies Beta's.
# Usage: requests.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="requests test"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN CEXCHAIN_SERVER

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
now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
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

A="$WORK/alpha"; B="$WORK/beta"
a() { run "$@" --ledger "$A"; }
b() { run "$@" --ledger "$B"; }

# --- Two organizations; Beta's ledger hashes with SM3 ---------------------------------
for k in a-root a-log clerk; do run key generate --out "$k.key" > /dev/null; done
for k in b-root b-log b-person; do run key generate --alg sm2-sm3 --out "$k.key" > /dev/null; done
run init --name "Alpha" --root-key a-root.key --log-key a-log.key --ledger "$A" > /dev/null
run init --name "Beta" --root-key b-root.key --log-key b-log.key --hash sm3 --ledger "$B" > /dev/null
A_ID="$(a status --json | json 'd["ledger_id"]')"
B_ID="$(b status --json | json 'd["ledger_id"]')"
a peer add beta --ledger-id "$B_ID" > /dev/null

# The requesting contract (tools/testvectors/test_contracts.py): arguments
# [[kind, params, after], ...] make one request per item, due `after` ms
# after the call, replying to result; a byte string is its output; a text
# makes it refuse. An answer sets the state to [status, request].
python3 - "$SOURCE/testvectors/test-contracts.json" << 'EOF'
import json, sys
with open(sys.argv[1]) as f:
    open("requesting.wasm", "wb").write(bytes.fromhex(json.load(f)["request"]))
EOF
deploy() {
    run contract deploy requesting.wasm --function open=create --function ask=call \
        --function result=call --function when.due=call --compiler "test_contracts.py 1" \
        --name "Requesting" --json "$@" | json 'd["contract"]["id"]'
}
C="$(deploy --as a-root.key --ledger "$A")"
CLERK="$(a actor add --as a-root.key --kind person --name "Clerk" --key clerk.key --json | json 'd["actor"]["id"]')"
a delegation grant --as a-root.key --to "$CLERK" --allow contract-call,delegation-grant \
    --contracts "$C" --may-delegate > /dev/null

# --- Help, completion -------------------------------------------------------------------
run request list --help | contains 'stays open'
run request answer --help | contains 'never personal data'
run request cancel --help | contains 'cannot be withdrawn'
run request wait --help | contains 'is a hint'
run executor add --help | contains 'scope'
run delegation grant --help | contains -- '--request-kinds'
run contract verify --help | contains -- '--require-answered'
run completion bash | contains 'executor'
run completion zsh | contains 'request'
run help --json | contains '"request answer"'

# --- An instance asks for work ----------------------------------------------------------
# Created with a byte-string output, so that it names Beta as its partner:
# a notice due in an hour and a post due in two seconds.
NOW="$(now_ms)"
CREATE="<<[1, {1: \"open\", 3: {\"partner\": h'$B_ID'}, 7: [{1: \"notify\", 2: {\"about\": \"welcome\"}, 3: $((NOW + 3600000)), 4: \"result\"}, {1: \"http.post\", 2: {\"n\": 1}, 3: $((NOW + 2000)), 4: \"result\"}]}]>>"
I="$(a contract create "$C" open --args "$CREATE" --as a-root.key --json | json 'd["instance"]["id"]')"
a request list > list.txt
contains 'notify .* open' list.txt
contains 'http.post .* open' list.txt
a request list --json | json 'len(d)' | contains -x 2
R_NOTIFY="$(a request list --kind notify --json | json 'd[0]["id"]')"
R_POST="$(a request list --kind http.post --json | json 'd[0]["id"]')"
a request show "${R_NOTIFY:0:12}" > show.txt
contains 'kind:       notify' show.txt
contains 'params:     {"about": "welcome"}' show.txt
contains 'reply:      result' show.txt
contains 'answer:     none yet' show.txt
a request show "$R_NOTIFY" --json > show.json
json 'd["asked_by"]["function"]' < show.json | contains -x open
json 'd["status"]' < show.json | contains -x open
json 'd["contract"]' < show.json | contains -x "$C"
a contract instance "$I" > instance.txt
contains 'requests:  2 made by its calls, 2 open' instance.txt
a contract instance "$I" --json | json 'len(d["open_requests"])' | contains -x 2
a contract instance "$I" --json | json 'len(d["calls"][0]["requests"])' | contains -x 2
expect_exit 1 request list --open --answered --ledger "$A"
expect_exit 1 request list --kind Notify --ledger "$A"
contains 'not a request kind' out.txt

# --- An executor that answers notify requests only ---------------------------------------
NOTIFIER="$(a executor add Notifier --contract "$C" --kinds notify --key-out notifier.key \
    --as a-root.key --json | json 'd["actor"]["id"]')"
[ "$(ls -l notifier.key | cut -c1-10)" = "-rw-------" ] || fail "the executor's key must be owner-only"
expect_exit 2 executor add Notifier --contract "$C" --kinds notify --key-out notifier.key \
    --as a-root.key --ledger "$A"
contains 'never overwritten' out.txt
expect_exit 1 executor add Other --contract "$C" --kinds notify --as a-root.key --ledger "$A"
contains -- '--key' out.txt
expect_exit 1 executor add Other --contract "$C" --kinds notify --functions nope \
    --key clerk.key --as a-root.key --ledger "$A"
contains 'no function nope' out.txt
D_NOTIFIER="$(a delegation list --actor "$NOTIFIER" --json | json 'd[0]["id"]')"
a delegation show "$D_NOTIFIER" > delegation.txt
contains 'functions:     result' delegation.txt
contains 'answers:       requests of kinds notify' delegation.txt
contains 'contracts:     "Requesting"' delegation.txt
a delegation show "$D_NOTIFIER" --json | json 'd["scope"]["request_kinds"]' | contains -x "\['notify'\]"
a delegation show "$D_NOTIFIER" --json | json 'd["scope"]["functions"]' | contains -x "\['result'\]"
a executor list | contains '"Notifier" .*answers notify; 0 answer(s), 1 open request(s)'
a executor show "$NOTIFIER" | contains "waiting:     1 open request(s) it may answer"
a delegation list | contains 'calling result answering notify'

# --- Alpha's server: discovery for executors --------------------------------------------
a token create staff --scope read,submit,admin --out staff.token > /dev/null
a token create notifier --scope executor --out executor.token > /dev/null
a token create notifier-read --scope read,executor --out executor-read.token > /dev/null
a token create beta --scope peer --out beta-at-alpha.token > /dev/null
run token create --help | contains 'executor (the requests'
start_server alpha.json --ledger "$A" --log-key a-log.key
URL="$(json 'd["url"]' < alpha.json)"
b peer add alpha --ledger-id "$A_ID" --url "$URL" --token-file beta-at-alpha.token > /dev/null
WAIT=(--server "$URL" --token-file executor.token)
run request wait "${WAIT[@]}" --timeout 0 --json > wait.json
json 'len(d["requests"])' < wait.json | contains -x 2
json 'd["hint"]' < wait.json | contains -x True
json 'd["requests"][0]["params"]' < wait.json | contains -x '{"about": "welcome"}'
CURSOR="$(json 'd["cursor"]' < wait.json)"
run request wait "${WAIT[@]}" --kind notify --timeout 0 | contains 'notify .* open'
run request wait "${WAIT[@]}" --instance "$I" --timeout 0 --json | json 'len(d["requests"])' | contains -x 2
# A long poll: nothing new yet, until a call asks for another notice.
run request wait "${WAIT[@]}" --kind notify --after "$CURSOR" --timeout 20 --json > polled.json &
POLL=$!
sleep 1
a contract call "$I" ask --args '[["notify", {"about": "reminder"}, 3600000]]' --as clerk.key > /dev/null
wait "$POLL"
json 'len(d["requests"])' < polled.json | contains -x 1
json 'd["requests"][0]["params"]' < polled.json | contains -x '{"about": "reminder"}'
R_REMIND="$(json 'd["requests"][0]["id"]' < polled.json)"
expect_exit 1 request wait "${WAIT[@]}" --timeout 26
expect_exit 1 request wait --timeout 0
contains -- '--server' out.txt
expect_exit 2 request wait --server "$URL" --token-file beta-at-alpha.token --timeout 0
contains 'lacks the scope' out.txt

# An executor's token alone reads no ledger: the command line's --server
# mode needs read too. With read and executor, it answers and nothing else.
EXEC=(--server "$URL" --token-file executor-read.token --ledger-id "$A_ID" --cache "$WORK/cache")
expect_exit 2 request list --server "$URL" --token-file executor.token --ledger-id "$A_ID" \
    --cache "$WORK/cache-executor"
run request list "${EXEC[@]}" --open --json | json 'len(d)' | contains -x 3
run request answer "$R_NOTIFY" --done --args '{"ref": "N-1001"}' --as notifier.key --dry-run "${EXEC[@]}" \
    | contains 'would be recorded'
run request answer "$R_NOTIFY" --done --args '{"ref": "N-1001"}' --reference T-7 --as notifier.key \
    "${EXEC[@]}" --json > answered.json
json 'd["request"]["status"]' < answered.json | contains -x done
json 'd["request"]["answer"]["kind"]' < answered.json | contains -x device
json 'd["request"]["answer"]["delegation"]' < answered.json | contains -x "$D_NOTIFIER"
json 'd["request"]["answer"]["reference"]' < answered.json | contains -x T-7
expect_exit 2 contract call "$I" ask --args '[]' --as a-root.key "${EXEC[@]}"
contains 'answers to requests only' out.txt
run request wait "${WAIT[@]}" --state answered --timeout 0 --json | json 'd["requests"][0]["status"]' \
    | contains -x done

# --- Refusals ---------------------------------------------------------------------------
# Answered already; an expiry before the deadline; a kind its delegation does
# not cover; flags that do not go together.
expect_exit 2 request answer "$R_NOTIFY" --failed --as clerk.key --ledger "$A"
contains 'answered already' out.txt
expect_exit 2 request answer "$R_REMIND" --expired --as a-root.key --ledger "$A"
contains 'can expire only from then' out.txt
expect_exit 2 request answer "$R_POST" --done --as notifier.key --ledger "$A"
contains 'no valid delegation lets Notifier' out.txt
expect_exit 2 request answer "$R_POST" --done --as notifier.key --delegation "$D_NOTIFIER" --ledger "$A"
contains 'covers only answers to requests of its kinds' out.txt
run request answer "$R_POST" --done --as notifier.key --delegation "$D_NOTIFIER" --dry-run --ledger "$A" \
    | contains 'it would not be recorded: the ledger refuses the answer'
expect_exit 1 request answer "$R_POST" --done --failed --as clerk.key --ledger "$A"
expect_exit 1 request answer "$R_POST" --as clerk.key --ledger "$A"
expect_exit 1 request answer "$R_POST" --done --reason late --as clerk.key --ledger "$A"
expect_exit 1 request answer "$R_POST" --failed --reason "Not Found" --as clerk.key --ledger "$A"
contains 'a reason is a code' out.txt
expect_exit 1 request answer "$R_POST" --done --at 2026-01-01 --as clerk.key --ledger "$A"
# The contract decides which answers it takes: one it refuses leaves the
# request open.
expect_exit 2 request answer "$R_POST" --done --args '"not yet"' --as clerk.key --ledger "$A"
contains 'the contract refuses the call: not yet' out.txt
contains 'stays open' out.txt
a request show "$R_POST" --json | json 'd["status"]' | contains -x open

# --- A person answers by hand, late -----------------------------------------------------
sleep 2
a request list --overdue | contains 'http.post .*OVERDUE'
a contract evidence "$I" --log-key a-log.key --out overdue.cbor > /dev/null
expect_exit 3 contract verify overdue.cbor --ledger-id "$A_ID" --require-answered
contains 'still open past their deadline at the checkpoint' out.txt
contains 'http.post' out.txt
run contract verify overdue.cbor --ledger-id "$A_ID" > /dev/null
run request answer "$R_POST" --done --args '{"ref": "P-1"}' --as clerk.key --ledger "$A" > hand.txt
contains 'answered request .* (http.post): done, late by' hand.txt
a request show "$R_POST" --json > late.json
json 'd["answer"]["late"]' < late.json | contains -x True
json 'd["answer"]["kind"]' < late.json | contains -x person
json 'd["answer"]["by"]["name"]' < late.json | contains -x Clerk
a request list --answered-by "$CLERK" --json | json 'len(d)' | contains -x 1
a request list --answered-by "$NOTIFIER" --json | json 'd[0]["id"]' | contains -x "$R_NOTIFY"

# --- An answer that asks again; an expiry; a cancellation --------------------------------
# The notifier fails the reminder and the contract asks for a retry, due in two
# seconds, which nobody answers: the root expires it once it is due.
run request answer "$R_REMIND" --failed --args '[["notify", {"retry": 1}, 2000]]' --as notifier.key \
    --ledger "$A" > retry.txt
contains 'new request .* (notify)' retry.txt
R_RETRY="$(a request list --open --kind notify --json | json 'd[0]["id"]')"
sleep 2
a request answer "$R_RETRY" --expired --reason timeout --dry-run --as a-root.key | contains 'would be recorded'
a request answer "$R_RETRY" --expired --reason timeout --as a-root.key --json > expired.json
json 'd["request"]["status"]' < expired.json | contains -x expired
json 'd["request"]["answer"]["arguments"]' < expired.json | contains -x '{"reason": "timeout"}'
a contract call "$I" ask --args '[["http.post", null, 3600000]]' --as clerk.key > /dev/null
R_CANCEL="$(a request list --open --json | json 'd[0]["id"]')"
a request cancel "$R_CANCEL" --as clerk.key > cancel.txt
contains 'cancelled request .* (http.post): answered failed, reason cancelled' cancel.txt
a request show "$R_CANCEL" --json | json 'd["answer"]["arguments"]' | contains -x '{"reason": "cancelled"}'
a request list --failed --json | json 'len(d)' | contains -x 3
a request list --open --json | json 'len(d)' | contains -x 0
expect_exit 2 request cancel "$R_CANCEL" --as clerk.key --ledger "$A"
a contract instance "$I" > instance.txt
contains 'answers:   .* (http.post): done, late by' instance.txt
a contract instance "$I" --json | json '[c["answer"]["status"] for c in d["calls"] if c["answer"]]' \
    | contains -x "\['done', 'done', 'failed', 'expired', 'failed'\]"
a executor show "$NOTIFIER" --json > executor.json
json 'd["answers"]' < executor.json | contains -x 2
json '[r["kind"] for r in d["answered"]]' < executor.json | contains -x "\['notify', 'notify'\]"

# --- Beta, a party, verifies every request and answer offline ----------------------------
b contract fetch --peer alpha --instance "$I" --out alpha-instance.cbor > /dev/null
run contract verify alpha-instance.cbor --ledger-id "$A_ID" --require-answered --json > verified.json
json 'd["verified"]' < verified.json | contains -x True
json 'len(d["instance"]["requests"])' < verified.json | contains -x 5
json 'd["instance"]["open_requests"]' < verified.json | contains -x '\[\]'
json '[r["status"] for r in d["instance"]["requests"]]' < verified.json \
    | contains -x "\['done', 'done', 'failed', 'expired', 'failed'\]"
json '[c["answer"]["late"] for c in d["calls"] if c["answer"]]' < verified.json \
    | contains -x "\[False, True, False, True, False\]"
json '[c["called_by"]["kind"] for c in d["calls"] if c["answer"]]' < verified.json \
    | contains -x "\['device', 'person', 'device', 'organization', 'person'\]"
run contract verify alpha-instance.cbor --ledger-id "$A_ID" > verified.txt
contains 'LATE by' verified.txt
contains 'Requests     5 made by its calls, 5 answered, 0 open' verified.txt

# --- A final instance takes answers only -------------------------------------------------
NOW="$(now_ms)"
FINAL="<<[1, {1: \"closed\", 5: true, 7: [{1: \"notify\", 2: null, 3: $((NOW + 3600000)), 4: \"result\"}]}]>>"
F="$(a contract create "$C" open --args "$FINAL" --as a-root.key --json | json 'd["instance"]["id"]')"
a contract instance "$F" | contains 'final: it takes only answers to its open requests'
expect_exit 2 contract call "$F" ask --args '[]' --as clerk.key --ledger "$A"
contains 'is final' out.txt
R_FINAL="$(a request list --open --instance "$F" --json | json 'd[0]["id"]')"
a request answer "$R_FINAL" --done --as notifier.key | contains 'answered request .* (notify): done'
a contract instance "$F" | contains 'final: it takes no more calls'

# --- Delegations: keys 8 and 9 narrow like record types ----------------------------------
# A helper device may answer notify requests and delegate; what it delegates
# answers no more than that.
for k in helper sub; do run key generate --out "$k.key" > /dev/null; done
HELPER="$(a actor add --as a-root.key --kind device --name "Helper" --key helper.key --json | json 'd["actor"]["id"]')"
SUB="$(a actor add --as a-root.key --kind device --name "Sub" --key sub.key --json | json 'd["actor"]["id"]')"
D_HELPER="$(a delegation grant --as a-root.key --to "$HELPER" --allow contract-call,delegation-grant \
    --contracts "$C" --functions result --request-kinds notify --may-delegate --json | json 'd["delegation"]["id"]')"
expect_exit 2 delegation grant --as helper.key --delegation "$D_HELPER" --to "$SUB" \
    --allow contract-call --contracts "$C" --functions result --request-kinds http.post,notify --ledger "$A"
contains 'delegated request kinds exceed' out.txt
expect_exit 2 delegation grant --as helper.key --delegation "$D_HELPER" --to "$SUB" \
    --allow contract-call --contracts "$C" --request-kinds notify --ledger "$A"
contains 'delegated functions exceed' out.txt
a delegation grant --as helper.key --delegation "$D_HELPER" --to "$SUB" --allow contract-call \
    --contracts "$C" --functions result --request-kinds notify > /dev/null
expect_exit 1 delegation grant --as a-root.key --to "$SUB" --allow record-register \
    --request-kinds notify --ledger "$A"
contains -- '--allow contract-call' out.txt
expect_exit 1 delegation grant --as a-root.key --to "$SUB" --allow contract-call \
    --request-kinds 'Bad Kind' --ledger "$A"
a executor list --json | json 'len(d)' | contains -x 3
a executor list --kind notify --contract "$C" --json | json 'len(d)' | contains -x 3

# --- Revoking executors ------------------------------------------------------------------
a contract call "$I" ask --args '[["notify", null, 3600000]]' --as clerk.key > /dev/null
R_LAST="$(a request list --open --instance "$I" --json | json 'd[0]["id"]')"
a executor revoke "$SUB" --keep-actor --as a-root.key | contains 'answers nothing more under its delegations'
a actor show "$SUB" --json | json 'd["revoked"]' | contains -x False
a executor list --json | json 'len(d)' | contains -x 2
a executor revoke "$HELPER" --as a-root.key | contains 'revoked executor "Helper"'
a executor revoke "$NOTIFIER" --reason "replaced" --as a-root.key --json > revoked.json
json 'd["actor_revoked"]' < revoked.json | contains -x True
json 'len(d["delegations_revoked"])' < revoked.json | contains -x 1
expect_exit 2 request answer "$R_LAST" --done --as notifier.key --ledger "$A"
contains 'revoked' out.txt
a executor list | contains 'no executors'
a executor list --all | contains '"Notifier" .*\[revoked\]'
expect_exit 2 executor show "$CLERK" --ledger "$A"
contains 'is no executor' out.txt
expect_exit 2 executor revoke "$NOTIFIER" --as a-root.key --ledger "$A"
contains 'revoked already' out.txt
# Its answers stay, attributed to it.
a request list --answered-by "$NOTIFIER" --json | json 'len(d)' | contains -x 3

# --- Beta (SM3): a person answers by hand; Alpha verifies offline ------------------------
BC="$(deploy --as b-root.key --ledger "$B")"
PERSON="$(b actor add --as b-root.key --kind person --name "Beta Staff" --key b-person.key --json | json 'd["actor"]["id"]')"
b delegation grant --as b-root.key --to "$PERSON" --allow contract-call --contracts "$BC" > /dev/null
BI="$(b contract create "$BC" open --args '[["deliver", {"item": 7}, 86400000]]' --as b-root.key --json \
    | json 'd["instance"]["id"]')"
BR="$(b request list --open --json | json 'd[0]["id"]')"
[ "$BR" != "$R_NOTIFY" ] || fail "request ids differ by ledger"
b request answer "$BR" --done --args '{"ref": "D-7"}' --as b-person.key > /dev/null
b request show "$BR" --json | json 'd["answer"]["by"]["name"]' | contains -x "Beta Staff"
b contract evidence "$BI" --log-key b-log.key --out beta-instance.cbor > /dev/null
run contract verify beta-instance.cbor --ledger-id "$B_ID" --require-answered --json > beta.json
json 'd["home"]["hash"]' < beta.json | contains -x SM3
json 'd["instance"]["requests"][0]["status"]' < beta.json | contains -x done
json 'd["instance"]["requests"][0]["id"]' < beta.json | contains -x "$BR"

echo "requests end-to-end: ok"
