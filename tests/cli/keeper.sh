#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Keepers (6b E4), end to end. A ledger acts only on calls: a keeper, a
# device of the home, fires each contract's time rules once they are due and
# expires the requests left open past their deadline plus a grace. Alpha runs
# Bo's time contract (`when overdue 3 days suspend`, `when suspended 30 days
# terminate`; its code from testvectors/bo-v1.json, so every build runs it)
# and the requesting contract. Keepers are registered with keeper add; keeper
# due lists what is due by dry runs (now, at a later time, for one keeper);
# keeper run fires it on the ledger directory; then the server's own keeper
# (serve --keeper-key) fires a rule whose time comes while it runs, and
# expires a request after its grace, and keeper run fires one through the
# server's API. A keeper whose delegation does not cover
# a function is refused it; a revoked keeper idles. The instance's evidence
# verifies offline with the keeper's calls in it.
# Usage: keeper.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="keeper test"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN CEXCHAIN_SERVER

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; [ -f alpha.json.log ] && tail -n 20 alpha.json.log; exit 1; }
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
# eventually SECONDS COMMAND...: retries until it succeeds.
eventually() {
    local limit="$1"; shift
    for _ in $(seq 1 $((limit * 5))); do
        if "$@" > /dev/null 2>&1; then return 0; fi
        sleep 0.2
    done
    "$@"
}

A="$WORK/alpha"
a() { run "$@" --ledger "$A"; }
status_of() { a contract instance "$1" --json | json 'd["status"]'; }
has_status() { [ "$(status_of "$1")" = "$2" ]; }
request_status() { a request show "$1" --json | json 'd["status"]'; }
is_expired() { [ "$(request_status "$1")" = expired ]; }

# --- A ledger, two contracts ----------------------------------------------------------
for k in a-root a-log; do run key generate --out "$k.key" > /dev/null; done
run init --name "Alpha" --root-key a-root.key --log-key a-log.key --ledger "$A" > /dev/null
A_ID="$(a status --json | json 'd["ledger_id"]')"
python3 - "$SOURCE/testvectors" << 'EOF'
import json, sys
bo = json.load(open(sys.argv[1] + "/bo-v1.json"))
timed = [c for c in bo["contracts"] if c["name"] == "time"][0]
open("timed.wasm", "wb").write(bytes.fromhex(timed["code"]))
open("timed.functions", "w").write(" ".join(f"--function {n}={k}" for n, k in timed["interface"].items()) + "\n")
open("timed.compiler", "w").write(timed["compiler"])
tests = json.load(open(sys.argv[1] + "/test-contracts.json"))
open("requesting.wasm", "wb").write(bytes.fromhex(tests["request"]))
EOF
# Bo's time contract: `when overdue 3 days suspend`, `when suspended 30 days
# terminate`; created with {"fields": {"due": T}, "parties": {...}}.
read -r -a TIMED_FUNCTIONS < timed.functions
T="$(a contract deploy timed.wasm "${TIMED_FUNCTIONS[@]}" --compiler "$(cat timed.compiler)" \
    --name "Timed" --as a-root.key --json | json 'd["contract"]["id"]')"
# The requesting contract: [[kind, params, after], ...] makes requests due
# `after` ms after the call, replying to result; its when.due accepts and
# changes nothing.
C="$(a contract deploy requesting.wasm --function open=create --function ask=call \
    --function result=call --function when.due=call --compiler "test_contracts.py 1" \
    --name "Requesting" --as a-root.key --json | json 'd["contract"]["id"]')"
DAY=86400000
CUSTOMER="$(python3 -c 'print("c5" * 32)')"
create_timed() {
    a contract create "$T" create --args "{\"fields\": {\"due\": $1}, \"parties\": {\"customer\": h'$CUSTOMER', \"we\": h'$A_ID'}}" \
        --as a-root.key --json | json 'd["instance"]["id"]'
}
ask() {
    a contract create "$C" open --args "[[\"notify\", null, $1]]" --as a-root.key --json \
        | json 'd["instance"]["id"]'
}

# --- Help, completion -------------------------------------------------------------------
run keeper add --help | contains "never the actions that are the home's own"
run keeper due --help | contains 'dry runs that record nothing'
run keeper run --help | contains 'never early'
run keeper list --help | contains 'no key 9'
run serve --help | contains -- '--keeper-key'
run serve --help | contains '/v1/contracts/due'
run completion bash | contains 'keeper'
run completion zsh | contains 'keeper'
run help --json | contains '"keeper due"'

# --- Keepers ----------------------------------------------------------------------------
KEEPER="$(a keeper add Keeper --contracts "$T,$C" --functions result,when.suspend,when.terminate \
    --key-out keeper.key --as a-root.key --json | json 'd["actor"]["id"]')"
[ "$(ls -l keeper.key | cut -c1-10)" = "-rw-------" ] || fail "the keeper's key must be owner-only"
# By default, the contracts' time rules and result.
a keeper add Default --contracts "${T:0:12}" --key-out default.key --as a-root.key --json > default.json
DEFAULT="$(json 'd["actor"]["id"]' < default.json)"
json '",".join(d["functions"])' < default.json | contains -x 'when.suspend,when.terminate'
json 'd["actor"]["kind"]' < default.json | contains -x device
a keeper add Both --contracts "$C" --key-out both.key --as a-root.key --json \
    | json '",".join(d["functions"])' | contains -x 'result,when.due'
NARROW="$(a keeper add Narrow --contracts "$T" --functions when.suspend --key-out narrow.key \
    --as a-root.key --json | json 'd["actor"]["id"]')"
expect_exit 1 keeper add Bad --contracts "$T" --functions create --key-out bad.key --as a-root.key --ledger "$A"
contains 'has a function create for instances' out.txt
expect_exit 1 keeper add Bad --contracts "$T" --as a-root.key --ledger "$A"
contains -- '--key-out FILE' out.txt
expect_exit 2 keeper add Again --contracts "$T" --key-out keeper.key --as a-root.key --ledger "$A"
contains 'never overwritten' out.txt
a keeper list > list.txt
contains '"Keeper" .*calls result, when.suspend, when.terminate' list.txt
[ "$(a keeper list --json | json 'len(d)')" = 4 ] || fail "four keepers"
[ "$(a keeper list --contract "$C" --json | json 'len(d)')" = 2 ] || fail "two keep the requesting contract"
a keeper show "$KEEPER" > show.txt
contains 'calls:       0 time rule(s) fired, 0 request(s) expired' show.txt
contains 'status:      active' show.txt
expect_exit 2 keeper show "$A_ID" --ledger "$A"
contains 'is no keeper' out.txt
# An executor's delegation is not a keeper's (it has key 9).
a executor add Notifier --contract "$C" --kinds notify --key-out notifier.key --as a-root.key > /dev/null
[ "$(a keeper list --json | json 'len(d)')" = 4 ] || fail "an executor is no keeper"

# --- What is due, by dry runs -------------------------------------------------------------
NOW="$(now_ms)"
S1="$(create_timed $((NOW - 3 * DAY - 3600000)))"   # an hour past its rule's time
S3="$(create_timed $((NOW + 10 * DAY)))"            # not for days
R1="$(ask 1000)"                                    # a request due in a second
a keeper due > due.txt
contains "rule    when.suspend on ${S1:0:12} (\"Timed\" (${T:0:12})), status active" due.txt
contains 'keepers: "Keeper", "Default", "Narrow"' due.txt
contains "${S3:0:12}" due.txt && fail "S3 is not due"
a keeper due --json > due.json
json 'len(d["rules"]), len(d["expiries"]), d["next"]' < due.json | contains -x '1 0 None'
json 'd["rules"][0]["late_ms"] >= 3600000' < due.json | contains -x True
json 'd["rules"][0]["time"]' < due.json | contains 'Z$'
# Later, by --at: S3 too, and the request (past its grace).
LATER="$(python3 -c "import datetime as t; print(t.datetime.fromtimestamp(($NOW + 14 * $DAY) / 1000, t.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
a keeper due --at "$LATER" --json > later.json
json 'sorted(r["instance"][:12] for r in d["rules"]) == sorted(["'"${S1:0:12}"'", "'"${S3:0:12}"'"])' < later.json | contains -x True
json 'len(d["expiries"]), d["expiries"][0]["request"] != None' < later.json | contains -x '1 True'
# For one keeper: what its delegations cover. The narrow keeper does not
# answer requests.
a keeper due --keeper "$NARROW" --at "$LATER" --json | json 'len(d["rules"]), len(d["expiries"])' | contains -x '2 0'
a keeper due --instance "$S3" --at "$LATER" --json | json 'len(d["rules"]), d["instances"]' | contains -x '1 1'
a keeper due --contract "$C" --at "$LATER" --json | json 'len(d["rules"]), len(d["expiries"])' | contains -x '0 1'
a keeper due --limit 1 > limited.txt
contains 'stopped at the run limit: --start 1 goes on' limited.txt
a keeper due --limit 1 --start 1 --json | json 'd["instances"]' | contains -x 1
expect_exit 1 keeper due --limit 0 --ledger "$A"
expect_exit 1 keeper due --grace 31622401 --ledger "$A"

# --- keeper run, on the ledger directory --------------------------------------------------
run keeper run --as default.key --ledger "$A" > run.txt
contains "fired when.suspend on ${S1:0:12} (entry #[0-9]*): status suspended, 1 h.* after its time" run.txt
a contract instance "$S1" --json | json 'd["calls"][-1]["function"], d["calls"][-1]["by"]["name"]' \
    | contains -x 'when.suspend Default'
run keeper run --as default.key --ledger "$A" | contains 'nothing due'
# The request: expired once its grace has passed (here none).
sleep 1.2
run keeper run --as keeper.key --grace 0 --json --ledger "$A" > expired.json
json 'd["calls"][0]["kind"], d["calls"][0]["request_kind"], d["calls"][0]["function"]' < expired.json \
    | contains -x 'expiry notify result'
is_expired "$(a request list --instance "$R1" --json | json 'd[0]["id"]')"
# A keeper whose delegation does not cover a function is refused it, and
# nothing is recorded: the narrow keeper cannot terminate.
SIZE="$(a status --json | json 'd["entries"]')"
expect_exit 2 contract call "$S1" when.terminate --as narrow.key --ledger "$A"
contains -i 'delegation' out.txt
[ "$(a status --json | json 'd["entries"]')" = "$SIZE" ] || fail "nothing recorded"
expect_exit 1 keeper run --as keeper.key --rounds 2 --ledger "$A"
contains -- '--rounds goes with --every' out.txt
run keeper run --as narrow.key --every 1 --rounds 2 --json --ledger "$A" > rounds.jsonl
[ "$(wc -l < rounds.jsonl | tr -d ' ')" = 2 ] || fail "one line a round"

# --- The server's keeper ------------------------------------------------------------------
# S2's rule comes due seconds after the server starts; R2's request is due in a second.
S2="$(create_timed $(($(now_ms) - 3 * DAY + 6000)))"
R2="$(ask 1000)"
a token create reader --scope read --out reader.token > /dev/null
a token create runner --scope read,submit --out runner.token > /dev/null
start_server alpha.json --ledger "$A" --log-key a-log.key --keeper-key keeper.key \
    --keeper-interval 1 --expiry-grace 2
URL="$(json 'd["url"]' < alpha.json)"
json 'd["keeper"]' < alpha.json | contains -x True
expect_exit 1 serve --ledger "$A" --expiry-grace 5
contains 'go with --keeper-key' out.txt
# The server answers what is due, by its clock.
run keeper due --server "$URL" --token-file reader.token --at "$LATER" --json > server-due.json
json '"'"${S3}"'" in [r["instance"] for r in d["rules"]]' < server-due.json | contains -x True
run keeper due --server "$URL" --token-file reader.token --keeper "$NARROW" --at "$LATER" \
    | contains "for keeper ${NARROW:0:12}"
expect_exit 1 keeper due --server "$URL" --token-file reader.token --keeper "${NARROW:0:12}"
contains 'full id' out.txt
# S2's rule comes due while the server runs: its keeper fires it, the
# request expires after its grace, and S3 waits.
eventually 60 has_status "$S2" suspended
a contract instance "$S2" --json | json 'd["calls"][-1]["function"], d["calls"][-1]["by"]["name"]' \
    | contains -x 'when.suspend Keeper'
R2_ID="$(a request list --instance "$R2" --json | json 'd[0]["id"]')"
eventually 30 is_expired "$R2_ID"
a request show "$R2_ID" --json | json 'd["answer"]["by"]["name"]' | contains -x Keeper
has_status "$S3" active
contains '"event":"keeper-fired"' alpha.json.log
contains '"event":"keeper-expired"' alpha.json.log
a keeper show "$KEEPER" > show.txt
contains 'calls:       1 time rule(s) fired, 2 request(s) expired' show.txt
# A revoked keeper calls nothing more: the server's keeper idles.
a keeper revoke "$KEEPER" --as a-root.key > revoke.txt
contains 'calls nothing more' revoke.txt
eventually 30 contains '"event":"keeper-idle"' alpha.json.log
[ "$(a keeper list --json | json 'len(d)')" = 3 ] || fail "three active keepers"
a keeper list --all | contains '"Keeper" .*\[revoked\]'
a keeper show "$KEEPER" | contains 'status:      REVOKED'
expect_exit 2 keeper revoke "$KEEPER" --as a-root.key --ledger "$A"
contains 'revoked already' out.txt
# keeper run from another computer, through the server's API (a verified
# mirror): another keeper fires a rule that came due after the server's
# keeper was revoked.
S4="$(create_timed $(($(now_ms) - 3 * DAY - 1000)))"
run keeper run --as default.key --server "$URL" --token-file runner.token --ledger-id "$A_ID" \
    --cache "$WORK/cache" > remote.txt
contains "fired when.suspend on ${S4:0:12}" remote.txt
has_status "$S4" suspended

# --- Offline: the evidence shows the keeper's call and its event -----------------------------
a contract evidence "$S2" --log-key a-log.key --out s2.cbor > /dev/null
run contract verify s2.cbor --ledger-id "$A_ID" > verify.txt
contains -F "Status       suspended" verify.txt
contains -F "when.suspend" verify.txt
contains -F "VERIFICATION FAILED" verify.txt && fail "the evidence verifies"
a audit | contains 'audit passed'

# --- A clock ahead (CEXCHAIN_CLOCK_OFFSET) ------------------------------------------------
# For demonstrations and tests every command can run its clock ahead. A
# client ahead of the ledger it writes to is refused (a statement from the
# future); a ledger run ahead fires S3's rule, not due for days.
CEXCHAIN_CLOCK_OFFSET=3x expect_exit 1 status --ledger "$A"
contains 'CEXCHAIN_CLOCK_OFFSET is a whole number' out.txt
CEXCHAIN_CLOCK_OFFSET=3661d expect_exit 1 status --ledger "$A"
run --help | contains 'CEXCHAIN_CLOCK_OFFSET'
CEXCHAIN_CLOCK_OFFSET=14d run keeper run --as default.key --server "$URL" \
    --token-file runner.token --ledger-id "$A_ID" --cache "$WORK/cache" > out.txt
contains "refused when.suspend on ${S3:0:12}.*issued in the future" out.txt
has_status "$S3" active
for pid in "${SERVERS[@]}"; do kill "$pid" 2> /dev/null || true; wait "$pid" 2> /dev/null || true; done
SERVERS=()
CEXCHAIN_CLOCK_OFFSET=14d run keeper run --as default.key --ledger "$A" > ahead.txt
contains "fired when.suspend on ${S3:0:12}" ahead.txt
has_status "$S3" suspended
# A server stamps every write: it refuses a clock ahead unless told it is
# meant, and its status shows it.
CEXCHAIN_CLOCK_OFFSET=14d expect_exit 1 serve --ledger "$A" --listen 127.0.0.1:0
contains 'pass --allow-clock-offset' out.txt
CEXCHAIN_CLOCK_OFFSET=14d start_server ahead.json --ledger "$A" --allow-clock-offset
json 'd["clock_offset_ms"]' < ahead.json | contains -x 1209600000
contains 'runs 1209600 s ahead' ahead.json.log
AHEAD_URL="$(json 'd["url"]' < ahead.json)"
python3 - "$AHEAD_URL" "$(cat reader.token)" << 'PY' | contains -x 1209600000
import json, sys, urllib.request
request = urllib.request.Request(sys.argv[1] + "/v1/status",
                                 headers={"Authorization": "Bearer " + sys.argv[2]})
print(json.load(urllib.request.urlopen(request, timeout=5))["clock_offset_ms"])
PY
CEXCHAIN_CLOCK_OFFSET=14d a audit | contains 'audit passed'

echo "keeper end-to-end: ok"
