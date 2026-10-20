#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# An executor works requests at once (D-056, P4), end to end: many requests
# over many instances, several per instance, through a command connector run
# as several copies. The connector's program notes every action and checks
# that no two requests of one instance are acted on at once. The executor is
# killed (kill -9) at random points while it works, and restarted: in the
# end every request is answered once; a request is acted on again only after
# a kill that caught it acting (its outcome not yet journaled), and never
# after its outcome was. The options that set how many requests run at once:
# their help, completion, JSON, and refusals.
# Usage: executor_concurrency.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill -9 "$pid" 2> /dev/null || true; done
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="executor test"
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
lacks() { ! grep "$@" > /dev/null; }
healthy() { python3 -c "import urllib.request; urllib.request.urlopen('$1/healthz', timeout=1)"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
wait_for() {
    local tries="$1"; shift
    for _ in $(seq 1 "$tries"); do
        if "$@" > /dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    return 1
}

A="$WORK/alpha"
a() { run "$@" --ledger "$A"; }
for k in a-root a-log; do run key generate --out "$k.key" > /dev/null; done
run init --name "Alpha" --root-key a-root.key --log-key a-log.key --ledger "$A" > /dev/null
python3 - "$SOURCE/testvectors/test-contracts.json" << 'EOF'
import json, sys
with open(sys.argv[1]) as f:
    open("requesting.wasm", "wb").write(bytes.fromhex(json.load(f)["request"]))
EOF
C="$(a contract deploy requesting.wasm --function open=create --function ask=call \
    --function result=call --function when.due=call --compiler "test_contracts.py 1" \
    --name "Requesting" --as a-root.key --json | json 'd["contract"]["id"]')"

# --- The options: help, completion, refusals ---------------------------------------
run executor run --help | contains -- '--concurrency N'
run executor run --help | contains 'never two of one instance'
run executor connector add --help | contains -- '--concurrency N'
run executor connector add --help | contains 'one for a program'
run completion bash | contains '"executor run") opts=.*--concurrency'
run completion bash | contains '"executor connector add") opts=.*--concurrency'
run completion zsh | contains '"executor run") opts=.*--concurrency'

# --- Twelve instances, three requests each ----------------------------------------
INSTANCES=12
for i in $(seq 1 "$INSTANCES"); do
    a contract create "$C" open --args \
        "[[\"notify\", {\"n\": $i}, 3600000], [\"notify\", {\"n\": $((i + 100))}, 3600000], [\"notify\", {\"n\": $((i + 200))}, 3600000]]" \
        --as a-root.key > /dev/null
done
TOTAL=$((INSTANCES * 3))
a request list --open --json | json 'len(d)' | contains -x "$TOTAL"

# The program: notes each action (and its instance), takes the instance's
# place for the while it works (a second request of the instance there at
# the same time is an overlap), and answers done.
mkdir -p inflight
cat > act.sh << EOF
#!/bin/sh
read -r line
id=\$(printf '%s' "\$line" | sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p')
instance=\$(printf '%s' "\$line" | sed -n 's/.*"instance":"\([0-9a-f]*\)".*/\1/p')
echo "\$id \$instance" >> "$WORK/actions.txt"
if mkdir "$WORK/inflight/\$instance" 2> /dev/null; then
    sleep 0.\$(printf '%s' "\$id" | cut -c1 | tr 'abcdef' '123456')
    rmdir "$WORK/inflight/\$instance"
else
    echo "\$id \$instance" >> "$WORK/overlaps.txt"
fi
echo '{"result":{"ref":"ok"}}'
EOF
chmod +x act.sh

a executor add Worker --contract "$C" --kinds notify --key-out worker.key \
    --config-out worker.json --as a-root.key > /dev/null
expect_exit 1 executor connector add actor --config worker.json --type command --kinds notify \
    --program "$WORK/act.sh" --concurrency 0
expect_exit 1 executor connector add actor --config worker.json --type command --kinds notify \
    --program "$WORK/act.sh" --concurrency 257
run executor connector add actor --config worker.json --type command --kinds notify \
    --program "$WORK/act.sh" --timeout 10 --concurrency 6 --json | json 'd["concurrency"]' \
    | contains -x 6
run executor connector list --config worker.json | contains 'actor .*6 at once'
run executor connector show actor --config worker.json --json | json 'd["concurrency"]' | contains -x 6
json 'd["connectors"][0]["concurrency"]' < worker.json | contains -x 6

a token create worker --scope executor --out worker.token > /dev/null
PORT="$(free_port)"
URL="http://127.0.0.1:$PORT"
"$CEXCHAIN" serve --listen "127.0.0.1:$PORT" --ledger "$A" --log-key a-log.key --quiet \
    > server.out 2> server.log &
PIDS+=("$!")
wait_for 300 healthy "$URL" || { cat server.log; fail "the server did not start"; }
S="$WORK/state"
RUN=("$CEXCHAIN" executor run --config worker.json --state "$S" --server "$URL"
    --token-file worker.token --as worker.key --lease-ttl 5)
expect_exit 1 executor run --config worker.json --state "$S" --server "$URL" \
    --token-file worker.token --as worker.key --concurrency 0
contains 'concurrency' out.txt

answered() { [ "$(trap - ERR; a request list --answered --json 2> /dev/null | json 'len(d)')" = "$TOTAL" ]; }
idle() { [ -z "$(ls inflight)" ]; }

# --- Killed while it works, and restarted -------------------------------------------
# Each run's events go to its own file; a kill may cut its last line.
for round in 1 2 3 4; do
    "${RUN[@]}" --wait 1 --concurrency 8 --json > "run$round.jsonl" 2> "run$round.log" &
    EXECUTOR=$!
    PIDS+=("$EXECUTOR")
    # Somewhere between its start and its end: after 0.2 to 1.5 s.
    sleep "$(python3 -c "import random; random.seed($round * 7919); print(round(random.uniform(0.2, 1.5), 2))")"
    kill -9 "$EXECUTOR" 2> /dev/null || true
    wait "$EXECUTOR" 2> /dev/null || true
    # Its connectors finish the program in hand, then exit.
    wait_for 100 idle || fail "a program did not end"
    if answered; then break; fi
done
"${RUN[@]}" --wait 1 --concurrency 8 --json > final.jsonl 2> final.log &
EXECUTOR=$!
PIDS+=("$EXECUTOR")
wait_for 600 answered || { cat final.jsonl; fail "not every request was answered"; }
kill -TERM "$EXECUTOR"
code=0
wait "$EXECUTOR" || code=$?
[ "$code" -eq 0 ] || fail "a stopped executor exits 0, not $code"
contains '"concurrency":8' final.jsonl
contains '"event":"stopped"' final.jsonl

# --- Every request answered once, by the executor, done ------------------------------
a request list --open --json | json 'len(d)' | contains -x 0
a request list --answered --json | json 'sorted(set(r["status"] for r in d))' | contains -Fx "['done']"
run executor journal list --state "$S" --final --json | json 'len(d)' | contains -x "$TOTAL"
run executor journal list --state "$S" --json \
    | json 'sorted(set(e["stage"] for e in d))' | contains -Fx "['answered']"
[ ! -f overlaps.txt ] || { cat overlaps.txt; fail "two requests of one instance were acted on at once"; }

# Acted on once each, except where a kill caught a request acting: then once
# more, never after its outcome was journaled.
python3 - "$TOTAL" run*.jsonl final.jsonl << 'EOF'
import collections, json, sys
total, logs = int(sys.argv[1]), sys.argv[2:]
actions = collections.Counter(line.split()[0] for line in open("actions.txt"))
assert len(actions) == total, (len(actions), total)
interrupted = collections.Counter()
decided = set()
for log in logs:
    open_acts = set()
    for line in open(log):
        try:
            e = json.loads(line)
        except ValueError:
            continue  # cut by the kill
        r = e.get("request")
        if e["event"] == "acting":
            assert r not in decided, f"{r} acted on after its outcome was journaled"
            open_acts.add(r)
        elif e["event"] in ("outcome", "retry"):
            open_acts.discard(r)
            if e["event"] == "outcome":
                decided.add(r)
    interrupted.update(open_acts)
again = {r: n for r, n in actions.items() if n > 1}
for r, n in again.items():
    assert n <= 1 + interrupted[r], (r, n, interrupted[r])
print(f"{total} requests, {sum(actions.values())} actions, {len(again)} acted on again after a kill")
EOF
echo "executor concurrency end to end: OK"
