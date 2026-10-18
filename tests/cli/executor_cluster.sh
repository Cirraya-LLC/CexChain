#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# An executor as a long-running service beside a three-member cluster (6b,
# E11): one `executor run` (no --once) keeps answering while members restart
# under it: a follower; its own member, killed (kill -9) between the action
# and the answer; the leader; and the whole cluster at once. Every request is
# acted on once and answered once, none is lost, the executor never stops,
# and once its server is back it answers within seconds, not after a long
# backoff.
# Usage: executor_cluster.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2; dump_logs >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
EXECUTOR=""
dump_logs() {
    for log in "$WORK"/*.log "$WORK"/executor.jsonl; do
        [ -f "$log" ] && { echo "--- $log"; tail -n 15 "$log"; }
    done
    return 0
}
cleanup() {
    [ -n "$EXECUTOR" ] && kill -9 "$EXECUTOR" 2> /dev/null || true
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill -9 "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="executor cluster test"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN CEXCHAIN_CLOCK_OFFSET

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; dump_logs; exit 1; }
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# fixed_ports N: N distinct free ports below the ephemeral range, as in
# cluster.sh (a member's addresses are named before it binds them).
fixed_ports() {
    python3 - "$1" << 'PY'
import random, socket, subprocess, sys

def first_ephemeral():
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            return int(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    try:
        return int(subprocess.run(["sysctl", "-n", "net.inet.ip.portrange.first"],
                                  capture_output=True, text=True, check=True).stdout)
    except (OSError, ValueError, subprocess.CalledProcessError):
        return 32768

end = first_ephemeral()
end = end if 1024 < end <= 65535 else 32768
begin = max(1024, end - 16384)
if end - begin < 1024:
    begin, end = 1024, 65536
ports = []
while len(ports) < int(sys.argv[1]):
    port = random.randrange(begin, end)
    if port in ports:
        continue
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            continue
    ports.append(port)
print(" ".join(map(str, ports)))
PY
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
# status N: member N's /v1/status.
status() {
    python3 - "${API[$1]}" "$(cat ops.token)" << 'PY'
import json, sys, urllib.request
request = urllib.request.Request(sys.argv[1] + "/v1/status",
                                 headers={"Authorization": "Bearer " + sys.argv[2]})
print(urllib.request.urlopen(request, timeout=5).read().decode())
PY
}
leader_of() { status "$1" | json 'd["cluster"]["leader"]'; }
# knows_leader N: member N knows a leader that is up.
knows_leader() {
    local l
    l="$(leader_of "$1")"
    [ -n "$l" ] && [ "$l" != None ] && [ -n "${PIDS[$l]:-}" ]
}
start_member() {
    local n="$1"
    "$CEXCHAIN" serve --cluster --ledger "node$n" --listen "127.0.0.1:${APORT[$n]}" \
        --log-key log.key --checkpoint-interval 0 --json > "node$n.json" 2>> "node$n.log" &
    PIDS[$n]=$!
    echo "${PIDS[$n]}" > "member$n.pid"
    eventually 60 status "$n"
}
stop_member() { # N [SIGNAL]
    kill "-${2:-TERM}" "${PIDS[$1]}" 2> /dev/null || true
    wait "${PIDS[$1]}" 2> /dev/null || true
    unset "PIDS[$1]"
}

API=(); APORT=(); RPORT=()
read -r -a PORTS <<< "$(fixed_ports 6)"
for n in 1 2 3; do
    APORT[$n]="${PORTS[$((2 * n - 2))]}"; RPORT[$n]="${PORTS[$((2 * n - 1))]}"
    API[$n]="http://127.0.0.1:${APORT[$n]}"
done

# --- Founding: the requesting contract, an executor, its connector ------------------
run key generate --out root.key > /dev/null
run key generate --out log.key > /dev/null
LEDGER_ID="$(run init --ledger node1 --org "Cluster Org" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
# The requesting contract (tools/testvectors/test_contracts.py): open's
# [[kind, params, after], ...] makes requests, which result answers.
python3 -c "import json, sys; open('requesting.wasm', 'wb').write(bytes.fromhex(json.load(open(sys.argv[1]))['request']))" \
    "$SOURCE/testvectors/test-contracts.json"
REQ="$(run contract deploy requesting.wasm --ledger node1 --as root.key --function open=create \
    --function result=call --compiler "test_contracts.py 1" --json | json 'd["contract"]["id"]')"
run executor add Worker --contract "$REQ" --kinds notify --key-out worker.key \
    --config-out worker.json --as root.key --ledger node1 > /dev/null
run token create --ledger node1 ops --scope read,submit,admin --out ops.token > /dev/null
run token create --ledger node1 worker --scope executor --out worker.token > /dev/null
# The connector's program: logs each request it acts on. In "kill" mode it
# first kills the executor's own member (kill -9), so the answer cannot be
# sent until that member is back; in "quorum" mode, the two others, so the
# answer cannot be written until one is back.
cat > act.sh << EOF
#!/bin/sh
id="\$(python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')"
echo "\$id" >> "$WORK/actions.txt"
case "\$(cat "$WORK/mode" 2> /dev/null)" in
    kill) kill -9 "\$(cat "$WORK/member1.pid")" ;;
    quorum) kill -9 "\$(cat "$WORK/member2.pid")" "\$(cat "$WORK/member3.pid")" ;;
esac
rm -f "$WORK/mode"
echo '{"result": {"ref": "done"}}'
EOF
chmod +x act.sh
run executor connector add actor --config worker.json --type command --kinds notify \
    --program "$WORK/act.sh" --timeout 10 > /dev/null
S="$WORK/state"

# --- The cluster -----------------------------------------------------------------
run checkpoint create --ledger node1 --log-key log.key > /dev/null
run cluster init --ledger node1 --id 1 --raft "127.0.0.1:${RPORT[1]}" --api "${API[1]}" > /dev/null
start_member 1
eventually 60 knows_leader 1
export CEXCHAIN_TOKEN="$(cat ops.token)"
for n in 2 3; do
    run cluster join --ledger "node$n" --from "${API[1]}" --ledger-id "$LEDGER_ID" --id "$n" \
        --raft "127.0.0.1:${RPORT[$n]}" --api "${API[$n]}" --secret-file node1/cluster/secret > /dev/null
    cp node1/api-tokens "node$n/api-tokens"
    start_member "$n"
    run cluster add --server "${API[1]}" --id "$n" --raft "127.0.0.1:${RPORT[$n]}" --api "${API[$n]}" > /dev/null
    eventually 60 sh -c "[ \"\$(\"$CEXCHAIN\" cluster status --server ${API[1]} --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)[\"members\"]))')\" = $n ]"
done
for n in 1 2 3; do eventually 60 knows_leader "$n"; done

# --- The executor, as a service on member 1 ----------------------------------------
"$CEXCHAIN" executor run --config worker.json --state "$S" --server "${API[1]}" \
    --token-file worker.token --as worker.key --wait 1 --lease-ttl 5 --json \
    > executor.jsonl 2> executor.log &
EXECUTOR=$!
eventually 30 contains '"granted":true' executor.jsonl

# ask AT N: a request (notify, {"n": N}) made through member AT.
ASKED=0
ask() {
    run contract create "$REQ" open --args "[[\"notify\", {\"n\": $2}, 3600000]]" --as root.key \
        --server "${API[$1]}" --ledger-id "$LEDGER_ID" --cache "$WORK/cache$1" > /dev/null
    ASKED=$((ASKED + 1))
}
# all_done AT: every request asked is answered done, as member AT knows.
all_done() {
    [ "$(run request list --answered --json --server "${API[$1]}" --ledger-id "$LEDGER_ID" \
        --cache "$WORK/cache$1" | json 'sum(1 for r in d if r["status"] == "done")')" = "$ASKED" ]
}
alive() { kill -0 "$EXECUTOR"; }
other_than() { for n in 1 2 3; do [ "$n" != "$1" ] && [ -n "${PIDS[$n]:-}" ] && { echo "$n"; return; }; done; }

# Everyone up.
ask 2 1
ask 3 2
eventually 30 all_done 2

# A follower restarts (not the executor's member).
LEADER="$(leader_of 1)"
F=2; [ "$LEADER" = 2 ] && F=3
stop_member "$F" 9
ask "$(other_than "$F")" 3
eventually 30 all_done "$(other_than "$F")"
start_member "$F"
ask "$F" 4
eventually 30 all_done "$F"
alive || fail "the executor stopped"

# Its own member dies between the action and the answer: the answer waits in
# the journal, and is sent once the member is back, without a second action.
echo kill > mode
ask 2 5
journal_stage() { run executor journal list --state "$S" --json | json '" ".join(sorted(e["stage"] for e in d))'; }
waiting_answer() { journal_stage | grep -E 'outcome|answering' > /dev/null; }
eventually 60 waiting_answer || fail "the outcome was never journaled"
wait "${PIDS[1]}" 2> /dev/null || true
unset "PIDS[1]"
# Meanwhile requests come through the others (a new leader if 1 led).
eventually 60 knows_leader 2
ask 2 6
alive || fail "the executor stopped while its member was down"
start_member 1
eventually 60 all_done 1
alive || fail "the executor stopped"

# The leader dies; requests go on through the others.
eventually 60 knows_leader 1
LEADER="$(leader_of 1)"
stop_member "$LEADER" 9
SURVIVOR="$(other_than "$LEADER")"
eventually 60 knows_leader "$SURVIVOR"
ask "$SURVIVOR" 7
[ "$LEADER" != 1 ] && eventually 60 all_done "$SURVIVOR"
start_member "$LEADER"
eventually 60 all_done 1

# The two other members die after the action: member 1 is up, but no answer
# can be written without a quorum. Once they are back, it is sent at once.
for n in 1 2 3; do eventually 60 knows_leader "$n"; done
RETRIES="$(grep -c '"event":"retry-later"' executor.jsonl || true)"
more_retries() { [ "$(grep -c '"event":"retry-later"' executor.jsonl)" -gt "$RETRIES" ]; }
echo quorum > mode
ask 1 8
eventually 60 more_retries || fail "the answer was never held back"
for n in 2 3; do wait "${PIDS[$n]}" 2> /dev/null || true; unset "PIDS[$n]"; done
sleep 3
alive || fail "the executor stopped without a quorum"
for n in 2 3; do start_member "$n"; done
eventually 60 all_done 1

# The whole cluster restarts at once (as for a new clock or a new release).
for n in 1 2 3; do stop_member "$n"; done
alive || fail "the executor stopped while the cluster was down"
for n in 1 2 3; do start_member "$n"; done
for n in 1 2 3; do eventually 60 knows_leader "$n"; done
BACK="$(python3 -c 'import time; print(int(time.time()))')"
ask 3 9
ask 1 10
eventually 60 all_done 1
python3 -c 'import sys, time; sys.exit(0 if time.time() - int(sys.argv[1]) < 30 else 1)' "$BACK" \
    || fail "answers took more than 30 s once the cluster was back"

# Each request acted on once and answered once; nothing lost or waiting.
[ "$ASKED" = 10 ] || fail "ten requests"
[ "$(sort actions.txt | uniq | wc -l | tr -d ' ')" = 10 ] || fail "every request acted on"
[ "$(wc -l < actions.txt | tr -d ' ')" = 10 ] || fail "no request acted on twice"
[ "$(grep -c '"event":"acting"' executor.jsonl)" = 10 ] || fail "ten actions"
[ "$(grep -c '"event":"answered"' executor.jsonl)" = 10 ] || fail "each request answered once"
run request list --open --json --server "${API[1]}" --ledger-id "$LEDGER_ID" --cache "$WORK/cache1" \
    | json 'len(d)' | contains -x 0
run executor journal list --state "$S" --json \
    | json 'sorted(set(e["stage"] for e in d)) == ["answered"] or sorted(set(e["stage"] for e in d))' \
    > stages.txt
contains -x True stages.txt || fail "every journal entry answered: $(cat stages.txt)"
# Short backoffs: no wait of more than a few seconds was scheduled.
python3 - executor.jsonl << 'PY' || fail "a long backoff"
import json, sys
waits = [e.get("in_ms", 0) for e in map(json.loads, open(sys.argv[1])) if e["event"] == "retry-later"]
sys.exit(0 if all(w <= 10000 for w in waits) else 1)
PY
kill -TERM "$EXECUTOR"
code=0
wait "$EXECUTOR" || code=$?
EXECUTOR=""
[ "$code" -eq 0 ] || fail "a stopped executor exits 0, not $code"
tail -n 1 executor.jsonl | json 'd["event"], d["waiting"]' | contains -x "stopped 0"

echo "executor across cluster restarts: ok"
