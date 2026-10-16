#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A three-member cluster, end to end: founding, joining, writes through any
# member, the leader killed (no acknowledged write lost, a new leader within
# seconds), the old leader back and caught up, and a hand-over. A request a
# contract call made before the leader died is found at the new leader and
# answered through a follower (spec v0.8). Every member runs a keeper
# (serve --keeper-key): only the leader's acts, expiring overdue requests,
# and a new leader's carries on.
# Usage: cluster.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2; dump_logs >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
dump_logs() {
    for log in "$WORK"/*.log; do
        [ -f "$log" ] && { echo "--- $log"; tail -n 15 "$log"; }
    done
    return 0
}
cleanup() {
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill -9 "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="cluster test"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN

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
# fixed_ports N: N distinct ports for the members' Raft and API addresses,
# which the cluster's membership names, so they are chosen before a member
# binds them. Not from bind(0): that hands out ports from the ephemeral range,
# where the system also picks the local end of every outgoing connection, and
# by the time a member started (or restarted), one of the cluster's own Raft
# or client connections could hold its port ("Address already in use"). These
# come from just below that range, where the system assigns none, and each is
# free when chosen. (tests/support/ports.hpp does the same for C++ tests.)
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
if end - begin < 1024:  # no room below the range: any port, as free as can be checked
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
# status N: member N's /v1/status (no mirror involved).
status() {
    python3 - "${API[$1]}" "$(cat ops.token)" << 'PY'
import json, sys, urllib.request
request = urllib.request.Request(sys.argv[1] + "/v1/status",
                                 headers={"Authorization": "Bearer " + sys.argv[2]})
print(urllib.request.urlopen(request, timeout=5).read().decode())
PY
}
leader_of() { status "$1" | json 'd["cluster"]["leader"]'; }
size_of() { status "$1" | json 'd["size"]'; }
# has_size N SIZE: member N holds SIZE entries (evaluated on each call).
has_size() { [ "$(size_of "$1")" = "$2" ]; }
# digest N SIZE: a hash of member N's first SIZE log entries.
# The status of the one request an instance made.
is_expired() {
    [ "$(client request list --instance "$1" --json | json 'd[0]["status"]')" = expired ]
}
digest() {
    python3 - "${API[$1]}" "$(cat ops.token)" "$2" << 'PY'
import hashlib, sys, urllib.request
url, token, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
request = urllib.request.Request(f"{url}/v1/entries?start=0&count={size}",
                                 headers={"Authorization": "Bearer " + token})
print(hashlib.sha256(urllib.request.urlopen(request, timeout=5).read()).hexdigest())
PY
}
start_member() {
    local n="$1"
    "$CEXCHAIN" serve --cluster --ledger "node$n" --listen "127.0.0.1:${APORT[$n]}" \
        --log-key log.key --checkpoint-interval 0 --keeper-key keeper.key --keeper-interval 1 \
        --expiry-grace 0 --json > "node$n.json" 2> "node$n.log" &
    PIDS[$n]=$!
    eventually 60 status "$n"
}

API=(); APORT=(); RPORT=()
read -r -a PORTS <<< "$(fixed_ports 6)"
for n in 1 2 3; do
    APORT[$n]="${PORTS[$((2 * n - 2))]}"; RPORT[$n]="${PORTS[$((2 * n - 1))]}"
    API[$n]="http://127.0.0.1:${APORT[$n]}"
done

# --- Founding --------------------------------------------------------------------
run key generate --out root.key > /dev/null
run key generate --out log.key > /dev/null
LEDGER_ID="$(run init --ledger node1 --org "Cluster Org" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
run record issue --ledger node1 --as root.key --type example.document/1 --field n=0 > /dev/null
# The requesting contract (tools/testvectors/test_contracts.py): a call's
# [[kind, params, after], ...] makes requests, which result answers.
python3 -c "import json, sys; open('requesting.wasm', 'wb').write(bytes.fromhex(json.load(open(sys.argv[1]))['request']))" \
    "$SOURCE/testvectors/test-contracts.json"
REQ="$(run contract deploy requesting.wasm --ledger node1 --as root.key --function open=create \
    --function result=call --compiler "test_contracts.py 1" --json | json 'd["contract"]["id"]')"
# The keeper: it may call the contract's result, so it expires its requests.
run keeper add Keeper --contracts "$REQ" --key-out keeper.key --as root.key --ledger node1 > /dev/null
run token create --ledger node1 ops --scope read,submit,admin --out ops.token > /dev/null
run cluster init --help | contains 'Three members ride out the loss of one'
expect_exit 2 cluster init --ledger node1 --id 1 --raft "127.0.0.1:${RPORT[1]}" --api "${API[1]}"
contains 'checkpoint the whole log first' out.txt
run checkpoint create --ledger node1 --log-key log.key > /dev/null
run cluster init --ledger node1 --id 1 --raft "127.0.0.1:${RPORT[1]}" --api "${API[1]}" \
    | contains 'founds a cluster'
[ "$(ls -l node1/cluster/secret | cut -c1-10)" = "-rw-------" ] || fail "the secret must be owner-only"
expect_exit 1 serve --ledger node1 --cluster --threads 0
start_member 1
eventually 60 sh -c "[ \"\$(\"$CEXCHAIN\" cluster status --server ${API[1]} --token-file ops.token --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"leads\"])')\" = True ]"

# --- Joining -----------------------------------------------------------------------
export CEXCHAIN_TOKEN="$(cat ops.token)"
for n in 2 3; do
    run cluster join --ledger "node$n" --from "${API[1]}" --ledger-id "$LEDGER_ID" --id "$n" \
        --raft "127.0.0.1:${RPORT[$n]}" --api "${API[$n]}" --secret-file node1/cluster/secret \
        | contains 'copied the cluster'
    cp node1/api-tokens "node$n/api-tokens"
    start_member "$n"
    run cluster add --server "${API[1]}" --id "$n" --raft "127.0.0.1:${RPORT[$n]}" --api "${API[$n]}" \
        | contains 'being added'
    eventually 60 sh -c "[ \"\$(\"$CEXCHAIN\" cluster status --server ${API[1]} --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)[\"members\"]))')\" = $n ]"
done
run cluster status --server "${API[1]}" | contains 'leader'
# A member's files are its own while it runs: the command line goes through the API.
expect_exit 2 status --ledger node2

# --- Writes through any member -----------------------------------------------------
client() { run "$@" --server "${API[$CLIENT_AT]}" --ledger-id "$LEDGER_ID" --cache "$WORK/cache"; }
CLIENT_AT=3   # a follower: writes go to the leader
for i in 1 2 3; do
    client record issue --as root.key --type example.document/1 --field "n=$i" > /dev/null
done
client contract create "$REQ" open --args '[["notify", null, 86400000]]' --as root.key > /dev/null
REQUEST="$(client request list --open --json | json 'd[0]["id"]')"
# A request due in a second: the leader's keeper expires it; the followers'
# keepers do nothing.
SHORT="$(client contract create "$REQ" open --args '[["notify", null, 1000]]' --as root.key --json | json 'd["instance"]["id"]')"
eventually 60 is_expired "$SHORT"
FIRST_LEADER="$(leader_of 1)"
contains '"event":"keeper-expired"' "node$FIRST_LEADER.log" || fail "the leader's keeper expires it"
for n in 1 2 3; do
    [ "$n" = "$FIRST_LEADER" ] || ! contains '"event":"keeper-' "node$n.log" || fail "member $n is no leader"
done
client checkpoint create > /dev/null
WANT="$(size_of 1)"
for n in 1 2 3; do eventually 60 has_size "$n" "$WANT"; done
[ "$(digest 1 "$WANT")" = "$(digest 2 "$WANT")" ] || fail "members 1 and 2 differ"
[ "$(digest 1 "$WANT")" = "$(digest 3 "$WANT")" ] || fail "members 1 and 3 differ"

# --- The leader dies ---------------------------------------------------------------
LEADER="$(leader_of 2)"
# A request falls due while the leader is down: the new leader's keeper expires it.
LATE="$(client contract create "$REQ" open --args '[["notify", null, 2000]]' --as root.key --json | json 'd["instance"]["id"]')"
kill -9 "${PIDS[$LEADER]}"; wait "${PIDS[$LEADER]}" 2> /dev/null || true; unset "PIDS[$LEADER]"
# Its files are still a member's: nothing writes to them outside the cluster.
expect_exit 2 record issue --ledger "node$LEADER" --as root.key --type example.document/1 --field n=x
contains 'cluster member' out.txt
expect_exit 2 serve --ledger "node$LEADER" --listen 127.0.0.1:0
contains 'serve it with --cluster' out.txt
OTHERS=(); for n in 1 2 3; do [ "$n" != "$LEADER" ] && OTHERS+=("$n"); done
CLIENT_AT="${OTHERS[0]}"
NEW=""
for _ in $(seq 1 300); do
    NEW="$(leader_of "${OTHERS[0]}" 2> /dev/null || true)"
    [ -n "$NEW" ] && [ "$NEW" != "None" ] && [ "$NEW" != "$LEADER" ] && break
    sleep 0.2
done
[ -n "$NEW" ] && [ "$NEW" != "None" ] && [ "$NEW" != "$LEADER" ] || fail "no new leader"
# Acknowledged writes all survived; new ones go on.
for i in 4 5; do
    eventually 60 client record issue --as root.key --type example.document/1 --field "n=$i"
done
client checkpoint create > /dev/null
client record list --json | json 'len(d)' | contains -x 6
eventually 60 is_expired "$LATE"
contains '"event":"keeper-expired"' "node$NEW.log" || fail "the new leader's keeper expires it"
# The request made before the failover is open at the new leader, and an
# answer through a follower reaches it.
run request wait --server "${API[$NEW]}" --token-file ops.token --timeout 0 --json \
    | json 'd["requests"][0]["id"]' | contains -x "$REQUEST"
client request answer "$REQUEST" --done --as root.key > /dev/null
run request wait --server "${API[$NEW]}" --token-file ops.token --state answered --timeout 0 --json \
    | json '[r["status"] for r in d["requests"] if r["id"] == "'"$REQUEST"'"][0]' | contains -x done
WANT="$(size_of "$NEW")"
for n in "${OTHERS[@]}"; do eventually 60 has_size "$n" "$WANT"; done
[ "$(digest "${OTHERS[0]}" "$WANT")" = "$(digest "${OTHERS[1]}" "$WANT")" ] || fail "survivors differ"

# --- The old leader comes back and catches up --------------------------------------
start_member "$LEADER"
eventually 60 has_size "$LEADER" "$WANT"
[ "$(digest "$LEADER" "$WANT")" = "$(digest "$NEW" "$WANT")" ] || fail "the old leader differs"
[ "$(leader_of "$LEADER")" = "$NEW" ] || fail "the old leader should follow"

# --- A frozen leader (as if cut off), then thawed: no fork --------------------------
FROZEN="$(leader_of "$LEADER")"
kill -STOP "${PIDS[$FROZEN]}"
LIVE=(); for n in 1 2 3; do [ "$n" != "$FROZEN" ] && LIVE+=("$n"); done
CLIENT_AT="${LIVE[0]}"
for _ in $(seq 1 300); do
    THAWED_LEADER="$(leader_of "${LIVE[0]}" 2> /dev/null || true)"
    [ -n "$THAWED_LEADER" ] && [ "$THAWED_LEADER" != "None" ] && [ "$THAWED_LEADER" != "$FROZEN" ] && break
    sleep 0.2
done
[ "$THAWED_LEADER" != "$FROZEN" ] || fail "no leader while the old one is frozen"
eventually 60 client record issue --as root.key --type example.document/1 --field n=frozen
kill -CONT "${PIDS[$FROZEN]}"
WANT="$(size_of "$THAWED_LEADER")"
eventually 60 has_size "$FROZEN" "$WANT"
[ "$(digest "$FROZEN" "$WANT")" = "$(digest "$THAWED_LEADER" "$WANT")" ] || fail "the thawed leader forked"
NEW="$THAWED_LEADER"
LEADER="$FROZEN"

# --- A hand-over ---------------------------------------------------------------------
run cluster step-down --server "${API[$NEW]}" | contains 'handing'
for _ in $(seq 1 300); do
    NEXT="$(leader_of "$LEADER" 2> /dev/null || true)"
    [ -n "$NEXT" ] && [ "$NEXT" != "None" ] && [ "$NEXT" != "$NEW" ] && break
    sleep 0.2
done
[ "$NEXT" != "$NEW" ] || fail "leadership did not move"
eventually 60 client record issue --as root.key --type example.document/1 --field n=6
client audit | contains 'audit passed'

echo "cluster end-to-end: ok"
