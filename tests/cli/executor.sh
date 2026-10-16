#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The executor runtime (6b, E5), end to end: Alpha's requesting contract asks
# for notices (answered through a webhook to a local receiver that checks
# the HMAC signature) and posts (answered by a command connector, a script
# run without a shell). The executor finds requests at Alpha's server with an
# executor token, verifies each in the instance's signed evidence, journals,
# acts, and answers: done, failed with a reason, after a retry. A lying API
# that invents a request gets nothing done. A crash (kill -9) between acting
# and answering resumes without a second action; a keeper that expires a
# request while the executor cannot answer it makes the late answer final in
# the journal, not retried. Two copies of one executor take turns by the
# server's lease. Secrets are sealed and never shown. Every answer verifies
# offline.
# Usage: executor.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2> /dev/null || true; done
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
lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
# Waits up to N tenths of a second for a command to succeed.
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
for k in a-root a-log clerk; do run key generate --out "$k.key" > /dev/null; done
run init --name "Alpha" --root-key a-root.key --log-key a-log.key --ledger "$A" > /dev/null
A_ID="$(a status --json | json 'd["ledger_id"]')"
python3 - "$SOURCE/testvectors/test-contracts.json" << 'EOF'
import json, sys
with open(sys.argv[1]) as f:
    open("requesting.wasm", "wb").write(bytes.fromhex(json.load(f)["request"]))
EOF
C="$(a contract deploy requesting.wasm --function open=create --function ask=call \
    --function result=call --function when.due=call --compiler "test_contracts.py 1" \
    --name "Requesting" --as a-root.key --json | json 'd["contract"]["id"]')"
CLERK="$(a actor add --as a-root.key --kind person --name "Clerk" --key clerk.key --json | json 'd["actor"]["id"]')"
a delegation grant --as a-root.key --to "$CLERK" --allow contract-call --contracts "$C" > /dev/null
I="$(a contract create "$C" open --args '[]' --as a-root.key --json | json 'd["instance"]["id"]')"
# Asks for a request of KIND with PARAMS, due AFTER ms from now; prints its id.
ask() {
    a contract call "$I" ask --args "[[\"$1\", $2, $3]]" --as clerk.key > /dev/null
    a request list --open --kind "$1" --json | json 'd[-1]["id"]'
}
status_of() { a request show "$1" --json | json 'd["status"]'; }

# --- Help, completion -------------------------------------------------------------------
run executor run --help | contains 'never acted on'
run executor run --help | contains 'never params, results, responses'
run executor connector add --help | contains 'never through a shell'
run executor secret set --help | contains 'never from the command line'
run executor journal show --help | contains 'HASH(salt || response)'
run connector webhook --help | contains 'X-CexChain-Signature'
run connector command --help | contains 'EX_TEMPFAIL'
run completion bash | contains '"executor connector") words="add list remove show"'
run completion zsh | contains 'executor secret'
run help --json | contains '"executor run"'

# --- The executor, its config, its secrets ---------------------------------------------
a executor add Worker --contract "$C" --kinds http.post,notify --key-out worker.key \
    --config-out worker.json --as a-root.key --json > worker-added.json
WORKER="$(json 'd["actor"]["id"]' < worker-added.json)"
json 'd["config_file"]' < worker-added.json | contains -x worker.json
json 'd["actor"]' < worker.json | contains -x "$WORKER"
json 'd["ledger_id"]' < worker.json | contains -x "$A_ID"
json 'len(d["connectors"])' < worker.json | contains -x 0
expect_exit 2 executor add Other --contract "$C" --kinds notify --key-out other.key \
    --config-out worker.json --as a-root.key --ledger "$A"
contains 'never overwritten' out.txt
[ ! -f other.key ] || fail "nothing is registered when the config cannot be written"
expect_exit 2 executor check --config worker.json
contains 'no connectors yet' out.txt

S="$WORK/state"
printf 'shared-hook-secret\n' > hook.secret.input
printf 'shared-hook-secret' > hook.secret
run executor secret set hook-key --state "$S" --from-file hook.secret.input > secret.txt
contains 'secret hook-key set (18 bytes' secret.txt
lacks 'shared-hook-secret' secret.txt
printf 'panel-token-value' | run executor secret set panel-token --state "$S" --json \
    | json 'd["bytes"]' | contains -x 17
run executor secret list --state "$S" --json | json '",".join(d)' | contains -x 'hook-key,panel-token'
[ "$(ls -l "$S/secrets.key" | cut -c1-10)" = "-rw-------" ] || fail "the secrets key is owner-only"
python3 - "$S" << 'EOF'
import os, sys
for name in os.listdir(os.path.join(sys.argv[1], "secrets")):
    data = open(os.path.join(sys.argv[1], "secrets", name), "rb").read()
    assert b"shared-hook-secret" not in data and b"panel-token-value" not in data, name
EOF
printf 'x' | run executor secret set gone --state "$S" > /dev/null
run executor secret remove gone --state "$S" > /dev/null
expect_exit 2 executor secret remove gone --state "$S"
expect_exit 1 executor secret set 'bad name' --state "$S"

# The webhook receiver: logs each POST, checks its signature (401 if wrong),
# and answers from a queue of "STATUS BODY" lines, else 200 with a result.
cat > receiver.py << 'EOF'
import hashlib, hmac, json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
work = sys.argv[1]
secret = open(os.path.join(work, "hook.secret"), "rb").read()
lock = threading.Lock()
log = os.path.join(work, "hooks.jsonl")
queue = os.path.join(work, "hook-queue.txt")
class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        stamp = self.headers.get("X-CexChain-Timestamp", "")
        expected = "sha256=" + hmac.new(secret, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        signed = hmac.compare_digest(self.headers.get("X-CexChain-Signature", ""), expected)
        request = json.loads(body)
        status, reply = 200, None
        with lock:
            pending = open(queue).read().splitlines() if os.path.exists(queue) else []
            if pending:
                code, _, rest = pending[0].partition(" ")
                status, reply = int(code), rest
                open(queue, "w").write("".join(line + "\n" for line in pending[1:]))
            with open(log, "a") as f:
                f.write(json.dumps({"id": request["id"], "kind": request["kind"],
                                    "attempt": self.headers.get("X-CexChain-Attempt"),
                                    "key": self.headers.get("Idempotency-Key"),
                                    "signed": signed, "params": request.get("params")}) + "\n")
        if not signed:
            status, reply = 401, "{}"
        if reply is None:
            reply = json.dumps({"result": {"ref": "W-" + request["id"][:6]}, "note": "private"})
        data = reply.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if status == 503:
            self.send_header("Retry-After", "1")
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        pass
server = ThreadingHTTPServer(("127.0.0.1", 0), Hook)
open(os.path.join(work, "hook.port.tmp"), "w").write(str(server.server_address[1]))
os.rename(os.path.join(work, "hook.port.tmp"), os.path.join(work, "hook.port"))
server.serve_forever()
EOF
python3 receiver.py "$WORK" 2> receiver.log &
PIDS+=("$!")
wait_for 100 test -s hook.port || fail "the receiver did not start"
HOOK="http://127.0.0.1:$(cat hook.port)/hook"

# The command connector's program: records each request and acts as
# post-mode says. It is run without a shell's help: its arguments are fixed.
cat > post.sh << EOF
#!/bin/sh
cat > "$WORK/post-last.json"
env > "$WORK/post-env.txt"
echo "\$1" >> "$WORK/post-count"
mode="\$(cat "$WORK/post-mode" 2> /dev/null || echo ok)"
case "\$mode" in
    busy) exit 75 ;;
    fail) echo '{"reason":"no-capacity"}'; exit 3 ;;
    kill-server) kill "\$(cat "$WORK/server.pid")"; echo '{"result":{"ref":"C-late"}}' ;;
    *) echo '{"result":{"ref":"C-1"},"internal":"not published"}' ;;
esac
EOF
chmod +x post.sh

run executor connector add notices --config worker.json --type webhook --kinds notify \
    --url "$HOOK" --secret hook-key --timeout 5 > connector.txt
contains 'secret hook-key' connector.txt
run executor connector add poster --config worker.json --type command --kinds http.post \
    --program "$WORK/post.sh" --arg '$(touch pwned)' --secrets panel-token --timeout 5 > /dev/null
run executor connector list --config worker.json > connectors.txt
contains 'notices .*webhook .*serves notify on any contract' connectors.txt
contains 'poster .*command .*serves http.post' connectors.txt
run executor connector show poster --config worker.json --json | json 'd["args"][0]' | contains -x '$(touch pwned)'
expect_exit 2 executor connector add twice --config worker.json --type command --kinds notify \
    --program /bin/true
contains 'both serve notify' out.txt
expect_exit 1 executor connector add hook2 --config worker.json --type webhook --kinds x \
    --url "$HOOK" --secret hook-key --program /bin/true
expect_exit 2 executor connector add plain --config worker.json --type webhook --kinds other \
    --url http://example.com/x --secret hook-key
contains 'https' out.txt
run executor connector add spare --config worker.json --type command --kinds spare.kind \
    --program /bin/true > /dev/null
run executor connector remove spare --config worker.json > /dev/null
expect_exit 2 executor connector show spare --config worker.json
expect_exit 2 executor check --config worker.json
contains 'needs the secret' out.txt
run executor check --config worker.json --state "$S" --json > check.json
json 'd["ok"]' < check.json | contains -x True
json 'd["connectors"][0]["ready"]["name"]' < check.json | contains -x webhook

# --- Alpha's server; executor tokens ---------------------------------------------------------
a token create worker --scope executor --out worker.token > /dev/null
PORT="$(free_port)"
URL="http://127.0.0.1:$PORT"
start_server() {
    "$CEXCHAIN" serve --listen "127.0.0.1:$PORT" --ledger "$A" --log-key a-log.key --quiet \
        > server.out 2> server.log &
    echo "$!" > server.pid
    PIDS+=("$(cat server.pid)")
    wait_for 300 healthy "$URL" || { cat server.log; fail "the server did not start"; }
}
start_server
RUN=("$CEXCHAIN" executor run --config worker.json --state "$S" --server "$URL" --token-file worker.token
    --as worker.key --lease-ttl 5)

# --- Done, through a webhook and a command ------------------------------------------------
R1="$(ask notify '{"about": "welcome"}' 3600000)"
R2="$(ask http.post '{"cmd": "$(touch pwned)"}' 3600000)"
"${RUN[@]}" --once --json > once.jsonl
contains '"event":"answered"' once.jsonl
status_of "$R1" | contains -x done
status_of "$R2" | contains -x done
[ "$(lines hooks.jsonl)" -eq 1 ] || fail "one POST for the notice"
json 'd["signed"]' < hooks.jsonl | contains -x True
json 'd["key"]' < hooks.jsonl | contains -x "$R1"
json 'd["params"]["about"]' < hooks.jsonl | contains -x welcome
json 'd["id"]' < post-last.json | contains -x "$R2"
json 'd["secrets"]["panel-token"]' < post-last.json | contains -x panel-token-value
contains -x '$(touch pwned)' post-count
[ ! -e pwned ] || fail "params and arguments never reach a shell"
lacks '^CEXCHAIN_' post-env.txt
# The answer publishes the result and the response's salted digest only.
a request show "$R1" --json > r1.json
json 'd["answer"]["arguments"]' < r1.json > r1-args.txt
contains "\"result\": {\"ref\": \"W-${R1:0:6}\"}" r1-args.txt
contains "\"response\": h'[0-9a-f]\{64\}'" r1-args.txt
lacks 'private' r1.json
lacks 'reason' r1-args.txt
a request show "$R2" --json | json 'd["answer"]["arguments"]' | contains '"ref": "C-1"'
a request show "$R2" --json | lacks 'not published'
json 'd["answer"]["by"]["id"]' < r1.json | contains -x "$WORKER"
json 'd["answer"]["kind"]' < r1.json | contains -x device
run executor journal show "${R1:0:12}" --state "$S" --response-out r1-response.json --json > j1.json
json 'd["stage"]' < j1.json | contains -x answered
json 'd["digest_checked"]' < j1.json | contains -x SHA-256
json 'd["note"]' < r1-response.json | contains -x private
run executor journal list --state "$S" --final | contains 'notify .*answered .*attempts 1'
# Nothing in the logs or the journal shows a secret.
for f in once.jsonl "$S"/journal/*.json; do
    lacks 'shared-hook-secret' "$f"
    lacks 'panel-token-value' "$f"
done
# Again: nothing more to do.
"${RUN[@]}" --once --json > again.jsonl
lacks '"event":"acting"' again.jsonl
[ "$(lines hooks.jsonl)" -eq 1 ] || fail "nothing is done twice"

# --- Failed, with a reason; and a retry ------------------------------------------------------
echo '422 {"reason":"unmapped"}' > hook-queue.txt
R3="$(ask notify '{"about": "reminder"}' 3600000)"
"${RUN[@]}" --once > /dev/null
status_of "$R3" | contains -x failed
a request show "$R3" --json | json 'd["answer"]["arguments"]' | contains '"reason": "unmapped"' 

echo '503 {}' > hook-queue.txt
R4="$(ask notify '{"about": "retry"}' 3600000)"
"${RUN[@]}" --wait 1 --json > retry.jsonl 2> retry.log &
EXECUTOR=$!
PIDS+=("$EXECUTOR")
answered() { [ "$(trap - ERR; status_of "$1" 2> /dev/null)" = "$2" ]; }
wait_for 300 answered "$R4" done || fail "the retry was not answered"
kill -TERM "$EXECUTOR"
code=0
wait "$EXECUTOR" || code=$?
[ "$code" -eq 0 ] || fail "a stopped executor exits 0, not $code"
contains '"event":"retry"' retry.jsonl
contains '"event":"stopped"' retry.jsonl
run executor journal show "$R4" --state "$S" --json | json 'd["attempts"]' | contains -x 2
[ "$(grep -c "\"$R4\"" hooks.jsonl)" -eq 2 ] || fail "two POSTs: the first refused, the second done"

# --- A lying API: a request it invents is never acted on ----------------------------------
FAKE="$(printf '5a%.0s' $(seq 1 32))"
cat > proxy.py << 'EOF'
import json, os, sys, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
upstream, work = sys.argv[1], sys.argv[2]
class Proxy(BaseHTTPRequestHandler):
    def forward(self, method):
        length = int(self.headers.get("Content-Length", "0"))
        if method == "POST" and os.path.exists(os.path.join(work, "refuse-posts")):
            self.rfile.read(length)
            data = b'{"error":{"code":"unavailable","message":"busy"}}'
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        request = urllib.request.Request(upstream + self.path,
                                         data=self.rfile.read(length) if length else None,
                                         method=method)
        for name in ("Authorization", "Content-Type", "Accept"):
            if self.headers.get(name):
                request.add_header(name, self.headers.get(name))
        try:
            with urllib.request.urlopen(request, timeout=60) as r:
                status, data, kind = r.status, r.read(), r.headers.get("Content-Type")
        except urllib.error.HTTPError as e:
            status, data, kind = e.code, e.read(), e.headers.get("Content-Type")
        fake = os.path.join(work, "proxy-fake.json")
        if method == "GET" and self.path.startswith("/v1/requests") and status == 200 and \
                os.path.exists(fake):
            listed = json.loads(data)
            listed["requests"].append(json.load(open(fake)))
            data = json.dumps(listed).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind or "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        self.forward("GET")
    def do_POST(self):
        self.forward("POST")
    def log_message(self, *args):
        pass
server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
open(os.path.join(work, "proxy.port.tmp"), "w").write(str(server.server_address[1]))
os.rename(os.path.join(work, "proxy.port.tmp"), os.path.join(work, "proxy.port"))
server.serve_forever()
EOF
echo "{\"id\": \"$FAKE\", \"instance\": \"$I\", \"kind\": \"notify\", \"contract\": \"$C\"}" \
    > proxy-fake.json
python3 proxy.py "$URL" "$WORK" 2> proxy.log &
PIDS+=("$!")
wait_for 100 test -s proxy.port || fail "the proxy did not start"
POSTS="$(lines hooks.jsonl)"
run executor run --config worker.json --state "$S" --server "http://127.0.0.1:$(cat proxy.port)" \
    --token-file worker.token --as worker.key --lease-ttl 5 --once --json > lying.jsonl
contains '"event":"unverified"' lying.jsonl
[ "$(lines hooks.jsonl)" -eq "$POSTS" ] || fail "nothing is done for an invented request"
run executor journal show "$FAKE" --state "$S" --json > fake.json
json 'd["stage"]' < fake.json | contains -x unverified
json 'd["attempts"]' < fake.json | contains -x 0
json 'd["note"]' < fake.json | contains "signed evidence"
rm proxy-fake.json
PROXY="http://127.0.0.1:$(cat proxy.port)"

# --- kill -9 between acting and answering: resumed without a second action -------------------
echo kill-server > post-mode
R5="$(ask http.post '{"n": 5}' 3600000)"
ACTIONS="$(lines post-count)"
"${RUN[@]}" --wait 1 --json > crash.jsonl 2> crash.log &
EXECUTOR=$!
PIDS+=("$EXECUTOR")
stage_is() { [ "$(trap - ERR; run executor journal show "$1" --state "$S" --json 2> /dev/null | json 'd["stage"]')" = "$2" ]; }
# Acted, the outcome journaled, the answer not sent: the server is down.
wait_for 300 stage_is "$R5" outcome || { cat crash.jsonl; fail "the outcome was never journaled"; }
kill -9 "$EXECUTOR"
wait "$EXECUTOR" 2> /dev/null || true
[ "$(lines post-count)" -eq $((ACTIONS + 1)) ] || fail "one action"
echo ok > post-mode
start_server
status_of "$R5" | contains -x open
"${RUN[@]}" --once --json > resumed.jsonl
status_of "$R5" | contains -x done
[ "$(lines post-count)" -eq $((ACTIONS + 1)) ] || fail "resumed without a second action"
lacks '"event":"acting"' resumed.jsonl

# --- A keeper expires a request the executor cannot answer: the late answer is final ---------
KEEPER_ID="$(a keeper add Keeper --contracts "$C" --key-out keeper.key --as a-root.key --json \
    | json 'd["actor"]["id"]')"
# Through a server that takes no answers for a while: the executor acts,
# signs its answer, and keeps trying to send it.
touch refuse-posts
# Due in 20 s: time for the action (it never starts within its 5 s timeout of
# the deadline), slow builds included.
R6="$(ask http.post '{"n": 6}' 20000)"
ACTIONS="$(lines post-count)"
"$CEXCHAIN" executor run --config worker.json --state "$S" --server "$PROXY" \
    --token-file worker.token --as worker.key --wait 1 --lease-ttl 5 --json > late.jsonl 2> late.log &
EXECUTOR=$!
PIDS+=("$EXECUTOR")
wait_for 300 stage_is "$R6" answering || { cat late.jsonl; fail "the answer was never journaled"; }
# Once the deadline passes, the keeper expires it.
past_deadline() { [ "$(trap - ERR; a request list --overdue --json | json 'len(d)')" -ge 1 ]; }
wait_for 300 past_deadline || fail "the deadline did not pass"
a keeper run --as keeper.key --grace 0 --json | json 'len(d["calls"])' | contains -x 1
status_of "$R6" | contains -x expired
# The answer is sent at last, refused, and journaled as final.
rm refuse-posts
wait_for 600 stage_is "$R6" closed || { cat late.jsonl; fail "the late answer was not journaled"; }
kill -TERM "$EXECUTOR"
wait "$EXECUTOR"
run executor journal show "$R6" --state "$S" --json > late.json
json 'd["answered_status"]' < late.json | contains -x expired
json 'd["answered_by"]' < late.json | contains -x "$KEEPER_ID"
json 'd["status"]' < late.json | contains -x done
json 'd["note"]' < late.json | contains 'answered elsewhere'
[ "$(lines post-count)" -eq $((ACTIONS + 1)) ] || fail "one action, not retried"
"${RUN[@]}" --once --json > after.jsonl
lacks '"event":"acting"' after.jsonl
status_of "$R6" | contains -x expired

# --- Two copies, one lease ------------------------------------------------------------------------
SA="$WORK/copy-a"; SB="$WORK/copy-b"
for d in "$SA" "$SB"; do
    mkdir -p "$d"
    cp -R "$S/secrets" "$S/secrets.key" "$S/secrets.pub" "$d/"
done
COPY=("$CEXCHAIN" executor run --config worker.json --server "$URL" --token-file worker.token
    --as worker.key --wait 1 --lease-ttl 5 --json --state)
"${COPY[@]}" "$SA" > copy-a.jsonl 2> copy-a.log &
COPY_A=$!
PIDS+=("$COPY_A")
# (once the last run's lease, 5 s, has lapsed)
wait_for 150 contains '"granted":true' copy-a.jsonl || fail "copy A did not take the lease"
"${COPY[@]}" "$SB" > copy-b.jsonl 2> copy-b.log &
COPY_B=$!
PIDS+=("$COPY_B")
wait_for 100 contains '"granted":false' copy-b.jsonl || fail "copy B was not told to stand by"
POSTS="$(lines hooks.jsonl)"
R7="$(ask notify '{"about": "copies"}' 3600000)"
wait_for 300 answered "$R7" done || fail "copy A did not answer"
kill -TERM "$COPY_A"
wait "$COPY_A"
R8="$(ask notify '{"about": "takeover"}' 3600000)"
wait_for 300 answered "$R8" done || { cat copy-b.jsonl; fail "copy B did not take over"; }
kill -TERM "$COPY_B"
wait "$COPY_B"
[ "$(lines hooks.jsonl)" -eq $((POSTS + 2)) ] || fail "each request acted on once"
contains "\"request\":\"$R7\"" copy-a.jsonl
lacks "\"event\":\"acting\".*\"request\":\"$R7\"" copy-b.jsonl
contains "\"event\":\"answered\".*\"request\":\"$R8\"" copy-b.jsonl
contains '"granted":true' copy-b.jsonl
# One state directory, one copy.
"${COPY[@]}" "$SB" > copy-b2.jsonl 2> copy-b2.log &
COPY_B=$!
PIDS+=("$COPY_B")
wait_for 100 contains '"event":"started"' copy-b2.jsonl || fail "copy B did not restart"
expect_exit 2 executor run --config worker.json --state "$SB" --server "$URL" \
    --token-file worker.token --as worker.key --once
contains 'another copy' out.txt
kill -TERM "$COPY_B"
wait "$COPY_B"

# --- Every answer verifies offline ---------------------------------------------------------------
a contract evidence "$I" --log-key a-log.key --out instance.cbor > /dev/null
run contract verify instance.cbor --ledger-id "$A_ID" --json > verified.json
python3 << 'EOF'
import json
report = json.load(open("verified.json"))
statuses = sorted(c["answer"]["status"] for c in report["calls"] if c.get("answer"))
assert statuses == ["done"] * 6 + ["expired", "failed"], statuses
EOF
echo "executor end to end: OK"
