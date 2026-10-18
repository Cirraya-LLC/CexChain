#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A hosting provider rents a server to a customer, billed each month,
# narrated step by step. The contract (hosting.bo, next to this script)
# decides; it never acts outside the ledger, it asks:
#   - the provider's ledger runs on a cluster of three servers on this
#     computer, each with the keeper (serve --keeper-key), which fires the
#     contract's time rules on the leader;
#   - an executor of the provider's carries out the requests through two
#     webhooks: a fake control panel (panel.py: subscribe, suspend, resume,
#     terminate, reclaim) and a fake billing system (billing.py: invoice,
#     collect, done only once the whole amount is in);
#   - the customer, with a ledger of its own, consents to subscribe, renew,
#     and terminate; the provider's AI agent answers the notices through MCP;
#     a clerk answers a payment made in cash by hand;
#   - time passes: the script moves every clock ahead with
#     CEXCHAIN_CLOCK_OFFSET (for demonstrations and tests only) and restarts
#     the cluster, rather than waiting a month;
#   - anyone verifies the whole history offline.
# It needs a cexchain built with the Bo compiler (GCC 16; the release build
# and the Docker image have it) and python3.
#
# Usage: idc-hosting.sh [CEXCHAIN] [DIR]
#   CEXCHAIN  the command-line tool (default: cexchain on the PATH)
#   DIR       where to keep the ledgers (default: a temporary directory,
#             removed at the end; give one to look around afterwards)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2; logs >&2' ERR

CEXCHAIN="${1:-cexchain}"
# A path relative to where the script starts works too.
case "$CEXCHAIN" in */*) CEXCHAIN="$(cd "$(dirname "$CEXCHAIN")" && pwd)/$(basename "$CEXCHAIN")" ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${2:-}" ]; then
    WORK="$2"; KEEP=1; mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"; KEEP=0
fi
WORK="$(cd "$WORK" && pwd)"
MEMBERS=(); FAKES=()
logs() {
    for log in "$WORK"/node*.log "$WORK"/*.err; do
        [ -s "$log" ] && { echo "--- $log"; tail -n 15 "$log"; }
    done
    return 0
}
stop_members() {
    for pid in ${MEMBERS[@]+"${MEMBERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    for pid in ${MEMBERS[@]+"${MEMBERS[@]}"}; do wait "$pid" 2> /dev/null || true; done
    MEMBERS=()
}
cleanup() {
    stop_members
    for pid in ${FAKES[@]+"${FAKES[@]}"}; do kill "$pid" 2> /dev/null || true; done
    [ "$KEEP" = 0 ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cd "$WORK"
export CEXCHAIN_PASSPHRASE="demo only: use real passphrases or hardware keys"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN CEXCHAIN_CLOCK_OFFSET

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
say() { printf '   %s\n' "$*"; }
run() { "$CEXCHAIN" "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
indent() { sed 's/^/   /'; }
check() {
    if ! grep -F -- "$2" "$1" > /dev/null; then
        echo "expected \"$2\" in $1:" >&2
        cat "$1" >&2
        exit 1
    fi
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

step "1. A hosting provider and a customer, each with a ledger of its own"
if [ "$(run version --json | json 'd["bo"] is not None')" != True ]; then
    echo "This example needs a cexchain built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
run key generate --out provider-root.key > /dev/null
run key generate --out provider-log.key > /dev/null
PROVIDER_ID="$(run init --name "Harbour Hosting Ltd." --root-key provider-root.key \
    --log-key provider-log.key --ledger node1 --json | json 'd["ledger_id"]')"
run key generate --out customer-root.key > /dev/null
run key generate --out customer-log.key > /dev/null
CUSTOMER_ID="$(run init --name "Kowloon Design Studio" --root-key customer-root.key \
    --log-key customer-log.key --ledger customer --json | json 'd["ledger_id"]')"
run peer add provider --ledger-id "$PROVIDER_ID" --ledger customer > /dev/null
run peer add customer --ledger-id "$CUSTOMER_ID" --ledger node1 > /dev/null
say "Harbour Hosting Ltd.     ledger ${PROVIDER_ID:0:16}... (the provider: the contract's home)"
say "Kowloon Design Studio    ledger ${CUSTOMER_ID:0:16}... (the customer)"

step "2. The provider writes the rules, tests them, and deploys them"
cp "$HERE/hosting.bo" .
# The rules without their comments and tests.
sed '/^# Its tests/,$d' hosting.bo | grep -v '^ *#' | grep -v '^$' | sed 's/^/   | /'
run bo test hosting.bo | tail -n 1 | indent
CONTRACT="$(run contract deploy --bo hosting.bo --as provider-root.key --ledger node1 --json \
    2> /dev/null | json 'd["contract"]["id"]')"
say "Deployed: contract ${CONTRACT:0:16}... Bo added the bills and the requests; its text says so:"
run contract explain "$CONTRACT" --ledger node1 > text.txt
check text.txt 'It asks an executor for invoice for the customer'
grep -E '^  4\.1\.(7|8|9) ' text.txt | indent

step "3. Who acts for the provider: an executor, a keeper, an AI agent, a clerk"
# The executor: a program with a key of its own and a delegation to answer
# this contract's requests of these kinds, and nothing else.
run executor add Operations --contract "$CONTRACT" \
    --kinds subscribe,suspend,resume,terminate,reclaim,invoice,collect \
    --key-out ops.key --config-out ops.json --as provider-root.key --ledger node1 > /dev/null
# The keeper: a device that fires the contract's time rules once they are due.
run keeper add Keeper --contracts "$CONTRACT" --key-out keeper.key --as provider-root.key \
    --ledger node1 > /dev/null
# A clerk, a person, who may answer collections by hand, and the AI agent she
# is responsible for, which may answer notices.
run key generate --out clerk.key > /dev/null
run key generate --out agent.key > /dev/null
CLERK="$(run actor add --kind person --name "Mei Chan" --key clerk.key --as provider-root.key \
    --ledger node1 --json | json 'd["actor"]["id"]')"
run delegation grant --to "$CLERK" --allow contract-call --contracts "$CONTRACT" --functions result \
    --request-kinds collect --days 365 --as provider-root.key --ledger node1 > /dev/null
AGENT="$(run actor add --kind agent --name "Support Agent" --key agent.key --responsible "$CLERK" \
    --model example-llm --model-version 2026-10 --as provider-root.key --ledger node1 --json \
    | json 'd["actor"]["id"]')"
run delegation grant --to "$AGENT" --allow contract-call --contracts "$CONTRACT" --functions result \
    --request-kinds notify --days 365 --as provider-root.key --ledger node1 > /dev/null
# API tokens: the staff's and the agent's (read and submit), the executor's.
run token create staff --scope read,submit --out staff.token --ledger node1 > /dev/null
run token create agent --scope read,submit --out agent.token --ledger node1 > /dev/null
run token create operations --scope executor --out ops.token --ledger node1 > /dev/null
run token create admin --scope read,submit,admin --out admin.token --ledger node1 > /dev/null
say "Executor \"Operations\": answers subscribe, suspend, resume, terminate, reclaim, invoice, collect."
say "Keeper \"Keeper\": fires the time rules. Clerk Mei Chan: collections by hand."
say "AI agent \"Support Agent\" (Mei Chan responsible for it): notices only."

step "4. The provider's ledger runs on a cluster of three servers"
# Three members on this computer, each with its Raft port and its API. Ports
# are chosen before any member binds them (the cluster's membership names
# them), from just below the range the system hands out for outgoing
# connections, so that none of the cluster's own connections takes one.
read -r -a PORTS <<< "$(python3 - << 'PY'
import random, socket, subprocess
end = 32768
try:
    end = int(open("/proc/sys/net/ipv4/ip_local_port_range").read().split()[0])
except (OSError, ValueError, IndexError):
    try:
        end = int(subprocess.run(["sysctl", "-n", "net.inet.ip.portrange.first"],
                                 capture_output=True, text=True, check=True).stdout)
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass
end = end if 1024 < end <= 65535 else 32768
begin = max(1024, end - 16384)
if end - begin < 1024:
    begin, end = 1024, 65536
ports = []
while len(ports) < 6:
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
)"
API=(); APORT=(); RPORT=()
for n in 1 2 3; do
    APORT[$n]="${PORTS[$((2 * n - 2))]}"; RPORT[$n]="${PORTS[$((2 * n - 1))]}"
    API[$n]="http://127.0.0.1:${APORT[$n]}"
done
# status N: member N's /v1/status.
status() {
    python3 - "${API[$1]}" "$(cat admin.token)" << 'PY'
import sys, urllib.request
request = urllib.request.Request(sys.argv[1] + "/v1/status",
                                 headers={"Authorization": "Bearer " + sys.argv[2]})
print(urllib.request.urlopen(request, timeout=5).read().decode())
PY
}
has_leader() { [ "$(status "$1" | json 'd["cluster"]["leader"] is not None')" = True ]; }
member_count() { [ "$(run cluster status --server "${API[1]}" --token-file admin.token --json | json 'len(d["members"])')" = "$1" ]; }
start_member() {
    local n="$1"
    "$CEXCHAIN" serve --cluster --ledger "node$n" --listen "127.0.0.1:${APORT[$n]}" \
        --log-key provider-log.key --keeper-key keeper.key --keeper-interval 1 --json \
        > "node$n.json" 2> "node$n.log" &
    MEMBERS+=("$!")
    eventually 60 status "$n"
}
start_cluster() {
    for n in 1 2 3; do start_member "$n"; done
    eventually 60 has_leader 1
}
run checkpoint create --ledger node1 --log-key provider-log.key > /dev/null
run cluster init --ledger node1 --id 1 --raft "127.0.0.1:${RPORT[1]}" --api "${API[1]}" > /dev/null
start_member 1
eventually 60 has_leader 1
for n in 2 3; do
    CEXCHAIN_TOKEN="$(cat admin.token)" run cluster join --ledger "node$n" --from "${API[1]}" \
        --ledger-id "$PROVIDER_ID" --id "$n" --raft "127.0.0.1:${RPORT[$n]}" --api "${API[$n]}" \
        --secret-file node1/cluster/secret > /dev/null
    cp node1/api-tokens "node$n/api-tokens"
    start_member "$n"
    run cluster add --server "${API[1]}" --token-file admin.token --id "$n" \
        --raft "127.0.0.1:${RPORT[$n]}" --api "${API[$n]}" > /dev/null
    eventually 60 member_count "$n"
done
run cluster status --server "${API[1]}" --token-file admin.token | indent
# From here on the provider's staff work through the API, with a verified
# mirror of the ledger on their computer (any member will do: a follower
# hands writes to the leader).
URL="${API[2]}"
prov() { run "$@" --server "$URL" --token-file staff.token --ledger-id "$PROVIDER_ID" --cache "$WORK/cache"; }

step "5. The executor's connectors: the panel's webhook and the billing system's"
# Each system shares a secret with the executor, which signs every request it
# posts (HMAC); the executor keeps the secrets sealed in its state directory.
for system in panel billing; do
    python3 -c 'import secrets; print(secrets.token_hex(32), end="")' > "$system.secret"
    run executor secret set "$system-key" --state ops-state --from-file "$system.secret" > /dev/null
    python3 "$HERE/$system.py" "$WORK" "$system.secret" 2> "$system.err" &
    FAKES+=("$!")
    eventually 30 test -s "$system.port"
done
run executor connector add panel --config ops.json --type webhook \
    --kinds subscribe,suspend,resume,terminate,reclaim \
    --url "http://127.0.0.1:$(cat panel.port)/requests" --secret panel-key --timeout 10 > /dev/null
run executor connector add billing --config ops.json --type webhook --kinds invoice,collect \
    --url "http://127.0.0.1:$(cat billing.port)/requests" --secret billing-key --timeout 10 > /dev/null
run executor connector list --config ops.json | indent
run executor check --config ops.json --state ops-state > /dev/null
# The executor runs as a service of its own; here it runs once after each
# step (--once), so that the story is told in order. Each run finds the open
# requests at the cluster, verifies each in the contract's signed evidence
# before acting, posts it to its system, and answers with the result.
executor() {
    local before=0
    [ -f executor.jsonl ] && before="$(wc -l < executor.jsonl)"
    run executor run --config ops.json --state ops-state --server "$URL" --token-file ops.token \
        --as ops.key --once --json >> executor.jsonl 2>> executor.err
    tail -n "+$((before + 1))" executor.jsonl | python3 -c '
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    if e.get("event") in ("answered", "retry", "closed", "failed"):
        why = e.get("reason") or e.get("why")
        print("   executor: %s %s%s" % (e.get("kind", "?"), e["event"], " (%s)" % why if why else ""))'
}
# news FILE: what a fake system logged since the last look.
news() {
    local seen=0
    [ -f "$1.seen" ] && seen="$(cat "$1.seen")"
    [ -f "$1" ] || return 0
    tail -n "+$((seen + 1))" "$1" | sed "s/^/   $2: /"
    wc -l < "$1" | tr -d ' ' > "$1.seen"
}

step "6. The customer subscribes: the panel provisions the server, billing invoices it"
SERVICE="$(prov contract create "$CONTRACT" create \
    --args "{\"fields\": {}, \"parties\": {\"we\": h'$PROVIDER_ID', \"customer\": h'$CUSTOMER_ID'}}" \
    --as provider-root.key --json | json 'd["instance"]["id"]')"
# The customer checks the instance's evidence offline, then consents on its
# own ledger to that exact call; its consent is a file the provider's call
# cites.
consent() { # FUNCTION OUT
    prov contract evidence "$SERVICE" --out now.cbor > /dev/null
    run contract verify now.cbor --ledger-id "$PROVIDER_ID" > /dev/null
    run contract consent --home "$PROVIDER_ID" --evidence now.cbor --instance "$SERVICE" \
        --function "$1" --args "{}" --log-key customer-log.key --out "$2" --as customer-root.key \
        --ledger customer > /dev/null
}
call() { # FUNCTION OUT [--consent FILE]
    local function="$1" out="$2"
    shift 2
    prov contract call "$SERVICE" "$function" --args "{}" --as provider-root.key "$@" > "$out" 2>&1
}
consent subscribe subscribe.cbor
call subscribe subscribe.txt --consent subscribe.cbor
check subscribe.txt 'status: active'
say "Subscribed, with the customer's consent: the call asked for subscribe and invoice."
executor
news panel.log panel
news billing.log billing
# field NAME: one of the instance's fields; day NAME: a date field, as a day
# in Hong Kong (the contract counts days at UTC+08:00).
field() { prov contract instance "$SERVICE" --json | json "json.loads(d['state'])['fields']['$1']"; }
day() {
    python3 -c "import datetime as t, sys; print(t.datetime.fromtimestamp(int(sys.argv[1]) / 1000, t.timezone(t.timedelta(hours=8))).strftime('%Y-%m-%d'))" "$(field "$1")"
}
[ "$(field machine)" = srv-0001 ] || { echo "the server's name was not kept" >&2; exit 1; }
say "The contract keeps the panel's name for the server, srv-0001; its address stays in the panel."
say "Paid until $(day paid_until), billed until $(day billed_until): one bill open, INV-0001."

step "7. The provider's AI agent sends the customer a notice, through MCP"
# Seven days before the due date the contract asks to notify the customer:
# before the first payment, the due date is today, so the keeper fired the
# rule at once. The provider's AI agent, an MCP client, finds the request,
# reads the instance, and answers once it has sent the notice. Its answer is
# signed with its own key, under its delegation (notices of this contract
# only), with its model and a hash of what it based the notice on.
has_notice() { [ "$(prov request list --kind notify --open --json | json 'len(d)')" != 0 ]; }
eventually 30 has_notice
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"support-desk","version":"1"}}'
tool() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{%s,"name":"%s","arguments":%s}}\n' "$1" "$META" "$2" "$3"; }
agent() { # NOTICE: the agent answers the open notify request, having sent NOTICE
    local id
    id="$(prov request list --kind notify --open --json | json 'd[0]["id"]')"
    {
        tool 1 cexchain_list_requests '{"state":"open","kinds":["notify"]}'
        tool 2 cexchain_get_instance "{\"instance\":\"$SERVICE\"}"
        tool 3 cexchain_answer_request "{\"request\":\"$id\",\"status\":\"done\",\"arguments\":{\"result\":\"$2\"},\"inputs\":\"$1\"}"
    } > agent-calls.jsonl
    run mcp --server "$URL" --token-file agent.token --ledger-id "$PROVIDER_ID" \
        --cache "$WORK/agent-cache" --as agent.key < agent-calls.jsonl > agent-answers.jsonl 2> agent.err
    sed -n 3p agent-answers.jsonl | json 'd["result"]["structuredContent"]["recorded"]' \
        | grep -x True > /dev/null || { cat agent-answers.jsonl >&2; exit 1; }
    say "Support Agent (AI) to the customer: \"$1\""
    say "Answered through MCP: done, $2, signed by the agent."
}
agent "Your server srv-0001 is ready. Invoice INV-0001, HKD 800.00, is due $(day paid_until)." MSG-0001

step "8. The customer pays the invoice; the executor collects it"
# The invoice done, the contract asked for its collection, from the due
# date on. The bank reports the customer's transfer to the billing system;
# the executor's next run posts the collection, which is done now that the
# whole amount is in.
echo "INV-0001 800.00" >> payments.txt
executor
news billing.log billing
say "Paid until $(day paid_until), billed until $(day billed_until): no bill open."

# advance DATE DAYS: moves every clock to DAYS days after a date field
# (an hour into that day), restarting the cluster to read the new clock.
# Each command reads CEXCHAIN_CLOCK_OFFSET, so the customer's ledger, the
# executor, and the agent move with the provider's.
OFFSET=0
advance() {
    OFFSET="$(python3 -c "import sys, time; t = int(sys.argv[1]) / 1000 + int(sys.argv[2]) * 86400 + 3600; print(max(int(sys.argv[3]), int(t - time.time()) + 1))" \
        "$(field "$1")" "$2" "$OFFSET")"
    stop_members
    export CEXCHAIN_CLOCK_OFFSET="${OFFSET}s"
    start_cluster
    say "Clocks moved $((OFFSET / 86400)) days ahead (CEXCHAIN_CLOCK_OFFSET=${OFFSET}s): it is $(python3 -c "import datetime as t, sys; print(t.datetime.fromtimestamp(t.datetime.now().timestamp() + int(sys.argv[1]), t.timezone(t.timedelta(hours=8))).strftime('%Y-%m-%d %H:%M'))" "$OFFSET") in Hong Kong."
}
status_is() { [ "$(prov contract instance "$SERVICE" --json | json 'd["status"]')" = "$1" ]; }
last_call() { prov contract instance "$SERVICE" --json | json '"%s by %s" % (d["calls"][-1]["function"], d["calls"][-1]["by"]["name"])'; }

step "9. A week before the next due date: a reminder; the customer renews"
advance paid_until -7
eventually 30 has_notice
agent "Your server srv-0001 is paid until $(day paid_until). Renew it before then to keep it running." MSG-0002
consent renew renew.cbor
call renew renew.txt --consent renew.cbor
check renew.txt 'status: active'
say "Renewed, with the customer's consent: billed until $(day billed_until), an invoice asked for."
executor
news billing.log billing
# The customer pays part of the bill; the collection waits for the rest.
echo "INV-0002 500.00" >> payments.txt
executor
news billing.log billing
say "Billed until $(day billed_until); paid until $(day paid_until), with HKD 300.00 still to pay."

step "10. Three days overdue: the keeper suspends the server; the panel follows"
advance paid_until 3
eventually 30 status_is suspended
say "The keeper: $(last_call). The contract asked the panel to suspend it."
executor
news panel.log panel
news billing.log billing

step "11. The rest is paid in cash: a clerk answers by hand, and the server resumes"
# The customer pays the HKD 300.00 left at the provider's counter, which the
# billing system never sees. The clerk answers the collection herself, done,
# with the receipt she wrote: a person's answer, under her delegation.
COLLECT="$(prov request list --kind collect --open --json | json 'd[0]["id"]')"
prov request answer "$COLLECT" --done --args '{"result": "CASH-0001"}' --as clerk.key > answer.txt
check answer.txt 'done'
status_is active
say "Mei Chan answered collect ${COLLECT:0:12}...: done, receipt CASH-0001."
say "Paid until $(day paid_until): no longer overdue, so the contract made it active and asked to resume it."
executor
news panel.log panel

step "12. The customer ends the service: the server deleted, its address reclaimed"
consent terminate terminate.cbor
call terminate terminate.txt --consent terminate.cbor
check terminate.txt 'terminated'
say "Terminated, with the customer's consent: the call asked for terminate and reclaim."
executor
news panel.log panel
status_is terminated
say "The instance is final: it takes no more calls, but the panel's answers were recorded."
say "Paid until $(day paid_until): the unused days are not refunded in this version."

step "13. Anyone verifies the whole history offline"
prov contract evidence "$SERVICE" --out history.cbor > /dev/null
run contract verify history.cbor --ledger-id "$PROVIDER_ID" > history.txt
check history.txt 'rebuilds'
# Who made each call: the customer's consents on its own ledger, the
# executor's answers (a device), the keeper's time rules, the AI agent's
# answers through MCP with its model, and the clerk's answer by hand.
check history.txt 'call when.suspend by "Keeper" [device]'
check history.txt 'call result by "Operations" [device]'
check history.txt 'call result by "Support Agent" [AI agent: example-llm; responsible: Mei Chan; via mcp:cexchain_answer_request]'
check history.txt 'call result by "Mei Chan" [person'
check history.txt 'given by "Kowloon Design Studio"'
check history.txt 'params {"machine": "srv-0001"}'
check history.txt '11 made by its calls, 11 answered, 0 open'
grep -E ' (create|call) |^ +answers ' history.txt \
    | sed -E 's/^ +//; s/^(#[0-9]+) +([0-9-]{10}) [0-9:]{8} UTC +/\1 \2 /; s/^answers +/           answers /' \
    | sed -E 's/ \[AI agent: ([^;]*);.*\]/ [AI agent, \1, via MCP]/' | cut -c1-100 | indent
sed -n '/^  Requests/p' history.txt | sed 's/^ *//' | indent
sed -n '/^  Verified/,/^$/{/^$/!p;}' history.txt | sed 's/^ *//' | indent
say "The same file opens in the browser verifier (cexchain-verify.html), with nothing installed."
run audit --ledger customer > /dev/null
prov audit > /dev/null
say "Both ledgers audit clean; the panel and billing system hold no ledger of their own."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
