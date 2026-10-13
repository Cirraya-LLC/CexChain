#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A supply agreement across three organizations, governed by a contract
# written in Bo and narrated step by step: a core enterprise builds the
# contract and deploys it on its ledger, and proposes an agreement to its
# supplier and its bank; the supplier's sales manager and the bank's AI agent
# consent, each on their own organization's ledger, and the core
# enterprise's registrar records the signature once the contract has both
# consents; anyone verifies the agreement offline, rebuilding the contract's
# code from its source; once the goods are delivered, it is closed. The
# bank's ledger hashes with SM3 and signs with SM2. Three ledgers talk over
# HTTP.
#
# The contract is supply-agreement.bo, next to this script: Bo, CexChain's
# contract language (Phase 6, step 6). The deploy records its source, so
# whoever verifies an agreement can read the terms the code enforces and
# check that the code is built from them. It needs a cexchain built with the
# Bo compiler (GCC 16; the release build and the Docker image have it).
#
# Usage: supply-agreement.sh [CEXCHAIN] [DIR]
#   CEXCHAIN  the command-line tool (default: cexchain on the PATH)
#   DIR       where to keep the ledgers (default: a temporary directory,
#             removed at the end; give one to look around afterwards)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="${1:-cexchain}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${2:-}" ]; then
    WORK="$2"; KEEP=1; mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"; KEEP=0
fi
WORK="$(cd "$WORK" && pwd)"
SERVER=""
cleanup() {
    if [ -n "$SERVER" ]; then
        kill "$SERVER" 2> /dev/null || true
        wait "$SERVER" 2> /dev/null || true
    fi
    [ "$KEEP" = 0 ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cd "$WORK"
export CEXCHAIN_PASSPHRASE="demo only: use real passphrases or hardware keys"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
say() { printf '   %s\n' "$*"; }
run() { "$CEXCHAIN" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
indent() { sed 's/^/   /'; }

# Ledger directories, one per organization.
CORE="$WORK/core"; SUP="$WORK/supplier"; BANK="$WORK/bank"

step "1. Three organizations, each with its own ledger"
for org in core supplier; do
    run key generate --out "$org-root.key" > /dev/null
    run key generate --out "$org-log.key" > /dev/null
done
# The bank uses the Chinese commercial algorithms: SM2 keys, SM3 hashes.
run key generate --alg sm2-sm3 --out bank-root.key > /dev/null
run key generate --alg sm2-sm3 --out bank-log.key > /dev/null
run init --org "Core Enterprise Co." --root-key core-root.key --log-key core-log.key --ledger "$CORE" > /dev/null
run init --org "Tier-1 Supplier Ltd." --root-key supplier-root.key --log-key supplier-log.key \
    --ledger "$SUP" > /dev/null
run init --org "Bank A" --root-key bank-root.key --log-key bank-log.key --hash sm3 --ledger "$BANK" > /dev/null
id_of() { run status --ledger "$1" --json | field '["ledger_id"]'; }
CORE_ID="$(id_of "$CORE")"; SUP_ID="$(id_of "$SUP")"; BANK_ID="$(id_of "$BANK")"
say "Core Enterprise  ledger ${CORE_ID:0:16}... (SHA-256)"
say "Supplier         ledger ${SUP_ID:0:16}... (SHA-256)"
say "Bank A           ledger ${BANK_ID:0:16}... (SM3)"
say "Ledger ids are exchanged at onboarding, through a channel each side trusts."
run peer add supplier --ledger-id "$SUP_ID" --ledger "$CORE" > /dev/null
run peer add bank --ledger-id "$BANK_ID" --ledger "$CORE" > /dev/null
run peer add bank --ledger-id "$BANK_ID" --ledger "$SUP" > /dev/null
run peer add supplier --ledger-id "$SUP_ID" --ledger "$BANK" > /dev/null

step "2. The core enterprise builds the contract and deploys it on its ledger, the agreement's home"
if [ "$(run version --json | field '["bo"] is not None')" != True ]; then
    echo "This demo needs a cexchain built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
cp "$HERE/supply-agreement.bo" .
sed 's/^/   | /' supply-agreement.bo
# Building checks the contract and compiles it to a WebAssembly module with a
# function per action ("sign", "close") and one that creates an instance
# ("create"). The deploy records the code, the compiler, and the source with
# the language packs it was read with, so anyone can rebuild the code and
# compare. (The warning says the comments are published with it.)
run bo build supply-agreement.bo 2>&1 | indent
CONTRACT="$(run contract deploy --bo supply-agreement.bo --as core-root.key --ledger "$CORE" --json \
    2> /dev/null | field '["contract"]["id"]')"
run contract show "$CONTRACT" --ledger "$CORE" | indent
say "The ledger runs the contract on every call and records the call only if the contract"
say "accepts it. The contract may also say whose consent it still needs."

step "3. The core enterprise proposes the agreement to its supplier and its bank"
# Creating an instance takes the terms and binds the roles to ledgers. Money
# is in the currency's smallest unit (fen), dates in milliseconds since 1970.
DELIVER_BY=1796054400000   # 2026-12-01, 00:00 in Hong Kong and Shanghai
TERMS="{\"goods\": \"Bearings 6204-2RS\", \"pieces\": 20000, \"price\": 125000000, \"deliver_by\": $DELIVER_BY}"
PROPOSE="{\"fields\": $TERMS, \"parties\": {\"we\": h'$CORE_ID', \"supplier\": h'$SUP_ID', \"bank\": h'$BANK_ID'}}"
AGREEMENT="$(run contract create "$CONTRACT" create --args "$PROPOSE" --reference "PO-2026-1012" \
    --as core-root.key --ledger "$CORE" --json | field '["instance"]["id"]')"
run contract instance "$AGREEMENT" --ledger "$CORE" | sed -n '1,8p' | indent
say "Can the core enterprise sign it alone? A dry run asks the contract:"
run contract call "$AGREEMENT" sign --dry-run --as core-root.key --ledger "$CORE" | indent

step "4. The core enterprise runs its server with a registrar"
# The registrar is a device with a delegation for calls on this contract
# only. It records a call only once the contract has the consents it asks
# for: never on its own word.
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
REGISTRAR="$(run actor add --as core-root.key --kind device --name "Contract Registrar" --key registrar.pub \
    --ledger "$CORE" --json | field '["actor"]["id"]')"
run delegation grant --as core-root.key --to "$REGISTRAR" --allow contract-call --contracts "$CONTRACT" \
    --ledger "$CORE" > /dev/null
for p in supplier bank; do
    run token create "$p" --scope peer --out "$p.token" --ledger "$CORE" > /dev/null
done
run token create staff --scope read,submit --out staff.token --ledger "$CORE" > /dev/null
# Started directly (not through a shell function), so $! is the server itself.
"$CEXCHAIN" serve --ledger "$CORE" --log-key core-log.key --registrar-key registrar.key \
    --listen 127.0.0.1:0 --json --quiet > core.json 2> core.log &
SERVER=$!
for _ in $(seq 1 300); do
    python3 -c "import json; json.load(open('core.json'))" 2> /dev/null && break
    sleep 0.1
done
URL="$(field '["url"]' < core.json)"
say "Serving at $URL."
run peer add core --ledger-id "$CORE_ID" --url "$URL" --token-file supplier.token --ledger "$SUP" > /dev/null
run peer add core --ledger-id "$CORE_ID" --url "$URL" --token-file bank.token --ledger "$BANK" > /dev/null
# The core enterprise's staff work through the server (client mode): what
# they see is checked against the ledger's history on their own machine.
STAFF=(--server "$URL" --token-file staff.token --ledger-id "$CORE_ID" --cache "$WORK/cache")
CALL="$(run contract propose "$AGREEMENT" sign --reference "Signature of PO-2026-1012" \
    "${STAFF[@]}" --json | field '["call"]')"
say "The core enterprise proposes signing to its registrar, which holds call ${CALL:0:12}"
say "until the supplier and the bank consent."

step "5. Who may consent: a person at the supplier, an AI agent at the bank"
run key generate --out manager.key > /dev/null
MANAGER="$(run actor add --as supplier-root.key --kind person --name "Sales Manager" --key manager.key \
    --ledger "$SUP" --json | field '["actor"]["id"]')"
run delegation grant --as supplier-root.key --to "$MANAGER" --allow record-register \
    --record-types cexchain.contract-consent/1 --ledger "$SUP" > /dev/null
run key generate --alg sm2-sm3 --out officer.key > /dev/null
run key generate --alg sm2-sm3 --out credit-agent.key > /dev/null
OFFICER="$(run actor add --as bank-root.key --kind person --name "Credit Officer" --key officer.key \
    --ledger "$BANK" --json | field '["actor"]["id"]')"
AGENT="$(run actor add --as bank-root.key --kind agent --name "Credit Agent" --key credit-agent.key \
    --responsible "$OFFICER" --model credit-review-1 --model-version 2026-10 --ledger "$BANK" \
    --json | field '["actor"]["id"]')"
run delegation grant --as bank-root.key --to "$AGENT" --allow record-register \
    --record-types cexchain.contract-consent/1 --days 30 --ledger "$BANK" > /dev/null
say "Supplier: \"Sales Manager\", a person, may consent to contract calls."
say "Bank A:   \"Credit Agent\", an AI agent with its own key, may consent for 30 days;"
say "          the credit officer is accountable for it."

step "6. The supplier's sales manager reviews the call and consents on the supplier's ledger"
run contract pending --peer core --ledger "$SUP" | indent
# The consent is a record on the supplier's own ledger naming the exact terms:
# the instance and its head, the function, and a digest of the arguments. It
# applies to this one call, once, until it lapses. Its evidence goes to the
# registrar, which runs the contract again with it.
run contract consent --peer core --call "$CALL" --reference "Sales approval SA-88" --as manager.key \
    --log-key supplier-log.key --send --ledger "$SUP" | indent
say "(In practice the manager adds --presence and confirms with a passkey or a UKey;"
say " the report then shows that a person was present.)"

step "7. The bank's AI agent consents through MCP, on the bank's SM3 ledger"
# The bank runs `cexchain mcp` for its agent: an MCP client (here, this
# script) sends JSON-RPC requests on its standard input. Every action is
# signed with the agent's key, checked against its delegation, and recorded
# with provenance: its model and the tool it used. The agent first checks
# who it is, the call the registrar holds, and the instance itself.
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}'
tool() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{%s,"name":"%s","arguments":%s}}\n' "$1" "$META" "$2" "$3"; }
{
    tool 1 cexchain_whoami '{}'
    tool 2 cexchain_list_pending_calls '{"home":"core"}'
    tool 3 cexchain_fetch_instance "{\"home\":\"core\",\"instance\":\"$AGREEMENT\"}"
    tool 4 cexchain_consent_contract_call "{\"home\":\"core\",\"call\":\"$CALL\",\"reference\":\"Credit approval CA-2026-311\",\"inputs\":\"credit memo CM-311: facility limit CNY 2,000,000\"}"
} > agent-requests.jsonl
run mcp --ledger "$BANK" --as credit-agent.key --log-key bank-log.key < agent-requests.jsonl \
    > agent-responses.jsonl 2> /dev/null
python3 - agent-responses.jsonl << 'EOF' | indent
import json, sys
results = {}
for line in open(sys.argv[1]):
    response = json.loads(line)
    result = response["result"]
    if result.get("isError"):
        sys.exit("the agent's tool failed: " + result["content"][0]["text"])
    results[response["id"]] = result["structuredContent"]
me = results[1]
print(f'whoami:   "{me["name"]}" ({me["kind"]}, model {me["model"]}), responsible: {me["responsible"]}')
held = results[2]["calls"][0]
print(f'pending:  call {held["call"][:12]}: {held["function"]}, waiting for {held["waiting_for"]}')
instance = results[3]["instance"]
print(f'instance: status {instance["status"]}, evidence verified')
consent = results[4]
answer = consent["home_answer"]
print(f'consent:  record {consent["consent"][:12]} on the bank\'s ledger; the registrar: {answer["status"]},')
print(f'          the agreement is now {answer["instance_status"]}')
EOF

step "8. Anyone verifies the agreement offline"
# The supplier fetches the instance's evidence from its home and checks it:
# every call is run again, every consent is checked on the ledger that gave
# it, and the contract's code is rebuilt from the source its deploy carries.
# The same file opens in the browser verifier (cexchain-verify.html).
run contract fetch --peer core --instance "$AGREEMENT" --out agreement.cbor --ledger "$SUP" > /dev/null
run contract verify agreement.cbor --ledger-id "$CORE_ID" | indent

step "9. The goods are delivered; the agreement is closed"
# Closing needs only the supplier's confirmation: the contract says so.
CALL="$(run contract propose "$AGREEMENT" close --reference "Goods received GRN-2026-1130" \
    "${STAFF[@]}" --json | field '["call"]')"
run contract consent --peer core --call "$CALL" --reference "Delivered in full" --as manager.key \
    --log-key supplier-log.key --send --ledger "$SUP" | indent
run contract fetch --peer core --instance "$AGREEMENT" --out closed.cbor --ledger "$BANK" > /dev/null
run contract verify closed.cbor --ledger-id "$CORE_ID" | grep -E 'Status|consent of|rebuilds' | indent
for d in "$CORE" "$SUP" "$BANK"; do run audit --ledger "$d" > /dev/null; done
say "Every ledger audits clean."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
