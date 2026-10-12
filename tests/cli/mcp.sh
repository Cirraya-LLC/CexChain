#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Drives `cexchain mcp` with raw JSON-RPC, as an AI client would: modern and
# legacy protocol revisions, every tool, an out-of-scope refusal, and the
# resulting evidence verified offline.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
VECTORS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../testvectors" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

run() { "$CEXCHAIN" "$@"; }
# Readers in pipelines consume all input: with pipefail, a reader that exits
# early (grep -q, head) can kill the writer with SIGPIPE and fail the test.
contains() { grep "$@" > /dev/null; }
id_from() { grep -oE '[0-9a-f]{64}' | sed -n 1p; }
json_id() { python3 -c "import json, sys; print(json.load(sys.stdin)['instance']['id'])"; }
fail() { echo "FAIL: $1"; echo "--- responses:"; cat responses.txt; exit 1; }

export CEXCHAIN_PASSPHRASE="mcp test passphrase"
for k in root log alice agent; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --ledger ledger --org "Cirraya Test Factory" --root-key root.key --log-key log.key | id_from)"
ALICE="$(run actor add --ledger ledger --as root.key --kind person --name "Alice Inspector" --key alice.key | id_from)"
run delegation grant --ledger ledger --as root.key --to "$ALICE" --allow actor-register,delegation-grant,record-register \
    --record-types cexchain.certificate/1 --days 30 --may-delegate > /dev/null
AGENT="$(run actor add --ledger ledger --as alice.key --kind agent --name "Drafting Agent" --key agent.key \
    --responsible "$ALICE" --model claude-opus-5-5 --model-version 2026-09 | id_from)"
run delegation grant --ledger ledger --as alice.key --to "$AGENT" --allow record-register \
    --record-types cexchain.certificate/1 --days 7 > /dev/null

META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}'
cat > requests.jsonl <<JSON
{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{$META}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{$META}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{$META,"name":"cexchain_whoami","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{$META,"name":"cexchain_issue_record","arguments":{"record_type":"cexchain.certificate/1","fields":{"product":"Flange DN50","result":"pass"},"inputs":"inspection sheet 2026-10-06 #7"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{$META,"name":"cexchain_issue_record","arguments":{"record_type":"cexchain.delivery/1","fields":{"item":"flanges"}}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{$META,"name":"cexchain_record_types","arguments":{}}}
{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}
{"jsonrpc":"2.0","id":8,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":9,"method":"ping"}
{"jsonrpc":"2.0","id":10,"method":"resources/list","params":{}}
this is not json
{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"cexchain_issue_record","arguments":{}}}
JSON
run mcp --ledger ledger --as agent.key < requests.jsonl > responses.txt 2> stderr.txt

line() { sed -n "$1p" responses.txt; }
line 1 | contains '"supportedVersions":\["2026-07-28"' || fail "discover"
line 1 | contains '"resultType":"complete"' || fail "discover resultType"
line 2 | contains '"name":"cexchain_issue_record"' || fail "tools/list"
line 2 | contains '"cacheScope":"private"' || fail "tools/list caching"
line 3 | contains '"responsible":"Alice Inspector"' || fail "whoami responsible"
line 3 | contains 'record-register' || fail "whoami delegations"
line 4 | contains '"isError":false' || fail "issue"
RECORD="$(line 4 | grep -oE '"record_id":"[0-9a-f]{64}"' | id_from)"
[ -n "$RECORD" ] || fail "issue record id"
line 5 | contains '"isError":true' || fail "out-of-scope issue must be refused"
line 5 | contains 'no valid delegation' || fail "refusal reason"
line 6 | contains 'cexchain.delivery/1' || fail "record types"
line 7 | contains '"code":-32022' || fail "unsupported version"
line 8 | contains '"protocolVersion":"2025-06-18"' || fail "legacy initialize"
line 9 | contains '"result":{}' || fail "legacy ping"
line 10 | contains '"code":-32601' || fail "unknown method"
line 11 | contains '"code":-32700' || fail "parse error"
line 12 | contains '"isError":true' || fail "missing arguments"
[ "$(wc -l < responses.txt)" -eq 12 ] || fail "one response per request, none for notifications"

# The agent's record carries its accountability, visible to any verifier.
run checkpoint create --ledger ledger --log-key log.key > /dev/null
run export "$RECORD" --ledger ledger --log-key log.key --disclose result --out bundle.cbor > /dev/null
run verify bundle.cbor --ledger-id "$LEDGER_ID" > report.txt
contains 'AI agent: claude-opus-5-5; responsible: Alice Inspector; via mcp:cexchain_issue_record' report.txt \
    || { cat report.txt; fail "report"; }
contains 'result = pass' report.txt || fail "disclosure"
if contains -r 'Flange DN50' ledger/vault; then fail "agent-issued field values must be sealed"; fi

# The agent can verify evidence through MCP too.
printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{%s,"name":"cexchain_verify_evidence","arguments":{"bundle_path":"bundle.cbor","expected_ledger_id":"%s"}}}\n' \
    "$META" "$LEDGER_ID" | run mcp --ledger ledger --as agent.key > responses.txt 2> /dev/null
contains '"verified":true' responses.txt || fail "verify through MCP"

# Assets (D-052): the agent reads them and verifies an asset's evidence.
HOLDER="$(printf 'ab%.0s' $(seq 1 32))"
ASSET="$(run asset issue receivable --ledger ledger --as root.key --holder "$HOLDER" --amount 880.50 \
    --due 2027-01-06 --field invoice=INV-9 | id_from)"
run checkpoint create --ledger ledger --log-key log.key > /dev/null
run asset evidence "$ASSET" --ledger ledger --log-key log.key --out asset.cbor > /dev/null
cat > asset-requests.jsonl <<JSON
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{$META,"name":"cexchain_list_assets","arguments":{"state":"active"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{$META,"name":"cexchain_get_asset","arguments":{"asset":"${ASSET:0:12}"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{$META,"name":"cexchain_verify_asset_evidence","arguments":{"evidence_path":"asset.cbor","expected_ledger_id":"$LEDGER_ID"}}}
JSON
run mcp --ledger ledger --as agent.key < asset-requests.jsonl > responses.txt 2> /dev/null
contains '880.50 CNY' responses.txt || fail "asset tools"
contains "\"holder\":\"$HOLDER\"" responses.txt || fail "asset holder"
contains '"chain":' responses.txt || fail "asset evidence through MCP"

# Contracts (D-053): the agent reads them and verifies an instance's evidence.
# The vectors' oracle contract writes the output its byte-string argument holds.
python3 -c "import json, sys; open('oracle.wasm', 'wb').write(bytes.fromhex(json.load(open(sys.argv[1]))['contract']))" \
    "$VECTORS/protocol-v0.6.json"
CONTRACT="$(run contract deploy oracle.wasm --ledger ledger --as root.key --function open=create \
    --function act=call --compiler "hand-assembled 1" --name "Test agreement" | id_from)"
INSTANCE="$(run contract create "$CONTRACT" open --ledger ledger --as root.key \
    --args '<<[1, {1: "terms", 2: "open"}]>>' --json | json_id)"
run contract evidence "$INSTANCE" --ledger ledger --log-key log.key --out instance.cbor > /dev/null
cat > contract-requests.jsonl <<JSON
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{$META,"name":"cexchain_list_contracts","arguments":{}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{$META,"name":"cexchain_get_instance","arguments":{"instance":"${INSTANCE:0:12}"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{$META,"name":"cexchain_verify_contract_evidence","arguments":{"evidence_path":"instance.cbor","expected_ledger_id":"$LEDGER_ID"}}}
JSON
run mcp --ledger ledger --as agent.key < contract-requests.jsonl > responses.txt 2> /dev/null
contains 'Test agreement' responses.txt || fail "contract tools"
contains '"status":"open"' responses.txt || fail "instance status"
contains 'CexChain contract report' responses.txt || fail "contract evidence through MCP"
echo "mcp end-to-end: ok"
