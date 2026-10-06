#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Drives `cexchain mcp` with raw JSON-RPC, as an AI client would: modern and
# legacy protocol revisions, every tool, an out-of-scope refusal, and the
# resulting evidence verified offline.
set -euo pipefail

CEXCHAIN="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

run() { "$CEXCHAIN" "$@"; }
id_from() { grep -oE '[0-9a-f]{64}' | head -1; }
fail() { echo "FAIL: $1"; echo "--- responses:"; cat responses.txt; exit 1; }

for k in root log alice agent; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --ledger ledger --org "Cirraya Test Factory" --root-key root.key --log-key log.key | id_from)"
ALICE="$(run actor add --ledger ledger --as root.key --kind person --name "Alice Inspector" --key alice.key | id_from)"
run delegate --ledger ledger --as root.key --to "$ALICE" --allow actor-register,delegation-grant,record-register \
    --record-types cexchain.certificate/1 --days 30 --may-delegate > /dev/null
AGENT="$(run actor add --ledger ledger --as alice.key --kind agent --name "Drafting Agent" --key agent.key \
    --responsible "$ALICE" --model claude-opus-5-5 --model-version 2026-09 | id_from)"
run delegate --ledger ledger --as alice.key --to "$AGENT" --allow record-register \
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
line 1 | grep -q '"supportedVersions":\["2026-07-28"' || fail "discover"
line 1 | grep -q '"resultType":"complete"' || fail "discover resultType"
line 2 | grep -q '"name":"cexchain_issue_record"' || fail "tools/list"
line 2 | grep -q '"cacheScope":"private"' || fail "tools/list caching"
line 3 | grep -q '"responsible":"Alice Inspector"' || fail "whoami responsible"
line 3 | grep -q 'record-register' || fail "whoami delegations"
line 4 | grep -q '"isError":false' || fail "issue"
RECORD="$(line 4 | grep -oE '"record_id":"[0-9a-f]{64}"' | id_from)"
[ -n "$RECORD" ] || fail "issue record id"
line 5 | grep -q '"isError":true' || fail "out-of-scope issue must be refused"
line 5 | grep -q 'no valid delegation' || fail "refusal reason"
line 6 | grep -q 'cexchain.delivery/1' || fail "record types"
line 7 | grep -q '"code":-32022' || fail "unsupported version"
line 8 | grep -q '"protocolVersion":"2025-06-18"' || fail "legacy initialize"
line 9 | grep -q '"result":{}' || fail "legacy ping"
line 10 | grep -q '"code":-32601' || fail "unknown method"
line 11 | grep -q '"code":-32700' || fail "parse error"
line 12 | grep -q '"isError":true' || fail "missing arguments"
[ "$(wc -l < responses.txt)" -eq 12 ] || fail "one response per request, none for notifications"

# The agent's record carries its accountability, visible to any verifier.
run checkpoint --ledger ledger --log-key log.key > /dev/null
run export --ledger ledger --log-key log.key --record "$RECORD" --disclose result --out bundle.cbor > /dev/null
run verify bundle.cbor --ledger-id "$LEDGER_ID" > report.txt
grep -q 'AI agent: claude-opus-5-5; responsible: Alice Inspector; via mcp:cexchain_issue_record' report.txt \
    || { cat report.txt; fail "report"; }
grep -q 'result = pass' report.txt || fail "disclosure"

# The agent can verify evidence through MCP too.
printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{%s,"name":"cexchain_verify_evidence","arguments":{"bundle_path":"bundle.cbor","expected_ledger_id":"%s"}}}\n' \
    "$META" "$LEDGER_ID" | run mcp --ledger ledger --as agent.key > responses.txt 2> /dev/null
grep -q '"verified":true' responses.txt || fail "verify through MCP"
echo "mcp end-to-end: ok"
