#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Drives `cexchain mcp` with raw JSON-RPC, as an AI client would: modern and
# legacy protocol revisions, every tool, an out-of-scope refusal, and the
# resulting evidence verified offline. Contracts across two organizations:
# the home's agent creates and calls an instance; a bank's agent proposes a
# call to the home's registrar and consents to it on the bank's SM3 ledger.
# Parts (v0.7): the agents read parents and parts, and call and propose on parts.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
VECTORS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../testvectors" && pwd)"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN CEXCHAIN_SERVER

run() { "$CEXCHAIN" "$@"; }
# Readers in pipelines consume all input: with pipefail, a reader that exits
# early (grep -q, head) can kill the writer with SIGPIPE and fail the test.
contains() { grep "$@" > /dev/null; }
id_from() { grep -oE '[0-9a-f]{64}' | sed -n 1p; }
json_id() { python3 -c "import json, sys; print(json.load(sys.stdin)['instance']['id'])"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# A tool's structured result, from the response on line N.
result() { sed -n "${1}p" responses.txt | json "d['result']['structuredContent']$2"; }
fail() { echo "FAIL: $1"; echo "--- responses:"; cat responses.txt; exit 1; }

export CEXCHAIN_PASSPHRASE="mcp test passphrase"
for k in root log alice agent; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --ledger ledger --org "Cirraya Test Factory" --root-key root.key --log-key log.key | id_from)"
ALICE="$(run actor add --ledger ledger --as root.key --kind person --name "Alice Inspector" --key alice.key | id_from)"
run delegation grant --ledger ledger --as root.key --to "$ALICE" --allow actor-register,delegation-grant,record-register \
    --record-types example.document/1 --days 30 --may-delegate > /dev/null
AGENT="$(run actor add --ledger ledger --as alice.key --kind agent --name "Drafting Agent" --key agent.key \
    --responsible "$ALICE" --model claude-opus-5-5 --model-version 2026-09 | id_from)"
run delegation grant --ledger ledger --as alice.key --to "$AGENT" --allow record-register \
    --record-types example.document/1 --days 7 > /dev/null

META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}'
cat > requests.jsonl <<JSON
{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{$META}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{$META}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{$META,"name":"cexchain_whoami","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{$META,"name":"cexchain_issue_record","arguments":{"record_type":"example.document/1","fields":{"product":"Flange DN50","result":"pass"},"inputs":"inspection sheet 2026-10-06 #7"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{$META,"name":"cexchain_issue_record","arguments":{"record_type":"example.note/1","fields":{"item":"flanges"}}}}
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
for tool in call_contract list_pending_calls fetch_instance propose_contract_call consent_contract_call; do
    line 2 | contains "\"name\":\"cexchain_$tool\"" || fail "tools/list: $tool"
done
line 2 | contains '"cacheScope":"private"' || fail "tools/list caching"
# Spec v0.9 removed native assets: no tool reads them any more.
if line 2 | contains -E '"name":"cexchain_[a-z_]*asset'; then fail "tools/list: an asset tool"; fi
line 3 | contains '"responsible":"Alice Inspector"' || fail "whoami responsible"
line 3 | contains 'record-register' || fail "whoami delegations"
line 4 | contains '"isError":false' || fail "issue"
RECORD="$(line 4 | grep -oE '"record_id":"[0-9a-f]{64}"' | id_from)"
[ -n "$RECORD" ] || fail "issue record id"
line 5 | contains '"isError":true' || fail "out-of-scope issue must be refused"
line 5 | contains 'no valid delegation' || fail "refusal reason"
line 6 | contains 'cexchain.contract-consent/1' || fail "record types"
result 6 "['record_types'][3]['purpose']" | contains 'contract consent' || fail "record type purposes"
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

# --- Contracts across organizations, through MCP (D-053) ------------------------------
# The factory's ledger is the home of a supply agreement; a bank, whose ledger
# hashes with SM3, is a party. The counting contract writes its arguments'
# item n for a call citing n consents (each item is an output, as CBOR in a
# byte string): signing and closing need the bank's consent.
python3 -c "import json, sys; open('counting.wasm', 'wb').write(bytes.fromhex(json.load(open(sys.argv[1]))['counting']))" \
    "$VECTORS/test-contracts.json"
COUNTING="$(run contract deploy counting.wasm --ledger ledger --as root.key --function propose=create \
    --function sign=call --function close=call --compiler "test_contracts.py 1" --name "Supply agreement" | id_from)"
run delegation grant --ledger ledger --as root.key --to "$AGENT" --allow contract-call \
    --contracts "$COUNTING" --days 7 > /dev/null
for k in b-root b-log b-officer b-agent; do run key generate --alg sm2-sm3 --out "$k.key" > /dev/null; done
BANK_ID="$(run init --ledger bank --org "Partner Bank" --root-key b-root.key --log-key b-log.key --hash sm3 | id_from)"
OFFICER="$(run actor add --ledger bank --as b-root.key --kind person --name "Credit Officer" --key b-officer.key | id_from)"
BANK_AGENT="$(run actor add --ledger bank --as b-root.key --kind agent --name "Credit Agent" \
    --key b-agent.key --responsible "$OFFICER" --model credit-model-7 | id_from)"
run peer add bank --ledger-id "$BANK_ID" --ledger ledger > /dev/null
CREATE="[<<[1, {1: \\\"proposed\\\", 2: \\\"proposed\\\", 3: {\\\"bank\\\": h'$BANK_ID'}}]>>]"
SIGN="[<<[2, [h'$BANK_ID']]>>, <<[1, {1: \\\"signed\\\", 2: \\\"signed\\\"}]>>]"
CLOSE="[<<[2, [h'$BANK_ID']]>>, <<[1, {1: \\\"closed\\\", 2: \\\"closed\\\", 5: true}]>>]"
call() { printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{%s,"name":"%s","arguments":%s}}\n' "$1" "$META" "$2" "$3"; }

# The factory's agent acts on its own ledger: what the contract decides, and
# what its delegation (this contract only) allows.
{
    call 1 cexchain_call_contract "{\"contract\":\"${COUNTING:0:12}\",\"function\":\"propose\",\"arguments\":\"$CREATE\",\"dry_run\":true}"
    call 2 cexchain_call_contract "{\"contract\":\"$COUNTING\",\"function\":\"propose\",\"arguments\":\"$CREATE\",\"reference\":\"PO-7\",\"inputs\":\"purchase order PO-7\"}"
    call 3 cexchain_call_contract "{\"contract\":\"$COUNTING\",\"function\":\"propose\",\"arguments\":\"[1.5]\"}"
    call 4 cexchain_call_contract "{\"contract\":\"$COUNTING\",\"function\":\"propose\",\"arguments\":{\"price\":98000}}"
    call 5 cexchain_call_contract "{\"instance\":\"$INSTANCE\",\"function\":\"act\",\"arguments\":\"<<[1, {1: 2}]>>\"}"
    call 6 cexchain_call_contract "{\"contract\":\"$COUNTING\",\"instance\":\"$INSTANCE\",\"function\":\"propose\"}"
} > home-requests.jsonl
run mcp --ledger ledger --as agent.key < home-requests.jsonl > responses.txt 2> /dev/null
[ "$(result 1 "['verdict']")" = accept ] || fail "dry run"
[ "$(result 1 "['recorded']")" = False ] || fail "a dry run records nothing"
[ "$(result 2 "['recorded']")" = True ] || fail "create"
[ "$(result 2 "['instance']['status']")" = proposed ] || fail "created instance"
AGREEMENT="$(result 2 "['instance']['id']")"
line 3 | contains 'floating-point' || fail "arguments are checked"
[ "$(result 4 "['verdict']")" = refuse ] || fail "JSON arguments reach the contract"
result 4 "['reason']" | contains 'trapped' || fail "a refusal's reason"
line 5 | contains 'no valid delegation' || fail "another contract is out of scope"
line 6 | contains "give 'contract'" || fail "contract or instance"
call 1 cexchain_call_contract "{\"instance\":\"${AGREEMENT:0:12}\",\"function\":\"sign\",\"arguments\":\"$SIGN\"}" \
    | run mcp --ledger ledger --as agent.key > responses.txt 2> /dev/null
[ "$(result 1 "['verdict']")" = needs ] || fail "signing needs the bank"
[ "$(result 1 "['needs'][0]")" = "$BANK_ID" ] || fail "whose consent"
[ "$(result 1 "['recorded']")" = False ] || fail "nothing recorded without consents"
result 1 "['reason']" | contains 'needs the consent of bank' || fail "needs, by peer name"
result 1 "['advice']" | contains 'registrar' || fail "advice"

# The factory serves its ledger with a registrar for this contract.
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
REGISTRAR="$(run actor add --ledger ledger --as root.key --kind device --name "Contract Registrar" --key registrar.pub | id_from)"
run delegation grant --ledger ledger --as root.key --to "$REGISTRAR" --allow contract-call \
    --contracts "$COUNTING" > /dev/null
run token create bank --scope peer --out bank.token --ledger ledger > /dev/null
"$CEXCHAIN" serve --ledger ledger --log-key log.key --registrar-key registrar.key --listen 127.0.0.1:0 \
    --json --quiet > factory.json 2> factory.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do
    python3 -c "import json; json.load(open('factory.json'))" 2> /dev/null && break
    sleep 0.1
done
URL="$(json 'd["url"]' < factory.json)"
run peer add factory --ledger-id "$LEDGER_ID" --url "$URL" --token-file bank.token --ledger bank > /dev/null

# The bank's agent: no delegation for consents yet, and a server without the log key.
{
    call 1 cexchain_ledger_status '{}'
    call 2 cexchain_propose_contract_call "{\"home\":\"factory\",\"instance\":\"$AGREEMENT\",\"function\":\"sign\",\"arguments\":\"$SIGN\"}"
    call 3 cexchain_consent_contract_call "{\"home\":\"factory\",\"call\":\"$AGREEMENT\"}"
} > bank-requests.jsonl
run mcp --ledger bank --as b-agent.key < bank-requests.jsonl > responses.txt 2> /dev/null
[ "$(result 1 "['peers'][0]['name']")" = factory ] || fail "peers"
line 2 | contains 'no valid delegation lets you consent' || fail "proposals need a consent delegation"
line 3 | contains 'log-key' || fail "consents need the log key"
run delegation grant --ledger bank --as b-root.key --to "$BANK_AGENT" --allow record-register \
    --record-types cexchain.contract-consent/1 > /dev/null
bank_mcp() { run mcp --ledger bank --as b-agent.key --log-key b-log.key > responses.txt 2> /dev/null; }

# It proposes signing to the factory's registrar, reviews the call and the
# instance, and consents; its consent completes the call.
call 1 cexchain_propose_contract_call "{\"home\":\"factory\",\"instance\":\"$AGREEMENT\",\"function\":\"sign\",\"arguments\":\"$SIGN\",\"reference\":\"INV-7\",\"days\":3}" \
    | bank_mcp
[ "$(result 1 "['status']")" = waiting ] || fail "proposed"
result 1 "['waiting_for']" | contains 'Partner Bank (this ledger' || fail "waiting for the bank"
CALL="$(result 1 "['call']")"
{
    call 1 cexchain_list_pending_calls '{"home":"factory"}'
    call 2 cexchain_fetch_instance "{\"home\":\"factory\",\"instance\":\"$AGREEMENT\"}"
    call 3 cexchain_consent_contract_call "{\"home\":\"factory\",\"call\":\"$CALL\",\"days\":40}"
    call 4 cexchain_consent_contract_call "{\"home\":\"factory\",\"call\":\"$CALL\",\"reference\":\"Credit approval CA-7\",\"inputs\":\"credit memo 7\"}"
} > consent-requests.jsonl
bank_mcp < consent-requests.jsonl
[ "$(result 1 "['calls'][0]['call']")" = "$CALL" ] || fail "pending calls"
result 1 "['calls'][0]['arguments']" | contains "h'" || fail "terms in diagnostic notation"
[ "$(result 2 "['instance']['status']")" = proposed ] || fail "fetched instance"
result 2 "['report']" | contains 'CexChain contract report' || fail "instance report"
line 3 | contains 'from 1 to 30' || fail "days"
[ "$(result 4 "['home_answer']['status']")" = recorded ] || fail "the registrar recorded the call"
[ "$(result 4 "['function']")" = sign ] || fail "consent terms"
[ "$(run contract instance "$AGREEMENT" --ledger ledger --json | json 'd["status"]')" = signed ] \
    || fail "signed"

# Closing: the bank's agent keeps its consent as a file, which the factory's
# agent cites in its own call.
call 1 cexchain_propose_contract_call "{\"home\":\"factory\",\"instance\":\"$AGREEMENT\",\"function\":\"close\",\"arguments\":\"$CLOSE\"}" \
    | bank_mcp
CALL2="$(result 1 "['call']")"
{
    call 1 cexchain_consent_contract_call "{\"home\":\"factory\",\"call\":\"$CALL2\",\"send\":false}"
    call 2 cexchain_consent_contract_call "{\"home\":\"factory\",\"call\":\"$CALL2\",\"send\":false,\"out\":\"close-bank.cbor\"}"
} > close-requests.jsonl
bank_mcp < close-requests.jsonl
line 1 | contains "give 'out'" || fail "a consent kept nowhere"
[ "$(result 2 ".get('home_answer')")" = None ] || fail "not sent"
[ -s close-bank.cbor ] || fail "the consent's evidence"
call 1 cexchain_call_contract "{\"instance\":\"$AGREEMENT\",\"function\":\"close\",\"arguments\":\"$CLOSE\",\"consents\":[\"close-bank.cbor\"]}" \
    | run mcp --ledger ledger --as agent.key > responses.txt 2> /dev/null
[ "$(result 1 "['recorded']")" = True ] || fail "closed"
[ "$(result 1 "['instance']['final']")" = True ] || fail "final"

# Anyone verifies it offline: who acted, through which tool, under which model.
run contract fetch --peer factory --instance "$AGREEMENT" --out agreement.cbor --ledger bank > /dev/null
run contract verify agreement.cbor --ledger-id "$LEDGER_ID" > verify.txt
contains 'via mcp:cexchain_call_contract' verify.txt || { cat verify.txt; fail "the agent's call"; }
contains 'given by "Credit Agent" (a machine: AI agent; model credit-model-7; responsible: Credit Officer)' verify.txt \
    || { cat verify.txt; fail "the agent's consent"; }
contains 'ref. Credit approval CA-7' verify.txt || fail "consent reference"
run contract verify agreement.cbor --ledger-id "$LEDGER_ID" --json > verify.json
json '[t["name"] for c in d["calls"] for k in c["consents"] for t in k["provenance"]["tools"]]' < verify.json \
    | contains -Fx "['mcp:cexchain_consent_contract_call', 'mcp:cexchain_consent_contract_call']" \
    || fail "consents through MCP"
json 'd["calls"][2]["consents"][0]["provenance"]["input_commitment"] is None' < verify.json \
    | contains -x True || fail "inputs only where given"
# Parts (v0.7): the splitting test contract. The factory's agent issues a
# receivable the factory holds and splits it between the factory and the
# bank; it then splits the factory's part (a call on a part). The bank's
# agent reads its part, with its parent, and sells it back to the factory
# through the registrar (the write tools work on parts).
python3 -c "import json, sys; open('split.wasm', 'wb').write(bytes.fromhex(json.load(open(sys.argv[1]))['split']))" \
    "$VECTORS/test-contracts.json"
SPLIT="$(run contract deploy split.wasm --ledger ledger --as root.key --function issue=create \
    --function split=call --function transfer=call --compiler "test_contracts.py 1" --name "Receivable" | id_from)"
for actor in "$AGENT" "$REGISTRAR"; do
    run delegation grant --ledger ledger --as root.key --to "$actor" --allow contract-call \
        --contracts "$SPLIT" --days 7 > /dev/null
done
call 1 cexchain_call_contract "{\"contract\":\"$SPLIT\",\"function\":\"issue\",\"arguments\":\"[h'$LEDGER_ID', 900]\"}" \
    | run mcp --ledger ledger --as agent.key > responses.txt 2> /dev/null
RECEIVABLE="$(result 1 "['instance']['id']")"
[ "$(result 1 "['children']")" = "[]" ] || fail "an issue creates no parts"
call 1 cexchain_call_contract "{\"instance\":\"$RECEIVABLE\",\"function\":\"split\",\"arguments\":\"[[h'$LEDGER_ID', 500], [h'$BANK_ID', 400]]\"}" \
    | run mcp --ledger ledger --as agent.key > responses.txt 2> /dev/null
[ "$(result 1 "['recorded']")" = True ] || fail "split"
OWN_PART="$(result 1 "['children'][0]")"
BANK_PART="$(result 1 "['children'][1]")"
{
    call 1 cexchain_get_instance "{\"instance\":\"${RECEIVABLE:0:12}\"}"
    call 2 cexchain_get_instance "{\"instance\":\"$OWN_PART\"}"
    call 3 cexchain_call_contract "{\"instance\":\"$OWN_PART\",\"function\":\"split\",\"arguments\":\"[[h'$LEDGER_ID', 200], [h'$LEDGER_ID', 300]]\",\"dry_run\":true}"
    call 4 cexchain_call_contract "{\"instance\":\"$OWN_PART\",\"function\":\"split\",\"arguments\":\"[[h'$LEDGER_ID', 200], [h'$LEDGER_ID', 300]]\"}"
} > part-requests.jsonl
run mcp --ledger ledger --as agent.key < part-requests.jsonl > responses.txt 2> /dev/null
[ "$(result 1 "['final']")" = True ] || fail "a split receivable is final"
[ "$(result 1 "['children'][1]['id']")" = "$BANK_PART" ] || fail "the parent lists its parts"
[ "$(result 1 "['children'][1]['parties']['holder']")" = "$BANK_ID" ] || fail "a part's holder"
[ "$(result 2 "['parent']")" = "$RECEIVABLE" ] || fail "a part's parent"
[ "$(result 2 "['depth']")" = 1 ] || fail "a part's depth"
[ "$(result 2 "['ancestors']")" = "['$RECEIVABLE']" ] || fail "a part's ancestors"
[ "$(result 3 "['verdict']")" = accept ] || fail "a dry run on a part"
[ "$(result 3 "['children'].__len__()")" = 2 ] || fail "a dry run shows the parts"
[ "$(result 4 "['children'].__len__()")" = 2 ] || fail "a part split again"
TIER3="$(result 4 "['children'][0]")"
[ "$(run contract instance "$TIER3" --ledger ledger --json | json 'd["depth"]')" = 2 ] || fail "tier 3"
{
    call 1 cexchain_fetch_instance "{\"home\":\"factory\",\"instance\":\"$BANK_PART\"}"
    call 2 cexchain_propose_contract_call "{\"home\":\"factory\",\"instance\":\"$BANK_PART\",\"function\":\"transfer\",\"arguments\":\"h'$LEDGER_ID'\"}"
} > bank-part-requests.jsonl
bank_mcp < bank-part-requests.jsonl
[ "$(result 1 "['instance']['parent']")" = "$RECEIVABLE" ] || fail "fetched part's parent"
[ "$(result 1 "['instance']['ancestors'][0]['id']")" = "$RECEIVABLE" ] || fail "fetched part's ancestors"
result 1 "['report']" | contains 'Ancestors    oldest first' || fail "the part's report"
[ "$(result 2 "['status']")" = waiting ] || fail "a part's party proposes"
PART_CALL="$(result 2 "['call']")"
call 1 cexchain_consent_contract_call "{\"home\":\"factory\",\"call\":\"$PART_CALL\"}" | bank_mcp
[ "$(result 1 "['home_answer']['status']")" = recorded ] || fail "the bank's consent on its part"
[ "$(run contract instance "$BANK_PART" --ledger ledger --json | json 'd["parties"]["holder"]')" = "$LEDGER_ID" ] \
    || fail "sold back"
run contract evidence "$TIER3" --ledger ledger --log-key log.key --out tier3.cbor > /dev/null
call 1 cexchain_verify_contract_evidence "{\"evidence_path\":\"tier3.cbor\",\"expected_ledger_id\":\"$LEDGER_ID\"}" \
    | run mcp --ledger ledger --as agent.key > responses.txt 2> /dev/null
[ "$(result 1 "['instance']['depth']")" = 2 ] || fail "a tier-3 part verified through MCP"
[ "$(result 1 "['verified']")" = True ] || fail "verified"
run mcp --help | contains 'cexchain_consent_contract_call'
run completion bash | contains 'log-key'
for l in ledger bank; do run audit --ledger "$l" | contains 'audit passed'; done
echo "mcp end-to-end: ok"
