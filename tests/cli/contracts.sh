#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Contracts across four organizations, end to end (D-053): a core enterprise
# deploys a contract and proposes an agreement to its supplier and its bank,
# whose ledger hashes with SM3. The supplier proposes signing it to the core
# enterprise's registrar; the supplier's organization and the bank's AI agent
# consent on their own ledgers, and the registrar records the call. The
# agreement is closed with a consent carried as a file, and everyone verifies
# it offline. Refused on the way: a stale head, a consent from a ledger the
# contract did not ask for, one sent by another peer, a lapsed one, a
# withdrawn one, a retired contract, and delegations for another contract.
# Backups keep the held calls and the consents calls cite.
# Usage: contracts.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="contracts test"
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
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
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

D="$WORK/core"; S="$WORK/supplier"; B="$WORK/bank"; O="$WORK/outsider"
d() { run "$@" --ledger "$D"; }
s() { run "$@" --ledger "$S"; }
b() { run "$@" --ledger "$B"; }
o() { run "$@" --ledger "$O"; }

# --- Four organizations; the bank's ledger hashes with SM3 ---------------------------
for k in d s o; do
    run key generate --out "$k-root.key" > /dev/null
    run key generate --out "$k-log.key" > /dev/null
done
for k in b-root b-log b-officer b-agent; do run key generate --alg sm2-sm3 --out "$k.key" > /dev/null; done
run init --org "Core Enterprise" --root-key d-root.key --log-key d-log.key --ledger "$D" > /dev/null
run init --org "Supplier" --root-key s-root.key --log-key s-log.key --ledger "$S" > /dev/null
run init --org "Bank" --root-key b-root.key --log-key b-log.key --hash sm3 --ledger "$B" > /dev/null
run init --org "Outsider" --root-key o-root.key --log-key o-log.key --ledger "$O" > /dev/null
D_ID="$(d status --json | json 'd["ledger_id"]')"
S_ID="$(s status --json | json 'd["ledger_id"]')"
B_ID="$(b status --json | json 'd["ledger_id"]')"
O_ID="$(o status --json | json 'd["ledger_id"]')"
d peer add supplier --ledger-id "$S_ID" > /dev/null
d peer add bank --ledger-id "$B_ID" > /dev/null
d peer add outsider --ledger-id "$O_ID" > /dev/null
s peer add bank --ledger-id "$B_ID" > /dev/null

# The contracts: from the test vectors (tools/testvectors/test_contracts.py
# assembles the counting contract; protocol-v0.6.json holds the oracle).
python3 - "$SOURCE/testvectors" << 'EOF'
import json, sys
vectors = sys.argv[1]
with open(vectors + "/test-contracts.json") as f:
    open("counting.wasm", "wb").write(bytes.fromhex(json.load(f)["counting"]))
with open(vectors + "/protocol-v0.6.json") as f:
    open("oracle.wasm", "wb").write(bytes.fromhex(json.load(f)["contract"]))
EOF

# --- Deploying -----------------------------------------------------------------------
run contract deploy --help | contains 'contract profile'
printf 'not a module' > junk.wasm
expect_exit 2 contract deploy junk.wasm --function propose=create --compiler x --as d-root.key \
    --ledger "$D"
contains 'is not a contract module' out.txt
expect_exit 1 contract deploy counting.wasm --function sign=call --compiler x --as d-root.key \
    --ledger "$D"
contains 'creates instances' out.txt
expect_exit 1 contract deploy counting.wasm --function propose=maybe --compiler x --as d-root.key \
    --ledger "$D"
expect_exit 1 contract deploy counting.wasm --function propose=create --as d-root.key --ledger "$D"
contains 'missing required option --compiler' out.txt
C="$(d contract deploy counting.wasm --function propose=create --function sign=call \
    --function close=call --compiler "test_contracts.py 1" --name "Supply agreement" \
    --source "$SOURCE/tools/testvectors/test_contracts.py" --as d-root.key --json \
    | json 'd["contract"]["id"]')"
d contract show "${C:0:12}" > show.txt
contains 'name:       Supply agreement' show.txt
contains 'functions:  close, propose (creates), sign' show.txt
d contract show "$C" --code-out back.wasm --source-out back.py > /dev/null
cmp counting.wasm back.wasm
cmp "$SOURCE/tools/testvectors/test_contracts.py" back.py
d contract show "$C" --json | json 'd["functions"]["propose"]' | contains -x create
d contract show "$C" --json | json 'd["code_size"]' | contains -x "$(wc -c < counting.wasm | tr -d ' ')"
X="$(d contract deploy oracle.wasm --function open=create --function act=call \
    --compiler "hand-assembled 1" --as d-root.key --json | json 'd["contract"]["id"]')"
d contract list | contains '"Supply agreement"'
d contract list --json | json 'len(d)' | contains -x 2
d log list | contains 'deploy contract'

# --- An agreement, proposed to the supplier and the bank -----------------------------------
# The counting contract writes its arguments' item n for a call citing n
# consents (the last one for more): each item is the contract's output, as
# CBOR in a byte string.
CREATE="[<<[1, {1: \"proposed\", 2: \"proposed\", 3: {\"supplier\": h'$S_ID', \"bank\": h'$B_ID'}}]>>]"
d contract create "$C" propose --args "$CREATE" --as d-root.key --dry-run \
    | contains 'would accept propose: status proposed'
d contract instances --json | json 'len(d)' | contains -x 0
expect_exit 1 contract create "$C" propose --args '[1.5]' --as d-root.key --ledger "$D"
contains 'floating-point' out.txt
expect_exit 1 contract create "$C" propose --args "$CREATE" --args-cbor x.cbor --as d-root.key \
    --ledger "$D"
expect_exit 2 contract create "$C" sign --as d-root.key --ledger "$D"
contains 'no function sign that creates' out.txt
expect_exit 2 contract create "$C" propose --args '"not today"' --as d-root.key --ledger "$D"
contains 'the contract refuses the call: not today' out.txt
I="$(d contract create "$C" propose --args "$CREATE" --reference "PO-2026-1012" --as d-root.key \
    --json | json 'd["instance"]["id"]')"
d contract instance "${I:0:12}" > inst.txt
contains 'status:    proposed' inst.txt
contains 'supplier: supplier' inst.txt
contains 'create with propose by "Core Enterprise"' inst.txt
d contract instance "$I" --json | json 'd["parties"]["bank"]' | contains -x "$B_ID"
d contract instances --party bank | contains 'proposed'
d contract instances --contract "$X" --json | json 'len(d)' | contains -x 0
d status | contains 'contracts:     2 (1 instances)'

# Signing needs both parties' consents: the home cannot record it alone.
LO="$(printf '%s\n' "$S_ID" "$B_ID" | LC_ALL=C sort | sed -n 1p)"
HI="$(printf '%s\n' "$S_ID" "$B_ID" | LC_ALL=C sort | sed -n 2p)"
NEEDS="<<[2, [h'$LO', h'$HI']]>>"
SIGN="[$NEEDS, $NEEDS, <<[1, {1: \"signed\", 2: \"effective\"}]>>]"
d contract call "$I" sign --args "$SIGN" --as d-root.key --dry-run --json > dry.json
json 'd["verdict"]' < dry.json | contains -x needs
json 'len(d["needs"])' < dry.json | contains -x 2
expect_exit 2 contract call "$I" sign --args "$SIGN" --as d-root.key --ledger "$D"
contains 'needs the consent of' out.txt
contains 'contract propose' out.txt

# --- The registrar, and delegations limited to contracts ----------------------------------
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
run key generate --out clerk.key > /dev/null
REGISTRAR="$(d actor add --as d-root.key --kind device --name "Contract Registrar" \
    --key registrar.pub --json | json 'd["actor"]["id"]')"
d delegation grant --as d-root.key --to "$REGISTRAR" --allow contract-call \
    --contracts "${C:0:12}" > /dev/null
d delegation list | contains "for contract(s) ${C:0:12}"
d delegation list --json | json 'd[0]["scope"]["contracts"][0]' | contains -x "$C"
expect_exit 2 delegation grant --as d-root.key --to "$REGISTRAR" --allow contract-call \
    --contracts 00000000 --ledger "$D"
contains 'no contract' out.txt
CLERK="$(d actor add --as d-root.key --kind person --name "Clerk" --key clerk.key --json \
    | json 'd["actor"]["id"]')"
d delegation grant --as d-root.key --to "$CLERK" --allow contract-call,contract-retire \
    --contracts "$X" > /dev/null
# The clerk may act on the oracle's instances only.
J="$(d contract create "$X" open --args "<<[1, {1: \"open\", 2: \"open\", 3: {\"supplier\": h'$S_ID'}}]>>" \
    --as d-root.key --json | json 'd["instance"]["id"]')"
d contract call "$J" act --args "<<[1, {1: \"acted\", 2: \"acted\"}]>>" --as clerk.key \
    | contains 'status: acted'
expect_exit 2 contract call "$I" sign --args "$SIGN" --as clerk.key --ledger "$D"
contains 'no valid delegation lets Clerk do this' out.txt
expect_exit 2 contract retire "$C" --as clerk.key --ledger "$D"
contains 'no valid delegation' out.txt

for p in supplier bank outsider; do d token create "$p" --scope peer --out "$p-at-core.token" > /dev/null; done
d token create staff --scope read,submit,admin --out staff.token > /dev/null
start_server core.json --ledger "$D" --log-key d-log.key --registrar-key registrar.key
D_URL="$(json 'd["url"]' < core.json)"
SERVER=(--server "$D_URL" --token-file staff.token --ledger-id "$D_ID" --cache "$WORK/cache")
s peer add core --ledger-id "$D_ID" --url "$D_URL" --token-file supplier-at-core.token > /dev/null
b peer add core --ledger-id "$D_ID" --url "$D_URL" --token-file bank-at-core.token > /dev/null
o peer add core --ledger-id "$D_ID" --url "$D_URL" --token-file outsider-at-core.token > /dev/null
b peer add supplier --ledger-id "$S_ID" > /dev/null

# The registrar records no call on its own word, nor on another contract.
expect_exit 2 contract propose "$J" act --args "<<[2, [h'$S_ID']]>>" "${SERVER[@]}"
contains 'no delegation for calls on this contract' out.txt

# --- Online: the supplier proposes signing; both parties consent ---------------------------
s contract propose "$I" sign --peer core --args "$SIGN" --reference "INV-77" --json > proposed.json
json 'd["status"]' < proposed.json | contains -x waiting
json 'len(d["missing"])' < proposed.json | contains -x 2
CALL="$(json 'd["call"]' < proposed.json)"
HEAD="$(d contract instance "$I" --json | json 'd["head"]')"
s contract propose "$I" sign --peer core --args "$SIGN" --reference "INV-77" > again.txt
contains 'core: waiting' again.txt
contains 'waiting for:  .*bank (' again.txt
contains 'Supplier (this ledger' again.txt
expect_exit 2 contract propose "$I" sign --peer core --args "$SIGN" --reference "INV-78" --ledger "$S"
contains 'another reference' out.txt
expect_exit 2 contract propose "$I" sign --peer core --args "$SIGN" --head 1 --ledger "$S"
contains 'moved on' out.txt
expect_exit 2 contract propose "$I" sign --peer core --args '"no deal"' --ledger "$S"
contains 'refuses the call: no deal' out.txt
expect_exit 2 contract propose "$I" sign --peer core --args '[<<[1, {1: "x"}]>>]' --ledger "$S"
contains 'without consents' out.txt
# To a ledger that is no party, the instance does not exist.
expect_exit 2 contract propose "$I" sign --peer core --args "$SIGN" --head "$HEAD" --ledger "$O"
contains 'no such instance' out.txt
expect_exit 1 contract propose "$I" sign --args "$SIGN" --ledger "$S"
contains 'propose to a home' out.txt

# Each sees the calls that concern it.
s contract pending --peer core | contains "call ${CALL:0:12}  sign on instance ${I:0:12}"
b contract pending --peer core --json | json 'd[0]["call"]' | contains -x "$CALL"
b contract pending --peer core "$CALL" --json | json 'd["arguments"]' | contains "h'"
o contract pending --peer core --json | json 'len(d)' | contains -x 0
run contract pending "${SERVER[@]}" --json | json 'd[0]["proposer"]' | contains -x supplier
d contract pending | contains 'proposed by:  supplier'

# The supplier's organization consents, with the terms the registrar holds.
s contract consent --peer core --call "$CALL" --as s-root.key --log-key s-log.key --send \
    --out sign-s.cbor > consent-s.txt
contains 'consented to sign' consent-s.txt
contains 'core: waiting' consent-s.txt
expect_exit 1 contract consent --peer core --call "$CALL" --head 3 --as s-root.key \
    --log-key s-log.key --ledger "$S"
contains 'drop --head' out.txt
# A ledger the contract did not ask for: refused.
expect_exit 2 contract consent --peer core --instance "$I" --function sign --args "$SIGN" \
    --head "$HEAD" --as o-root.key --log-key o-log.key --send --ledger "$O"
contains 'did not ask for your ledger' out.txt
# A consent sent by another peer than the one whose ledger gave it: refused.
expect_exit 2 contract send sign-s.cbor --peer core --ledger "$B"
contains 'peer core refused' out.txt

# The bank's AI agent consents on the bank's SM3 ledger; that completes it.
OFFICER="$(b actor add --as b-root.key --kind person --name "Credit Officer" --key b-officer.key \
    --json | json 'd["actor"]["id"]')"
AGENT="$(b actor add --as b-root.key --kind agent --name "Credit Agent" --key b-agent.key \
    --responsible "$OFFICER" --model credit-model-7 --json | json 'd["actor"]["id"]')"
b delegation grant --as b-root.key --to "$AGENT" --allow record-register \
    --record-types cexchain.contract-consent/1 > /dev/null
b contract consent --peer core --call "$CALL" --as b-agent.key --log-key b-log.key --send \
    --reference "Credit approval CA-9" --json > consent-b.json
json 'd["home_answer"]["status"]' < consent-b.json | contains -x recorded
d contract instance "$I" --json | json 'd["status"]' | contains -x effective
d contract instance "$I" > inst.txt
contains 'call sign by "Contract Registrar"' inst.txt
contains 'AI agent, model credit-model-7' inst.txt
d contract pending | contains 'no pending calls'
# A consent to the head before the call can no longer be used.
expect_exit 2 contract send sign-s.cbor --peer core --ledger "$S"
contains 'earlier head' out.txt

# --- Evidence, verified offline ---------------------------------------------------------
s contract fetch --peer core --instance "$I" --out e1.cbor | contains 'effective (verified)'
run contract verify e1.cbor --ledger-id "$D_ID" > verify1.txt
contains 'Status       effective' verify1.txt
contains 'consent of Supplier (SHA-256): given by "Supplier"' verify1.txt
contains 'consent of Bank (SM3): given by "Credit Agent"' verify1.txt
contains 'model credit-model-7; responsible: Credit Officer' verify1.txt
contains 'ref. Credit approval CA-9' verify1.txt
contains 'reference  INV-77' verify1.txt
run contract verify e1.cbor --ledger-id "$D_ID" --json > verify1.json
json 'd["verified"]' < verify1.json | contains -x True
json 'd["instance"]["parties"]["bank"]["organization"]' < verify1.json | contains -x Bank
json 'len(d["calls"])' < verify1.json | contains -x 2
json 'd["calls"][1]["called_by"]["name"]' < verify1.json | contains -x "Contract Registrar"
json 'd["calls"][1]["outcome"]["status"]' < verify1.json | contains -x effective
json 'sorted(c["organization"] for c in d["calls"][1]["consents"])' < verify1.json \
    | contains -Fx "['Bank', 'Supplier']"
json '[c["provenance"]["model"] for c in d["calls"][1]["consents"] if c["provenance"]]' \
    < verify1.json | contains -Fx "['credit-model-7']"
expect_exit 3 contract verify e1.cbor --ledger-id "$S_ID"
expect_exit 3 contract verify e1.cbor --ledger-id "$D_ID" --require-presence
contains 'without proof of a person' out.txt
expect_exit 3 contract verify e1.cbor --ledger-id "$D_ID" --min-witnesses 1
contains '0 trusted witness cosignatures, 1 required' out.txt
python3 -c "b = bytearray(open('e1.cbor', 'rb').read()); b[len(b) // 2] ^= 1; open('bad.cbor', 'wb').write(b)"
expect_exit 3 contract verify bad.cbor --ledger-id "$D_ID" --json
contains '"verified": false' out.txt
# No party, no evidence.
expect_exit 2 contract fetch --peer core --instance "$I" --out none.cbor --ledger "$O"
contains 'only to its parties' out.txt

# Through the server, as its staff: the same answers from a verified mirror.
run contract list "${SERVER[@]}" --json | json 'len(d)' | contains -x 2
run contract instance "$I" "${SERVER[@]}" --json | json 'd["status"]' | contains -x effective
run contract evidence "$I" "${SERVER[@]}" --out e2.cbor > /dev/null
run contract verify e2.cbor --ledger-id "$D_ID" | contains 'Status       effective'

# --- Offline: closing it with a consent carried as a file ----------------------------------
CLOSE="[<<[2, [h'$S_ID']]>>, <<[1, {1: \"closed\", 2: \"closed\", 5: true}]>>]"
HEAD="$(d contract instance "$I" --json | json 'd["head"]')"
close_consent() { # OUT ARGS...: the supplier's consent to closing, as a file
    local out="$1"; shift
    s contract consent --home "$D_ID" --hash sha256 --instance "$I" --function close \
        --args "$CLOSE" --head "$HEAD" --as s-root.key --log-key s-log.key --out "$out" "$@" > /dev/null
}
close_consent lapsed.cbor --days 0
expect_exit 2 contract call "$I" close --args "$CLOSE" --consent lapsed.cbor --as d-root.key \
    --ledger "$D"
contains 'lapsed' out.txt
expect_exit 1 contract consent --home "$D_ID" --instance "$I" --function close --args "$CLOSE" \
    --head "$HEAD" --as s-root.key --log-key s-log.key --ledger "$S"
contains 'give --hash' out.txt
close_consent close-s.cbor --reference "Delivered in full"
expect_exit 2 contract call "$I" close --args "[]" --consent close-s.cbor --as d-root.key \
    --ledger "$D"
contains 'other terms' out.txt
d contract call "$I" close --args "$CLOSE" --consent close-s.cbor --as d-root.key \
    | contains 'status: closed (final)'
expect_exit 2 contract call "$I" close --args "$CLOSE" --consent close-s.cbor --as d-root.key \
    --ledger "$D"
contains 'final' out.txt
d contract evidence "$I" --log-key d-log.key --out e3.cbor | contains 'wrote the evidence'
run contract verify e3.cbor --ledger-id "$D_ID" > verify3.txt
contains 'FINAL: it takes no more calls' verify3.txt
contains 'ref. Delivered in full' verify3.txt
d contract instances --open --json | json 'len(d)' | contains -x 1

# --- A consent withdrawn before use, and a held call kept by backups ------------------------
I2="$(d contract create "$C" propose --args "$CREATE" --as d-root.key --json \
    | json 'd["instance"]["id"]')"
run contract propose "$I2" sign --args "$SIGN" "${SERVER[@]}" --json > proposed2.json
json 'd["proposer"]' < proposed2.json | contains -x staff
CALL2="$(json 'd["call"]' < proposed2.json)"
s contract consent --peer core --call "$CALL2" --as s-root.key --log-key s-log.key --json > w.json
s contract withdraw "$(json 'd["consent"]' < w.json)" --as s-root.key | contains 'withdrew consent'
s checkpoint create --log-key s-log.key > /dev/null
s export "$(json 'd["consent"]' < w.json)" --log-key s-log.key --out withdrawn.cbor > /dev/null
expect_exit 2 contract send withdrawn.cbor --peer core --ledger "$S"
contains 'withdrawn' out.txt
s contract consent --peer core --call "$CALL2" --as s-root.key --log-key s-log.key --send \
    | contains 'core: waiting'

d backup create --out d.backup --log-key d-log.key > /dev/null
run backup restore d.backup --ledger "$WORK/restored" > /dev/null
run contract pending --ledger "$WORK/restored" --json > restored.json
json 'd[0]["call"]' < restored.json | contains -x "$CALL2"
json 'd[0]["consented"]' < restored.json | contains "$S_ID"
run contract evidence "$I" --ledger "$WORK/restored" --log-key d-log.key --out e4.cbor > /dev/null
run contract verify e4.cbor --ledger-id "$D_ID" | contains 'consent of Bank (SM3)'

# --- Retiring ------------------------------------------------------------------------------
d contract retire "$C" --reason "version 2" --as d-root.key | contains 'creates no more instances'
d contract show "$C" | contains 'retired:    #'
expect_exit 2 contract create "$C" propose --args "$CREATE" --as d-root.key --ledger "$D"
contains 'retired' out.txt
expect_exit 2 contract retire "$C" --as d-root.key --ledger "$D"
contains 'retired already' out.txt
d contract list --active --json | json 'len(d)' | contains -x 1
# Its instances carry on.
run contract pending "${SERVER[@]}" --json | json 'len(d)' | contains -x 1

# --- Help, completion, audits ------------------------------------------------------------
for cmd in deploy show list retire create call instance instances evidence propose pending \
    consent withdraw send fetch verify; do
    run contract "$cmd" --help | contains 'Usage: cexchain contract'
done
run contract call --help | contains 'diagnostic notation'
run delegation grant --help | contains 'contract-call'
run completion bash | contains 'instances'
for fn in d s b o; do "$fn" audit | contains 'audit passed'; done
echo "contracts end-to-end: ok"
