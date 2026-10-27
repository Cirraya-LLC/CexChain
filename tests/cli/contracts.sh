#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Contracts across four organizations, end to end: a core enterprise
# deploys a contract and proposes an agreement to its supplier and its bank,
# whose ledger hashes with SM3. The supplier proposes signing it to the core
# enterprise's registrar; the supplier's organization and the bank's AI agent
# consent on their own ledgers, and the registrar records the call. The
# agreement is closed with a consent carried as a file, and everyone verifies
# it offline. Refused on the way: a stale head, a consent from a ledger the
# contract did not ask for, one sent by another peer, a lapsed one, a
# withdrawn one, a retired contract, and delegations for another contract.
# Backups keep the held calls and the consents calls cite. Then parts (v0.7):
# a receivable split across organizations, a part split again, a tier-3 part
# taken by the bank, verified offline, and sold on with an SM3 consent; the
# depth limit and a retired contract refuse new parts.
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
# The ledger's rules for requests (v0.8) answer a dry run too: the contract
# accepts a call asking for work due at once, and the ledger refuses it.
ASK="[<<[1, {1: \"asked\", 2: \"asked\", 7: [{1: \"provision\", 2: null, 3: 1, 4: \"sign\"}]}]>>]"
d contract call "$I" sign --args "$ASK" --as d-root.key --dry-run \
    | contains "it would not be recorded: the ledger refuses the call: a request's deadline"
d contract call "$I" sign --args "$ASK" --as d-root.key --dry-run --json \
    | json 'd["verdict"]' | contains -x refuse
expect_exit 2 contract call "$I" sign --args "$ASK" --as d-root.key --ledger "$D"
contains "a request's deadline is after the call" out.txt
d contract instance "$I" --json | json 'd["status"]' | contains -x proposed

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
# A QR code for an instance's evidence, as for a record's.
d qr "$I" --bundle-url https://example.com/e3.cbor --verifier-url https://verify.example.com/ --json |
    json 'd["instance_id"]' | contains -x "$I"
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

# --- A deploy that says it is Bo ----------------------------------------------------------
# Its source is checked in every build (the front end reads bo-source
# bundles) and rebuilt where the build has the Bo compiler (bo.sh tests that).
printf 'not a bundle' > junk.bundle
BJ="$(d contract deploy counting.wasm --function propose=create --language bo \
    --compiler "cexchain-bo 9.9.9; codegen 1; edition 1" --source junk.bundle --as d-root.key --json \
    | json 'd["contract"]["id"]')"
d contract show "$BJ" | contains "rebuild:    MALFORMED: the deploy's source is not a bo-source bundle"
d contract show "$BJ" --json | json 'd["bo"]["status"], d["bo"]["failed"]' | contains -x "malformed True"
# No contract text for a malformed source (exit 3), nor for a contract not
# written in Bo.
expect_exit 3 contract explain "$BJ" --ledger "$D"
contains "no contract text: its source does not rebuild to its code" out.txt
contains "rebuild:  MALFORMED" out.txt
expect_exit 2 contract explain "$C" --ledger "$D"
contains "is written in wasm, not Bo" out.txt
# A bundle in the right shape whose pack digests are not the packs': another
# release's, as far as this build can tell.
python3 - << 'EOF2'
def head(major, n):
    return bytes([major << 5 | n]) if n < 24 else bytes([major << 5 | 24, n])
def text(t):
    b = t.encode()
    return head(3, len(b)) + b
packs = [text(i) + head(0, 1) + bytes([0x58, 32]) + bytes(32) for i in ("en", "zh-Hans-CN", "zh-Hant-HK")]
bundle = (head(5, 4) + head(0, 1) + head(0, 1) + head(0, 2) + head(0, 1) + head(0, 3)
          + text("contract X\n") + head(0, 4) + head(4, 3) + b"".join(head(4, 3) + p for p in packs))
open("other.bundle", "wb").write(bundle)
EOF2
BO="$(d contract deploy counting.wasm --function propose=create --language bo \
    --compiler "cexchain-bo 9.9.9; codegen 1; edition 1" --source other.bundle --as d-root.key --json \
    | json 'd["contract"]["id"]')"
d contract show "$BO" > show-bo.txt
contains "            Bo, edition 1: 11 bytes of source; packs en 1, zh-Hans-CN 1, zh-Hant-HK 1" show-bo.txt
contains "rebuild:    not rebuilt: .*the official pack en version 1 has the digest" show-bo.txt
# Not rebuilt here, so no text that could be confirmed as the code's (exit 2).
expect_exit 2 contract explain "$BO" --ledger "$D"
contains "no contract text: its source was not rebuilt to its code here" out.txt
expect_exit 2 contract explain "$BO" --ledger "$D" --json
json 'd["explained"], d["source"]["failed"]' < out.txt | contains -x "False False"
IB="$(d contract create "$BO" propose --args "$CREATE" --as d-root.key --json | json 'd["instance"]["id"]')"
d contract evidence "$IB" --log-key d-log.key --out bo.cbor > /dev/null
run contract verify bo.cbor --ledger-id "$D_ID" | contains "               not rebuilt: "
run contract verify bo.cbor --ledger-id "$D_ID" --json | json 'd["verified"], d["source"]["status"]' \
    | contains -Ex "True (other-compiler|not-rebuilt)"
expect_exit 3 contract verify bo.cbor --ledger-id "$D_ID" --require-rebuild
contains 'VERIFICATION FAILED: the contract.s source was not rebuilt to its code' out.txt
expect_exit 3 contract verify e3.cbor --ledger-id "$D_ID" --require-rebuild
contains 'not Bo: nothing rebuilds its code' out.txt

# --- Parts: instances created by a call (v0.7) --------------------------------------------
# The splitting test contract (testvectors/test-contracts.json): a receivable
# with the state [amount, tier] and the parties {holder}. issue [holder,
# amount] creates one; split [[ledger, amount], ...] ends it and makes each
# part a child [amount, tier + 1] held by its ledger; transfer LEDGER passes
# it on. Splitting and transferring need the holder's consent, unless the
# home holds it. The supplier splits a receivable between the outsider (a
# tier-2 supplier here) and itself; the outsider splits its part; the bank
# takes a tier-3 part, verifies it offline, and sells it on with a consent
# from its SM3 ledger.
python3 -c 'import json, sys; open("split.wasm", "wb").write(bytes.fromhex(json.load(open(sys.argv[1]))["split"]))' \
    "$SOURCE/testvectors/test-contracts.json"
SP="$(d contract deploy split.wasm --function issue=create --function split=call \
    --function transfer=call --compiler "test_contracts.py 1" --name "Receivable" --as d-root.key \
    --json | json 'd["contract"]["id"]')"
d delegation grant --as d-root.key --to "$REGISTRAR" --allow contract-call --contracts "${SP:0:12}" \
    > /dev/null
R="$(d contract create "$SP" issue --args "[h'$S_ID', 1000]" --reference "INV-2026-88" \
    --as d-root.key --json | json 'd["instance"]["id"]')"
d contract instance "$R" --json | json 'd["parent"], d["depth"], d["ancestors"], d["children"]' \
    | contains -x 'None 0 \[\] \[\]'

# Tier 1: the supplier proposes the split to the home's registrar and
# consents; a transfer it proposed before lapses once the split moves the
# receivable's head.
PARTS="[[h'$O_ID', 600], [h'$S_ID', 400]]"
expect_exit 2 contract propose "$R" split --peer core --args "[[h'$O_ID', 600], [h'$S_ID', 300]]" \
    --ledger "$S"
contains 'do not add up' out.txt
s contract propose "$R" transfer --peer core --args "h'$B_ID'" --json | json 'd["status"]' \
    | contains -x waiting
s contract propose "$R" split --peer core --args "$PARTS" --json > split1.json
json 'd["missing"]' < split1.json | contains "$S_ID"
s contract consent --peer core --call "$(json 'd["call"]' < split1.json)" --as s-root.key \
    --log-key s-log.key --send > split1.txt
contains 'core: recorded' split1.txt
contains 'part 1: ' split1.txt
d contract pending --json | json 'len([c for c in d if c["instance"] == "'"$R"'"])' | contains -x 0
A="$(d contract instances --parent "$R" --json | json 'd[0]["id"]')"
A2="$(d contract instances --parent "${R:0:12}" --json | json 'd[1]["id"]')"
d contract instances --parent "$R" --json | json 'len(d)' | contains -x 2
d contract instances --parent "$R" | contains "part 1 of ${R:0:12}, depth 1"
d contract instance "$R" > r.txt
contains 'status:    split (final' r.txt
contains "children:  $A part 0 of #[0-9]*: active; holder: outsider" r.txt
contains "           $A2 part 1 of #[0-9]*: active; holder: supplier" r.txt
d contract instance "$A" > a.txt
contains "parent:    $R (part 0 of its call #[0-9]*; depth 1)" a.txt
contains "ancestors: ${R:0:12} (split) > this one" a.txt
contains 'created by split on the parent by "Contract Registrar", consents: supplier' a.txt
d contract instance "$A" --json > a.json
json 'd["parent"], d["depth"], d["position"], d["state"]' < a.json \
    | contains -x "$R 1 0 \[600, 2\]"
json 'd["ancestors"] == ["'"$R"'"], d["created_by"] == d["calls"][0]["index"]' < a.json \
    | contains -x 'True True'
d contract instance "$R" --json | json '[c["id"] for c in d["children"]] == ["'"$A"'", "'"$A2"'"]' \
    | contains -x True
# A final parent takes no proposals; its parts carry on.
expect_exit 2 contract propose "$R" transfer --peer core --args "h'$B_ID'" --ledger "$S"
contains 'final' out.txt

# Tier 2: the outsider, a party of its part only, proposes splitting it.
expect_exit 2 contract propose "$R" split --peer core --args "$PARTS" --head 1 --ledger "$O"
contains 'no such instance' out.txt
o contract propose "$A" split --peer core --args "[[h'$O_ID', 250], [h'$O_ID', 350]]" \
    --json > split2.json
o contract consent --peer core --call "$(json 'd["call"]' < split2.json)" --as o-root.key \
    --log-key o-log.key --send | contains 'core: recorded'
P3="$(d contract instances --parent "$A" --json | json 'd[0]["id"]')"
d contract instance "$P3" --json | json 'd["depth"], d["state"], len(d["ancestors"])' \
    | contains -x '2 \[250, 3\] 2'
d contract instance "$P3" | contains "ancestors: ${R:0:12} (split) > ${A:0:12} (split) > this one"

# The bank takes the tier-3 part: the outsider consents as a file, which the
# home cites in its call.
HEAD3="$(d contract instance "$P3" --json | json 'd["head"]')"
o contract consent --home "$D_ID" --hash sha256 --instance "$P3" --function transfer \
    --args "h'$B_ID'" --head "$HEAD3" --as o-root.key --log-key o-log.key --out t3.cbor > /dev/null
d contract call "$P3" transfer --args "h'$B_ID'" --dry-run --consent t3.cbor --as d-root.key \
    | contains 'would accept transfer'
d contract call "$P3" transfer --args "h'$B_ID'" --consent t3.cbor --as d-root.key \
    | contains 'holder: bank'
b contract fetch --peer core --instance "$P3" --out p3.cbor | contains '(verified)'
run contract verify p3.cbor --ledger-id "$D_ID" > p3.txt
contains "Part of      ${A:0:12}: part 0 of its call #[0-9]*, depth 2" p3.txt
contains 'Ancestors    oldest first' p3.txt
contains "Instance ${R:0:12}, depth 0" p3.txt
contains "Instance ${A:0:12}, depth 1, part 0 of #" p3.txt
contains 'consent of Supplier (SHA-256)' p3.txt
contains "outcome    status split; final; part 0 ${A:0:12}: active (holder: Outsider" p3.txt
contains "part 0 ${P3:0:12}: active (holder: Outsider" p3.txt
contains "Calls        its own, after the call that created it" p3.txt
contains 'consent of Outsider (SHA-256)' p3.txt
contains "Its ancestors' calls" p3.txt
run contract verify p3.cbor --ledger-id "$D_ID" --json > p3.json
json 'd["verified"], d["instance"]["parent"] == "'"$A"'", d["instance"]["depth"]' < p3.json \
    | contains -x 'True True 2'
json '[a["id"] for a in d["instance"]["ancestors"]] == ["'"$R"'", "'"$A"'"]' < p3.json \
    | contains -x True
json '[c["function"] for c in d["calls"]]' < p3.json \
    | contains -Fx "['issue', 'split', 'split', 'transfer']"
json 'd["instance"]["ancestors"][1]["calls"] == [c["index"] for c in d["calls"][1:3]]' < p3.json \
    | contains -x True
json '[c["id"] for c in d["calls"][1]["outcome"]["children"]] == ["'"$A"'", "'"$A2"'"]' < p3.json \
    | contains -x True
# Its sibling's evidence has none of its calls; the bank sees no other part.
d contract evidence "$(d contract instances --parent "$A" --json | json 'd[1]["id"]')" \
    --log-key d-log.key --out p4.cbor > /dev/null
run contract verify p4.cbor --ledger-id "$D_ID" --json | json '[c["function"] for c in d["calls"]]' \
    | contains -Fx "['issue', 'split', 'split']"
expect_exit 2 contract fetch --peer core --instance "$A" --out none.cbor --ledger "$B"
contains 'only to its parties' out.txt

# The bank, a party of the part, sells it on with a consent from its SM3
# ledger; the supplier then holds it and verifies its whole history.
b contract propose "$P3" transfer --peer core --args "h'$S_ID'" --json > sell.json
b contract consent --peer core --call "$(json 'd["call"]' < sell.json)" --as b-root.key \
    --log-key b-log.key --send | contains 'core: recorded'
s contract fetch --peer core --instance "$P3" --out p3s.cbor > /dev/null
run contract verify p3s.cbor --ledger-id "$D_ID" > p3s.txt
contains 'consent of Bank (SM3)' p3s.txt
contains 'consent of Outsider (SHA-256)' p3s.txt
contains 'consent of Supplier (SHA-256)' p3s.txt
# Through the server, as its staff, from a verified mirror.
run contract instance "$P3" "${SERVER[@]}" --json | json 'd["depth"]' | contains -x 2
run contract evidence "$P3" "${SERVER[@]}" --out p3staff.cbor > /dev/null
run contract verify p3staff.cbor --ledger-id "$D_ID" --json | json 'len(d["calls"])' | contains -x 5

# Depth 8: the home holds a receivable and splits it one part at a time;
# the ledger refuses a ninth generation, even where the contract accepts.
X="$(d contract create "$SP" issue --args "[h'$D_ID', 256]" --as d-root.key --json \
    | json 'd["instance"]["id"]')"
for _ in 1 2 3 4 5 6 7 8; do
    X="$(d contract call "$X" split --args "[[h'$D_ID', 256]]" --as d-root.key --json \
        | json 'd["children"][0]')"
done
d contract instance "$X" --json | json 'd["depth"], len(d["ancestors"])' | contains -x '8 8'
d contract call "$X" split --args "[[h'$D_ID', 256]]" --as d-root.key --dry-run \
    | contains 'it would not be recorded: the ledger refuses the call: an instance at depth 8'
d contract call "$X" split --args "[[h'$D_ID', 256]]" --as d-root.key --dry-run --json \
    | json 'd["verdict"]' | contains -x refuse
expect_exit 2 contract call "$X" split --args "[[h'$D_ID', 256]]" --as d-root.key --ledger "$D"
contains 'depth 8 creates no children' out.txt
d contract evidence "$X" --log-key d-log.key --out x8.cbor > /dev/null
run contract verify x8.cbor --ledger-id "$D_ID" --json \
    | json 'd["instance"]["depth"], len(d["instance"]["ancestors"]), len(d["calls"])' \
    | contains -x '8 8 9'
# A retired contract makes no parts; calls that make none carry on.
d contract retire "$SP" --as d-root.key > /dev/null
d contract call "$X" split --args "[[h'$D_ID', 256]]" --as d-root.key --dry-run \
    | contains 'a retired contract creates no more instances, children included'
d contract call "$X" transfer --args "h'$S_ID'" --as d-root.key | contains 'holder: supplier'

# Backups keep every consent a part's ancestors' calls cite.
d backup create --out d2.backup --log-key d-log.key > /dev/null
run backup restore d2.backup --ledger "$WORK/restored2" > /dev/null
run contract evidence "$P3" --ledger "$WORK/restored2" --log-key d-log.key --out p3r.cbor > /dev/null
run contract verify p3r.cbor --ledger-id "$D_ID" | contains 'consent of Bank (SM3)'

# --- Help, completion, audits ------------------------------------------------------------
for cmd in deploy show list retire create call instance instances evidence propose pending \
    consent withdraw send fetch verify explain; do
    run contract "$cmd" --help | contains 'Usage: cexchain contract'
done
run contract call --help | contains 'diagnostic notation'
run delegation grant --help | contains 'contract-call'
run completion bash | contains 'instances'
run completion bash | contains -- '--parent'
run contract instance --help | contains 'its ancestors'
for fn in d s b o; do "$fn" audit | contains 'audit passed'; done
echo "contracts end-to-end: ok"
