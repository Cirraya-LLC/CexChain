#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Builds evidence with the native command-line tool, for the browser verifier
# tests. Usage: make_evidence.sh CEXCHAIN DIR
# Writes into DIR: bundle.cbor, report.pdf, ledger-id, record-id, and
# native-report.json (what `cexchain verify --json` reports); for an asset,
# asset.cbor, asset-id, asset-ledger-id, and native-asset-report.json; and for
# a contract instance, contract.cbor, instance-id, contract-ledger-id, and
# native-contract-report.json and .txt (what `cexchain contract verify` reports).
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
DIR="$2"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$DIR"
cd "$DIR"
rm -rf ledger ./*.key ./*.pub
export CEXCHAIN_PASSPHRASE="browser verifier test" CEXCHAIN_LEDGER="$DIR/ledger"
run() { "$CEXCHAIN" "$@"; }
id_from() { grep -oE '[0-9a-f]{64}' | sed -n 1p; }

for k in root log alice agent witness; do run key generate --out "$k.key" > /dev/null; done
run key public witness.key --out witness.pub > /dev/null
run init --org "Cirraya Test Factory" --root-key root.key --log-key log.key | id_from > ledger-id
ALICE="$(run actor add --as root.key --kind person --name "Alice Inspector" --key alice.key | id_from)"
run delegation grant --as root.key --to "$ALICE" --allow actor-register,delegation-grant,record-register,record-endorse \
    --days 30 --may-delegate > /dev/null
AGENT="$(run actor add --as alice.key --kind agent --name "Drafting Agent" --key agent.key \
    --responsible "$ALICE" --model claude-opus-5-5 --model-version 2026-09 | id_from)"
run delegation grant --as alice.key --to "$AGENT" --allow record-register --days 7 > /dev/null
printf '%%PDF-1.7 inspection report' > report.pdf
run record issue --as agent.key --type cexchain.certificate/1 --field product="Flange DN50" \
    --field result=pass --field "note=中文 ✓ <script>alert(1)</script>" --attach report.pdf \
    --meta product="Flange DN50" --inputs "inspection sheet #7" | id_from > record-id
run record endorse "$(cat record-id)" --as alice.key --role inspector > /dev/null
run checkpoint create --log-key log.key > /dev/null
run export "$(cat record-id)" --log-key log.key --disclose result,note --with-attachments --out bundle.cbor > /dev/null
run verify bundle.cbor --ledger-id "$(cat ledger-id)" --attachment report.pdf=report.pdf --json > native-report.json

# An asset: a core enterprise's receivable that its supplier pledges to a
# bank, each consenting on its own ledger; the consents travel as files.
for k in core-root core-log sup-root sup-log bank-root bank-log; do run key generate --out "$k.key" > /dev/null; done
run init --org "Cirraya Core Enterprise" --root-key core-root.key --log-key core-log.key --ledger "$DIR/core" \
    | id_from > asset-ledger-id
SUPPLIER="$(run init --org "Cirraya Supplier" --root-key sup-root.key --log-key sup-log.key --ledger "$DIR/supplier" | id_from)"
BANK="$(run init --org "Cirraya Bank" --root-key bank-root.key --log-key bank-log.key --ledger "$DIR/bank" | id_from)"
run asset issue receivable --holder "$SUPPLIER" --amount 125000.00 --currency CNY --due 2027-01-06 \
    --field contract=PO-2026-0815 --field invoice=INV-77 --as core-root.key --ledger "$DIR/core" | id_from > asset-id
HEAD="$(run asset show "$(cat asset-id)" --ledger "$DIR/core" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["head"])')"
consent() { # ROOT LOG LEDGER OUT
    run asset consent --home "$(cat asset-ledger-id)" --asset "$(cat asset-id)" --action pledge --to "$BANK" \
        --head "$HEAD" --as "$1" --log-key "$2" --ledger "$3" --out "$4" > /dev/null
}
consent sup-root.key sup-log.key "$DIR/supplier" consent-supplier.cbor
consent bank-root.key bank-log.key "$DIR/bank" consent-bank.cbor
run asset record pledge "$(cat asset-id)" --to "$BANK" --consent consent-supplier.cbor --consent consent-bank.cbor \
    --as core-root.key --ledger "$DIR/core" > /dev/null
run checkpoint create --log-key core-log.key --ledger "$DIR/core" > /dev/null
run asset evidence "$(cat asset-id)" --log-key core-log.key --fields '*' --out asset.cbor --ledger "$DIR/core" > /dev/null
run asset verify asset.cbor --ledger-id "$(cat asset-ledger-id)" --json > native-asset-report.json

# A contract instance on the core enterprise's ledger: an agreement it
# proposes to the supplier and the bank, then signs with both consents, the
# bank's given by its AI agent; the consents travel as files.
python3 -c 'import json,sys; open("counting.wasm","wb").write(bytes.fromhex(json.load(open(sys.argv[1]))["counting"]))' \
    "$SOURCE/testvectors/test-contracts.json"
cp asset-ledger-id contract-ledger-id
core() { run "$@" --ledger "$DIR/core"; }
CONTRACT="$(core contract deploy counting.wasm --function propose=create --function sign=call \
    --function close=call --compiler "test_contracts.py 1" --name "Supply agreement" --as core-root.key | id_from)"
# The counting contract answers a call citing n consents with item n of its
# arguments (the last one for more): the CBOR, in a byte string, of its output.
CREATE="[<<[1, {1: \"proposed\", 2: \"proposed\", 3: {\"supplier\": h'$SUPPLIER', \"bank\": h'$BANK'}}]>>]"
core contract create "$CONTRACT" propose --args "$CREATE" --reference PO-2026-1012 --as core-root.key \
    | id_from > instance-id
INSTANCE="$(cat instance-id)"
LO="$(printf '%s\n' "$SUPPLIER" "$BANK" | LC_ALL=C sort | sed -n 1p)"
HI="$(printf '%s\n' "$SUPPLIER" "$BANK" | LC_ALL=C sort | sed -n 2p)"
NEEDS="<<[2, [h'$LO', h'$HI']]>>"
SIGN="[$NEEDS, $NEEDS, <<[1, {1: \"signed\", 2: \"effective\", 4: [[\"signed\", {\"amount\": 125000}]]}]>>]"
run key generate --out manager.key > /dev/null
MANAGER="$(core actor add --as core-root.key --kind person --name "Procurement Manager" --key manager.key | id_from)"
core delegation grant --as core-root.key --to "$MANAGER" --allow contract-call --contracts "$CONTRACT" > /dev/null
for k in bank-officer bank-agent; do run key generate --out "$k.key" > /dev/null; done
OFFICER="$(run actor add --as bank-root.key --kind person --name "Credit Officer" --key bank-officer.key \
    --ledger "$DIR/bank" | id_from)"
AGENT="$(run actor add --as bank-root.key --kind agent --name "Credit Agent" --key bank-agent.key \
    --responsible "$OFFICER" --model credit-model-7 --ledger "$DIR/bank" | id_from)"
run delegation grant --as bank-root.key --to "$AGENT" --allow record-register \
    --record-types cexchain.contract-consent/1 --ledger "$DIR/bank" > /dev/null
HEAD="$(core contract instance "$INSTANCE" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["head"])')"
consent() { # AS LOG LEDGER OUT ARGS...
    local as="$1" log="$2" ledger="$3" out="$4"; shift 4
    run contract consent --home "$(cat contract-ledger-id)" --hash sha256 --instance "$INSTANCE" \
        --function sign --args "$SIGN" --head "$HEAD" --as "$as" --log-key "$log" --ledger "$ledger" \
        --out "$out" "$@" > /dev/null
}
consent sup-root.key sup-log.key "$DIR/supplier" sign-supplier.cbor
consent bank-agent.key bank-log.key "$DIR/bank" sign-bank.cbor --reference "Credit approval CA-9"
core contract call "$INSTANCE" sign --args "$SIGN" --consent sign-supplier.cbor --consent sign-bank.cbor \
    --reference INV-77 --as manager.key > /dev/null
run checkpoint create --log-key core-log.key --ledger "$DIR/core" > /dev/null
core contract evidence "$INSTANCE" --log-key core-log.key --out contract.cbor > /dev/null
run contract verify contract.cbor --ledger-id "$(cat contract-ledger-id)" --json > native-contract-report.json
run contract verify contract.cbor --ledger-id "$(cat contract-ledger-id)" > native-contract-report.txt
