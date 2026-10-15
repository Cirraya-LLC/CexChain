#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Builds evidence with the native command-line tool, for the browser verifier
# tests. Usage: make_evidence.sh CEXCHAIN DIR
# Writes into DIR: bundle.cbor, report.pdf, ledger-id, record-id, and
# native-report.json (what `cexchain verify --json` reports); for a contract
# instance, contract.cbor, instance-id, contract-ledger-id, and
# native-contract-report.json and .txt (what `cexchain contract verify` reports);
# and for a tier-3 part of a receivable (v0.7), part.cbor, part-id,
# part-parent-id, part-root-id, and native-part-report.json and .txt.
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
run record issue --as agent.key --type example.document/1 --field product="Flange DN50" \
    --field result=pass --field "note=中文 ✓ <script>alert(1)</script>" --attach report.pdf \
    --meta product="Flange DN50" --inputs "inspection sheet #7" | id_from > record-id
run record endorse "$(cat record-id)" --as alice.key --role inspector > /dev/null
run checkpoint create --log-key log.key > /dev/null
run export "$(cat record-id)" --log-key log.key --disclose result,note --with-attachments --out bundle.cbor > /dev/null
run verify bundle.cbor --ledger-id "$(cat ledger-id)" --attachment report.pdf=report.pdf --json > native-report.json

# Three organizations, each with its own ledger.
for k in core-root core-log sup-root sup-log bank-root bank-log; do run key generate --out "$k.key" > /dev/null; done
run init --org "Cirraya Core Enterprise" --root-key core-root.key --log-key core-log.key --ledger "$DIR/core" \
    | id_from > contract-ledger-id
SUPPLIER="$(run init --org "Cirraya Supplier" --root-key sup-root.key --log-key sup-log.key --ledger "$DIR/supplier" | id_from)"
BANK="$(run init --org "Cirraya Bank" --root-key bank-root.key --log-key bank-log.key --ledger "$DIR/bank" | id_from)"

# A contract instance on the core enterprise's ledger: an agreement it
# proposes to the supplier and the bank, then signs with both consents, the
# bank's given by its AI agent; the consents travel as files.
python3 -c 'import json,sys; open("counting.wasm","wb").write(bytes.fromhex(json.load(open(sys.argv[1]))["counting"]))' \
    "$SOURCE/testvectors/test-contracts.json"
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

# A tier-3 part of a receivable (v0.7), with the splitting test contract: the
# core enterprise issues a receivable to the supplier, which consents to
# splitting it between itself and the bank, then to splitting its own part;
# the bank, holding a tier-3 part, consents to passing it to the core
# enterprise. The consents travel as files.
python3 -c 'import json,sys; open("split.wasm","wb").write(bytes.fromhex(json.load(open(sys.argv[1]))["split"]))' \
    "$SOURCE/testvectors/test-contracts.json"
CORE="$(cat contract-ledger-id)"
SPLIT="$(core contract deploy split.wasm --function issue=create --function split=call --function transfer=call \
    --compiler "test_contracts.py 1" --name "Receivable" --as core-root.key | id_from)"
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
RECEIVABLE="$(core contract create "$SPLIT" issue --args "[h'$SUPPLIER', 1000]" --as core-root.key --json | field '["instance"]["id"]')"
split_with_consent() { # INSTANCE ARGS AS LOG LEDGER: prints the first part's id
    local head
    head="$(core contract instance "$1" --json | field '["head"]')"
    run contract consent --home "$CORE" --hash sha256 --instance "$1" --function "${6:-split}" --args "$2" \
        --head "$head" --as "$3" --log-key "$4" --ledger "$5" --out step.cbor > /dev/null
    core contract call "$1" "${6:-split}" --args "$2" --consent step.cbor --as core-root.key --json \
        | python3 -c 'import json,sys; c=json.load(sys.stdin)["children"]; print(c[0] if c else "")'
}
TIER2="$(split_with_consent "$RECEIVABLE" "[[h'$SUPPLIER', 600], [h'$BANK', 400]]" sup-root.key sup-log.key "$DIR/supplier")"
split_with_consent "$TIER2" "[[h'$BANK', 250], [h'$SUPPLIER', 350]]" sup-root.key sup-log.key "$DIR/supplier" > part-id
split_with_consent "$(cat part-id)" "h'$CORE'" bank-root.key bank-log.key "$DIR/bank" transfer > /dev/null
echo "$TIER2" > part-parent-id
echo "$RECEIVABLE" > part-root-id
core contract evidence "$(cat part-id)" --log-key core-log.key --out part.cbor > /dev/null
run contract verify part.cbor --ledger-id "$CORE" --json > native-part-report.json
run contract verify part.cbor --ledger-id "$CORE" > native-part-report.txt
