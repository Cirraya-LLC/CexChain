#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Builds evidence with the native command-line tool, for the browser verifier
# tests. Usage: make_evidence.sh KANHE DIR
# Writes into DIR: bundle.cbor, report.pdf, ledger-id, record-id, and
# native-report.json (what `kanhe verify --json` reports); for a contract
# instance, contract.cbor, instance-id, contract-ledger-id, and
# native-contract-report.json and .txt (what `kanhe contract verify` reports);
# for a tier-3 part of a receivable (v0.7), part.cbor, part-id,
# part-parent-id, part-root-id, and native-part-report.json and .txt; and for
# an instance whose calls made requests (v0.8), requests.cbor, requests-id,
# requests-ledger-id, and native-requests-report.json and .txt; and the
# record's evidence again with a time-stamp authority's token over its
# checkpoint (v0.11), stamped.cbor, tsa-root.pem, and
# native-stamped-report.json (with that root trusted).
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
DIR="$2"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$DIR"
cd "$DIR"
rm -rf ledger ./*.key ./*.pub
export KANHE_PASSPHRASE="browser verifier test" KANHE_LEDGER="$DIR/ledger"
run() { "$KANHE" "$@"; }
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

# The same record, its checkpoint stamped by a time-stamp authority made
# with OpenSSL's command line (v0.11).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tsa-root.key \
    -out tsa-root.pem -days 3650 -subj "/CN=Test TSA Root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2> /dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tsa.key -out tsa.csr \
    -subj "/CN=Test TSA" 2> /dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n' > tsa.ext
openssl x509 -req -in tsa.csr -CA tsa-root.pem -CAkey tsa-root.key -CAcreateserial -out tsa.pem \
    -days 3650 -extfile tsa.ext 2> /dev/null
printf '[ tsa ]\ndefault_tsa = c\n[ c ]\nserial = %s/tsa.serial\nsigner_cert = %s/tsa.pem\ncerts = %s/tsa-root.pem\nsigner_key = %s/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\ness_cert_id_alg = sha256\n' \
    "$DIR" "$DIR" "$DIR" "$DIR" > tsa.cnf
echo 01 > tsa.serial
IMPRINT="$(run checkpoint show --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["timestamp_imprint"])')"
openssl ts -query -digest "$IMPRINT" -sha256 -cert -out stamp.tsq 2> /dev/null
openssl ts -reply -config tsa.cnf -queryfile stamp.tsq -token_out -out stamp.tst 2> /dev/null
run checkpoint add-timestamp stamp.tst > /dev/null
run export "$(cat record-id)" --log-key log.key --disclose result,note --with-attachments --out stamped.cbor > /dev/null
run verify stamped.cbor --ledger-id "$(cat ledger-id)" --attachment report.pdf=report.pdf \
    --tsa-root tsa-root.pem --json > native-stamped-report.json

# A claim (v0.14): a condition confirmed on another record's fields.
PAYSLIP="$(run record issue --as root.key --type example.org.payslip/1 \
    --field monthly_salary="HKD 32,000.50" --field status=staff | id_from)"
run claim issue "$PAYSLIP" --as root.key --if 'monthly_salary > HKD 30000.00' \
    --if 'status in staff,contractor' --subject "Chan Tai Man" --until 2099-01-01 | id_from > claim-id
run checkpoint create --log-key log.key > /dev/null
run export "$(cat claim-id)" --log-key log.key --out claim.cbor > /dev/null

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
    --record-types kanhe.contract-consent/1 --ledger "$DIR/bank" > /dev/null
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

# Requests and answers (v0.8), with the requesting test contract: a creation
# asks for a notice (due in an hour), a post, and a reminder (both due in a
# second). An executor device answers the notice on time; a clerk answers the
# post by hand, late, and its answer asks for another notice; the reminder is
# left open past its deadline.
for k in svc-root svc-log svc-device svc-clerk; do run key generate --out "$k.key" > /dev/null; done
SVC="$DIR/services"
run init --org "Cirraya Services" --root-key svc-root.key --log-key svc-log.key --ledger "$SVC" \
    | id_from > requests-ledger-id
python3 -c 'import json,sys; open("requesting.wasm","wb").write(bytes.fromhex(json.load(open(sys.argv[1]))["request"]))' \
    "$SOURCE/testvectors/test-contracts.json"
svc() { run "$@" --ledger "$SVC"; }
RC="$(svc contract deploy requesting.wasm --function open=create --function ask=call --function result=call \
    --compiler "test_contracts.py 1" --name "Requesting" --as svc-root.key | id_from)"
svc executor add Notifier --contract "$RC" --kinds notify --key svc-device.key --as svc-root.key > /dev/null
CLERK="$(svc actor add --as svc-root.key --kind person --name "Desk Clerk" --key svc-clerk.key | id_from)"
svc delegation grant --as svc-root.key --to "$CLERK" --allow contract-call --contracts "$RC" > /dev/null
svc contract create "$RC" open --as svc-root.key \
    --args '[["notify", {"about": "welcome"}, 3600000], ["http.post", {"n": 1}, 1000], ["notify", null, 1000]]' \
    | id_from > requests-id
request_of() { svc request list --kind "$1" --json | python3 -c "import json,sys; print(json.load(sys.stdin)[$2]['id'])"; }
sleep 1.5
svc request answer "$(request_of notify 0)" --done --args '{"ref": "N-1"}' --as svc-device.key > /dev/null
svc request answer "$(request_of http.post 0)" --done --args '[["notify", {"retry": 1}, 3600000]]' \
    --as svc-clerk.key > /dev/null
run checkpoint create --log-key svc-log.key --ledger "$SVC" > /dev/null
svc contract evidence "$(cat requests-id)" --log-key svc-log.key --out requests.cbor > /dev/null
run contract verify requests.cbor --ledger-id "$(cat requests-ledger-id)" --json > native-requests-report.json
run contract verify requests.cbor --ledger-id "$(cat requests-ledger-id)" > native-requests-report.txt

# The record handed over as a W3C credential (spec/credentials.md), issued for
# https://college.example (the tests answer that address themselves):
# credential.jwt, credential-evidence.cbor (its published address's evidence,
# with the endorsement), credential-did.json, credential-list.jwt, and
# native-credential-report.json (what `kanhe credential verify --offline` reports).
run credential key add Credentials --key-out credentials.key --as root.key > /dev/null
CREDENTIAL_TOKEN="$(run record publish "$(cat record-id)" --disclose result,note --json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
echo "$CREDENTIAL_TOKEN" > credential-token
run credential issue "$CREDENTIAL_TOKEN" --as credentials.key --url https://college.example \
    --name "Inspection certificate" --metadata product --log-key log.key --out credential.jwt > /dev/null
run checkpoint create --log-key log.key > /dev/null
run export "$(cat record-id)" --log-key log.key --disclose result,note --out credential-evidence.cbor > /dev/null
run credential did-document --url https://college.example --out credential-did.json > /dev/null
run credential status --as credentials.key --url https://college.example --out credential-list.jwt > /dev/null
run credential verify credential.jwt --offline --evidence credential-evidence.cbor \
    --did-document credential-did.json --status-list credential-list.jwt --json > native-credential-report.json
