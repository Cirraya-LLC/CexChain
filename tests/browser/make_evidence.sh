#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Builds evidence with the native command-line tool, for the browser verifier
# tests. Usage: make_evidence.sh CEXCHAIN DIR
# Writes into DIR: bundle.cbor, report.pdf, ledger-id, record-id, and
# native-report.json (what `cexchain verify --json` reports).
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
DIR="$2"
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
