#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# End-to-end scenario through the cexchain command-line tool:
# an organization delegates to an inspector, who runs an AI drafting agent;
# the agent issues a quality certificate, the inspector endorses it, and a
# third party verifies the exported evidence offline.
set -euo pipefail

CEXCHAIN="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

run() { "$CEXCHAIN" "$@"; }
expect_failure() {
    if "$CEXCHAIN" "$@" > out.txt 2>&1; then
        echo "expected failure: $*"; cat out.txt; exit 1
    fi
}
id_from() { grep -oE '[0-9a-f]{64}' | head -1; }

for k in root log alice agent bob; do run key generate --out "$k.key" > /dev/null; done
run key generate --alg sm2-sm3 --out sm2.key > /dev/null
run key show sm2.key | grep -q 'SM2-SM3'

run init --ledger ledger --org "Cirraya Test Factory" --root-key root.key --log-key log.key > init.txt
LEDGER_ID="$(id_from < init.txt)"

ALICE="$(run actor add --ledger ledger --as root.key --kind person --name "Alice Inspector" --key alice.key | id_from)"
run delegate --ledger ledger --as root.key --to "${ALICE:0:10}" \
    --allow actor-register,delegation-grant,record-register,record-endorse,record-transition \
    --record-types cexchain.certificate/1 --days 30 --may-delegate > /dev/null
AGENT="$(run actor add --ledger ledger --as alice.key --kind agent --name "Drafting Agent" --key agent.key \
    --responsible "$ALICE" --model claude-opus-5-5 --model-version 2026-09 | id_from)"
run delegate --ledger ledger --as alice.key --to "$AGENT" --allow record-register \
    --record-types cexchain.certificate/1 --days 7 > /dev/null
BOB="$(run actor add --ledger ledger --as root.key --kind person --name "Bob Receiver" --key bob.key | id_from)"
run actor list --ledger ledger | grep -q 'claude-opus-5-5'

printf '%%PDF-1.7 inspection report' > report.pdf
RECORD="$(run issue --ledger ledger --as agent.key --type cexchain.certificate/1 \
    --field product="Flange DN50" --field batch=B-2026-1006 --field result=pass \
    --attach report.pdf --meta product="Flange DN50" | id_from)"

# Out of scope: the agent may not endorse, and Bob has no delegation at all.
expect_failure endorse --ledger ledger --as agent.key --record "$RECORD" --role inspector
expect_failure endorse --ledger ledger --as bob.key --record "$RECORD" --role inspector
grep -q 'no valid delegation' out.txt

run endorse --ledger ledger --as alice.key --record "$RECORD" --role inspector > /dev/null
run transition --ledger ledger --as alice.key --record "$RECORD" --to suspended > /dev/null
run record show --ledger ledger --record "$RECORD" | grep -q 'state:   suspended'
expect_failure transition --ledger ledger --as alice.key --record "$RECORD" --to delivered
run transition --ledger ledger --as alice.key --record "$RECORD" --to issued > /dev/null

# Evidence needs a checkpoint covering the record.
expect_failure export --ledger ledger --log-key log.key --record "$RECORD" --out bundle.cbor
run checkpoint --ledger ledger --log-key log.key > /dev/null
run export --ledger ledger --log-key log.key --record "$RECORD" --disclose result \
    --with-attachments --out bundle.cbor > /dev/null
run status --ledger ledger | grep -q 'checkpoint:    size'

# Offline verification by a third party.
run verify bundle.cbor --ledger-id "$LEDGER_ID" --attachment report.pdf=report.pdf > report.txt
grep -q 'Cirraya Test Factory' report.txt
grep -q 'result = pass' report.txt
grep -q 'AI agent: claude-opus-5-5; responsible: Alice Inspector' report.txt
grep -q 'authorized by Alice Inspector <- Cirraya Test Factory' report.txt
grep -q 'endorsed as inspector' report.txt
grep -q 'report.pdf (application/pdf, 26 bytes): matches' report.txt
grep -q 'State        issued' report.txt

# A tampered attachment, a wrong ledger, and a corrupted bundle are caught.
printf 'forged' > forged.pdf
expect_failure verify bundle.cbor --attachment report.pdf=forged.pdf
expect_failure verify bundle.cbor --ledger-id "$ALICE"
python3 - <<'PY' 2>/dev/null || perl -e 'open F,"+<","bundle.cbor"; binmode F; seek F,300,0; read F,$b,1; seek F,300,0; print F chr(ord($b)^1); close F'
data = bytearray(open("bundle.cbor", "rb").read()); data[300] ^= 1; open("bundle.cbor", "wb").write(data)
PY
expect_failure verify bundle.cbor

# The ledger survives reopening (replay re-validates everything).
run status --ledger ledger | grep -q 'records:       1'
echo "cli end-to-end: ok"
