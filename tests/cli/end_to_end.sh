#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# End-to-end scenario through every cexchain command: an organization
# delegates to an inspector, who runs an AI drafting agent; the agent issues a
# quality certificate, the inspector endorses it, keys rotate, rights are
# revoked, and a third party verifies the exported evidence offline.
set -euo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="correct horse battery staple"
unset CEXCHAIN_LEDGER

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
# expect_exit CODE COMMAND...: the command must exit with CODE.
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
# Readers in pipelines consume all input: with pipefail, a reader that exits
# early (grep -q, head) can kill the writer with SIGPIPE and fail the test.
contains() { grep "$@" > /dev/null; }
id_from() { grep -oE '[0-9a-f]{64}' | sed -n 1p; }
# json EXPR: evaluates a Python expression over the JSON on stdin (as d).
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
mode_of() { ls -l "$1" | cut -c1-10; }

# --- General -----------------------------------------------------------------
run version | contains 'SM2-SM3'
run version --json | json 'd["protocol_version"]' | contains -x 1
run --help | contains 'record issue'
run help record | contains 'record transition'
run record show --help | contains 'Usage: cexchain record show RECORD'
run help --json | json 'len(d) > 40' | contains -x True
run completion bash > completion.bash && bash -n completion.bash
contains 'rotate-key' completion.bash
run completion zsh | contains bashcompinit
expect_exit 1 frobnicate
expect_exit 1 issue
contains "did you mean 'cexchain record issue'" out.txt
expect_exit 1 record
expect_exit 1 status --no-such-option
expect_exit 1 record show
expect_exit 1 actor add --kind person

# --- Keys --------------------------------------------------------------------
for k in root log alice agent bob; do run key generate --out "$k.key" > /dev/null; done
[ "$(mode_of root.key)" = "-rw-------" ] || fail "private keys must be owner-only"
run key show root.key | contains 'private key (encrypted)'
run key generate --alg sm2-sm3 --out sm2.key --json | json 'd["public_key"]["algorithm"]' | contains -x SM2-SM3
run key generate --alg ml-dsa-65 --no-passphrase --out pq.key | contains 'NOT encrypted'
run key show pq.key --json | json 'd["encrypted"]' | contains -x False
expect_exit 2 key generate --out root.key
contains 'never overwritten' out.txt

CEXCHAIN_PASSPHRASE=wrong expect_exit 2 key show root.key
contains 'wrong passphrase' out.txt
printf 'another secret\n' > new.pass
run key passphrase bob.key --new-passphrase-file new.pass > /dev/null
expect_exit 2 key show bob.key
run key show bob.key --passphrase-file new.pass > /dev/null
run key passphrase bob.key --passphrase-file new.pass --remove | contains 'WITHOUT encryption'
CEXCHAIN_NEW_PASSPHRASE="$CEXCHAIN_PASSPHRASE" run key passphrase bob.key > /dev/null
run key show bob.key | contains 'private key (encrypted)'

run key public alice.key --out alice.pub > /dev/null
run key show alice.pub | contains 'public key'
run inspect alice.pub --json | json 'd["kind"]' | contains -x public-key

# --- Ledger ------------------------------------------------------------------
LEDGER_ID="$(run init --ledger ledger --org "Cirraya Test Factory" --root-key root.key --log-key log.key | id_from)"
expect_exit 2 init --ledger ledger --org Again --root-key root.key --log-key log.key
expect_exit 1 status
export CEXCHAIN_LEDGER="$WORK/ledger"
run status --json | json 'd["ledger_id"]' | contains -x "$LEDGER_ID"
run status | contains 'checkpoint:    none yet'
expect_exit 2 actor add --as alice.pub --kind person --name X --key alice.pub
contains 'is a public key' out.txt

# --- Actors and delegations ----------------------------------------------------
# Alice is registered from her public key: the administrator never sees her private key.
ALICE="$(run actor add --as root.key --kind person --name "Alice Inspector" --key alice.pub | id_from)"
GRANT="$(run delegation grant --as root.key --to "${ALICE:0:10}" \
    --allow actor-register,actor-rotate-key,delegation-grant,delegation-revoke,record-register,record-endorse,record-transition \
    --record-types cexchain.certificate/1 --days 30 --may-delegate | id_from)"
expect_exit 1 actor add --as alice.key --kind agent --name "Drafting Agent" --key agent.key --model m
contains 'responsible' out.txt
AGENT="$(run actor add --as alice.key --kind agent --name "Drafting Agent" --key agent.key \
    --responsible "$ALICE" --model claude-opus-5-5 --model-version 2026-09 --runtime "ci-runner" | id_from)"
AGENT_GRANT="$(run delegation grant --as alice.key --to "$AGENT" --allow record-register \
    --record-types cexchain.certificate/1 --days 7 --json | json 'd["delegation"]["id"]')"
BOB="$(run actor add --as root.key --kind person --name "Bob Receiver" --key bob.key | id_from)"

run actor list | contains 'claude-opus-5-5'
run actor list --kind agent --json | json 'len(d)' | contains -x 1
run actor show "$AGENT" > actor.txt
contains 'responsible:   Alice Inspector' actor.txt
contains 'runtime:       ci-runner' actor.txt
run actor show "$ALICE" --json | json 'len(d["delegations_granted"])' | contains -x 1
run delegation list | contains 'Alice Inspector -> Drafting Agent'
run delegation list --actor "$BOB" --json | json 'len(d)' | contains -x 0
run delegation show "$AGENT_GRANT" | contains 'authority:     Alice Inspector <- Cirraya Test Factory'
run delegation show "$GRANT" --json | json 'd["scope"]["may_delegate"]' | contains -x True

# --- Records -------------------------------------------------------------------
run record types | contains 'issued -> suspended'
run record types --json | json '[t["name"] for t in d]' | contains 'cexchain.delivery/1'
printf '%%PDF-1.7 inspection report' > report.pdf
RECORD="$(run record issue --as agent.key --type cexchain.certificate/1 \
    --field product="Flange DN50" --field batch=B-2026-1006 --field result=pass \
    --attach report.pdf --meta product="Flange DN50" --inputs "inspection sheet #7" | id_from)"
run record list | contains 'cexchain.certificate/1'
run record show "${RECORD:0:8}" > record.txt
contains 'state:      issued' record.txt
contains 'metadata:   product = Flange DN50' record.txt
contains 'attachment: report.pdf (application/pdf, 26 bytes)' record.txt
run record show "$RECORD" --json | json 'd["next_states"]' | contains suspended
run record fields "$RECORD" | contains -x 'result = pass'
run record fields "$RECORD" --json | json 'd["fields"]["batch"]' | contains -x B-2026-1006

# Out of scope: the agent may not endorse, Bob has no delegation, and a
# delivery is outside the agent's record types.
expect_exit 2 record endorse "$RECORD" --as agent.key --role inspector
expect_exit 2 record endorse "$RECORD" --as bob.key --role inspector
contains 'no valid delegation' out.txt
expect_exit 2 record issue --as agent.key --type cexchain.delivery/1 --field item=flanges

run record endorse "$RECORD" --as alice.key --role inspector > /dev/null
run record transition "$RECORD" --as alice.key --to suspended > /dev/null
run record show "$RECORD" | contains 'state:      suspended'
expect_exit 2 record transition "$RECORD" --as alice.key --to delivered
run record transition "$RECORD" --as alice.key --to issued --json | json 'd["to"]' | contains -x issued
run record history "$RECORD" > history.txt
contains 'AI provenance: model claude-opus-5-5 2026-09, via cli:cexchain, inputs committed' history.txt
contains 'responsible: Alice Inspector' history.txt
contains 'authorized by Alice Inspector <- Cirraya Test Factory' history.txt
run record history "$RECORD" --json | json 'len(d)' | contains -x 4

# --- Vault ---------------------------------------------------------------------
# Private field values are sealed to the vault key: nothing readable on disk.
[ -f ledger/vault.key ] && [ -f ledger/vault.pub ] || fail "init creates the vault key"
if contains -r 'B-2026-1006' ledger; then fail "field values must not be stored in the clear"; fi
run inspect "ledger/vault/$RECORD.cbor" --json | json 'd["kind"]' | contains -x sealed-vault
run inspect ledger/vault.pub --json | json 'd["kind"]' | contains -x vault-public-key
run vault status --json | json 'd["sealed_records"]' | contains -x 1
CEXCHAIN_PASSPHRASE=wrong expect_exit 2 record fields "$RECORD"
contains 'wrong passphrase' out.txt

# Move the vault key off the host, then back to a new key on the host.
run vault keygen --out offhost.key > /dev/null
[ -f offhost.key.pub ] || fail "vault keygen writes the public half"
expect_exit 2 vault keygen --out offhost.key
run vault rekey --new-public-key offhost.key.pub | contains 're-sealed 1 records'
[ -f ledger/vault.key.old ] && [ ! -f ledger/vault.key ] || fail "rekey keeps the previous key aside"
expect_exit 2 record fields "$RECORD"
contains 'no vault key' out.txt
expect_exit 2 record fields "$RECORD" --vault-key ledger/vault.key.old
contains "not this ledger's vault key" out.txt
run record fields "$RECORD" --vault-key offhost.key | contains -x 'result = pass'
CEXCHAIN_NEW_PASSPHRASE="$CEXCHAIN_PASSPHRASE" run vault rekey --vault-key offhost.key --json \
    | json 'd["records"]' | contains -x 1
run record fields "$RECORD" | contains -x 'batch = B-2026-1006'
run vault status | contains 'sealed:        1 records'

# A ledger whose vault private key never touches the ledger host.
run init --ledger ledger2 --org "Second Site" --root-key root.key --log-key log.key \
    --vault-public-key offhost.key.pub | contains 'kept elsewhere'
[ ! -f ledger2/vault.key ] || fail "an external vault key is not copied to the host"

# --- Checkpoints, proofs, receipts, and the log --------------------------------------
expect_exit 2 export "$RECORD" --log-key log.key --out bundle.cbor
run checkpoint create --log-key log.key > /dev/null
SIZE="$(run status --json | json 'd["entries"]')"
run checkpoint list | contains "size $SIZE"
run checkpoint show --out checkpoint.cbor | contains "size:       $SIZE"
run inspect checkpoint.cbor --json | json 'd["checkpoint"]["tree_size"]' | contains -x "$SIZE"
run proof inclusion 3 --json | json 'd["tree_size"]' | contains -x "$SIZE"
run proof inclusion "${RECORD:0:12}" --size 7 | contains 'tree size:  7'
run proof consistency 2 "$SIZE" --json | json 'len(d["path"]) > 0' | contains -x True
run receipt "$RECORD" --log-key log.key --out receipt.cbor > /dev/null
run inspect receipt.cbor --json | json 'd["kind"]' | contains -x receipt
run log list | contains 'genesis of "Cirraya Test Factory"'
run log list --type record-endorse --json | json 'len(d)' | contains -x 1
run log show "${RECORD:0:10}" --raw > entry.txt
contains 'provenance:    model claude-opus-5-5' entry.txt
contains 'raw COSE_Sign1' entry.txt
run log export --out log.cbor --from 1 > /dev/null
run inspect log.cbor --json | json 'len(d["entries"])' | contains -x "$((SIZE - 1))"

# --- Evidence ----------------------------------------------------------------------
run export "$RECORD" --log-key log.key --disclose result --with-attachments --out bundle.cbor > /dev/null
run inspect bundle.cbor | contains 'evidence-bundle'
run key public alice.key --out witness.pub > /dev/null
run verify bundle.cbor --ledger-id "$LEDGER_ID" --attachment report.pdf=report.pdf > report.txt
contains 'Cirraya Test Factory' report.txt
contains 'result = pass' report.txt
contains 'AI agent: claude-opus-5-5; responsible: Alice Inspector; via cli:cexchain' report.txt
contains 'authorized by Alice Inspector <- Cirraya Test Factory' report.txt
contains 'endorsed as inspector' report.txt
contains 'report.pdf (application/pdf, 26 bytes): matches' report.txt
contains 'State        issued' report.txt
run verify bundle.cbor --ledger-id "$LEDGER_ID" --witness witness.pub --json > report.json
json 'd["verified"] and d["disclosed_fields"]["result"] == "pass"' < report.json | contains -x True
json 'd["events"][0]["actor"]["model"]' < report.json | contains -x claude-opus-5-5
expect_exit 2 verify bundle.cbor --witness alice.key
contains 'is a private key' out.txt

# A tampered attachment, a wrong ledger, and a corrupted bundle are caught.
printf 'forged' > forged.pdf
expect_exit 3 verify bundle.cbor --attachment report.pdf=forged.pdf
expect_exit 3 verify bundle.cbor --ledger-id "$ALICE"
cp bundle.cbor corrupted.cbor
python3 -c 'import sys; p="corrupted.cbor"; d=bytearray(open(p,"rb").read()); d[300]^=1; open(p,"wb").write(d)'
expect_exit 3 verify corrupted.cbor
[ "$("$CEXCHAIN" verify corrupted.cbor --json | json 'd["verified"]' || true)" = "False" ] || fail "json failure report"

# --- Key rotation and revocation -------------------------------------------------------
run key generate --out alice2.key > /dev/null
run actor rotate-key "$ALICE" --as alice.key --new-key alice2.key > /dev/null
expect_exit 2 record endorse "$RECORD" --as alice.key --role approver
contains 'does not belong to any actor' out.txt
run actor show "$ALICE" | contains 'key rotations: #'

run delegation revoke "$AGENT_GRANT" --as alice2.key --reason "pilot over" > /dev/null
expect_exit 2 record issue --as agent.key --type cexchain.certificate/1 --field result=pass
run delegation list --all | contains '\[revoked\]'

run actor revoke "$BOB" --as root.key --reason "left the company" > /dev/null
if run actor list | contains 'Bob Receiver'; then fail "revoked actors are hidden by default"; fi
run actor list --all | contains 'Bob Receiver  \[revoked\]'

run record revoke "$RECORD" --as root.key --reason "superseded" > /dev/null
[ "$(run record list --json | json 'len(d)')" = "0" ] || fail "revoked records are hidden by default"
run record list --all | contains '\[revoked\]'
run record show "$RECORD" | contains 'REVOKED'

# --- Audit -----------------------------------------------------------------------------
run checkpoint create --log-key log.key --json | json 'd["tree_size"]' > /dev/null
run audit | contains 'audit passed'
run audit --json | json 'd["ok"] and d["checkpoints"] == 2' | contains -x True

# A ledger altered on disk refuses to open.
cp -R ledger altered
python3 -c 'import sys; p="altered/statements"; d=bytearray(open(p,"rb").read()); d[len(d)//2]^=1; open(p,"wb").write(d)'
expect_exit 2 status --ledger altered

echo "cli end-to-end: ok"
