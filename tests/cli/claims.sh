#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Claims (spec v0.14), end to end: the issuer confirms conditions on a
# record's fields, checked against its private data, without disclosing
# them; a condition that does not hold gets no claim unless asked for; the
# claim's evidence states the condition in words and says when its source
# was revoked since; claims are listed, shown, and withdrawn.
# Usage: claims.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="claims test"
export CEXCHAIN_LEDGER="$WORK/ledger"
unset CEXCHAIN_SERVER CEXCHAIN_TOKEN

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

for k in root log; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --name "Example Trading" --root-key root.key --log-key log.key --json |
    json 'd["ledger_id"]')"
PAYSLIP="$(run record issue --as root.key --type example.org.payslip/1 \
    --field monthly_salary="HKD 32,000.50" --field status=staff --field age=26 \
    --field born=2000-05-01 --field name="Chan Tai Man" --json | json 'd["record"]["id"]')"

# --- Issued when the condition holds -------------------------------------------------
C="$(run claim issue "$PAYSLIP" --as root.key --if 'monthly_salary > HKD 30000.00' \
    --if 'status in staff,contractor' --subject "Chan Tai Man" --until 2099-01-01 --json)"
CLAIM="$(echo "$C" | json 'd["claim"]')"
[ "$(echo "$C" | json 'd["text"]')" = \
    'monthly_salary is above HKD 30,000.00 and status is one of "staff", "contractor"' ] ||
    fail "the condition in words: $C"
[ "$(echo "$C" | json 'd["holds"]')" = True ] || fail "it holds"
run claim issue "$PAYSLIP" --as root.key --if 'age between 18 and 65' --if 'born < 2008-11-10' \
    --if 'name = "Chan Tai Man"' > /dev/null
[ "$(run record show "$CLAIM" --json | json 'd["state"]')" = confirmed ] || fail "confirmed"

# --- Not issued when it does not, unless asked -------------------------------------
expect_exit 2 claim issue "$PAYSLIP" --as root.key --if 'monthly_salary > HKD 40000'
contains "does not hold: no claim is issued" out.txt || fail "silence by default"
expect_exit 2 claim issue "$PAYSLIP" --as root.key --if 'email exists'
NO="$(run claim issue "$PAYSLIP" --as root.key --if 'monthly_salary > HKD 40000' --allow-no --json)"
[ "$(echo "$NO" | json 'd["holds"]')" = False ] || fail "a claim that it does not hold, on purpose"
expect_exit 1 claim issue "$PAYSLIP" --as root.key --if 'name > "A"'
expect_exit 1 claim issue "$PAYSLIP" --as root.key --if 'age between 65 and 18'
# A claim is no source; a claim's source is a record of this ledger.
expect_exit 2 claim issue "$CLAIM" --as root.key --if 'basis.status exists'
[ "$(run claim list --json | json 'len(d)')" = 3 ] || fail "three claims"
[ "$(run claim list --source "$PAYSLIP" --json | json 'd[0]["status"]')" = standing ]
run claim show "$CLAIM" | contains "holds:    monthly_salary is above HKD 30,000.00"

# --- Its evidence: the condition, not the fields; the source's status -------------
run checkpoint create --log-key log.key > /dev/null
run export "$CLAIM" --log-key log.key --out claim.cbor > /dev/null
R="$(run verify claim.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$R" | json 'd["verified"]')" = True ] || fail "the claim verifies"
[ "$(echo "$R" | json 'd["complete"]')" = True ] || fail "completely"
[ "$(echo "$R" | json 'd["record"]["claim"]["source_status"]')" = live ] || fail "a live source"
[ "$(echo "$R" | json 'd["record"]["claim"]["subject"]')" = "Chan Tai Man" ]
! echo "$R" | contains "32,000.50" || fail "the salary stays sealed"
run verify claim.cbor --ledger-id "$LEDGER_ID" | contains "Claim        holds: monthly_salary is above"
run record revoke "$PAYSLIP" --as root.key --reason "a new payslip" > /dev/null
run checkpoint create --log-key log.key > /dev/null
run export "$CLAIM" --log-key log.key --out claim2.cbor > /dev/null
R="$(run verify claim2.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$R" | json 'd["record"]["claim"]["source_status"]')" = revoked ] ||
    fail "the source revoked since"
run verify claim2.cbor --ledger-id "$LEDGER_ID" | contains "REVOKED since"
[ "$(run claim list --source "$PAYSLIP" --json | json 'd[0]["status"]')" = "source revoked" ]
# A revoked record is no source.
expect_exit 2 claim issue "$PAYSLIP" --as root.key --if 'age >= 18'

# --- Withdrawn ---------------------------------------------------------------------------
run claim revoke "$CLAIM" --as root.key --reason "issued in error" | contains "withdrew claim"
[ "$(run claim show "$CLAIM" --json | json 'd["status"]')" = withdrawn ] || fail "withdrawn"
expect_exit 2 claim revoke "$PAYSLIP" --as root.key

for command in "claim issue" "claim list" "claim show" "claim revoke"; do
    read -r -a words <<< "$command"
    run "${words[@]}" --help | contains -- '--json'
done
run completion bash | contains 'claim'
run record types --json | contains "cexchain.claim/1"
echo "claims: passed"
