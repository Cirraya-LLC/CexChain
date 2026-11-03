#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Proposal and consent files (.cexchain) between two ledgers that do not
# reach each other's APIs: a proposal written, shown, and consented to; the
# call recorded from the consent file alone (its arguments taken from it);
# and what is refused: a call that needs no consent or would be refused, a
# consent file given as a proposal and the other way round, a file changed
# on the way, a consent to a head the instance has left, and a proposal of
# another instance's evidence. Needs the Bo compiler (lending.bo).
# Usage: exchange.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export CEXCHAIN_PASSPHRASE="exchange test"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN CEXCHAIN_SERVER

# A command line as typed: bo, cexchain-console, and cexchain-index are the
# programs beside cexchain.
run() {
    case "$1" in
    bo | cexchain-console | cexchain-index) "$(dirname "$CEXCHAIN")/$1" "${@:2}" ;;
    *) "$CEXCHAIN" "$@" ;;
    esac
}
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

echo "== help and completion"
for command in "contract proposal" "contract file show"; do
    # shellcheck disable=SC2086
    run $command --help | contains -F "cexchain $command" || fail "help for $command"
done
run contract consent --help | contains -F -- "--proposal" || fail "consent --proposal"
run completion bash | contains -F "proposal" || fail "completion: proposal"

echo "== two ledgers, and a camera on Alice's"
for who in alice bob; do
    run key generate --out "$who-root.key" > /dev/null
    run key generate --out "$who-log.key" > /dev/null
done
run init --name Alice --root-key alice-root.key --log-key alice-log.key --ledger alice > /dev/null
run init --name Bob --root-key bob-root.key --log-key bob-log.key --ledger bob > /dev/null
ALICE_ID=$(run status --ledger alice --json | json 'd["ledger_id"]')
BOB_ID=$(run status --ledger bob --json | json 'd["ledger_id"]')
run bo build "$SOURCE/examples/lending/lending.bo" --out lending.boc > /dev/null
CONTRACT=$(run contract deploy lending.boc --as alice-root.key \
    --ledger alice --json 2> /dev/null | json 'd["contract"]["id"]')
make_camera() {
    run contract create "$CONTRACT" create \
        --args "{\"fields\": {\"name\": \"$1\"}, \"parties\": {\"owner\": h'$ALICE_ID'}}" \
        --as alice-root.key --ledger alice --json | json 'd["instance"]["id"]'
}
CAMERA=$(make_camera "Camera X100")
LEND="{\"counterparty\": h'$BOB_ID'}"

echo "== a proposal, shown, consented to, and the call recorded from the consent file"
run contract proposal "$CAMERA" lend --args "$LEND" --note "For your trip" --as alice-root.key \
    --log-key alice-log.key --out lend.cexchain --ledger alice --json > proposal.json
[ "$(json 'd["needs"]' < proposal.json)" = "['$BOB_ID']" ] || fail "the proposal names Bob"
run contract file show lend.cexchain --json > shown.json
[ "$(json '(d["kind"], d["verified"], d["organization"], d["status"])' < shown.json)" = \
  "('proposal', True, 'Alice', 'active')" ] || fail "file show: the proposal"
[ "$(json 'd["note"]' < shown.json)" = "For your trip" ] || fail "file show: the note"
run contract consent --proposal lend.cexchain --as bob-root.key --log-key bob-log.key \
    --out lend-consent.cexchain --ledger bob --json > consent.json
[ "$(json 'd["function"]' < consent.json)" = lend ] || fail "the consent's terms"
run contract file show lend-consent.cexchain --json > given.json
[ "$(json '(d["kind"], d["from"], d["organization"])' < given.json)" = "('consent', '$BOB_ID', 'Bob')" ] ||
    fail "file show: the consent"
# The consent file alone: no --args.
run contract call "$CAMERA" lend --consent lend-consent.cexchain --as alice-root.key \
    --ledger alice | contains -F "status: lent" || fail "the call from the consent file"

echo "== refused"
# A call the contract would refuse (lent already), and one that waits for no one.
expect_exit 2 contract proposal "$CAMERA" lend --args "$LEND" --as alice-root.key \
    --log-key alice-log.key --out again.cexchain --ledger alice
contains -F "would not be recorded" out.txt || fail "a refused call is no proposal"
[ ! -e again.cexchain ] || fail "no file for a refused call"
# The consent was to the head the instance has left.
expect_exit 2 contract call "$CAMERA" lend --consent lend-consent.cexchain --as alice-root.key \
    --ledger alice
# A consent file is not a proposal, nor a proposal a consent.
expect_exit 2 contract consent --proposal lend-consent.cexchain --as bob-root.key \
    --log-key bob-log.key --ledger bob
contains -F "is a consent, not a proposal" out.txt || fail "a consent as a proposal"
LENS=$(make_camera "Lens 50mm")
run contract proposal "$LENS" lend --args "$LEND" --as alice-root.key --log-key alice-log.key \
    --out lens.cexchain --ledger alice > /dev/null
expect_exit 2 contract call "$LENS" lend --consent lens.cexchain --as alice-root.key --ledger alice
contains -F "this file is a proposal" out.txt || fail "a proposal as a consent"
# Changed on the way: one byte of the note, or the head.
python3 - lens.cexchain << 'EOF'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
# The instance id (key 4): flip its last byte, so the evidence is of another instance.
start = data.find(bytes.fromhex("045820")) + 3
data[start + 31] ^= 1
open("tampered.cexchain", "wb").write(bytes(data))
EOF
expect_exit 2 contract file show tampered.cexchain
contains -F "of another instance" out.txt || fail "a proposal changed on the way"
expect_exit 2 contract consent --proposal tampered.cexchain --as bob-root.key \
    --log-key bob-log.key --ledger bob
printf 'not a file' > garbage.cexchain
expect_exit 2 contract file show garbage.cexchain
contains -F "is not a proposal or consent file" out.txt || fail "not a file"

echo "exchange: all checks passed"
