#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A concert ticket in the words of a vocabulary pack of the organizer's own,
# narrated step by step. Bo's core has no word for a ticket's guest or for
# checking in; the organizer writes them once, in three languages, with the
# standard terms of their actions, as a pack file (events.vocab, next to this
# script), and any contract that writes `use events` reads them.
#   - the organizer checks the pack and the contract (tickets.bo), runs its
#     tests, and deploys it: the deploy embeds the whole pack in the
#     contract's source bundle;
#   - the organizer reserves a ticket for a fan, who agrees on their own
#     ledger after checking the ticket's history offline: the contract's code
#     rebuilt from its source and the pack the bundle carries, with no pack
#     file at hand;
#   - the fan checks in at the door; anyone verifies the whole history
#     offline.
# It needs a cexchain built with the Bo compiler (GCC 16; the release build
# and the Docker image have it).
#
# Usage: events.sh [CEXCHAIN] [DIR]
#   CEXCHAIN  the command-line tool (default: cexchain on the PATH)
#   DIR       where to keep the ledgers (default: a temporary directory,
#             removed at the end; give one to look around afterwards)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="${1:-cexchain}"
case "$CEXCHAIN" in */*) CEXCHAIN="$(cd "$(dirname "$CEXCHAIN")" && pwd)/$(basename "$CEXCHAIN")" ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${2:-}" ]; then
    WORK="$2"; KEEP=1; mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"; KEEP=0
fi
WORK="$(cd "$WORK" && pwd)"
cleanup() {
    [ "$KEEP" = 0 ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cd "$WORK"
export CEXCHAIN_PASSPHRASE="demo only: use real passphrases or hardware keys"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN CEXCHAIN_LANGUAGE

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
say() { printf '   %s\n' "$*"; }
run() { "$CEXCHAIN" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
indent() { sed 's/^/   /'; }
check() {
    if ! grep -F -- "$2" "$1" > /dev/null; then
        echo "expected \"$2\" in $1:" >&2
        cat "$1" >&2
        exit 1
    fi
}

ORG="$WORK/organizer"; FAN="$WORK/fan"

step "1. The organizer and a fan, each with a ledger of their own"
for who in org fan; do
    run key generate --out "$who-root.key" > /dev/null
    run key generate --out "$who-log.key" > /dev/null
done
run init --name "City Concerts" --root-key org-root.key --log-key org-log.key --ledger "$ORG" > /dev/null
run init --name "Fan" --root-key fan-root.key --log-key fan-log.key --ledger "$FAN" > /dev/null
id_of() { run status --ledger "$1" --json | field '["ledger_id"]'; }
ORG_ID="$(id_of "$ORG")"; FAN_ID="$(id_of "$FAN")"
say "Organizer  ledger ${ORG_ID:0:16}..."
say "Fan        ledger ${FAN_ID:0:16}..."
run peer add fan --ledger-id "$FAN_ID" --ledger "$ORG" > /dev/null
run peer add organizer --ledger-id "$ORG_ID" --ledger "$FAN" > /dev/null

step "2. The organizer's own words: a vocabulary pack"
if [ "$(run version --json | field '["bo"] is not None')" != True ]; then
    echo "This example needs a cexchain built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
cp "$HERE/events.vocab" "$HERE/tickets.bo" .
run bo vocab check events.vocab > vocab.txt
check vocab.txt 'vocabulary pack events version 1'
indent < vocab.txt
run bo vocab show events.vocab --language zh-Hant-HK > words.txt
check words.txt '來賓'
sed -n '1,12p' words.txt | indent

step "3. The contract, in those words: tested, then deployed with the pack"
sed '/^# Its tests/,$d' tickets.bo | sed 's/^/   | /'
run bo test tickets.bo --vocab events.vocab | tail -n 1 | indent
# Without the pack, its words are no words of Bo's: the source does not read.
if run bo check tickets.bo > nopack.txt 2>&1; then
    echo "the contract must not check without its pack" >&2
    exit 1
fi
check nopack.txt 'use events names no vocabulary pack read here'
say "Without --vocab, use events names no pack: Bo never guesses."
run contract deploy --bo tickets.bo --vocab events.vocab --as org-root.key --ledger "$ORG" \
    --json > deploy.json 2> /dev/null
CONTRACT="$(field '["contract"]["id"]' < deploy.json)"
say "Deployed: contract ${CONTRACT:0:16}... Its source bundle embeds events.vocab."

step "4. A ticket"
TICKET="$(run contract create "$CONTRACT" create \
    --args "{\"fields\": {\"venue\": \"City Hall\", \"seat\": \"A12\", \"quantity\": 1}, \"parties\": {\"organizer\": h'$ORG_ID'}}" \
    --as org-root.key --ledger "$ORG" --json | field '["instance"]["id"]')"
run contract instance "$TICKET" --ledger "$ORG" > ticket.txt
check ticket.txt 'status:    active'
sed -n '1,5p' ticket.txt | indent

step "5. Reserved for the fan, who agrees"
RESERVE="{\"counterparty\": h'$FAN_ID'}"
run contract call "$TICKET" reserve --args "$RESERVE" --dry-run --as org-root.key --ledger "$ORG" \
    > dry.txt
check dry.txt 'consent'
# The fan checks the ticket's history offline, with no pack file: the
# bundle carries the pack, so the contract rebuilds from its source.
run contract evidence "$TICKET" --log-key org-log.key --out ticket.cbor --ledger "$ORG" > /dev/null
mkdir -p fan-side
(cd fan-side && run contract verify ../ticket.cbor --ledger-id "$ORG_ID" > ../verify1.txt)
check verify1.txt 'rebuilds'
check verify1.txt 'vocabulary packs events 1 (1 embedded, not official)'
say "The fan verifies the evidence offline: the contract rebuilds with the pack it carries."
run contract consent --home "$ORG_ID" --evidence ticket.cbor --instance "$TICKET" \
    --function reserve --args "$RESERVE" --as fan-root.key --log-key fan-log.key \
    --out reserve-consent.cbor --ledger "$FAN" > /dev/null
run contract call "$TICKET" reserve --args "$RESERVE" --consent reserve-consent.cbor \
    --as org-root.key --ledger "$ORG" > reserve.txt
check reserve.txt 'status: reserved'
indent < reserve.txt
if run contract call "$TICKET" reserve --args "$RESERVE" --as org-root.key --ledger "$ORG" \
    > twice.txt 2>&1; then
    echo "a second reservation must be refused" >&2
    exit 1
fi
check twice.txt 'bo:state reserve'
say "A reserved ticket is not reserved again (bo:state reserve)."

step "6. The fan checks in at the door"
run contract evidence "$TICKET" --log-key org-log.key --out reserved.cbor --ledger "$ORG" > /dev/null
run contract consent --home "$ORG_ID" --evidence reserved.cbor --instance "$TICKET" \
    --function check_in --args "{}" --as fan-root.key --log-key fan-log.key \
    --out check-in-consent.cbor --ledger "$FAN" > /dev/null
run contract call "$TICKET" check_in --args "{}" --consent check-in-consent.cbor \
    --as org-root.key --ledger "$ORG" > in.txt
check in.txt 'status: checked_in'
indent < in.txt

step "7. Anyone verifies the whole history offline"
run contract evidence "$TICKET" --log-key org-log.key --out history.cbor --ledger "$ORG" > /dev/null
run contract verify history.cbor --ledger-id "$ORG_ID" > verify2.txt
check verify2.txt 'rebuilds'
check verify2.txt 'check_in'
indent < verify2.txt
for d in "$ORG" "$FAN"; do run audit --ledger "$d" > /dev/null; done
say "Both ledgers audit clean."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
