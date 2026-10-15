#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Lending a camera to a friend, narrated step by step. Two people, each with
# a ledger of their own on one computer, and a contract of a dozen lines that
# says what may happen and who must agree. Nothing here is about business:
# the same steps record a book, a tool, or a key lent.
#   - Alice writes the contract in Bo (lending.bo, next to this script),
#     tests it, and deploys it on her ledger;
#   - she registers her camera as an instance of it, and keeps its serial
#     number and a photo in a record whose values stay private;
#   - she lends it to Bob, which needs Bob's agreement: he checks the camera's
#     history offline, then consents on his own ledger, as a file she records
#     the call with;
#   - Bob brings it back; anyone verifies the whole history offline, every
#     call run again, every consent checked, the contract's code rebuilt from
#     its source.
# No server and no platform: the files go between them by any channel. It
# needs a cexchain built with the Bo compiler (GCC 16; the release build and
# the Docker image have it).
#
# Usage: lending.sh [CEXCHAIN] [DIR]
#   CEXCHAIN  the command-line tool (default: cexchain on the PATH)
#   DIR       where to keep the ledgers (default: a temporary directory,
#             removed at the end; give one to look around afterwards)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="${1:-cexchain}"
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
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN

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

ALICE="$WORK/alice"; BOB="$WORK/bob"

step "1. Two people, each with a ledger of their own"
for who in alice bob; do
    run key generate --out "$who-root.key" > /dev/null
    run key generate --out "$who-log.key" > /dev/null
done
run init --name "Alice" --root-key alice-root.key --log-key alice-log.key --ledger "$ALICE" > /dev/null
run init --name "Bob" --root-key bob-root.key --log-key bob-log.key --ledger "$BOB" > /dev/null
id_of() { run status --ledger "$1" --json | field '["ledger_id"]'; }
ALICE_ID="$(id_of "$ALICE")"; BOB_ID="$(id_of "$BOB")"
say "Alice  ledger ${ALICE_ID:0:16}..."
say "Bob    ledger ${BOB_ID:0:16}..."
say "Each keeps the other's ledger id, learned in person or over a channel they trust."
run peer add bob --ledger-id "$BOB_ID" --ledger "$ALICE" > /dev/null
run peer add alice --ledger-id "$ALICE_ID" --ledger "$BOB" > /dev/null

step "2. Alice writes the rules, tests them, and deploys them on her ledger"
if [ "$(run version --json | field '["bo"] is not None')" != True ]; then
    echo "This example needs a cexchain built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
cp "$HERE/lending.bo" .
sed '/^# Its tests/,$d' lending.bo | sed 's/^/   | /'
run bo test lending.bo | tail -n 1 | indent
CONTRACT="$(run contract deploy --bo lending.bo --as alice-root.key --ledger "$ALICE" --json \
    2> /dev/null | field '["contract"]["id"]')"
say "Deployed: contract ${CONTRACT:0:16}... Her ledger now runs it on every call."

step "3. Alice registers her camera"
# What the rules must see goes into the instance, which whoever holds its
# evidence reads. What is private (the serial number, a photo) goes into a
# record of a type she names herself: its values stay sealed on her ledger,
# and only their commitments are recorded. The instance's creation names the
# record in its reference.
printf 'a photo of the camera' > camera.jpg
RECORD="$(run record issue --type example.alice.belonging/1 --field serial=X100-2611-0042 \
    --field bought=2025-12-24 --attach camera.jpg --as alice-root.key --ledger "$ALICE" --json \
    | field '["record"]["id"]')"
CAMERA="$(run contract create "$CONTRACT" create \
    --args "{\"fields\": {\"name\": \"Camera X100\"}, \"parties\": {\"owner\": h'$ALICE_ID'}}" \
    --reference "details: record $RECORD" --as alice-root.key --ledger "$ALICE" --json \
    | field '["instance"]["id"]')"
run contract instance "$CAMERA" --ledger "$ALICE" > camera.txt
check camera.txt 'status:    active'
sed -n '1,5p' camera.txt | indent

step "4. Alice lends it to Bob, who must agree"
LEND="{\"counterparty\": h'$BOB_ID'}"
run contract call "$CAMERA" lend --args "$LEND" --dry-run --as alice-root.key --ledger "$ALICE" \
    > dry.txt
check dry.txt 'consent'
indent < dry.txt
# Alice sends Bob the camera's evidence. Bob checks it offline before he
# agrees: the contract's code rebuilt from its source, every call run again.
run contract evidence "$CAMERA" --log-key alice-log.key --out camera.cbor --ledger "$ALICE" > /dev/null
run contract verify camera.cbor --ledger-id "$ALICE_ID" > verify1.txt
check verify1.txt 'rebuilds'
say "Bob verifies the camera's evidence offline: its contract rebuilds from its source."
# His consent is a record on his own ledger naming the exact call: the
# instance, its head, the function, and a digest of the arguments. It counts
# once, for this call only.
run contract consent --home "$ALICE_ID" --evidence camera.cbor --instance "$CAMERA" --function lend \
    --args "$LEND" --as bob-root.key --log-key bob-log.key --out lend-consent.cbor \
    --ledger "$BOB" > /dev/null
say "Bob consents on his ledger and sends Alice the file lend-consent.cbor."
run contract call "$CAMERA" lend --args "$LEND" --consent lend-consent.cbor --as alice-root.key \
    --ledger "$ALICE" > lend.txt
check lend.txt 'status: lent'
indent < lend.txt

step "5. Nobody lends it twice"
if run contract call "$CAMERA" lend --args "$LEND" --as alice-root.key --ledger "$ALICE" \
    > twice.txt 2>&1; then
    echo "a second loan must be refused" >&2
    exit 1
fi
check twice.txt 'bo:state lend'
say "While it is lent, the contract refuses another loan (bo:state lend)."

step "6. Bob brings it back"
run contract evidence "$CAMERA" --log-key alice-log.key --out lent.cbor --ledger "$ALICE" > /dev/null
run contract consent --home "$ALICE_ID" --evidence lent.cbor --instance "$CAMERA" \
    --function bring_back --args "{}" --as bob-root.key --log-key bob-log.key \
    --out back-consent.cbor --ledger "$BOB" > /dev/null
run contract call "$CAMERA" bring_back --args "{}" --consent back-consent.cbor \
    --as alice-root.key --ledger "$ALICE" > back.txt
check back.txt 'status: active'
indent < back.txt

step "7. Anyone verifies the whole history offline"
run contract evidence "$CAMERA" --log-key alice-log.key --out history.cbor --ledger "$ALICE" > /dev/null
run contract verify history.cbor --ledger-id "$ALICE_ID" > verify2.txt
check verify2.txt 'rebuilds'
check verify2.txt 'bring_back'
indent < verify2.txt
for d in "$ALICE" "$BOB"; do run audit --ledger "$d" > /dev/null; done
say "Both ledgers audit clean."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
