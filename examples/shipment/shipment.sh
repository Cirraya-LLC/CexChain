#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A shipment's chain of custody, narrated step by step. Goods kept cold go
# from a shipper to a carrier, a transit warehouse, and a consignee; an
# insurer covers them. Five organizations, each with a ledger of its own on
# one computer (the carrier's on the Chinese SM2 and SM3 algorithms), and a
# contract in Bo (shipment.bo, next to this script):
#   - the shipper deploys the contract, registers a data logger (a device)
#     and a keeper (a device that calls time rules), and books the shipment,
#     its packing list kept private in a record;
#   - the carrier's driver signs every handover in person, with a hardware
#     key (SoftHSM stands in for a USB key here; a passkey in a browser does
#     the same); a signature with a key alone is refused;
#   - the data logger posts readings, one out of range; the deadline passes,
#     and the keeper marks the shipment late;
#   - the warehouse takes the goods and gives them back; a handover the
#     contract does not allow is refused;
#   - at delivery the consignee scans a QR code, verifies offline, and
#     receives the goods; the contract charges each day late;
#   - the consignee claims the excursion, and the insurer pays;
#   - anyone verifies the whole history offline: who signed each step (a
#     device, a person present, the keeper), every consent on its own ledger.
# No server: consents travel as files, by any channel. It needs a cexchain
# built with the Bo compiler (GCC 16; the release build and the Docker image
# have it) and SoftHSM (brew install softhsm, or apt install softhsm2).
#
# Usage: shipment.sh [CEXCHAIN] [DIR] [PKCS11_MODULE]
#   CEXCHAIN       the command-line tool (default: cexchain on the PATH)
#   DIR            where to keep the ledgers (default: a temporary directory,
#                  removed at the end; give one to look around afterwards)
#   PKCS11_MODULE  SoftHSM's module (default: $PKCS11_MODULE, or found where
#                  Homebrew and Linux distributions install it)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="${1:-cexchain}"
# A path relative to where the script starts works too.
case "$CEXCHAIN" in */*) CEXCHAIN="$(cd "$(dirname "$CEXCHAIN")" && pwd)/$(basename "$CEXCHAIN")" ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE="${3:-${PKCS11_MODULE:-}}"
if [ -z "$MODULE" ]; then
    for m in /opt/homebrew/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
        if [ -f "$m" ]; then MODULE="$m"; break; fi
    done
fi
if [ -z "$MODULE" ] || ! command -v softhsm2-util > /dev/null; then
    echo "This example needs SoftHSM, which stands in for the driver's hardware key:" >&2
    echo "brew install softhsm, or apt install softhsm2 (or give its module as PKCS11_MODULE)." >&2
    exit 1
fi
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

ORGS="shipper carrier warehouse consignee insurer"
name_of() {
    case "$1" in
        shipper) echo "Shipper Co." ;;
        carrier) echo "Cold Chain Carrier Ltd." ;;
        warehouse) echo "Transit Warehouse Ltd." ;;
        consignee) echo "Consignee Clinic" ;;
        insurer) echo "Cargo Insurer Ltd." ;;
    esac
}
dir() { echo "$WORK/$1"; }
id_of() { run status --ledger "$(dir "$1")" --json | field '["ledger_id"]'; }

step "1. Five organizations, each with a ledger of its own"
for org in $ORGS; do
    if [ "$org" = carrier ]; then
        # The carrier uses the Chinese commercial algorithms: SM2 keys, SM3 hashes.
        run key generate --alg sm2-sm3 --out "$org-root.key" > /dev/null
        run key generate --alg sm2-sm3 --out "$org-log.key" > /dev/null
        run init --name "$(name_of "$org")" --root-key "$org-root.key" --log-key "$org-log.key" \
            --hash sm3 --ledger "$(dir "$org")" > /dev/null
    else
        run key generate --out "$org-root.key" > /dev/null
        run key generate --out "$org-log.key" > /dev/null
        run init --name "$(name_of "$org")" --root-key "$org-root.key" --log-key "$org-log.key" \
            --ledger "$(dir "$org")" > /dev/null
    fi
done
SHIPPER_ID="$(id_of shipper)"; CARRIER_ID="$(id_of carrier)"; WAREHOUSE_ID="$(id_of warehouse)"
CONSIGNEE_ID="$(id_of consignee)"; INSURER_ID="$(id_of insurer)"
for org in $ORGS; do
    printf '   %-24s ledger %s...%s\n' "$(name_of "$org")" "$(id_of "$org" | cut -c1-16)" \
        "$([ "$org" = carrier ] && echo ' (SM2, SM3)' || true)"
done
say "Each keeps the others' ledger ids, learned over a channel it trusts."
for org in carrier warehouse consignee insurer; do
    run peer add "$org" --ledger-id "$(id_of "$org")" --ledger "$(dir shipper)" > /dev/null
    run peer add shipper --ledger-id "$SHIPPER_ID" --ledger "$(dir "$org")" > /dev/null
done

step "2. The shipper writes the rules, tests them, and deploys them on its ledger"
if [ "$(run version --json | field '["bo"] is not None')" != True ]; then
    echo "This example needs a cexchain built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
cp "$HERE/shipment.bo" .
# The rules without their comments and tests: the parties, the fields, and
# who may do what, when.
sed '/^# Its tests/,$d' shipment.bo | grep -v '^#' | sed 's/^/   | /'
run bo test shipment.bo | tail -n 1 | indent
CONTRACT="$(run contract deploy --bo shipment.bo --as shipper-root.key --ledger "$(dir shipper)" \
    --json 2> /dev/null | field '["contract"]["id"]')"
say "Deployed: contract ${CONTRACT:0:16}... The shipper's ledger runs it on every call."
say "Every party can read the same contract in its own language:"
run contract explain "$CONTRACT" --language zh-Hans-CN --ledger "$(dir shipper)" > text-zh.txt
check text-zh.txt '本人在场'
grep -A4 '^4.2 pick_up' text-zh.txt | indent

step "3. Who signs: a driver in person, a data logger, a keeper"
# The driver is a person at the carrier. He signs with a key of his own and
# proves presence with a second key, on a hardware token that needs his PIN:
# here SoftHSM stands in for a USB key. A passkey (Touch ID, a phone) proves
# presence the same way, through a browser (--presence instead of
# --presence-key).
mkdir tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$WORK" > softhsm2.conf
export SOFTHSM2_CONF="$WORK/softhsm2.conf" CEXCHAIN_PKCS11_PIN=123456
softhsm2-util --init-token --free --label Driver --pin 123456 --so-pin 12345678 > /dev/null
UKEY="pkcs11:token=Driver;object=presence?module-path=$MODULE"
run key generate --pkcs11 "$UKEY" --alg esp256 --out driver-ukey.pub > /dev/null
run key generate --alg sm2-sm3 --out driver.key > /dev/null
DRIVER="$(run actor add --kind person --name "Driver Lee" --key driver.key --as carrier-root.key \
    --ledger "$(dir carrier)" --json | field '["actor"]["id"]')"
run presence enroll --pkcs11 "$UKEY" --label "Driver's hardware key" --out driver.credential > /dev/null
run actor set-presence "$DRIVER" --credential driver.credential --as carrier-root.key \
    --ledger "$(dir carrier)" > /dev/null
# He may consent for the carrier, and only in person.
run delegation grant --to "$DRIVER" --allow record-register \
    --record-types cexchain.contract-consent/1 --require-presence --as carrier-root.key \
    --ledger "$(dir carrier)" > /dev/null
say "Carrier: Driver Lee, a person, who consents for the carrier and only in person"
say "         (a hardware key with a PIN; a passkey would do the same in a browser)."
# The data logger is a device of the shipper, packed with the goods. Its
# delegation lets it call one function of this one contract: measure.
run key generate --out logger.key > /dev/null
LOGGER="$(run actor add --kind device --name "Data logger DL-7" --key logger.key \
    --as shipper-root.key --ledger "$(dir shipper)" --json | field '["actor"]["id"]')"
run delegation grant --to "$LOGGER" --allow contract-call --contracts "$CONTRACT" \
    --functions measure --as shipper-root.key --ledger "$(dir shipper)" > /dev/null
say "Shipper: Data logger DL-7, a device, which may only post readings (measure)."
# The keeper is another device of the shipper: it calls the contract's time
# rules once they are due (here when.late), on a schedule or by hand.
run keeper add Keeper --contracts "$CONTRACT" --key-out keeper.key --as shipper-root.key \
    --ledger "$(dir shipper)" --json > keeper.json
say "Shipper: a keeper, a device that calls $(field '["functions"]' < keeper.json | tr -d "[]'")."

step "4. The shipper books the shipment"
# What the rules must see goes into the instance, which every party's
# evidence shows. What is private (the product, its batch, the cartons) goes
# into a record of a type the shipper names: its values stay sealed on its
# ledger, and only their commitments are recorded.
PACKING="$(run record issue --type example.shipper.packing-list/1 --field product="Vaccine, 2 to 8 C" \
    --field batch=VX-2610-118 --field cartons=12 --as shipper-root.key --ledger "$(dir shipper)" \
    --json | field '["record"]["id"]')"
# The deadline is two days ago, so that this run shows a late delivery, a
# keeper, and a charge without waiting days. Dates count at UTC+08:00.
read -r DUE DUE_DAY <<< "$(python3 -c "
import datetime as d
tz = d.timezone(d.timedelta(hours=8))
now = d.datetime.now(tz)
due = d.datetime(now.year, now.month, now.day, tzinfo=tz) - d.timedelta(days=2)
print(int(due.timestamp()) * 1000, due.strftime('%Y-%m-%d'))")"
# Arguments name each field and party: money in cents (HKD 800,000 is
# 80000000), dates in milliseconds, parties by their ledger ids. The days
# late, the late charge, and the excursions have defaults: not given.
FIELDS="\"due\": $DUE, \"amount\": 80000000, \"penalty_per_day\": 200000"
PARTIES="\"shipper\": h'$SHIPPER_ID', \"carrier\": h'$CARRIER_ID', \"warehouse\": h'$WAREHOUSE_ID', \"consignee\": h'$CONSIGNEE_ID', \"insurer\": h'$INSURER_ID'"
SHIPMENT="$(run contract create "$CONTRACT" create --args "{\"fields\": {$FIELDS}, \"parties\": {$PARTIES}}" \
    --reference "packing list: record $PACKING" --as shipper-root.key --ledger "$(dir shipper)" --json \
    | field '["instance"]["id"]')"
say "Shipment ${SHIPMENT:0:16}...: due $DUE_DAY, insured for HKD 800,000, HKD 2,000 a day late."
say "Its creation names the packing list, record ${PACKING:0:16}..., whose values stay private."
# The data logger posts its first readings, signed with its own key:
# temperatures in hundredths of a degree (4.2 °C is 420).
run contract call "$SHIPMENT" measure --args '{"readings": [420, 510, 550, 430]}' --as logger.key \
    --ledger "$(dir shipper)" > /dev/null
say "Data logger: 4.2, 5.1, 5.5, 4.3 °C."

# Helpers for the steps below. The shipper's ledger, the shipment's home,
# makes every call; another party acts by consenting on its own ledger to
# that exact call (the instance, its head, the function, the arguments),
# after checking the shipment's evidence offline. Its consent is a file the
# shipper's call cites.
evidence() {
    run contract evidence "$SHIPMENT" --log-key shipper-log.key --out "$1" \
        --ledger "$(dir shipper)" > /dev/null
}
consent() { # ORG FUNCTION ARGS OUT [the signer's options]
    local org="$1" function="$2" args="$3" out="$4"
    shift 4
    evidence now.cbor
    run contract verify now.cbor --ledger-id "$SHIPPER_ID" > /dev/null
    run contract consent --home "$SHIPPER_ID" --evidence now.cbor --instance "$SHIPMENT" \
        --function "$function" --args "$args" --log-key "$org-log.key" --out "$out" \
        --ledger "$(dir "$org")" "$@" > /dev/null
}
driver() { # FUNCTION OUT: the driver consents for the carrier, in person
    consent carrier "$1" "{}" "$2" --as driver.key --presence-key "$UKEY"
}
call() { # FUNCTION ARGS OUT [--consent FILE ...]
    local function="$1" args="$2" out="$3"
    shift 3
    run contract call "$SHIPMENT" "$function" --args "$args" "$@" --as shipper-root.key \
        --ledger "$(dir shipper)" > "$out" 2>&1
}
refused() { # OUT REASON FUNCTION ARGS [--consent FILE ...]
    local out="$1" reason="$2" function="$3" args="$4"
    shift 4
    if call "$function" "$args" "$out" "$@"; then
        echo "expected a refusal ($reason)" >&2
        exit 1
    fi
    check "$out" "$reason"
}
status_is() {
    run contract instance "$SHIPMENT" --ledger "$(dir shipper)" > instance.txt
    check instance.txt "status:    $1"
}
state_field() { # FIELD: its value in the instance's state
    run contract instance "$SHIPMENT" --ledger "$(dir shipper)" --json \
        | python3 -c "import json,re,sys; print(re.search(r'\"$1\": ([^,}]+)', json.load(sys.stdin)['state']).group(1))"
}

step "5. Pick-up: the driver signs in person"
# First the carrier's office signs with its organization's key alone. The
# contract wants a person who proves presence, so the shipper's ledger
# refuses the call, and nothing is recorded.
consent carrier pick_up "{}" office.cbor --as carrier-root.key
refused office.txt 'bo:in-person pick_up' pick_up "{}" --consent office.cbor
say "Signed with the carrier's key alone:"
indent < office.txt
# The driver checks the shipment's evidence offline, then consents on the
# carrier's ledger with his key and his hardware key.
driver pick_up pickup.cbor
call pick_up "{}" pickup.txt --consent pickup.cbor
check pickup.txt 'status: in_transit'
check pickup.txt 'holder: carrier'
say "Signed by Driver Lee in person: the carrier holds the goods, in_transit."

step "6. On the road: an excursion, and the deadline passes"
run contract call "$SHIPMENT" measure --args '{"readings": [520, 610, 1140, 830]}' --as logger.key \
    --ledger "$(dir shipper)" > /dev/null
[ "$(state_field excursions)" = 2 ] || { echo "two readings out of range" >&2; exit 1; }
say "Data logger: 5.2, 6.1, 11.4, 8.3 °C. Two readings above 8 °C: excursions 2."
# The due date was two days ago, so the deadline rule's time, a day after
# it, came yesterday. The keeper asks what is due (dry runs that record
# nothing), then fires it; a keeper that is late fires late, never early,
# and the event shows how late.
run keeper due --ledger "$(dir shipper)" > due.txt
check due.txt 'when.late'
run keeper run --as keeper.key --ledger "$(dir shipper)" > fired.txt
check fired.txt 'fired when.late'
status_is late
say "The keeper fires when.late: the shipment is late, for every party to see."
indent < fired.txt

step "7. The transit warehouse takes the goods, and gives them back"
# The driver hands them over in person, and the warehouse consents to take
# them on its own ledger.
driver drop_off dropoff.cbor
consent warehouse drop_off "{}" store.cbor --as warehouse-root.key
call drop_off "{}" dropoff.txt --consent dropoff.cbor --consent store.cbor
check dropoff.txt 'holder: warehouse'
say "Dropped off: the warehouse holds the goods."
# Could the warehouse hand them straight to the consignee? Both consent, but
# the contract says only the carrier delivers what it holds: refused.
consent warehouse deliver "{}" shortcut-w.cbor --as warehouse-root.key
consent consignee deliver "{}" shortcut-c.cbor --as consignee-root.key
refused shortcut.txt 'bo:requires deliver 2' deliver "{}" --consent shortcut-w.cbor \
    --consent shortcut-c.cbor
say "The warehouse handing them to the consignee itself: refused (bo:requires deliver 2)."
# The driver picks them up again; the warehouse, which holds them, consents
# to give them up.
driver pick_up pickup2.cbor
consent warehouse pick_up "{}" release.cbor --as warehouse-root.key
call pick_up "{}" pickup2.txt --consent pickup2.cbor --consent release.cbor
check pickup2.txt 'holder: carrier'
check pickup2.txt 'status: late'
say "Picked up again in person: the carrier holds the goods; still late."

step "8. Delivery: the consignee scans a QR code, verifies, and receives"
# A QR code on the cartons opens the packing list's evidence in the browser
# verifier (cexchain-verify.html), which checks it on the phone itself. The
# shipper publishes the evidence, disclosing the product and the cartons
# only; the batch stays sealed.
run export "$PACKING" --log-key shipper-log.key --disclose product,cartons --out packing-list.cbor \
    --ledger "$(dir shipper)" > /dev/null
BUNDLE_URL="https://shipper.example/evidence/packing-list.cbor"
VERIFIER_URL="https://verify.example/cexchain-verify.html"
run qr "$PACKING" --bundle-url "$BUNDLE_URL" --verifier-url "$VERIFIER_URL" --out label-qr.svg \
    --ledger "$(dir shipper)" --json > qr.json
say "QR code on the cartons: label-qr.svg, opening"
say "  $(field '["url"]' < qr.json | cut -c1-96)..."
# Offline, the same check on the command line: the record is the shipper's,
# and what it discloses is what was committed to.
run verify packing-list.cbor --ledger-id "$SHIPPER_ID" > packing.txt
check packing.txt 'cartons = 12'
say "The consignee verifies the packing list offline, as the page does:"
grep -E 'Ledger|Record|product =|cartons =' packing.txt | sed 's/^ *//' | indent
# The custody chain itself: the shipment's evidence, every call run again,
# every consent checked on its own ledger, the contract rebuilt from its
# source. The verifier page checks it too, from a file or a link naming the
# instance (#l=LEDGER&r=INSTANCE&b=URL).
evidence chain.cbor
run contract verify chain.cbor --ledger-id "$SHIPPER_ID" > chain.txt
check chain.txt 'rebuilds'
check chain.txt 'present: hardware key'
say "The consignee verifies the chain of custody offline: shipper, driver in person,"
say "warehouse, driver in person; the contract rebuilds from its source. The page"
say "checks it too, from a link naming the instance (cexchain qr draws records only):"
say "  $VERIFIER_URL#l=${SHIPPER_ID:0:8}...&r=${SHIPMENT:0:8}...&b=.../shipment.cbor"
# The consignee consents to receive the goods; the driver hands them over in
# person. Two days late: the contract counts the whole days late and charges
# HKD 2,000 for each.
consent consignee deliver "{}" receive.cbor --as consignee-root.key
driver deliver deliver.cbor
call deliver "{}" deliver.txt --consent receive.cbor --consent deliver.cbor
check deliver.txt 'status: delivered'
check deliver.txt 'holder: consignee'
LATE="$(state_field late_charge)"
DAYS="$(state_field days_late)"
case "$DAYS $LATE" in
    "2 400000" | "3 600000") ;; # two days late, or three if this ran across midnight
    *) echo "unexpected days late and late charge: $DAYS $LATE" >&2; exit 1 ;;
esac
say "Delivered: the consignee holds the goods. $DAYS days late: HKD $((LATE / 100000)),000 (HKD 2,000 a day)."

step "9. The consignee claims the excursion, and the insurer pays"
consent consignee claim "{}" claim.cbor --as consignee-root.key
call claim "{}" claim.txt --consent claim.cbor
check claim.txt 'status: claimed'
say "Claimed: two readings above 8 °C, within 7 days of delivery."
# The insurer checks the evidence offline (the readings, signed by the
# shipper's device, are in it), then consents to pay HKD 120,000.
PAYOUT='{"payout": 12000000}'
consent insurer compensate "$PAYOUT" payout.cbor --as insurer-root.key
call compensate "$PAYOUT" compensate.txt --consent payout.cbor
check compensate.txt 'status: compensated'
say "Compensated: HKD 120,000. The shipment is final and takes no more calls."

step "10. Anyone verifies the whole history offline"
evidence history.cbor
run contract verify history.cbor --ledger-id "$SHIPPER_ID" > history.txt
check history.txt 'rebuilds'
# Who made each call, and who gave each consent: the data logger and the
# keeper (devices), the driver present with his hardware key, and the
# organizations with their own keys.
check history.txt 'call measure by "Data logger DL-7" [device]'
check history.txt 'call when.late by "Keeper" [device]'
check history.txt 'given by "Driver Lee" (a person, present: hardware key)'
grep -E ' (create|call) |consent of' history.txt \
    | sed -E 's/^ +//; s/^(#[0-9]+) +[0-9-]{10} [0-9:]{8} UTC +/\1 /; s/^consent of/      consent of/' \
    | indent
sed -n '/^  Verified/,/^$/{/^$/!p;}' history.txt | sed 's/^ *//' | indent
for org in $ORGS; do run audit --ledger "$(dir "$org")" > /dev/null; done
say "All five ledgers audit clean."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
