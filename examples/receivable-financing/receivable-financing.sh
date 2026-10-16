#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A receivable financed by a bank, then sold, narrated step by step. A core
# enterprise owes its supplier CNY 1,250,000, payable at maturity: a
# receivable, governed by a contract written in Bo (receivable-financing.bo,
# next to this script), kept on the core enterprise's ledger.
#   - the supplier pledges it to Bank A, which checks it offline first; both
#     consent, each on its own ledger;
#   - a regulator witnesses the core enterprise's ledger, and Bank A lends
#     only once the pledge is in a checkpoint the regulator cosigned;
#   - the supplier tries to finance the same receivable with Bank B: the
#     contract refuses a second pledge;
#   - the loan repaid, Bank A releases the pledge, and the supplier sells the
#     receivable to a factoring company, which consents to the purchase;
#   - at maturity the core enterprise pays, and the factoring company
#     confirms it was paid;
#   - anyone verifies the receivable's whole history offline: every call run
#     again, every consent checked on the ledger that gave it, the contract's
#     code rebuilt from its source.
# Five ledgers, each its own organization, talk over HTTP. It needs a
# cexchain built with the Bo compiler (GCC 16; the release build and the
# Docker image have it).
#
# Usage: receivable-financing.sh [CEXCHAIN] [DIR]
#   CEXCHAIN  the command-line tool (default: cexchain on the PATH)
#   DIR       where to keep the ledgers (default: a temporary directory,
#             removed at the end; give one to look around afterwards)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="${1:-cexchain}"
# A path relative to where the script starts works too.
case "$CEXCHAIN" in */*) CEXCHAIN="$(cd "$(dirname "$CEXCHAIN")" && pwd)/$(basename "$CEXCHAIN")" ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${2:-}" ]; then
    WORK="$2"; KEEP=1; mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"; KEEP=0
fi
WORK="$(cd "$WORK" && pwd)"
SERVER=""
cleanup() {
    if [ -n "$SERVER" ]; then
        kill "$SERVER" 2> /dev/null || true
        wait "$SERVER" 2> /dev/null || true
    fi
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
    # check WHAT PYTHON-CONDITION: fails the demo unless the condition, on
    # the JSON read from standard input, holds.
    python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if ($2) else 1)" \
        || { echo "unexpected: $1" >&2; exit 1; }
}

# One organization per name: its ledger directory, and its keys (ORG-root.key
# signs for the organization, ORG-log.key signs its log).
# (Plain variables, not associative arrays: macOS ships bash 3.2.)
ORGS=(core supplier banka bankb factor)
name_of() {
    case "$1" in
    core) echo "Core Enterprise Co." ;;
    supplier) echo "Tier-1 Supplier Ltd." ;;
    banka) echo "Bank A" ;;
    bankb) echo "Bank B" ;;
    factor) echo "Factor Co." ;;
    esac
}
dir() { echo "$WORK/$1"; }
# An organization's ledger id, once its ledger exists.
id() { cat "$WORK/$1.id"; }

step "1. Five organizations, each with its own ledger"
for org in "${ORGS[@]}"; do
    run key generate --out "$org-root.key" > /dev/null
    run key generate --out "$org-log.key" > /dev/null
    run init --name "$(name_of "$org")" --root-key "$org-root.key" --log-key "$org-log.key" \
        --ledger "$(dir "$org")" > /dev/null
    run status --ledger "$(dir "$org")" --json | field '["ledger_id"]' > "$WORK/$org.id"
    say "$(printf '%-22s ledger %s...' "$(name_of "$org")" "$(id "$org" | cut -c1-16)")"
done
CORE_ID="$(id core)"; SUPPLIER_ID="$(id supplier)"; BANKA_ID="$(id banka)"
BANKB_ID="$(id bankb)"; FACTOR_ID="$(id factor)"
say "Ledger ids are exchanged at onboarding, through a channel each side trusts."
for org in "${ORGS[@]:1}"; do
    run peer add "$org" --ledger-id "$(id "$org")" --ledger "$(dir core)" > /dev/null
done

step "2. The core enterprise builds the contract and deploys it on its ledger"
if [ "$(run version --json | field '["bo"] is not None')" != True ]; then
    echo "This demo needs a cexchain built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
cp "$HERE/receivable-financing.bo" .
# The contract, without its tests (bo test runs them below).
sed '/^# Its tests/,$d' receivable-financing.bo | sed 's/^/   | /'
# Building checks the contract and compiles it to a WebAssembly module, a
# function per action. The deploy records the code and its source, so anyone
# can rebuild the code and read the terms it enforces. (The warning says the
# comments are published with it.)
run bo build receivable-financing.bo 2>&1 | indent
run bo test receivable-financing.bo | tail -n 1 | indent
CONTRACT="$(run contract deploy --bo receivable-financing.bo --as core-root.key --ledger "$(dir core)" \
    --json 2> /dev/null | field '["contract"]["id"]')"
say "Deployed as ${CONTRACT:0:16}... What a pledge means, in the contract text every party"
say "confirms (here in Simplified Chinese):"
run contract explain "$CONTRACT" --language zh-Hans-CN --ledger "$(dir core)" \
    | sed -n '/^4.1 /,/^4.2 /p' | sed '$d' | indent

step "3. The core enterprise confirms what it owes: a receivable, held by the supplier"
# Money is in the smallest unit (fen); dates in milliseconds since 1970.
DUE=1806940800000   # 2027-04-06, 00:00 in Shanghai and Hong Kong
ISSUE="{\"fields\": {\"amount\": 125000000, \"due\": $DUE}, \"parties\": {\"issuer\": h'$CORE_ID', \"supplier\": h'$SUPPLIER_ID'}}"
RECEIVABLE="$(run contract create "$CONTRACT" issue --args "$ISSUE" --reference "PO-2026-0815, INV-2026-0077" \
    --as core-root.key --ledger "$(dir core)" --json | field '["instance"]["id"]')"
run contract instance "$RECEIVABLE" --ledger "$(dir core)" | sed -n '1,7p' | indent
say "The receivable's state (amount, due date, holder) is public to whoever holds its"
say "evidence; the purchase order and the invoice stay in the core enterprise's own records."

step "4. The core enterprise runs its server with a registrar"
# The registrar is a device with a delegation for calls on this contract
# only: it records a call once the contract has every consent it asks for,
# and never on its own word.
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
REGISTRAR="$(run actor add --as core-root.key --kind device --name "Contract Registrar" \
    --key registrar.pub --ledger "$(dir core)" --json | field '["actor"]["id"]')"
run delegation grant --as core-root.key --to "$REGISTRAR" --allow contract-call \
    --contracts "$CONTRACT" --ledger "$(dir core)" > /dev/null
for org in "${ORGS[@]:1}"; do
    run token create "$org" --scope peer --out "$org.token" --ledger "$(dir core)" > /dev/null
done
# Started directly (not through a shell function), so $! is the server itself.
"$CEXCHAIN" serve --ledger "$(dir core)" --log-key core-log.key --registrar-key registrar.key \
    --listen 127.0.0.1:0 --json --quiet > core.json 2> core.log &
SERVER=$!
for _ in $(seq 1 300); do
    python3 -c "import json; json.load(open('core.json'))" 2> /dev/null && break
    sleep 0.1
done
URL="$(field '["url"]' < core.json)"
say "Serving at $URL."
for org in "${ORGS[@]:1}"; do
    run peer add core --ledger-id "$CORE_ID" --url "$URL" --token-file "$org.token" \
        --ledger "$(dir "$org")" > /dev/null
done

# org CALL REFERENCE: the organization reviews the call it is asked to
# consent to, and consents on its own ledger; the consent's evidence goes to
# the registrar.
consent() {
    local org="$1" call="$2" reference="$3"
    run contract consent --peer core --call "$call" --reference "$reference" --as "$org-root.key" \
        --log-key "$org-log.key" --send --ledger "$(dir "$org")" | indent
}
# org FUNCTION [ARGS]: the organization proposes a call on the receivable to
# the registrar; prints the call's id.
propose() {
    local org="$1" function="$2" args="${3:-}"
    if [ -n "$args" ]; then
        run contract propose "$RECEIVABLE" "$function" --args "$args" --peer core \
            --ledger "$(dir "$org")" --json | field '["call"]'
    else
        run contract propose "$RECEIVABLE" "$function" --peer core --ledger "$(dir "$org")" \
            --json | field '["call"]'
    fi
}
status_is() {
    local status
    status="$(run contract instance "$RECEIVABLE" --ledger "$(dir core)" --json | field '["status"]')"
    [ "$status" = "$1" ] || { echo "unexpected: the receivable is $status, not $1" >&2; exit 1; }
}

step "5. The supplier asks Bank A to finance it: both consent to a pledge, each on its own ledger"
CALL="$(propose supplier pledge "{\"counterparty\": h'$BANKA_ID'}")"
consent supplier "$CALL" "Pledge to Bank A, facility SCF-2026-0042"
say "(Here the organizations' own keys sign. In practice a person signs with a UKey or a"
say " passkey, adding --presence, and the report shows that a person was present.)"
say "Bank A is no party yet. It sees the call it is asked to consent to:"
run contract pending --peer core --ledger "$(dir banka)" | indent
say "and checks the receivable first, offline, from the evidence the supplier hands it:"
run contract fetch --peer core --instance "$RECEIVABLE" --out receivable.cbor \
    --ledger "$(dir supplier)" > /dev/null
run contract verify receivable.cbor --ledger-id "$CORE_ID" | grep -E 'Contract|Status|State|rebuilds' \
    | indent
run contract verify receivable.cbor --ledger-id "$CORE_ID" --json \
    | check "the receivable verifies" 'd["verified"] and d["instance"]["status"] == "active"'
consent banka "$CALL" "Facility SCF-2026-0042 approved"
status_is pledged

step "6. A regulator witnesses the core enterprise's ledger; Bank A lends only after that"
REG="$WORK/regulator"
run key public core-log.key --out core-log.pub > /dev/null
run key generate --out regulator-witness.key > /dev/null
run key public regulator-witness.key --out regulator-witness.pub > /dev/null
run witness add-log --dir "$REG" --ledger-id "$CORE_ID" --log-key core-log.pub --name core > /dev/null
run checkpoint create --log-key core-log.key --ledger "$(dir core)" > /dev/null
run checkpoint cosign-request --witness regulator-witness.pub --out cosign.cbor \
    --ledger "$(dir core)" > /dev/null
run witness cosign cosign.cbor --dir "$REG" --key regulator-witness.key --out cosignature.cbor > /dev/null
run checkpoint add-cosignature cosignature.cbor --witness regulator-witness.pub \
    --ledger "$(dir core)" > /dev/null
say "Now a party (the pledgee), Bank A fetches the receivable itself and verifies it, trusting"
say "the regulator's witness key: a home that showed another lender a different history would"
say "need the regulator to cosign that too, and a witness cosigns only one history."
run contract fetch --peer core --instance "$RECEIVABLE" --out pledged.cbor --ledger "$(dir banka)" > /dev/null
run contract verify pledged.cbor --ledger-id "$CORE_ID" --witness regulator-witness.pub \
    --min-witnesses 1 | grep -E 'Status|Witnesses' | indent
run contract verify pledged.cbor --ledger-id "$CORE_ID" --witness regulator-witness.pub \
    --min-witnesses 1 --json \
    | check "the pledge" 'd["verified"] and d["calls"][-1]["function"] == "pledge"'

step "7. The supplier tries to finance the same receivable again, with Bank B"
# (The trap is cleared inside: a refusal is what this step expects.)
if out="$(trap - ERR; run contract propose "$RECEIVABLE" pledge \
    --args "{\"counterparty\": h'$BANKB_ID'}" --peer core --ledger "$(dir supplier)" 2>&1)"; then
    echo "unexpected: a second pledge was accepted" >&2
    exit 1
fi
say "Refused: ${out#error: }"
say "Bank B, checking the evidence the supplier would hand it, would see the pledge in any case."

step "8. The supplier repays Bank A, which releases the pledge"
CALL="$(propose banka release)"
consent banka "$CALL" "Facility SCF-2026-0042 repaid"
status_is active

step "9. The supplier sells the receivable to a factoring company"
CALL="$(propose supplier transfer "{\"counterparty\": h'$FACTOR_ID'}")"
consent supplier "$CALL" "Sale to Factor Co., agreement F-2026-311"
say "Factor Co. checks that the pledge was released, from the evidence the supplier hands it,"
say "before it consents to buy:"
run contract fetch --peer core --instance "$RECEIVABLE" --out released.cbor \
    --ledger "$(dir supplier)" > /dev/null
run contract verify released.cbor --ledger-id "$CORE_ID" --json \
    | check "the release" 'd["verified"] and d["instance"]["status"] == "active" and d["calls"][-1]["function"] == "release"'
consent factor "$CALL" "Purchase F-2026-311"
status_is active
run contract instance "$RECEIVABLE" --ledger "$(dir core)" --json \
    | check "the factor holds it" 'd["parties"]["holder"] == "'"$FACTOR_ID"'"'
say "Factor Co. holds the receivable now."

step "10. At maturity the core enterprise pays, and Factor Co. confirms"
# Paying is the core enterprise's own word; the payee is the pledgee if there
# is one, else the holder.
run contract call "$RECEIVABLE" pay --reference "CNAPS 2027040600001" --as core-root.key \
    --ledger "$(dir core)" | indent
CALL="$(propose factor confirm_payment)"
consent factor "$CALL" "Received in full"
status_is settled

step "11. The receivable's history, as anyone can verify it offline"
run contract fetch --peer core --instance "$RECEIVABLE" --out settled.cbor --ledger "$(dir factor)" > /dev/null
run contract verify settled.cbor --ledger-id "$CORE_ID" > verify.txt
# The report, without each call's arguments and outcome in full.
grep -vE '^ +(arguments|outcome|State) ' verify.txt | indent
run contract verify settled.cbor --ledger-id "$CORE_ID" --json \
    | check "the history" 'd["verified"] and [c["function"] for c in d["calls"]] == ["issue", "pledge", "release", "transfer", "pay", "confirm_payment"]'
for org in "${ORGS[@]}"; do run audit --ledger "$(dir "$org")" > /dev/null; done
say "Every ledger audits clean."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
