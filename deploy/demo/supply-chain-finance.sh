#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A supply-chain finance walkthrough on one machine, narrated step by step:
# a core enterprise confirms what it owes its supplier as a receivable; the
# supplier pledges it to a bank; a second bank's attempt to finance the same
# receivable is refused; the pledge is released, the debtor pays, and the
# payee confirms. Five ledgers, each its own organization, talk over HTTP.
#
# Usage: supply-chain-finance.sh [CEXCHAIN] [DIR]
#   CEXCHAIN  the command-line tool (default: cexchain on the PATH)
#   DIR       where to keep the ledgers (default: a temporary directory,
#             removed at the end; give one to look around afterwards)
set -Eeuo pipefail

CEXCHAIN="${1:-cexchain}"
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

# Ledger directories, one per organization.
CORE="$WORK/core"; SUP="$WORK/supplier"; BANK="$WORK/bank"; BANK2="$WORK/bank2"; REG="$WORK/regulator"

step "1. Five organizations, each with its own ledger"
for org in core supplier bank bank2 regulator; do
    run key generate --out "$org-root.key" > /dev/null
    run key generate --out "$org-log.key" > /dev/null
done
run init --org "Core Enterprise Co." --root-key core-root.key --log-key core-log.key --ledger "$CORE" > /dev/null
run init --org "Tier-1 Supplier Ltd." --root-key supplier-root.key --log-key supplier-log.key --ledger "$SUP" > /dev/null
run init --org "Bank A" --root-key bank-root.key --log-key bank-log.key --ledger "$BANK" > /dev/null
run init --org "Bank B" --root-key bank2-root.key --log-key bank2-log.key --ledger "$BANK2" > /dev/null
id_of() { run status --ledger "$1" --json | field '["ledger_id"]'; }
CORE_ID="$(id_of "$CORE")"; SUP_ID="$(id_of "$SUP")"; BANK_ID="$(id_of "$BANK")"; BANK2_ID="$(id_of "$BANK2")"
say "Core Enterprise  ledger ${CORE_ID:0:16}..."
say "Supplier         ledger ${SUP_ID:0:16}..."
say "Bank A           ledger ${BANK_ID:0:16}..."
say "Bank B           ledger ${BANK2_ID:0:16}..."
say "Ledger ids are exchanged at onboarding, through a channel each side trusts."
run peer add supplier --ledger-id "$SUP_ID" --ledger "$CORE" > /dev/null
run peer add bank-a --ledger-id "$BANK_ID" --ledger "$CORE" > /dev/null
run peer add bank-b --ledger-id "$BANK2_ID" --ledger "$CORE" > /dev/null
run peer add bank-a --ledger-id "$BANK_ID" --ledger "$SUP" > /dev/null
run peer add bank-b --ledger-id "$BANK2_ID" --ledger "$SUP" > /dev/null

step "2. The core enterprise runs its server with a registrar"
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
REGISTRAR="$(run actor add --as core-root.key --kind device --name "Asset Registrar" --key registrar.pub \
    --ledger "$CORE" --json | field '["actor"]["id"]')"
run delegation grant --as core-root.key --to "$REGISTRAR" --allow asset-action \
    --record-types cexchain.receivable/1 --ledger "$CORE" > /dev/null
for p in supplier bank-a bank-b; do
    run token create "$p" --scope peer --out "$p.token" --ledger "$CORE" > /dev/null
done
# Started directly (not through a shell function), so $! is the server itself.
"$CEXCHAIN" serve --ledger "$CORE" --log-key core-log.key --registrar-key registrar.key \
    --listen 127.0.0.1:0 --json --quiet > core.json 2> core.log &
SERVER=$!
for _ in $(seq 1 300); do
    python3 -c "import json; json.load(open('core.json'))" 2> /dev/null && break
    sleep 0.1
done
URL="$(field '["url"]' < core.json)"
say "Serving at $URL; the registrar records an asset action once every party has consented."
run peer add core --ledger-id "$CORE_ID" --url "$URL" --token-file supplier.token --ledger "$SUP" > /dev/null
run peer add core --ledger-id "$CORE_ID" --url "$URL" --token-file bank-a.token --ledger "$BANK" > /dev/null
run peer add core --ledger-id "$CORE_ID" --url "$URL" --token-file bank-b.token --ledger "$BANK2" > /dev/null

step "3. The core enterprise confirms what it owes: a receivable, held by the supplier"
ASSET="$(run asset issue receivable --holder supplier --amount 1250000.00 --currency CNY --due 2027-04-06 \
    --title "Receivable for PO-2026-0815" --field contract=PO-2026-0815 --field invoice=INV-2026-0077 \
    --field goods="Bearings, 20,000 units" --as core-root.key --ledger "$CORE" --json | field '["asset"]["id"]')"
run asset show "$ASSET" --ledger "$CORE" | sed 's/^/   /'
run checkpoint create --log-key core-log.key --ledger "$CORE" > /dev/null
run asset evidence "$ASSET" --log-key core-log.key --fields '*' --out receivable.cbor --ledger "$CORE" > /dev/null
say "The supplier receives the receivable's evidence, with its fields disclosed (receivable.cbor)."

step "4. The supplier asks Bank A to finance it: both consent to a pledge, each on its own ledger"
run asset consent --peer core --asset "$ASSET" --action pledge --to bank-a --as supplier-root.key \
    --log-key supplier-log.key --ledger "$SUP" --send | sed 's/^/   /'
say "(Here the organizations' own keys sign. In practice a person signs with a UKey or a"
say " passkey, adding --presence, and the report shows that a person was present.)"
say "Bank A checks the receivable first, offline:"
run asset verify receivable.cbor --ledger-id "$CORE_ID" | sed -n '3,9p' | sed 's/^/   /'
run asset consent --peer core --asset "$ASSET" --action pledge --to "$BANK_ID" --evidence receivable.cbor \
    --reference "Facility SCF-2026-0042" --as bank-root.key --log-key bank-log.key --ledger "$BANK" --send \
    | sed 's/^/   /'

step "5. A regulator witnesses the core enterprise's ledger; Bank A funds only after that"
run key public core-log.key --out core-log.pub > /dev/null
run key generate --out regulator-witness.key > /dev/null
run key public regulator-witness.key --out regulator-witness.pub > /dev/null
run witness add-log --dir "$REG" --ledger-id "$CORE_ID" --log-key core-log.pub --name core > /dev/null
run checkpoint create --log-key core-log.key --ledger "$CORE" > /dev/null
run checkpoint cosign-request --witness regulator-witness.pub --out cosign.cbor --ledger "$CORE" > /dev/null
run witness cosign cosign.cbor --dir "$REG" --key regulator-witness.key --out cosignature.cbor > /dev/null
run checkpoint add-cosignature cosignature.cbor --witness regulator-witness.pub --ledger "$CORE" > /dev/null
run asset fetch --peer core --asset "$ASSET" --out pledged.cbor --ledger "$BANK" > /dev/null
run asset verify pledged.cbor --ledger-id "$CORE_ID" --witness regulator-witness.pub --min-witnesses 1 \
    | sed 's/^/   /'

step "6. The supplier tries to finance the same receivable again, with Bank B"
if out="$(run asset consent --peer core --asset "$ASSET" --action pledge --to bank-b \
    --as supplier-root.key --log-key supplier-log.key --ledger "$SUP" --send 2>&1)"; then
    say "UNEXPECTED: a second pledge was accepted"; exit 1
fi
say "Refused: ${out#error: }"
say "Bank B, checking the evidence, would see the pledge to Bank A in any case."

step "7. The supplier repays Bank A, which releases the pledge"
run asset consent --peer core --asset "$ASSET" --action release --as bank-root.key --log-key bank-log.key \
    --ledger "$BANK" --send | sed 's/^/   /'

step "8. At maturity the debtor pays, and the supplier confirms"
run asset record pay "$ASSET" --reference "CNAPS 2027040600001" --as core-root.key --ledger "$CORE" \
    | sed 's/^/   /'
run asset consent --peer core --asset "$ASSET" --action confirm --as supplier-root.key \
    --log-key supplier-log.key --ledger "$SUP" --send | sed 's/^/   /'

step "9. The chain of title, as anyone can verify it offline"
run asset fetch --peer core --asset "$ASSET" --out settled.cbor --ledger "$SUP" > /dev/null
run asset verify settled.cbor --ledger-id "$CORE_ID" | sed 's/^/   /'
for d in "$CORE" "$SUP" "$BANK" "$BANK2"; do run audit --ledger "$d" > /dev/null; done
say "Every ledger audits clean."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
