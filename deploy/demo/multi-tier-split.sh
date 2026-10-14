#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Multi-tier supply-chain finance, narrated step by step. A core enterprise
# owes its tier-1 supplier CNY 1,000,000, payable at maturity: a receivable,
# governed by a contract written in Bo. Small suppliers deep in a supply
# chain rarely get credit on their own; here they borrow against the core
# enterprise's promise instead:
#   - the tier-1 supplier splits the receivable between two tier-2 suppliers,
#     who are not parties of anything yet: each sees the call it is asked to
#     agree to, and consents on its own ledger (one of them hashes with SM3
#     and signs with SM2);
#   - one tier-2 supplier splits its part again, keeping some and passing
#     the rest to a tier-3 supplier;
#   - the tier-3 supplier pledges its part to a bank for financing. Before it
#     agrees, the bank verifies the part offline: the whole chain of title,
#     from the core enterprise's receivable down, every consent included;
#   - at maturity the core enterprise pays each part, the pledged one to the
#     bank, and each payee confirms it was paid.
# Each part is an instance of its own, created by the call that split its
# parent: it is held, pledged, and paid on its own. The core enterprise's
# ledger is the home of every part; every holder's consent is a record on its
# own ledger. Six ledgers talk over HTTP.
#
# The contract is multi-tier-split.bo, next to this script: Bo, CexChain's
# contract language. Splitting is the `split` of Bo's standard library (the
# holder starts it, every recipient consents, the parts add up to the amount,
# each part is one tier down). It needs a cexchain built with the Bo compiler
# (GCC 16; the release build and the Docker image have it).
#
# Usage: multi-tier-split.sh [CEXCHAIN] [DIR]
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
ORGS=(core assembly gears castings forge bank)
name_of() {
    case "$1" in
    core) echo "Core Enterprise Co." ;;
    assembly) echo "Assembly Co. (tier 1)" ;;
    gears) echo "Gears Co. (tier 2)" ;;
    castings) echo "Castings Co. (tier 2)" ;;
    forge) echo "Forge Co. (tier 3)" ;;
    bank) echo "Bank B" ;;
    esac
}
dir() { echo "$WORK/$1"; }
# An organization's ledger id, once its ledger exists.
id() { cat "$WORK/$1.id"; }

step "1. Six organizations, each with its own ledger"
for org in "${ORGS[@]}"; do
    if [ "$org" = castings ] || [ "$org" = bank ]; then
        # The Chinese commercial algorithms: SM2 keys, SM3 hashes.
        run key generate --alg sm2-sm3 --out "$org-root.key" > /dev/null
        run key generate --alg sm2-sm3 --out "$org-log.key" > /dev/null
        run init --org "$(name_of "$org")" --root-key "$org-root.key" --log-key "$org-log.key" \
            --hash sm3 --ledger "$(dir "$org")" > /dev/null
    else
        run key generate --out "$org-root.key" > /dev/null
        run key generate --out "$org-log.key" > /dev/null
        run init --org "$(name_of "$org")" --root-key "$org-root.key" --log-key "$org-log.key" \
            --ledger "$(dir "$org")" > /dev/null
    fi
    run status --ledger "$(dir "$org")" --json | field '["ledger_id"]' > "$WORK/$org.id"
    say "$(printf '%-24s ledger %s...' "$(name_of "$org")" "$(id "$org" | cut -c1-16)")"
done
CORE_ID="$(id core)"; ASSEMBLY_ID="$(id assembly)"; GEARS_ID="$(id gears)"
CASTINGS_ID="$(id castings)"; FORGE_ID="$(id forge)"; BANK_ID="$(id bank)"
say "Castings Co. and Bank B hash with SM3 and sign with SM2; the others use SHA-256 and Ed25519."
say "Ledger ids are exchanged at onboarding, through a channel each side trusts."
for org in "${ORGS[@]:1}"; do
    run peer add "$org" --ledger-id "$(id "$org")" --ledger "$(dir core)" > /dev/null
done

step "2. The core enterprise builds the contract and deploys it on its ledger"
if [ "$(run version --json | field '["bo"] is not None')" != True ]; then
    echo "This demo needs a cexchain built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
cp "$HERE/multi-tier-split.bo" .
# The contract, without its tests (bo test runs them below).
sed '/^# Its tests/,$d' multi-tier-split.bo | sed 's/^/   | /'
# Building checks the contract and compiles it to a WebAssembly module, a
# function per action. The deploy records the code and its source, so anyone
# can rebuild the code and read the terms it enforces. (The warning says the
# comments are published with it.)
run bo build multi-tier-split.bo 2>&1 | indent
# The contract's own tests: each runs on an instance of its own, parts
# included, as the ledger would run the calls.
run bo test multi-tier-split.bo | tail -n 1 | indent
CONTRACT="$(run contract deploy --bo multi-tier-split.bo --as core-root.key --ledger "$(dir core)" \
    --json 2> /dev/null | field '["contract"]["id"]')"
say "Deployed as ${CONTRACT:0:16}... What splitting means, in the contract text every party"
say "confirms (here in Simplified Chinese):"
run contract explain "$CONTRACT" --language zh-Hans-CN --ledger "$(dir core)" \
    | sed -n '/^4.1 /,/^4.2 /p' | sed '$d' | indent

step "3. The core enterprise issues the receivable to its tier-1 supplier"
# Money is in the smallest unit (fen); dates in milliseconds since 1970.
DUE=1814284800000   # 2027-06-30, 00:00 in Shanghai and Hong Kong
ISSUE="{\"fields\": {\"amount\": 100000000, \"due\": $DUE, \"tier\": 1}, \"parties\": {\"issuer\": h'$CORE_ID', \"supplier\": h'$ASSEMBLY_ID'}}"
RECEIVABLE="$(run contract create "$CONTRACT" issue --args "$ISSUE" --reference "INV-2026-1014" \
    --as core-root.key --ledger "$(dir core)" --json | field '["instance"]["id"]')"
run contract instance "$RECEIVABLE" --ledger "$(dir core)" | sed -n '1,7p' | indent

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
    run peer add core --ledger-id "$(id core)" --url "$URL" --token-file "$org.token" \
        --ledger "$(dir "$org")" > /dev/null
done

# org CALL: the organization reviews the call it is asked to consent to, and
# consents on its own ledger; the consent's evidence goes to the registrar.
consent() {
    local org="$1" call="$2" reference="$3"
    run contract consent --peer core --call "$call" --reference "$reference" --as "$org-root.key" \
        --log-key "$org-log.key" --send --ledger "$(dir "$org")" | indent
}
status_of() { run contract instance "$1" --ledger "$(dir core)" --json | field '["status"]'; }

step "5. Tier 1: the supplier splits the receivable between two tier-2 suppliers"
# CNY 600,000 to Gears Co. and CNY 400,000 to Castings Co.: one part for
# each recipient, adding up to the amount.
PARTS="{\"parts\": [60000000, 40000000], \"recipients\": [h'$GEARS_ID', h'$CASTINGS_ID']}"
say "Parts that do not add up are refused, before anyone is asked:"
run contract call "$RECEIVABLE" split --args "{\"parts\": [60000000, 30000000], \"recipients\": [h'$GEARS_ID', h'$CASTINGS_ID']}" \
    --dry-run --as core-root.key --ledger "$(dir core)" | indent
CALL="$(run contract propose "$RECEIVABLE" split --args "$PARTS" --reference "Split S-1" --peer core \
    --ledger "$(dir assembly)" --json | field '["call"]')"
say "The registrar holds call ${CALL:0:12} until the supplier and both recipients consent."
say "Gears Co. and Castings Co. are parties of nothing yet; each sees the call it is asked to"
say "consent to, with its terms:"
run contract pending --peer core --ledger "$(dir castings)" | indent
consent assembly "$CALL" "Split approved, S-1"
consent gears "$CALL" "Part accepted, G-77"
consent castings "$CALL" "Part accepted, C-12"
[ "$(status_of "$RECEIVABLE")" = divided ] || { echo "the receivable is not divided" >&2; exit 1; }
GEARS_PART="$(run contract instances --parent "$RECEIVABLE" --ledger "$(dir core)" --json | field '[0]["id"]')"
CASTINGS_PART="$(run contract instances --parent "$RECEIVABLE" --ledger "$(dir core)" --json | field '[1]["id"]')"
say "The receivable is divided and takes no more calls; its parts carry on:"
run contract instances --parent "$RECEIVABLE" --ledger "$(dir core)" | indent

step "6. Tier 2: Gears Co. splits its part, CNY 250,000 to a tier-3 supplier"
# Gears Co. keeps CNY 350,000; Forge Co., a party of nothing yet, consents.
PARTS="{\"parts\": [25000000, 35000000], \"recipients\": [h'$FORGE_ID', h'$GEARS_ID']}"
CALL="$(run contract propose "$GEARS_PART" split --args "$PARTS" --reference "Split S-2" --peer core \
    --ledger "$(dir gears)" --json | field '["call"]')"
consent gears "$CALL" "Split approved, S-2"
consent forge "$CALL" "Part accepted, F-5"
FORGE_PART="$(run contract instances --parent "$GEARS_PART" --ledger "$(dir core)" --json | field '[0]["id"]')"
KEPT_PART="$(run contract instances --parent "$GEARS_PART" --ledger "$(dir core)" --json | field '[1]["id"]')"
say "Forge Co.'s part, at depth 2 (a part of a part), tier 3:"
run contract instance "$FORGE_PART" --ledger "$(dir core)" | sed -n '1,9p' | indent
run contract instance "$FORGE_PART" --ledger "$(dir core)" --json \
    | check "the tier-3 part" 'd["depth"] == 2 and "\"tier\": 3" in d["state"] and "\"amount\": 25000000" in d["state"]'

step "7. Forge Co. pledges its part to Bank B, which verifies it offline first"
CALL="$(run contract propose "$FORGE_PART" pledge --args "{\"counterparty\": h'$BANK_ID'}" \
    --reference "Facility FC-2027-03" --peer core --ledger "$(dir forge)" --json | field '["call"]')"
consent forge "$CALL" "Pledge to Bank B, FC-2027-03"
say "Forge Co. fetches its part's evidence from the core enterprise and hands the file to the"
say "bank. The bank checks it on its own machine: every call of the part and of the instances"
say "it came from is run again, every consent is checked on the ledger that gave it, and the"
say "contract's code is rebuilt from its source."
run contract fetch --peer core --instance "$FORGE_PART" --out forge-part.cbor --ledger "$(dir forge)" > /dev/null
run contract verify forge-part.cbor --ledger-id "$CORE_ID" > verify.txt
# The report, without each call's arguments and outcome in full.
grep -vE '^ +(arguments|outcome|State) ' verify.txt | indent
run contract verify forge-part.cbor --ledger-id "$CORE_ID" --json \
    | check "the part verifies" 'd["verified"] and d["instance"]["depth"] == 2 and len(d["instance"]["ancestors"]) == 2'
say "The chain holds: the core enterprise issued CNY 1,000,000; the supplier and Gears Co."
say "agreed to each split; this part is CNY 250,000, held by Forge Co., unpledged. The bank's"
say "credit officer approves, and the bank consents on its SM3 ledger."
consent bank "$CALL" "Facility FC-2027-03 approved"
[ "$(status_of "$FORGE_PART")" = pledged ] || { echo "the part is not pledged" >&2; exit 1; }
say "Pledged. Now a party of the part, the bank fetches it itself and verifies it again:"
run contract fetch --peer core --instance "$FORGE_PART" --out pledged.cbor --ledger "$(dir bank)" | indent
run contract verify pledged.cbor --ledger-id "$CORE_ID" --json \
    | check "the pledge" 'd["verified"] and d["calls"][-1]["function"] == "pledge"'
say "A pledged part neither splits nor moves; asked anyway, the contract refuses:"
run contract call "$FORGE_PART" transfer --args "{\"counterparty\": h'$GEARS_ID'}" --dry-run \
    --as core-root.key --ledger "$(dir core)" | indent

step "8. At maturity the core enterprise pays every part"
# Paying is the core enterprise's own word; the payee is the pledgee if there
# is one (the bank), else the holder. Each payee confirms it was paid.
say "The parts that take calls:"
run contract instances --contract "$CONTRACT" --open --ledger "$(dir core)" | indent
for part in "$CASTINGS_PART" "$KEPT_PART" "$FORGE_PART"; do
    run contract call "$part" pay --reference "Payment at maturity" --as core-root.key \
        --ledger "$(dir core)" > /dev/null
done
confirm() {
    local org="$1" part="$2"
    local call
    call="$(run contract propose "$part" confirm_payment --peer core --ledger "$(dir "$org")" \
        --json | field '["call"]')"
    consent "$org" "$call" "Received in full"
}
confirm castings "$CASTINGS_PART"
confirm gears "$KEPT_PART"
confirm bank "$FORGE_PART"
for part in "$CASTINGS_PART" "$KEPT_PART" "$FORGE_PART"; do
    [ "$(status_of "$part")" = settled ] || { echo "a part is not settled" >&2; exit 1; }
done
say "Every part is settled:"
run contract instances --contract "$CONTRACT" --ledger "$(dir core)" | indent

step "9. Anyone verifies; every ledger audits clean"
run contract fetch --peer core --instance "$FORGE_PART" --out settled.cbor --ledger "$(dir bank)" > /dev/null
run contract verify settled.cbor --ledger-id "$CORE_ID" | grep -E 'Status|FINAL|rebuilds' | indent
for org in "${ORGS[@]}"; do run audit --ledger "$(dir "$org")" > /dev/null; done
say "Every ledger audits clean."
say "What each holder sees: a part's evidence carries the history of the instances it came"
say "from up to the split that made it, the other parts of that split included (their"
say "holders and amounts), so that anyone can check the parts add up. Its own later calls"
say "stay with its own parties."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
