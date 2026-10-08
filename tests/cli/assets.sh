#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Ownership assets across five organizations, end to end (D-052): a core
# enterprise issues a receivable to its supplier; the supplier and a bank
# consent to a pledge on their own ledgers, and the core enterprise's
# registrar records it; a second bank's pledge is refused; the pledge is
# released, the receivable transferred, paid, disputed, paid again, and
# settled. A warehouse's receipt is pledged and redeemed in parts, with
# consents carried as files. Everyone verifies the chain of title offline.
# Usage: assets.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="assets test"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN CEXCHAIN_SERVER

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
start_server() {
    local out="$1"; shift
    "$CEXCHAIN" serve --listen 127.0.0.1:0 --json --quiet "$@" > "$out" 2> "$out.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        if [ -s "$out" ] && python3 -c "import json; json.load(open('$out'))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    cat "$out.log"
    fail "the server did not start"
}

D="$WORK/core"; S="$WORK/supplier"; B="$WORK/bank"; C="$WORK/bank2"; W="$WORK/warehouse"
d() { run "$@" --ledger "$D"; }
s() { run "$@" --ledger "$S"; }
b() { run "$@" --ledger "$B"; }
c() { run "$@" --ledger "$C"; }
w() { run "$@" --ledger "$W"; }

# --- Five organizations ------------------------------------------------------------
for k in d s b c w; do
    run key generate --out "$k-root.key" > /dev/null
    run key generate --out "$k-log.key" > /dev/null
done
run init --org "Core Enterprise" --root-key d-root.key --log-key d-log.key --ledger "$D" > /dev/null
run init --org "Supplier" --root-key s-root.key --log-key s-log.key --ledger "$S" > /dev/null
run init --org "Bank" --root-key b-root.key --log-key b-log.key --ledger "$B" > /dev/null
run init --org "Second Bank" --root-key c-root.key --log-key c-log.key --ledger "$C" > /dev/null
run init --org "Warehouse" --root-key w-root.key --log-key w-log.key --ledger "$W" > /dev/null
D_ID="$(d status --json | json 'd["ledger_id"]')"
S_ID="$(s status --json | json 'd["ledger_id"]')"
B_ID="$(b status --json | json 'd["ledger_id"]')"
C_ID="$(c status --json | json 'd["ledger_id"]')"
W_ID="$(w status --json | json 'd["ledger_id"]')"
# Each learns the others' ledger ids out of band.
d peer add supplier --ledger-id "$S_ID" > /dev/null
d peer add bank --ledger-id "$B_ID" > /dev/null
d peer add bank2 --ledger-id "$C_ID" > /dev/null
s peer add bank --ledger-id "$B_ID" > /dev/null
s peer add bank2 --ledger-id "$C_ID" > /dev/null
w peer add supplier --ledger-id "$S_ID" > /dev/null
w peer add bank --ledger-id "$B_ID" > /dev/null

# The core enterprise's registrar: a device that records asset actions.
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
REGISTRAR="$(d actor add --as d-root.key --kind device --name "Asset Registrar" --key registrar.pub --json | json 'd["actor"]["id"]')"
d delegation grant --as d-root.key --to "$REGISTRAR" --allow asset-action \
    --record-types cexchain.receivable/1 > /dev/null

# --- Issuing ---------------------------------------------------------------------------
run asset issue --help | contains 'receivable or warehouse-receipt'
expect_exit 1 asset issue receivable --holder supplier --amount 10 --due 2027-01-06 \
    --as d-root.key --ledger "$D"
contains 'missing required option --field' out.txt
expect_exit 1 asset issue receivable --holder supplier --amount 10.001 --due 2027-01-06 \
    --field contract=X --as d-root.key --ledger "$D"
contains 'decimal places' out.txt
expect_exit 1 asset issue receivable --holder supplier --quantity 5 --amount 1 --due 2027-01-06 \
    --field contract=X --as d-root.key --ledger "$D"
expect_exit 2 asset issue receivable --holder "$D_ID" --amount 10 --due 2027-01-06 \
    --field contract=X --as d-root.key --ledger "$D"
contains 'another ledger than its home' out.txt
A="$(d asset issue receivable --holder supplier --amount 125000.00 --currency CNY --due 2027-01-06 \
    --title "PO-2026-0815" --field contract=PO-2026-0815 --field invoice=INV-77 \
    --as d-root.key --json | json 'd["asset"]["id"]')"
d asset show "${A:0:12}" | contains '^state:     active'
d asset show "$A" | contains '125000.00 CNY'
d asset show "$A" --json | json 'd["holder"]' | contains -x "$S_ID"
d asset list | contains 'held by supplier'
d asset list --holder bank --json | json 'len(d)' | contains -x 0
d record show "$A" | contains 'cexchain.receivable/1'
# Assets change only through asset actions.
expect_exit 2 record revoke "$A" --as d-root.key --ledger "$D"
contains 'never revoked' out.txt

# The supplier gets the evidence, with the fields disclosed, and checks it.
d checkpoint create --log-key d-log.key > /dev/null
d asset evidence "$A" --log-key d-log.key --fields '*' --out a0.cbor | contains 'wrote the evidence'
run asset verify a0.cbor --ledger-id "$D_ID" > verify0.txt
contains 'State        active' verify0.txt
contains 'invoice = INV-77' verify0.txt
run asset verify a0.cbor --ledger-id "$D_ID" --json | json 'd["asset"]["display"]' | contains -x '125000.00 CNY'
expect_exit 3 asset verify a0.cbor --ledger-id "$S_ID"
expect_exit 3 asset verify a0.cbor --ledger-id "$D_ID" --min-witnesses 1
contains '0 trusted witness cosignatures, 1 required' out.txt

# --- Online: the registrar takes consents ------------------------------------------------
for p in supplier bank bank2; do d token create "$p" --scope peer --out "$p-at-core.token" > /dev/null; done
d token create staff --scope read,submit,admin --out staff.token > /dev/null
start_server core.json --ledger "$D" --log-key d-log.key --registrar-key registrar.key
D_URL="$(json 'd["url"]' < core.json)"
s peer add core --ledger-id "$D_ID" --url "$D_URL" --token-file supplier-at-core.token > /dev/null
b peer add core --ledger-id "$D_ID" --url "$D_URL" --token-file bank-at-core.token > /dev/null
c peer add core --ledger-id "$D_ID" --url "$D_URL" --token-file bank2-at-core.token > /dev/null
b peer add supplier --ledger-id "$S_ID" > /dev/null

# The supplier asks to pledge it to the bank; the bank agrees. Each consents
# on its own ledger; the second consent completes it.
s asset consent --peer core --asset "$A" --action pledge --to bank --as s-root.key \
    --log-key s-log.key --send | contains 'core: waiting'
# The bank is no party yet: it takes the head from the evidence the supplier gave it.
expect_exit 2 asset fetch --peer core --asset "$A" --out early.cbor --ledger "$B"
contains 'only to its parties' out.txt
b asset consent --peer core --asset "$A" --action pledge --to "$B_ID" --evidence a0.cbor \
    --reference "Loan SCF-2026-0042" --as b-root.key --log-key b-log.key --send --json > pledged.json
json 'd["home_answer"]["status"]' < pledged.json | contains -x recorded
d asset show "$A" --json | json 'd["state"]' | contains -x pledged
d asset show "$A" --json | json 'd["pledgee"]' | contains -x "$B_ID"

# The bank funds only once the pledge is witnessed: here the second bank
# witnesses the core enterprise's ledger.
run key public d-log.key --out d-log.pub > /dev/null
run key generate --out c-witness.key > /dev/null
run key public c-witness.key --out c-witness.pub > /dev/null
d checkpoint create --log-key d-log.key > /dev/null
b asset fetch --peer core --asset "$A" --out a1.cbor | contains 'pledged (verified)'
expect_exit 3 asset verify a1.cbor --ledger-id "$D_ID" --witness c-witness.pub --min-witnesses 1
run witness add-log --dir c-witness --ledger-id "$D_ID" --log-key d-log.pub --name core > /dev/null
d checkpoint cosign-request --witness c-witness.pub --out request.cbor > /dev/null
run witness cosign request.cbor --dir c-witness --key c-witness.key --out cosig.cbor > /dev/null
d checkpoint add-cosignature cosig.cbor --witness c-witness.pub > /dev/null
b asset fetch --peer core --asset "$A" --out a1.cbor > /dev/null
run asset verify a1.cbor --ledger-id "$D_ID" --witness c-witness.pub --min-witnesses 1 > verify1.txt
contains 'Witnesses    1 trusted' verify1.txt
contains 'pledge' verify1.txt
contains 'consent of Supplier' verify1.txt
contains 'consent of Bank' verify1.txt
run asset verify a1.cbor --ledger-id "$D_ID" --json | json 'len(d["chain"])' | contains -x 2

# A second pledge: the supplier tries the second bank. The registrar refuses.
expect_exit 2 asset consent --peer core --asset "$A" --action pledge --to bank2 --as s-root.key \
    --log-key s-log.key --send --ledger "$S"
contains 'does not allow this action' out.txt
# A consent to the head before the pledge is stale.
expect_exit 2 asset consent --peer core --asset "$A" --action pledge --to bank2 --evidence a0.cbor \
    --as s-root.key --log-key s-log.key --send --ledger "$S"
contains 'head' out.txt
# Only the pledgee releases.
expect_exit 2 asset consent --peer core --asset "$A" --action release --as s-root.key \
    --log-key s-log.key --send --ledger "$S"
contains 'not a party' out.txt

# A court freezes it; nothing moves until it is unfrozen.
d asset record freeze "$A" --as d-root.key --reference "Court order (2026) 0101 Zhi Bao 1234" \
    | contains 'state: frozen'
expect_exit 2 asset consent --peer core --asset "$A" --action release --as b-root.key \
    --log-key b-log.key --send --ledger "$B"
d asset record unfreeze "$A" --as d-root.key | contains 'state: pledged'

# The bank releases it: one consent is all it takes.
b asset consent --peer core --asset "$A" --action release --as b-root.key --log-key b-log.key \
    --send | contains 'core: recorded'
d asset show "$A" | contains '^state:     active'

# A consent is withdrawn before use, and then refused.
s asset consent --peer core --asset "$A" --action transfer --to bank2 --as s-root.key \
    --log-key s-log.key --out withdrawn.cbor --json > w.json
s asset withdraw "$(json 'd["consent"]' < w.json)" --as s-root.key | contains 'withdrew consent'
s checkpoint create --log-key s-log.key > /dev/null
s export "$(json 'd["consent"]' < w.json)" --log-key s-log.key --out withdrawn.cbor > /dev/null
expect_exit 2 asset send withdrawn.cbor --peer core --ledger "$S"
contains 'withdrawn' out.txt

# Transferred to the second bank (it buys the receivable), paid, disputed,
# paid again, and confirmed.
s asset consent --peer core --asset "$A" --action transfer --to bank2 --as s-root.key \
    --log-key s-log.key --out transfer-s.cbor > /dev/null
c asset consent --peer core --asset "$A" --action transfer --to "$C_ID" --head \
    "$(d asset show "$A" --json | json 'd["head"]')" --as c-root.key --log-key c-log.key \
    --out transfer-c.cbor > /dev/null
s asset send transfer-s.cbor --peer core | contains 'waiting'
c asset send transfer-c.cbor --peer core | contains 'recorded'
d asset show "$A" --json | json 'd["holder"]' | contains -x "$C_ID"
d asset record pay "$A" --as d-root.key --reference "CNAPS 2026101500001" | contains 'state: paid'
c asset consent --peer core --asset "$A" --action dispute --reference "nothing arrived" \
    --as c-root.key --log-key c-log.key --send | contains 'recorded'
d asset record pay "$A" --as d-root.key --reference "CNAPS 2026101600007" | contains 'state: paid'
c asset consent --peer core --asset "$A" --action confirm --as c-root.key --log-key c-log.key \
    --send | contains 'recorded'
d asset show "$A" --json | json 'd["state"]' | contains -x settled
d asset show "$A" --json | json 'len(d["actions"])' | contains -x 9
expect_exit 2 asset record freeze "$A" --as d-root.key --ledger "$D"
contains 'no more actions' out.txt
d checkpoint create --log-key d-log.key > /dev/null
c asset fetch --peer core --asset "$A" --out a2.cbor | contains 'settled (verified)'
run asset verify a2.cbor --ledger-id "$D_ID" > verify2.txt
contains 'State        settled' verify2.txt
contains 'dispute' verify2.txt
# The former pledgee is no party now.
expect_exit 2 asset fetch --peer core --asset "$A" --out none.cbor --ledger "$B"

# Through the server, as its staff: the same answers from a verified mirror.
run asset show "$A" --server "$D_URL" --token-file staff.token --ledger-id "$D_ID" \
    --cache "$WORK/cache" --json | json 'd["state"]' | contains -x settled
run asset evidence "$A" --server "$D_URL" --token-file staff.token --ledger-id "$D_ID" \
    --cache "$WORK/cache" --out a3.cbor > /dev/null
run asset verify a3.cbor --ledger-id "$D_ID" | contains 'State        settled'

# --- Offline: consents as files, recorded by the home's people ----------------------------
R="$(w asset issue warehouse-receipt --holder supplier --quantity 100 --unit t \
    --field goods="Copper cathode, grade A" --as w-root.key --json | json 'd["asset"]["id"]')"
w asset show "$R" | contains '100 t'
w checkpoint create --log-key w-log.key > /dev/null
w asset evidence "$R" --log-key w-log.key --out r0.cbor > /dev/null
s peer add warehouse --ledger-id "$W_ID" > /dev/null
b peer add warehouse --ledger-id "$W_ID" > /dev/null
consent_file() { # LEDGER-FN ROOT LOG OUT ARGS...: a consent to an action on the receipt
    local fn="$1" root="$2" log="$3" out="$4"; shift 4
    "$fn" asset consent --peer warehouse --asset "$R" --as "$root" --log-key "$log" \
        --head "$(w asset show "$R" --json | json 'd["head"]')" --out "$out" "$@" > /dev/null
}
consent_file s s-root.key s-log.key p-s.cbor --action pledge --to bank
consent_file b b-root.key b-log.key p-b.cbor --action pledge --to "$B_ID"
expect_exit 2 asset record pledge "$R" --to bank --consent p-s.cbor --as w-root.key --ledger "$W"
contains 'one consent from each party' out.txt
w asset record pledge "$R" --to bank --consent p-s.cbor --consent p-b.cbor --as w-root.key \
    | contains 'state: pledged'
# A consent counts once: the same files again no longer match the head.
expect_exit 2 asset record pledge "$R" --to bank --consent p-s.cbor --consent p-b.cbor \
    --as w-root.key --ledger "$W"
consent_file s s-root.key s-log.key r-s.cbor --action redeem --quantity 40
consent_file b b-root.key b-log.key r-b.cbor --action redeem --quantity 40
w asset record redeem "$R" --quantity 40 --consent r-s.cbor --consent r-b.cbor --as w-root.key \
    | contains 'state: pledged'
w asset show "$R" --json | json 'd["quantity"]' | contains -x 60
consent_file b b-root.key b-log.key rel.cbor --action release
w asset record release "$R" --consent rel.cbor --as w-root.key | contains 'state: active'
consent_file s s-root.key s-log.key r2.cbor --action redeem --quantity 60
w asset record redeem "$R" --quantity 60 --consent r2.cbor --as w-root.key | contains 'state: redeemed'
w checkpoint create --log-key w-log.key > /dev/null
w asset evidence "$R" --log-key w-log.key --out r1.cbor > /dev/null
run asset verify r1.cbor --ledger-id "$W_ID" --json > r1.json
json 'd["asset"]["state"]' < r1.json | contains -x redeemed
json 'len(d["chain"])' < r1.json | contains -x 5
json 'sum(len(s["consents"]) for s in d["chain"])' < r1.json | contains -x 6

# Backups keep the consents the asset actions pin.
w backup create --out w.backup --log-key w-log.key > /dev/null
run backup restore w.backup --ledger "$WORK/restored" > /dev/null
run asset evidence "$R" --ledger "$WORK/restored" --log-key w-log.key --out r2.cbor > /dev/null
run asset verify r2.cbor --ledger-id "$W_ID" | contains 'State        redeemed'

# --- Help, completion, audits --------------------------------------------------------------
for cmd in issue show list record evidence consent withdraw send fetch verify; do
    run asset "$cmd" --help | contains 'Usage: cexchain asset'
done
run completion bash | contains 'consent'
for fn in d s b c w; do "$fn" audit | contains 'audit passed'; done
echo "assets end-to-end: ok"
