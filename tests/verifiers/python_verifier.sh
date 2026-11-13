#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The independent Python verifier (verifiers/python), written from the
# specification only, against `kanhe verify` and `kanhe contract
# verify`: both read the same evidence, made here with the command line, and
# must reach the same verdict and report the same facts (the record or the
# instance, its events or calls with their outcomes, consents, requests and
# answers, who acted under whose authority, presence, provenance, witnesses,
# open witness networks' cosignatures, time-stamps, completeness). Damaged
# evidence must fail in both. Evidence
# packed from the independent test vectors (testvectors/), and the contract
# evidence the examples leave behind, must verify in both. Ledgers forged at
# the specification's edges show where the two agree and where the text
# leaves the outcome open.
#
# Usage: python_verifier.sh KANHE [PYTHON]
#   PYTHON: a Python 3.11+ with the packages of
#   verifiers/python/requirements.txt; default $KANHE_PYTHON, or python3.
#   `openssl` (3.5+) must be on PATH.
# Without such a Python the test is skipped (exit 77), unless PYTHON or
# KANHE_PYTHON names one: then it fails.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
PYTHON="${2:-${KANHE_PYTHON:-python3}}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFIER="$REPO/verifiers/python"
if ! "$PYTHON" -c 'import sys; from cryptography.hazmat.primitives.asymmetric import mldsa
sys.exit(sys.version_info < (3, 11))' 2> /dev/null; then
    echo "$PYTHON is not a Python 3.11+ with verifiers/python/requirements.txt installed"
    [ -z "${2:-${KANHE_PYTHON:-}}" ] || exit 1
    echo "skipped"
    exit 77
fi
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export KANHE_PASSPHRASE="python verifier test"
unset KANHE_SERVER KANHE_TOKEN KANHE_CLOCK_OFFSET
export KANHE_LEDGER="$WORK/a"

run() { "$KANHE" "$@"; }
pyverify() { PYTHONPATH="$VERIFIER" "$PYTHON" -m kanhe_verify "$@"; }
mutate() { "$PYTHON" "$VERIFIER/tests/mutate.py" "$@"; }
json() { "$PYTHON" -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
fail() { echo "FAIL: $*"; exit 1; }
key() { run key generate --out "$1.key" ${2:+--alg "$2"} > /dev/null && run key public "$1.key" --out "$1.pub" > /dev/null; }
actor() { run actor add "$@" --json | json 'd["actor"]["id"]'; }
grant() { run delegation grant "$@" --json | json 'd["delegation"]["id"]'; }
issue() { run record issue "$@" --json | json 'd["record"]["id"]'; }

COMPARED=0
# compare NAME BUNDLE EXPECT [verify options...]: both verifiers, one bundle.
# EXPECT is verified, failed, or any (they need only agree). With KNOWN set
# (a regular expression), differences at the report fields whose paths match
# it are known ones: printed, and not failures.
compare() {
    local name="$1" bundle="$2" expect="$3"
    shift 3
    local pe=0 be=0
    pyverify "$bundle" --json "$@" > py.json 2> py.err || pe=$?
    run verify "$bundle" --json "$@" > bb.json 2> bb.err || be=$?
    local args=(py.json "$pe" bb.json "$be")
    [ "$expect" = any ] || args+=(--expect "$expect")
    [ -z "${KNOWN:-}" ] || args+=(--known "$KNOWN")
    if ! "$PYTHON" "$VERIFIER/tests/compare_reports.py" "${args[@]}" > cmp.txt; then
        cat cmp.txt py.err bb.err
        fail "$name"
    fi
    COMPARED=$((COMPARED + 1))
    local verdict
    verdict="$(json '("failed: " + d.get("error", "a check beside the bundle")) if not d.get("verified") else ("verified, complete" if d.get("complete") else "verified, not complete")' < py.json)"
    echo "  agree: $name ($verdict)"
    grep note: cmp.txt || true
}

# damage NAME BUNDLE EXPECT OPERATION [ARGUMENT] [-- verify options...]
damage() {
    local name="$1" bundle="$2" expect="$3" op="$4"
    shift 4
    local arg=()
    if [ $# -gt 0 ] && [ "$1" != "--" ]; then arg=("$1"); shift; fi
    [ $# -gt 0 ] && [ "$1" = "--" ] && shift
    mutate "$bundle" damaged.cbor "$op" ${arg[@]+"${arg[@]}"}
    compare "$name" damaged.cbor "$expect" "$@"
}

# --- Ledger A: SHA-256; people, an AI agent, a device; chains of delegations
echo "Ledger A: a record by an AI agent, endorsed through delegation chains"
key root; key log; key log2; key root2; key reviewer esp256; key reviewer2; key bot; key dev ml-dsa-65; key dev2
key clerk sm2-sm3; key wit1; key wit2 esp256
LEDGER_A="$(run init --name "Example Lab" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
REVIEWER="$(actor --as root.key --kind person --name Reviewer --key reviewer.pub)"
CLERK="$(actor --as root.key --kind person --name Clerk --key clerk.pub)"
DEV="$(actor --as root.key --kind device --name "Scale 7" --key dev.pub)"
D_REVIEWER="$(grant --as root.key --to "$REVIEWER" --allow actor-register,actor-revoke,delegation-grant,delegation-revoke,record-register,record-endorse,record-revoke --may-delegate --until 2030-01-01)"
BOT="$(actor --as reviewer.key --kind agent --name "Drafting Bot" --key bot.pub --responsible "$REVIEWER" --model model-x --runtime "test runtime")"
D_BOT="$(grant --as reviewer.key --to "$BOT" --allow record-register,record-endorse --record-types example.org.report/1,example.org.report/2 --until 2029-01-01)"
grant --as root.key --to "$DEV" --allow record-endorse,record-transition,record-revoke > /dev/null
grant --as reviewer.key --to "$CLERK" --allow record-endorse --until 2029-06-01 > /dev/null
OTHER="$(issue --as reviewer.key --type example.org.note/1 --field text="not this one")"
echo "a lab report" > report.pdf
echo "a photograph" > photo.jpg
R1="$(issue --as bot.key --type example.org.report/1 --field title="Flange test" --field result=pass \
    --field units=120 --meta lab=North --meta batch=B-7 --attach report.pdf --attach photo.jpg \
    --model model-x --model-version 2026-11 --inputs "the measurements")"
run record endorse "$R1" --as reviewer.key --role reviewer > /dev/null
run record endorse "$R1" --as dev.key --role instrument > /dev/null
run record endorse "$R1" --as clerk.key --role witness > /dev/null
run record endorse "$R1" --as bot.key --role drafter --model model-y > /dev/null
run checkpoint create --log-key log.key > /dev/null
run export "$R1" --log-key log.key --disclose title,result --with-attachments --out a-r1.cbor > /dev/null
compare "agent's record, four endorsers, disclosures, attachments" a-r1.cbor verified \
    --ledger-id "$LEDGER_A" --attachment report.pdf=report.pdf
compare "the same, without the expected ledger id" a-r1.cbor verified
compare "the same, for another ledger id" a-r1.cbor failed --ledger-id "$(printf '0%.0s' {1..64})"
compare "a wrong attachment content" a-r1.cbor failed --ledger-id "$LEDGER_A" \
    --attachment report.pdf=photo.jpg --attachment photo.jpg=photo.jpg
run export "$R1" --log-key log.key --out a-r1-plain.cbor > /dev/null
compare "no disclosures, no openings" a-r1-plain.cbor verified --attachment report.pdf=report.pdf

echo "Ledger A: keys rotated, a delegation and the agent revoked, the record revoked and superseded"
run actor rotate-key "$REVIEWER" --as root.key --new-key reviewer2.pub > /dev/null
run actor rotate-key "$DEV" --as dev.key --new-key dev2.pub > /dev/null
run delegation revoke "$D_BOT" --as reviewer2.key --reason "project over" > /dev/null
run actor revoke "$BOT" --as reviewer2.key --reason retired > /dev/null
run record revoke "$R1" --as dev2.key --reason "a corrected report replaces it" > /dev/null
R2="$(issue --as reviewer2.key --type example.org.report/2 --field title="Flange test, corrected" --supersedes "$R1")"
run checkpoint create --log-key log.key > /dev/null
run export "$R1" --log-key log.key --disclose units --out a-r1-later.cbor > /dev/null
compare "the old version: revoked, superseded, its signers since revoked" a-r1-later.cbor verified --ledger-id "$LEDGER_A"
run export "$R2" --log-key log.key --out a-r2.cbor > /dev/null
compare "the new version, whose old one the bundle does not hold" a-r2.cbor verified --ledger-id "$LEDGER_A"

echo "Ledger A: witnesses, rotations of the log and root keys, a mechanism type"
run ledger genesis --out genesis.cbor > /dev/null
for w in 1 2; do
    run witness add-log --dir "w$w" --genesis genesis.cbor --ledger-id "$LEDGER_A" --name lab > /dev/null
    run checkpoint cosign-request --witness "wit$w.pub" --out "req$w.cbor" --from 0 > /dev/null
    run witness cosign "req$w.cbor" --dir "w$w" --key "wit$w.key" --out "cosig$w.cbor" > /dev/null
    run checkpoint add-cosignature "cosig$w.cbor" --witness "wit$w.pub" > /dev/null
done
run export "$R2" --log-key log.key --out a-r2-witnessed.cbor > /dev/null
compare "two cosignatures, one witness trusted" a-r2-witnessed.cbor verified --witness wit1.pub
run ledger rotate-log-key --as root.key --new-key log2.pub > /dev/null
run ledger rotate-root-key --as root.key --new-key root2.pub > /dev/null
REQ="$(issue --as reviewer2.key --type kanhe.access-request/1 --field note="ask for the logs" --meta purpose=audit)"
run record transition "$REQ" --as dev2.key --to withdrawn > /dev/null
run record endorse "$R2" --as root2.key --role approver > /dev/null
run checkpoint create --log-key log2.key > /dev/null
for w in 1 2; do
    run checkpoint cosign-request --witness "wit$w.pub" --out "req$w.cbor" > /dev/null
    run witness cosign "req$w.cbor" --dir "w$w" --key "wit$w.key" --out "cosig$w.cbor" > /dev/null
    run checkpoint add-cosignature "cosig$w.cbor" --witness "wit$w.pub" > /dev/null
done
run export "$R2" --log-key log2.key --out a-r2-rotated.cbor > /dev/null
compare "after both rotations, witnesses that followed them" a-r2-rotated.cbor verified --ledger-id "$LEDGER_A" \
    --witness wit1.pub --witness wit2.pub
compare "one witness trusted" a-r2-rotated.cbor verified --witness wit2.pub
compare "more trusted witnesses required than cosigned" a-r2-rotated.cbor failed --witness wit1.pub --min-witnesses 2
run export "$REQ" --log-key log2.key --out a-req.cbor > /dev/null
compare "an access request, withdrawn" a-req.cbor verified --ledger-id "$LEDGER_A"
run export "$OTHER" --log-key log2.key --out a-other.cbor > /dev/null
compare "an untouched record after the rotations" a-other.cbor verified --ledger-id "$LEDGER_A"

# --- Ledger B: SM3, SM2 keys, an ML-DSA log key, an SM2 witness ------------
echo "Ledger B: SM3 with SM2 keys"
export KANHE_LEDGER="$WORK/b"
key broot sm2-sm3; key blog sm2-sm3; key blog2 ml-dsa-44; key officer sm2-sm3; key bdev esp256; key bwit sm2-sm3
LEDGER_B="$(run init --name "Example Registry" --hash sm3 --root-key broot.key --log-key blog.key --json | json 'd["ledger_id"]')"
OFFICER="$(actor --as broot.key --kind person --name Officer --key officer.pub)"
BDEV="$(actor --as broot.key --kind device --name Reader --key bdev.pub)"
grant --as broot.key --to "$OFFICER" --allow record-register,record-endorse,record-revoke --record-types example.org.permit/1,example.org.permit/2 > /dev/null
grant --as broot.key --to "$BDEV" --allow record-endorse > /dev/null
B1="$(issue --as officer.key --type example.org.permit/1 --field holder="Example Shop" --field number=42 --meta district=7)"
run record endorse "$B1" --as bdev.key --role inspector > /dev/null
run checkpoint create --log-key blog.key > /dev/null
run ledger genesis --out bgenesis.cbor > /dev/null
run witness add-log --dir bw --genesis bgenesis.cbor --ledger-id "$LEDGER_B" --name registry > /dev/null
run checkpoint cosign-request --witness bwit.pub --out breq.cbor --from 0 > /dev/null
run witness cosign breq.cbor --dir bw --key bwit.key --out bcosig.cbor > /dev/null
run checkpoint add-cosignature bcosig.cbor --witness bwit.pub > /dev/null
run export "$B1" --log-key blog.key --disclose holder,number --out b-b1.cbor > /dev/null
compare "SM3 ledger, SM2 signatures, an SM2 witness" b-b1.cbor verified --ledger-id "$LEDGER_B" --witness bwit.pub
run ledger rotate-log-key --as broot.key --new-key blog2.pub > /dev/null
B2="$(issue --as officer.key --type example.org.permit/2 --field holder="Example Shop" --supersedes "$B1")"
run checkpoint create --log-key blog2.key > /dev/null
run checkpoint cosign-request --witness bwit.pub --out breq.cbor > /dev/null
run witness cosign breq.cbor --dir bw --key bwit.key --out bcosig.cbor > /dev/null
run checkpoint add-cosignature bcosig.cbor --witness bwit.pub > /dev/null
run export "$B1" --log-key blog2.key --out b-b1-later.cbor > /dev/null
compare "SM3, after a rotation to an ML-DSA log key, superseded" b-b1-later.cbor verified --ledger-id "$LEDGER_B" --witness bwit.pub
run export "$B2" --log-key blog2.key --out b-b2.cbor > /dev/null
compare "SM3, the new version" b-b2.cbor verified --ledger-id "$LEDGER_B" --witness bwit.pub

# --- Time-stamp authorities (RFC 3161, OpenSSL's responder) ------------------
echo "Time-stamps: two authorities, SHA-256 and SM3 ledgers, the clock rule"
authority() { # NAME: a root and its time-stamping authority
    local n="$1"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$n-root.key.pem" \
        -out "$n-root.pem" -days 3650 -subj "/CN=Test Root $n" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2> /dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$n-tsa.key.pem" -out "$n.csr" \
        -subj "/CN=Test TSA $n" 2> /dev/null
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n' > "$n.ext"
    openssl x509 -req -in "$n.csr" -CA "$n-root.pem" -CAkey "$n-root.key.pem" -CAcreateserial \
        -out "$n-tsa.pem" -days 3650 -extfile "$n.ext" 2> /dev/null
    echo 01 > "$n.serial"
    cat > "$n.cnf" << EOF
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial = $WORK/$n.serial
crypto_device = builtin
signer_cert = $WORK/$n-tsa.pem
certs = $WORK/$n-root.pem
signer_key = $WORK/$n-tsa.key.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sm3
accuracy = secs:1
clock_precision_digits = 3
ess_cert_id_alg = sha256
EOF
}
token() { # CNF IMPRINT HASH OUT
    openssl ts -query -digest "$2" "-$3" -cert -out q.tsq 2> /dev/null
    openssl ts -reply -config "$1" -queryfile q.tsq -token_out -out "$4" 2> /dev/null
}
stamp() { # CNF HASH: stamp the ledger's latest checkpoint
    token "$1" "$(run checkpoint show --json | json 'd["timestamp_imprint"]')" "$2" t.tst
    run checkpoint add-timestamp t.tst > /dev/null
}
authority one
authority two
export KANHE_LEDGER="$WORK/c"
key croot; key clog
run init --name "Stamped Org" --root-key croot.key --log-key clog.key > /dev/null
C1="$(issue --as croot.key --type example.org.deed/1 --field parcel=12)"
run checkpoint create --log-key clog.key > /dev/null
stamp one.cnf sha256
run record endorse "$C1" --as croot.key --role notary > /dev/null
C2="$(issue --as croot.key --type example.org.deed/1 --field parcel=13)"
run checkpoint create --log-key clog.key > /dev/null
stamp two.cnf sha256
stamp one.cnf sha256
run record endorse "$C1" --as croot.key --role registrar > /dev/null
run record endorse "$C2" --as croot.key --role notary > /dev/null
run checkpoint create --log-key clog.key > /dev/null
run export "$C1" --log-key clog.key --out c-c1.cbor > /dev/null
run export "$C2" --log-key clog.key --out c-c2.cbor > /dev/null
compare "anchors, no authority trusted" c-c1.cbor verified
compare "anchors, one authority trusted" c-c1.cbor verified --tsa-root one-root.pem
compare "anchors, both authorities trusted" c-c1.cbor verified --tsa-root one-root.pem --tsa-root two-root.pem
compare "more trusted authorities required than stamped" c-c1.cbor failed --tsa-root two-root.pem --min-timestamps 2
compare "a record registered after the first stamp" c-c2.cbor verified --tsa-root one-root.pem --tsa-root two-root.pem
export KANHE_LEDGER="$WORK/d"
key droot sm2-sm3; key dlog sm2-sm3
run init --name "Stamped SM3 Org" --hash sm3 --root-key droot.key --log-key dlog.key > /dev/null
D1="$(issue --as droot.key --type example.org.deed/1 --field parcel=1)"
run checkpoint create --log-key dlog.key > /dev/null
stamp one.cnf sm3
run export "$D1" --log-key dlog.key --out d-d1.cbor > /dev/null
compare "an SM3 ledger's anchor, an SM3 imprint" d-d1.cbor verified --tsa-root one-root.pem
# The clock rule: a ledger whose clock runs ten minutes ahead dates entries
# later than the authority saw them.
export KANHE_LEDGER="$WORK/e"
key eroot; key elog
KANHE_CLOCK_OFFSET=10m run init --name "Fast Clock Org" --root-key eroot.key --log-key elog.key > /dev/null
E1="$(KANHE_CLOCK_OFFSET=10m issue --as eroot.key --type example.org.deed/1 --field parcel=9)"
KANHE_CLOCK_OFFSET=10m run checkpoint create --log-key elog.key > /dev/null
KANHE_CLOCK_OFFSET=10m run export "$E1" --log-key elog.key --out e-e1.cbor > /dev/null
read -r IMPRINT HASH <<< "$(mutate e-e1.cbor --imprint)"
token one.cnf "$IMPRINT" "$HASH" e.tst
mutate e-e1.cbor e-stamped.cbor add-anchor e.tst
compare "the clock rule: dated after a trusted authority saw it" e-stamped.cbor failed --tsa-root one-root.pem
compare "the same token, its authority not trusted" e-stamped.cbor verified
read -r IMPRINT HASH <<< "$(mutate c-c1.cbor --imprint)"
token one.cnf "$IMPRINT" sm3 wrong.tst
mutate c-c1.cbor c-wrong-hash.cbor add-anchor wrong.tst
compare "a token whose imprint is under another hash" c-wrong-hash.cbor failed
openssl ts -query -digest "$IMPRINT" -sha256 -out nocert.tsq 2> /dev/null # no certReq
openssl ts -reply -config one.cnf -queryfile nocert.tsq -token_out -out nocert.tst 2> /dev/null
mutate c-c1.cbor c-nocert.cbor add-anchor nocert.tst
compare "a token without its signing certificate" c-nocert.cbor failed
sed 's/^accuracy = secs:1$//' one.cnf > one-noaccuracy.cnf
token one-noaccuracy.cnf "$IMPRINT" sha256 noaccuracy.tst
mutate c-c1.cbor c-noaccuracy.cbor add-anchor noaccuracy.tst
compare "a token without an accuracy" c-noaccuracy.cbor verified --tsa-root one-root.pem
token one.cnf "$(printf 'ab%.0s' {1..32})" sha256 other.tst
mutate c-c1.cbor c-other.cbor add-anchor other.tst
compare "a token over another checkpoint" c-other.cbor failed

# --- Open witness networks (spec v0.13, section 10.2) ------------------------------
# Witnesses written from c2sp.org's texts (c2sp_witness.py, beside this
# script) cosign a SHA-256 ledger's checkpoint notes, with Ed25519 and with
# ML-DSA-44; exports carry their cosignatures in anchors.
echo "Open witness networks: C2SP witnesses' cosignatures of checkpoint notes, in anchors"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
# start_witness DIR NAME KIND LEDGER NOTE_KEY: an open network's witness of the
# ledger in LEDGER, listed there; its verifier key is then in DIR/witness.vkey.
start_witness() {
    local dir="$1" name="$2" kind="$3" ledger="$4" note="$5" entry
    entry="$(run witness network-entry --ledger "$ledger" --note-key "$note" --contact "ops (at) example.org" --json)"
    mkdir -p "$dir"
    "$PYTHON" "$REPO/tests/verifiers/c2sp_witness.py" "$dir" "$name" "$(json 'd["origin"]' <<< "$entry")" \
        "$(json 'd["vkey"]' <<< "$entry")" "$kind" 2> "$dir.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do [ -s "$dir/port" ] && break; sleep 0.1; done
    [ -s "$dir/port" ] || { cat "$dir.log"; fail "the witness $name did not start"; }
    run witness register "http://127.0.0.1:$(cat "$dir/port")/add-checkpoint" --vkey "$(cat "$dir/witness.vkey")" \
        --ledger "$ledger" > /dev/null
}
export KANHE_LEDGER="$WORK/n"
key nroot; key nlog; key nnote; key nwit esp256
N_ID="$(run init --name "Network Witnessed Org" --root-key nroot.key --log-key nlog.key --json | json 'd["ledger_id"]')"
N1="$(issue --as nroot.key --type example.org.deed/1 --field parcel=31)"
run checkpoint create --log-key nlog.key > /dev/null
start_witness nw-ed witness.example/ed25519 ed25519 "$WORK/n" nnote.key
start_witness nw-ml witness.example/ml-dsa-44 ml-dsa-44 "$WORK/n" nnote.key
NV_ED="$(cat nw-ed/witness.vkey)" NV_ML="$(cat nw-ml/witness.vkey)"
run checkpoint network-cosign --note-key nnote.key > /dev/null
run export "$N1" --log-key nlog.key --out n-n1.cbor > /dev/null
compare "two network witnesses, neither trusted" n-n1.cbor verified --ledger-id "$N_ID"
compare "the Ed25519 network witness trusted, one required" n-n1.cbor verified --witness-vkey "$NV_ED" --min-witnesses 1
compare "the ML-DSA-44 network witness trusted, one required" n-n1.cbor verified --witness-vkey "$NV_ML" \
    --min-witnesses 1
compare "both trusted, two required" n-n1.cbor verified --witness-vkey "$NV_ED" --witness-vkey "$NV_ML" --min-witnesses 2
compare "one trusted, two required" n-n1.cbor failed --witness-vkey "$NV_ML" --min-witnesses 2
compare "neither trusted, one required" n-n1.cbor failed --min-witnesses 1
# A ledger witness and a time-stamp authority on the same checkpoint: counted together.
run ledger genesis --out ngenesis.cbor > /dev/null
run witness add-log --dir nw --genesis ngenesis.cbor --ledger-id "$N_ID" --name network > /dev/null
run checkpoint cosign-request --witness nwit.pub --out nreq.cbor --from 0 > /dev/null
run witness cosign nreq.cbor --dir nw --key nwit.key --out ncosig.cbor > /dev/null
run checkpoint add-cosignature ncosig.cbor --witness nwit.pub > /dev/null
stamp one.cnf sha256
run export "$N1" --log-key nlog.key --out n-n1-all.cbor > /dev/null
compare "a ledger witness, two network witnesses, a time-stamp, all trusted, three required" n-n1-all.cbor verified \
    --witness nwit.pub --witness-vkey "$NV_ED" --witness-vkey "$NV_ML" --min-witnesses 3 --tsa-root one-root.pem \
    --min-timestamps 1
compare "the same, four required" n-n1-all.cbor failed --witness nwit.pub --witness-vkey "$NV_ED" \
    --witness-vkey "$NV_ML" --min-witnesses 4
compare "the ledger witness and one network witness trusted" n-n1-all.cbor verified --witness nwit.pub \
    --witness-vkey "$NV_ML" --min-witnesses 2
# A later checkpoint: the network's anchor is proven consistent with it; then
# one witness cosigns that one too (exports carry each witness's latest).
run record endorse "$N1" --as nroot.key --role surveyor > /dev/null
run checkpoint create --log-key nlog.key > /dev/null
run export "$N1" --log-key nlog.key --out n-n1-later.cbor > /dev/null
compare "a later checkpoint, the network's anchor proven consistent with it" n-n1-later.cbor verified \
    --witness-vkey "$NV_ED" --witness-vkey "$NV_ML" --min-witnesses 2
run checkpoint network-cosign --note-key nnote.key --witness witness.example/ed25519 > /dev/null
run export "$N1" --log-key nlog.key --out n-n1-two.cbor > /dev/null
"$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER'); from kanhe_verify import cbor
sys.exit(len([a for a in cbor.decode(open('n-n1-two.cbor', 'rb').read())[8] if 4 in a]) != 2)" \
    || fail "n-n1-two.cbor holds network cosignatures in two anchors"
compare "network cosignatures of two sizes, in two anchors" n-n1-two.cbor verified \
    --witness-vkey "$NV_ED" --witness-vkey "$NV_ML" --min-witnesses 2
compare "the same, three required" n-n1-two.cbor failed --witness-vkey "$NV_ED" --witness-vkey "$NV_ML" --min-witnesses 3
compare "the same, neither trusted" n-n1-two.cbor verified
# Damaged: a trusted witness's cosignature must verify, an untrusted one's is only counted.
for i in 0 1; do
    damage "network cosignature $i damaged, both witnesses trusted" n-n1.cbor failed break-network-cosignature "$i" \
        -- --witness-vkey "$NV_ED" --witness-vkey "$NV_ML"
    damage "network cosignature $i damaged, neither trusted" n-n1.cbor verified break-network-cosignature "$i"
    damage "network cosignature $i damaged, one witness trusted" n-n1.cbor any break-network-cosignature "$i" \
        -- --witness-vkey "$NV_ML"
    damage "network cosignature $i with another time, both trusted" n-n1.cbor failed network-time "$i" \
        -- --witness-vkey "$NV_ED" --witness-vkey "$NV_ML"
    damage "network cosignature $i with another time, neither trusted" n-n1.cbor verified network-time "$i"
done
for i in 0 1; do
    damage "n-n1-two: network cosignature $i damaged, both trusted" n-n1-two.cbor failed break-network-cosignature \
        "$i" -- --witness-vkey "$NV_ED" --witness-vkey "$NV_ML"
done
damage "network cosignatures left out, one required" n-n1.cbor failed drop-network-cosignatures \
    -- --witness-vkey "$NV_ED" --min-witnesses 1
damage "network cosignatures left out, the time-stamp kept" n-n1-all.cbor verified drop-network-cosignatures \
    -- --tsa-root one-root.pem --min-timestamps 1 --witness nwit.pub --min-witnesses 1
damage "n-n1-two: anchors left out" n-n1-two.cbor failed drop-anchors -- --witness-vkey "$NV_ED" --min-witnesses 1
# The command line: a verifier key that is no network witness's is a usage error.
N_LOG_VKEY="$(run witness network-entry --note-key nnote.key --contact x --json | json 'd["vkey"]')"
for bad in "$N_LOG_VKEY" "${NV_ED/+/ +}" "${NV_ED^^}" "${NV_ML%=}" "not a key" ""; do
    pe=0; pyverify n-n1.cbor --witness-vkey "$bad" > /dev/null 2>&1 || pe=$?
    be=0; run verify n-n1.cbor --witness-vkey "$bad" > /dev/null 2>&1 || be=$?
    [ "$pe" = 1 ] && [ "$be" = 1 ] || fail "--witness-vkey '$bad' is a usage error: python $pe, kanhe verify $be"
done
echo "  agree: verifier keys that are no network witness's are usage errors"
pyverify n-n1-two.cbor --witness-vkey "$NV_ED" | grep -q "witness.example/ed25519 saw size" || fail "the text report"

# --- Proof of presence with a hardware key (SoftHSM) -------------------------
# SoftHSM leaks what it decodes for EdDSA keys (tests/cli/lsan-softhsm.supp):
# not ours. Matching it needs full stacks, which slow ASan down, so only
# around the token's commands.
SAVED_LSAN_OPTIONS="${LSAN_OPTIONS-}" SAVED_ASAN_OPTIONS="${ASAN_OPTIONS-}"
softhsm_on() {
    export LSAN_OPTIONS="suppressions=$REPO/tests/cli/lsan-softhsm.supp${SAVED_LSAN_OPTIONS:+:$SAVED_LSAN_OPTIONS}"
    export ASAN_OPTIONS="fast_unwind_on_malloc=0${SAVED_ASAN_OPTIONS:+:$SAVED_ASAN_OPTIONS}"
}
softhsm_off() { export LSAN_OPTIONS="$SAVED_LSAN_OPTIONS" ASAN_OPTIONS="$SAVED_ASAN_OPTIONS"; }
MODULE=""
for m in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so; do
    [ -f "$m" ] && MODULE="$m" && break
done
if [ -n "$MODULE" ] && command -v softhsm2-util > /dev/null; then
    echo "Presence: a hardware key on a token (SoftHSM)"
    softhsm_on
    mkdir tokens
    printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$WORK/tokens" > softhsm2.conf
    export SOFTHSM2_CONF="$WORK/softhsm2.conf" KANHE_PKCS11_PIN=1234
    softhsm2-util --init-token --free --label Kanhe --pin 1234 --so-pin 5678 > /dev/null
    URI="pkcs11:token=Kanhe;object=ukey?module-path=$MODULE"
    run key generate --pkcs11 "$URI" --out ukey.pub > /dev/null
    export KANHE_LEDGER="$WORK/f"
    key froot; key flog; key fperson; key fperson2
    run init --name "Present Org" --root-key froot.key --log-key flog.key > /dev/null
    PERSON="$(actor --as froot.key --kind person --name Signer --key fperson.pub)"
    grant --as froot.key --to "$PERSON" --allow record-register,record-endorse --require-presence > /dev/null
    run presence enroll --pkcs11 "$URI" --label "Office UKey" --out cred.json > /dev/null
    run actor set-presence "$PERSON" --as froot.key --credential cred.json > /dev/null
    F1="$(issue --as fperson.key --type example.org.approval/1 --field decision=yes --presence-key "$URI")"
    run record endorse "$F1" --as fperson.key --role approver --presence-key "$URI" > /dev/null
    run actor rotate-key "$PERSON" --as fperson.key --new-key fperson2.pub --presence-key "$URI" > /dev/null
    run record endorse "$F1" --as fperson2.key --role signer --presence-key "$URI" > /dev/null
    run checkpoint create --log-key flog.key > /dev/null
    run export "$F1" --log-key flog.key --out f-f1.cbor > /dev/null
    compare "presence by hardware key, a self-rotation with presence" f-f1.cbor verified
    softhsm_off
else
    echo "Presence: SoftHSM not found, hardware-key presence skipped (the vectors cover passkeys)"
fi

# --- Bundles packed from the independent test vectors ------------------------
echo "Bundles packed from testvectors/ (passkeys, hardware keys, rotations, versions, mechanism types)"
"$PYTHON" "$VERIFIER/tests/vector_bundles.py" vectors > /dev/null
while read -r file ledger; do
    compare "vectors: $file" "vectors/$file" verified --ledger-id "$ledger"
done < <(json '"\n".join(x["file"] + " " + x["ledger_id"] for x in d)' < vectors/index.json)
# With protocol-v0.13.json's anchor: an Ed25519 and an ML-DSA-44 network witness.
while read -r file ledger ed ml; do
    compare "vectors: $file, both network witnesses trusted" "vectors/$file" verified --ledger-id "$ledger" \
        --witness-vkey "$ed" --witness-vkey "$ml" --min-witnesses 2
    compare "vectors: $file, neither trusted" "vectors/$file" verified --ledger-id "$ledger"
done < <(json '"\n".join(" ".join([x["file"], x["ledger_id"]] + x["vkeys"]) for x in d)' < vectors/network.json)

# --- Damaged bundles ------------------------------------------------------------
echo "Damaged bundles"
# (a-r1-plain has no attachment openings, the only bytes no signature or
# hash covers besides untrusted cosignatures.)
SIZE="$(wc -c < a-r1-plain.cbor)"
for i in $(seq 0 11); do
    damage "a-r1-plain: flipped byte $((SIZE * i / 12 + 7))" a-r1-plain.cbor failed flip "$((SIZE * i / 12 + 7))"
done
ENTRIES="$("$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER'); from kanhe_verify import cbor; print(len(cbor.decode(open('a-r1.cbor','rb').read())[2]))")"
for i in $(seq 0 $((ENTRIES - 2))); do
    damage "a-r1: entry $i left out" a-r1.cbor failed drop-entry "$i"
done
damage "a-r1: the state commitment left out, its proofs kept" a-r1.cbor failed drop-last-entry
mutate a-r1.cbor no-commitment.cbor drop-last-entry
damage "a-r1: the state commitment and the proofs left out" no-commitment.cbor verified drop-proofs
PROOFS="$("$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER'); from kanhe_verify import cbor; print(len(cbor.decode(open('a-r1.cbor','rb').read())[7]))")"
for i in $(seq 0 $((PROOFS - 1))); do
    damage "a-r1: state proof $i left out" a-r1.cbor failed drop-proof "$i"
done
damage "a-r1: receipts swapped" a-r1.cbor failed swap-receipts 1
damage "a-r1: a field disclosed twice" a-r1.cbor failed duplicate-disclosure 0
damage "a-r1: disclosures left out" a-r1.cbor verified drop-disclosures
damage "a-r1: another record as the subject" a-r1.cbor failed subject "$OTHER"
damage "a-r1-later: another version as the subject" a-r1-later.cbor failed subject "$R2"
damage "a-r2-rotated: a trusted witness's broken cosignature" a-r2-rotated.cbor failed break-cosignature 0 -- --witness wit1.pub --witness wit2.pub
damage "a-r2-rotated: an untrusted witness's broken cosignature" a-r2-rotated.cbor any break-cosignature 0
damage "a-r2-rotated: a cosignature twice" a-r2-rotated.cbor verified duplicate-cosignature 0 -- --witness wit1.pub --witness wit2.pub
damage "a-r2-rotated: cosignatures left out" a-r2-rotated.cbor verified drop-cosignatures -- --witness wit1.pub
damage "a-r2-rotated: an older checkpoint's cosignatures added, trusted" a-r2-rotated.cbor any \
    add-cosignatures-of a-r2-witnessed.cbor -- --witness wit1.pub
damage "a-r2-rotated: an older checkpoint's cosignatures added, untrusted" a-r2-rotated.cbor any \
    add-cosignatures-of a-r2-witnessed.cbor
for i in 1 2 3 4; do
    damage "a-r2-rotated: entry $i left out (rotations among them)" a-r2-rotated.cbor failed drop-entry "$i"
done
damage "b-b1-later: entry 3 left out" b-b1-later.cbor failed drop-entry 3
damage "b-b1-later: a flipped byte" b-b1-later.cbor failed flip 200
damage "c-c1: anchors left out" c-c1.cbor verified drop-anchors -- --tsa-root one-root.pem
SIZE="$(wc -c < c-c1.cbor)"
damage "c-c1: a flipped byte in an anchor's token" c-c1.cbor failed flip "$((SIZE - 300))" -- --tsa-root one-root.pem

# --- Contract evidence (spec sections 14 and 15) -----------------------------------
# Both verifiers replay every call, running the contract again, and check every
# consent a call cites on the consenting party's own ledger; their reports must
# agree field by field, as for records.
CONTRACTS=0
# ccompare NAME FILE EXPECT [contract verify options...]: both verifiers, one
# piece of contract evidence. EXPECT is verified, failed, or any.
ccompare() {
    local name="$1" file="$2" expect="$3"
    shift 3
    local pe=0 be=0
    pyverify contract "$file" --json "$@" > py.json 2> py.err || pe=$?
    run contract verify "$file" --json "$@" > bb.json 2> bb.err || be=$?
    local args=(py.json "$pe" bb.json "$be")
    [ "$expect" = any ] || args+=(--expect "$expect")
    [ -z "${KNOWN:-}" ] || args+=(--known "$KNOWN")
    if ! "$PYTHON" "$VERIFIER/tests/compare_reports.py" "${args[@]}" > cmp.txt; then
        cat cmp.txt py.err bb.err
        fail "$name"
    fi
    COMPARED=$((COMPARED + 1))
    CONTRACTS=$((CONTRACTS + 1))
    local verdict
    verdict="$(json '("failed: " + d.get("error", "?")) if not d.get("verified") else "verified, %d calls, %d consents, %d requests" % (len(d["calls"]), sum(len(c["consents"]) for c in d["calls"]), len(d["instance"]["requests"]))' < py.json)"
    echo "  agree: $name ($verdict)"
    grep note: cmp.txt || true
}
# cdamage NAME FILE EXPECT OPERATION [ARGUMENT] [-- verify options...]
cdamage() {
    local name="$1" file="$2" expect="$3" op="$4"
    shift 4
    local arg=()
    if [ $# -gt 0 ] && [ "$1" != "--" ]; then arg=("$1"); shift; fi
    [ $# -gt 0 ] && [ "$1" = "--" ] && shift
    mutate "$file" damaged.cbor "$op" ${arg[@]+"${arg[@]}"}
    ccompare "$name" damaged.cbor "$expect" "$@"
}
now_ms() { "$PYTHON" -c 'import time; print(int(time.time() * 1000))'; }
subject_of() { "$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER'); from kanhe_verify import cbor
print(cbor.decode(open(sys.argv[1], 'rb').read())[1].hex())" "$1"; }
"$PYTHON" - "$REPO/testvectors" << 'PY'
import json, sys
contracts = json.load(open(sys.argv[1] + "/test-contracts.json"))
open("split.wasm", "wb").write(bytes.fromhex(contracts["split"]))
open("requesting.wasm", "wb").write(bytes.fromhex(contracts["request"]))
open("oracle.wasm", "wb").write(bytes.fromhex(json.load(open(sys.argv[1] + "/protocol-v0.6.json"))["contract"]))
PY

echo "Contracts: a home, a SHA-256 party, an SM3 party; parts split across them, consents of every kind"
G="$WORK/g"; P="$WORK/p"; Q="$WORK/q"
g() { run "$@" --ledger "$G"; }
p() { run "$@" --ledger "$P"; }
q() { run "$@" --ledger "$Q"; }
key groot; key glog; key gclerk; key gnotifier; key gagent; key gkeeper; key proot; key plog; key pperson; key pdevice
key qroot sm2-sm3; key qlog sm2-sm3; key qofficer sm2-sm3; key qagent sm2-sm3; key gwit; key pwit esp256
G_ID="$(run init --name "Contract Home" --root-key groot.key --log-key glog.key --ledger "$G" --json | json 'd["ledger_id"]')"
P_ID="$(run init --name "Party One" --root-key proot.key --log-key plog.key --ledger "$P" --json | json 'd["ledger_id"]')"
Q_ID="$(run init --name "Party Two" --hash sm3 --root-key qroot.key --log-key qlog.key --ledger "$Q" --json | json 'd["ledger_id"]')"
PPERSON="$(p actor add --as proot.key --kind person --name "Party Clerk" --key pperson.pub --json | json 'd["actor"]["id"]')"
PDEVICE="$(p actor add --as proot.key --kind device --name "Party Signer" --key pdevice.pub --json | json 'd["actor"]["id"]')"
p delegation grant --as proot.key --to "$PPERSON" --allow record-register --record-types kanhe.contract-consent/1 > /dev/null
p delegation grant --as proot.key --to "$PDEVICE" --allow record-register > /dev/null
QOFFICER="$(q actor add --as qroot.key --kind person --name "Credit Officer" --key qofficer.pub --json | json 'd["actor"]["id"]')"
q delegation grant --as qroot.key --to "$QOFFICER" --allow actor-register,delegation-grant,record-register --may-delegate > /dev/null
QAGENT="$(q actor add --as qofficer.key --kind agent --name "Credit Agent" --key qagent.pub --responsible "$QOFFICER" \
    --model credit-model-7 --json | json 'd["actor"]["id"]')"
q delegation grant --as qofficer.key --to "$QAGENT" --allow record-register --record-types kanhe.contract-consent/1 > /dev/null
SPLIT="$(g contract deploy split.wasm --function issue=create --function split=call --function transfer=call \
    --compiler "test_contracts.py 1" --name "Receivable" --source "$REPO/tools/testvectors/test_contracts.py" \
    --as groot.key --json | json 'd["contract"]["id"]')"
head_of() { g contract instance "$1" --json | json 'd["head"]'; }
# consent PARTY_FN INSTANCE FUNCTION ARGS OUT KEY LOG_KEY [options]: a consent file from a party's ledger
consent() {
    local party="$1" instance="$2" function="$3" args="$4" out="$5" as="$6" log="$7"
    shift 7
    "$party" contract consent --home "$G_ID" --hash sha256 --instance "$instance" --function "$function" \
        --args "$args" --head "$(head_of "$instance")" --as "$as" --log-key "$log" --out "$out" "$@" > /dev/null
}
R1="$(g contract create "$SPLIT" issue --args "[h'$P_ID', 1000]" --reference INV-2026-1 --as groot.key --json \
    | json 'd["instance"]["id"]')"
# A time-stamp authority sees the receivable's creation, and nothing after it.
g checkpoint create --log-key glog.key > /dev/null
KANHE_LEDGER="$G" stamp one.cnf sha256
PARTS="[[h'$Q_ID', 600], [h'$P_ID', 400]]"
consent p "$R1" split "$PARTS" c-split1.cbor proot.key plog.key --reference "Split approved"
read -r A B <<< "$(g contract call "$R1" split --args "$PARTS" --consent c-split1.cbor --as groot.key --json \
    | json '" ".join(d["children"])')"
PARTS="[[h'$Q_ID', 300], [h'$G_ID', 300]]"
consent q "$A" split "$PARTS" c-split2.cbor qagent.key qlog.key --reference "CA-9"
read -r A1 A2 <<< "$(g contract call "$A" split --args "$PARTS" --consent c-split2.cbor --as groot.key --json \
    | json '" ".join(d["children"])')"
g contract call "$A2" transfer --args "h'$P_ID'" --as groot.key > /dev/null
consent p "$B" transfer "h'$Q_ID'" c-transfer-b.cbor pperson.key plog.key
g contract call "$B" transfer --args "h'$Q_ID'" --consent c-transfer-b.cbor --as groot.key > /dev/null
consent q "$A1" transfer "h'$P_ID'" c-transfer-a1.cbor qofficer.key qlog.key --days 1
g contract call "$A1" transfer --args "h'$P_ID'" --consent c-transfer-a1.cbor --as groot.key > /dev/null
g contract retire "$SPLIT" --reason "version 2" --as groot.key > /dev/null
consent p "$A1" transfer "h'$Q_ID'" c-transfer-a1b.cbor pdevice.key plog.key
g contract call "$A1" transfer --args "h'$Q_ID'" --consent c-transfer-a1b.cbor --as groot.key > /dev/null
for i in R1 A B A1 A2; do g contract evidence "${!i}" --log-key glog.key --out "g-$i.cbor" > /dev/null; done
ccompare "a receivable split in two, final" g-R1.cbor verified --ledger-id "$G_ID"
ccompare "a tier-2 part split again, with an AI agent's consent from an SM3 ledger" g-A.cbor verified --ledger-id "$G_ID"
ccompare "a part moved on with a person's consent" g-B.cbor verified --ledger-id "$G_ID"
ccompare "a tier-3 part: ancestors, consents of an agent, a person, a device; then retired" g-A1.cbor verified \
    --ledger-id "$G_ID"
ccompare "a part the home held, which needed no consent" g-A2.cbor verified --ledger-id "$G_ID"
ccompare "the same, without the expected ledger id" g-A1.cbor verified
ccompare "the same, for another ledger id" g-A1.cbor failed --ledger-id "$P_ID"
ccompare "a person's presence required for each consent" g-A1.cbor failed --ledger-id "$G_ID" --require-presence
ccompare "a part of its own needing no consent, its ancestors' consents without presence" g-A2.cbor failed \
    --require-presence
ccompare "requests answered required, none made" g-A1.cbor verified --require-answered
ccompare "a trusted witness required, none cosigned" g-A1.cbor failed --min-witnesses 1
pyverify contract g-A1.cbor --deploy-out py.boc > /dev/null
run contract verify g-A1.cbor --deploy-out bb.boc > /dev/null
cmp -s py.boc bb.boc || fail "the deploy files differ"
echo "  agree: the deploy file, byte for byte"

echo "Contracts: witnesses and time-stamps on the home and on a party's consent"
run ledger genesis --ledger "$G" --out ggenesis.cbor > /dev/null
run witness add-log --dir gw --genesis ggenesis.cbor --ledger-id "$G_ID" --name home > /dev/null
# The tier-3 part is the SM3 party's now: its consent, cosigned by the party's witness.
run ledger genesis --ledger "$Q" --out qgenesis.cbor > /dev/null
run witness add-log --dir pw --genesis qgenesis.cbor --ledger-id "$Q_ID" --name party > /dev/null
consent q "$A1" transfer "h'$P_ID'" c-witnessed.cbor qroot.key qlog.key
q checkpoint cosign-request --witness pwit.pub --out preq.cbor --from 0 > /dev/null
run witness cosign preq.cbor --dir pw --key pwit.key --out pcosig.cbor > /dev/null
q checkpoint add-cosignature pcosig.cbor --witness pwit.pub > /dev/null
q export "$(subject_of c-witnessed.cbor)" --log-key qlog.key --out c-witnessed2.cbor > /dev/null
g contract call "$A1" transfer --args "h'$P_ID'" --consent c-witnessed2.cbor --as groot.key > /dev/null
g checkpoint create --log-key glog.key > /dev/null
g checkpoint cosign-request --witness gwit.pub --out greq.cbor --from 0 > /dev/null
run witness cosign greq.cbor --dir gw --key gwit.key --out gcosig.cbor > /dev/null
g checkpoint add-cosignature gcosig.cbor --witness gwit.pub > /dev/null
KANHE_LEDGER="$G" stamp one.cnf sha256
g contract evidence "$A1" --log-key glog.key --out g-A1-witnessed.cbor > /dev/null
ccompare "home and party witnesses, both trusted" g-A1-witnessed.cbor verified --witness gwit.pub --witness pwit.pub \
    --min-witnesses 1
ccompare "the party's witness only" g-A1-witnessed.cbor failed --witness pwit.pub --min-witnesses 1
ccompare "a trusted time-stamp authority" g-A1-witnessed.cbor verified --tsa-root one-root.pem --min-timestamps 1
ccompare "more trusted authorities required than stamped" g-A1-witnessed.cbor failed --tsa-root one-root.pem \
    --min-timestamps 2
mutate g-A1-witnessed.cbor g-A1-inner.cbor unwrap
compare "the tier-3 part's bundle alone, as verify reports it" g-A1-inner.cbor verified --ledger-id "$G_ID" \
    --tsa-root one-root.pem --witness gwit.pub
mutate g-A1-witnessed.cbor g-consent.cbor consent 0
compare "a consent's bundle alone" g-consent.cbor verified --witness pwit.pub

echo "Contracts: open-network witnesses on the home and on a party's consent"
key gnote; key pnote
start_witness gnw witness.example/home ed25519 "$G" gnote.key
start_witness pnw witness.example/party ml-dsa-44 "$P" pnote.key
GV="$(cat gnw/witness.vkey)" PV="$(cat pnw/witness.vkey)"
# The tier-3 part is the SHA-256 party's again: its consent, cosigned by its network witness.
consent p "$A1" transfer "h'$Q_ID'" c-net.cbor proot.key plog.key
p checkpoint network-cosign --note-key pnote.key > /dev/null
p export "$(subject_of c-net.cbor)" --log-key plog.key --out c-net2.cbor > /dev/null
g contract call "$A1" transfer --args "h'$Q_ID'" --consent c-net2.cbor --as groot.key > /dev/null
g checkpoint create --log-key glog.key > /dev/null
g checkpoint network-cosign --note-key gnote.key > /dev/null
g contract evidence "$A1" --log-key glog.key --out g-A1-net.cbor > /dev/null
# Network witnesses are trusted on every ledger: the home's and each party's.
ccompare "network witnesses of the home and of a party, both trusted, one required" \
    g-A1-net.cbor verified --ledger-id "$G_ID" --witness-vkey "$GV" --witness-vkey "$PV" --min-witnesses 1
ccompare "the home's network witness trusted, two required" g-A1-net.cbor failed --witness-vkey "$GV" --min-witnesses 2
ccompare "the same, neither trusted" g-A1-net.cbor verified
ccompare "the party's network witness only, one required" g-A1-net.cbor failed \
    --witness-vkey "$PV" --min-witnesses 1
ccompare "with the ledger witnesses and the time-stamp authority too" g-A1-net.cbor \
    verified --witness gwit.pub --witness pwit.pub --witness-vkey "$GV" --witness-vkey "$PV" --tsa-root one-root.pem
cdamage "the home's network cosignature damaged, trusted" g-A1-net.cbor failed "inner:break-network-cosignature" 0 \
    -- --witness-vkey "$GV"
cdamage "the home's network cosignature damaged, not trusted" g-A1-net.cbor verified \
    "inner:break-network-cosignature" 0
cdamage "the party's network cosignature damaged: no longer the consent the call pins" g-A1-net.cbor failed \
    "consents:break-network-cosignature" 0
mutate g-A1-net.cbor g-net-consent.cbor consent "$("$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER')
from kanhe_verify import cbor
consents = cbor.decode(open('g-A1-net.cbor', 'rb').read())[2]
print(next(i for i, c in enumerate(consents) if any(4 in a for a in cbor.decode(c).get(8, []))))")"
compare "the party's consent with its network cosignature, alone" g-net-consent.cbor verified --witness-vkey "$PV" \
    --min-witnesses 1
damage "the party's consent alone, its network cosignature damaged, trusted" g-net-consent.cbor failed \
    break-network-cosignature 0 -- --witness-vkey "$PV"
damage "the party's consent alone, its network cosignature damaged, not trusted" g-net-consent.cbor verified \
    break-network-cosignature 0
for bad in "$N_LOG_VKEY" "not a key"; do
    pe=0; pyverify contract g-A1-net.cbor --witness-vkey "$bad" > /dev/null 2>&1 || pe=$?
    be=0; run contract verify g-A1-net.cbor --witness-vkey "$bad" > /dev/null 2>&1 || be=$?
    [ "$pe" = 1 ] && [ "$be" = 1 ] || fail "contract: --witness-vkey '$bad' is a usage error: python $pe, kanhe $be"
done
pyverify contract g-A1-net.cbor --witness-vkey "$GV" | grep -q "witness.example/home saw size" || fail "the contract text"

echo "Contracts: requests and answers, by executors, an AI agent, a keeper, and a person; late, expired, overdue"
GCLERK="$(g actor add --as groot.key --kind person --name "Service Clerk" --key gclerk.pub --json | json 'd["actor"]["id"]')"
GNOTIFIER="$(g actor add --as groot.key --kind device --name "Notifier" --key gnotifier.pub --json | json 'd["actor"]["id"]')"
GKEEPER="$(g actor add --as groot.key --kind device --name "Keeper" --key gkeeper.pub --json | json 'd["actor"]["id"]')"
REQ="$(g contract deploy requesting.wasm --function open=create --function ask=call --function result=call \
    --function when.due=call --compiler "test_contracts.py 1" --name "Requesting" --as groot.key --json \
    | json 'd["contract"]["id"]')"
g delegation grant --as groot.key --to "$GCLERK" --allow contract-call,actor-register,delegation-grant --contracts "$REQ" \
    --may-delegate > /dev/null
GAGENT="$(g actor add --as gclerk.key --kind agent --name "Notice Agent" --key gagent.pub --responsible "$GCLERK" \
    --model notice-model-2 --json | json 'd["actor"]["id"]')"
g delegation grant --as gclerk.key --to "$GAGENT" --allow contract-call --contracts "$REQ" --functions result \
    --request-kinds notify > /dev/null
g delegation grant --as groot.key --to "$GNOTIFIER" --allow contract-call --contracts "$REQ" --functions result \
    --request-kinds invoice,notify > /dev/null
g delegation grant --as groot.key --to "$GKEEPER" --allow contract-call --contracts "$REQ" --functions result,when.due \
    > /dev/null
NOW="$(now_ms)"
OPEN="<<[1, {1: \"open\", 2: \"opened\", 3: {\"customer\": h'$P_ID'}, 4: [[\"opened\", {\"plan\": 1}]], 7: [{1: \"notify\", 2: {\"about\": \"welcome\"}, 3: $((NOW + 3600000)), 4: \"result\"}, {1: \"http.post\", 2: {\"n\": 1}, 3: $((NOW + 60000)), 4: \"result\"}, {1: \"invoice\", 2: {\"amount\": 100}, 3: $((NOW + 7200000)), 4: \"result\"}]}]>>"
S1="$(g contract create "$REQ" open --args "$OPEN" --reference "SVC-1" --as gclerk.key --json | json 'd["instance"]["id"]')"
rid() { g request list --instance "$1" --kind "$2" --open --json | json 'd[0]["id"]'; }
g request answer "$(rid "$S1" notify)" --done --args '{"ref": "N-1"}' --as gagent.key > /dev/null
KANHE_CLOCK_OFFSET=5m g request answer "$(rid "$S1" http.post)" --done --args '{"ref": "P-1"}' --as gclerk.key \
    > /dev/null
g contract call "$S1" ask --args '[["notify", {"about": "bill"}, 600000], ["suspend", null, 86400000]]' --as gclerk.key \
    > /dev/null
g request answer "$(rid "$S1" notify)" --failed --args '[["notify", {"retry": 1}, 60000]]' --as gnotifier.key > /dev/null
KANHE_CLOCK_OFFSET=3h g request answer "$(rid "$S1" invoice)" --expired --as gkeeper.key > /dev/null
KANHE_CLOCK_OFFSET=3h g request answer "$(rid "$S1" notify)" --expired --as gkeeper.key > /dev/null
FINAL="<<[1, {1: \"closed\", 2: \"closed\", 5: true, 7: [{1: \"notify\", 2: null, 3: $((NOW + 36000000)), 4: \"result\"}]}]>>"
S2="$(KANHE_CLOCK_OFFSET=3h g contract create "$REQ" open --args "$FINAL" --as gclerk.key --json | json 'd["instance"]["id"]')"
KANHE_CLOCK_OFFSET=3h g request answer "$(rid "$S2" notify)" --done --as gnotifier.key > /dev/null
KANHE_CLOCK_OFFSET=3h g checkpoint create --log-key glog.key > /dev/null
for i in S1 S2; do g contract evidence "${!i}" --log-key glog.key --out "g-$i.cbor" > /dev/null; done
ccompare "answers done, failed, expired, on time and late; one open request" g-S1.cbor verified --ledger-id "$G_ID"
ccompare "the same, every request answered required (one is not yet due)" g-S1.cbor verified --require-answered
ccompare "a final instance that took an answer" g-S2.cbor verified --ledger-id "$G_ID"
KANHE_CLOCK_OFFSET=2d g contract call "$S1" ask --args '[["notify", {"about": "late"}, 1000]]' --as gclerk.key > /dev/null
KANHE_CLOCK_OFFSET=2d g checkpoint create --log-key glog.key > /dev/null
g contract evidence "$S1" --log-key glog.key --out g-S1-overdue.cbor > /dev/null
ccompare "open requests overdue at the checkpoint" g-S1-overdue.cbor verified --ledger-id "$G_ID"
ccompare "overdue requests, every request answered required" g-S1-overdue.cbor failed --require-answered
ccompare "overdue, and presence required too" g-S1-overdue.cbor failed --require-answered --require-presence \
    --min-timestamps 1 --tsa-root one-root.pem

echo "Contracts: an SM3 home, children without parties, values of every CBOR kind, a retired contract"
H="$WORK/h"
h() { run "$@" --ledger "$H"; }
key hroot sm2-sm3; key hlog ml-dsa-44; key hclerk
H_ID="$(run init --name "SM3 Home" --hash sm3 --root-key hroot.key --log-key hlog.key --ledger "$H" --json | json 'd["ledger_id"]')"
HCLERK="$(h actor add --as hroot.key --kind person --name "Oracle Clerk" --key hclerk.pub --json | json 'd["actor"]["id"]')"
ORACLE="$(h contract deploy oracle.wasm --function open=create --function act=call --compiler "hand-assembled 1" \
    --as hroot.key --json | json 'd["contract"]["id"]')"
h delegation grant --as hroot.key --to "$HCLERK" --allow contract-call --contracts "$ORACLE" --functions act > /dev/null
O="$(h contract create "$ORACLE" open --args "<<[1, {1: \"parent\", 2: \"open\", 3: {\"buyer\": h'$H_ID'}, 6: [{1: \"first\"}, {1: {\"second\": 2}, 2: \"draft\", 3: {\"bank\": h'$Q_ID', \"buyer\": h'$H_ID'}}]}]>>" \
    --as hroot.key --json | json 'd["instance"]["id"]')"
read -r O0 O1 <<< "$(h contract instances --parent "$O" --json | json '" ".join(i["id"] for i in d)')"
h contract call "$O" act --args '{"note": "the state becomes the hash of the input"}' --as hclerk.key > /dev/null
"$PYTHON" - "$VERIFIER" << 'PY'
import sys
sys.path.insert(0, sys.argv[1])
from kanhe_verify import cbor
T, M = cbor.Tag, cbor.Map
values = [0, 23, 24, -1, -25, 2**64 - 1, -2**64, "", 'q"uote', "back\\slash", "nl\n\t\x01\x1f\x7f", "é中😀 ",
          b"", b"\x00\xff", [], {}, [1, [2, []]], {1: "a", -1: "b", "k": 2, b"bk": 3}, M([([1], 2)]),
          M([(True, 1), (None, 2), (False, 3)]), T(1, 1700000000), T(24, b"\x01"), T(2**40, 0), True, False, None,
          {"b": 1, "a": 2, "aa": 3}, -2**63, 2**63]
open("values.cbor", "wb").write(cbor.encode({"values": values}))
PY
h contract call "$O0" act --args-cbor values.cbor --as hclerk.key > /dev/null
h contract retire "$ORACLE" --as hroot.key > /dev/null
h contract call "$O" act --args '{"after": "the retire"}' --as hroot.key > /dev/null
h contract call "$O1" act --args "<<[1, {1: \"done\", 4: [[\"done\", {\"by\": [1, 2]}]], 5: true}]>>" --as hroot.key > /dev/null
for i in O O0 O1; do h contract evidence "${!i}" --log-key hlog.key --out "h-$i.cbor" > /dev/null; done
ccompare "an SM3 home's parent, which carried on after the retire" h-O.cbor verified --ledger-id "$H_ID"
ccompare "a child without parties, called with values of every CBOR kind" h-O0.cbor verified --ledger-id "$H_ID"
ccompare "a child with parties, final" h-O1.cbor verified --ledger-id "$H_ID"

if [ -n "${URI:-}" ]; then
    echo "Contracts: a consent proven present with a hardware key (SoftHSM)"
    softhsm_on
    key ppresent
    PPRESENT="$(p actor add --as proot.key --kind person --name "Present Approver" --key ppresent.pub --json | json 'd["actor"]["id"]')"
    p delegation grant --as proot.key --to "$PPRESENT" --allow record-register --record-types kanhe.contract-consent/1 \
        --require-presence > /dev/null
    run presence enroll --pkcs11 "$URI" --label "Approver UKey" --out pcred.json > /dev/null
    p actor set-presence "$PPRESENT" --as proot.key --credential pcred.json > /dev/null
    # The splitting contract is retired: a new deploy of it creates the instance.
    SPLIT2="$(g contract deploy split.wasm --function issue=create --function split=call --function transfer=call \
        --compiler "test_contracts.py 1" --as groot.key --json | json 'd["contract"]["id"]')"
    R2="$(g contract create "$SPLIT2" issue --args "[h'$P_ID', 50]" --as groot.key --json | json 'd["instance"]["id"]')"
    consent p "$R2" transfer "h'$Q_ID'" c-present.cbor ppresent.key plog.key --presence-key "$URI"
    g contract call "$R2" transfer --args "h'$Q_ID'" --consent c-present.cbor --as groot.key > /dev/null
    g contract evidence "$R2" --log-key glog.key --out g-R2.cbor > /dev/null
    ccompare "a consent proven by a hardware key, presence required" g-R2.cbor verified --require-presence
    softhsm_off
fi

# The examples' contracts are written in Bo: they need bo beside kanhe (a
# GCC build).
if [ -x "$(dirname "$KANHE")/bo" ]; then
echo "Contracts: evidence the examples leave behind (Bo contracts, time rules, keepers, MCP, parts)"
EXAMPLES=(lending day-student supply-agreement multi-tier-split receivable-financing events)
[ -n "$MODULE" ] && EXAMPLES+=(shipment) # its driver's hardware key is SoftHSM's
for ex in "${EXAMPLES[@]}"; do
    if ! bash "$REPO/examples/$ex/$ex.sh" "$KANHE" "$WORK/ex-$ex" > "ex-$ex.log" 2>&1; then
        tail -20 "ex-$ex.log"
        fail "the example $ex"
    fi
    for f in "$WORK/ex-$ex"/*.cbor; do
        if "$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER'); from kanhe_verify import cbor, protocol
sys.exit(0 if protocol.is_contract_evidence(cbor.decode(open(sys.argv[1], 'rb').read())) else 1)" "$f" 2> /dev/null; then
            ccompare "$ex: $(basename "$f")" "$f" verified
        fi
    done
done
pyverify contract "$WORK/ex-supply-agreement/closed.cbor" --deploy-out py.boc > /dev/null
run contract verify "$WORK/ex-supply-agreement/closed.cbor" --deploy-out bb.boc > /dev/null
cmp -s py.boc bb.boc || fail "a Bo deploy file differs"
echo "  agree: a Bo contract's deploy file, byte for byte"
else
    echo "Contracts: the examples skipped (no bo beside kanhe: it is built with GCC)"
fi

echo "Contracts: the vectors' signed contract evidence (protocol v0.6, v0.7, v0.8)"
"$PYTHON" - "$REPO/testvectors" << 'PY'
import json, sys
out = []
for version in ("v0.7", "v0.8"):
    for lg in json.load(open(f"{sys.argv[1]}/protocol-{version}.json"))["ledgers"]:
        for name, e in lg["evidence"].items():
            path = f"cv-{version}-{lg['hash']}-{name.replace(' ', '-')}.cbor"
            open(path, "wb").write(bytes.fromhex(e["contract_evidence"]))
            out.append(f"{path} {lg['ledger_id']}")
for lg in json.load(open(f"{sys.argv[1]}/protocol-v0.6.json"))["ledgers"]:
    path = f"cv-v0.6-{lg['hash']}.cbor"
    open(path, "wb").write(bytes.fromhex(lg["contract_evidence"]["encoded"]))
    out.append(f"{path} {lg['ledger_id']} opaque")
open("cv.txt", "w").write("\n".join(out) + "\n")
PY
while read -r file ledger opaque; do
    if [ -n "$opaque" ]; then
        ccompare "vectors: $file (its bundles are opaque bytes)" "$file" failed --ledger-id "$ledger"
    else
        ccompare "vectors: $file" "$file" verified --ledger-id "$ledger"
        ccompare "vectors: $file, every request answered required" "$file" any --require-answered
    fi
done < cv.txt

echo "Contracts: damaged contract evidence"
mutate g-A1.cbor inner.cbor unwrap
ENTRIES="$("$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER'); from kanhe_verify import cbor; print(len(cbor.decode(open('inner.cbor','rb').read())[2]))")"
for i in $(seq 1 $((ENTRIES - 2))); do
    cdamage "g-A1: entry $i of its bundle left out" g-A1.cbor failed "inner:drop-entry" "$i"
done
PROOFS="$("$PYTHON" -c "import sys; sys.path.insert(0, '$VERIFIER'); from kanhe_verify import cbor; print(len(cbor.decode(open('inner.cbor','rb').read())[7]))")"
for i in $(seq 0 $((PROOFS - 1))); do
    cdamage "g-A1: state proof $i left out" g-A1.cbor failed "inner:drop-proof" "$i"
done
cdamage "g-A1: the state commitment and its proofs left out (not complete)" g-A1.cbor failed "inner:drop-last-entry"
cdamage "g-A1: receipts swapped" g-A1.cbor failed "inner:swap-receipts" 3
cdamage "g-A1: a consent left out" g-A1.cbor failed drop-consent 0
cdamage "g-A1: every consent left out" g-A1.cbor failed drop-consents
cdamage "g-A1: an empty list of consents" g-A1.cbor failed empty-consents
cdamage "g-A1: a consent twice" g-A1.cbor failed duplicate-consent 1
cdamage "g-A1: the consents in the other order" g-A1.cbor verified reverse-consents
cdamage "g-A1: a consent no call cites" g-A1.cbor failed add-consent g-B.cbor
cdamage "g-A1: another instance's bundle" g-A1.cbor failed bundle-of g-A.cbor
cdamage "g-A2: a consent bundle where its bundle should be" g-A2.cbor failed bundle-of c-split1.cbor
cdamage "g-S1: entry 3 of its bundle left out" g-S1.cbor failed "inner:drop-entry" 3
cdamage "g-S1: a flipped byte" g-S1.cbor failed flip 300
SIZE="$(wc -c < g-A1.cbor)"
for i in $(seq 0 9); do
    cdamage "g-A1: flipped byte $((SIZE * i / 10 + 11))" g-A1.cbor failed flip "$((SIZE * i / 10 + 11))"
done
ccompare "a record's bundle given as contract evidence" a-r1.cbor failed
compare "contract evidence given as a bundle" g-A1.cbor failed

echo "Probes of the contract rules' edges (home and party ledgers forged by the test)"
"$PYTHON" "$VERIFIER/tests/contract_probes.py" "$KANHE"

# --- Forged ledgers at the specification's edges -----------------------------------
echo "Probes of the specification's edges (ledgers forged by the test)"
"$PYTHON" "$VERIFIER/tests/probes.py" "$KANHE"
echo "Probes of open witness networks (anchors forged by the test, verified with the witnesses' verifier keys)"
"$PYTHON" "$VERIFIER/tests/network_probes.py" "$KANHE"

# --- Credentials (spec/credentials.md, section 7) -------------------------------------
# A certificate issued as a W3C credential: both verifiers check it against its
# evidence, with the DID document and status list, and agree; PyJWT, a widely used
# JOSE library, verifies its signature with the DID document's key as any wallet
# would; and every lie fails in both.
export KANHE_LEDGER="$WORK/vc"
run key generate --out vc-root.key > /dev/null
run key generate --out vc-log.key > /dev/null
VC_ID="$(run init --name "Example College" --root-key vc-root.key --log-key vc-log.key --json | json 'd["ledger_id"]')"
VC_CERT="$(issue --as vc-root.key --type example.org.diploma/1 --field name="Chan Siu Ming" \
    --field programme="Nursing" --field grades="A, A, B" --meta year=2026)"
VC_TOKEN="$(run record publish "$VC_CERT" --disclose name,programme --json | json 'd["token"]')"
run credential key add Credentials --key-out vc-cred.key --as vc-root.key > /dev/null
VC_URL="https://college.example"
run credential issue "$VC_TOKEN" --as vc-cred.key --url "$VC_URL" --name "Diploma in Nursing" --metadata year \
    --log-key vc-log.key --out vc.jwt > /dev/null
run checkpoint create --log-key vc-log.key > /dev/null
run export "$VC_CERT" --disclose name,programme --log-key vc-log.key --out vc-evidence.cbor > /dev/null
run credential did-document --url "$VC_URL" --out vc-did.json > /dev/null
run credential status --as vc-cred.key --url "$VC_URL" --out vc-list.jwt > /dev/null
vc_compare() { # CREDENTIAL EVIDENCE LIST: both verifiers, the same facts
    local c="$1" e="$2" l="$3" ours theirs
    ours="$(run credential verify "$c" --offline --evidence "$e" --did-document vc-did.json --status-list "$l" \
        --ledger-id "$VC_ID" --json || true)"
    theirs="$(pyverify credential "$c" --evidence "$e" --did-document vc-did.json --status-list "$l" \
        --ledger-id "$VC_ID" --json || true)"
    "$PYTHON" - "$ours" "$theirs" << 'PY' || fail "the verifiers disagree on a credential"
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
def facts(d):
    if not d.get("credential"):
        return {"verified": d["verified"]}
    key = d["credential_key"]
    return {"verified": d["verified"], "credential": d["credential"], "status": d["record"]["status"],
            "complete": d["record"]["complete"], "key": key and key["id"], "problems": len(d["problems"]),
            "did": d["did_document"] and len(d["did_document"]["problems"]),
            "list": d["status_list"] and (d["status_list"]["revoked"], len(d["status_list"]["problems"]))}
if facts(a) != facts(b):
    print(json.dumps(facts(a), indent=1), json.dumps(facts(b), indent=1), sep="\n")
    sys.exit(1)
print(facts(a)["verified"])
PY
}
[ "$(vc_compare vc.jwt vc-evidence.cbor vc-list.jwt)" = True ] || fail "the credential verifies in both"
COMPARED=$((COMPARED + 1))
# PyJWT, with the key the DID document gives under the credential's kid.
"$PYTHON" - vc.jwt vc-did.json << 'PY' || fail "PyJWT does not verify the credential"
import json, sys
import jwt
token = open(sys.argv[1]).read().strip()
doc = json.load(open(sys.argv[2]))
kid = jwt.get_unverified_header(token)["kid"]
method = next(m for m in doc["verificationMethod"] if m["id"] == kid)
claims = jwt.decode(token, jwt.PyJWK(method["publicKeyJwk"]).key, algorithms=["ES256"])
assert claims["@context"] == ["https://www.w3.org/ns/credentials/v2"]
assert claims["credentialSubject"]["name"] == "Chan Siu Ming"
PY
# Lies: a changed claim (signature kept), a sealed field claimed (signed anew by a
# stranger's key), and the record revoked behind a list that hides it.
"$PYTHON" - vc.jwt << 'PY' > vc-forged.jwt
import base64, json, sys
h, p, s = open(sys.argv[1]).read().strip().split(".")
d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
d["credentialSubject"]["programme"] = "Medicine"
p = base64.urlsafe_b64encode(json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
print(h + "." + p.rstrip(b"=").decode() + "." + s)
PY
[ "$(vc_compare vc-forged.jwt vc-evidence.cbor vc-list.jwt)" = False ] || fail "a changed claim fails in both"
"$PYTHON" - vc.jwt << 'PY' > vc-stranger.jwt
import base64, json, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
h, p, _ = open(sys.argv[1]).read().strip().split(".")
d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
d["credentialSubject"]["grades"] = "A, A, A"
key = ec.generate_private_key(ec.SECP256R1())
header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
p = b(json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
r, s = decode_dss_signature(key.sign((h + "." + p).encode(), ec.ECDSA(hashes.SHA256())))
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
s = min(s, n - s)
print(h + "." + p + "." + b(r.to_bytes(32, "big") + s.to_bytes(32, "big")))
PY
[ "$(vc_compare vc-stranger.jwt vc-evidence.cbor vc-list.jwt)" = False ] || fail "a stranger's signature fails in both"
run record revoke "$VC_CERT" --as vc-root.key --reason "issued in error" > /dev/null
run checkpoint create --log-key vc-log.key > /dev/null
run export "$VC_CERT" --disclose name,programme --log-key vc-log.key --out vc-revoked.cbor > /dev/null
[ "$(vc_compare vc.jwt vc-revoked.cbor vc-list.jwt)" = False ] || fail "a list that hides a revocation fails in both"
run credential status --as vc-cred.key --url "$VC_URL" --out vc-list2.jwt > /dev/null
[ "$(vc_compare vc.jwt vc-revoked.cbor vc-list2.jwt)" = True ] || fail "a revoked credential verifies as revoked"
COMPARED=$((COMPARED + 3))
code=0; pyverify credential vc.jwt > /dev/null 2>&1 || code=$?
[ "$code" = 1 ] || fail "credential: --evidence is required"
export KANHE_LEDGER="$WORK/a"

# --- The verifier's own tests against testvectors/ ---------------------------------
echo "Unit tests against testvectors/"
(cd "$VERIFIER" && "$PYTHON" -m unittest discover -s tests 2>&1 | tail -3)

# --- The command line itself ------------------------------------------------------------
pyverify a-r1.cbor --ledger-id "$LEDGER_A" > report.txt
grep -q "Verified: every statement above" report.txt || fail "the text report"
grep -q "Complete:" report.txt || fail "the text report says complete"
mutate a-r1.cbor bad.cbor drop-entry 1
code=0; pyverify bad.cbor > /dev/null || code=$?
[ "$code" = 3 ] || fail "a failure exits 3"
code=0; pyverify > /dev/null 2>&1 || code=$?
[ "$code" = 1 ] || fail "a usage error exits 1"
code=0; pyverify a-r1.cbor --ledger-id abcd > /dev/null 2>&1 || code=$?
[ "$code" = 1 ] || fail "a short ledger id is a usage error"
code=0; pyverify missing.cbor > /dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "an unreadable bundle exits 2"
pyverify --help | grep -q -- "--tsa-root" || fail "--help"
pyverify contract g-A1.cbor --ledger-id "$G_ID" > report.txt
grep -q "Verified: the instance's complete history" report.txt || fail "the contract report"
grep -q "consent of Party Two (SM3)" report.txt || fail "the contract report shows consents"
code=0; pyverify contract bad.cbor > /dev/null || code=$?
[ "$code" = 3 ] || fail "contract evidence that fails exits 3"
code=0; pyverify contract > /dev/null 2>&1 || code=$?
[ "$code" = 1 ] || fail "contract: a usage error exits 1"
code=0; pyverify contract g-A1.cbor --attachment a=b > /dev/null 2>&1 || code=$?
[ "$code" = 1 ] || fail "contract: --attachment is a usage error"
code=0; pyverify contract g-A1.cbor --ledger-id "${G_ID:0:12}" > /dev/null 2>&1 || code=$?
[ "$code" = 1 ] || fail "contract: a short ledger id is a usage error"
code=0; pyverify contract missing.cbor > /dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "contract: an unreadable file exits 2"
code=0; pyverify contract g-A1.cbor --deploy-out "$WORK/no/such/dir/x.boc" > /dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "contract: an unwritable --deploy-out exits 2"
code=0; pyverify a-r1.cbor --require-answered > /dev/null 2>&1 || code=$?
[ "$code" = 1 ] || fail "a contract option for a bundle is a usage error"
pyverify contract --help | grep -q -- "--require-answered" || fail "contract --help"

echo "python verifier against kanhe verify and contract verify: $COMPARED comparisons agree" \
    "($CONTRACTS of contract evidence); passed"
