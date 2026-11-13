#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Records as W3C Verifiable Credentials (spec/credentials.md): a credential
# key registered as a device, a published certificate issued as a credential
# (its endorsement on the ledger names its status entry), the issuer's DID
# document and status lists served to anyone, the credential verified against
# its record's evidence, and found out when it lies: claims the evidence does
# not show, another key, a status list that hides a revocation. Revoked, it
# says so at once. Through a server too.
# Usage: credentials.sh KANHE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export KANHE_PASSPHRASE="credentials test"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
unset KANHE_LEDGER KANHE_SERVER KANHE_TOKEN

run() { "$KANHE" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(($1))"; }
# A JWS's header (0) or payload (1), as JSON.
part() { python3 -c "import base64,sys; p=open('$1').read().strip().split('.')[$2]; sys.stdout.write(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)).decode())"; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
start_server() {
    local out="$1"; shift
    "$KANHE" serve --json --quiet "$@" > "$out" 2> "$out.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        if [ -s "$out" ] && python3 -c "import json,sys; json.load(open('$out'))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    cat "$out.log"
    fail "the server did not start"
}
fetch() { curl -s -D headers.txt -o "$2" -w '%{http_code}' "$1"; }

for k in root log; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --ledger local --name "Example College" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
CERT="$(run record issue --ledger local --as root.key --type example.org.diploma/1 \
    --field name="Chan Siu Ming" --field programme="Nursing" --field grades="A, A, B" \
    --meta year=2026 --json | json 'd["record"]["id"]')"
TOKEN="$(run record publish --ledger local "$CERT" --disclose name,programme --json | json 'd["token"]')"

# --- A credential key: a device that may only endorse --------------------------------
expect_exit 1 credential key add Credentials --ledger local --key-out nope.key --alg ed25519 --as root.key
run key generate --out ed.key > /dev/null
expect_exit 1 credential key add Credentials --ledger local --key ed.key --as root.key
contains "esp256" out.txt
K="$(run credential key add Credentials --ledger local --key-out cred.key --as root.key \
    --types example.org.diploma/1 --json)"
KEY_ACTOR="$(echo "$K" | json 'd["actor"]')"
THUMBPRINT="$(echo "$K" | json 'd["thumbprint"]')"
[ "${#THUMBPRINT}" = 43 ] || fail "a SHA-256 JWK thumbprint"
[ "$(run credential key list --ledger local --json | json 'len(d)')" = 1 ] || fail "one credential key"
run credential key list --ledger local | contains "Credentials"
# Not a credential key: the organization's own key.
PORT="$(free_port)"
URL="http://127.0.0.1:$PORT"
expect_exit 2 credential issue "$TOKEN" --ledger local --as root.key --url "$URL" --log-key log.key
contains "not a credential key" out.txt

# --- Served: the DID document and status lists, to anyone -------------------------------
start_server server.json --ledger local --log-key log.key --checkpoint-interval 0 \
    --listen "127.0.0.1:$PORT" --credential-key cred.key --credential-url "$URL"
[ "$(json 'd["credentials"]' < server.json)" = "did:web:127.0.0.1%3A$PORT" ] || fail "the issuer's DID"
[ "$(fetch "$URL/.well-known/did.json" did.json)" = 200 ] || fail "GET the DID document"
contains -i "^access-control-allow-origin: \*" headers.txt || fail "any wallet may read it"
contains -i "^content-type: application/did+json" headers.txt || fail "a DID document's type"
[ "$(json 'd["id"]' < did.json)" = "did:web:127.0.0.1%3A$PORT" ] || fail "its id"
[ "$(json 'd["verificationMethod"][0]["id"]' < did.json)" = "did:web:127.0.0.1%3A$PORT#$THUMBPRINT" ] ||
    fail "the server's credential key, by its thumbprint"
[ "$(json 'd["service"][0]["ledger"]' < did.json)" = "$LEDGER_ID" ] || fail "the ledger named"
[ "$(fetch "$URL/did.json" did2.json)" = 200 ] || fail "GET /did.json"
cmp did.json did2.json || fail "one document"
[ "$(fetch "$URL/status/1" list.jwt)" = 404 ] || fail "no list before a credential"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/status/1")" = 405 ] || fail "GET only"

# --- Issued on the ledger directory ----------------------------------------------------
expect_exit 1 credential issue "$TOKEN" --ledger local --as cred.key --log-key log.key
contains -- "--url" out.txt
expect_exit 1 credential issue "$TOKEN" --ledger local --as cred.key --url http://example.com --log-key log.key
expect_exit 2 credential issue "$TOKEN" --ledger local --as cred.key --url "$URL" --metadata colour \
    --log-key log.key
contains "no entry colour" out.txt
I="$(run credential issue "$TOKEN" --ledger local --as cred.key --url "$URL" --name "Diploma in Nursing" \
    --metadata year --out diploma.jwt --log-key log.key --json)"
[ "$(echo "$I" | json 'd["again"]')" = False ] || fail "the first issue"
[ "$(echo "$I" | json 'd["list"]')" = 1 ] || fail "list 1"
INDEX="$(echo "$I" | json 'd["index"]')"
[ -n "$(echo "$I" | json 'd["endorsement"]')" ] || fail "an endorsement registered"
stat -c %a diploma.jwt 2> /dev/null | contains -x 600 || stat -f %Lp diploma.jwt | contains -x 600 ||
    fail "kept privately"
part diploma.jwt 0 > header.json
[ "$(json 'd["alg"], d["typ"], d["cty"]' < header.json)" = "('ES256', 'vc+jwt', 'vc')" ] || fail "the header"
[ "$(json 'd["kid"]' < header.json)" = "did:web:127.0.0.1%3A$PORT#$THUMBPRINT" ] || fail "the kid"
part diploma.jwt 1 > payload.json
[ "$(json 'd["@context"]' < payload.json)" = "['https://www.w3.org/ns/credentials/v2']" ] || fail "VCDM 2.0"
[ "$(json 'd["issuer"]["name"]' < payload.json)" = "Example College" ] || fail "the issuer's name"
[ "$(json 'd["name"]' < payload.json)" = "Diploma in Nursing" ] || fail "its name"
[ "$(json 'sorted(d["credentialSubject"].items())' < payload.json)" = \
    "[('name', 'Chan Siu Ming'), ('programme', 'Nursing'), ('year', '2026')]" ] ||
    fail "the claims: the printed fields and the metadata asked for, no more"
! contains "A, A, B" payload.json || fail "the grades stay sealed"
[ "$(json 'd["credentialStatus"]["statusListCredential"]' < payload.json)" = "$URL/status/1" ] || fail "its list"
[ "$(json 'd["credentialStatus"]["statusListIndex"]' < payload.json)" = "$INDEX" ] || fail "its index"
[ "$(json 'd["evidence"][0]["id"]' < payload.json)" = "$URL/c/$TOKEN" ] || fail "its evidence"
[ "$(json 'd["evidence"][0]["record"]' < payload.json)" = "$CERT" ] || fail "its record"
# The ledger shows it: the endorsement names the entry.
run record show --ledger local "$CERT" | contains "credential/1/$INDEX"
L="$(run credential list --ledger local --json)"
[ "$(echo "$L" | json 'len(d)')" = 1 ] || fail "one credential"
[ "$(echo "$L" | json 'd[0]["status"], d[0]["index"], d[0]["credential_key"]')" = \
    "('live', $INDEX, '$KEY_ACTOR')" ] || fail "listed"
run credential show --ledger local "$CERT" | contains "list 1, index $INDEX"
# Issued again: the same entry, no second endorsement.
J="$(run credential issue "$TOKEN" --ledger local --as cred.key --url "$URL" --name "Diploma in Nursing" \
    --metadata year --out again.jwt --log-key log.key --json)"
[ "$(echo "$J" | json 'd["again"], d["index"], d["endorsement"]')" = "(True, $INDEX, None)" ] ||
    fail "issued again: the same entry"

# --- Verified: the standard checks and the record behind it --------------------------
V="$(run credential verify diploma.jwt --allow-http --ledger-id "$LEDGER_ID" --json)" ||
    { echo "$V"; fail "the credential verifies"; }
[ "$(echo "$V" | json 'd["verified"]')" = True ] || fail "verified"
[ "$(echo "$V" | json 'd["record"]["status"], d["record"]["complete"]')" = "('live', True)" ] ||
    fail "a live record, complete evidence"
[ "$(echo "$V" | json 'd["credential_key"]["id"]')" = "$KEY_ACTOR" ] || fail "signed by the endorsing device"
[ "$(echo "$V" | json 'd["did_document"]["problems"], d["status_list"]["revoked"]')" = "([], False)" ] ||
    fail "the DID document agrees, the list says not revoked"
run credential verify diploma.jwt --allow-http --ledger-id "$LEDGER_ID" | contains "^VERIFIED"
expect_exit 1 credential verify diploma.jwt --ledger-id "$LEDGER_ID"
contains -- "--allow-http" out.txt
expect_exit 2 credential verify diploma.jwt --allow-http --ledger-id "$(printf '%064d' 0)"
# Offline, from files.
fetch "$URL/c/$TOKEN" evidence.cbor > /dev/null
fetch "$URL/status/1" list.jwt > /dev/null
contains -i "^content-type: application/vc+jwt" headers.txt || fail "a status list's type"
part list.jwt 1 | json 'd["credentialSubject"]["encodedList"][:5]' | contains -x "uH4sI" ||
    fail "u and base64url of GZIP"
run credential verify diploma.jwt --offline --evidence evidence.cbor --did-document did.json \
    --status-list list.jwt --json | json 'd["verified"]' | contains -x True
expect_exit 1 credential verify diploma.jwt --offline
run credential verify again.jwt --offline --evidence evidence.cbor --json | json 'd["verified"]' | contains -x True

# --- Lies are found out ----------------------------------------------------------------
forge() { # FILE PYTHON-EXPRESSION-ON-d: the payload changed, the signature kept
    python3 - "$1" "$2" > forged.jwt << 'PY'
import base64, json, sys
h, p, s = open(sys.argv[1]).read().strip().split(".")
d = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
exec(sys.argv[2])
p = base64.urlsafe_b64encode(json.dumps(d, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False).encode()).rstrip(b"=").decode()
print(f"{h}.{p}.{s}")
PY
}
forge diploma.jwt 'd["credentialSubject"]["programme"] = "Medicine"'
R="$(run credential verify forged.jwt --offline --evidence evidence.cbor --json || true)"
[ "$(echo "$R" | json 'd["verified"]')" = False ] || fail "a changed claim"
echo "$R" | json 'd["problems"]' | contains "programme = Medicine" || fail "named"
echo "$R" | json 'd["problems"]' | contains "signature" || fail "and the signature fails"
expect_exit 3 credential verify forged.jwt --offline --evidence evidence.cbor
# --- Revoked: the list says so at once ----------------------------------------------------
run credential revoke --ledger local --as root.key "$CERT" --reason "issued in error" > /dev/null
[ "$(fetch "$URL/status/1" list2.jwt)" = 200 ] || fail "the list after a revocation"
fetch "$URL/c/$TOKEN" evidence2.cbor > /dev/null
R="$(run credential verify diploma.jwt --allow-http --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$R" | json 'd["verified"], d["record"]["status"], d["status_list"]["revoked"]')" = \
    "(True, 'revoked', True)" ] || fail "a revoked credential: verified as revoked"
run credential verify diploma.jwt --allow-http --ledger-id "$LEDGER_ID" | contains "revoked"
# A list that hides the revocation (the old one) disagrees with the ledger.
R="$(run credential verify diploma.jwt --offline --evidence evidence2.cbor --status-list list.jwt --json || true)"
[ "$(echo "$R" | json 'd["verified"]')" = False ] || fail "a list that hides a revocation"
echo "$R" | json 'd["status_list"]["problems"]' | contains "ledger says the record is revoked" ||
    fail "the disagreement named"
run credential status --ledger local --json | json 'd["revoked"][0]["index"], d["entries"]' |
    contains -x "($INDEX, 1)"
run credential status --ledger local --out static.jwt --as cred.key --url "$URL" > /dev/null
[ -s static.jwt ] || fail "a status list for a static host"
run credential did-document --ledger local --url "$URL" --out static-did.json > /dev/null
[ "$(json 'd["id"]' < static-did.json)" = "did:web:127.0.0.1%3A$PORT" ] || fail "the DID document for a static host"
expect_exit 2 credential issue "$TOKEN" --ledger local --as cred.key --url "$URL" --log-key log.key
contains "revoked" out.txt

# --- Through the server (client mode) ----------------------------------------------------
run token create --ledger local ops --scope read,submit,admin --out ops.token > /dev/null
export KANHE_SERVER="$URL" KANHE_TOKEN="$(cat ops.token)"
CACHE="$WORK/cache"
run status --cache "$CACHE" --ledger-id "$LEDGER_ID" > /dev/null
SECOND="$(run record issue --cache "$CACHE" --as root.key --type example.org.diploma/1 \
    --field name="Wong Siu Ming" --field programme="Midwifery" --json | json 'd["record"]["id"]')"
T2="$(run record publish --cache "$CACHE" "$SECOND" --disclose name,programme \
    --vault-key local/vault/vault.key --json | json 'd["token"]')"
expect_exit 1 credential issue "$T2" --cache "$CACHE" --as cred.key --log-key log.key
C2="$(run credential issue "$T2" --cache "$CACHE" --as cred.key --json)"
echo "$C2" | json 'd["credential"]' > second.jwt
[ "$(echo "$C2" | json 'd["issuer"]')" = "did:web:127.0.0.1%3A$PORT" ] || fail "the server's URL by default"
[ "$(echo "$C2" | json 'd["index"]')" != "$INDEX" ] || fail "another index"
run credential verify second.jwt --allow-http --ledger-id "$LEDGER_ID" --json | json 'd["verified"]' |
    contains -x True
[ "$(run credential list --cache "$CACHE" --json | json 'len(d)')" = 2 ] || fail "two credentials"
unset KANHE_SERVER KANHE_TOKEN

# --- A credential key revoked: its keys leave the DID document ------------------------
run credential key revoke --ledger local --as root.key "${KEY_ACTOR:0:12}" --reason "lost" > /dev/null
[ "$(fetch "$URL/.well-known/did.json" did3.json)" = 503 ] || fail "a server whose key was revoked"
run credential did-document --ledger local --url "$URL" --json | json 'd["verificationMethod"]' |
    contains -x "\[\]" || fail "no keys left"
echo "SMOKE: credentials OK"
