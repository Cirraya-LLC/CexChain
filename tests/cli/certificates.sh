#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Certificates, end to end: a kind that prints fields, a table issued in bulk
# (carried on after a stop, nothing issued twice), each certificate at a
# private address its QR code opens, printed from the default template and
# from one's own, revoked, and withdrawn.
# Usage: certificates.sh KANHE
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

export KANHE_PASSPHRASE="certificates test"
export KANHE_LEDGER="$WORK/ledger"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
unset KANHE_SERVER KANHE_TOKEN

# A command line as typed: kanhe-console is the program beside kanhe.
run() {
    case "$1" in
    kanhe-console) "$(dirname "$KANHE")/$1" "${@:2}" ;;
    *) "$KANHE" "$@" ;;
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
start_server() {
    local out="$1"; shift
    "$KANHE" serve --listen 127.0.0.1:0 --json "$@" > "$out" 2> "$out.log" &
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
fetch() { curl -s -o body.cbor -w '%{http_code}' "$1"; }
cert() { run kanhe-console certificate "$@"; }

for k in root log; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --ledger "$KANHE_LEDGER" --name "Example Academy" --root-key root.key \
    --log-key log.key --json | json 'd["ledger_id"]')"
TYPE=example.org.diploma/1

# --- A kind that prints fields ------------------------------------------------------
cat > diploma.json << 'JSON'
{"sheet": 1, "kind": "document", "type": "example.org.diploma/1", "name": "Diploma",
 "fields": [{"name": "name", "label": "Name", "required": true},
            {"name": "degree", "label": "Degree", "required": true},
            {"name": "grades", "label": "Grades"},
            {"name": "year", "label": "Year", "type": "number", "private": false}],
 "files": "none", "printed": ["name", "degree", "year"], "answers": ["degree", "grades"]}
JSON
run kanhe-console kind add diploma.json > /dev/null
run kanhe-console kind show "$TYPE" | contains "printed on its certificates: name, degree, year"
[ "$(run kanhe-console kind show "$TYPE" --json | json 'd["printed"]')" = "['name', 'degree', 'year']" ]
run kanhe-console kind show "$TYPE" | contains "the console answers questions about: degree, grades"
python3 -c 'import json; d = json.load(open("diploma.json")); d["printed"] = ["nickname"]; print(json.dumps(d))' > bad.json
expect_exit 1 kanhe-console kind add bad.json --replace
contains "names the kind's own fields" out.txt || fail "printed names its own fields"
python3 -c 'import json; d = json.load(open("diploma.json")); d["answers"] = ["grades", "grades"]; print(json.dumps(d))' > bad.json
expect_exit 1 kanhe-console kind add bad.json --replace
contains '"answers" names grades twice' out.txt

# --- The table: mistakes name their line -------------------------------------------
issue() { cert issue "$TYPE" --as root.key "$@"; }
printf 'Name,Degree\nAlice,\n' > missing.csv
expect_exit 1 kanhe-console certificate issue "$TYPE" --as root.key --csv missing.csv --out x.csv
contains "line 2: the field Degree is required" out.txt || fail "a missing value"
printf 'Name,Nickname\nAlice,Al\n' > unknown.csv
expect_exit 1 kanhe-console certificate issue "$TYPE" --as root.key --csv unknown.csv --out x.csv
contains 'line 1: the kind Diploma has no field "Nickname"' out.txt || fail "an unknown column"
printf 'Name,Degree,Year\nBob,BSc,soon\n' > year.csv
expect_exit 1 kanhe-console certificate issue "$TYPE" --as root.key --csv year.csv --out x.csv
contains "line 2: the field Year is a number" out.txt || fail "a value of the wrong type"
printf 'Name,Degree\n"Bob,BSc\n' > open.csv
expect_exit 1 kanhe-console certificate issue "$TYPE" --as root.key --csv open.csv --out x.csv
contains "never closed" out.txt || fail "an open quote"
[ ! -e x.csv ] || fail "nothing issued from a wrong table"

# A byte order mark, labels and names as headings, quoted commas, CRLF, a blank line.
printf '\xEF\xBB\xBFName,Degree,grades,Year\r\n"Chan, Tai Man",BSc,"A, A, B",2026\r\nWong Siu Ming,MSc,,2026\r\n\r\nLee Ka Yan,BA & MA,B,2025\r\n' > table.csv
[ "$(issue --csv table.csv --out issued.csv --dry-run --json | json 'd["to_issue"]')" = 3 ]
[ ! -e issued.csv ] || fail "a dry run issues nothing"

# --- Issued, stopped halfway, carried on --------------------------------------------
issue --csv table.csv --out issued.csv --url https://academy.example | contains "issued 3 certificates"
stat -c %a issued.csv 2> /dev/null | contains -x 600 || stat -f %Lp issued.csv | contains -x 600 ||
    fail "the list is kept privately"
[ "$(wc -l < issued.csv | tr -d ' ')" = 7 ] || fail "issued, then published, each row"
# As if it stopped after issuing the last row, before publishing it.
run record unpublish "$(tail -n 1 issued.csv | cut -d, -f4)" > /dev/null
sed '$d' issued.csv > cut.csv && mv cut.csv issued.csv
R="$(issue --csv table.csv --out issued.csv --url https://academy.example --json)"
[ "$(echo "$R" | json 'd["issued"]')" = 1 ] && [ "$(echo "$R" | json 'd["already"]')" = 2 ] ||
    fail "carried on: $R"
[ "$(run record list --type "$TYPE" --json | json 'len(d)')" = 3 ] || fail "nothing issued twice"
[ "$(issue --csv table.csv --out issued.csv --json | json 'd["issued"]')" = 0 ] || fail "all done"
sed 's/Wong Siu Ming,MSc/Wong Siu Ming,PhD/' table.csv > changed.csv
expect_exit 2 kanhe-console certificate issue "$TYPE" --as root.key --csv changed.csv --out issued.csv
contains "line 3 of changed.csv changed since it was issued" out.txt || fail "a changed row"

# --- Listed and shown ----------------------------------------------------------------
LIST="$(cert list --json)"
[ "$(echo "$LIST" | json 'len(d)')" = 3 ] || fail "three certificates"
TOKEN="$(echo "$LIST" | json '[c for c in d if c["fields"][0]["value"] == "Chan, Tai Man"][0]["token"]')"
WONG="$(echo "$LIST" | json '[c for c in d if c["fields"][0]["value"] == "Wong Siu Ming"][0]["token"]')"
LEE="$(echo "$LIST" | json '[c for c in d if c["fields"][0]["value"] == "Lee Ka Yan"][0]["token"]')"
echo "$LIST" | json '[(f["label"], f["value"]) for f in d[0]["fields"]]' | contains "('Year', '2026')" ||
    fail "a public printed field, from the metadata"
! echo "$LIST" | contains "A, A, B" || fail "the grades are not printed"
cert list | contains "Chan, Tai Man, BSc, 2026"
SHOW="$(cert show "$TOKEN" --url https://academy.example --json)"
[ "$(echo "$SHOW" | json 'd["status"]')" = valid ]
echo "$SHOW" | json 'd["verify_url"]' |
    contains "^https://kanhe.cirraya.com/verify/#l=$LEDGER_ID&r=[0-9a-f]\{64\}&b=https://academy.example/c/$TOKEN$" ||
    fail "the link its QR code holds"
cert show "$TOKEN" --url https://academy.example --language zh-Hans | contains "&lang=zh-Hans"

# --- Served: what scanning gets ------------------------------------------------------
start_server server.json --ledger "$KANHE_LEDGER" --log-key log.key --checkpoint-interval 0
URL="$(json 'd["url"]' < server.json)"
[ "$(fetch "$URL/c/$TOKEN")" = 200 ] || fail "GET /c/TOKEN"
REPORT="$(run verify body.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$REPORT" | json 'd["verified"]')" = True ] || fail "the evidence verifies"
echo "$REPORT" | json 'd["disclosed_fields"]' | contains "Chan, Tai Man" || fail "the name disclosed"
! echo "$REPORT" | json 'd["disclosed_fields"]' | contains "A, A, B" || fail "the grades stay sealed"

# --- Printed ---------------------------------------------------------------------------
expect_exit 1 kanhe-console certificate print --type "$TYPE" --out pages
contains -- "--url URL" out.txt || fail "the QR code needs the server's address"
P="$(cert print --type "$TYPE" --out pages --url "$URL" --json)"
[ "$(echo "$P" | json 'len(d["printed"])')" = 3 ] || fail "three pages"
PAGE="pages/$TOKEN.html"
contains "Chan, Tai Man" "$PAGE" && contains "Example Academy" "$PAGE" && contains "<svg" "$PAGE" ||
    fail "the page"
contains "#l=$LEDGER_ID&amp;r=" "$PAGE" || fail "the link, escaped"
contains "BA &amp; MA" "pages/$LEE.html" || fail "values are escaped"
! contains "A, A, B" "$PAGE" || fail "the grades are not printed"
contains 'lang="en"' "$PAGE" && contains "Scan the code" "$PAGE"
cert print "$TOKEN" --out zh --url "$URL" --language zh-Hant > /dev/null
contains "簽發日期" "zh/$TOKEN.html" && contains "lang=zh-Hant" "zh/$TOKEN.html" || fail "in Chinese"
printf '<p>{{name}} / {{field.year}} / {{issued}}</p>{{qr}}' > own.html
cert print "$TOKEN" --out own --url "$URL" --template own.html > /dev/null
contains "<p>Chan, Tai Man / 2026 / 20" "own/$TOKEN.html" || fail "one's own template"
printf '<p>{{grades}}</p>' > sealed.html
expect_exit 1 kanhe-console certificate print "$TOKEN" --out sealed --url "$URL" --template sealed.html
contains "{{grades}}" out.txt || fail "a sealed field cannot be printed"
[ -z "$(ls sealed 2> /dev/null)" ] || fail "nothing written from a wrong template"

# --- Revoked, then withdrawn ---------------------------------------------------------
WONG_RECORD="$(echo "$LIST" | json '[c for c in d if c["token"] == "'"$WONG"'"][0]["record"]')"
run record revoke --as root.key "$WONG_RECORD" --reason "issued in error" > /dev/null
cert list | grep -- "$WONG" | contains revoked || fail "listed as revoked"
cert print --type "$TYPE" --out again --url "$URL" | contains "left out 1 revoked or replaced"
[ ! -e "again/$WONG.html" ] || fail "a revoked certificate is not printed"
expect_exit 2 kanhe-console certificate print "$WONG" --out again --url "$URL"
[ "$(fetch "$URL/c/$WONG")" = 200 ] || fail "the address still answers"
run verify body.cbor --ledger-id "$LEDGER_ID" --json | json 'd["record"]["revoked"]' | contains -x True ||
    fail "scanning shows it revoked"
cert withdraw "$LEE" | contains "took the certificate's address down"
[ "$(fetch "$URL/c/$LEE")" = 404 ] || fail "withdrawn"
expect_exit 2 kanhe-console certificate withdraw "$LEE"
[ "$(cert list --json | json 'len(d)')" = 2 ] || fail "two left"

# --- Through the server, the kind from its sheet --------------------------------------
run token create --ledger "$KANHE_LEDGER" ops --scope read,admin --out ops.token > /dev/null
C=(--server "$URL" --token-file ops.token --cache "$WORK/cache" --ledger-id "$LEDGER_ID")
THROUGH="$(unset KANHE_LEDGER; cert list "${C[@]}" --sheet diploma.json --json)"
[ "$(echo "$THROUGH" | json 'len(d)')" = 2 ] || fail "listed through the server"
echo "$THROUGH" | json 'd[0]["address"]' | contains "^$URL/c/" || fail "the server's address"

# --- The console's machine signs, once the organization lets it --------------------
python3 - << 'PY'
import os
def text(value):
    data = value.encode()
    return bytes([0x60 + len(data)]) + data
credential = bytes([0xa3, 0x01]) + text("localhost") + bytes([0x02, 0x50]) + os.urandom(16)
credential += bytes([0x03, 0x82, 0x32, 0x58, 0x20]) + os.urandom(32)
open("owner.passkey", "wb").write(credential)
PY
printf 'console unlock words\n' > unlock.txt
SCRIPTED="$WORK/scripted"
run kanhe-console setup --ledger "$SCRIPTED" --name "Example Academy" --credential owner.passkey \
    --unlock-file unlock.txt > /dev/null
run kanhe-console kind add diploma.json --ledger "$SCRIPTED" > /dev/null
M=(--ledger "$SCRIPTED" --machine --unlock-file unlock.txt --csv table.csv --out machine.csv)
expect_exit 2 kanhe-console certificate issue "$TYPE" "${M[@]}"
contains "no valid delegation\|may not\|delegation" out.txt || fail "not allowed yet"
expect_exit 1 kanhe-console certificate issue "$TYPE" "${M[@]}" --as root.key
cert allow "$TYPE" --ledger "$SCRIPTED" --unlock-file unlock.txt | contains "may now issue Diploma"
[ "$(cert issue "$TYPE" "${M[@]}" --json | json 'd["issued"]')" = 3 ] || fail "issued by the machine"
REC="$(cert list --ledger "$SCRIPTED" --json | json 'd[0]["record"]')"
BY="$(run record show --ledger "$SCRIPTED" "$REC" --json | json 'd["registrant"]["id"]')"
run actor show --ledger "$SCRIPTED" "$BY" --json | json 'd["kind"]' | contains -x device ||
    fail "issued by the organization's device"
run kanhe-console activity --ledger "$SCRIPTED" --json | contains "certificates.issue" ||
    fail "the console's log says so"

# Certificates as W3C credentials (spec/credentials.md): off at first; the
# console's own credential key, registered and allowed with the organization's
# root key it keeps; then a credential per certificate, its claims the printed
# fields, issued again with the same status entry.
VC=(--ledger "$SCRIPTED" --unlock-file unlock.txt --out vc --url https://academy.example)
expect_exit 2 kanhe-console certificate credential --type "$TYPE" "${VC[@]}"
contains "credential allow" out.txt || fail "credentials are off at first"
run kanhe-console credential allow --ledger "$SCRIPTED" --unlock-file unlock.txt --json > on.json
[ "$(json 'd["registered"] is not None and d["delegation"] is not None' < on.json)" = True ] ||
    fail "the credential key registered and allowed"
run kanhe-console credential allow --ledger "$SCRIPTED" --unlock-file unlock.txt | contains "on already"
run credential key list --ledger "$SCRIPTED" --json | json 'd[0]["name"]' | contains -x Credentials
cert credential --type "$TYPE" "${VC[@]}" --json > vc.json
[ "$(json 'len(d)' < vc.json)" = 3 ] || fail "a credential per certificate"
VC_TOKEN="$(json 'd[0]["token"]' < vc.json)"
VC_INDEX="$(json 'd[0]["index"]' < vc.json)"
python3 -c "import base64,json,sys; p=open(sys.argv[1]).read().split('.')[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))))" \
    "vc/$VC_TOKEN.jwt" > vc-payload.json
[ "$(json '(d["issuer"]["id"], d["name"])' < vc-payload.json)" = "('did:web:academy.example', 'Diploma')" ] ||
    fail "the issuer and the kind's name"
json 'sorted(d["credentialSubject"])' < vc-payload.json | contains -x "\['degree', 'name', 'year'\]" ||
    fail "the printed fields, the public year among them"
[ "$(run credential list --ledger "$SCRIPTED" --json | json 'len(d)')" = 3 ] || fail "the ledger shows three"
cert credential "$VC_TOKEN" "${VC[@]}" --json | json '(d[0]["again"], d[0]["index"])' |
    contains -x "(True, $VC_INDEX)" || fail "issued again: the same entry"
run kanhe-console activity --ledger "$SCRIPTED" --json | contains "credentials.allow" ||
    fail "the console's log says credentials are on"
run kanhe-console credential allow --help | contains -- '--json'
cert credential --help | contains -- '--json'

# The console's machine may answer parties' questions too, once allowed (spec v0.15).
run kanhe-console answers allow --ledger "$SCRIPTED" --unlock-file unlock.txt --json |
    json 'd["machine"]' | contains -x "$BY" || fail "the same machine answers"
run kanhe-console activity --ledger "$SCRIPTED" --json | contains "answers.allow" ||
    fail "the console's log says it may answer"
run kanhe-console answers allow --help | contains -- '--json'

for command in allow issue list show withdraw print; do
    cert "$command" --help | contains -- '--json'
done
run kanhe-console completion bash | contains 'certificate'
echo "certificates: passed"
