#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Searches and reports: records and things under contracts found by what the
# ledger holds in the clear, a page at a time, and counted in groups, from the
# search index kept beside the ledger (built from the log, rebuilt when lost),
# on a directory and through a server's HTTP API.
# Usage: search.sh KANHE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export KANHE_PASSPHRASE="search test"
unset KANHE_SERVER KANHE_TOKEN
export KANHE_LEDGER="$WORK/ledger"

# A command line as typed: bo, kanhe-console, and kanhe-index are the
# programs beside kanhe.
run() {
    case "$1" in
    bo | kanhe-console | kanhe-index) "$(dirname "$KANHE")/$1" "${@:2}" ;;
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
http() {
    python3 - "$@" << 'PY'
import sys, urllib.request, urllib.error
url, token = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
request = urllib.request.Request(url)
if token:
    request.add_header("Authorization", "Bearer " + token)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status, body = response.status, response.read()
except urllib.error.HTTPError as error:
    status, body = error.code, error.read()
print(status)
sys.stdout.write(body.decode("utf-8", "replace"))
PY
}

for k in root log; do run key generate --out "$k.key" > /dev/null; done
run init --name "Search School" --root-key root.key --log-key log.key > /dev/null
app() {
    run record issue --as root.key --type example.school.application/1 --field "address=$4" \
        --meta "student=$1" --meta "class=$2" --meta "year=$3" --json | json 'd["record"]["id"]'
}
LI="$(app 李明 S5B 2025 'Hill Road')"
CHAN="$(app 陳永康 S4A 2026 'Shore Road')"
HO="$(app 何家欣 S5B 2026 'Lake Road')"
run record revoke "$CHAN" --as root.key --reason withdrawn > /dev/null
B1="$(run record issue --as root.key --type example.school.blank-form/1 --field text=v1 \
    --meta title=走讀申請表 --json | json 'd["record"]["id"]')"
B2="$(run record issue --as root.key --type example.school.blank-form/1 --field text=v2 \
    --meta title=走讀申請表 --supersedes "$B1" --json | json 'd["record"]["id"]')"

# --- Records ------------------------------------------------------------------------
[ ! -e ledger/search.sqlite ] || fail "no index before the first search"
run kanhe-index search records --type example.school.application/1 > out.txt
[ "$(grep -c example.school.application/1 out.txt)" -eq 2 ] || fail "two applications, the revoked one left out"
contains 'as of log entry' out.txt
[ -e ledger/search.sqlite ] || fail "the index beside the ledger"
ids() { run kanhe-index search records "$@" --json | json '[r["id"] for r in d["records"]]'; }
[ "$(ids --meta class=S5B)" = "['$HO', '$LI']" ] || fail "--meta"
[ "$(ids --meta-min year=2026)" = "['$HO']" ] || fail "--meta-min"
[ "$(ids --meta-min year=2026 --revoked any)" = "['$HO', '$CHAN']" ] || fail "--revoked any"
[ "$(ids --revoked yes)" = "['$CHAN']" ] || fail "--revoked yes"
[ "$(ids --text 走讀申請)" = "['$B2', '$B1']" ] || fail "--text, full text"
[ "$(ids --text 李明)" = "['$LI']" ] || fail "--text, two characters"
[ "$(ids --type example.school.blank-form/1 --current)" = "['$B2']" ] || fail "--current"
run kanhe-index search records --type example.school.blank-form/1 | contains "${B1:0:12} .*\[superseded\]"
[ "$(ids --registrant "$(run status --json | json 'd["ledger_id"]')" --limit 2)" = "['$B2', '$B1']" ] ||
    fail "--registrant, --limit"
[ "$(ids --since 2000-01-01 --until 2000-01-02)" = "[]" ] || fail "--since --until"
# A page at a time, both ways.
PAGE="$(run kanhe-index search records --limit 2 --json)"
NEXT="$(echo "$PAGE" | json 'd["next"]')"
[ "$NEXT" != None ] || fail "a next page"
[ "$(run kanhe-index search records --limit 2 --cursor "$NEXT" --json | json '[r["id"] for r in d["records"]]')" = "['$HO', '$LI']" ] ||
    fail "--cursor"
[ "$(ids --oldest --limit 1)" = "['$LI']" ] || fail "--oldest"
run kanhe-index search records --oldest --limit 1 | contains -- "--cursor p"
expect_exit 1 kanhe-index search records --limit 0
contains 'limit is 1 to 1,000' out.txt
expect_exit 1 kanhe-index search records --revoked maybe
expect_exit 1 kanhe-index search records --since yesterday
expect_exit 1 kanhe-index search records --meta class
expect_exit 1 kanhe-index search records --text "$(printf 'a\001bc')"
contains 'without control characters' out.txt

# --- Reports ------------------------------------------------------------------------
REPORT="$(run kanhe-index report records --by type,state --revoked any --json)"
[ "$(echo "$REPORT" | json 'sorted((g["key"]["type"], g["count"]) for g in d["groups"])')" = \
    "[('example.school.application/1', 3), ('example.school.blank-form/1', 2)]" ] || fail "report by type"
[ "$(run kanhe-index report records --json | json 'd["groups"][0]["count"]')" = 4 ] || fail "one count without --by"
run kanhe-index report records --by day --utc-offset +08:00 --csv > days.csv
head -1 days.csv | contains -x $'day,count\r'
[ "$(wc -l < days.csv)" -eq 2 ] || fail "one day"
run kanhe-index report records --by type | contains -E '^example.school.application/1 +2'
expect_exit 1 kanhe-index report records --by contract
contains 'by names type, state, registrant' out.txt
expect_exit 1 kanhe-index report records --by day --utc-offset +15:00

# --- Things under contracts -----------------------------------------------------------
python3 -c "import json,sys; open('oracle.wasm','wb').write(bytes.fromhex(json.load(open(sys.argv[1]))['contract']))" \
    "$SOURCE/testvectors/protocol-v0.6.json"
C="$(run contract deploy oracle.wasm --function apply=create --function approve=call \
    --compiler "hand-assembled 1" --name "Day student" --as root.key --json | json 'd["contract"]["id"]')"
out() { echo "<<[1, {1: {\"state\": \"$1\", \"fields\": {\"class\": \"$2\", \"fee\": $3}}, 2: \"$1\"}]>>"; }
make() {
    run contract create "$C" apply --args "$(out submitted "$1" "$2")" "${@:3}" --as root.key --json |
        json 'd["instance"]["id"]'
}
A="$(make S5B 300 --reference APP-1)"
B="$(make S4A 500)"
D="$(make S5B 700)"
run contract call "$A" approve --args "$(out approved S5B 300)" --as root.key > /dev/null
things() { run kanhe-index search instances "$@" --json | json '[r["id"] for r in d["instances"]]'; }
[ "$(things --status submitted)" = "['$D', '$B']" ] || fail "--status"
[ "$(things --field class=S5B)" = "['$D', '$A']" ] || fail "--field"
[ "$(things --field-min fee=400 --field-max fee=600)" = "['$B']" ] || fail "--field-min --field-max"
[ "$(things --contract-name 'Day student' --limit 1)" = "['$D']" ] || fail "--contract-name"
[ "$(things --contract "${C:0:12}" --reference APP-1)" = "['$A']" ] || fail "--contract --reference"
[ "$(things --final yes)" = "[]" ] || fail "--final"
run kanhe-index search instances --status approved | contains "${A:0:12} .*Day student .*approved .*class=S5B, fee=300"
REPORT="$(run kanhe-index report instances --by state --sum fee --json)"
[ "$(echo "$REPORT" | json '[(g["key"]["state"], g["count"], g["sum"], g["min"], g["max"]) for g in d["groups"]]')" = \
    "[('submitted', 2, 1200, 500, 700), ('approved', 1, 300, 300, 300)]" ] || fail "report instances --sum"
run kanhe-index report instances --by contract --csv | contains "^$C,3"
expect_exit 1 kanhe-index search instances --final maybe

# --- The index: rebuilt when lost ------------------------------------------------------
SIZE="$(run status --json | json 'd["entries"]')"
[ "$(run kanhe-index status --json | json 'd["indexed"]')" = "$SIZE" ] || fail "index status"
run kanhe-index status | contains "indexed:    $SIZE of $SIZE log entries"
rm -f ledger/search.sqlite ledger/search.sqlite-wal ledger/search.sqlite-shm
[ "$(ids --meta class=S5B)" = "['$HO', '$LI']" ] || fail "rebuilt when lost"
run kanhe-index rebuild | contains "from $SIZE log entries: 5 records, 3 instances"

# --- Through a server -------------------------------------------------------------------
TOKEN="$(run token create reader --scope read --json | json 'd["token"]')"
WRITER="$(run token create writer --scope read,submit --json | json 'd["token"]')"
# The primary writes; the index serves beside it, read-only, on the same
# directory, as an explorer beside a node.
wait_for() {
    for _ in $(seq 1 300); do
        if [ -s "$1" ] && python3 -c "import json; json.load(open('$1'))" 2> /dev/null; then return; fi
        sleep 0.1
    done
}
"$KANHE" serve --listen 127.0.0.1:0 --json > server.json 2> server.log &
SERVERS+=("$!")
"$(dirname "$KANHE")/kanhe-index" serve --listen 127.0.0.1:0 --json > index.json 2> index.log &
SERVERS+=("$!")
wait_for server.json
wait_for index.json
URL="$(json 'd["url"]' < server.json)"
INDEX_URL="$(json 'd["url"]' < index.json)"
[ "$(json 'd["read_only"]' < index.json)" = True ] || fail "the index serves read-only"
[ "$(http "$URL/v1/records" "$TOKEN" | sed -n 1p)" = 404 ] || fail "the chain's server has no index"
get() { http "$INDEX_URL$1" "$TOKEN"; }
get "/v1/records?type=example.school.application/1&meta.class=S5B" > r.txt
[ "$(sed -n 1p r.txt)" = 200 ] || fail "GET /v1/records"
[ "$(sed -n '2,$p' r.txt | json '[r["id"] for r in d["records"]]')" = "['$HO', '$LI']" ] || fail "records over HTTP"
get "/v1/records/$B1" | sed -n '2,$p' | json 'd["latest"], d["versions"], d["record"]["superseded_by"]' |
    contains -x "$B2 2 $B2"
get "/v1/records/$B2/versions" | sed -n '2,$p' | json '[v["id"] for v in d["versions"]]' | contains -xF "['$B1', '$B2']"
get "/v1/instances?field.fee.min=600" | sed -n '2,$p' | json '[i["id"] for i in d["instances"]]' | contains -xF "['$D']"
get "/v1/reports/instances?by=state&sum=fee" | sed -n '2,$p' | json 'd["groups"][0]["sum"]' | contains -x 1200
get "/v1/reports/records?by=week" | sed -n '2,$p' | json 'd["by"]' | contains -xF "['week']"
[ "$(get "/v1/records?limit=5000" | sed -n 1p)" = 400 ] || fail "a bad query is a 400"
get "/v1/records?colour=blue" | contains 'unknown parameter colour'
[ "$(http "$INDEX_URL/v1/records" | sed -n 1p)" = 401 ] || fail "read scope"
[ "$(get "/v1/records/$(printf '0%.0s' $(seq 1 64))" | sed -n 1p)" = 404 ] || fail "no such record"
# A record issued while it serves is found at once (the query catches up).
LEDGER_ID="$(run status --json | json 'd["ledger_id"]')"
env -u KANHE_LEDGER KANHE_TOKEN="$WRITER" "$KANHE" record issue --as root.key \
    --type example.school.application/1 --field address=x --meta student=新生 --server "$URL" \
    --cache "$WORK/cache" --ledger-id "$LEDGER_ID" --json > issued.json 2> issued.err ||
    { cat issued.err; fail "issue through the server"; }
NEW="$(json 'd["record"]["id"]' < issued.json)"
get "/v1/records?q=%E6%96%B0%E7%94%9F" | sed -n '2,$p' | json '[r["id"] for r in d["records"]]' |
    contains -xF "['$NEW']"

# Help and completion name the commands.
run kanhe-index search records --help | contains -- '--meta KEY=VALUE'
run kanhe-index report instances --help | contains -- '--sum FIELD'
run kanhe-index completion bash | contains 'rebuild'
echo "search: all checks passed"
