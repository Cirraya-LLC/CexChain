#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The web console's server side, end to end: `serve --console` serves the
# page at /console/ with its security headers, answers only for its own
# names, and refuses other sites' pages.
# Usage: console.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2; tail -n 20 "$WORK"/*.log >&2 || true' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="console test"
export CEXCHAIN_LEDGER="$WORK/ledger"
unset CEXCHAIN_TOKEN

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# request METHOD PORT PATH HOST [ORIGIN [BODY]]: prints the status, the headers
# (lower-case names), a blank line, then the body. $TOKEN, if set, is sent as
# an API token.
request() {
    python3 - "$@" << 'PY'
import http.client, os, sys
method, port, path, host = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
origin = sys.argv[5] if len(sys.argv) > 5 else ""
body = sys.argv[6].encode() if len(sys.argv) > 6 else b""
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
connection.putrequest(method, path, skip_host=True)
connection.putheader("Host", host)
if origin:
    connection.putheader("Origin", origin)
if os.environ.get("TOKEN"):
    connection.putheader("Authorization", "Bearer " + os.environ["TOKEN"])
if method == "POST":
    connection.putheader("Content-Length", str(len(body)))
    connection.putheader("Content-Type", "application/json")
connection.endheaders(body if method == "POST" else None)
response = connection.getresponse()
print(response.status)
for name, value in response.getheaders():
    print(f"{name.lower()}: {value}")
print()
sys.stdout.write(response.read().decode("utf-8", "replace"))
PY
}
status_of() { request "$@" | sed -n 1p; }
# start_server FILE ARGS...: serves in the background; FILE gets its JSON.
start_server() {
    local out="$1"; shift
    "$CEXCHAIN" serve --listen 127.0.0.1:0 --json --quiet "$@" > "$out" 2> "$out.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        if [ -s "$out" ] && python3 -c "import json,sys; json.load(open('$out'))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    fail "the server did not start"
}

run key generate --out root.key > /dev/null
run key generate --out log.key > /dev/null
run init --org "Console Org" --root-key root.key --log-key log.key > /dev/null

# --- Options ---------------------------------------------------------------
expect_exit 1 serve --public-url https://ledger.example.com
grep -q -- "--public-url goes with --console" out.txt || fail "--public-url alone"
expect_exit 1 serve --console --public-url ftp://ledger.example.com
grep -q "https:// or http://" out.txt || fail "a URL's scheme"
run serve --help > out.txt
grep -q -- "--console" out.txt || fail "serve --help names --console"
grep -q -- "--public-url URL" out.txt || fail "serve --help names --public-url"

# --- Without --console, /console/ is an unknown path ---------------------------
start_server plain.json
PORT=$(json 'd["port"]' < plain.json)
[ "$(json 'd["console"]' < plain.json)" = "None" ] || fail "no console without --console"
[ "$(status_of GET "$PORT" /console/ "127.0.0.1:$PORT")" = 404 ] || fail "console off"
kill "${SERVERS[-1]}"

# --- The page and its headers --------------------------------------------------
start_server console.json --console
PORT=$(json 'd["port"]' < console.json)
[ "$(json 'd["console"]' < console.json)" = "http://localhost:$PORT/console/" ] ||
    fail "the console's URL"
request GET "$PORT" /console/ "localhost:$PORT" > page.txt
[ "$(sed -n 1p page.txt)" = 200 ] || fail "the page"
grep -q "^content-type: text/html; charset=utf-8" page.txt || fail "the page's type"
grep -q "^content-security-policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval';" \
    page.txt || fail "the page's CSP"
grep -q "^x-frame-options: DENY" page.txt || fail "no framing"
grep -q "^cache-control: no-store" page.txt || fail "no caching"
grep -q "<!doctype html>" page.txt || fail "the page's body"
for file in console.js console.css; do
    [ "$(status_of GET "$PORT" "/console/$file" "127.0.0.1:$PORT")" = 200 ] || fail "$file"
done
[ "$(status_of GET "$PORT" /console "localhost:$PORT")" = 308 ] || fail "/console redirects"
[ "$(status_of GET "$PORT" /console/missing "localhost:$PORT")" = 404 ] || fail "unknown file"
# The API beside it is unchanged.
[ "$(status_of GET "$PORT" /healthz "localhost:$PORT")" = 200 ] || fail "the API"

# --- Only its own names, only its own page --------------------------------------
[ "$(status_of GET "$PORT" /console/ "attacker.example:$PORT")" = 421 ] || fail "rebinding"
[ "$(status_of GET "$PORT" /console/ "localhost:1")" = 421 ] || fail "another port"
[ "$(status_of GET "$PORT" /console/ "localhost:$PORT" "https://attacker.example")" = 403 ] ||
    fail "another site's page"
[ "$(status_of POST "$PORT" /console/api/session "localhost:$PORT")" = 403 ] ||
    fail "a write without an Origin"
kill "${SERVERS[-1]}"

# --- A public URL: answered for that name only -----------------------------------
start_server public.json --console --public-url https://Ledger.Example.com/
PORT=$(json 'd["port"]' < public.json)
[ "$(json 'd["console"]' < public.json)" = "https://ledger.example.com/console/" ] ||
    fail "the public console's URL"
[ "$(status_of GET "$PORT" /console/ "ledger.example.com")" = 200 ] || fail "the public name"
[ "$(status_of GET "$PORT" /console/ "localhost:$PORT")" = 421 ] || fail "localhost refused"

# --- Sessions -----------------------------------------------------------------
# Signing in begins one; until then there are none, and none to revoke.
[ "$(status_of GET "$PORT" /console/api/session "ledger.example.com")" = 401 ] ||
    fail "no session without a token"
run console session list > out.txt
grep -q "no console sessions" out.txt || fail "console session list"
[ "$(run console session list --json)" = "[]" ] || fail "console session list --json"
expect_exit 2 console session revoke 0123456789abcdef
grep -q "no console session 0123456789abcdef" out.txt || fail "revoking an unknown session"
run console session revoke --help > out.txt
grep -q "End a web console session" out.txt || fail "console session revoke --help"

# --- Users and invitations -------------------------------------------------------
run console user list > out.txt
grep -q "no console users" out.txt || fail "no users at first"
# The console running above published its address; setup-link uses it.
run console setup-link > out.txt
grep -q "https://ledger.example.com/console/#/enroll/cxi_" out.txt || fail "the setup link"
CODE=$(sed -n 's|.*#/enroll/\(cxi_[A-Za-z0-9_-]*\).*|\1|p' out.txt)
LOCAL=$(run console setup-link --url "http://localhost:7470/" --json)
[ "$(echo "$LOCAL" | json 'd["role"]')" = owner ] || fail "setup-link --json"
echo "$LOCAL" | json 'd["link"]' | grep -q "^http://localhost:7470/console/#/enroll/cxi_" ||
    fail "setup-link --url"
# A new setup link replaces the last: the first code no longer begins a registration.
BEGIN=$(request POST "$PORT" /console/api/enroll/begin "ledger.example.com" \
    "https://ledger.example.com" "{\"code\": \"$CODE\", \"name\": \"Alice\"}")
[ "$(echo "$BEGIN" | sed -n 1p)" = 404 ] || fail "a replaced setup link"
CODE=$(echo "$LOCAL" | json 'd["link"].split("/enroll/")[1]')
BEGIN=$(request POST "$PORT" /console/api/enroll/begin "ledger.example.com" \
    "https://ledger.example.com" "{\"code\": \"$CODE\", \"name\": \"Alice\"}")
[ "$(echo "$BEGIN" | sed -n 1p)" = 200 ] || fail "the setup link begins a registration"
echo "$BEGIN" | grep -q '"rp":{"id":"ledger.example.com"' || fail "the passkey's relying party"

run console user add Bob --role viewer > out.txt
grep -q "invite Bob" out.txt || fail "console user add"
run console user list > out.txt
grep -q "^Bob .*viewer .*invited" out.txt || fail "the invitation listed"
grep -q "^(setup) .*owner .*invited" out.txt || fail "the setup invitation listed"
[ "$(run console user list --json | json 'len(d["invitations"])')" = 2 ] || fail "--json"
expect_exit 1 console user add "Bad Name!"
expect_exit 1 console user add Carol --role boss
expect_exit 1 console user role Bob boss
expect_exit 2 console user show Bob
expect_exit 2 console user role Bob admin
run console user revoke Bob > out.txt
grep -q "revoked Bob and their invitations" out.txt || fail "revoking an invitation"
expect_exit 2 console user revoke Bob
run console user revoke --help > out.txt
grep -q "only owner" out.txt || fail "console user revoke --help"

# --- The console's sealed keys ------------------------------------------------------
run console key list > out.txt
grep -q "keys are not set up" out.txt || fail "keys before setup"
expect_exit 2 console key import root root.key
printf 'the unlock passphrase of these tests\n' > unlock.txt
run console key init --unlock-file unlock.txt > out.txt
grep -q "recovery code (shown once" out.txt || fail "console key init"
grep -qE '^    [A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$' out.txt || fail "the recovery code's form"
expect_exit 2 console key init
grep -q "set up already" out.txt || fail "a second key init"
run console key import root root.key > out.txt
grep -q "sealed the key root" out.txt || fail "console key import"
KEYS=$(run console key list --json)
[ "$(echo "$KEYS" | json 'd["keys"][0]["name"]')" = root ] || fail "console key list --json"
[ "$(echo "$KEYS" | json 'sorted(s["kind"] for s in d["slots"])')" = "['passphrase', 'recovery']" ] ||
    fail "the slots"
expect_exit 1 console key import Root root.key
run console key remove root > out.txt
expect_exit 2 console key remove root
expect_exit 1 serve --unlock-file unlock.txt
printf 'not the passphrase at all\n' > wrong.txt
# Linking a user to a person of the ledger needs a sealed key, the user, and a person.
expect_exit 1 console user link Nobody --key root
expect_exit 2 console user link Nobody --actor 00000000 --key root
grep -q "holds no key named root" out.txt || fail "linking with no such key"
expect_exit 2 console user passkeys Nobody --out passkeys
grep -q "no console user named Nobody" out.txt || fail "passkeys of no such user"

# --- console run, status, open, stop ------------------------------------------------
kill "${SERVERS[-1]}"
run console status > out.txt
grep -q "the console is not running" out.txt || fail "status when stopped"
expect_exit 2 console stop
FREE=$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1])")
"$CEXCHAIN" console run --port "$FREE" --quiet > run.log 2>&1 &
SERVERS+=("$!")
for _ in $(seq 1 300); do
    [ "$(run console status --json | json 'd["running"]')" = True ] && break
    sleep 0.1
done
run console status > out.txt
grep -q "the console runs (process [0-9]*) at http://localhost:$FREE/console/" out.txt ||
    fail "status when running"
[ "$(run console open --print)" = "http://localhost:$FREE/console/" ] || fail "console open --print"
[ "$(status_of GET "$FREE" /console/ "localhost:$FREE")" = 200 ] || fail "console run serves"
expect_exit 2 console run --port "$FREE"
grep -q "the console runs already" out.txt || fail "a second console run"
run console stop > out.txt
grep -q "stopped the console" out.txt || fail "console stop"
[ "$(run console status --json | json 'd["running"]')" = False ] || fail "stopped"
expect_exit 1 console run --port 70000
expect_exit 1 console run --port "$FREE" --unlock-file wrong.txt
grep -q "does not unlock the console's keys" out.txt || fail "a wrong unlock file"

# --- console settings ------------------------------------------------------------
run console settings show > out.txt
grep -q "language: each browser's own" out.txt || fail "no language at first"
grep -q "backup folder: none chosen" out.txt || fail "no backup folder at first"
expect_exit 1 console settings set
expect_exit 1 console settings set --language fr
run console settings set --language zh-Hant-HK --backup-folder backups/ledger > out.txt
grep -q "language: zh-Hant-HK" out.txt || fail "console settings set"
[ -d backups/ledger ] || fail "the backup folder is made"
SETTINGS=$(run console settings show --json)
[ "$(echo "$SETTINGS" | json 'd["backup_folder"]')" = "$WORK/backups/ledger" ] ||
    fail "the backup folder is a full path"
[ "$(echo "$SETTINGS" | json 'd["language"]')" = zh-Hant-HK ] || fail "settings --json"
expect_exit 2 console settings set --backup-folder unlock.txt/inside
grep -q "cannot be made" out.txt || fail "a folder that cannot be made"
run console settings set --language browser --backup-folder none > /dev/null
[ "$(run console settings show --json | json 'd["language"]')" = None ] || fail "language cleared"
run console settings set --help > out.txt
grep -q -- "--backup-folder DIR" out.txt || fail "console settings set --help"

# --- Document kinds ---------------------------------------------------------------
cat > photo-kind.json << 'JSON'
{"sheet": 1, "kind": "document", "type": "example.org.photo/1", "name": "Photo",
 "fields": [{"name": "place", "label": "Place", "required": true},
            {"name": "taken", "type": "date"}],
 "files": "required"}
JSON
run console kind list > out.txt
grep -q "no kinds" out.txt || fail "no kinds at first"
run console kind add photo-kind.json > out.txt
grep -q "added the kind Photo (example.org.photo/1)" out.txt || fail "console kind add"
expect_exit 2 console kind add photo-kind.json
grep -q -- "--replace" out.txt || fail "a second add"
run console kind add photo-kind.json --replace > /dev/null
[ "$(run console kind list --json | json 'd[0]["fields"][1]["type"]')" = date ] || fail "kind list --json"
run console kind show example.org.photo/1 > out.txt
grep -q "field taken .* date .* private" out.txt || fail "console kind show"
printf '{"sheet": 1, "kind": "document", "type": "x/1", "name": "X", "fields": []}' > bad-kind.json
expect_exit 1 console kind add bad-kind.json
grep -q "1 to 32 fields" out.txt || fail "a bad kind sheet"
run console kind remove example.org.photo/1 > out.txt
grep -q "its records stay on the ledger" out.txt || fail "console kind remove"
expect_exit 2 console kind show example.org.photo/1
run console kind add --help > out.txt
grep -q '"sheet": 1' out.txt || fail "console kind add --help"

# --- console setup: the first run, for scripts -------------------------------------
# A passkey's credential file, as presence enroll writes one: a CBOR map of its
# relying party, its credential id, and its public key.
python3 - << 'PY'
import os
def text(value):
    data = value.encode()
    return bytes([0x60 + len(data)]) + data
credential = bytes([0xa3, 0x01]) + text("localhost") + bytes([0x02, 0x50]) + os.urandom(16)
credential += bytes([0x03, 0x82, 0x32, 0x58, 0x20]) + os.urandom(32)
open("owner.passkey", "wb").write(credential)
PY
SCRIPTED="$WORK/scripted"
expect_exit 1 console setup --ledger "$SCRIPTED" --credential owner.passkey
expect_exit 1 console setup --ledger "$SCRIPTED" --name "Bad Name!" --credential owner.passkey
[ ! -e "$SCRIPTED/statements" ] || fail "a refused setup makes no ledger"
run console setup --ledger "$SCRIPTED" --name "Scripted Owner" --credential owner.passkey \
    --unlock-file unlock.txt --json > setup.json
[ "$(json 'len(d["ledger"]["id"]) if isinstance(d["ledger"], dict) else len(d["ledger"])' < setup.json)" = 64 ] ||
    fail "console setup --json names the ledger"
json 'd["recovery_code"]' < setup.json | grep -qE '^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$' ||
    fail "console setup prints the recovery code"
expect_exit 2 console setup --ledger "$SCRIPTED" --name Again --credential owner.passkey
grep -q "holds a ledger already" out.txt || fail "a second setup"
KEYS=$(run console key list --ledger "$SCRIPTED" --json)
[ "$(echo "$KEYS" | json 'sorted(k["name"] for k in d["keys"])')" = "['log', 'owner', 'root']" ] ||
    fail "setup seals the root, log, and owner keys"
[ "$(echo "$KEYS" | json 'sorted(s["kind"] for s in d["slots"])')" = "['passphrase', 'recovery']" ] ||
    fail "setup's slots"
[ "$(echo "$KEYS" | json 'd["vault_key"]')" = True ] || fail "setup seals a vault key"
[ -f "$SCRIPTED/vault/vault.pub" ] && [ ! -f "$SCRIPTED/vault/vault.key" ] ||
    fail "the vault's private key only sealed"
USERS=$(run console user list --ledger "$SCRIPTED" --json)
[ "$(echo "$USERS" | json 'd["users"][0]["role"]')" = owner ] || fail "setup's owner"
run delegation list --ledger "$SCRIPTED" --json > out.txt
grep -q '"require_presence": *true' out.txt || fail "the owner's delegation requires presence"
run console setup --help > out.txt
grep -q "for scripts" out.txt || fail "console setup --help"

# The scripted ledger, served by its console: unlocked by the file, its API opens.
start_console() {
    "$CEXCHAIN" console run --ledger "$1" --port "$FREE" --quiet "${@:2}" > "$1.run.log" 2>&1 &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        [ "$(run console status --ledger "$1" --json | json 'd["running"]')" = True ] && return 0
        sleep 0.1
    done
    fail "the console did not start on $1"
}
run token create reader --ledger "$SCRIPTED" --scope read --out scripted.token > /dev/null
start_console "$SCRIPTED" --unlock-file unlock.txt
[ "$(TOKEN=$(cat scripted.token) status_of GET "$FREE" /v1/status "localhost:$FREE")" = 200 ] ||
    fail "the unlocked ledger is served"
run console stop --ledger "$SCRIPTED" > /dev/null
# Locked: the console answers, and the ledger waits for it.
start_console "$SCRIPTED"
[ "$(status_of GET "$FREE" /v1/status "localhost:$FREE")" = 503 ] || fail "locked, the API waits"
[ "$(status_of GET "$FREE" /healthz "localhost:$FREE")" = 200 ] || fail "locked, it is healthy"
request GET "$FREE" /console/api/start "localhost:$FREE" | grep -q '"first_run":false' ||
    fail "the console's start"
RECOVER=$(request POST "$FREE" /console/api/recover/begin "localhost:$FREE" "http://localhost:$FREE" \
    '{"recovery_code": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG"}')
[ "$(echo "$RECOVER" | sed -n 1p)" = 403 ] || fail "a wrong recovery code"
CODE=$(json 'd["recovery_code"]' < setup.json)
RECOVER=$(request POST "$FREE" /console/api/recover/begin "localhost:$FREE" "http://localhost:$FREE" \
    "{\"recovery_code\": \"$CODE\"}")
[ "$(echo "$RECOVER" | sed -n 1p)" = 200 ] || fail "the recovery code begins a recovery"
# The code unlocked the console, so its API opened.
[ "$(TOKEN=$(cat scripted.token) status_of GET "$FREE" /v1/status "localhost:$FREE")" = 200 ] ||
    fail "the code unlocks"
run console stop --ledger "$SCRIPTED" > /dev/null

# --- console run on an empty directory: the first run's setup link --------------------
EMPTY="$WORK/empty"
CEXCHAIN_NO_BROWSER=1 "$CEXCHAIN" console run --ledger "$EMPTY" --port "$FREE" --quiet --json \
    > first.json 2> first.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do
    [ "$(run console status --ledger "$EMPTY" --json | json 'd["running"]')" = True ] && break
    sleep 0.1
done
[ "$(json 'd["setup"]' < first.json)" = True ] || fail "an empty directory's first run"
grep -q "^http://localhost:$FREE/console/#/enroll/cxi_" "$EMPTY/console/setup-link" ||
    fail "the setup link's file"
grep -q 'http-equiv="refresh"' "$(json 'd["setup_page"]' < first.json)" || fail "the setup page"
request GET "$FREE" /console/api/start "localhost:$FREE" | grep -q '"first_run":true' ||
    fail "the page knows it is the first run"
[ "$(status_of GET "$FREE" /v1/status "localhost:$FREE")" = 503 ] || fail "no ledger yet"
SETUP_CODE=$(sed -n 's|.*#/enroll/\(cxi_[A-Za-z0-9_-]*\).*|\1|p' "$EMPTY/console/setup-link")
BEGIN=$(request POST "$FREE" /console/api/enroll/begin "localhost:$FREE" "http://localhost:$FREE" \
    "{\"code\": \"$SETUP_CODE\", \"name\": \"Alice\"}")
echo "$BEGIN" | grep -q '"first_run":true' || fail "the setup link begins the first run"
echo "$BEGIN" | grep -q '"prf":{"eval":{"first":"' || fail "the first passkey is asked for its PRF"
run console status --ledger "$EMPTY" > out.txt
grep -q "no owner yet" out.txt || fail "no owner before the first run"
run console stop --ledger "$EMPTY" > /dev/null
[ ! -e "$EMPTY/statements" ] || fail "no ledger until the passkey is registered"

# --- A ledger made by the README's quick start opens in the console ---------------------
QUICK="$WORK/quick"
mkdir "$QUICK"
(
    cd "$QUICK"
    export CEXCHAIN_LEDGER=./ledger
    run key generate --out root.key > /dev/null
    run key generate --out log.key > /dev/null
    run init --name "Alice" --root-key root.key --log-key log.key > /dev/null
    run key generate --out alice.key > /dev/null
    run key public alice.key --out alice.pub > /dev/null
    ALICE=$(run actor add --as root.key --kind person --name "Alice" --key alice.pub | grep -oE '[0-9a-f]{64}' | sed -n 1p)
    run delegation grant --as root.key --to "$ALICE" --allow record-register,record-endorse \
        --record-types example.org.photo/1 --days 30 > /dev/null
    printf 'not really a photo\n' > photo.jpg
    run record issue --as alice.key --type example.org.photo/1 --field place="Victoria Harbour" \
        --field taken=2026-10-16 --attach photo.jpg > /dev/null
    run console key init --unlock-file "$WORK/unlock.txt" > /dev/null
    run console key import log log.key > /dev/null
    run console key import alice alice.key > /dev/null
    run console key import vault ledger/vault/vault.key | grep -q "vault key" ||
        fail "console key import vault"
    run console key list --json | python3 -c 'import json,sys; assert json.load(sys.stdin)["vault_key"]'
    run key generate --out other.key > /dev/null
    if run console key import vault other.key > /dev/null 2>&1; then fail "another key as the vault key"; fi
    run token create reader --scope read --out "$WORK/quick.token" > /dev/null
)
start_console "$QUICK/ledger" --unlock-file unlock.txt
STATUS=$(TOKEN=$(cat quick.token) request GET "$FREE" /v1/status "localhost:$FREE")
[ "$(echo "$STATUS" | sed -n 1p)" = 200 ] || fail "the quick start's ledger is served"
echo "$STATUS" | grep -q '"organization":"Alice"' || fail "the quick start's organization"
run console stop --ledger "$QUICK/ledger" > /dev/null

echo "console: all checks passed"
