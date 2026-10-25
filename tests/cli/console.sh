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
# (lower-case names), a blank line, then the body.
request() {
    python3 - "$@" << 'PY'
import http.client, sys
method, port, path, host = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
origin = sys.argv[5] if len(sys.argv) > 5 else ""
body = sys.argv[6].encode() if len(sys.argv) > 6 else b""
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
connection.putrequest(method, path, skip_host=True)
connection.putheader("Host", host)
if origin:
    connection.putheader("Origin", origin)
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

echo "console: all checks passed"
