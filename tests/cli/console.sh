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
# request METHOD PORT PATH HOST [ORIGIN]: prints the status, the headers
# (lower-case names), a blank line, then the body.
request() {
    python3 - "$@" << 'PY'
import http.client, sys
method, port, path, host = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
origin = sys.argv[5] if len(sys.argv) > 5 else ""
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
connection.putrequest(method, path, skip_host=True)
connection.putheader("Host", host)
if origin:
    connection.putheader("Origin", origin)
if method == "POST":
    connection.putheader("Content-Length", "0")
connection.endheaders()
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

echo "console: all checks passed"
