#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Two organizations become each other's peers with one invitation code each
# way: each code carries the inviting ledger's id, its name, its API's URL,
# and a token issued for the invited party. Accepting adds the peer with its
# token kept owner-only; the peer then reaches the inviter's API as its peer
# (its registrar's held calls). Refused: a code changed on the way, a name
# taken, a code that is not one.
# Usage: parties.sh CEXCHAIN
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
export CEXCHAIN_PASSPHRASE="parties test"
unset CEXCHAIN_LEDGER CEXCHAIN_TOKEN CEXCHAIN_SERVER

# A command line as typed: bo, cexchain-console, and cexchain-index are the
# programs beside cexchain.
run() {
    case "$1" in
    bo | cexchain-console | cexchain-index) "$(dirname "$CEXCHAIN")/$1" "${@:2}" ;;
    *) "$CEXCHAIN" "$@" ;;
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

echo "== help and completion"
for command in "peer invite" "peer accept"; do
    # shellcheck disable=SC2086
    run $command --help | contains -F "cexchain $command" || fail "help for $command"
done
run completion bash | contains -F "invite" || fail "completion: invite"

echo "== two ledgers, one code each way"
for who in alice bob; do
    run key generate --out "$who-root.key" > /dev/null
    run key generate --out "$who-log.key" > /dev/null
done
run init --name Alice --root-key alice-root.key --log-key alice-log.key --ledger alice > /dev/null
run init --name Bob --root-key bob-root.key --log-key bob-log.key --ledger bob > /dev/null
ALICE_ID=$(run status --ledger alice --json | json 'd["ledger_id"]')
BOB_ID=$(run status --ledger bob --json | json 'd["ledger_id"]')
# The server's address, chosen ahead (serve holds the ledger's lock while it runs).
ALICE_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
ALICE_URL="http://127.0.0.1:$ALICE_PORT"
# Alice's server will witness her peers' ledgers: her code carries its key.
run key generate --out alice-witness.key > /dev/null
run key public alice-witness.key --out alice-witness.pub > /dev/null
run peer invite bob --url "$ALICE_URL" --witness-key alice-witness.pub --ledger alice --json > invite.json
[ "$(json 'd["witness"]' < invite.json)" = True ] || fail "the code carries the witness key"
CODE=$(json 'd["code"]' < invite.json)
case "$CODE" in cxp_*) ;; *) fail "an invitation code starts with cxp_" ;; esac
[ "$(json 'd["fingerprint"]' < invite.json)" = "$(echo "$ALICE_ID" | sed -E 's/^(.{4})(.{4})(.{4})(.{4})(.{4}).*/\1 \2 \3 \4 \5/')" ] ||
    fail "the fingerprint is the ledger id's first 20 hex digits"
run token list --ledger alice --json | json '[(t["name"], t["scopes"]) for t in d]' |
    contains -F "('bob', ['peer'])" || fail "the invitation issues a peer token"
expect_exit 2 peer invite bob --ledger alice
contains -F "a token named bob exists" out.txt || fail "one invitation per name"

run peer accept "$CODE" --name alice --ledger bob --json > accepted.json
[ "$(json '(d["ledger_id"], d["organization"], d["url"])' < accepted.json)" = "('$ALICE_ID', 'Alice', '$ALICE_URL')" ] ||
    fail "the peer the code names"
TOKEN_FILE=$(json 'd["token_file"]' < accepted.json)
[ "$(json 'd["witness_key"]["key"]' < accepted.json)" = "$(run key show alice-witness.key --json | json 'd["public_key"]["key"]')" ] ||
    fail "accepting keeps the witness key"
[ "$(run peer show alice --ledger bob --json | json 'd["witness_key"] is not None')" = True ] ||
    fail "the peer has the witness key"
[ "$(stat -c %a "$TOKEN_FILE" 2> /dev/null || stat -f %Lp "$TOKEN_FILE")" = 600 ] ||
    fail "the token is kept owner-only"
# And back: Bob invites Alice, who accepts under the name she invited him with.
BACK=$(run peer invite alice --ledger bob --json | json 'd["code"]')
run peer accept "$BACK" --name bob --ledger alice > /dev/null
run peer list --ledger alice --json | json '[p["name"] for p in d]' | contains -F "['bob']" ||
    fail "Alice has Bob as a peer"

echo "== Bob reaches Alice's API as her peer"
"$CEXCHAIN" serve --listen "127.0.0.1:$ALICE_PORT" --json --quiet --ledger alice > alice.json 2> alice.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do
    if [ -s alice.json ] && python3 -c "import json; json.load(open('alice.json'))" 2> /dev/null; then break; fi
    sleep 0.1
done

# The registrar's held calls that concern Bob: none yet, but asked as her peer.
run contract pending --peer alice --ledger bob | contains -F "no pending calls" ||
    fail "Bob's token reaches Alice's API"
# Alice's genesis entry, which Bob follows her keys from as her witness.
python3 - "$ALICE_URL/v1/genesis" "$(cat "$TOKEN_FILE")" << 'PY' || fail "a peer reads the genesis entry"
import sys, urllib.request
request = urllib.request.Request(sys.argv[1], headers={"Authorization": "Bearer " + sys.argv[2]})
with urllib.request.urlopen(request, timeout=10) as answer:
    assert answer.status == 200 and answer.headers["Content-Type"] == "application/cbor"
    assert len(answer.read()) > 64
PY
python3 - "$ALICE_URL/v1/genesis" << 'PY' || fail "the genesis entry needs a token"
import sys, urllib.request, urllib.error
try:
    urllib.request.urlopen(sys.argv[1], timeout=10)
    sys.exit("read without a token")
except urllib.error.HTTPError as error:
    assert error.code == 401, error.code
PY
# Another token does not.
cp "$TOKEN_FILE" token.kept
echo "cxt_not_the_token" > "$TOKEN_FILE"
expect_exit 2 contract pending --peer alice --ledger bob
cp token.kept "$TOKEN_FILE"

echo "== refused"
expect_exit 1 peer accept "not-a-code" --name carol --ledger bob
contains -F "not an invitation code" out.txt || fail "not a code"
# A code changed on the way names another ledger: its fingerprint is not the
# one the inviter reads out, so the people comparing them catch it.
TAMPERED=$(python3 -c "
import base64
code = '$CODE'[4:]
raw = bytearray(base64.urlsafe_b64decode(code + '=' * (-len(code) % 4)))
raw[raw.find(bytes.fromhex('025820')) + 3] ^= 1
print('cxp_' + base64.urlsafe_b64encode(bytes(raw)).decode().rstrip('='))")
run peer accept "$TAMPERED" --name carol --ledger bob --json > carol.json
[ "$(json 'd["fingerprint"]' < carol.json)" != "$(json 'd["fingerprint"]' < invite.json)" ] ||
    fail "a changed code shows another fingerprint"
run peer remove carol --ledger bob > /dev/null
# Cut short, it is no code.
expect_exit 1 peer accept "${CODE:0:40}" --name carol --ledger bob
expect_exit 2 peer accept "$CODE" --name alice --ledger bob
contains -F "exists" out.txt || fail "a name taken"

echo "parties: all checks passed"
