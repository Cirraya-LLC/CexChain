#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Time-stamp tokens (spec v0.11): a time-stamp authority (OpenSSL's, over
# HTTP) stamps checkpoints; the ledger keeps the tokens and exports carry
# them as anchors; a verifier that trusts the authority's root learns when
# the record existed by, and one that does not relies on nothing. A token got
# by hand is kept too. A server stamps by itself (serve --tsa), replicas copy
# the tokens, and backups carry them.
# Usage: timestamps.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export CEXCHAIN_PASSPHRASE="timestamps test"
unset CEXCHAIN_SERVER CEXCHAIN_TOKEN CEXCHAIN_CLOCK_OFFSET
export CEXCHAIN_LEDGER="$WORK/ledger"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost

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

# --- A time-stamp authority: a root, its time-stamping certificate, OpenSSL's
# responder, and an HTTP front for it -----------------------------------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout root.key.pem \
    -out root.pem -days 3650 -subj "/CN=Test TSA Root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2> /dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tsa.key.pem -out tsa.csr \
    -subj "/CN=Test TSA" 2> /dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n' > tsa.ext
openssl x509 -req -in tsa.csr -CA root.pem -CAkey root.key.pem -CAcreateserial -out tsa.pem \
    -days 3650 -extfile tsa.ext 2> /dev/null
cat > tsa.cnf << EOF
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial = $WORK/tsa.serial
crypto_device = builtin
signer_cert = $WORK/tsa.pem
certs = $WORK/root.pem
signer_key = $WORK/tsa.key.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sm3
accuracy = secs:1
clock_precision_digits = 3
ess_cert_id_alg = sha256
EOF
echo 01 > tsa.serial
cat > tsa.py << 'EOF'
import http.server, os, socketserver, subprocess, sys, tempfile

class Authority(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        query = self.rfile.read(int(self.headers["Content-Length"]))
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "q"), "wb") as f:
                f.write(query)
            subprocess.run(["openssl", "ts", "-reply", "-config", sys.argv[1], "-queryfile",
                            os.path.join(d, "q"), "-out", os.path.join(d, "r")],
                           check=True, capture_output=True)
            with open(os.path.join(d, "r"), "rb") as f:
                answer = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, *args):
        pass

class Server(http.server.HTTPServer):
    # No reverse lookup of 127.0.0.1 (getfqdn), which can take many seconds.
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

server = Server(("127.0.0.1", 0), Authority)
print(server.server_address[1], flush=True)
server.serve_forever()
EOF
python3 tsa.py "$WORK/tsa.cnf" > tsa.port 2> tsa.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do [ -s tsa.port ] && break; sleep 0.1; done
[ -s tsa.port ] || { cat tsa.log; fail "the test time-stamp authority did not start"; }
TSA="http://127.0.0.1:$(cat tsa.port)/tsa"

# --- A ledger with a record, its checkpoint stamped ----------------------------
for k in root log; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --name "Stamped Org" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
RECORD="$(run record issue --as root.key --type example.document/1 --field result=pass --json |
    json 'd["record"]["id"]')"
expect_exit 2 checkpoint timestamp --tsa "$TSA" # nothing to stamp yet
run checkpoint create --log-key log.key > /dev/null
STAMPED="$(run checkpoint timestamp --tsa "$TSA" --out first.tst --json)"
[ "$(echo "$STAMPED" | json 'd["authority"]')" = "CN=Test TSA" ] || fail "the authority's name"
FIRST_SIZE="$(echo "$STAMPED" | json 'd["tree_size"]')"
[ -s first.tst ] || fail "--out writes the token"
run checkpoint timestamps | contains -E "^ +$FIRST_SIZE  .*CN=Test TSA$"
[ "$(run checkpoint timestamps --json | json 'd[0]["trusted"]')" = None ] || fail "no roots: no trust"
[ "$(run checkpoint timestamps --tsa-root root.pem --json | json 'd[0]["trusted"]')" = True ] ||
    fail "trusted under its root"
SHOWN="$(run checkpoint show --json)"
[ "$(echo "$SHOWN" | json 'len(d["timestamps"])')" = 1 ] || fail "checkpoint show lists it"
echo "$SHOWN" | json 'd["timestamp_imprint"]' | contains -E '^[0-9a-f]{64}$'
run checkpoint show | contains 'stamped:    by CN=Test TSA at '

# Later entries and checkpoints: the evidence carries the stamped checkpoint as
# an anchor, with a consistency proof to its own.
run record issue --as root.key --type example.document/1 --field result=later > /dev/null
run checkpoint create --log-key log.key > /dev/null
run export "$RECORD" --log-key log.key --out evidence.cbor > /dev/null
REPORT="$(run verify evidence.cbor --ledger-id "$LEDGER_ID" --tsa-root root.pem --json)"
[ "$(echo "$REPORT" | json 'd["timestamps"]["trusted_authorities"]')" = 1 ] || fail "trusted"
echo "$REPORT" | json 'd["timestamps"]["existed_by"]' | contains -E '^20[0-9]{2}-'
echo "$REPORT" | json 'd["events"][0]["existed_by"]' | contains -E '^20[0-9]{2}-'
run verify evidence.cbor --ledger-id "$LEDGER_ID" --tsa-root root.pem > report.txt
contains 'Time-stamps  1 trusted authority' report.txt
contains 'CN=Test TSA saw checkpoint size' report.txt
contains 'Existed by   .*as a time-stamp authority you trust saw it' report.txt
# Without the root, the token is counted and nothing is relied on.
UNTRUSTED="$(run verify evidence.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$UNTRUSTED" | json 'd["timestamps"]["trusted_authorities"]')" = 0 ] || fail "untrusted"
[ "$(echo "$UNTRUSTED" | json 'd["timestamps"]["existed_by"]')" = None ] || fail "no time"
expect_exit 3 verify evidence.cbor --ledger-id "$LEDGER_ID" --min-timestamps 1
run verify evidence.cbor --ledger-id "$LEDGER_ID" --tsa-root root.pem --min-timestamps 1 > /dev/null
expect_exit 2 verify evidence.cbor --tsa-root tsa.cnf # not a certificate

# --- A token got by hand: the imprint checkpoint show gives, to OpenSSL --------
IMPRINT="$(run checkpoint show --json | json 'd["timestamp_imprint"]')"
LATEST_SIZE="$(run checkpoint show --json | json 'd["tree_size"]')"
openssl ts -query -digest "$IMPRINT" -sha256 -cert -out hand.tsq 2> /dev/null
openssl ts -reply -config tsa.cnf -queryfile hand.tsq -token_out -out hand.tst 2> /dev/null
run checkpoint add-timestamp hand.tst --json | json 'd["tree_size"]' | contains -x "$LATEST_SIZE"
run checkpoint add-timestamp hand.tst > /dev/null # again: nothing changes
[ "$(run checkpoint timestamps --json | json 'len(d)')" = 2 ] || fail "two tokens"
expect_exit 2 checkpoint add-timestamp hand.tst --size "$FIRST_SIZE" # not over that checkpoint
expect_exit 2 checkpoint add-timestamp evidence.cbor # not a token
[ "$(run checkpoint timestamps --size "$FIRST_SIZE" --json | json 'len(d)')" = 1 ] || fail "--size"
run audit --json | json 'd["timestamps"]' | contains -x 2

# --- A server stamps by itself; a replica and a backup keep the tokens --------
run token create replica --scope read --out replica.token > /dev/null
# The program itself, not the run function: a function in the background
# is a subshell, and killing it would leave the server running.
"$CEXCHAIN" serve --listen 127.0.0.1:0 --json --log-key log.key --checkpoint-interval 1 \
    --tsa "$TSA" --timestamp-interval 1 > serve.json 2> serve.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do
    python3 -c "import json; json.load(open('serve.json'))" 2> /dev/null && break
    sleep 0.1
done
URL="$(json 'd["url"]' < serve.json)"
[ "$(json 'd["timestamp_authority"]' < serve.json)" = "$TSA" ] || fail "serve reports its authority"
run record issue --as root.key --type example.document/1 --field result=served > /dev/null
for _ in $(seq 1 100); do
    [ "$(run checkpoint timestamps --json | json 'len(d)')" -ge 3 ] && break
    sleep 0.2
done
[ "$(run checkpoint timestamps --json | json 'len(d)')" -ge 3 ] || { cat serve.log; fail "serve --tsa"; }
contains '"event":"timestamp"' serve.log
run serve --help | contains -- '--timestamp-interval'
expect_exit 1 serve --timestamp-interval 5 # needs --tsa

CEXCHAIN_TOKEN="$(cat replica.token)" run replica init --from "$URL" --ledger-id "$LEDGER_ID" \
    --ledger replica > /dev/null
PRIMARY_TOKENS="$(run checkpoint timestamps --json | json 'len(d)')"
REPLICA_TOKENS="$(run checkpoint timestamps --ledger replica --json | json 'len(d)')"
[ "$REPLICA_TOKENS" -ge 2 ] && [ "$REPLICA_TOKENS" -le "$PRIMARY_TOKENS" ] ||
    fail "the replica copies the tokens ($REPLICA_TOKENS of $PRIMARY_TOKENS)"

run backup create --log-key log.key --out ledger.cxb > /dev/null
run backup restore ledger.cxb --ledger restored > /dev/null
[ "$(run checkpoint timestamps --ledger restored --json | json 'len(d)')" = \
    "$(run checkpoint timestamps --json | json 'len(d)')" ] || fail "the backup carries the tokens"

# --- Help, completion ------------------------------------------------------------
run checkpoint timestamp --help | contains -- '--tsa URL'
run checkpoint add-timestamp --help | contains 'timestamp_imprint'
run completion bash | contains 'add-timestamp'
run help --json | contains '"command": "checkpoint timestamps"'

echo "timestamps end to end: passed"
