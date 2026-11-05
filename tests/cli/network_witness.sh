#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Open witness networks (spec v0.13), end to end, against a witness written
# here from c2sp.org/tlog-witness and tlog-cosignature (Python's standard
# library and the openssl command line): the ledger's entry for a network's
# list, its checkpoint notes, add-checkpoint with consistency proofs, a 409
# answered from the witness's size, a witness ahead of the ledger refused,
# cosignatures kept, exported, and counted by a verifier that trusts the
# witness's verifier key; a server asking by itself, a replica and a backup
# keeping them.
# Usage: network_witness.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="network witness test"
unset CEXCHAIN_SERVER CEXCHAIN_TOKEN CEXCHAIN_CLOCK_OFFSET
export CEXCHAIN_LEDGER="$WORK/ledger"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
issue() { run record issue --as root.key --type example.document/1 --field n="$1" --json | json 'd["record"]["id"]'; }

# --- A witness, as c2sp.org/tlog-witness has it ---------------------------------
cat > witness.py << 'EOF'
import base64, hashlib, http.server, os, socketserver, struct, subprocess, sys, tempfile, time

work, name, origin, log_vkey = sys.argv[1:5]
key_pem = os.path.join(work, "witness.pem")
subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", key_pem], check=True)
der = subprocess.run(["openssl", "pkey", "-in", key_pem, "-pubout", "-outform", "DER"],
                     check=True, capture_output=True).stdout
public = der[-32:]
def key_id(n, kind, key):
    return hashlib.sha256(n.encode() + b"\n" + bytes([kind]) + key).digest()[:4]
open(os.path.join(work, "witness.vkey"), "w").write(
    f"{name}+{key_id(name, 4, public).hex()}+{base64.b64encode(bytes([4]) + public).decode()}")
log_name, log_id, log_key = log_vkey.split("+", 2)
log_key = base64.b64decode(log_key)[1:]
state = {"size": 0, "root": None}

def openssl_verify(public_key, message, signature):
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "k"), "wb").write(bytes.fromhex("302a300506032b6570032100") + public_key)
        open(os.path.join(d, "m"), "wb").write(message)
        open(os.path.join(d, "s"), "wb").write(signature)
        return subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey",
                               os.path.join(d, "k"), "-rawin", "-in", os.path.join(d, "m"), "-sigfile",
                               os.path.join(d, "s")], capture_output=True).returncode == 0

def sign(message):
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "m"), "wb").write(message)
        return subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key_pem, "-rawin", "-in",
                               os.path.join(d, "m")], check=True, capture_output=True).stdout

def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def consistent(old_size, new_size, old_root, new_root, proof):
    # RFC 9162, section 2.1.4.2.
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size & (old_size - 1) == 0:
        proof = [old_root] + proof
    if not proof:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node(c, fr), node(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root

class Witness(http.server.BaseHTTPRequestHandler):
    def answer(self, status, body=b"", kind="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        mode = open(os.path.join(work, "mode")).read().strip() if os.path.exists(os.path.join(work, "mode")) else ""
        if mode.startswith("size "):  # a lost state, or a longer history seen
            state["size"], state["root"] = int(mode[5:]), None
            os.remove(os.path.join(work, "mode"))
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        head, rest = body.split("\n\n", 1)
        lines = head.split("\n")
        old = int(lines[0][4:])
        proof = [base64.b64decode(p) for p in lines[1:]]
        text, signatures = rest.split("\n\n", 1)
        text += "\n"
        note_origin, size, root = text.split("\n")[:3]
        if note_origin != origin:
            return self.answer(404)
        size, root = int(size), base64.b64decode(root)
        ok = False
        for line in signatures.strip("\n").split("\n"):
            who, raw = line[2:].split(" ")
            raw = base64.b64decode(raw)
            if who == log_name and raw[:4].hex() == log_id:
                ok = openssl_verify(log_key, text.encode(), raw[4:])
        if not ok:
            return self.answer(403)
        if old > size:
            return self.answer(400)
        if old != state["size"]:
            return self.answer(409, f"{state['size']}\n".encode(), "text/x.tlog.size")
        if old == 0 and proof:
            return self.answer(422)
        if old and state["root"] is not None and not consistent(old, size, state["root"], root, proof):
            return self.answer(422)
        state["size"], state["root"] = size, root
        now = int(time.time())
        signature = sign(f"cosignature/v1\ntime {now}\n{text}".encode())
        line = f"— {name} {base64.b64encode(key_id(name, 4, public) + struct.pack('>Q', now) + signature).decode()}\n"
        self.answer(200, line.encode())

    def log_message(self, *args):
        pass

class Server(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

server = Server(("127.0.0.1", 0), Witness)
open(os.path.join(work, "port.tmp"), "w").write(str(server.server_address[1]))
os.rename(os.path.join(work, "port.tmp"), os.path.join(work, "port"))
server.serve_forever()
EOF

# --- A SHA-256 ledger, its note key, and its entry for a network's list ---------
for k in root log; do run key generate --out "$k.key" > /dev/null; done
run key generate --out note.key > /dev/null
LEDGER_ID="$(run init --name "Witnessed Org" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
RECORD="$(issue 1)"
run checkpoint create --log-key log.key > /dev/null
ENTRY="$(run witness network-entry --note-key note.key --contact "ops (at) example.org" --json)"
ORIGIN="$(echo "$ENTRY" | json 'd["origin"]')"
LOG_VKEY="$(echo "$ENTRY" | json 'd["vkey"]')"
[ "$ORIGIN" = "cirraya.com/cexchain/$LEDGER_ID" ] || fail "the origin is derived from the ledger id"
[ "${LOG_VKEY%%+*}" = "$ORIGIN" ] || fail "the note key's name is the origin"
run witness network-entry --note-key note.key --contact x --qpd 48 | contains -x "qpd 48"
run witness network-entry --note-key note.key --contact x | contains "^vkey $ORIGIN+"
expect_exit 1 witness network-entry --note-key root.key --contact x --qpd 0
run checkpoint note | contains -x "$ORIGIN"
run checkpoint note --note-key note.key | contains "^— $ORIGIN "

python3 witness.py "$WORK" witness.example/test "$ORIGIN" "$LOG_VKEY" 2> witness.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do [ -s port ] && break; sleep 0.1; done
[ -s port ] || { cat witness.log; fail "the test witness did not start"; }
WITNESS="http://127.0.0.1:$(cat port)/add-checkpoint"
WITNESS_VKEY="$(cat witness.vkey)"

# --- Listed, asked, cosigned -------------------------------------------------------
run witness register "$WITNESS" --vkey "$WITNESS_VKEY" --json | json 'd["kind"]' | contains -x network
expect_exit 1 witness register "$WITNESS" --vkey "$LOG_VKEY" # a log's key cosigns nothing
expect_exit 1 witness register "$WITNESS" --vkey "$WITNESS_VKEY" --name other
run witness registered --json | json '[w["kind"] for w in d["witnesses"]]' | contains network
run witness registered witness.example/test | contains 'network witness'
FIRST_SIZE="$(run status --json | json 'd["entries"]')"
run checkpoint network-cosign --note-key note.key --json | json 'd["witnesses"][0]["cosigned"]' | contains -x True
[ "$(run checkpoint network-cosignatures --json | json 'len(d)')" = 1 ] || fail "kept"
run checkpoint network-cosign --note-key note.key > /dev/null # again: the same size, cosigned anew
# Later entries: from the size it cosigned, with a consistency proof.
for i in 2 3 4; do issue "$i" > /dev/null; done
run checkpoint create --log-key log.key > /dev/null
run checkpoint network-cosign --note-key note.key | contains "cosigned the checkpoint at size"
run checkpoint network-cosignatures | contains -E "^ +[0-9]+  .*witness.example/test$"

# The witness lost its state: its 409 is answered from the size it gives.
issue 5 > /dev/null
run checkpoint create --log-key log.key > /dev/null
echo "size 0" > mode
run checkpoint network-cosign --note-key note.key > /dev/null
# A witness that saw a longer history of this ledger: refused, not asked again.
issue 6 > /dev/null
run checkpoint create --log-key log.key > /dev/null
echo "size 100000" > mode
expect_exit 2 checkpoint network-cosign --note-key note.key
contains 'a fork, or a restore' out.txt
echo "size 0" > mode

# --- Evidence: counted by a verifier that trusts the witness --------------------
run checkpoint network-cosign --note-key note.key > /dev/null
run export "$RECORD" --log-key log.key --out evidence.cbor > /dev/null
REPORT="$(run verify evidence.cbor --ledger-id "$LEDGER_ID" --witness-vkey "$WITNESS_VKEY" --min-witnesses 1 --json)"
[ "$(echo "$REPORT" | json 'd["witnesses"]["trusted"]')" = 1 ] || fail "trusted"
[ "$(echo "$REPORT" | json 'd["witnesses"]["network"][0]["witness"]')" = witness.example/test ] || fail "listed"
run verify evidence.cbor --witness-vkey "$WITNESS_VKEY" | contains 'witness.example/test saw size'
UNTRUSTED="$(run verify evidence.cbor --json)"
[ "$(echo "$UNTRUSTED" | json 'd["witnesses"]["untrusted"]')" = 1 ] || fail "untrusted"
expect_exit 3 verify evidence.cbor --min-witnesses 1
expect_exit 1 verify evidence.cbor --witness-vkey "$LOG_VKEY"
run audit --json | json 'd["network_cosignatures"]' | contains -E '^[1-9]'

# --- A server asks by itself; a replica and a backup keep them ---------------------
run token create replica --scope read --out replica.token > /dev/null
BEFORE="$(run checkpoint network-cosignatures --json | json 'len(d)')"
run serve --listen 127.0.0.1:0 --json --log-key log.key --checkpoint-interval 1 \
    --note-key note.key --network-interval 1 > serve.json 2> serve.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do
    python3 -c "import json; json.load(open('serve.json'))" 2> /dev/null && break
    sleep 0.1
done
URL="$(json 'd["url"]' < serve.json)"
[ "$(json 'd["network_witnesses"]' < serve.json)" = 1 ] || fail "serve lists the witness"
issue 7 > /dev/null
for _ in $(seq 1 100); do
    [ "$(run checkpoint network-cosignatures --json | json 'len(d)')" -gt "$BEFORE" ] && break
    sleep 0.2
done
[ "$(run checkpoint network-cosignatures --json | json 'len(d)')" -gt "$BEFORE" ] || { cat serve.log; fail "serve --note-key"; }
contains '"event":"network-cosignature"' serve.log
expect_exit 1 serve --network-interval 5 # needs --note-key
CEXCHAIN_TOKEN="$(cat replica.token)" run replica init --from "$URL" --ledger-id "$LEDGER_ID" \
    --ledger replica > /dev/null
[ "$(run checkpoint network-cosignatures --ledger replica --json | json 'len(d)')" -ge 1 ] || fail "the replica copies them"
run backup create --log-key log.key --out ledger.cxb > /dev/null
run backup restore ledger.cxb --ledger restored > /dev/null
[ "$(run checkpoint network-cosignatures --ledger restored --json | json 'len(d)')" = \
    "$(run checkpoint network-cosignatures --json | json 'len(d)')" ] || fail "the backup carries them"

# --- Unlisted, an SM3 ledger, help, completion --------------------------------------
run witness unregister witness.example/test > /dev/null
expect_exit 2 checkpoint network-cosign --note-key note.key
run key generate --out sm3root.key > /dev/null
run key generate --out sm3log.key > /dev/null
run init --name "SM3 Org" --root-key sm3root.key --log-key sm3log.key --hash sm3 --ledger sm3 > /dev/null
expect_exit 2 witness register "$WITNESS" --vkey "$WITNESS_VKEY" --ledger sm3
run checkpoint network-cosign --help | contains -- '--note-key KEY'
run witness network-entry --help | contains 'qpd'
run verify --help | contains -- '--witness-vkey'
run completion bash | contains 'network-cosignatures'

echo "network witness end to end: passed"
