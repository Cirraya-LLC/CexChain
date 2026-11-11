#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Interop with an open network's witness (spec v0.13): litewitness
# (filippo.io/torchwood), the implementation witness networks run, cosigns
# a Kanhe ledger's checkpoint notes. It is configured, as a network's
# maintainers would, with the ledger's origin and note key from `witness
# network-entry`; the ledger asks it with `checkpoint network-cosign`,
# first from nothing and then with a consistency proof, and a verifier that
# trusts its verifier key counts its cosignature in exported evidence.
# Usage: litewitness.sh KANHE   ($LITEWITNESS, $WITNESSCTL: the programs,
# default on PATH; ssh-agent, ssh-keygen, and python3 must be on PATH)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
LITEWITNESS="${LITEWITNESS:-litewitness}"
WITNESSCTL="${WITNESSCTL:-witnessctl}"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export KANHE_PASSPHRASE="interop test"
unset KANHE_SERVER KANHE_TOKEN KANHE_CLOCK_OFFSET
export KANHE_LEDGER="$WORK/ledger"
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
run() { "$KANHE" "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
issue() { run record issue --as root.key --type example.document/1 --field n="$1" --json | json 'd["record"]["id"]'; }

# The ledger, its note key, and the entry a network's maintainers configure.
for k in root log note; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --name "Interop Org" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
RECORD="$(issue 1)"
run checkpoint create --log-key log.key > /dev/null
ENTRY="$(run witness network-entry --note-key note.key --contact interop --json)"
ORIGIN="$(echo "$ENTRY" | json 'd["origin"]')"
LOG_VKEY="$(echo "$ENTRY" | json 'd["vkey"]')"

# litewitness: its key in an ssh-agent of its own, the log configured by hand.
ssh-keygen -q -t ed25519 -N '' -f witness -C interop
ssh-agent -a "$WORK/agent.sock" > agent.env
PIDS+=("$(sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p' agent.env)")
SSH_AUTH_SOCK="$WORK/agent.sock" ssh-add -q witness
FINGERPRINT="$(ssh-keygen -lf witness.pub | awk '{print $2}')"
NAME=example.org/interop-witness
"$WITNESSCTL" add-log -db "$WORK/witness.db" -origin "$ORIGIN"
"$WITNESSCTL" add-key -db "$WORK/witness.db" -origin "$ORIGIN" -key "$LOG_VKEY"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
"$LITEWITNESS" -db "$WORK/witness.db" -name "$NAME" -key "$FINGERPRINT" -ssh-agent "$WORK/agent.sock" \
    -listen "127.0.0.1:$PORT" > litewitness.log 2>&1 &
PIDS+=("$!")
for _ in $(seq 1 100); do
    python3 -c "import socket; socket.create_connection(('127.0.0.1', $PORT), 1)" 2> /dev/null && break
    sleep 0.1
done
# Its verifier key, from its public key (c2sp.org/signed-note, type 0x04).
WITNESS_VKEY="$(python3 - "$NAME" witness.pub << 'EOF'
import base64, hashlib, sys
name, path = sys.argv[1], sys.argv[2]
key = base64.b64decode(open(path).read().split()[1])[-32:]
material = bytes([4]) + key
key_id = hashlib.sha256(name.encode() + b"\n" + material).digest()[:4]
print(name + "+" + key_id.hex() + "+" + base64.b64encode(material).decode())
EOF
)"

# Asked from nothing, then from the size it cosigned, with a consistency proof.
run witness register "http://127.0.0.1:$PORT/add-checkpoint" --vkey "$WITNESS_VKEY" > /dev/null
run checkpoint network-cosign --note-key note.key || { cat litewitness.log; fail "the first cosignature"; }
for i in 2 3 4 5; do issue "$i" > /dev/null; done
run checkpoint create --log-key log.key > /dev/null
run checkpoint network-cosign --note-key note.key || { cat litewitness.log; fail "the second cosignature"; }
[ "$(run checkpoint network-cosignatures --json | json 'len(d)')" = 2 ] || fail "two cosignatures kept"

# Counted by a verifier that trusts it.
run export "$RECORD" --log-key log.key --out evidence.cbor > /dev/null
REPORT="$(run verify evidence.cbor --ledger-id "$LEDGER_ID" --witness-vkey "$WITNESS_VKEY" --min-witnesses 1 --json)"
[ "$(echo "$REPORT" | json 'd["witnesses"]["trusted"]')" = 1 ] || fail "litewitness's cosignature counts"
echo "litewitness interop: passed"
