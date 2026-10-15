#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Keys on tokens, end to end, with SoftHSM standing in for USB keys and HSMs:
# the organization's root key lives on a token, a person signs with a token
# key and proves presence with a second one (a UKey), and verifiers see it.
# Usage: pkcs11.sh CEXCHAIN SOFTHSM_MODULE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
MODULE="$2"
# Leaks inside SoftHSM itself are not ours to fix. Matching them needs full
# stacks: the fast unwinder stops in libcrypto, which has no frame pointers.
export LSAN_OPTIONS="suppressions=$(cd "$(dirname "$0")" && pwd)/lsan-softhsm.supp${LSAN_OPTIONS:+:$LSAN_OPTIONS}"
export ASAN_OPTIONS="fast_unwind_on_malloc=0${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
contains() { grep "$@" > /dev/null; }
id_from() { grep -oE '[0-9a-f]{64}' | sed -n 1p; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}

mkdir tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > softhsm2.conf
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
softhsm2-util --init-token --free --label CexChain --pin 123456 --so-pin 12345678 > /dev/null
export CEXCHAIN_PKCS11_PIN=123456 CEXCHAIN_PASSPHRASE="token test" CEXCHAIN_LEDGER="$WORK/ledger"
token() { printf 'pkcs11:token=CexChain;object=%s?module-path=%s' "$1" "$MODULE"; }
ROOT="$(token root)"
ALICE_KEY="$(token alice)"
ALICE_UKEY="$(token alice-ukey)"

# Keys are generated on the token; only public halves come out.
run key generate --pkcs11 "$ROOT" --alg esp256 --out root.pub | contains 'never leaves it'
run key generate --pkcs11 "$ALICE_KEY" --alg ed25519 --out alice.pub > /dev/null
run key generate --pkcs11 "$ALICE_UKEY" --alg esp256 --out alice-ukey.pub > /dev/null
expect_exit 2 key generate --pkcs11 "$ROOT" --alg esp256 --out again.pub
contains 'already has a key' out.txt
run key show "$ROOT" | contains 'key on a token'
run key show "$ROOT" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["type"] == "token"'
CEXCHAIN_PKCS11_PIN=000000 expect_exit 2 key show "$ROOT"
contains 'wrong PIN' out.txt

# The organization's root key never leaves its token (an HSM).
run key generate --out log.key > /dev/null
run init --org "Token Bank" --root-key "$ROOT" --log-key log.key > /dev/null
ALICE="$(run actor add --as "$ROOT" --kind person --name "Alice Officer" --key alice.pub | id_from)"

# Alice's UKey proves her presence.
run presence enroll --pkcs11 "$ALICE_UKEY" --label "Bank UKey" --out alice.ukey | contains 'hardware key enrolled'
run inspect alice.ukey --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["kind"] == "passkey-credential" and d["method"] == "hardware-key"'
run actor set-presence "$ALICE" --as "$ROOT" --credential alice.ukey > /dev/null
run actor show "$ALICE" | contains 'hardware key:  ESP256 .* (Bank UKey)'
run delegation grant --as "$ROOT" --to "$ALICE" --allow record-register,record-endorse --days 1 --require-presence > /dev/null

expect_exit 2 record issue --as "$ALICE_KEY" --type example.document/1 --field result=pass
contains 'requires proof of presence' out.txt
# The presence key is a second key, unlocked by a person: never the signing
# key, never one whose PIN is written into its URI.
expect_exit 1 record issue --as "$ALICE_KEY" --type example.document/1 --field result=pass --presence-key "$ALICE_KEY"
contains 'must not be the signing key' out.txt
expect_exit 1 record issue --as "$ALICE_KEY" --type example.document/1 --field result=pass \
    --presence-key "$ALICE_UKEY&pin-value=1234"
contains 'remove pin-value' out.txt
# URIs: an absolute module path, and each attribute once.
expect_exit 2 key public "pkcs11:token=CexChain;object=alice?module-path=libsofthsm2.so"
contains 'absolute' out.txt
expect_exit 2 key public "$ALICE_KEY&module-path=/tmp/other.so"
contains 'repeats an attribute' out.txt
RECORD="$(run record issue --as "$ALICE_KEY" --type example.document/1 --field result=pass \
    --presence-key "$ALICE_UKEY" | id_from)"
run record endorse "$RECORD" --as "$ALICE_KEY" --role inspector --presence-key "$ALICE_UKEY" > /dev/null
run record history "$RECORD" | contains 'presence proven'

# Anyone can see she was present, from evidence alone.
run checkpoint create --log-key log.key > /dev/null
run export "$RECORD" --log-key log.key --out bundle.cbor > /dev/null
LEDGER_ID="$(run status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["ledger_id"])')"
run verify bundle.cbor --ledger-id "$LEDGER_ID" | contains 'present: hardware key'
run verify bundle.cbor --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert [e["presence"]["method"] for e in d["events"]] == ["hardware-key", "hardware-key"]'
run audit | contains 'audit passed'
echo "pkcs11 end-to-end: ok"
