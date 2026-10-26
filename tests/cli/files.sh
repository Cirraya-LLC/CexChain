#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Kept files: a record's attached files kept with it, sealed to the vault key,
# on a ledger directory and through a server (--server, submission key 4 and
# /v1/vault/files). A kept copy is checked against the record when it is
# opened or added, kept once, and taken into backups.
# Usage: files.sh CEXCHAIN
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

export CEXCHAIN_PASSPHRASE="files test"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
start_server() {
    local out="$1"; shift
    "$CEXCHAIN" serve --listen 127.0.0.1:0 --json "$@" > "$out" 2> "$out.log" &
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

for k in root log; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --ledger local --name "Files Test" --root-key root.key --log-key log.key --json | json 'd["ledger_id"]')"
printf 'the photo itself\n' > photo.jpg
printf 'some notes\n' > notes.txt
printf 'not the photo\n' > forged.jpg

# --- On a ledger directory -----------------------------------------------------
expect_exit 1 record issue --ledger local --as root.key --type example.org.photo/1 --field a=b --keep-files
contains -- '--keep-files keeps the files given with --attach' out.txt
RECORD="$(run record issue --ledger local --as root.key --type example.org.photo/1 --field place=Harbour \
    --attach photo.jpg --attach notes.txt --keep-files --json | json 'd["record"]["id"]')"
LIST="$(run record file list --ledger local "$RECORD" --json)"
[ "$(echo "$LIST" | json '[f["name"] for f in d["files"]]')" = "['photo.jpg', 'notes.txt']" ] ||
    fail "record file list --json"
[ "$(echo "$LIST" | json '[f["kept"] for f in d["files"]]')" = "[True, True]" ] || fail "both kept"
run record file list --ledger local "$RECORD" | contains 'photo.jpg .* kept'
[ "$(find local/vault/files -name '*.cbor' | wc -l)" -eq 2 ] || fail "two sealed files"
! grep -q 'the photo itself' local/vault/files/*/0.cbor || fail "a kept file is sealed"
run record file get --ledger local "$RECORD" photo.jpg --out got.jpg | contains 'checked against the record'
cmp got.jpg photo.jpg || fail "the kept photo"
run record file get --ledger local "$RECORD" 1 --out got.txt --json | json 'd["name"]' | contains -x notes.txt
cmp got.txt notes.txt || fail "a file by its index"
expect_exit 1 record file get --ledger local "$RECORD" missing.png --out x
contains 'attaches no file named missing.png' out.txt

# A kept file is replaced by nothing else: removed, then added back only as itself.
run record file remove --ledger local "$RECORD" notes.txt | contains 'still commits to it'
expect_exit 2 record file remove --ledger local "$RECORD" notes.txt
expect_exit 2 record file get --ledger local "$RECORD" notes.txt --out x
contains 'no copy of notes.txt is kept' out.txt
expect_exit 2 record file add --ledger local "$RECORD" forged.jpg --name notes.txt
contains 'not the file the record committed to' out.txt
run record file add --ledger local "$RECORD" notes.txt | contains 'kept notes.txt'
run record file add --ledger local "$RECORD" notes.txt | contains 'kept already'
# A sealed file swapped on disk is caught when opened.
cp local/vault/files/*/1.cbor saved.cbor
cp local/vault/files/*/1.cbor local/vault/files/*/0.cbor
expect_exit 2 record file get --ledger local "$RECORD" photo.jpg --out x
cp saved.cbor local/vault/files/*/1.cbor
run record file remove --ledger local "$RECORD" photo.jpg > /dev/null
run record file add --ledger local "$RECORD" photo.jpg > /dev/null

# Backups take the kept files, and a restore brings them back.
run backup create --ledger local --log-key log.key --out backup.cbor > /dev/null
run backup restore backup.cbor --ledger restored > /dev/null
run record file get --ledger restored "$RECORD" photo.jpg --out restored.jpg --vault-key local/vault/vault.key > /dev/null
cmp restored.jpg photo.jpg || fail "a kept file restored"

for command in "record file list" "record file get" "record file add" "record file remove"; do
    read -r -a words <<< "$command"
    run "${words[@]}" --help | contains -- '--json'
done
run record issue --help | contains -- '--keep-files'
run completion bash | contains 'file'

# --- Through a server ----------------------------------------------------------------
run token create --ledger local ops --scope read,submit,admin --out ops.token > /dev/null
run token create --ledger local writer --scope read,submit --out writer.token > /dev/null
start_server server.json --ledger local --log-key log.key --checkpoint-interval 0 --max-body 1048576
URL="$(json 'd["url"]' < server.json)"
export CEXCHAIN_SERVER="$URL" CEXCHAIN_TOKEN="$(cat writer.token)"
CACHE="$WORK/cache"
run status --cache "$CACHE" --ledger-id "$LEDGER_ID" > /dev/null
REMOTE="$(run record issue --cache "$CACHE" --as root.key --type example.org.photo/1 --field place=Peak \
    --attach photo.jpg --keep-files --json | json 'd["record"]["id"]')"
[ "$(find local/vault/files/"$REMOTE" -name '*.cbor' | wc -l)" -eq 1 ] || fail "kept by the server"
run record file list --cache "$CACHE" "$REMOTE" | contains 'photo.jpg .* kept'
run record file get --cache "$CACHE" "$REMOTE" photo.jpg --out remote.jpg \
    --vault-key local/vault/vault.key > /dev/null
cmp remote.jpg photo.jpg || fail "a kept file through the server"
# Removing needs the admin scope; adding again goes through PUT.
expect_exit 2 record file remove --cache "$CACHE" "$REMOTE" photo.jpg
CEXCHAIN_TOKEN="$(cat ops.token)" run record file remove --cache "$CACHE" "$REMOTE" photo.jpg > /dev/null
run record file list --cache "$CACHE" "$REMOTE" | contains 'not kept'
expect_exit 2 record file add --cache "$CACHE" "$REMOTE" forged.jpg --name photo.jpg --vault-key local/vault/vault.key
run record file add --cache "$CACHE" "$REMOTE" photo.jpg --vault-key local/vault/vault.key > /dev/null
run record file list --cache "$CACHE" "$REMOTE" --json | json 'd["files"][0]["kept"]' | contains -x True

# The API refuses what is not a kept file for an attachment.
put() {
    python3 - "$URL" "$1" "$2" "$(cat writer.token)" << 'PY'
import sys, urllib.request
url, path, body, token = sys.argv[1:5]
request = urllib.request.Request(url + path, data=open(body, "rb").read(), method="PUT",
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/cbor"})
try:
    print(urllib.request.urlopen(request).status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
}
printf 'not cbor' > junk.bin
[ "$(put "/v1/vault/files/$REMOTE/0" junk.bin)" = 400 ] || fail "a malformed file"
[ "$(put "/v1/vault/files/$REMOTE/5" saved.cbor)" = 400 ] || fail "no attachment at that index"
[ "$(put "/v1/vault/files/$REMOTE/0" saved.cbor)" = 400 ] || fail "another size"
[ "$(put "/v1/vault/files/$(printf '%064d' 0)/0" saved.cbor)" = 404 ] || fail "no such record"

echo "files: all checks passed"
