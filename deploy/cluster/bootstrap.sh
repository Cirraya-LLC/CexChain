#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Creates the demo cluster's ledger and members, once (see compose.yaml).
set -eu
if [ -e /members/node1/ledger/statements ]; then
    echo "already bootstrapped"
    exit 0
fi
cd /members/node1
kanhe key generate --no-passphrase --out root.key
kanhe key generate --no-passphrase --out log.key
kanhe init --ledger ledger --org "Demo Org" --root-key root.key --log-key log.key

# The executor service's sample: a contract whose `ask` asks for a notice,
# the executor's actor (it answers notify requests on that contract only),
# its token, and its config with one connector, all in its own volume.
kanhe contract deploy --bo /deploy/executor/notices.bo --ledger ledger --as root.key --json \
    > /tmp/deployed.json
CONTRACT="$(sed -n 's/^    "id": "\([0-9a-f]*\)".*/\1/p' /tmp/deployed.json | head -n 1)"
cd /members/executor
kanhe key generate --no-passphrase --out executor.key
kanhe executor add Executor --ledger /members/node1/ledger --as /members/node1/root.key \
    --contract "$CONTRACT" --kinds notify --key executor.key --config-out executor.json
kanhe token create executor --ledger /members/node1/ledger --scope executor \
    --out executor.token
kanhe executor connector add notices --config executor.json --type command \
    --kinds notify --program /bin/sh --arg /deploy/executor/notify.sh --secrets notify-token \
    --timeout 10
echo "$CONTRACT" > /members/node1/notices.contract
cd /members/node1

kanhe checkpoint create --ledger ledger --log-key log.key
kanhe token create admin --ledger ledger --scope read,submit,admin --out admin.token
kanhe cluster init --ledger ledger --id 1 --raft node1:7001 --api http://node1:8080
LEDGER_ID="$(kanhe status --ledger ledger --json | sed -n 's/^  "ledger_id": "\([0-9a-f]*\)".*/\1/p')"
echo "$LEDGER_ID" > ledger.id

# The others copy the founder's ledger through its API, as on separate hosts.
kanhe serve --ledger ledger --listen 127.0.0.1:8080 --read-only --quiet &
SERVER=$!
sleep 1
for n in 2 3; do
    KANHE_TOKEN="$(cat admin.token)" kanhe cluster join \
        --ledger "/members/node$n/ledger" --from http://127.0.0.1:8080 --ledger-id "$LEDGER_ID" \
        --id "$n" --raft "node$n:7001" --api "http://node$n:8080" \
        --secret-file ledger/cluster/secret
    cp ledger/api-tokens "/members/node$n/ledger/api-tokens"
    cp log.key admin.token "/members/node$n/"
done
kill "$SERVER"
wait "$SERVER" || true
chown -R 10001:10001 /members/node1 /members/node2 /members/node3 /members/executor
echo "bootstrapped ledger $LEDGER_ID with three members"
