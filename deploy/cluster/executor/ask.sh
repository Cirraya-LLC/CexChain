#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Asks for a notice through the cluster (see ../compose.yaml): creates an
# instance of the sample contract and calls its `ask`, whose request the
# executor service answers. Run in a client container with node1's volume
# at /keys; NOTE is the message (default: hello).
set -eu
export CEXCHAIN_TOKEN="$(cat /keys/admin.token)"
contract="$(cat /keys/notices.contract)"
ledger="$(cat /keys/ledger.id)"
set -- --server "${SERVER:-http://node2:8080}" --ledger-id "$ledger" --cache /tmp/cache \
    --as /keys/root.key
instance="$(cexchain contract create "$contract" create \
    --args "{\"fields\": {}, \"parties\": {\"we\": h'$ledger'}}" "$@" \
    | sed -n 's/^created instance \([0-9a-f]*\) .*/\1/p')"
cexchain contract call "$instance" ask --args "{\"note\": \"${NOTE:-hello}\"}" "$@"
echo "asked on instance $instance: cexchain contract instance $instance shows the reply"
