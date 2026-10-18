#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The executor service (see ../compose.yaml): seals the connector's secret
# from the Docker secret notify_token (a file on the host, never in the image
# or the compose file), then runs the executor until it is stopped. It finds
# requests at one member, verifies each in the instance's signed evidence,
# acts through its connectors, and answers; while that member restarts, or
# the cluster elects a leader, it waits and tries again within seconds.
set -eu
cexchain executor secret set notify-token --state /data/state \
    --from-file /run/secrets/notify_token > /dev/null
exec cexchain executor run --config /data/executor.json --state /data/state \
    --server "${CEXCHAIN_EXECUTOR_SERVER:-http://node1:8080}" \
    --token-file /data/executor.token --as /data/executor.key
