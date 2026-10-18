#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The compose file's sample connector program (a `command` connector): the
# executor runs it once per request, with the request as one JSON line on
# stdin, "secrets" included (here notify-token, sealed from a Docker secret).
# Replace its body with a call to your own system. It writes a line per
# request to /data/notified.log, never the secret, and answers done with a
# reference; exit 75 asks to try again, any other failure fails the request.
set -eu
request="$(cat)"
id="$(printf '%s' "$request" | grep -o '"id":"[0-9a-f]*"' | head -n 1 | cut -d '"' -f 4)"
case "$request" in
    *'"notify-token":"'*) ;;
    *) echo '{"reason": "no-token"}'; exit 3 ;;
esac
[ -n "$id" ] || exit 75
printf '%s notify %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$id" >> /data/notified.log
printf '{"result": "N-%s"}\n' "$(printf '%s' "$id" | cut -c 1-8)"
