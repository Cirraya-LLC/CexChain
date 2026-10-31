#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Update checks, notify only: a release manifest signed with a release key
# made here says a newer version exists; update check says so, and update
# install downloads this computer's package, checks its size and SHA-256,
# and says how to install it. Refused: a manifest changed after signing, one
# signed by another key, a package that is not the one named. Over the web
# too, through a redirect. A build with no release key or manifest checks
# nothing.
# Usage: update.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export CEXCHAIN_PASSPHRASE="update test"

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

for command in "update check" "update install" "update sign"; do
    # shellcheck disable=SC2086
    run $command --help | grep -F "cexchain $command" > /dev/null || fail "help for $command"
done
run completion bash | grep "install" > /dev/null || fail "completion"

# Without a release key and a manifest, nothing is checked.
run update check | grep "checks no updates" > /dev/null || fail "a build without a release key"
[ "$(run update check --json | json 'd["checked"]')" = False ] || fail "--json"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) PLATFORM=linux-x86_64 ;;
    Linux-aarch64) PLATFORM=linux-aarch64 ;;
    Darwin-arm64) PLATFORM=macos-arm64 ;;
    *) PLATFORM=macos-x86_64 ;;
esac
run key generate --out release.key > /dev/null
run key public release.key --out release.pub > /dev/null
printf 'the package itself\n' > cexchain-99.0.0.tar.gz
manifest() {
    python3 - "$1" "$2" "$PLATFORM" << 'PY'
import hashlib, json, os, sys
out, version, platform = sys.argv[1:]
name = "cexchain-99.0.0.tar.gz"
data = open(name, "rb").read()
json.dump({"product": "cexchain", "version": version, "released": "2099-01-01",
           "notes": "https://example.org/notes",
           "files": [{"platform": platform, "kind": "tar.gz", "name": name, "url": name,
                      "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]},
          open(out, "w"))
PY
}
manifest newer.json 99.0.0
run update sign newer.json --as release.key > /dev/null
[ -f newer.json.sig ] || fail "update sign writes MANIFEST.sig"
run update check --manifest newer.json --release-key release.pub > out.txt
grep -q "cexchain 99.0.0 is available" out.txt || fail "a newer version"
[ "$(run update check --manifest newer.json --release-key release.pub --json | json '(d["newer"], d["platform"])')" = "(True, '$PLATFORM')" ] ||
    fail "update check --json"

manifest same.json 0.0.1
run update sign same.json --as release.key > /dev/null
run update check --manifest same.json --release-key release.pub | grep "is up to date" > /dev/null ||
    fail "not newer"

# Changed after signing, or signed by another key: refused.
python3 -c "
import json; d = json.load(open('newer.json')); d['version'] = '99.0.1'
json.dump(d, open('changed.json', 'w'))"
cp newer.json.sig changed.json.sig
expect_exit 3 update check --manifest changed.json --release-key release.pub
grep -q "NOT VERIFIED" out.txt || fail "a changed manifest"
run key generate --out other.key > /dev/null
run key public other.key --out other.pub > /dev/null
expect_exit 3 update check --manifest newer.json --release-key other.pub
expect_exit 2 update sign out.txt --as release.key
grep -q "not a release manifest" out.txt || fail "only manifests are signed"

# Install: downloaded, checked, and said how to install; nothing installed.
run update install --manifest newer.json --release-key release.pub --dir downloads --json > installed.json
cmp downloads/cexchain-99.0.0.tar.gz cexchain-99.0.0.tar.gz || fail "the package downloaded"
json 'd["install"]' < installed.json | grep "cexchain-99.0.0.tar.gz" > /dev/null || fail "how to install it"

# Over the web, through a redirect to a download signed in its query, as a
# release's "latest" link does.
python3 - << 'PY' &
import http.server
class Files(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path.startswith("/latest/"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:%d/files/%s?sig=a%%2Fb&se=1"
                             % (self.server.server_port, self.path[len("/latest/"):]))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if not self.path.startswith("/files/") or "?sig=" not in self.path:
            self.send_error(404)
            return
        self.path = "/" + self.path[len("/files/"):].split("?")[0]
        super().do_GET()
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Files)
open("port.tmp", "w").write(str(server.server_port))
__import__("os").rename("port.tmp", "port.txt")
server.serve_forever()
PY
SERVER=$!
trap 'kill "$SERVER" 2> /dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 1 100); do [ -s port.txt ] && break; sleep 0.1; done
LATEST="http://127.0.0.1:$(cat port.txt)/latest/newer.json"
run update check --manifest "$LATEST" --release-key release.pub | grep "99.0.0 is available" > /dev/null ||
    fail "a manifest over the web"
run update install --manifest "$LATEST" --release-key release.pub --dir web > /dev/null
cmp web/cexchain-99.0.0.tar.gz cexchain-99.0.0.tar.gz || fail "a package over the web"
expect_exit 2 update check --manifest "http://127.0.0.1:$(cat port.txt)/missing.json" \
    --release-key release.pub
grep -q "status 404" out.txt || fail "a missing manifest"
printf 'another package\n' > cexchain-99.0.0.tar.gz
expect_exit 3 update install --manifest newer.json --release-key release.pub --dir downloads2
grep -q "not the one the manifest names" out.txt || fail "a package not the one named"
[ ! -e downloads2/cexchain-99.0.0.tar.gz ] || fail "nothing kept of it"

echo "update: all checks passed"
