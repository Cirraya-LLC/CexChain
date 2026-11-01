#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Signing in with an organization's account: a console trusts an OpenID
# Connect provider and a CAS server (here a small one in Python, signing ID
# tokens with RS256 through openssl), and applicants sign in through them:
# the flow, the one-time code, the applicant's session and pseudonym, the
# domains a provider allows, and refusals (a replayed state, a used code,
# an applicant's token on staff routes).
# Usage: sso.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
export CEXCHAIN_PASSPHRASE="sso test"
export CEXCHAIN_LEDGER="$WORK/school"
unset CEXCHAIN_SERVER CEXCHAIN_TOKEN

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
wait_for() { for _ in $(seq 1 300); do [ -s "$1" ] && return 0; sleep 0.1; done; fail "$1 did not appear"; }

# --- The identity provider ------------------------------------------------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out idp.pem 2> /dev/null
cat > idp.py << 'PY'
import base64, hashlib, http.server, json, os, subprocess, sys, time, urllib.parse
port_file, key = sys.argv[1], sys.argv[2]
modulus = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-modulus"],
                         capture_output=True, text=True, check=True).stdout.strip().split("=")[1]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
n, e = b64(bytes.fromhex(modulus)), b64((65537).to_bytes(3, "big"))
codes = {}
class Provider(http.server.BaseHTTPRequestHandler):
    def answer(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        issuer = f"http://127.0.0.1:{self.server.server_port}"
        if url.path == "/.well-known/openid-configuration":
            self.answer(200, json.dumps({"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                                         "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"}).encode())
        elif url.path == "/jwks":
            self.answer(200, json.dumps({"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
                                                   "n": n, "e": e}]}).encode())
        elif url.path == "/authorize":
            assert q["response_type"] == "code" and q["code_challenge_method"] == "S256" and "openid" in q["scope"]
            code = b64(os.urandom(12))
            codes[code] = q
            self.answer(302, headers=[("Location", q["redirect_uri"] + "?" +
                                       urllib.parse.urlencode({"code": code, "state": q["state"]}))])
        elif url.path == "/cas/login" and "service" not in q:
            self.answer(200, b"{}")
        elif url.path == "/cas/login":
            service = q["service"]
            self.answer(302, headers=[("Location", service + ("&" if "?" in service else "?") + "ticket=ST-1-test")])
        elif url.path == "/cas/p3/serviceValidate":
            ok = q.get("ticket") == "ST-1-test" and q.get("format") == "JSON"
            body = {"serviceResponse": {"authenticationSuccess": {"user": "chan", "attributes": {
                "displayName": ["Chan Wing"], "mail": ["chan@school.example"]}}}} if ok else \
                {"serviceResponse": {"authenticationFailure": {"code": "INVALID_TICKET"}}}
            self.answer(200, json.dumps(body).encode())
        else:
            self.answer(404)
    def do_POST(self):
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()))
        issuer = f"http://127.0.0.1:{self.server.server_port}"
        want = "Basic " + base64.b64encode(b"console:the-client-secret").decode()
        q = codes.pop(form.get("code", ""), None)
        if (self.path != "/token" or self.headers.get("Authorization") != want or q is None
                or b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != q["code_challenge"]
                or form.get("redirect_uri") != q["redirect_uri"]):
            self.answer(400, b'{"error": "invalid_grant"}')
            return
        now = int(time.time())
        header = b64(json.dumps({"alg": "RS256", "kid": "k1", "typ": "JWT"}).encode())
        claims = b64(json.dumps({"iss": issuer, "sub": "student-42", "aud": "console", "iat": now,
                                 "exp": now + 300, "nonce": q["nonce"], "name": "Li Ming",
                                 "email": "li@school.example", "email_verified": True}).encode())
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key],
                                   input=(header + "." + claims).encode(), capture_output=True, check=True).stdout
        self.answer(200, json.dumps({"access_token": "x", "token_type": "Bearer",
                                     "id_token": header + "." + claims + "." + b64(signature)}).encode())
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
open(port_file + ".tmp", "w").write(str(server.server_port))
os.rename(port_file + ".tmp", port_file)
server.serve_forever()
PY
python3 idp.py idp.port idp.pem 2> idp.log &
PIDS+=("$!")
wait_for idp.port
IDP="http://127.0.0.1:$(cat idp.port)"

# --- The console, set up for scripts, unlocked ------------------------------------------
python3 - << 'PY'
import os
def text(value):
    data = value.encode()
    return bytes([0x60 + len(data)]) + data
credential = bytes([0xa3, 0x01]) + text("localhost") + bytes([0x02, 0x50]) + os.urandom(16)
credential += bytes([0x03, 0x82, 0x32, 0x58, 0x20]) + os.urandom(32)
open("owner.passkey", "wb").write(credential)
PY
printf 'the unlock passphrase of these tests\n' > unlock.txt
run console setup --name "School Owner" --credential owner.passkey --unlock-file unlock.txt > /dev/null
printf 'the-client-secret\n' > secret.txt

# --- Providers ------------------------------------------------------------------------
expect_exit 1 console sso add school --oidc "$IDP"
contains 'client-secret-file' out.txt
expect_exit 1 console sso add school --oidc "$IDP" --cas "$IDP/cas"
expect_exit 1 console sso add school --oidc http://login.school.example --client-id console \
    --client-secret-file secret.txt
contains 'https' out.txt
expect_exit 1 console sso add School --oidc "$IDP" --client-id console --client-secret-file secret.txt
run console sso add school --oidc "$IDP" --client-id console --client-secret-file secret.txt \
    --label "School account" --allow-domain school.example > out.txt
contains '/console/sso/callback' out.txt
run console sso add campus --cas "$IDP/cas" --label "Campus account" > /dev/null
run console sso add strict --oidc "$IDP" --client-id console --client-secret-file secret.txt \
    --allow-domain other.example > /dev/null
expect_exit 2 console sso add campus --cas "$IDP/cas"
contains 'replace' out.txt
[ "$(run console sso list --json | json '[p["name"] for p in d]')" = "['school', 'campus', 'strict']" ] ||
    fail "console sso list"
run console sso show school --json | json 'd["secret_sealed"], d["allow_domains"]' |
    contains -xF "True ['school.example']"
! grep -rq the-client-secret school/console/identity.json || fail "the secret is not kept in the clear"
run console sso test school | contains 'discovery ok; 1 signing key'
run console sso test campus --json | json 'd["login"]' | contains -x "$IDP/cas/login"

# --- The console runs ---------------------------------------------------------------------
FREE="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
"$CEXCHAIN" console run --port "$FREE" --unlock-file unlock.txt --quiet > run.log 2>&1 &
PIDS+=("$!")
for _ in $(seq 1 300); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:$FREE/console/')" 2> /dev/null && break
    sleep 0.1
done
cat > flow.py << 'PY'
# The browser's part: begin, follow the provider, back to the console, finish.
import http.client, json, sys, urllib.parse
port, provider = int(sys.argv[1]), sys.argv[2]
host, origin = f"localhost:{port}", f"http://localhost:{port}"
def call(method, path, body=None, token=None, to=("127.0.0.1", port), headers_host=None):
    c = http.client.HTTPConnection(*to, timeout=20)
    headers = {"Host": headers_host or host}
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Origin"] = origin
    if token:
        headers["Authorization"] = "Bearer " + token
    c.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
    r = c.getresponse()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read().decode()
status, _, body = call("POST", "/console/api/sso/begin", {"provider": provider, "form": "day-student"})
assert status == 200, body
url = urllib.parse.urlparse(json.loads(body)["url"])
status, headers, _ = call("GET", url.path + "?" + url.query, to=(url.hostname, url.port),
                          headers_host=f"{url.hostname}:{url.port}")
assert status == 302, status
back = urllib.parse.urlparse(headers["location"])
assert back.netloc == host and back.path == "/console/sso/callback", back
status, headers, _ = call("GET", back.path + "?" + back.query)
assert status == 303, status
fragment = headers["location"]
print(json.dumps({"fragment": fragment, "callback": back.path + "?" + back.query}))
PY
signin() { python3 flow.py "$FREE" "$1"; }
finish() {
    python3 - "$FREE" "$1" << 'PY'
import http.client, json, sys
port, code = int(sys.argv[1]), sys.argv[2]
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
c.request("POST", "/console/api/sso/finish", body=json.dumps({"code": code}),
          headers={"Host": f"localhost:{port}", "Origin": f"http://localhost:{port}", "Content-Type": "application/json"})
r = c.getresponse()
print(json.dumps({"status": r.status, "body": json.loads(r.read() or b"{}")}))
PY
}
get() {
    python3 - "$FREE" "$1" "${2:-}" "${3:-GET}" << 'PY'
import http.client, json, sys
port, path, token, method = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
headers = {"Host": f"localhost:{port}"}
if token:
    headers["Authorization"] = "Bearer " + token
if method != "GET":
    headers["Origin"] = f"http://localhost:{port}"
c.request(method, path, headers=headers)
r = c.getresponse()
print(r.status)
print(r.read().decode())
PY
}

[ "$(get /console/api/sso | sed -n 2p | json '[p["label"] for p in d["providers"]]')" = \
    "['School account', 'Campus account', 'strict']" ] || fail "GET /console/api/sso"

# OpenID Connect: in, with a one-time code, then a session.
FLOW="$(signin school)"
FRAGMENT="$(echo "$FLOW" | json 'd["fragment"]')"
case "$FRAGMENT" in /console/#/signed-in/*) ;; *) fail "signed in: $FRAGMENT" ;; esac
CODE="${FRAGMENT##*/}"
DONE="$(finish "$CODE")"
[ "$(echo "$DONE" | json 'd["status"]')" = 200 ] || fail "finish: $DONE"
TOKEN="$(echo "$DONE" | json 'd["body"]["token"]')"
PSEUDONYM="$(echo "$DONE" | json 'd["body"]["applicant"]["pseudonym"]')"
echo "$PSEUDONYM" | contains -E '^a-[0-9a-f]{24}$'
[ "$(echo "$DONE" | json 'd["body"]["applicant"]["form"], d["body"]["applicant"]["email"]')" = \
    "day-student li@school.example" ] || fail "the applicant"
[ "$(finish "$CODE" | json 'd["status"]')" = 401 ] || fail "a code is used once"
[ "$(get /console/api/applicant "$TOKEN" | sed -n 2p | json 'd["applicant"]["pseudonym"]')" = "$PSEUDONYM" ] ||
    fail "GET /console/api/applicant"
[ "$(get /console/api/things "$TOKEN" | sed -n 1p)" = 401 ] || fail "an applicant is not staff"
# The provider's state is used once: the same answer again is refused.
CALLBACK="$(echo "$FLOW" | json 'd["callback"]')"
get "$CALLBACK" > replay.txt || true
python3 - "$FREE" "$CALLBACK" << 'PY' | contains 'sign-in-failed/expired'
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=10)
c.request("GET", sys.argv[2], headers={"Host": f"localhost:{sys.argv[1]}"})
print(c.getresponse().getheader("Location"))
PY
# The same person again: the same pseudonym.
AGAIN="$(finish "$(signin school | json 'd["fragment"]' | sed 's|.*/||')")"
[ "$(echo "$AGAIN" | json 'd["body"]["applicant"]["pseudonym"]')" = "$PSEUDONYM" ] || fail "a stable pseudonym"
# Signing out.
[ "$(get /console/api/applicant "$TOKEN" DELETE | sed -n 1p)" = 200 ] || fail "sign out"
[ "$(get /console/api/applicant "$TOKEN" | sed -n 1p)" = 401 ] || fail "signed out"

# CAS: another provider, another pseudonym.
CAS="$(finish "$(signin campus | json 'd["fragment"]' | sed 's|.*/||')")"
[ "$(echo "$CAS" | json 'd["body"]["applicant"]["name"]')" = "Chan Wing" ] || fail "CAS: $CAS"
[ "$(echo "$CAS" | json 'd["body"]["applicant"]["pseudonym"]')" != "$PSEUDONYM" ] || fail "CAS pseudonym"

# A provider that allows only another domain turns the account away.
signin strict | json 'd["fragment"]' | contains 'sign-in-failed/not-allowed'

# Bad requests.
python3 - "$FREE" << 'PY'
import http.client, json, sys
port = int(sys.argv[1])
def post(path, body, origin=True):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": f"localhost:{port}", "Content-Type": "application/json"}
    if origin:
        headers["Origin"] = f"http://localhost:{port}"
    c.request("POST", path, body=json.dumps(body), headers=headers)
    return c.getresponse().status
assert post("/console/api/sso/begin", {"provider": "nobody"}) == 404
assert post("/console/api/sso/begin", {}) == 400
assert post("/console/api/sso/begin", {"provider": "school"}, origin=False) == 403
assert post("/console/api/sso/finish", {"code": "made-up"}) == 401
PY

# Removing a provider removes its secret.
run console sso remove strict > /dev/null
[ ! -e school/console/sso-strict.secret ] || fail "the secret is removed"
expect_exit 2 console sso show strict
run console sso add --help | contains -- '--allow-domain DOMAIN'
run completion bash | contains 'sso'
"$CEXCHAIN" console stop > /dev/null 2>&1 || true
echo "sso: all checks passed"
