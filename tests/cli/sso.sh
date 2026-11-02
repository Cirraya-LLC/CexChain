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
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
cp "$SOURCE/tests/cli/idp.py" idp.py
python3 idp.py idp.port idp.pem 2> idp.log &
PIDS+=("$!")
wait_for idp.port
IDP="http://127.0.0.1:$(cat idp.port)"

# --- A ledger, and its console's keys -------------------------------------------------
for k in root log; do run key generate --out "$k.key" > /dev/null; done
run init --name "Example School" --root-key root.key --log-key log.key > /dev/null
printf 'the unlock passphrase of these tests\n' > unlock.txt
run console key init --unlock-file unlock.txt > /dev/null
run console key import root root.key > /dev/null
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

# --- A self-service form (with the Bo compiler) ---------------------------------------
BO="$(run version --json | json 'd["bo"] is not None')"
if [ "$BO" = True ]; then
    C="$(run contract deploy --bo "$SOURCE/examples/day-student/day-student.bo" --as root.key --json \
        2> /dev/null | json 'd["contract"]["id"]')"
    cat > kind.json << 'JSON'
{"sheet": 1, "kind": "document", "type": "example.school.day-student-form/1", "name": "Day student form",
 "fields": [{"name": "student", "label": "Student", "type": "text", "private": false, "required": true},
            {"name": "address", "label": "Address", "type": "text", "private": true, "required": true}],
 "files": "none", "keep_files": false}
JSON
    run console kind add kind.json > /dev/null
    cat > form.json << JSON
{"form": 1, "name": "day-student", "title": "Day student application", "contract": "$C",
 "create": "create", "steps": ["withdraw"], "kind": "example.school.day-student-form/1",
 "record_field": "details", "providers": ["school"]}
JSON
    expect_exit 2 console intake grant --unlock-file unlock.txt
    contains 'publish a form first' out.txt
    run console form add form.json | contains 'console intake grant'
    expect_exit 2 console form add form.json
    sed "s/\"create\": \"create\"/\"create\": \"withdraw\"/" form.json > wrong.json
    expect_exit 2 console form add wrong.json --replace
    contains 'does not create things' out.txt
    run console form list | contains 'day-student'
    run console form link day-student --url http://localhost:7470 | contains -x 'http://localhost:7470/console/#/apply/day-student'
    expect_exit 1 console intake grant
    GRANT="$(run console intake grant --unlock-file unlock.txt --json)"
    [ "$(echo "$GRANT" | json 'd["new_key"], d["revoked"]')" = "True 0" ] || fail "the first intake grant"
    [ "$(run console intake grant --unlock-file unlock.txt --json | json 'd["revoked"]')" = 1 ] ||
        fail "a new grant revokes the old"
    INTAKE="$(run console intake show --json | json 'd["actor"]')"
    run delegation list --actor "$INTAKE" --json | json 'len(d)' | contains -x 1
fi

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
staff = len(sys.argv) > 3 and sys.argv[3] == "staff"
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
status, _, body = call("POST", "/console/api/sso/begin",
                      {"provider": provider, "staff": True} if staff else {"provider": provider, "form": "day-student"})
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
signin() { python3 flow.py "$FREE" "$1" "${2:-}"; }
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

# --- An applicant uses the form ----------------------------------------------------------
if [ "$BO" = True ]; then
    FORM="$(get /console/api/apply/day-student | sed -n '2,$p')"
    [ "$(echo "$FORM" | json '[p["name"] for p in d["providers"]], [f["name"] for f in d["fields"]]')" = \
        "['school'] ['student', 'address']" ] || fail "the form: $FORM"
    [ "$(echo "$FORM" | json '[i["name"] for i in d["inputs"]]')" = "['guardian_agrees', 'note']" ] ||
        fail "the creating call's own inputs: $(echo "$FORM" | json "d[\"inputs\"]")"
    LI="$(finish "$(signin school | json 'd["fragment"]' | sed 's|.*/||')" | json 'd["body"]["token"]')"
    post() {
        python3 - "$FREE" "$1" "$2" "$3" << 'PY'
import http.client, json, sys
port, path, token, body = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
c.request("POST", path, body=body, headers={"Host": f"localhost:{port}", "Origin": f"http://localhost:{port}",
          "Content-Type": "application/json", "Authorization": "Bearer " + token})
r = c.getresponse()
print(r.status)
print(r.read().decode())
PY
    }
    SUBMITTED="$(post /console/api/apply/day-student "$LI" \
        '{"fields": {"student": "Li Ming", "address": "12 Hill Road"}, "values": {"guardian_agrees": true}}')"
    [ "$(echo "$SUBMITTED" | sed -n 1p)" = 201 ] || fail "submitted: $SUBMITTED"
    THING="$(echo "$SUBMITTED" | sed -n 2p | json 'd["thing"]')"
    DOCUMENT="$(echo "$SUBMITTED" | sed -n 2p | json 'd["document"]')"
    MINE="$(get /console/api/mine "$LI" | sed -n 2p)"
    [ "$(echo "$MINE" | json '[(i["id"], i["state"], i["steps"]) for i in d["items"]]')" = \
        "[('$THING', 'submitted', ['withdraw'])]" ] || fail "my items: $MINE"
    # Not a step of theirs; a step of theirs.
    [ "$(post "/console/api/mine/$THING" "$LI" '{"function": "counsellor_approves"}' | sed -n 1p)" = 403 ] ||
        fail "a staff step"
    [ "$(post "/console/api/mine/$THING" "$LI" '{"function": "withdraw"}' | sed -n 1p | cut -c1)" = 2 ] ||
        fail "withdraw"
    [ "$(get /console/api/mine "$LI" | sed -n 2p | json 'd["items"][0]["state"], len(d["items"][0]["history"])')" = \
        "withdrawn 2" ] || fail "withdrawn"
    # Another applicant sees none of it, and cannot act on it.
    CHAN="$(finish "$(signin campus | json 'd["fragment"]' | sed 's|.*/||')" | json 'd["body"]["token"]')"
    [ "$(get /console/api/mine "$CHAN" | sed -n 2p | json 'len(d["items"])')" = 0 ] || fail "another's items"
    [ "$(post "/console/api/mine/$THING" "$CHAN" '{"function": "withdraw"}' | sed -n 1p)" = 404 ] ||
        fail "another's thing"
    [ "$(post /console/api/apply/day-student "$CHAN" '{"fields": {}}' | sed -n 1p)" = 403 ] ||
        fail "this form takes the school's accounts only"
    # On the ledger: a device acted, the applicant only a pseudonym, the address sealed.
    run contract instance "$THING" --json | json 'd["status"]' | contains -x withdrawn
    run search instances --reference "$PSEUDONYM" --json | json '[i["id"] for i in d["instances"]]' |
        contains -xF "['$THING']"
    run record show "$DOCUMENT" --json | json 'd["metadata"]["applicant"], d["metadata"]["student"]' |
        contains -xF "$PSEUDONYM Li Ming"
    ! grep -rq "Hill Road" school/statements* || fail "the address is sealed"
    run record history "$DOCUMENT" | contains 'Intake \[device\]'
fi

# --- Staff sign in with a linked account, too ------------------------------------------
python3 - << 'PY'
import os
def text(value):
    data = value.encode()
    return bytes([0x60 + len(data)]) + data
credential = bytes([0xa3, 0x01]) + text("localhost") + bytes([0x02, 0x50]) + os.urandom(16)
credential += bytes([0x03, 0x82, 0x32, 0x58, 0x20]) + os.urandom(32)
open("owner.passkey", "wb").write(credential)
PY
STAFF="$WORK/office"
run console setup --ledger "$STAFF" --name "Office Owner" --credential owner.passkey \
    --unlock-file unlock.txt > /dev/null
run console sso add school --ledger "$STAFF" --oidc "$IDP" --client-id console \
    --client-secret-file secret.txt > /dev/null
run console sso add campus --ledger "$STAFF" --cas "$IDP/cas" > /dev/null
expect_exit 2 console user account Nobody --ledger "$STAFF" --provider school --subject x
expect_exit 1 console user account "Office Owner" --ledger "$STAFF" --provider school
run console user account "Office Owner" --ledger "$STAFF" --provider school --subject student-42 |
    contains 'approving still takes their passkey'
"$CEXCHAIN" console stop > /dev/null 2>&1 || true
OFFICE="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
"$CEXCHAIN" console run --ledger "$STAFF" --port "$OFFICE" --unlock-file unlock.txt --quiet > office.log 2>&1 &
PIDS+=("$!")
for _ in $(seq 1 300); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:$OFFICE/console/')" 2> /dev/null && break
    sleep 0.1
done
FREE="$OFFICE"
SIGNED="$(finish "$(signin school staff | json 'd["fragment"]' | sed 's|.*/||')")"
SESSION="$(echo "$SIGNED" | json 'd["body"]["session"]')"
echo "$SESSION" | contains -E '^cxs_'
[ "$(get /console/api/session "$SESSION" | sed -n 2p | json 'd["user"]')" = "Office Owner" ] ||
    fail "a staff session"
# An account no one linked: no session.
signin campus staff | json 'd["fragment"]' | contains 'sign-in-failed/no-staff-account'
run console user account "Office Owner" --ledger "$STAFF" --provider school --remove > /dev/null
signin school staff | json 'd["fragment"]' | contains 'sign-in-failed/no-staff-account'

# Removing a provider removes its secret.
run console sso remove strict > /dev/null
[ ! -e school/console/sso-strict.secret ] || fail "the secret is removed"
expect_exit 2 console sso show strict
run console sso add --help | contains -- '--allow-domain DOMAIN'
run completion bash | contains 'sso'
"$CEXCHAIN" console stop > /dev/null 2>&1 || true
echo "sso: all checks passed"
