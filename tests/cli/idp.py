# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A small identity provider for tests: OpenID Connect (discovery, a JWKS of
# one RSA key, an authorization endpoint that signs the user in at once, a
# token endpoint that checks the client's secret and PKCE and answers an ID
# token signed with RS256 through openssl) and CAS 3.0 (/cas/login,
# /cas/p3/serviceValidate as JSON). The account is always student-42
# (li@school.example) over OpenID Connect and chan over CAS.
# Usage: idp.py PORT_FILE KEY.pem   (writes its port to PORT_FILE once listening)
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
