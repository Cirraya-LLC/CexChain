# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""A witness of an open network, written from c2sp.org's tlog-witness,
tlog-cosignature, tlog-checkpoint, and signed-note with Python's standard
library and the openssl command line (3.5 or later), for tests: it knows
nothing of Kanhe.

It serves add-checkpoint for one log: it checks the log's note signature
with the log's verifier key, refuses an old size that is not the one it
cosigned last (409, with its size), checks the RFC 6962 consistency proof
from it, and cosigns the new note with its own key: Ed25519 (signature type
0x04, cosignature/v1) or ML-DSA-44 (type 0x06, a CosignedSubtree from 0).

Usage: python3 c2sp_witness.py WORK NAME ORIGIN LOG_VKEY [ed25519|ml-dsa-44]
It writes WORK/witness.vkey (its verifier key) and, once it listens on
127.0.0.1, WORK/port.
"""

import base64
import hashlib
import http.server
import os
import socketserver
import struct
import subprocess
import sys
import tempfile
import time

work, name, origin, log_vkey = sys.argv[1:5]
kind = sys.argv[5] if len(sys.argv) > 5 else "ed25519"
SIGNATURE_TYPE = {"ed25519": 0x04, "ml-dsa-44": 0x06}[kind]
key_pem = os.path.join(work, "witness.pem")
subprocess.run(["openssl", "genpkey", "-algorithm", {"ed25519": "ed25519", "ml-dsa-44": "ML-DSA-44"}[kind],
                "-out", key_pem], check=True)
spki = subprocess.run(["openssl", "pkey", "-in", key_pem, "-pubout", "-outform", "DER"],
                      check=True, capture_output=True).stdout
public = spki[-{"ed25519": 32, "ml-dsa-44": 1312}[kind]:]


def key_id(key_name, signature_type, key):
    return hashlib.sha256(key_name.encode() + b"\n" + bytes([signature_type]) + key).digest()[:4]


with open(os.path.join(work, "witness.vkey"), "w") as f:
    f.write(f"{name}+{key_id(name, SIGNATURE_TYPE, public).hex()}+"
            f"{base64.b64encode(bytes([SIGNATURE_TYPE]) + public).decode()}")
log_name, log_id, log_key = log_vkey.split("+", 2)
log_key = base64.b64decode(log_key)[1:]
state = {"size": 0, "root": None}


def openssl_verify(public_key, message, signature):
    """An Ed25519 signature by the log's note key."""
    with tempfile.TemporaryDirectory() as d:
        paths = [os.path.join(d, n) for n in ("k", "m", "s")]
        for path, data in zip(paths, (bytes.fromhex("302a300506032b6570032100") + public_key, message, signature)):
            with open(path, "wb") as f:
                f.write(data)
        return subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", paths[0],
                               "-rawin", "-in", paths[1], "-sigfile", paths[2]], capture_output=True).returncode == 0


def sign(message):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "m")
        with open(path, "wb") as f:
            f.write(message)
        return subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key_pem, "-rawin", "-in", path],
                              check=True, capture_output=True).stdout


def cosign(text, size, root, now):
    """tlog-cosignature: cosignature/v1 for Ed25519, a CosignedSubtree for
    ML-DSA-44 (FIPS 204, pure, empty context: openssl's defaults)."""
    if SIGNATURE_TYPE == 0x04:
        return sign(f"cosignature/v1\ntime {now}\n{text}".encode())
    subtree = (b"subtree/v1\n\0" + bytes([len(name.encode())]) + name.encode() + struct.pack(">Q", now)
               + bytes([len(origin.encode())]) + origin.encode() + struct.pack(">QQ", 0, size) + root)
    return sign(subtree)


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def consistent(old_size, new_size, old_root, new_root, proof):
    # RFC 9162, section 2.1.4.2.
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size & (old_size - 1) == 0:
        proof = [old_root] + proof
    if not proof:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node(c, fr), node(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


class Witness(http.server.BaseHTTPRequestHandler):
    def answer(self, status, body=b"", content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        head, rest = body.split("\n\n", 1)
        lines = head.split("\n")
        old = int(lines[0][4:])
        proof = [base64.b64decode(p) for p in lines[1:]]
        text, signatures = rest.split("\n\n", 1)
        text += "\n"
        note_origin, size, root = text.split("\n")[:3]
        if note_origin != origin:
            return self.answer(404)
        size, root = int(size), base64.b64decode(root)
        ok = False
        for line in signatures.strip("\n").split("\n"):
            who, raw = line[2:].split(" ")
            raw = base64.b64decode(raw)
            if who == log_name and raw[:4].hex() == log_id:
                ok = openssl_verify(log_key, text.encode(), raw[4:])
        if not ok:
            return self.answer(403)
        if old > size:
            return self.answer(400)
        if old != state["size"]:
            return self.answer(409, f"{state['size']}\n".encode(), "text/x.tlog.size")
        if old == 0 and proof:
            return self.answer(422)
        if old and state["root"] is not None and not consistent(old, size, state["root"], root, proof):
            return self.answer(422)
        state["size"], state["root"] = size, root
        now = int(time.time())
        signature = key_id(name, SIGNATURE_TYPE, public) + struct.pack(">Q", now) + cosign(text, size, root, now)
        self.answer(200, f"— {name} {base64.b64encode(signature).decode()}\n".encode())

    def log_message(self, *args):
        pass


class Server(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


server = Server(("127.0.0.1", 0), Witness)
with open(os.path.join(work, "port.tmp"), "w") as f:
    f.write(str(server.server_address[1]))
os.rename(os.path.join(work, "port.tmp"), os.path.join(work, "port"))
server.serve_forever()
