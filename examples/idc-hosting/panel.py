# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A fake control panel, for the hosting example: the webhook an executor's
# connector posts the contract's requests to (spec/connectors.md, 7.1). It
# checks each request's signature, acts once per request id (a retry gets
# the first answer again), and keeps its servers and addresses in a JSON
# file. It answers subscribe with the new server's name (the contract keeps
# it); the address stays here. A real panel would do the same through its
# own API.
#
# Usage: python3 panel.py DIR SECRET_FILE
#   writes DIR/panel.port once it listens, DIR/panel.json (its state), and
#   one line per action to DIR/panel.log.
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

work, secret = sys.argv[1], open(sys.argv[2], "rb").read().strip()
state_file = os.path.join(work, "panel.json")
lock = threading.Lock()
# Addresses from a documentation range (RFC 5737).
POOL = ["203.0.113.%d" % n for n in range(10, 14)]


def load():
    if os.path.exists(state_file):
        with open(state_file) as f:
            return json.load(f)
    return {"answers": {}, "servers": {}, "free": POOL, "cooling": []}


def save(state):
    with open(state_file + ".tmp", "w") as f:
        json.dump(state, f, indent=1)
    os.replace(state_file + ".tmp", state_file)


def note(line):
    with open(os.path.join(work, "panel.log"), "a") as f:
        f.write(line + "\n")


def act(state, request):
    kind, params = request["kind"], request.get("params") or {}
    servers = state["servers"]
    # The panel knows each server by the contract instance that ordered it.
    mine = [n for n, s in servers.items() if s["instance"] == request["instance"]]
    if kind == "subscribe":
        if mine:
            return 200, {"result": mine[0]}
        if not state["free"]:
            return 200, {"status": "failed", "reason": "no-address"}
        name = "srv-%04d" % (len(servers) + 1)
        address = state["free"].pop(0)
        servers[name] = {"instance": request["instance"], "address": address, "status": "running"}
        note("provisioned %s at %s" % (name, address))
        return 200, {"result": name}
    if kind == "reclaim":
        name = params.get("machine", "")
        server = servers.get(name)
        if server is None or server["address"] is None:
            return 200, {"status": "failed", "reason": "no-such-server"}
        state["cooling"].append(server["address"])
        note("reclaimed %s from %s: cooling before reuse" % (server["address"], name))
        server["address"] = None
        return 200, {"result": "released"}
    if kind in ("suspend", "resume", "terminate"):
        if not mine:
            return 200, {"status": "failed", "reason": "no-such-server"}
        server = servers[mine[0]]
        server["status"] = {"suspend": "suspended", "resume": "running", "terminate": "deleted"}[kind]
        note("%s %s" % (server["status"], mine[0]))
        return 200, {"result": mine[0] + " " + server["status"]}
    return 400, {"reason": "unknown-kind"}


class Panel(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        stamp = self.headers.get("X-CexChain-Timestamp", "0")
        expected = "sha256=" + hmac.new(secret, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        fresh = stamp.isdigit() and abs(int(stamp) - time.time() * 1000) < 300000
        if not (fresh and hmac.compare_digest(self.headers.get("X-CexChain-Signature", ""), expected)):
            return self.answer(401, {"reason": "bad-signature"})
        request = json.loads(body)
        with lock:
            state = load()
            done = state["answers"].get(request["id"])
            if done is None:
                done = act(state, request)
                state["answers"][request["id"]] = done
                save(state)
        self.answer(*done)

    def answer(self, status, reply):
        data = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        # Quiet: the script narrates, and each request is in the log file.
        del format, args


server = ThreadingHTTPServer(("127.0.0.1", 0), Panel)
with open(os.path.join(work, "panel.port.tmp"), "w") as f:
    f.write(str(server.server_address[1]))
os.replace(os.path.join(work, "panel.port.tmp"), os.path.join(work, "panel.port"))
server.serve_forever()
