# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A fake billing system, for the hosting example: the webhook an executor's
# connector posts invoice and collect requests to (spec/connectors.md, 7.1).
# It checks each request's signature and issues one invoice per request id.
# A collection is done only once the invoice's whole amount has come in
# (the payments the bank reports, in DIR/payments.txt: "INVOICE HKD" lines,
# such as "INV-0001 800.00"); until then it asks the executor to try again
# later. Amounts come in cents and dates in milliseconds, as the contract
# keeps them. Its state is a JSON file.
#
# Usage: python3 billing.py DIR SECRET_FILE
#   writes DIR/billing.port once it listens, DIR/billing.json (its state),
#   and one line per action to DIR/billing.log.
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

work, secret = sys.argv[1], open(sys.argv[2], "rb").read().strip()
state_file = os.path.join(work, "billing.json")
lock = threading.Lock()


def load():
    if os.path.exists(state_file):
        with open(state_file) as f:
            return json.load(f)
    return {"invoices": {}, "by_request": {}, "receipts": 0}


def save(state):
    with open(state_file + ".tmp", "w") as f:
        json.dump(state, f, indent=1)
    os.replace(state_file + ".tmp", state_file)


def note(line):
    with open(os.path.join(work, "billing.log"), "a") as f:
        f.write(line + "\n")


def hkd(cents):
    return (Decimal(cents) / 100).quantize(Decimal("0.01"))


def day(ms):
    # The contract counts days in Hong Kong time (UTC+08:00).
    return datetime.fromtimestamp(ms / 1000, timezone(timedelta(hours=8))).strftime("%Y-%m-%d")


def paid(invoice):
    total = Decimal(0)
    path = os.path.join(work, "payments.txt")
    if os.path.exists(path):
        for line in open(path):
            number, _, amount = line.strip().partition(" ")
            if number == invoice:
                total += Decimal(amount)
    return total


def act(state, request):
    kind, params = request["kind"], request.get("params") or {}
    invoices = state["invoices"]
    if kind == "invoice":
        number = state["by_request"].get(request["id"])
        if number is None:
            number = "INV-%04d" % (len(invoices) + 1)
            invoices[number] = {"amount": str(hkd(params["amount"])), "from": day(params["paid_until"]),
                                "to": day(params["billed_until"]), "receipt": None}
            state["by_request"][request["id"]] = number
            note("issued %s: HKD %s for %s to %s" % (number, invoices[number]["amount"],
                                                     invoices[number]["from"], invoices[number]["to"]))
        return 200, {"result": number}
    if kind == "collect":
        invoice = invoices.get(params.get("invoice", ""))
        if invoice is None:
            return 200, {"status": "failed", "reason": "no-such-invoice"}
        if invoice["receipt"] is None:
            due, received = Decimal(invoice["amount"]), paid(params["invoice"]).quantize(Decimal("0.01"))
            if received < due:
                note("%s: HKD %s of %s in, waiting" % (params["invoice"], received, due))
                return 200, {"status": "retry", "reason": "awaiting-payment", "retry_after_ms": 1000}
            state["receipts"] += 1
            invoice["receipt"] = "RCPT-%04d" % state["receipts"]
            note("%s paid in full: receipt %s" % (params["invoice"], invoice["receipt"]))
        return 200, {"result": invoice["receipt"]}
    return 400, {"reason": "unknown-kind"}


class Billing(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        stamp = self.headers.get("X-CexChain-Timestamp", "0")
        expected = "sha256=" + hmac.new(secret, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        fresh = stamp.isdigit() and abs(int(stamp) - time.time() * 1000) < 300000
        if not (fresh and hmac.compare_digest(self.headers.get("X-CexChain-Signature", ""), expected)):
            return self.answer(401, {"reason": "bad-signature"})
        with lock:
            state = load()
            status, reply = act(state, json.loads(body))
            save(state)
        self.answer(status, reply)

    def answer(self, status, reply):
        data = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Billing)
with open(os.path.join(work, "billing.port.tmp"), "w") as f:
    f.write(str(server.server_address[1]))
os.replace(os.path.join(work, "billing.port.tmp"), os.path.join(work, "billing.port"))
server.serve_forever()
