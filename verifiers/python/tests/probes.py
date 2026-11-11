# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Probes of the specification's edges: small ledgers forged here, each
with one unusual statement or bundle, verified by both verifiers.

A probe either has an expected verdict, which the specification decides
(both verifiers must reach it), or is open: the specification does not say,
and the probe records what each verifier does. Open probes that the two
verifiers decide differently are questions for the specification.

Usage: python3 probes.py KANHE [--list]
Exit status 1 if a decided probe fails in either verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from kanhe_verify import cbor, crypto, merkle, statetree  # noqa: E402
from vector_bundles import inclusion_path, smt_proof  # noqa: E402

T0 = 1_800_000_000_000  # 2027-01-15
MINUTE = 60_000
DAY = 86_400_000
STATEMENT_TYPE = "application/kanhe-statement+cbor"
CHECKPOINT_TYPE = "application/kanhe-checkpoint+cbor"
STATE_TYPE = "application/kanhe-state+cbor"


def _key(name: str):
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"Kanhe probe key: {name}".encode()).digest())


class Forge:
    """A ledger written by hand: statements signed with throwaway Ed25519
    keys, log entries at chosen times, the state kept by hand (so that a
    statement the rules refuse can still be committed to), checkpoints,
    receipts, and bundles holding every entry and every state proof."""

    def __init__(self, hash_alg: int = crypto.SHA256, root: str = "root", log: str = "log",
                 genesis_log: str | None = None, name: str = "Probe Org", t0: int = T0):
        self.hash_alg = hash_alg
        self.h = crypto.hash_function(hash_alg)
        self.entries: list[bytes] = []
        self.leaves: dict[bytes, list] = {}
        self.log = log
        self.nonce = 0
        self.time = t0
        body = {1: hash_alg, 2: name, 3: self.pub(root), 4: self.pub(genesis_log or log)}
        self.ledger_id = None
        self.ledger_id = self.add(1, root, None, body, creates=1)

    def pub(self, name: str) -> list:
        return [crypto.ED25519, _key(name).public_key().public_bytes_raw()]

    def kid(self, name: str) -> bytes:
        return self.h(cbor.encode(self.pub(name)))

    def sign(self, name: str, content_type: str, payload: bytes) -> tuple[bytes, bytes]:
        protected = cbor.encode({1: crypto.ED25519, 3: content_type, 4: self.kid(name)})
        tbs = cbor.encode(["Signature1", protected, b"", payload])
        signature = _key(name).sign(tbs)
        return cbor.encode(cbor.Tag(18, [protected, {}, payload, signature])), self.h(tbs)

    def payload(self, kind: int, actor, body, delegation=None, issued_at=None, provenance=None) -> dict:
        self.nonce += 1
        p = {0: 1, 1: kind, 5: self.time - 10 if issued_at is None else issued_at,
             6: self.nonce.to_bytes(16, "big"), 7: body}
        if self.ledger_id is not None:
            p[2] = self.ledger_id
            p[3] = actor
        if delegation is not None:
            p[4] = delegation
        if provenance is not None:
            p[9] = provenance
        return p

    def add(self, kind: int, signer: str, actor, body, delegation=None, creates: int | None = None,
            touches=(), issued_at=None, provenance=None, presence=None, registered_at=None) -> bytes:
        p = self.payload(kind, actor, body, delegation, issued_at, provenance)
        if presence is not None:
            p[8] = presence(self, signer, p)
        signed, sid = self.sign(signer, STATEMENT_TYPE, cbor.encode(p))
        at = self.time if registered_at is None else registered_at
        index = len(self.entries)
        self.entries.append(cbor.encode({1: sid, 2: at, 3: signed}))
        self.time += MINUTE
        if creates is not None:
            self.leaves[sid] = [creates, sid, [index]]
        for target in touches:
            self.leaves[target][2].append(index)
        return sid

    def actor(self, kind: int, name: str, key: str, signer: str = "root", actor=None, delegation=None,
              extra: dict | None = None) -> bytes:
        body = {1: kind, 2: name, 3: self.pub(key)}
        body.update(extra or {})
        return self.add(2, signer, actor or self.ledger_id, body, delegation, creates=1)

    def grant(self, grantee: bytes, scope: dict, signer: str = "root", actor=None, delegation=None) -> bytes:
        return self.add(5, signer, actor or self.ledger_id, {1: grantee, 2: scope}, delegation, creates=2)

    def record(self, signer: str, actor, delegation=None, kind: str = "example.org.probe/1", fields=None,
               extra: dict | None = None) -> bytes:
        leaves = [cbor.encode([name, bytes([0x5A]) * 16, value])
                  for name, value in sorted((fields if fields is not None else {"note": "probe"}).items(),
                                            key=lambda f: f[0].encode())]
        body = {1: kind, 2: merkle.tree_hash(self.h, leaves), 3: len(leaves)}
        body.update(extra or {})
        return self.add(16, signer, actor, body, delegation, creates=3)

    def commit(self, time=None, payload_time=None):
        index = len(self.entries)
        leaves = sorted(self.leaves.values(), key=lambda leaf: leaf[1])
        at = self.time if time is None else time
        payload = cbor.encode({1: self.ledger_id, 2: self.hash_alg, 3: index,
                               4: statetree.root_of(self.h, leaves),
                               5: at if payload_time is None else payload_time})
        signed, cid = self.sign(self.log, STATE_TYPE, payload)
        self.entries.append(cbor.encode({1: cid, 2: at, 4: signed}))
        self.time += MINUTE

    def bundle(self, subject: bytes, checkpoint_time=None, mutate=None) -> bytes:
        if not self.entries or 4 not in cbor.decode(self.entries[-1]):
            self.commit()
        n = len(self.entries)
        root = merkle.tree_hash(self.h, self.entries)
        payload = cbor.encode({1: self.ledger_id, 2: self.hash_alg, 3: n, 4: root,
                               5: self.time if checkpoint_time is None else checkpoint_time})
        checkpoint, _ = self.sign(self.log, CHECKPOINT_TYPE, payload)
        protected = cbor.encode({1: crypto.ED25519, 4: self.kid(self.log), 395: 1 if self.hash_alg == crypto.SHA256
                                 else -65537})
        listed = []
        for i, entry in enumerate(self.entries):
            proof = cbor.encode([n, i, inclusion_path(self.h, i, self.entries)])
            signature = _key(self.log).sign(cbor.encode(["Signature1", protected, b"", root]))
            listed.append([entry, cbor.encode(cbor.Tag(18, [protected, {396: {-1: [proof]}}, None, signature]))])
        leaves = sorted(self.leaves.values(), key=lambda leaf: leaf[1])
        bundle = {0: 1, 1: subject, 2: listed, 3: checkpoint,
                  7: [[leaf, smt_proof(self.h, leaves, leaf[1])] for leaf in leaves]}
        if mutate is not None:
            mutate(bundle)
        return cbor.encode(bundle)


def webauthn(credential: str, rp_id: str = "localhost", origin: str = "http://localhost:4000",
             flags: int = 0x05, tail: str = ',"crossOrigin":false}'):
    """A WebAuthn assertion over the statement's challenge, by the Ed25519
    credential key `credential`."""
    def make(forge: Forge, signer: str, payload: dict) -> dict:
        challenge = forge.h(b"Kanhe presence v1" + forge.kid(signer) + cbor.encode(payload))
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (1).to_bytes(4, "big")
        b64 = base64.urlsafe_b64encode(challenge).decode().rstrip("=")
        client = ('{"type":"webauthn.get","challenge":"' + b64 + '","origin":"' + origin + '"' + tail).encode()
        signature = _key(credential).sign(auth + hashlib.sha256(client).digest())
        return {1: credential.encode(), 2: auth, 3: client, 4: signature}
    return make


def passkey(forge: Forge, name: str, rp_id: str = "localhost") -> dict:
    return {1: rp_id, 2: name.encode(), 3: forge.pub(name)}


# ---------------------------------------------------------------------------
# The probes: (name, expected verdict or None if the spec is open, bundle)
# ---------------------------------------------------------------------------

def one_field(f: Forge) -> dict:
    """A record-register body with one field."""
    leaf = cbor.encode(["note", bytes([0x5A]) * 16, "probe"])
    return {1: "example.org.probe/1", 2: merkle.tree_hash(f.h, [leaf]), 3: 1}


def _person_with_delegation(forge: Forge, scope: dict | None = None, key: str = "person"):
    person = forge.actor(1, "Approver", key)
    delegation = forge.grant(person, scope or {1: [3, 7, 16, 17, 18, 19]})
    return person, delegation


def cases():
    out = []

    def case(name, expect, build):
        out.append((name, expect, build))

    # Section 5: issued at, at most 5 minutes after the registration time.
    def issued(offset):
        def build():
            f = Forge()
            record = f.add(16, "root", f.ledger_id, one_field(f),
                           creates=3, issued_at=f.time + offset)
            return f.bundle(record)
        return build
    case("issued at exactly 5 minutes after registration", True, issued(5 * MINUTE))
    case("issued at 5 minutes and 1 ms after registration", False, issued(5 * MINUTE + 1))

    # Section 17: registration times are ordered; no verifier step says so.
    def times_back():
        f = Forge()
        first = f.record("root", f.ledger_id)
        f.add(17, "root", f.ledger_id, {1: first, 2: "reviewer"}, touches=[first], registered_at=f.time - 10 * MINUTE)
        return f.bundle(first)
    case("registration times go back between two entries", None, times_back)

    def checkpoint_before_entries():
        f = Forge()
        record = f.record("root", f.ledger_id)
        return f.bundle(record, checkpoint_time=T0 - DAY)
    case("a checkpoint dated before the entries it covers", None, checkpoint_before_entries)

    def commitment_time_differs():
        f = Forge()
        record = f.record("root", f.ledger_id)
        f.commit(payload_time=T0 - DAY)
        return f.bundle(record)
    case("a state commitment whose payload time differs from its entry's", None, commitment_time_differs)

    # Section 5: delegations valid at now (scope keys 3 and 4).
    def at_not_after(delta):
        def build():
            f = Forge()
            person = f.actor(1, "Approver", "person")
            until = f.time + MINUTE + delta  # the record is registered one minute after the grant
            delegation = f.grant(person, {1: [16], 4: until})
            record = f.record("person", person, delegation)
            return f.bundle(record)
        return build
    case("a delegation used exactly at its not-after time", None, at_not_after(0))
    case("a delegation used 1 ms after its not-after time", False, at_not_after(-1))

    def scope_case(scope, expect, name):
        def build():
            f = Forge()
            person = f.actor(1, "Approver", "person")
            delegation = f.grant(person, scope)
            return f.bundle(f.record("person", person, delegation))
        case(name, expect, build)
    scope_case({1: [16], 5: False}, None, "a scope with key 5 encoded false")
    scope_case({1: [16, 16]}, None, "a scope listing a statement type twice")
    scope_case({1: [16], 2: ["example.org.probe/1", "example.org.probe/1"]}, None,
               "a scope listing a record type twice")
    scope_case({1: [16], 3: T0 + 365 * DAY, 4: T0}, False, "a scope whose not-before is after its not-after")
    scope_case({1: [8, 16]}, False, "a scope naming ledger-rotate-log-key")
    scope_case({1: [17, 16]}, None, "a scope listing statement types out of order")

    def narrowing(child):
        def build():
            f = Forge()
            manager = f.actor(1, "Manager", "manager")
            top = f.grant(manager, {1: [5, 16], 3: T0, 4: T0 + 365 * DAY, 5: True})
            assistant = f.actor(1, "Assistant", "assistant")
            mid = f.grant(assistant, child, signer="manager", actor=manager, delegation=top)
            return f.bundle(f.record("assistant", assistant, mid))
        return build
    case("a delegated scope without the grantor's not-before", None, narrowing({1: [16], 4: T0 + DAY}))
    case("a delegated scope inside the grantor's window", True, narrowing({1: [16], 3: T0, 4: T0 + DAY}))

    # Section 5, actors.
    def genesis_same_keys():
        f = Forge(root="root", log="root")
        return f.bundle(f.record("root", f.ledger_id))
    case("a genesis whose root key is also its log key", None, genesis_same_keys)

    def reused_key():
        f = Forge()
        first = f.actor(3, "Old device", "shared")
        f.add(3, "shared", first, {1: first, 2: f.pub("fresh")}, touches=[first])
        second = f.actor(3, "New device", "shared")
        delegation = f.grant(second, {1: [16]})
        return f.bundle(f.record("shared", second, delegation))
    case("a key another actor rotated away from, registered again", None, reused_key)

    def device_with_responsible():
        f = Forge()
        person = f.actor(1, "Approver", "person")
        device = f.actor(3, "Scale", "scale", extra={4: person})
        delegation = f.grant(device, {1: [16]})
        return f.bundle(f.record("scale", device, delegation))
    case("a device registered with a responsible person (key 4)", None, device_with_responsible)

    def self_rotation_with_delegation():
        f = Forge()
        device = f.actor(3, "Scale", "scale")
        delegation = f.grant(device, {1: [16]})
        f.add(3, "scale", device, {1: device, 2: f.pub("scale2")}, delegation, touches=[device])
        return f.bundle(f.record("scale2", device, delegation))
    case("a self-rotation that names a delegation not covering it", None, self_rotation_with_delegation)

    def responsible_not_person():
        f = Forge()
        device = f.actor(3, "Scale", "scale")
        agent = f.actor(2, "Bot", "bot", extra={4: device, 5: {1: "m"}})
        delegation = f.grant(agent, {1: [16]})
        return f.bundle(f.add(16, "bot", agent, one_field(f), delegation,
                              creates=3, provenance={1: "m"}))
    case("an agent whose responsible actor is a device", False, responsible_not_person)

    def agent_without_model():
        f = Forge()
        person = f.actor(1, "Approver", "person")
        agent = f.actor(2, "Bot", "bot", extra={4: person, 5: {1: "m"}})
        delegation = f.grant(agent, {1: [16]})
        return f.bundle(f.add(16, "bot", agent, one_field(f), delegation,
                              creates=3, provenance={2: "v1"}))
    case("an agent's statement whose provenance names no model", False, agent_without_model)

    def person_with_provenance():
        f = Forge()
        person, delegation = _person_with_delegation(f)
        return f.bundle(f.add(16, "person", person, one_field(f), delegation,
                              creates=3, provenance={1: "a model a person used"}))
    case("a person's statement with AI provenance", True, person_with_provenance)

    # Section 7: presence.
    def presence_case(make_proof, self_rotate=False):
        def build():
            f = Forge()
            person, delegation = _person_with_delegation(f)
            f.add(7, "root", f.ledger_id, {1: person, 2: [passkey(f, "pk")]}, touches=[person])
            if self_rotate:
                f.add(3, "person", person, {1: person, 2: f.pub("person2")}, touches=[person], presence=make_proof)
                return f.bundle(f.record("person2", person, delegation))
            record = f.add(16, "person", person, one_field(f), delegation,
                           creates=3, presence=make_proof)
            return f.bundle(record)
        return build
    case("a passkey assertion as browsers make it", True, presence_case(webauthn("pk")))
    case("a passkey assertion without crossOrigin", True, presence_case(webauthn("pk", tail="}")))
    case("a passkey assertion with members after crossOrigin", None,
         presence_case(webauthn("pk", tail=',"crossOrigin":false,"other_keys_can_be_added_here":"x"}')))
    case("a passkey assertion from a subdomain of localhost", None,
         presence_case(webauthn("pk", origin="http://app.localhost:4000")))
    case("a passkey assertion from an origin with a path", False,
         presence_case(webauthn("pk", origin="http://localhost:4000/page")))
    case("a passkey assertion with crossOrigin true", False,
         presence_case(webauthn("pk", tail=',"crossOrigin":true}')))
    case("a passkey assertion without the user-present flag", False, presence_case(webauthn("pk", flags=0x04)))
    case("a self-rotation proven by a passkey without user verification", False,
         presence_case(webauthn("pk", flags=0x01), self_rotate=True))
    case("a self-rotation proven by a user-verified passkey", True,
         presence_case(webauthn("pk", flags=0x05), self_rotate=True))

    def device_presence():
        f = Forge()
        device = f.actor(3, "Scale", "scale")
        delegation = f.grant(device, {1: [16]})
        return f.bundle(f.add(16, "scale", device, one_field(f), delegation,
                              creates=3, presence=webauthn("pk")))
    case("a device's statement carrying a proof of presence", False, device_presence)

    def credential_is_past_log_key():
        f = Forge()
        person, delegation = _person_with_delegation(f)
        f.add(8, "root", f.ledger_id, {1: f.pub("log2")}, touches=[f.ledger_id])
        f.log = "log2"
        f.add(7, "root", f.ledger_id, {1: person, 2: [{2: b"old log", 3: f.pub("log"), 5: 2}]}, touches=[person])
        return f.bundle(f.record("person", person, delegation))
    case("a presence credential whose key was the log key before a rotation", None, credential_is_past_log_key)

    def log_key_is_presence_key():
        f = Forge()
        person, delegation = _person_with_delegation(f)
        f.add(7, "root", f.ledger_id, {1: person, 2: [{2: b"ukey", 3: f.pub("ukey"), 5: 2}]}, touches=[person])
        f.add(8, "root", f.ledger_id, {1: f.pub("ukey")}, touches=[f.ledger_id])
        f.log = "ukey"
        return f.bundle(f.record("person", person, delegation))
    case("a new log key that is a person's presence key", None, log_key_is_presence_key)

    # Section 6: records.
    def record_case(expect, name, kind="example.org.probe/1", fields=None, extra=None):
        def build():
            f = Forge()
            return f.bundle(f.record("root", f.ledger_id, kind=kind, fields=fields, extra=extra))
        case(name, expect, build)
    record_case(True, "a type that starts with Kanhe. in another case", kind="Kanhe.note/1")
    record_case(False, "an invented kanhe. type", kind="kanhe.note/1")
    record_case(None, "a record with no fields (count 0, the empty tree's root)", fields={})
    two = [["a.txt", "text/plain", 1, bytes(32)], ["a.txt", "text/plain", 2, bytes(32)]]
    record_case(None, "two attachments with one name", extra={4: two})
    record_case(None, "a field root of 31 bytes", extra={2: bytes(31)})
    record_case(False, "metadata with an integer key", extra={5: {1: "x"}})

    def empty_role():
        f = Forge()
        record = f.record("root", f.ledger_id)
        f.add(17, "root", f.ledger_id, {1: record, 2: ""}, touches=[record])
        return f.bundle(record)
    case("an endorsement in the empty role", None, empty_role)

    def lifecycle(kind, statement, expect, name):
        def build():
            f = Forge()
            record = f.record("root", f.ledger_id, kind=kind)
            f.add(statement[0], "root", f.ledger_id, {1: record, **statement[1]}, touches=[record])
            return f.bundle(record)
        case(name, expect, build)
    lifecycle("example.org.probe/1", (18, {2: "registered", 3: "done"}), False, "a transition on a user's type")
    lifecycle("kanhe.contract-consent/1", (17, {2: "witness"}), False, "an endorsement of a mechanism type")
    lifecycle("kanhe.contract-consent/1", (18, {2: "given", 3: "withdrawn"}), True, "a consent withdrawn")

    def chain(length):
        def build():
            f = Forge()
            grantor, grantor_key, parent = f.ledger_id, "root", None
            for i in range(length):
                actor = f.actor(1, f"Link {i}", f"link{i}")
                parent = f.grant(actor, {1: [5, 16], 5: True}, signer=grantor_key, actor=grantor, delegation=parent)
                grantor, grantor_key = actor, f"link{i}"
            return f.bundle(f.record(grantor_key, grantor, parent))
        return build
    case("a chain of 16 delegations", True, chain(16))
    case("a chain of 17 delegations", False, chain(17))

    def hardware_key():
        f = Forge()
        person, delegation = _person_with_delegation(f, {1: [16], 6: True})
        f.add(7, "root", f.ledger_id, {1: person, 2: [{2: b"ukey", 3: f.pub("ukey"), 5: 2}]}, touches=[person])

        def proof(forge, signer, payload):
            challenge = forge.h(b"Kanhe presence v1" + forge.kid(signer) + cbor.encode(payload))
            return {1: b"ukey", 4: _key("ukey").sign(challenge)}
        return f.bundle(f.add(16, "person", person, one_field(f), delegation,
                              creates=3, presence=proof))
    case("a hardware key's proof under a delegation that requires presence", True, hardware_key)

    def presence_required_missing():
        f = Forge()
        person, delegation = _person_with_delegation(f, {1: [16], 6: True})
        return f.bundle(f.record("person", person, delegation))
    case("no proof under a delegation that requires presence", False, presence_required_missing)

    def org_with_delegation():
        f = Forge()
        person, delegation = _person_with_delegation(f)
        return f.bundle(f.record("root", f.ledger_id, delegation))
    case("the organization naming a delegation", False, org_with_delegation)

    def no_proofs():
        f = Forge()
        record = f.record("root", f.ledger_id)

        def drop(bundle):
            del bundle[7]
        return f.bundle(record, mutate=drop)
    case("the state commitment included, no state proofs", False, no_proofs)

    def disclosures_out_of_order():
        f = Forge()
        fields = {"a": 1, "b": 2, "c": 3}
        record = f.record("root", f.ledger_id, fields=fields)
        leaves = [cbor.encode([n, bytes([0x5A]) * 16, v]) for n, v in sorted(fields.items())]

        def add(bundle):
            bundle[5] = [[leaves[i], i, inclusion_path(f.h, i, leaves)] for i in (2, 0)]
        return f.bundle(record, mutate=add)
    case("disclosures listed out of index order", None, disclosures_out_of_order)

    def unknown_entry_key():
        f = Forge()
        record = f.record("root", f.ledger_id)
        entry = cbor.decode(f.entries[-1])
        entry[5] = 1
        f.entries[-1] = cbor.encode(entry)
        return f.bundle(record)
    case("a log entry with an unknown key", False, unknown_entry_key)

    def superseded_unknown():
        f = Forge()
        return f.bundle(f.record("root", f.ledger_id, extra={6: f.h(b"no such record")}))
    case("a new version of a record the bundle does not hold (and the ledger never had)", None,
         superseded_unknown)

    def sm3_rotation_receipt_kid():
        f = Forge(hash_alg=crypto.SM3)
        return f.bundle(f.record("root", f.ledger_id))
    case("an SM3 ledger forged here", True, sm3_rotation_receipt_kid)

    # Statements about objects that are revoked already.
    def after_revocation(build_last, name, expect=None):
        def build():
            f = Forge()
            person, delegation = _person_with_delegation(f)
            record = f.record("person", person, delegation)
            build_last(f, person, delegation)
            return f.bundle(record)
        case(name, expect, build)
    after_revocation(lambda f, p, d: (f.add(4, "root", f.ledger_id, {1: p}, touches=[p]),
                                      f.add(4, "root", f.ledger_id, {1: p}, touches=[p])),
                     "an actor revoked twice")
    after_revocation(lambda f, p, d: (f.add(6, "root", f.ledger_id, {1: d}, touches=[d]),
                                      f.add(6, "root", f.ledger_id, {1: d}, touches=[d])),
                     "a delegation revoked twice")
    after_revocation(lambda f, p, d: (f.add(4, "root", f.ledger_id, {1: p}, touches=[p]),
                                      f.add(7, "root", f.ledger_id, {1: p, 2: [passkey(f, "pk")]}, touches=[p])),
                     "presence credentials set for a revoked person")
    after_revocation(lambda f, p, d: (f.add(4, "root", f.ledger_id, {1: p}, touches=[p]),
                                      f.add(3, "root", f.ledger_id, {1: p, 2: f.pub("new")}, touches=[p])),
                     "a revoked actor's key rotated")
    after_revocation(lambda f, p, d: (f.add(4, "root", f.ledger_id, {1: p}, touches=[p]),
                                      f.add(5, "root", f.ledger_id, {1: p, 2: {1: [16]}}, creates=2)),
                     "a delegation granted to a revoked actor")

    def own_credentials(flags):
        def build():
            f = Forge()
            person, delegation = _person_with_delegation(f)
            f.add(7, "root", f.ledger_id, {1: person, 2: [passkey(f, "pk")]}, touches=[person])
            f.add(7, "person", person, {1: person, 2: [passkey(f, "pk2")]}, touches=[person],
                  presence=webauthn("pk", flags=flags))
            return f.bundle(f.record("person", person, delegation))
        return build
    case("a person replaces their own passkeys, user-verified", True, own_credentials(0x05))
    case("a person replaces their own passkeys, not user-verified", False, own_credentials(0x01))
    case("a passkey assertion from https://localhost", True,
         presence_case(webauthn("pk", origin="https://localhost")))
    case("a passkey assertion from an upper-case origin", None,
         presence_case(webauthn("pk", origin="http://LOCALHOST:4000")))
    case("a passkey assertion from another relying party's origin", False,
         presence_case(webauthn("pk", origin="https://example.org")))

    def empty_tools():
        f = Forge()
        person, delegation = _person_with_delegation(f)
        return f.bundle(f.add(16, "person", person, one_field(f), delegation, creates=3,
                              provenance={1: "m", 4: []}))
    case("a provenance with an empty list of tools", False, empty_tools)

    def clear_credentials():
        f = Forge()
        person, delegation = _person_with_delegation(f)
        f.add(7, "root", f.ledger_id, {1: person, 2: [passkey(f, "pk")]}, touches=[person])
        f.add(7, "root", f.ledger_id, {1: person, 2: []}, touches=[person])
        return f.bundle(f.record("person", person, delegation))
    case("a person's credentials cleared (an empty list)", True, clear_credentials)

    # Section 6: claims (v0.14). The open ones are where the text leaves the
    # outcome to the reader.
    def claim_probe(condition, extra=None, signer="root", scope=None, source=None):
        def build():
            f = Forge()
            target = f.record("root", f.ledger_id, fields={"note": "probe", "x": 1})
            actor, delegation = f.ledger_id, None
            if scope is not None:
                actor, delegation = _person_with_delegation(f, scope)
            meta = {"source": target if source is None else source, "condition": condition, "holds": True,
                    "as_of": f.time - 1000}
            meta.update(extra(f) if extra is not None else {})
            return f.bundle(f.record(signer, actor, delegation, kind="kanhe.claim/1", extra={5: meta}))
        return build
    x_above_0 = [["x", ">", "number", 0]]
    case("a claim on a live record", True, claim_probe(x_above_0))
    case("a claim on a record the ledger never had", False,
         claim_probe(x_above_0, source=hashlib.sha256(b"no such record").digest()))
    case("a claim whose metadata has a key the CDDL does not list", False,
         claim_probe(x_above_0, extra=lambda f: {"note": "hello"}))
    case("a claim by a delegate whose scope lists claims, not the source's type", None,
         claim_probe(x_above_0, signer="person", scope={1: [16], 2: ["kanhe.claim/1"]}))
    case("a claim whose until is after its as_of and before its registration", None,
         claim_probe(x_above_0, extra=lambda f: {"until": f.time - 500}))
    case("a claim: between two texts", None, claim_probe([["x", "between", "text", ["a", "b"]]]))
    case("a claim: in with 1 and \"1.0\", one number encoded two ways", None,
         claim_probe([["x", "in", "number", [1, "1.0"]]]))
    case("a claim: between amounts of two currencies", None,
         claim_probe([["x", "between", "money", [[100, "HKD", 2], [200, "USD", 2]]]]))
    case("a claim: the date 0000-01-01", None, claim_probe([["x", "=", "date", "0000-01-01"]]))
    return out


def _run(args, cwd=None):
    done = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    try:
        report = json.loads(done.stdout)
    except ValueError:
        report = {"error": (done.stderr or done.stdout).strip()[:200]}
    return done.returncode, report


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    kanhe = argv[1]
    failures, open_differ = 0, 0
    env = dict(os.environ, PYTHONPATH=str(HERE.parent))
    with tempfile.TemporaryDirectory() as tmp:
        for name, expect, build in cases():
            path = os.path.join(tmp, "probe.cbor")
            with open(path, "wb") as f:
                f.write(build())
            py = subprocess.run([sys.executable, "-m", "kanhe_verify", path, "--json"], capture_output=True,
                                text=True, env=env)
            try:
                py_report = json.loads(py.stdout)
            except ValueError:
                py_report = {"error": py.stderr.strip()[-200:]}
            bb_code, bb_report = _run([kanhe, "verify", path, "--json"])
            py_ok, bb_ok = py.returncode == 0, bb_code == 0

            def verdict(ok, report):
                return "verified" if ok else f"refused ({report.get('error', '?')})"
            if expect is None:
                tag = "open, both agree" if py_ok == bb_ok else "OPEN, THEY DIFFER"
                open_differ += py_ok != bb_ok
            elif py_ok == expect and bb_ok == expect:
                tag = "as the spec says"
            else:
                tag = "WRONG"
                failures += 1
            print(f"  {tag}: {name}\n      python: {verdict(py_ok, py_report)}\n"
                  f"      kanhe verify: {verdict(bb_ok, bb_report)}")
    print(f"probes: {failures} decided probe(s) failed; {open_differ} open probe(s) on which the verifiers differ")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
