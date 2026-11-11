#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Writes testvectors/evidence-v1.json: a conformance suite of Kanhe
evidence that every verifier must pass.

Each case is one evidence bundle (spec section 11) or one instance's
contract evidence (section 15), forged here from the specification with
throwaway keys, the options a verifier is run with, the verdict the
specification decides, and facts its report must show. Ledgers are written
by hand: statements, log entries, state commitments, checkpoints, receipts,
cosignatures, and anchors with RFC 3161 tokens from OpenSSL's responder.
Nothing here uses the C++ programs or the Python verifier; contracts are run
by the reference interpreter (wasm_ref.py) only to check that each call
gives the output it was forged with.

Usage:
    python3 tools/testvectors/evidence_suite.py [--openssl /path/to/openssl]

generate.py calls it last, so that one run regenerates every vector. ECDSA,
SM2, and ML-DSA signatures and the tokens' times differ from run to run;
the verdicts and facts do not.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import time

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import generate as g
import wasm_ref as w

OUT = g.OUT / "evidence-v1.json"

T0 = 1_792_454_400_000  # 2026-10-20T00:00:00Z
SECOND, MINUTE, HOUR, DAY = 1_000, 60_000, 3_600_000, 86_400_000
SHA256, SM3 = -16, -65538
ED25519, ESP256, SM2, MLDSA44, MLDSA65, MLDSA87 = -19, -9, -65537, -48, -49, -50
MLDSA_KEYS = {MLDSA44: mldsa.MLDSA44PrivateKey, MLDSA65: mldsa.MLDSA65PrivateKey, MLDSA87: mldsa.MLDSA87PrivateKey}
ALG_NAMES = {ED25519: "Ed25519", ESP256: "ESP256", SM2: "SM2-SM3", MLDSA44: "ML-DSA-44", MLDSA65: "ML-DSA-65",
             MLDSA87: "ML-DSA-87"}
HASH_NAMES = {SHA256: "SHA-256", SM3: "SM3"}
ORG, PERSON, AGENT, DEVICE = 0, 1, 2, 3
KIND_NAMES = {ORG: "organization", PERSON: "person", AGENT: "agent", DEVICE: "device"}
TYPE_NAMES = {16: "record-register", 17: "record-endorse", 18: "record-transition", 19: "record-revoke",
              22: "contract-call"}
CONSENT = g.CONTRACT_CONSENT
CLAIM = g.CLAIM
EMPLOYMENT = "example.org.employment/1"
INTERFACE = {"propose": 1, "result": 2, "update": 2}
MODEL = "example-model-7"


class Env:
    """The OpenSSL command line and a scratch directory, for SM2 and RFC 3161."""
    openssl = "openssl"
    work = pathlib.Path(".")


def iso(ms: int) -> str:
    t = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def seed(name: str) -> bytes:
    return hashlib.sha256(f"Kanhe test key: evidence {name}".encode()).digest()


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + length + content


def _sm2_pem(d: int, point: bytes) -> str:
    """An SM2 private key as PKCS #8 (id-ecPublicKey on the SM2 curve)."""
    ec_private = _der(0x30, _der(0x02, b"\x01") + _der(0x04, d.to_bytes(32, "big"))
                      + _der(0xA1, _der(0x03, b"\x00" + point)))
    algorithm = _der(0x30, bytes.fromhex("06072a8648ce3d0201") + bytes.fromhex("06082a811ccf5501822d"))
    der = _der(0x30, _der(0x02, b"\x00") + algorithm + _der(0x04, ec_private))
    body = base64.b64encode(der).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"


class Key:
    """A throwaway signing key, derived from its name: seed = SHA-256("Kanhe
    test key: evidence <name>")."""

    def __init__(self, name: str, alg: int = ED25519):
        self.name, self.alg = name, alg
        s = seed(name)
        if alg == ED25519:
            self._key = ed25519.Ed25519PrivateKey.from_private_bytes(s)
            self.key = self._key.public_key().public_bytes_raw()
        elif alg == ESP256:
            self._key = ec.derive_private_key(int.from_bytes(s, "big") % (g.P256.n - 1) + 1, ec.SECP256R1())
            self.key = self._key.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint)
        elif alg in MLDSA_KEYS:
            self._key = MLDSA_KEYS[alg].from_seed_bytes(s)
            self.key = self._key.public_key().public_bytes_raw()
        elif alg == SM2:
            d = int.from_bytes(s, "big") % (g.SM2_CURVE.n - 2) + 1
            x, y = g.SM2_CURVE.mul(d, g.SM2_CURVE.g)
            self.key = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
            self._path = Env.work / f"sm2-{hashlib.sha256(name.encode()).hexdigest()[:16]}.pem"
            self._path.write_text(_sm2_pem(d, self.key))
        else:
            raise ValueError(alg)

    @property
    def public(self) -> list:
        return [self.alg, self.key]

    def sign(self, message: bytes) -> bytes:
        """A signature in Kanhe's wire format for the algorithm (section 3)."""
        if self.alg == ED25519 or self.alg in MLDSA_KEYS:
            return self._key.sign(message)
        if self.alg == ESP256:
            signature = g.raw_rs(self._key.sign(message, ec.ECDSA(hashes.SHA256())), low_s=True)
            assert g.ecdsa_p256_verify(self.key, message, signature)
            return signature
        tbs = Env.work / "sm2-tbs.bin"
        tbs.write_bytes(message)
        der = subprocess.run([Env.openssl, "pkeyutl", "-sign", "-rawin", "-digest", "sm3", "-inkey", str(self._path),
                              "-in", str(tbs), "-pkeyopt", f"distid:{g.SM2_DISTINGUISHING_ID}"],
                             check=True, capture_output=True).stdout
        signature = g.raw_rs(der)
        assert g.sm2_verify(self.key, message, signature, g.SM2_DISTINGUISHING_ID.encode())
        return signature

    def sign_der(self, message: bytes) -> bytes:
        """A WebAuthn ES256 signature: DER, as authenticators make it."""
        assert self.alg == ESP256
        return self._key.sign(message, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# Proof of presence (section 7)
# ---------------------------------------------------------------------------

def challenge(forge: "Forge", key: Key, payload: dict) -> bytes:
    return forge.h(b"Kanhe presence v1" + forge.kid(key) + g.dcbor(payload))


def passkey_credential(key: Key, credential_id: bytes, label: str) -> dict:
    return {1: "localhost", 2: credential_id, 3: key.public, 4: label}


def hardware_credential(key: Key, credential_id: bytes, label: str) -> dict:
    return {2: credential_id, 3: key.public, 4: label, 5: 2}


def passkey_proof(credential: Key, credential_id: bytes, flags: int = 0x05):
    """A WebAuthn assertion over the statement's challenge, as a browser makes
    it on http://localhost (flags 0x05: user present and verified)."""
    def make(forge, signer, payload):
        c = challenge(forge, signer, payload)
        auth = hashlib.sha256(b"localhost").digest() + bytes([flags]) + (7).to_bytes(4, "big")
        client = ('{"type":"webauthn.get","challenge":"' + g.b64url(c) +
                  '","origin":"http://localhost:4000","crossOrigin":false}').encode()
        data = auth + hashlib.sha256(client).digest()
        signature = credential.sign_der(data) if credential.alg == ESP256 else credential.sign(data)
        return {1: credential_id, 2: auth, 3: client, 4: signature}
    make.method = 1
    return make


def hardware_proof(credential: Key, credential_id: bytes, wrong: bool = False):
    """A hardware key's signature over the challenge itself; `wrong` signs
    another challenge."""
    def make(forge, signer, payload):
        c = challenge(forge, signer, payload)
        return {1: credential_id, 4: credential.sign(forge.h(c) if wrong else c)}
    make.method = 2
    return make


# ---------------------------------------------------------------------------
# A ledger written by hand
# ---------------------------------------------------------------------------

class Forge:
    """A ledger: statements signed with throwaway keys, log entries at chosen
    times, the state kept by hand, state commitments, checkpoints, receipts,
    and evidence bundles. Registration times move a minute per entry."""

    def __init__(self, name: str, *, hash_id: int = SHA256, root: Key | None = None, log: Key | None = None,
                 t0: int = T0):
        self.name, self.hash_id = name, hash_id
        self.entries: list[bytes] = []
        self.times: list[int] = []
        self.info: list[dict] = []
        self.index: dict[bytes, int] = {}
        self.leaves: dict[bytes, list] = {}
        self.snapshots: dict[int, list] = {}
        self.actors: dict[bytes, dict] = {}
        self.delegations: dict[bytes, dict] = {}
        self.records: dict[bytes, dict] = {}
        self.contracts: dict[bytes, dict] = {}
        self.instances: dict[bytes, dict] = {}
        self.requests: dict[bytes, dict] = {}
        self.claims: dict[bytes, bytes] = {}  # claim -> its source (v0.14)
        self.time = t0
        self.nonce = 0
        self.root = root or Key(f"{name} root")
        log = log or Key(f"{name} log")
        self.log_keys = [(0, log)]
        self.id = None
        self.id = self.add(1, self.root, None, {1: hash_id, 2: name, 3: self.root.public, 4: log.public})
        self.org = self.id
        self.info[0]["signer"] = self.id
        self.actors[self.id] = {"kind": ORG, "name": name, "key": None, "responsible": None, "revoked": False}
        self.leaves[self.id] = [1, self.id, [0]]

    # Hashes, keys, and signatures -------------------------------------------

    def h(self, data: bytes) -> bytes:
        return hashlib.new(g.HASHES[self.hash_id], data).digest()

    def merkle(self) -> g.MerkleOracle:
        return g.MerkleOracle(g.HASHES[self.hash_id])

    def kid(self, key: Key) -> bytes:
        return self.h(g.dcbor(key.public))

    def key_of(self, actor: bytes) -> Key:
        return self.root if actor == self.org else self.actors[actor]["key"]

    def log_key_for(self, size: int) -> Key:
        """The log key in effect for a tree of `size` entries (section 8)."""
        return [key for index, key in self.log_keys if index < size][-1]

    def sign(self, key: Key, content_type: str, payload: bytes) -> tuple[bytes, bytes]:
        protected = g.dcbor({1: key.alg, 3: content_type, 4: self.kid(key)})
        tbs = g.dcbor(["Signature1", protected, b"", payload])
        return g.dcbor(cbor2.CBORTag(18, [protected, {}, payload, key.sign(tbs)])), self.h(tbs)

    # Statements ---------------------------------------------------------------

    def add(self, kind: int, key: Key, actor, body, delegation=None, *, creates=None, touches=(), refs=(),
            presence=None, provenance=None, issued_at=None, at=None, encode=None) -> bytes:
        at = self.time if at is None else at
        self.nonce += 1
        p = {0: 1, 1: kind, 5: at - SECOND if issued_at is None else issued_at,
             6: hashlib.sha256(f"nonce {self.name} {self.nonce}".encode()).digest()[:16], 7: body}
        if self.id is not None:
            p[2], p[3] = self.id, actor
        if delegation is not None:
            p[4] = delegation
        if provenance is not None:
            p[9] = provenance
        if presence is not None:
            p[8] = presence(self, key, p)
        signed, sid = self.sign(key, g.STATEMENT_TYPE, (encode or g.dcbor)(p))
        index = len(self.entries)
        self.entries.append(g.dcbor({1: sid, 2: at, 3: signed}))
        self.times.append(at)
        self.info.append({"type": kind, "signer": actor, "delegation": delegation, "payload": p, "id": sid,
                          "presence": getattr(presence, "method", None) if presence is not None else None,
                          "refs": [r for r in (actor, delegation, *refs) if r is not None]})
        self.index[sid] = index
        if creates is not None:
            self.leaves[sid] = [creates, sid, [index]]
        for target in touches:
            self.leaves[target][2].append(index)
        self.time = at + MINUTE
        return sid

    def actor(self, kind: int, name: str, key: Key, *, by=None, delegation=None, responsible=None, model=None,
              provenance=None) -> bytes:
        by = by or self.org
        body = {1: kind, 2: name, 3: key.public}
        if responsible is not None:
            body[4] = responsible
        if model is not None:
            body[5] = {1: model}
        actor = self.add(2, self.key_of(by), by, body, delegation, creates=1,
                         refs=[responsible] if responsible else (), provenance=provenance)
        self.actors[actor] = {"kind": kind, "name": name, "key": key, "responsible": responsible, "revoked": False}
        return actor

    def grant(self, grantee: bytes, scope: dict, *, by=None, under=None, presence=None) -> bytes:
        by = by or self.org
        # The CDDL's scope: statement and record types strictly ascending.
        assert scope[1] == sorted(set(scope[1])), scope[1]
        assert 2 not in scope or scope[2] == sorted(set(scope[2]), key=str.encode), scope[2]
        d = self.add(5, self.key_of(by), by, {1: grantee, 2: scope}, under, creates=2, refs=[grantee],
                     presence=presence)
        self.delegations[d] = {"grantor": by, "parent": under, "grantee": grantee}
        return d

    def rotate_key(self, actor: bytes, new: Key, *, by=None, delegation=None, presence=None) -> bytes:
        by = by or actor
        sid = self.add(3, self.key_of(by), by, {1: actor, 2: new.public}, delegation, touches=[actor], refs=[actor],
                       presence=presence)
        if actor == self.org:
            self.root = new
        else:
            self.actors[actor]["key"] = new
        return sid

    def rotate_log_key(self, new: Key) -> bytes:
        sid = self.add(8, self.root, self.org, {1: new.public}, touches=[self.org])
        self.log_keys.append((self.index[sid], new))
        return sid

    def revoke_actor(self, actor: bytes, *, by=None, delegation=None) -> bytes:
        by = by or self.org
        sid = self.add(4, self.key_of(by), by, {1: actor, 2: "left"}, delegation, touches=[actor], refs=[actor])
        self.actors[actor]["revoked"] = True
        return sid

    def revoke_delegation(self, d: bytes, *, by=None, delegation=None) -> bytes:
        by = by or self.org
        return self.add(6, self.key_of(by), by, {1: d, 2: "project over"}, delegation, touches=[d], refs=[d])

    def set_presence(self, person: bytes, credentials: list) -> bytes:
        return self.add(7, self.root, self.org, {1: person, 2: credentials}, touches=[person], refs=[person])

    def record(self, by: bytes, kind: str = "example.org.report/1", *, delegation=None, fields=None, attachments=(),
               metadata=None, supersedes=None, presence=None, provenance=None, issued_at=None,
               encode=None) -> bytes:
        fields = {"note": "evidence suite"} if fields is None else fields
        ordered = sorted(fields.items(), key=lambda f: f[0].encode())
        tag = f"{self.name} {self.nonce}"
        salts = [self.h(f"field salt {tag} {name}".encode())[:16] for name, _ in ordered]
        leaves = [g.dcbor([name, salt, value]) for (name, value), salt in zip(ordered, salts)]
        body = {1: kind, 2: self.merkle().mth(leaves), 3: len(leaves)}
        opened = {}
        if attachments:
            body[4] = []
            for name, media, content in attachments:
                salt = self.h(f"attachment salt {tag} {name}".encode())[:16]
                body[4].append([name, media, len(content), self.h(salt + content)])
                opened[name] = (salt, content)
        if metadata is not None:
            body[5] = metadata
        if supersedes is not None:
            body[6] = supersedes
        rid = self.add(16, self.key_of(by), by, body, delegation, creates=3,
                       touches=[supersedes] if supersedes is not None else (), presence=presence,
                       provenance=provenance, issued_at=issued_at, encode=encode)
        self.records[rid] = {"names": [n for n, _ in ordered], "leaves": leaves, "attachments": opened}
        if kind == CLAIM and isinstance(metadata, dict) and "source" in metadata:
            self.claims[rid] = metadata["source"]
        return rid

    def about(self, kind: int, record: bytes, body: dict, by: bytes, delegation=None, **kw) -> bytes:
        """An endorsement, transition, or revocation of a record."""
        return self.add(kind, self.key_of(by), by, {1: record, **body}, delegation, touches=[record], **kw)

    def commit(self, at: int | None = None) -> int:
        """Appends the state commitment, signed by the log key in effect at its
        index; returns its index."""
        index = len(self.entries)
        at = self.time if at is None else at
        leaves = sorted(copy.deepcopy(list(self.leaves.values())), key=lambda leaf: leaf[1])
        payload = g.dcbor({1: self.id, 2: self.hash_id, 3: index, 4: g.smt_root(self, leaves), 5: at})
        signed, cid = self.sign(self.log_key_for(index), g.STATE_TYPE, payload)
        self.entries.append(g.dcbor({1: cid, 2: at, 4: signed}))
        self.times.append(at)
        self.info.append({"type": None, "signer": None, "delegation": None, "refs": [], "id": cid})
        self.snapshots[index] = leaves
        self.time = at + MINUTE
        return index

    def checkpoint(self, size: int | None = None, *, at: int | None = None, key: Key | None = None):
        """(signed checkpoint, its payload, root) over the first `size` entries."""
        size = len(self.entries) if size is None else size
        root = self.merkle().mth(self.entries[:size])
        at = self.times[size - 1] + SECOND if at is None else at
        payload = g.dcbor({1: self.id, 2: self.hash_id, 3: size, 4: root, 5: at})
        signed, _ = self.sign(key or self.log_key_for(size), g.CHECKPOINT_TYPE, payload)
        return signed, payload, root

    def receipt(self, index: int, size: int, root: bytes, key: Key, path=None) -> bytes:
        path = self.merkle().path(index, self.entries[:size]) if path is None else path
        protected = g.dcbor({1: key.alg, 4: self.kid(key), 395: g.VDS[self.hash_id]})
        tbs = g.dcbor(["Signature1", protected, b"", root])
        proof = g.dcbor([size, index, path])
        return g.dcbor(cbor2.CBORTag(18, [protected, {396: {-1: [proof]}}, None, key.sign(tbs)]))

    def cosign(self, witness: Key, checkpoint_payload: bytes) -> bytes:
        return self.sign(witness, g.COSIGNATURE_TYPE, checkpoint_payload)[0]

    def consistency(self, old: int, new: int) -> list[bytes]:
        return self.merkle().subproof(old, self.entries[:new], True)

    # What a bundle holds ------------------------------------------------------

    def chain(self, index: int) -> list[bytes]:
        out, d = [], self.info[index]["delegation"]
        while d is not None:
            out.append(d)
            d = self.delegations[d]["parent"]
        return out

    def events(self, subject: bytes, size: int) -> list[int]:
        """A record's history, or an instance's calls and, for a child, its
        ancestors' calls up to each one that created the next generation."""
        events = {i for i in self.leaves[subject][2] if i < size}
        node = self.instances.get(subject)
        while node is not None and node["parent"] is not None:
            parent = self.instances[node["parent"]]
            events |= {i for i in self.leaves[node["parent"]][2] if i <= node["created_by"]}
            node = parent
        return sorted(events)

    def involved(self, subject: bytes, size: int) -> list[bytes]:
        """Section 11, step 7: the record (or the instance and its contract),
        each event's signer, an agent signer's responsible person, and every
        delegation in the chain with its grantor. A claim's source (v0.14) is
        involved too, and its statements count as events."""
        out = [subject]
        if subject in self.instances:
            out.append(self.instances[subject]["contract"])
        events = self.events(subject, size)
        source = self.claims.get(subject)
        if source is not None:
            out.append(source)
            events = sorted(set(events) | {i for i in self.leaves[source][2] if i < size})
        for i in events:
            signer = self.info[i]["signer"]
            out.append(signer)
            if self.actors[signer]["kind"] == AGENT:
                out.append(self.actors[signer]["responsible"])
            for d in self.chain(i):
                out += [d, self.delegations[d]["grantor"]]
        return list(dict.fromkeys(out))

    def needed(self, subject: bytes, size: int) -> list[int]:
        """The entries a bundle holds: genesis, the events, every involved
        object's history, every rotation of the organization's keys, all they
        depend on (signers, delegations, referenced actors and contracts,
        with their histories), and the state commitment the checkpoint ends
        with."""
        def below(obj):
            return {i for i in self.leaves[obj][2] if i < size}
        needed = {0} | set(self.events(subject, size)) | below(self.org)
        for obj in self.involved(subject, size):
            if obj in self.instances and obj != subject:
                continue
            needed |= below(obj)
        work = sorted(needed)
        while work:
            for obj in self.info[work.pop()]["refs"]:
                for i in below(obj) - needed:
                    needed.add(i)
                    work.append(i)
        if size - 1 in self.snapshots:
            needed.add(size - 1)
        return sorted(needed)

    def bundle(self, subject: bytes, *, size=None, drop=(), extra=(), proofs=True, drop_proofs=(),
               disclose=(), open_=(), cosignatures=(), anchors=(), checkpoint=None, receipt_key=None) -> dict:
        """An evidence bundle as a map (encode with g.dcbor)."""
        size = len(self.entries) if size is None else size
        signed, _, root = checkpoint or self.checkpoint(size)
        key = receipt_key or self.log_key_for(size)
        indices = (set(self.needed(subject, size)) | set(extra)) - set(drop)
        b = {0: 1, 1: subject, 2: [[self.entries[i], self.receipt(i, size, root, key)] for i in sorted(indices)],
             3: signed}
        if cosignatures:
            b[4] = list(cosignatures)
        if disclose:
            record = self.records[subject]
            leaves = record["leaves"]
            b[5] = [[leaves[i], i, self.merkle().path(i, leaves)]
                    for i in sorted(record["names"].index(n) for n in disclose)]
        if open_:
            b[6] = [[name, self.records[subject]["attachments"][name][0]] for name in open_]
        if proofs and size - 1 in self.snapshots and size - 1 in indices:
            leaves = self.snapshots[size - 1]
            by_id = {leaf[1]: leaf for leaf in leaves}
            b[7] = [[by_id[obj], g.smt_proof(self, leaves, obj)] for obj in self.involved(subject, size)
                    if obj not in drop_proofs]
        if anchors:
            b[8] = list(anchors)
        return b

    # Contracts ------------------------------------------------------------------

    def deploy(self, code: bytes, interface: dict, *, by=None, delegation=None, name="Oracle test contract") -> bytes:
        by = by or self.org
        body = {1: code, 2: interface, 3: "wasm", 4: "tools/testvectors/evidence_suite.py 1", 6: name}
        k = self.add(21, self.key_of(by), by, body, delegation, creates=4)
        self.contracts[k] = {"module": w.load(code), "retired": False}
        return k

    def retire(self, contract: bytes, *, by=None, delegation=None) -> bytes:
        by = by or self.org
        sid = self.add(23, self.key_of(by), by, {1: contract, 2: "superseded"}, delegation, touches=[contract],
                       refs=[contract])
        self.contracts[contract]["retired"] = True
        return sid

    def signer_map(self, actor: bytes, presence, provenance) -> dict:
        """Who signs a statement, as a contract sees it (section 15)."""
        out = {1: self.actors[actor]["kind"]}
        if presence is not None:
            out[2] = presence.method
        if provenance and 1 in provenance:
            out[3] = provenance[1]
        return out

    def view(self, instance: bytes) -> dict:
        inst = self.instances[instance]
        out = {1: instance, 2: inst["head"], 3: inst["state"]}
        if inst["status"] is not None:
            out[4] = inst["status"]
        if inst["parties"]:
            out[5] = inst["parties"]
        if inst["parent"] is not None:
            out[6] = [inst["parent"], inst["depth"]]
        return out

    def create(self, contract: bytes, function: str, accept: dict, *, by: bytes, delegation=None, provenance=None):
        return self._call({1: contract, 3: function, 4: g.dcbor([1, accept])}, accept, by, delegation, provenance)

    def call(self, instance: bytes, function: str, accept: dict | None, *, by: bytes, delegation=None, consents=(),
             answer=None, reference=None, head=None, args=None, provenance=None, presence=None, check=True):
        """A call on an instance. The oracle contract writes a byte-string
        argument as its output, so the arguments are the accept's encoding
        (or `args`, for a call forged to break a rule)."""
        body = {2: instance, 3: function, 4: g.dcbor([1, accept]) if args is None else args,
                5: self.instances[instance]["head"] if head is None else head}
        if consents:
            body[6] = sorted(consents, key=lambda ref: ref[0])
        if reference is not None:
            body[7] = reference
        if answer is not None:
            body[8] = answer
        return self._call(body, accept, by, delegation, provenance, presence, check)

    def _call(self, body, accept, by, delegation, provenance=None, presence=None, check=True):
        at = self.time
        contract = body[1] if 1 in body else self.instances[body[2]]["contract"]
        if provenance is None and self.actors[by]["kind"] == AGENT:
            provenance = {1: MODEL}
        if check:
            # The run the home makes, by the reference interpreter: the output
            # must be the accept the call was forged with.
            inp = {1: body[3], 2: body[4], 3: self.id, 4: contract, 6: [by, self.signer_map(by, presence, provenance)],
                   7: at}
            if 2 in body:
                inp[5] = self.view(body[2])
            if 6 in body:
                inp[8] = [[ref[0], ref[3]] for ref in body[6]]
            if 8 in body:
                r = self.requests[body[8][0]]
                inp[9] = {1: body[8][0], 2: r["kind"], 3: r["params"], 4: r["deadline"], 5: r["asked_at"],
                          6: body[8][1]}
            outcome, output, _, reason = w.run(self.contracts[contract]["module"], g.dcbor(inp),
                                               g.HASHES[self.hash_id])
            if accept is None:
                assert outcome == "aborted", (outcome, output)
            else:
                assert (outcome, output) == ("ok", g.dcbor([1, accept])), (outcome, output, reason)
        creation = 1 in body
        sid = self.add(22, self.key_of(by), by, body, delegation, creates=5 if creation else None,
                       touches=() if creation else [body[2]], refs=[contract], provenance=provenance,
                       presence=presence, at=at)
        index = self.index[sid]
        if accept is None:
            return sid, [], []
        target = sid if creation else body[2]
        if creation:
            self.instances[sid] = {"contract": contract, "state": None, "status": None, "parties": {}, "final": False,
                                   "parent": None, "depth": 0, "created_by": None, "position": None}
        inst = self.instances[target]
        if 8 in body and body[8][0] in self.requests:
            self.requests[body[8][0]].update(status=body[8][1], answered_at=at)
        inst.update(head=index, state=accept[1], final=inst["final"] or accept.get(5, False))
        if 2 in accept:
            inst["status"] = accept[2]
        if 3 in accept:
            inst["parties"] = accept[3]
        children = []
        for position, child in enumerate(accept.get(6, [])):
            cid = self.h(g.dcbor([sid, position]))
            self.leaves[cid] = [5, cid, [index]]
            self.instances[cid] = {"contract": contract, "state": child[1], "status": child.get(2),
                                   "parties": child.get(3, {}), "final": False, "parent": target,
                                   "depth": inst["depth"] + 1, "created_by": index, "position": position,
                                   "head": index}
            children.append(cid)
        made = []
        for position, r in enumerate(accept.get(7, [])):
            rid = g.request_id(self, sid, position)
            self.requests[rid] = {"instance": target, "kind": r[1], "params": r[2], "deadline": r[3],
                                  "asked_at": at, "status": None, "answered_at": None}
            made.append(rid)
        return sid, children, made

    # Facts ------------------------------------------------------------------------

    def actor_fact(self, actor: bytes) -> dict:
        a = self.actors[actor]
        out = {"id": actor.hex(), "kind": KIND_NAMES[a["kind"]], "name": a["name"]}
        if a["kind"] == AGENT:
            out["responsible"] = self.actors[a["responsible"]]["name"]
        return out

    def authority_fact(self, index: int) -> list:
        """The grantors of the signer's delegation chain, its own first."""
        out = []
        for d in self.chain(index):
            grantor = self.delegations[d]["grantor"]
            out.append({"id": grantor.hex(), "kind": KIND_NAMES[self.actors[grantor]["kind"]]})
        return out

    def event_fact(self, index: int, **extra) -> dict:
        info = self.info[index]
        presence = {1: {"method": "webauthn", "user_verified": True},
                    2: {"method": "hardware-key", "user_verified": True}}.get(info["presence"])
        out = {"index": index, "type": TYPE_NAMES[info["type"]], "registered_at": iso(self.times[index]),
               "actor": self.actor_fact(info["signer"]), "authority": self.authority_fact(index),
               "presence": presence}
        out.update(extra)
        return out

    def ledger_fact(self, checked: bool = True) -> dict:
        return {"id": self.id.hex(), "organization": self.name, "hash": HASH_NAMES[self.hash_id],
                "id_checked": checked}


# ---------------------------------------------------------------------------
# Time-stamp authorities (section 10.1): roots and certificates made with
# `cryptography`, tokens made by OpenSSL's responder
# ---------------------------------------------------------------------------

class Authority:
    def __init__(self, name: str):
        self.name = name
        root_key = ec.derive_private_key(int.from_bytes(seed(f"tsa root {name}"), "big") % (2**255), ec.SECP256R1())
        tsa_key = ec.derive_private_key(int.from_bytes(seed(f"tsa {name}"), "big") % (2**255), ec.SECP256R1())
        start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Evidence Test Root {name}")])
        tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Evidence Test TSA {name}")])
        root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                .public_key(root_key.public_key()).serial_number(1).not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                               critical=True)
                .sign(root_key, hashes.SHA256()))
        tsa = (x509.CertificateBuilder().subject_name(tsa_name).issuer_name(root_name)
               .public_key(tsa_key.public_key()).serial_number(2).not_valid_before(start).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                              critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
               .sign(root_key, hashes.SHA256()))
        pem = serialization.Encoding.PEM
        self.root_pem = root.public_bytes(pem).decode()
        d = self.dir = Env.work / f"tsa-{name}"
        d.mkdir()
        (d / "root.pem").write_bytes(root.public_bytes(pem))
        (d / "tsa.pem").write_bytes(tsa.public_bytes(pem))
        (d / "tsa.key").write_bytes(tsa_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
        (d / "serial").write_text("01\n")
        (d / "tsa.cnf").write_text(
            "[ tsa ]\ndefault_tsa = c\n[ c ]\n"
            f"serial = {d / 'serial'}\nsigner_cert = {d / 'tsa.pem'}\ncerts = {d / 'root.pem'}\n"
            f"signer_key = {d / 'tsa.key'}\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
            "digests = sha256, sm3\naccuracy = secs:1\nclock_precision_digits = 3\ness_cert_id_alg = sha256\n")

    def stamp(self, payload: bytes, hash_id: int, certificate: bool = True) -> tuple[bytes, int]:
        """A token over `payload` (a checkpoint's payload) under the ledger's
        hash: (token, its time in Unix milliseconds). Without `certificate`,
        the query does not ask for the authority's certificate (certReq)."""
        name = g.HASHES[hash_id]
        imprint = hashlib.new(name, payload).digest()
        d = self.dir
        subprocess.run([Env.openssl, "ts", "-query", "-digest", imprint.hex(), f"-{name}",
                        *(["-cert"] if certificate else []), "-out", str(d / "q")], check=True, capture_output=True)
        subprocess.run([Env.openssl, "ts", "-reply", "-config", str(d / "tsa.cnf"), "-queryfile", str(d / "q"),
                        "-token_out", "-out", str(d / "token")], check=True, capture_output=True)
        text = subprocess.run([Env.openssl, "ts", "-reply", "-in", str(d / "token"), "-token_in", "-text"],
                              check=True, capture_output=True, text=True).stdout
        stamped = re.search(r"Time stamp: (.+) GMT", text).group(1)
        when = datetime.datetime.strptime(" ".join(stamped.split()), "%b %d %H:%M:%S.%f %Y")
        assert "Accuracy: 0x01 seconds" in text, text
        return (d / "token").read_bytes(), int(when.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)


ACCURACY = 1_000


def key_fact(key: Key) -> dict:
    """A public key as reports show it."""
    return {"algorithm": ALG_NAMES[key.alg], "key": key.key.hex()}


def anchor(checkpoint: bytes, tokens: list, consistency=None) -> dict:
    out = {1: checkpoint, 2: tokens}
    if consistency is not None:
        out[3] = consistency
    return out


# ---------------------------------------------------------------------------
# The suite
# ---------------------------------------------------------------------------

class Suite:
    def __init__(self):
        self.cases: list[dict] = []

    def add(self, name: str, description: str, kind: str, evidence: bytes, verified: bool, *, rule: str | None = None,
            facts: dict | None = None, ledger_id: bytes | None = None, witnesses=(), min_witnesses: int = 0,
            tsa_roots=(), min_timestamps: int = 0, attachments: dict | None = None, require_presence=False,
            require_answered=False):
        assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) and name not in {c["name"] for c in self.cases}, name
        assert verified == (rule is None), name
        assert verified or not facts, name
        options = {}
        if ledger_id is not None:
            options["ledger_id"] = ledger_id.hex()
        if witnesses:
            options["witnesses"] = [g.dcbor(key.public).hex() for key in witnesses]
        if min_witnesses:
            options["min_witnesses"] = min_witnesses
        if tsa_roots:
            options["tsa_roots"] = [a.root_pem for a in tsa_roots]
        if min_timestamps:
            options["min_timestamps"] = min_timestamps
        if attachments:
            options["attachments"] = {k: v.hex() for k, v in attachments.items()}
        if require_presence:
            options["require_presence"] = True
        if require_answered:
            options["require_answered"] = True
        case = {"name": name, "description": description, "kind": kind, "evidence": evidence.hex(),
                "options": options, "verified": verified}
        if rule is not None:
            case["rule"] = rule
        case["facts"] = facts or {}
        self.cases.append(case)


def enc(value) -> bytes:
    return g.dcbor(value)


def decode(data: bytes):
    """CBOR decoded by cbor2, with its tuples and frozen maps made lists and
    dicts again, so that it can be changed and encoded."""
    def thaw(v):
        if isinstance(v, (list, tuple)):
            return [thaw(x) for x in v]
        if isinstance(v, dict) or type(v).__name__ == "frozendict":
            return {thaw(k) if not isinstance(k, (list, tuple)) else k: thaw(x) for k, x in v.items()}
        if isinstance(v, cbor2.CBORTag):
            return cbor2.CBORTag(v.tag, thaw(v.value))
        return v
    return thaw(cbor2.loads(data))


def lab(name: str = "Evidence Lab", **kw) -> dict:
    """A lab's ledger: a person (a reviewer) delegated by the organization,
    who registers a report with four fields and two attachments; a device
    endorses it."""
    f = Forge(name, **kw)
    s = {"f": f}
    s["person"] = f.actor(PERSON, "Reviewer", Key(f"{name} reviewer"))
    s["d_person"] = f.grant(s["person"], {1: [2, 5, 16, 17, 19], 5: True})
    s["device"] = f.actor(DEVICE, "Scale 7", Key(f"{name} scale"))
    s["d_device"] = f.grant(s["device"], {1: [17]})
    s["fields"] = {"title": "Flange test", "result": "pass", "units": 120, "batch": b"\x07\x26"}
    s["files"] = [("report.pdf", "application/pdf", b"%PDF-1.7 a lab report"),
                  ("photo.jpg", "image/jpeg", b"\xff\xd8\xff a photograph")]
    s["record"] = f.record(s["person"], delegation=s["d_person"], fields=s["fields"], attachments=s["files"],
                           metadata={"lab": "North", "batch": 7})
    s["endorse"] = f.about(17, s["record"], {2: "instrument"}, s["device"], s["d_device"])
    return s


def record_cases(suite: Suite, one: Authority, two: Authority) -> None:
    # --- Valid: the plain cases -------------------------------------------------
    f = Forge("Plain Org")
    r = f.record(f.org, "example.org.note/1", fields={"text": "a plain note"})
    f.commit()
    suite.add("record-plain", "The organization registers a record; the bundle ends with the state commitment.",
              "record", enc(f.bundle(r)), True, ledger_id=f.id, facts={
                  "ledger": f.ledger_fact(), "checkpoint": {"tree_size": len(f.entries)},
                  "record": {"id": r.hex(), "type": "example.org.note/1", "state": "registered", "revoked": False,
                             "supersedes": None, "superseded_by": None},
                  "events": [f.event_fact(1)], "complete": True,
                  "state_commitment": {"index": len(f.entries) - 1},
                  "witnesses": {"trusted": 0, "untrusted": 0},
                  "timestamps": {"trusted_authorities": 0, "tokens": []},
                  "keys": {"log_key": key_fact(f.log_key_for(len(f.entries))),
                           "log_key_rotations": 0, "root_key_rotations": 0}})

    suite.add("record-plain-no-expected-ledger",
              "The same bundle verified without an expected ledger id: it verifies, unchecked against one.",
              "record", enc(f.bundle(r)), True, facts={"ledger": f.ledger_fact(checked=False), "complete": True})

    s = lab()
    f = s["f"]
    f.commit()
    content = dict((n, c) for n, _, c in s["files"])
    suite.add("record-disclosures-attachment",
              "A person's record under a delegation: two of four fields disclosed, one of two attachments opened and "
              "checked against its content.", "record",
              enc(f.bundle(s["record"], disclose=["title", "units"], open_=["report.pdf"])), True, ledger_id=f.id,
              attachments={"report.pdf": content["report.pdf"]}, facts={
                  "record": {"id": s["record"].hex(), "type": "example.org.report/1", "state": "registered",
                             "revoked": False, "metadata": {"batch": 7, "lab": "North"}},
                  "disclosed_fields": {"title": "Flange test", "units": 120},
                  "attachments": [{"name": "report.pdf", "media_type": "application/pdf",
                                   "size": len(content["report.pdf"]), "status": "verified"},
                                  {"name": "photo.jpg", "media_type": "image/jpeg",
                                   "size": len(content["photo.jpg"]), "status": "not-provided"}],
                  "events": [f.event_fact(f.index[s["record"]]), f.event_fact(f.index[s["endorse"]])],
                  "complete": True})
    lab_bundle, lab_forge = f.bundle(s["record"], disclose=["result", "title"], open_=["report.pdf", "photo.jpg"]), f

    # --- An AI agent under a chain of delegations ---------------------------------
    f = Forge("Agent Lab")
    person = f.actor(PERSON, "Lead Reviewer", Key("agent lab lead"))
    d1 = f.grant(person, {1: [2, 5, 16, 17], 2: ["example.org.draft/1"], 5: True})
    agent = f.actor(AGENT, "Drafting Agent", Key("agent lab agent"), by=person, delegation=d1, responsible=person,
                    model=MODEL)
    d2 = f.grant(agent, {1: [16], 2: ["example.org.draft/1"]}, by=person, under=d1)
    device = f.actor(DEVICE, "Spectrometer", Key("agent lab spectrometer"))
    d3 = f.grant(device, {1: [17]})
    r = f.record(agent, "example.org.draft/1", delegation=d2, fields={"text": "draft findings"},
                 provenance={1: MODEL, 2: "2026-10", 3: f.h(b"the measurements"),
                             4: [["kanhe_issue", f.h(b"tool v1")]]})
    e1 = f.about(17, r, {2: "reviewer"}, person, d1)
    e2 = f.about(17, r, {2: "instrument"}, device, d3)
    f.commit()
    suite.add("record-agent-delegation-chain",
              "An AI agent, registered by a person and delegated by them under the organization's delegation, "
              "registers a record with provenance; the person and a device endorse it.", "record",
              enc(f.bundle(r)), True, ledger_id=f.id, facts={
                  "events": [
                      f.event_fact(f.index[r], provenance={"model": MODEL, "model_version": "2026-10",
                                                           "input_commitment": f.h(b"the measurements").hex(),
                                                           "tools": [{"name": "kanhe_issue",
                                                                      "digest": f.h(b"tool v1").hex()}]}),
                      f.event_fact(f.index[e1], provenance=None),
                      f.event_fact(f.index[e2], provenance=None)],
                  "complete": True})

    # --- Key rotations -------------------------------------------------------------
    def rotation_org(old_key_commits: bool = False) -> dict:
        """The log and root keys rotated, a person's key rotated by the
        organization, a device's by itself, then endorsements under the new
        keys. `old_key_commits`: the old log key signs the state commitment."""
        f = Forge("Rotation Org")
        person = f.actor(PERSON, "Signer", Key("rotation signer"))
        dp = f.grant(person, {1: [16, 17]})
        device = f.actor(DEVICE, "Gate", Key("rotation gate"))
        dd = f.grant(device, {1: [17]})
        r = f.record(person, delegation=dp)
        log_rotation = f.rotate_log_key(Key("rotation log 2"))
        root_rotation = f.rotate_key(f.org, Key("rotation root 2"))
        f.rotate_key(person, Key("rotation signer 2"), by=f.org)
        f.rotate_key(device, Key("rotation gate 2"))
        events = [r, f.about(17, r, {2: "approver"}, person, dp), f.about(17, r, {2: "gate"}, device, dd),
                  f.about(17, r, {2: "owner"}, f.org)]
        if old_key_commits:
            new = f.log_keys.pop()
            f.commit()
            f.log_keys.append(new)
        else:
            f.commit()
        return {"f": f, "record": r, "events": events, "log_rotation": f.index[log_rotation],
                "root_rotation": f.index[root_rotation]}

    rotation = rotation_org()
    f, r = rotation["f"], rotation["record"]
    n = len(f.entries)
    suite.add("record-key-rotations",
              "The log key and the root key rotated; a person's key rotated by the organization, a device's by "
              "itself; endorsements under the new keys, the checkpoint under the new log key.", "record",
              enc(f.bundle(r)), True, ledger_id=f.id, facts={
                  "keys": {"log_key": key_fact(f.log_key_for(n)),
                           "log_key_rotations": 1, "root_key_rotations": 1},
                  "events": [f.event_fact(f.index[x]) for x in rotation["events"]], "complete": True})

    # --- Revoked later; a revoked record; versions -----------------------------------
    f = Forge("Revocation Org")
    person = f.actor(PERSON, "Former Clerk", Key("revocation clerk"))
    dp = f.grant(person, {1: [16]})
    device = f.actor(DEVICE, "Reader", Key("revocation reader"))
    dd = f.grant(device, {1: [17, 19]})
    r = f.record(person, delegation=dp)
    e = f.about(17, r, {2: "reader"}, device, dd)
    f.revoke_delegation(dp)
    f.revoke_actor(person)
    f.commit()
    suite.add("record-signer-revoked-later",
              "A person registers a record; later the organization revokes their delegation and the person. The "
              "record stays valid and the report shows the signer revoked.", "record", enc(f.bundle(r)), True,
              ledger_id=f.id, facts={
                  "record": {"id": r.hex(), "revoked": False},
                  "events": [f.event_fact(f.index[r], actor={**f.actor_fact(person), "revoked": True}),
                             f.event_fact(f.index[e], actor={**f.actor_fact(device), "revoked": False})],
                  "complete": True})
    revoked_later = {"f": f, "record": r, "person": person}

    f = Forge("Withdrawal Org")
    device = f.actor(DEVICE, "Registrar", Key("withdrawal registrar"))
    dd = f.grant(device, {1: [16, 19]})
    r = f.record(device, delegation=dd)
    x = f.about(19, r, {2: "issued in error"}, device, dd)
    f.commit()
    suite.add("record-revoked", "A device registers and later revokes a record; the bundle shows the revocation.",
              "record", enc(f.bundle(r)), True, ledger_id=f.id, facts={
                  "record": {"id": r.hex(), "revoked": True},
                  "events": [f.event_fact(f.index[r]), f.event_fact(f.index[x])], "complete": True})
    revoked_record = {"f": f, "record": r}

    f = Forge("Version Org")
    clerk = f.actor(PERSON, "Clerk", Key("version clerk"))
    dc = f.grant(clerk, {1: [16], 2: ["example.org.form/1", "example.org.form/2"]})
    v1 = f.record(clerk, "example.org.form/1", delegation=dc, fields={"text": "version 1"})
    v2 = f.record(clerk, "example.org.form/2", delegation=dc, fields={"text": "version 2"}, supersedes=v1)
    f.commit()
    suite.add("record-superseded", "Version 1's bundle holds the registration of version 2, which supersedes it.",
              "record", enc(f.bundle(v1)), True, ledger_id=f.id, facts={
                  "record": {"id": v1.hex(), "type": "example.org.form/1", "supersedes": None,
                             "superseded_by": v2.hex()},
                  "events": [f.event_fact(f.index[v1], new_version=None),
                             f.event_fact(f.index[v2], new_version=v2.hex())],
                  "complete": True})
    suite.add("record-new-version",
              "Version 2's bundle, which does not hold version 1: it is checked under every rule except those about "
              "version 1.", "record", enc(f.bundle(v2)), True, ledger_id=f.id, facts={
                  "record": {"id": v2.hex(), "type": "example.org.form/2", "supersedes": v1.hex(),
                             "superseded_by": None},
                  "events": [f.event_fact(f.index[v2])], "complete": True})

    # --- Not complete ------------------------------------------------------------------
    f = Forge("Open Org")
    r = f.record(f.org)
    f.about(17, r, {2: "owner"}, f.org)
    suite.add("record-not-complete",
              "The checkpoint ends with a statement, not a state commitment: the bundle verifies and is not "
              "complete.", "record", enc(f.bundle(r)), True, ledger_id=f.id,
              facts={"complete": False, "state_commitment": None, "events": [f.event_fact(1), f.event_fact(2)]})
    f.commit()
    suite.add("record-commitment-left-out",
              "The checkpoint ends with a state commitment, which the bundle leaves out with every state proof: it "
              "verifies and is not complete.", "record",
              enc(f.bundle(r, drop=[len(f.entries) - 1], proofs=False)), True, ledger_id=f.id,
              facts={"complete": False, "state_commitment": None})

    # --- Presence ---------------------------------------------------------------------
    f = Forge("Presence Org")
    person = f.actor(PERSON, "Approver", Key("presence approver"))
    dp = f.grant(person, {1: [16, 17], 6: True})
    passkey, ukey = Key("presence passkey", ESP256), Key("presence ukey")
    f.set_presence(person, [passkey_credential(passkey, b"passkey-1", "Laptop"),
                            hardware_credential(ukey, b"ukey-1", "Office UKey")])
    r = f.record(person, delegation=dp, presence=passkey_proof(passkey, b"passkey-1"))
    e = f.about(17, r, {2: "approver"}, person, dp, presence=hardware_proof(ukey, b"ukey-1"))
    f.rotate_key(person, Key("presence approver 2"), presence=passkey_proof(passkey, b"passkey-1"))
    e2 = f.about(17, r, {2: "signer"}, person, dp, presence=passkey_proof(passkey, b"passkey-1"))
    f.commit()
    suite.add("record-presence",
              "A person under a delegation that requires presence registers with a passkey (user verified), "
              "endorses with a hardware key, rotates their own key proving presence, user verified, and endorses "
              "again under the new key.", "record", enc(f.bundle(r)), True, ledger_id=f.id, facts={
                  "events": [f.event_fact(f.index[x]) for x in (r, e, e2)], "complete": True})
    presence = {"f": f}

    # --- Witnesses ------------------------------------------------------------------------
    f = Forge("Witnessed Org")
    r = f.record(f.org)
    f.commit()
    w1, w2, w3 = Key("witness one"), Key("witness two", ESP256), Key("witness three")
    cp, payload, root = f.checkpoint()
    cos = [f.cosign(w1, payload), f.cosign(w2, payload)]
    suite.add("record-witnesses", "Two cosignatures, by a trusted witness and by one the verifier does not trust.",
              "record", enc(f.bundle(r, checkpoint=(cp, payload, root), cosignatures=cos)), True, ledger_id=f.id,
              witnesses=[w1], min_witnesses=1, facts={"witnesses": {"trusted": 1, "untrusted": 1}, "complete": True})
    suite.add("record-witnesses-two-trusted", "Two cosignatures by two trusted witnesses, two required.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), cosignatures=cos)), True, ledger_id=f.id,
              witnesses=[w1, w2, w3], min_witnesses=2, facts={"witnesses": {"trusted": 2, "untrusted": 0}})
    twice = [cos[1], f.cosign(w2, payload), cos[0]]
    suite.add("record-witness-counted-once",
              "One trusted witness's checkpoint cosigned twice (two ECDSA signatures): it counts once.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), cosignatures=twice)), True, ledger_id=f.id,
              witnesses=[w2], facts={"witnesses": {"trusted": 1, "untrusted": 1}})
    suite.add("too-few-trusted-witnesses",
              "Two trusted witnesses required; one trusted witness cosigned (twice), the other cosigner is not "
              "trusted.", "record", enc(f.bundle(r, checkpoint=(cp, payload, root), cosignatures=twice)), False,
              rule="11 step 6", ledger_id=f.id, witnesses=[w2], min_witnesses=2)
    forged = bytearray(cos[0])
    forged[-1] ^= 0x01
    suite.add("forged-trusted-cosignature",
              "The only trusted witness's cosignature does not verify (its last signature byte flipped), and one "
              "trusted witness is required.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), cosignatures=[bytes(forged)])), False,
              rule="11 step 6", ledger_id=f.id, witnesses=[w1], min_witnesses=1)

    # --- Time-stamp authorities ------------------------------------------------------------
    f = Forge("Stamped Org")
    person = f.actor(PERSON, "Notary", Key("stamped notary"))
    dp = f.grant(person, {1: [16, 17]})
    r = f.record(person, delegation=dp)
    early = len(f.entries)
    early_cp, early_payload, _ = f.checkpoint(early)
    token_early, t_early = one.stamp(early_payload, f.hash_id)
    e = f.about(17, r, {2: "notary"}, person, dp)
    f.commit()
    n = len(f.entries)
    cp, payload, root = f.checkpoint()
    token_one, t_one = one.stamp(payload, f.hash_id)
    token_two, t_two = two.stamp(payload, f.hash_id)
    final = anchor(cp, [token_one])
    suite.add("record-timestamp", "A trusted authority's token over the bundle's own checkpoint.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[final])), True, ledger_id=f.id,
              tsa_roots=[one], min_timestamps=1, facts={
                  "timestamps": {"trusted_authorities": 1, "existed_by": iso(t_one + ACCURACY),
                                 "tokens": [{"checkpoint_size": n, "time": iso(t_one), "accuracy_ms": ACCURACY,
                                             "trusted": True}]},
                  "events": [f.event_fact(f.index[r], existed_by=iso(t_one + ACCURACY)),
                             f.event_fact(f.index[e], existed_by=iso(t_one + ACCURACY))]})
    earlier = anchor(early_cp, [token_early], f.consistency(early, n))
    suite.add("record-timestamp-earlier-checkpoint",
              "A trusted token over an earlier checkpoint, with its consistency proof: the registration existed by "
              "the token's time, the later endorsement has no such bound.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[earlier])), True, ledger_id=f.id,
              tsa_roots=[one], facts={
                  "timestamps": {"trusted_authorities": 1, "existed_by": iso(t_early + ACCURACY),
                                 "tokens": [{"checkpoint_size": early, "trusted": True}]},
                  "events": [f.event_fact(f.index[r], existed_by=iso(t_early + ACCURACY)),
                             f.event_fact(f.index[e], existed_by=None)]})
    both = anchor(cp, [token_one, token_two])
    suite.add("record-timestamp-two-authorities", "Tokens of two trusted authorities over the bundle's checkpoint.",
              "record", enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[both])), True, ledger_id=f.id,
              tsa_roots=[one, two], min_timestamps=2, facts={
                  "timestamps": {"trusted_authorities": 2, "existed_by": iso(min(t_one, t_two) + ACCURACY),
                                 "tokens": [{"checkpoint_size": n, "trusted": True},
                                            {"checkpoint_size": n, "trusted": True}]}})
    suite.add("record-timestamp-one-trusted",
              "Tokens of two authorities, one trusted: the other is counted and relied on for nothing.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[both])), True, ledger_id=f.id,
              tsa_roots=[two], facts={
                  "timestamps": {"trusted_authorities": 1, "existed_by": iso(t_two + ACCURACY),
                                 "tokens": [{"checkpoint_size": n, "trusted": False},
                                            {"checkpoint_size": n, "trusted": True}]}})
    suite.add("too-few-trusted-timestamps", "Two trusted authorities required; one trusted authority stamped it.",
              "record", enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[both])), False, rule="11 step 8",
              ledger_id=f.id, tsa_roots=[one], min_timestamps=2)
    other, _ = one.stamp(early_payload, f.hash_id)
    suite.add("token-over-another-checkpoint",
              "An anchor holds the bundle's checkpoint with a token whose imprint is another checkpoint's payload.",
              "record", enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[anchor(cp, [other])])), False,
              rule="11 step 8", ledger_id=f.id, tsa_roots=[one])
    bad_proof = f.consistency(early, n)
    bad_proof[0] = bytes(32)
    suite.add("anchor-not-consistent",
              "An anchor's earlier checkpoint with a consistency proof that does not lead to the bundle's "
              "checkpoint.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[anchor(early_cp, [token_early], bad_proof)])),
              False, rule="11 step 8", ledger_id=f.id, tsa_roots=[one])
    uncertified, _ = one.stamp(payload, f.hash_id, certificate=False)
    suite.add("token-without-certificate",
              "A token over the bundle's checkpoint that does not carry its authority's signing certificate.",
              "record", enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[anchor(cp, [uncertified])])), False,
              rule="11 step 8", ledger_id=f.id, tsa_roots=[one])
    sm3_token, _ = one.stamp(payload, SM3)
    suite.add("token-imprint-other-hash",
              "A SHA-256 ledger's checkpoint stamped with an SM3 imprint of its payload.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[anchor(cp, [sm3_token])])), False,
              rule="10.1, 11 step 8", ledger_id=f.id, tsa_roots=[one])

    # The clock rule (section 10.1): dated within the allowance, and beyond it.
    now = int(time.time() * 1000)
    f = Forge("Fast Clock Org", t0=now + 30 * SECOND - 4 * MINUTE)
    r = f.record(f.org)
    f.commit()
    cp, payload, root = f.checkpoint(at=now + 30 * SECOND)
    token, t = one.stamp(payload, f.hash_id)
    assert t + ACCURACY < now + 30 * SECOND <= t + ACCURACY + 60 * SECOND, "the stamp took too long"
    suite.add("timestamp-within-clock-allowance",
              "The checkpoint is dated about 30 seconds after a trusted authority's time: within the 60 seconds the "
              "clock rule allows.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[anchor(cp, [token])])), True, ledger_id=f.id,
              tsa_roots=[one], facts={"timestamps": {"trusted_authorities": 1}})
    f = Forge("Clock Ahead Org", t0=now + DAY)
    r = f.record(f.org)
    f.commit()
    cp, payload, root = f.checkpoint()
    token, t = one.stamp(payload, f.hash_id)
    ahead = enc(f.bundle(r, checkpoint=(cp, payload, root), anchors=[anchor(cp, [token])]))
    suite.add("clock-rule", "The ledger dates its entries and checkpoint a day after a trusted authority saw the "
              "checkpoint.", "record", ahead, False, rule="10.1 (the clock rule), 11 step 8", ledger_id=f.id,
              tsa_roots=[one])
    suite.add("clock-ahead-authority-not-trusted",
              "The same bundle, its authority not trusted: the clock rule applies only to trusted tokens.", "record",
              ahead, True, ledger_id=f.id, facts={"timestamps": {"trusted_authorities": 0,
                                                                 "tokens": [{"trusted": False}]}})

    # --- SM3 with SM2 keys; ML-DSA keys ---------------------------------------------------------
    f = Forge("SM3 Registry", hash_id=SM3, root=Key("sm3 root", SM2), log=Key("sm3 log", SM2))
    officer = f.actor(PERSON, "Officer", Key("sm3 officer", SM2))
    do = f.grant(officer, {1: [16, 17]})
    ukey = Key("sm3 ukey", SM2)
    f.set_presence(officer, [hardware_credential(ukey, b"sm2-ukey", "SM2 UKey")])
    r = f.record(officer, "example.org.permit/1", delegation=do, fields={"holder": "Example Shop", "number": 42})
    e = f.about(17, r, {2: "officer"}, officer, do, presence=hardware_proof(ukey, b"sm2-ukey"))
    f.commit()
    n = len(f.entries)
    cp, payload, root = f.checkpoint()
    witness = Key("sm3 witness", ESP256)
    token, t = one.stamp(payload, f.hash_id)
    suite.add("record-sm3-sm2",
              "An SM3 ledger with SM2 root, log, and signing keys, an SM2 hardware key's presence, an ESP256 "
              "witness, and a token over the SM3 hash of the checkpoint.", "record",
              enc(f.bundle(r, checkpoint=(cp, payload, root), cosignatures=[f.cosign(witness, payload)],
                           anchors=[anchor(cp, [token])], disclose=["number"])), True,
              ledger_id=f.id, witnesses=[witness], min_witnesses=1, tsa_roots=[one], min_timestamps=1, facts={
                  "ledger": f.ledger_fact(), "checkpoint": {"tree_hash": "SM3", "tree_size": n},
                  "keys": {"log_key": key_fact(f.log_key_for(n))},
                  "witnesses": {"trusted": 1}, "timestamps": {"trusted_authorities": 1},
                  "disclosed_fields": {"number": 42},
                  "events": [f.event_fact(f.index[r]), f.event_fact(f.index[e])], "complete": True})

    f = Forge("Post-Quantum Org")
    person = f.actor(PERSON, "Archivist", Key("pq archivist", MLDSA44))
    dp = f.grant(person, {1: [16]})
    device = f.actor(DEVICE, "Sensor", Key("pq sensor", ESP256))
    dd = f.grant(device, {1: [17]})
    f.rotate_log_key(Key("pq log 2", MLDSA65))
    r = f.record(person, delegation=dp)
    e = f.about(17, r, {2: "sensor"}, device, dd)
    f.commit()
    n = len(f.entries)
    suite.add("record-ml-dsa",
              "An ML-DSA-44 person and an ESP256 device; the log key rotated to ML-DSA-65, which signs the "
              "checkpoint, the receipts, and the state commitment.", "record", enc(f.bundle(r)), True,
              ledger_id=f.id, facts={
                  "keys": {"log_key": key_fact(f.log_key_for(n)),
                           "log_key_rotations": 1, "root_key_rotations": 0},
                  "events": [f.event_fact(f.index[r]), f.event_fact(f.index[e])], "complete": True})

    # --- A mechanism type's lifecycle -------------------------------------------------------------
    f = Forge("Consenting Org")
    terms = {"ledger": hashlib.sha256(b"a home ledger").digest(), "instance": hashlib.sha256(b"an instance").digest(),
             "function": "update", "arguments": f.h(g.dcbor(None)), "head": 3, "until": T0 + 30 * DAY}
    c = f.record(f.org, CONSENT, metadata=terms)
    x = f.about(18, c, {2: "given", 3: "withdrawn"}, f.org)
    f.commit()
    suite.add("record-consent-withdrawn", "A contract consent, given and then withdrawn by its organization.",
              "record", enc(f.bundle(c)), True, ledger_id=f.id, facts={
                  "record": {"id": c.hex(), "type": CONSENT, "state": "withdrawn", "revoked": False},
                  "events": [f.event_fact(f.index[c]), f.event_fact(f.index[x])], "complete": True})

    # --- Failures: receipts, entries, keys ------------------------------------------------------
    f = lab_forge
    s_record = s["record"]
    n = len(f.entries)
    b = copy.deepcopy(lab_bundle)
    tag = decode(b[2][2][1])
    size, index, path = decode(tag.value[1][396][-1][0])
    path = [bytes(a ^ 0xFF for a in path[0]), *path[1:]]
    protected, _, payload, signature = tag.value
    unprotected = {396: {-1: [g.dcbor([size, index, path])]}}
    b[2][2][1] = g.dcbor(cbor2.CBORTag(18, [protected, unprotected, payload, signature]))
    suite.add("receipt-bad-path", "A receipt whose inclusion path has one hash changed (its signature still holds).",
              "record", enc(b), False, rule="11 step 2", ledger_id=f.id)
    b = f.bundle(s_record)
    smaller = n - 1
    b[2][1][1] = f.receipt(1, smaller, f.merkle().mth(f.entries[:smaller]), f.log_key_for(n))
    suite.add("receipt-other-tree-size", "One receipt proves inclusion in the tree of another size.", "record",
              enc(b), False, rule="11 step 2", ledger_id=f.id)
    b = f.bundle(s_record)
    b[2][1], b[2][2] = b[2][2], b[2][1]
    suite.add("entries-not-ascending", "Two entries of the bundle swapped, so their indices do not ascend.",
              "record", enc(b), False, rule="11 step 2", ledger_id=f.id)
    suite.add("receipts-by-another-key", "Every receipt is signed by the person's key, not the log key.",
              "record", enc(f.bundle(s_record, receipt_key=f.actors[s["person"]]["key"])), False,
              rule="11 step 4", ledger_id=f.id)
    b = copy.deepcopy(lab_bundle)
    receipt = decode(b[2][0][1])
    protected, unprotected, payload, signature = receipt.value
    flipped = bytes([signature[0] ^ 0x01]) + signature[1:]
    b[2][0][1] = g.dcbor(cbor2.CBORTag(18, [protected, unprotected, payload, flipped]))
    suite.add("receipt-bad-signature", "The genesis entry's receipt signature does not verify.", "record", enc(b),
              False, rule="11 step 4", ledger_id=f.id)

    f, r = rotation["f"], rotation["record"]
    n = len(f.entries)
    old = f.log_keys[0][1]
    suite.add("receipts-under-old-log-key",
              "After a log key rotation, the receipts are signed by the old log key, the checkpoint by the new.",
              "record", enc(f.bundle(r, receipt_key=old)), False, rule="11 step 4", ledger_id=f.id)
    suite.add("checkpoint-under-old-log-key",
              "After a log key rotation, the checkpoint is signed by the old log key, the receipts by the new.",
              "record", enc(f.bundle(r, checkpoint=f.checkpoint(key=old))), False, rule="11 step 4", ledger_id=f.id)
    suite.add("log-key-rotation-left-out",
              "The bundle leaves out the log key rotation; checkpoint and receipts are under the new key.", "record",
              enc(f.bundle(r, drop=[rotation["log_rotation"]])), False, rule="11 step 4", ledger_id=f.id)
    suite.add("root-key-rotation-left-out",
              "The bundle leaves out the root key rotation; the organization later signs with its new root key.",
              "record", enc(f.bundle(r, drop=[rotation["root_rotation"]])), False, rule="11 step 3", ledger_id=f.id)
    stale = rotation_org(old_key_commits=True)
    suite.add("commitment-under-old-log-key",
              "After a log key rotation, the state commitment is signed by the old log key.", "record",
              enc(stale["f"].bundle(stale["record"])), False, rule="11 step 4", ledger_id=stale["f"].id)

    f = lab_forge
    suite.add("signer-registration-left-out",
              "The bundle leaves out the registration of the device that endorsed the record.", "record",
              enc(f.bundle(s_record, drop=[f.index[s["device"]]])), False, rule="11 step 3", ledger_id=f.id)
    suite.add("endorsement-left-out", "The bundle leaves out an endorsement of the record.", "record",
              enc(f.bundle(s_record, drop=[f.index[s["endorse"]]])), False, rule="11 step 7", ledger_id=f.id)
    b = f.bundle(s_record)
    b[7] = [p for p in b[7] if p[0][1] != s["d_device"]]
    suite.add("state-proof-left-out", "The bundle holds no state proof for the device's delegation.", "record",
              enc(b), False, rule="11 step 7", ledger_id=f.id)

    f, r, person = revoked_later["f"], revoked_later["record"], revoked_later["person"]
    revocation = f.leaves[person][2][-1]
    suite.add("signer-revocation-left-out",
              "The bundle leaves out the revocation of the person who registered the record.", "record",
              enc(f.bundle(r, drop=[revocation])), False, rule="11 step 7", ledger_id=f.id)
    f, r = revoked_record["f"], revoked_record["record"]
    suite.add("record-revocation-left-out", "The bundle leaves out the record's revocation.", "record",
              enc(f.bundle(r, drop=[f.leaves[r][2][-1]])), False, rule="11 step 7", ledger_id=f.id)

    # --- Failures: disclosures and attachments --------------------------------------------------
    f = lab_forge
    b = f.bundle(s_record, disclose=["result"])
    name, salt, _ = decode(b[5][0][0])
    b[5][0][0] = g.dcbor([name, salt, "fail"])
    suite.add("disclosure-does-not-match", "A disclosed field's value changed: it does not match the field root.",
              "record", enc(b), False, rule="6, 11 step 5", ledger_id=f.id)
    b = f.bundle(s_record, disclose=["result"])
    b[5] = [b[5][0], b[5][0]]
    suite.add("disclosure-twice", "One field disclosed twice.", "record", enc(b), False, rule="6, 11 step 5",
              ledger_id=f.id)
    content = dict((n, c) for n, _, c in s["files"])
    suite.add("attachment-does-not-match",
              "An attachment opened, its content provided beside the bundle, is not the content committed to.",
              "record", enc(f.bundle(s_record, open_=["report.pdf"])), False, rule="11 step 5", ledger_id=f.id,
              attachments={"report.pdf": content["photo.jpg"]})

    # --- Failures: identity and encoding --------------------------------------------------------
    suite.add("wrong-ledger-id", "A verifier that expects another ledger.", "record", enc(f.bundle(s_record)), False,
              rule="11 step 1", ledger_id=presence["f"].id)
    good = enc(f.bundle(s_record))
    assert good[:3] == b"\xa5\x00\x01", good[:3].hex()
    suite.add("cbor-not-shortest", "The bundle encodes its format version 1 in two bytes instead of one.", "record",
              good[:2] + b"\x18\x01" + good[3:], False, rule="2", ledger_id=f.id)

    def unsorted(p):
        """The payload, deterministic but for its record metadata's keys, in
        descending order."""
        def encode_map(items):
            return g._head(5, len(items)) + b"".join(k + v for k, v in items)
        meta = sorted(((g.dcbor(k), g.dcbor(v)) for k, v in p[7][5].items()), reverse=True)
        body = sorted((g.dcbor(k), encode_map(meta) if k == 5 else g.dcbor(v)) for k, v in p[7].items())
        return encode_map(sorted((g.dcbor(k), encode_map(body) if k == 7 else g.dcbor(v)) for k, v in p.items()))
    f = Forge("Unsorted Org")
    r = f.record(f.org, metadata={"a": 1, "b": 2}, encode=unsorted)
    f.commit()
    suite.add("cbor-unsorted-map",
              "A statement whose metadata map keys are not in bytewise order, signed as such.", "record",
              enc(f.bundle(r)), False, rule="2", ledger_id=f.id)

    # --- Failures: the ledger rules in replay ---------------------------------------------------
    def replay_case(name, description, build, rule="5, 11 step 3"):
        f = Forge("Rules Org " + name)
        r = build(f)
        f.commit()
        suite.add(name, description, "record", enc(f.bundle(r)), False, rule=rule, ledger_id=f.id)

    def scope(f):
        p = f.actor(PERSON, "Typist", Key("rules typist"))
        d = f.grant(p, {1: [16], 2: ["example.org.form/1"]})
        return f.record(p, "example.org.form/2", delegation=d)
    replay_case("scope-does-not-cover-type", "A person registers a record of a type their delegation does not list.",
                scope)

    def expired(f):
        p = f.actor(PERSON, "Temp", Key("rules temp"))
        d = f.grant(p, {1: [16], 4: f.time + MINUTE // 2})
        return f.record(p, delegation=d)
    replay_case("delegation-expired", "A person registers a record after their delegation's not-after time.",
                expired)

    def revoked_signer(f):
        p = f.actor(PERSON, "Leaver", Key("rules leaver"))
        d = f.grant(p, {1: [16]})
        f.revoke_actor(p)
        return f.record(p, delegation=d)
    replay_case("revoked-signer", "A person registers a record after the organization revoked them.", revoked_signer)

    def revoked_delegation(f):
        p = f.actor(PERSON, "Contractor", Key("rules contractor"))
        d = f.grant(p, {1: [16]})
        f.revoke_delegation(d)
        return f.record(p, delegation=d)
    replay_case("revoked-delegation", "A person registers a record under a delegation revoked before.",
                revoked_delegation)

    def no_presence(f):
        p = f.actor(PERSON, "Approver", Key("rules approver"))
        d = f.grant(p, {1: [16], 6: True})
        return f.record(p, delegation=d)
    replay_case("presence-required-missing", "A delegation requires presence; the statement carries no proof.",
                no_presence)

    def bad_presence(f):
        p = f.actor(PERSON, "Approver", Key("rules approver"))
        d = f.grant(p, {1: [16], 6: True})
        ukey = Key("rules ukey")
        f.set_presence(p, [hardware_credential(ukey, b"ukey", "UKey")])
        return f.record(p, delegation=d, presence=hardware_proof(ukey, b"ukey", wrong=True))
    replay_case("presence-proof-does-not-verify",
                "A delegation requires presence; the hardware key signed another challenge.", bad_presence,
                rule="5, 7, 11 step 3")

    def self_rotation(f):
        p = f.actor(PERSON, "Holder", Key("rules holder"))
        d = f.grant(p, {1: [16]})
        passkey = Key("rules holder passkey", ESP256)
        f.set_presence(p, [passkey_credential(passkey, b"holder-passkey", "Phone")])
        f.rotate_key(p, Key("rules holder 2"), presence=passkey_proof(passkey, b"holder-passkey", flags=0x01))
        return f.record(p, delegation=d)
    replay_case("self-rotation-not-user-verified",
                "A person with a passkey rotates their own key with a passkey proof that is user present, not user "
                "verified.", self_rotation, rule="5 authority, 7, 11 step 3")

    def issued_late(f):
        return f.record(f.org, issued_at=f.time + 5 * MINUTE + 1)
    replay_case("issued-too-late", "A statement issued 5 minutes and 1 ms after its registration time.", issued_late)

    def no_model(f):
        p = f.actor(PERSON, "Owner", Key("rules owner"))
        d = f.grant(p, {1: [2, 5, 16], 5: True})
        a = f.actor(AGENT, "Bot", Key("rules bot"), by=p, delegation=d, responsible=p, model=MODEL)
        da = f.grant(a, {1: [16]}, by=p, under=d)
        return f.record(a, delegation=da)
    replay_case("agent-without-model", "An AI agent's statement whose provenance names no model (it has none).",
                no_model)

    def unknown_signer(f):
        stranger = Key("rules stranger")
        return f.add(16, stranger, f.org, {1: "example.org.note/1", 2: f.merkle().mth([g.dcbor(["a", bytes(16), 1])]),
                                           3: 1}, creates=3)
    replay_case("not-signed-by-the-signer", "A statement in the organization's name signed by a key that is not its "
                "root key.", unknown_signer)


def claim_cases(suite: Suite) -> None:
    """Claims (v0.14, sections 6 and 11): a claim's bundle carries its source
    as an involved object, whose statements count as events, so that its
    report says whether the source is live, revoked, or replaced since."""
    f = Forge("Claims Employer")
    hr = f.actor(PERSON, "HR Officer", Key("claims hr"))
    d_hr = f.grant(hr, {1: [16, 19], 2: sorted([CLAIM, EMPLOYMENT], key=str.encode)})  # strictly ascending (UTF-8 bytes)
    payroll = f.actor(DEVICE, "Payroll System", Key("claims payroll"))
    d_pay = f.grant(payroll, {1: [16, 19], 2: [EMPLOYMENT]})
    s1 = f.record(payroll, EMPLOYMENT, delegation=d_pay, fields={
        "name": "Chan Tai Man", "monthly_salary": [3500000, "HKD", 2], "status": "staff"})
    s2 = f.record(payroll, EMPLOYMENT, delegation=d_pay, fields={
        "name": "Lee Siu Ming", "monthly_salary": [2800000, "HKD", 2], "status": "contractor"})
    s3 = f.record(payroll, EMPLOYMENT, delegation=d_pay, fields={
        "name": "Wong Mei Ling", "monthly_salary": [4200000, "HKD", 2], "status": "staff"})
    request = [hashlib.sha256(b"a requester's ledger").digest(), hashlib.sha256(b"its access request").digest()]

    def claim(by, delegation, source, condition, **extra):
        """A claim on `source`, evaluated half a minute before its
        registration."""
        meta = {"source": source, "condition": condition, "holds": True, "as_of": f.time - 30 * SECOND, **extra}
        return f.record(by, CLAIM, delegation=delegation, fields={"basis": "the payroll of 2026-10"},
                        metadata=meta), meta

    c1, m1 = claim(hr, d_hr, s1, g.SPEC_CLAIM_EXAMPLE, until=f.time + 30 * DAY, subject="Chan Tai Man")
    c2, m2 = claim(hr, d_hr, s2, [["status", "=", "text", "contractor"]], subject="Lee Siu Ming",
                   **{"for": request})
    c3, m3 = claim(f.org, None, s3, [["monthly_salary", ">=", "money", [4000000, "HKD", 2]],
                                     ["start_date", "exists", "text", None]], until=f.time + 30 * SECOND)
    c4, m4 = claim(hr, d_hr, s3, [["monthly_salary", "between", "money", [[3000000, "HKD", 2],
                                                                          [4000000, "HKD", 2]]]], holds=False)
    first = f.commit() + 1
    revocation = f.about(19, s1, {2: "corrected"}, payroll, d_pay)
    s2b = f.record(payroll, EMPLOYMENT, delegation=d_pay, supersedes=s2, fields={
        "name": "Lee Siu Ming", "monthly_salary": [3100000, "HKD", 2], "status": "staff"})
    withdrawal = f.about(19, c4, {2: "issued in error"}, hr, d_hr)
    payroll_revoked = f.revoke_actor(payroll)
    f.commit()

    def claim_fact(meta: dict, status: str, lapsed: bool = False) -> dict:
        return {"source": meta["source"].hex(), "source_type": EMPLOYMENT, "source_status": status,
                "condition": meta["condition"], "text": g.claim_words(meta["condition"]), "holds": meta["holds"],
                "as_of": iso(meta["as_of"]), "until": iso(meta["until"]) if "until" in meta else None,
                "lapsed": lapsed, "subject": meta.get("subject"),
                "for": [x.hex() for x in meta["for"]] if "for" in meta else None}

    def record_fact(c: bytes, claim: dict, revoked: bool = False) -> dict:
        return {"id": c.hex(), "type": CLAIM, "state": "confirmed", "revoked": revoked, "supersedes": None,
                "superseded_by": None, "claim": claim}

    assert g.claim_words(m1["condition"]) == g.SPEC_CLAIM_WORDS
    suite.add("claim-source-live",
              "A person's claim, in the specification's words, on a device's record of a generic type, which is "
              "live: the bundle carries the source's statements and a state proof for it and for everyone they "
              "involve.", "record", enc(f.bundle(c1, size=first)), True, ledger_id=f.id, facts={
                  "record": record_fact(c1, claim_fact(m1, "live")),
                  "events": [f.event_fact(f.index[c1])], "complete": True})
    suite.add("claim-lapsed",
              "The organization's claim whose until is before the checkpoint's time: it verifies, and the report "
              "says it has lapsed.", "record", enc(f.bundle(c3, size=first)), True, ledger_id=f.id, facts={
                  "record": record_fact(c3, claim_fact(m3, "live", lapsed=True)),
                  "events": [f.event_fact(f.index[c3])], "complete": True})
    suite.add("claim-source-revoked",
              "The same claim after its source was revoked: it verifies, and the report says the source is "
              "revoked.", "record", enc(f.bundle(c1)), True, ledger_id=f.id, facts={
                  "record": record_fact(c1, claim_fact(m1, "revoked")),
                  "events": [f.event_fact(f.index[c1])], "complete": True})
    suite.add("claim-source-replaced",
              "A claim, answering an access request, whose source a newer version superseded since: the bundle "
              "carries the superseding registration, and the report says the source is replaced.", "record",
              enc(f.bundle(c2)), True, ledger_id=f.id, facts={
                  "record": record_fact(c2, claim_fact(m2, "replaced")),
                  "events": [f.event_fact(f.index[c2])], "complete": True})
    suite.add("claim-withdrawn",
              "A claim that does not hold, withdrawn by its issuer by revoking it; its source is live.", "record",
              enc(f.bundle(c4)), True, ledger_id=f.id, facts={
                  "record": record_fact(c4, claim_fact(m4, "live"), revoked=True),
                  "events": [f.event_fact(f.index[c4]), f.event_fact(f.index[withdrawal])], "complete": True})
    suite.add("claim-source-own-bundle",
              "The source's own bundle: a claim's registration is a statement about the claim only, so the "
              "source's history does not list it and its report shows no claim.", "record", enc(f.bundle(s1)),
              True, ledger_id=f.id, facts={
                  "record": {"id": s1.hex(), "type": EMPLOYMENT, "revoked": True, "claim": None},
                  "events": [f.event_fact(f.index[s1]), f.event_fact(f.index[revocation])], "complete": True})
    suite.add("claim-source-proof-left-out", "A claim's bundle holds no state proof for its source.", "record",
              enc(f.bundle(c1, drop_proofs=[s1])), False, rule="11 step 7 (a claim's source is involved)",
              ledger_id=f.id)
    suite.add("claim-source-revocation-left-out",
              "A claim's bundle leaves out its source's revocation, so the source looks live.", "record",
              enc(f.bundle(c1, drop=[f.index[revocation]])), False, rule="11 step 7 (a claim's source is involved)",
              ledger_id=f.id)
    suite.add("claim-source-signer-revocation-left-out",
              "A claim's bundle leaves out the revocation of the device that registered its source and the "
              "source's new version.", "record", enc(f.bundle(c2, drop=[f.index[payroll_revoked]])), False,
              rule="11 step 7 (the source's statements count as events)", ledger_id=f.id)
    suite.add("claim-source-left-out",
              "A claim's bundle leaves out its source's registration.", "record",
              enc(f.bundle(c1, size=first, drop=[f.index[s1]])), False,
              rule="6 claims, 11 steps 3 and 7", ledger_id=f.id)
    assert f.index[s2b] in f.leaves[s2][2], "the new version's registration is in the source's history"


def contract_cases(suite: Suite) -> None:
    code = g.oracle_contract(w)

    class Home:
        """A contract home: a registrar (a device) and a clerk (a person),
        the oracle contract deployed, and two party ledgers: a supplier
        (SHA-256, whose approver proves presence with a hardware key) and a
        bank (SM3, SM2 keys, consenting as the organization)."""

        def __init__(self, name: str, t0: int = T0):
            self.f = f = Forge(name, t0=t0)
            self.k = f.deploy(code, INTERFACE)
            self.registrar = f.actor(DEVICE, "Registrar", Key(f"{name} registrar"))
            self.d_registrar = f.grant(self.registrar, {1: [22], 7: [self.k]})
            self.clerk = f.actor(PERSON, "Clerk", Key(f"{name} clerk"))
            self.d_clerk = f.grant(self.clerk, {1: [5, 22], 5: True, 7: [self.k]})
            self.supplier = Forge("Supplier", t0=t0 - DAY)
            s = self.supplier
            self.approver = s.actor(PERSON, "Approver", Key("supplier approver"))
            self.d_approver = s.grant(self.approver, {1: [16, 18], 2: [CONSENT]})
            self.ukey = Key("supplier ukey")
            s.set_presence(self.approver, [hardware_credential(self.ukey, b"supplier-ukey", "UKey")])
            self.bank = Forge("Bank", hash_id=SM3, root=Key("bank root", SM2), log=Key("bank log", SM2),
                              t0=t0 - DAY)

        def consent(self, party: Forge, instance: bytes, function: str, accept, head: int, *, by=None,
                    until=None, presence=True, terms=None, withdraw=False, complete=True, cite=None):
            """A consent on the party's ledger: its citation and its bundle."""
            f = self.f
            by = by or party.org
            metadata = {"ledger": f.id, "instance": instance, "function": function,
                        "arguments": f.h(g.dcbor(g.dcbor([1, accept]))), "head": head,
                        "until": f.time + 7 * DAY if until is None else until}
            metadata.update(terms or {})
            proof = None
            delegation = None
            if by != party.org:
                delegation = self.d_approver
                if presence:
                    proof = hardware_proof(self.ukey, b"supplier-ukey")
            party.time = max(party.time, f.time - HOUR)
            record = party.record(by, CONSENT, delegation=delegation, metadata=metadata, presence=proof)
            if withdraw:
                party.about(18, record, {2: "given", 3: "withdrawn"}, by, delegation)
            if complete:
                party.commit()
            bundle = enc(party.bundle(record))
            signer = cite if cite is not None else party.signer_map(by, proof, None)
            return [party.id, record, f.h(bundle), signer], bundle

        def evidence(self, subject: bytes, bundles=(), **kw) -> bytes:
            b = enc(self.f.bundle(subject, **kw))
            out = {0: 1, 1: b}
            if bundles:
                out[2] = list(bundles)
            return enc(out)

    def call_fact(f: Forge, sid: bytes, **extra) -> dict:
        i = f.index[sid]
        body = f.info[i]["payload"][7]
        out = {"index": i, "function": body[3], "creates": 1 in body,
               "called_by": f.actor_fact(f.info[i]["signer"]), "authority": f.authority_fact(i)}
        out.update(extra)
        return out

    def parties_fact(parties: dict) -> dict:
        return {role: {"ledger_id": ledger.hex()} for role, ledger in parties.items()}

    # --- An instance with consents from two other ledgers -----------------------------
    h = Home("Contract Home")
    f = h.f
    parties = {"bank": h.bank.id, "home": f.id, "supplier": h.supplier.id}
    proposed = {1: {"amount": 1_000_000, "currency": "HKD"}, 2: "proposed", 3: parties}
    a, _, _ = f.create(h.k, "propose", proposed, by=h.registrar, delegation=h.d_registrar)
    effective = {1: {"amount": 1_000_000, "currency": "HKD", "signed": True}, 2: "effective",
                 4: [["signed", {"by": ["bank", "supplier"]}]]}
    head = f.instances[a]["head"]
    c1, b1 = h.consent(h.supplier, a, "update", effective, head, by=h.approver)
    c2, b2 = h.consent(h.bank, a, "update", effective, head)
    sign, _, _ = f.call(a, "update", effective, by=h.registrar, delegation=h.d_registrar, consents=[c1, c2],
                        reference="PO-2026-1020")
    close = {1: "settled", 2: "settled", 5: True}
    done, _, _ = f.call(a, "update", close, by=h.clerk, delegation=h.d_clerk)
    f.commit()
    order = sorted([(c1, "supplier"), (c2, "bank")], key=lambda x: x[0][0])
    suite.add("contract-consents",
              "An instance created by a registrar, made effective with the consents of a person present on a "
              "SHA-256 party ledger and of an SM3 party's organization, then closed by a clerk.", "contract",
              h.evidence(a, [b1, b2]), True, ledger_id=f.id, facts={
                  "instance": {"id": a.hex(), "status": "settled", "final": True, "head": f.index[done],
                               "parties": parties_fact(parties), "state_cbor": g.dcbor("settled").hex(),
                               "contract": {"id": h.k.hex(), "retired": False}, "requests": [],
                               "open_requests": [], "overdue_requests": []},
                  "home": f.ledger_fact(),
                  "calls": [
                      call_fact(f, a, outcome={"status": "proposed", "final": False}, consents=[]),
                      call_fact(f, sign, reference="PO-2026-1020", outcome={"status": "effective", "final": False},
                                consents=[{"ledger_id": c[0].hex(), "record": c[1].hex()} for c, _ in order]),
                      call_fact(f, done, outcome={"status": "settled", "final": True}, consents=[])],
                  "complete": True})
    suite.add("contract-wrong-home", "The same evidence, verified for another home ledger.", "contract",
              h.evidence(a, [b1, b2]), False, rule="15 contract evidence step 1, 11 step 1",
              ledger_id=h.supplier.id)
    suite.add("contract-require-presence-unmet",
              "The same evidence with presence required for every consent: the bank's organization consented "
              "without it.", "contract", h.evidence(a, [b1, b2]), False,
              rule="15 consents (presence MAY be required), 17", ledger_id=f.id, require_presence=True)
    suite.add("contract-consent-bundle-missing",
              "The evidence leaves out the bank's consent bundle, which the call cites.", "contract",
              h.evidence(a, [b1]), False, rule="15 contract evidence step 4", ledger_id=f.id)
    _, extra = h.consent(h.supplier, a, "update", effective, head, by=h.supplier.org)
    suite.add("contract-consent-unpinned",
              "The evidence holds a consent bundle that no call cites.", "contract", h.evidence(a, [b1, b2, extra]),
              False, rule="15 contract evidence step 4", ledger_id=f.id)
    suite.add("contract-not-complete",
              "The instance's bundle leaves out the state commitment its checkpoint ends with.", "contract",
              h.evidence(a, [b1, b2], drop=[len(f.entries) - 1], proofs=False), False,
              rule="15 contract evidence step 1", ledger_id=f.id)

    # --- Consents that do not hold ----------------------------------------------------------------
    def consent_case(name, description, variant):
        h = Home("Consent Home " + name)
        f = h.f
        a, _, _ = f.create(h.k, "propose", {1: 0, 2: "proposed"}, by=h.registrar, delegation=h.d_registrar)
        accept = {1: 1, 2: "agreed"}
        head = f.instances[a]["head"]
        kw = variant(h, f)
        ref, bundle = h.consent(h.supplier, a, "update", accept, head, by=h.approver, **kw)
        f.call(a, "update", accept, by=h.registrar, delegation=h.d_registrar, consents=[ref])
        f.commit()
        suite.add(name, description, "contract", h.evidence(a, [bundle]), False, rule="15 contract evidence step 3",
                  ledger_id=f.id)
    consent_case("contract-consent-terms-differ",
                 "The consent names another function than the call's.", lambda h, f: {"terms": {"function": "close"}})
    consent_case("contract-consent-other-arguments",
                 "The consent names other arguments than the call's.",
                 lambda h, f: {"terms": {"arguments": f.h(g.dcbor(b"other"))}})
    consent_case("contract-consent-lapsed", "The consent lapsed a minute before the call was registered.",
                 lambda h, f: {"until": f.time - MINUTE})
    consent_case("contract-consent-signer-claim",
                 "The call claims the consent was signed by the organization; a person signed it, present.",
                 lambda h, f: {"cite": {1: 0}})
    consent_case("contract-consent-not-complete",
                 "The consent's bundle does not end with a state commitment.", lambda h, f: {"complete": False})
    consent_case("contract-consent-withdrawn", "The consent was withdrawn before its bundle's checkpoint.",
                 lambda h, f: {"withdraw": True})

    # --- Presence required and met; a retired contract -------------------------------------------
    h = Home("Presence Home")
    f = h.f
    a, _, _ = f.create(h.k, "propose", {1: 0, 2: "proposed"}, by=h.clerk, delegation=h.d_clerk)
    accept = {1: 1, 2: "agreed"}
    ref, bundle = h.consent(h.supplier, a, "update", accept, f.instances[a]["head"], by=h.approver)
    agreed, _, _ = f.call(a, "update", accept, by=h.clerk, delegation=h.d_clerk, consents=[ref])
    f.retire(h.k)
    later, _, _ = f.call(a, "update", {1: 2, 2: "carried on"}, by=h.clerk, delegation=h.d_clerk)
    f.commit()
    suite.add("contract-presence-and-retired",
              "A consent given by a person present with a hardware key, presence required; the contract is retired "
              "and the instance carries on.", "contract", h.evidence(a, [bundle]), True, ledger_id=f.id,
              require_presence=True, facts={
                  "instance": {"id": a.hex(), "status": "carried on", "final": False, "head": f.index[later],
                               "contract": {"id": h.k.hex(), "retired": True}},
                  "calls": [call_fact(f, a), call_fact(f, agreed, consents=[{"ledger_id": h.supplier.id.hex(),
                                                                            "record": ref[1].hex()}]),
                            call_fact(f, later)],
                  "complete": True})

    # --- A part (a child instance) ------------------------------------------------------------------
    h = Home("Split Home")
    f = h.f
    whole, _, _ = f.create(h.k, "propose", {1: 1000, 2: "issued", 3: {"holder": h.supplier.id}}, by=h.registrar,
                           delegation=h.d_registrar)
    split = {1: 0, 2: "split", 5: True, 6: [{1: 600, 2: "issued", 3: {"holder": h.bank.id}},
                                            {1: 400, 2: "issued", 3: {"holder": h.supplier.id}}]}
    ref, bundle = h.consent(h.supplier, whole, "update", split, f.instances[whole]["head"], by=h.approver)
    split_call, (part, _), _ = f.call(whole, "update", split, by=h.registrar, delegation=h.d_registrar,
                                      consents=[ref])
    moved, _, _ = f.call(part, "update", {1: 600, 2: "transferred", 3: {"holder": f.id}}, by=h.clerk,
                         delegation=h.d_clerk)
    f.commit()
    assert part == f.h(g.dcbor([split_call, 0]))
    suite.add("contract-part",
              "A part created by a split that cites the holder's consent, then transferred: its evidence holds its "
              "parent's calls up to the split, with that consent.", "contract", h.evidence(part, [bundle]), True,
              ledger_id=f.id, facts={
                  "instance": {"id": part.hex(), "parent": whole.hex(), "depth": 1, "position": 0,
                               "created_by": f.index[split_call], "status": "transferred",
                               "head": f.index[moved], "parties": parties_fact({"holder": f.id})},
                  "calls": [call_fact(f, whole, outcome={"status": "issued"}),
                            call_fact(f, split_call, outcome={"status": "split", "final": True}),
                            call_fact(f, moved, outcome={"status": "transferred"})],
                  "complete": True})

    # A part the creation never made: the home's state lists it, the replay does not.
    h = Home("Phantom Home")
    f = h.f
    whole, _, _ = f.create(h.k, "propose", {1: 1000, 2: "issued", 6: [{1: 1000, 2: "issued"}]}, by=h.registrar,
                           delegation=h.d_registrar)
    creation = f.index[whole]
    fake = f.h(g.dcbor([whole, 1]))
    f.leaves[fake] = [5, fake, [creation]]
    f.instances[fake] = {"contract": h.k, "state": 0, "status": None, "parties": {}, "final": False,
                         "parent": whole, "depth": 1, "created_by": creation, "position": 1, "head": creation}
    f.commit()
    suite.add("contract-part-not-made",
              "Evidence for a second part of a creation whose output made one: the home's state lists it, but the "
              "replay of the code does not make it.", "contract", h.evidence(fake), False,
              rule="15 contract evidence step 2", ledger_id=f.id)

    # --- Requests and answers ---------------------------------------------------------------------
    h = Home("Service Home")
    f = h.f
    executor = f.actor(DEVICE, "Notice Executor", Key("service executor"))
    d_exec = f.grant(executor, {1: [22], 7: [h.k], 8: ["result"], 9: ["notify"]}, by=h.clerk, under=h.d_clerk)
    now = f.time
    opened = {1: "open", 2: "open", 7: [{1: "notify", 2: {"about": "welcome"}, 3: now + DAY, 4: "result"},
                                        {1: "provision", 2: {"plan": "small"}, 3: now + 10 * DAY, 4: "result"}]}
    s1, _, (r1, r2) = f.create(h.k, "propose", opened, by=h.clerk, delegation=h.d_clerk)
    answered, _, _ = f.call(s1, "result", {1: "notified", 2: "active"}, by=executor, delegation=d_exec,
                            answer=[r1, 1])
    f.commit()
    request_facts = [{"id": r1.hex(), "kind": "notify", "status": "done", "reply": "result"},
                     {"id": r2.hex(), "kind": "provision", "status": "open", "reply": "result", "overdue": False}]
    suite.add("contract-request-answered",
              "A creation makes two requests to executors; a device answers one, done, under scope keys 8 and 9; the "
              "other is open and not yet due, so --require-answered passes.", "contract", h.evidence(s1), True,
              ledger_id=f.id, require_answered=True, facts={
                  "instance": {"id": s1.hex(), "status": "active", "requests": request_facts,
                               "open_requests": [r2.hex()], "overdue_requests": []},
                  "calls": [call_fact(f, s1, outcome={"status": "open", "requests": [
                      {"position": 0, "id": r1.hex(), "kind": "notify", "reply": "result"},
                      {"position": 1, "id": r2.hex(), "kind": "provision", "reply": "result"}]}, answer=None),
                      call_fact(f, answered, answer={"request": r1.hex(), "status": "done", "late": False},
                                outcome={"status": "active"})],
                  "complete": True})

    h = Home("Overdue Home")
    f = h.f
    now = f.time
    s2, _, (r3,) = f.create(h.k, "propose", {1: "open", 2: "open", 7: [
        {1: "notify", 2: {"about": "reminder"}, 3: now + HOUR, 4: "result"}]}, by=h.clerk, delegation=h.d_clerk)
    f.commit(at=now + 3 * HOUR)
    suite.add("contract-request-overdue",
              "A request still open three hours after its one-hour deadline, at the checkpoint: reported overdue.",
              "contract", h.evidence(s2), True, ledger_id=f.id, facts={
                  "instance": {"id": s2.hex(), "open_requests": [r3.hex()], "overdue_requests": [r3.hex()],
                               "requests": [{"id": r3.hex(), "status": "open", "overdue": True}]}})
    suite.add("contract-overdue-require-answered",
              "The same evidence with --require-answered: a request is open past its deadline.", "contract",
              h.evidence(s2), False, rule="15 requests in evidence (a verifier MAY fail overdue requests)",
              ledger_id=f.id, require_answered=True)

    # --- Calls the replay refuses ---------------------------------------------------------------------
    h = Home("Rejecting Home")
    f = h.f
    i, _, _ = f.create(h.k, "propose", {1: 0, 2: "open"}, by=h.clerk, delegation=h.d_clerk)
    f.call(i, "update", None, by=h.clerk, delegation=h.d_clerk, args="the amount exceeds the credit line")
    f.commit()
    suite.add("contract-call-rejected-by-code",
              "The log holds a call whose contract, run again, aborts: the home recorded a call its code rejects.",
              "contract", h.evidence(i), False, rule="5 contracts, 15 ledger rules and contract evidence step 2",
              ledger_id=f.id)

    h = Home("Unasked Home")
    f = h.f
    i, _, _ = f.create(h.k, "propose", {1: 0, 2: "open"}, by=h.clerk, delegation=h.d_clerk)
    unmade = g.request_id(f, i, 0)
    f.call(i, "result", {1: 1, 2: "answered"}, by=h.clerk, delegation=h.d_clerk, answer=[unmade, 1], check=False)
    f.commit()
    suite.add("contract-answer-unknown-request",
              "An answer to a request the creation's output never made.", "contract", h.evidence(i), False,
              rule="15 requests and answers (the request is one of the instance's, and open)", ledger_id=f.id)

    h = Home("Final Home")
    f = h.f
    i, _, _ = f.create(h.k, "propose", {1: 0, 2: "closed", 5: True}, by=h.clerk, delegation=h.d_clerk)
    f.call(i, "update", {1: 1, 2: "reopened"}, by=h.clerk, delegation=h.d_clerk)
    f.commit()
    suite.add("contract-call-on-final", "A call on an instance that its creation made final.", "contract",
              h.evidence(i), False, rule="15 ledger rules (the instance is not final)", ledger_id=f.id)

    h = Home("Stale Home")
    f = h.f
    i, _, _ = f.create(h.k, "propose", {1: 0, 2: "open"}, by=h.clerk, delegation=h.d_clerk)
    first = f.instances[i]["head"]
    f.call(i, "update", {1: 1, 2: "first"}, by=h.clerk, delegation=h.d_clerk)
    f.call(i, "update", {1: 2, 2: "second"}, by=h.clerk, delegation=h.d_clerk, head=first)
    f.commit()
    suite.add("contract-call-stale-head", "A call that names the instance's old head.", "contract", h.evidence(i),
              False, rule="15 ledger rules (the head is its head)", ledger_id=f.id)


DESCRIPTION = (
    "A conformance suite of Kanhe evidence (spec sections 11 and 15): each case is one evidence bundle "
    "(kind \"record\", verified as `kanhe verify` does) or one instance's contract evidence (kind \"contract\", "
    "as `kanhe contract verify` does), with the options to verify it with, the verdict the specification "
    "decides, and, for a failure, the section and step that decide it. tools/testvectors/evidence_suite.py "
    "forges every ledger from spec/README.md and spec/kanhe.cddl alone, independently of the C++ programs and "
    "of the Python verifier: statements signed with throwaway keys (seed = SHA-256(\"Kanhe test key: evidence "
    "<name>\"); Ed25519, ESP256, SM2 through the openssl command line, ML-DSA), log entries, state commitments, "
    "checkpoints, receipts, cosignatures, and anchors with RFC 3161 tokens by OpenSSL's responder (`openssl ts`), "
    "whose authorities' root and certificates `cryptography` makes (P-256, valid 2020-2040). Contract calls run "
    "the v0.6 oracle contract (oracle_contract in generate.py: a byte-string argument is its output) on the "
    "reference interpreter, wasm_ref.py, which must give the output each call was forged with. Options: "
    "`ledger_id` (the expected ledger, hex), `witnesses` (trusted witness keys, each the hex of a public key "
    "file, CBOR [alg, key]), `min_witnesses`, `tsa_roots` (trusted authorities' root certificates, PEM), "
    "`min_timestamps`, `attachments` (contents by name, hex), `require_presence` and `require_answered` "
    "(contract evidence only); an option left out is not used. A verifier must reach `verified`. When verified, "
    "its JSON report (the fields of `kanhe verify --json` or `kanhe contract verify --json`) must match "
    "`facts`, which hold only what was forged: a fact object matches a report object when every key of the fact "
    "is in the report and its value matches; a fact list matches a report list of the same length, element by "
    "element; any other value matches only an equal value (true, false, null, numbers, and strings exactly). "
    "Failures have no facts. Times in facts are the report's ISO 8601 UTC with milliseconds; a token's time is "
    "its genTime and its accuracy one second. ECDSA, SM2, and ML-DSA signatures and the tokens' times differ "
    "from one run of the generator to the next; verdicts and facts do not.")


def generate(openssl: str = "openssl") -> None:
    with tempfile.TemporaryDirectory() as tmp:
        Env.openssl, Env.work = openssl, pathlib.Path(tmp)
        one, two = Authority("One"), Authority("Two")
        suite = Suite()
        record_cases(suite, one, two)
        claim_cases(suite)
        contract_cases(suite)
    document = {"format": 1, "description": DESCRIPTION, "cases": suite.cases}
    OUT.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    counts = {}
    for case in suite.cases:
        key = f"{case['kind']} {'verified' if case['verified'] else 'failed'}"
        counts[key] = counts.get(key, 0) + 1
    print(f"wrote {len(suite.cases)} evidence cases to testvectors/{OUT.name}: "
          + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3.5+ command-line tool")
    generate(parser.parse_args().openssl)


if __name__ == "__main__":
    main()
