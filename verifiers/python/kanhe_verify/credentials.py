# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Kanhe credentials (spec/credentials.md): a record handed over as a W3C
Verifiable Credential, a compact JWS (ES256) over the JCS of its JSON, and
its verification against the record's evidence bundle (section 7), with the
issuer's DID document and status list when given.

Written from spec/credentials.md and the W3C and IETF texts it names, apart
from the reference implementation.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
import zlib
from dataclasses import dataclass, field
from typing import NoReturn

from . import crypto, protocol, rules
from .errors import VerifyError
from .evidence import Report, registration_time, verify_bundle

CONTEXT = "https://www.w3.org/ns/credentials/v2"
LIST_SIZE = 131072
LIST_BYTES = LIST_SIZE // 8
MAX_INTEGER = 2**53 - 1
ROLE = re.compile(r"credential/([1-9][0-9]*)/(0|[1-9][0-9]*)")
DECIMAL = re.compile(r"0|[1-9][0-9]*")
TOKEN = re.compile(r"[A-Za-z0-9_-]{22}")
HOST = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)*")
SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")


def fail(message: str) -> NoReturn:
    raise VerifyError(message)


# ---- JCS (RFC 8785) ---------------------------------------------------------

def _string(text: str) -> str:
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\f\n\r\t":
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value) -> str:
    """The JCS serialization of a JSON value made of dicts, lists, str, int
    (at most 2^53 - 1 in magnitude), bool, and None."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_INTEGER:
            fail("a JSON integer past 2^53 - 1")
        return str(value)
    if isinstance(value, float):
        fail("a JSON number that is not an integer")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    fail("a JSON value of another kind")


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            fail("a JSON object names a member twice")
        out[key] = value
    return out


def parse_jcs(text: str):
    """JSON that must be the JCS of what it parses to."""
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_float=lambda _: fail("a fraction"),
                           parse_constant=lambda _: fail("a non-finite number"))
    except (ValueError, RecursionError) as e:
        raise VerifyError("not JSON") from e
    if jcs(value) != text:
        fail("JSON that is not in its canonical form (RFC 8785)")
    return value


# ---- base64url, keys, names -----------------------------------------------------

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        fail("not unpadded base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64(data) != text:
        fail("base64url with nonzero trailing bits")
    return data


def jwk(public: crypto.PublicKey) -> dict:
    if public.alg != crypto.ESP256:
        fail("a credential key is ECDSA P-256 (ESP256)")
    return {"kty": "EC", "crv": "P-256", "x": b64(public.key[1:33]), "y": b64(public.key[33:65])}


def jwk_key(value) -> crypto.PublicKey:
    if (not isinstance(value, dict) or value.get("kty") != "EC" or value.get("crv") != "P-256"
            or "d" in value or not isinstance(value.get("x"), str) or not isinstance(value.get("y"), str)):
        fail("a JWK that is not a public EC P-256 key")
    x, y = unb64(value["x"]), unb64(value["y"])
    if len(x) != 32 or len(y) != 32:
        fail("a JWK whose coordinates are not 32 bytes each")
    return crypto.PublicKey(crypto.ESP256, b"\x04" + x + y)


def thumbprint(public: crypto.PublicKey) -> str:
    """RFC 7638: SHA-256 of the required members, in order, no spaces."""
    k = jwk(public)
    text = '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}' % (k["crv"], k["kty"], k["x"], k["y"])
    return b64(hashlib.sha256(text.encode()).digest())


@dataclass
class Base:
    url: str
    did: str
    did_document: str


def base_url(url: str) -> Base:
    """Section 1: https (http for localhost and 127.0.0.1), a host name, an
    optional port and path; its did:web."""
    url = url.rstrip("/")
    if url.startswith("https://"):
        http, rest = False, url[8:]
    elif url.startswith("http://"):
        http, rest = True, url[7:]
    else:
        fail(f"{url} is not an https URL")
    authority, slash, path = rest.partition("/")
    host, colon, port = authority.partition(":")
    if not HOST.fullmatch(host) or len(host) > 253:
        fail(f"{url} does not name a host in lowercase letters, digits, - and .")
    local = host in ("localhost", "127.0.0.1")
    if http and not local:
        fail(f"{url}: http only for localhost and 127.0.0.1")
    if not local and re.fullmatch(r"[0-9.]+", host):
        fail(f"{url}: did:web names a host, not an IP address")
    did = "did:web:" + host
    if colon:
        if not DECIMAL.fullmatch(port) or not 1 <= int(port) <= 65535:
            fail(f"{url} has a port that is not 1 to 65535")
        did += "%3A" + port
    if slash:
        for segment in path.split("/"):
            if not SEGMENT.fullmatch(segment) or segment in (".", ".."):
                fail(f"{url} has a path segment not allowed")
            did += ":" + segment
    return Base(url, did, url + ("/did.json" if slash else "/.well-known/did.json"))


def role_entry(role: str):
    m = ROLE.fullmatch(role)
    if m is None or int(m.group(2)) >= LIST_SIZE:
        return None
    return int(m.group(1)), int(m.group(2))


def claim_value(value):
    """A field's value as a claim: text, an integer of at most 2^53 - 1 in
    magnitude, or a boolean; None for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int) and abs(value) <= MAX_INTEGER:
        return value
    return None


def claim_name_allowed(name: str) -> bool:
    return bool(name) and name not in ("id", "type") and not name.startswith("@")


def decode_list(encoded: str) -> bytes:
    if not encoded.startswith("u"):
        fail("an encodedList that is not u and base64url")
    compressed = unb64(encoded[1:])
    try:
        d = zlib.decompressobj(wbits=31)  # exactly one GZIP member
        bits = d.decompress(compressed, LIST_BYTES + 1)
        if d.unconsumed_tail or not d.eof or d.unused_data:
            fail("a status list that is not one GZIP member of 16,384 bytes")
    except zlib.error as e:
        raise VerifyError("a status list that does not decompress") from e
    if len(bits) != LIST_BYTES:
        fail("a status list that is not 131,072 bits")
    return bits


def bit(bits: bytes, index: int) -> bool:
    return bool(bits[index // 8] >> (7 - index % 8) & 1)


# ---- JWS ----------------------------------------------------------------------

@dataclass
class Jws:
    header: dict
    payload: dict
    signing_input: bytes
    signature: bytes
    kid: str


def parse_jws(compact: str) -> Jws:
    compact = compact.strip()
    parts = compact.split(".")
    if len(parts) != 3:
        fail("not a compact JWS (three parts)")
    try:
        header = parse_jcs(unb64(parts[0]).decode())
        payload = parse_jcs(unb64(parts[1]).decode())
    except UnicodeDecodeError as e:
        raise VerifyError("a JWS part that is not UTF-8") from e
    signature = unb64(parts[2])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        fail("a JWS whose header or payload is not a JSON object")
    if set(header) - {"alg", "kid", "typ", "cty"}:
        fail("a JWS header member this profile does not define")
    if (header.get("alg") != "ES256" or not isinstance(header.get("kid"), str)
            or header.get("typ", "vc+jwt") != "vc+jwt" or header.get("cty", "vc") != "vc"):
        fail("a JWS that is not ES256 with a kid, typ vc+jwt, cty vc")
    if len(signature) != 64:
        fail("an ES256 signature is 64 bytes")
    return Jws(header, payload, (parts[0] + "." + parts[1]).encode(), signature, header["kid"])


# ---- the credential (section 4) and its check (section 7) ----------------------------

@dataclass
class Credential:
    jws: Jws
    issuer: str
    issuer_name: str
    name: str | None
    valid_from: str
    subject: dict
    list: int
    index: int
    list_url: str
    evidence_url: str
    base: Base
    ledger: bytes
    record: bytes
    thumbprint: str


def parse_credential(compact: str) -> Credential:
    jws = parse_jws(compact)
    p = jws.payload
    if set(p) - {"@context", "type", "name", "issuer", "validFrom", "credentialSubject", "credentialStatus",
                 "evidence"}:
        fail("a credential member this profile does not define")
    if p.get("@context") != [CONTEXT] or p.get("type") != ["VerifiableCredential"]:
        fail("not a credential of this profile (its context or type)")
    name = p.get("name")
    if "name" in p and (not isinstance(name, str) or not 1 <= len(name.encode()) <= 256):
        fail("a credential's name is 1 to 256 bytes of text")
    issuer = p.get("issuer")
    if (not isinstance(issuer, dict) or set(issuer) != {"id", "name"} or not isinstance(issuer["id"], str)
            or not isinstance(issuer["name"], str)):
        fail("a credential's issuer is {id, name}")
    if not isinstance(p.get("validFrom"), str):
        fail("a credential without validFrom")
    subject = p.get("credentialSubject")
    if not isinstance(subject, dict) or not 1 <= len(subject) <= 64:
        fail("a credential's subject holds 1 to 64 claims")
    for key, value in subject.items():
        if not claim_name_allowed(key) or claim_value(value) is None:
            fail("a credential claim of a name or value not allowed")
    status = p.get("credentialStatus")
    if (not isinstance(status, dict) or set(status) != {"id", "type", "statusPurpose", "statusListIndex",
                                                         "statusListCredential"}
            or status["type"] != "BitstringStatusListEntry" or status["statusPurpose"] != "revocation"
            or not all(isinstance(status[k], str) for k in status)):
        fail("a credential's status is a BitstringStatusListEntry")
    if not DECIMAL.fullmatch(status["statusListIndex"]) or int(status["statusListIndex"]) >= LIST_SIZE \
            or status["id"] != status["statusListCredential"] + "#" + status["statusListIndex"]:
        fail("a credential's status entry index or id is not as defined")
    evidence = p.get("evidence")
    if (not isinstance(evidence, list) or len(evidence) != 1 or not isinstance(evidence[0], dict)
            or set(evidence[0]) != {"id", "type", "ledger", "record"} or evidence[0]["type"] != ["KanheEvidence"]
            or not all(isinstance(evidence[0][k], str) for k in ("id", "ledger", "record"))):
        fail("a credential's evidence is one KanheEvidence entry")
    e = evidence[0]
    hexid = re.compile(r"[0-9a-f]{64}")
    if not hexid.fullmatch(e["ledger"]) or not hexid.fullmatch(e["record"]):
        fail("a credential's evidence names ids in lowercase hex")
    head, sep, token = e["id"].rpartition("/c/")
    if not sep or not TOKEN.fullmatch(token):
        fail("a credential's evidence address is not BASE/c/TOKEN")
    base = base_url(head)
    if base.url != head:
        fail("a credential's evidence address has no valid base URL")
    if issuer["id"] != base.did:
        fail("a credential's issuer is not the did:web of its base URL")
    list_url = status["statusListCredential"]
    prefix = base.url + "/status/"
    n = list_url[len(prefix):] if list_url.startswith(prefix) else ""
    if not re.fullmatch(r"[1-9][0-9]*", n):
        fail("a credential's status list is not BASE/status/N")
    kid_prefix = issuer["id"] + "#"
    if not jws.kid.startswith(kid_prefix) or len(jws.kid) != len(kid_prefix) + 43:
        fail("a credential's kid is not its issuer's DID and a thumbprint")
    return Credential(jws, issuer["id"], issuer["name"], name, p["validFrom"], subject, int(n),
                      int(status["statusListIndex"]), list_url, e["id"], base, bytes.fromhex(e["ledger"]),
                      bytes.fromhex(e["record"]), jws.kid[len(kid_prefix):])


def _keys_from(ledger: rules.Ledger, actor: rules.Actor, index: int) -> list:
    """The keys an actor held from `index` on: the one in effect then, and
    every later one."""
    timeline = []
    for i in sorted(actor.history):
        statement = ledger.applied[i].statement
        if statement.type == protocol.ACTOR_REGISTER and ledger.applied[i].id == actor.id:
            timeline.append((i, statement.fields["key"]))
        elif statement.type == protocol.ACTOR_ROTATE_KEY and statement.fields["actor"] == actor.id:
            timeline.append((i, statement.fields["key"]))
    out = []
    for n, (i, key) in enumerate(timeline):
        in_effect = i < index and (n + 1 == len(timeline) or timeline[n + 1][0] >= index)
        if in_effect or i > index:
            out.append(key)
    return out


@dataclass
class CredentialReport:
    credential: Credential
    evidence: Report
    status: str  # live, revoked, replaced
    key_actor: rules.Actor | None = None
    endorsed_at: int | None = None
    problems: list = field(default_factory=list)
    did_problems: list | None = None
    list_problems: list | None = None
    list_bit: bool | None = None

    @property
    def verified(self) -> bool:
        return not self.problems and not (self.did_problems or []) and not (self.list_problems or [])


def _iso(ms: int) -> str:
    from .report import iso_time
    return iso_time(ms)


def verify_credential(compact: str, bundle: bytes, *, did_document: str | None = None,
                      status_list: str | None = None, ledger_id: bytes | None = None,
                      witnesses: list | None = None) -> CredentialReport:
    c = parse_credential(compact)
    if ledger_id is not None and ledger_id != c.ledger:
        fail("the credential names another ledger than the one expected")
    evidence = verify_bundle(bundle, ledger_id=c.ledger, witnesses=witnesses or [])
    ledger, record = evidence.ledger, evidence.record
    status = "revoked" if record is not None and record.revoked else \
        "replaced" if record is not None and record.superseded_by else "live"
    r = CredentialReport(c, evidence, status)
    if record is None or record.id != c.record:
        r.problems.append("the evidence is not about the record the credential names")
        return r

    # Step 3: the endorsement naming this entry, by a device whose key signed it.
    role = f"credential/{c.list}/{c.index}"
    signed_with = None
    endorsed = False
    for i in record.history:
        applied = ledger.applied[i]
        s = applied.statement
        if s.type != protocol.RECORD_ENDORSE or s.fields["role"] != role:
            continue
        actor = ledger.actors[applied.signer]
        if actor.kind != protocol.DEVICE:
            continue
        endorsed = True
        for key in _keys_from(ledger, actor, i):
            if (key.alg == crypto.ESP256 and thumbprint(key) == c.thumbprint
                    and crypto.verify_signature(key, c.jws.signing_input, c.jws.signature)):
                signed_with, r.key_actor, r.endorsed_at = key, actor, applied.registered_at
                break
        if signed_with is not None:
            break
    if not endorsed:
        r.problems.append(f"the record's evidence holds no endorsement as {role} by a device")
    elif signed_with is None:
        r.problems.append("the credential's signature is not by a key of the device that endorsed the record")

    # Step 4: what it says.
    if c.issuer_name != ledger.name:
        r.problems.append(f"the credential names its issuer \"{c.issuer_name}\"; the ledger is \"{ledger.name}\"'s")
    registered = _iso(registration_time(ledger, record))
    if c.valid_from != registered:
        r.problems.append(f"the credential is valid from {c.valid_from}; the record was registered at {registered}")
    disclosed = dict(evidence.disclosed)
    metadata = record.metadata or {}
    for key, value in c.subject.items():
        found = False
        for source in (disclosed, metadata):
            if key in source:
                v = claim_value(source[key])
                if v is not None and type(v) is type(value) and v == value:
                    found = True
                    break
        if not found:
            r.problems.append(f"the claim {key} = {value} is not a field the evidence discloses, nor public metadata")

    # Step 6: the DID document.
    if did_document is not None:
        r.did_problems = []
        try:
            doc = json.loads(did_document)
        except ValueError:
            doc = None
        if not isinstance(doc, dict):
            r.did_problems.append("the DID document is not a JSON object")
        else:
            if doc.get("id") != c.issuer:
                r.did_problems.append(f"the DID document is not {c.issuer}'s")
            method = next((m for m in doc.get("verificationMethod") or []
                           if isinstance(m, dict) and m.get("id") == c.jws.kid), None)
            try:
                key = jwk_key(method.get("publicKeyJwk")) if method is not None else None
            except VerifyError:
                key = None
            if key is None or signed_with is None or key != signed_with:
                r.did_problems.append("the DID document does not give, under the credential's kid, the key of the "
                                      "device that endorsed the record")
            service = next((s for s in doc.get("service") or []
                            if isinstance(s, dict) and s.get("type") == "KanheLedger"), None)
            if service is None or service.get("ledger") != c.ledger.hex():
                r.did_problems.append("the DID document does not name this ledger as its Kanhe ledger")

    # Step 7: the status list.
    if status_list is not None:
        r.list_problems = []
        try:
            lst = parse_jws(status_list)
        except VerifyError as e:
            r.list_problems.append(f"the status list is not a JWS of this profile ({e})")
            return r
        signed = False
        if r.key_actor is not None:
            index = next(i for i in record.history if ledger.applied[i].statement.type == protocol.RECORD_ENDORSE
                         and ledger.applied[i].statement.fields["role"] == role
                         and ledger.applied[i].signer == r.key_actor.id)
            for key in _keys_from(ledger, r.key_actor, index):
                if (key.alg == crypto.ESP256 and lst.kid == c.issuer + "#" + thumbprint(key)
                        and crypto.verify_signature(key, lst.signing_input, lst.signature)):
                    signed = True
                    break
        if not signed:
            r.list_problems.append("the status list is not signed by the device that endorsed the record")
        p = lst.payload
        subject = p.get("credentialSubject") if isinstance(p.get("credentialSubject"), dict) else {}
        types = p.get("type") if isinstance(p.get("type"), list) else []
        if (p.get("id") != c.list_url or "BitstringStatusListCredential" not in types
                or subject.get("statusPurpose") != "revocation" or not isinstance(subject.get("encodedList"), str)):
            r.list_problems.append(f"the status list is not {c.list_url}")
        else:
            try:
                bits = decode_list(subject["encodedList"])
            except VerifyError as e:
                r.list_problems.append(f"the status list does not decode ({e})")
            else:
                r.list_bit = bit(bits, c.index)
                if r.list_bit != (status != "live"):
                    r.list_problems.append(
                        f"the issuer's status list says {'revoked' if r.list_bit else 'not revoked'}; its ledger "
                        f"says the record is {status}")
    return r


def to_json(r: CredentialReport) -> dict:
    """The facts both verifiers state, for comparing them."""
    c = r.credential
    return {
        "verified": r.verified,
        "kind": "credential",
        "credential": {"issuer": c.issuer, "issuer_name": c.issuer_name, "name": c.name,
                       "valid_from": c.valid_from, "subject": c.subject, "status_list": c.list_url,
                       "status_index": c.index, "evidence": c.evidence_url, "kid": c.jws.kid},
        "record": {"id": c.record.hex(), "type": r.evidence.record.type if r.evidence.record else None,
                   "status": r.status, "complete": r.evidence.complete},
        "credential_key": None if r.key_actor is None else {
            "id": r.key_actor.id.hex(), "name": r.key_actor.name, "revoked": r.key_actor.revoked,
            "endorsed_at": _iso(r.endorsed_at)},
        "problems": r.problems,
        "did_document": None if r.did_problems is None else {"problems": r.did_problems},
        "status_list": None if r.list_problems is None else {"revoked": r.list_bit, "problems": r.list_problems},
    }


def to_text(r: CredentialReport) -> str:
    c = r.credential
    lines = [f"VERIFIED: a W3C credential, and the record behind it on {r.evidence.ledger.name}'s ledger"
             if r.verified else "NOT VERIFIED"]
    for problem in r.problems + (r.did_problems or []) + (r.list_problems or []):
        lines.append(f"  - {problem}")
    lines.append(f"  Credential   {c.name or 'untitled'}, issued by {c.issuer_name} ({c.issuer})")
    lines.append(f"  Valid from   {c.valid_from}")
    lines.append("  Claims       " + "; ".join(f"{k}: {v}" for k, v in c.subject.items()))
    lines.append(f"  Record       {c.record.hex()[:12]}, {r.status}")
    if r.key_actor is not None:
        lines.append(f"  Signed by    {r.key_actor.name} (a device, {r.key_actor.id.hex()[:12]})")
    return "\n".join(lines)
