# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The protocol's structures, parsed and checked against spec/kanhe.cddl.

Each parser takes decoded CBOR and returns a small object, or raises
VerifyError if the value does not match the CDDL: a missing or unknown map
key, a wrong type, a size out of range. Maps with unknown keys are refused
everywhere except where the CDDL allows any key (record metadata, section 2).
Rules that need the ledger's state are in rules.py and contracts.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import cbor, cose, crypto, network
from .errors import VerifyError

# Statement types (section 4). 20 is reserved and unknown, like every type
# not listed here.
GENESIS = 1
ACTOR_REGISTER = 2
ACTOR_ROTATE_KEY = 3
ACTOR_REVOKE = 4
DELEGATION_GRANT = 5
DELEGATION_REVOKE = 6
ACTOR_SET_PRESENCE = 7
LEDGER_ROTATE_LOG_KEY = 8
RECORD_REGISTER = 16
RECORD_ENDORSE = 17
RECORD_TRANSITION = 18
RECORD_REVOKE = 19
CONTRACT_DEPLOY = 21
CONTRACT_CALL = 22
CONTRACT_RETIRE = 23

STATEMENT_TYPE_NAMES = {
    GENESIS: "genesis",
    ACTOR_REGISTER: "actor-register",
    ACTOR_ROTATE_KEY: "actor-rotate-key",
    ACTOR_REVOKE: "actor-revoke",
    DELEGATION_GRANT: "delegation-grant",
    DELEGATION_REVOKE: "delegation-revoke",
    ACTOR_SET_PRESENCE: "actor-set-presence",
    LEDGER_ROTATE_LOG_KEY: "ledger-rotate-log-key",
    RECORD_REGISTER: "record-register",
    RECORD_ENDORSE: "record-endorse",
    RECORD_TRANSITION: "record-transition",
    RECORD_REVOKE: "record-revoke",
    CONTRACT_DEPLOY: "contract-deploy",
    CONTRACT_CALL: "contract-call",
    CONTRACT_RETIRE: "contract-retire",
}
RECORD_STATEMENTS = (RECORD_REGISTER, RECORD_ENDORSE, RECORD_TRANSITION, RECORD_REVOKE)
CONTRACT_STATEMENTS = (CONTRACT_DEPLOY, CONTRACT_CALL, CONTRACT_RETIRE)

PERSON, AGENT, DEVICE = 1, 2, 3
ORGANIZATION = 0  # the organization actor, as the signer kind of section 15

HASHES = (crypto.SHA256, crypto.SM3)
# Receipt vds values (section 8).
VDS = {crypto.SHA256: 1, crypto.SM3: -65537}

REQUEST_KIND = re.compile(r"[a-z][a-z0-9._-]{0,63}")
CREATE, CALL = 1, 2  # function kinds (section 15)
DONE, FAILED, EXPIRED = 1, 2, 3  # answer statuses (v0.8)
ANSWER_STATUS_NAMES = {DONE: "done", FAILED: "failed", EXPIRED: "expired"}
# Sizes of section 15.
MAX_CODE = 524_288
MAX_SOURCE = 262_144
MAX_VALUE = 65_536  # arguments and states, encoded
MAX_FUNCTIONS = 256
MAX_CONSENTS = 16


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_id(v) -> bool:
    return isinstance(v, bytes) and len(v) == 32


def _map(value, what: str, required: set, optional: set = frozenset()) -> dict:
    if not isinstance(value, dict):
        raise VerifyError(f"{what} is not a map with integer keys")
    keys = set(value)
    if not all(_is_int(k) for k in keys):
        raise VerifyError(f"{what} has a key that is not an integer")
    missing = required - keys
    if missing:
        raise VerifyError(f"{what} lacks key {min(missing)}")
    unknown = keys - required - set(optional)
    if unknown:
        raise VerifyError(f"{what} has an unknown key {min(unknown)}")
    return value


def _check(condition: bool, message: str):
    if not condition:
        raise VerifyError(message)


def _tstr(v, what: str, low: int = 0, high: int | None = None) -> str:
    _check(isinstance(v, str), f"{what} is not text")
    n = len(v.encode("utf-8"))
    _check(n >= low and (high is None or n <= high), f"{what} has a length out of range")
    return v


def _bstr(v, what: str, low: int = 0, high: int | None = None) -> bytes:
    _check(isinstance(v, bytes), f"{what} is not a byte string")
    _check(len(v) >= low and (high is None or len(v) <= high), f"{what} has a length out of range")
    return v


def _id(v, what: str) -> bytes:
    _check(_is_id(v), f"{what} is not a 32-byte id")
    return v


def _uint(v, what: str) -> int:
    _check(_is_uint(v), f"{what} is not an unsigned integer")
    return v


def _strictly_ascending(items, key=lambda x: x) -> bool:
    keys = [key(i) for i in items]
    return all(a < b for a, b in zip(keys, keys[1:]))


# ---------------------------------------------------------------------------
# Statements (section 4)
# ---------------------------------------------------------------------------

@dataclass
class Scope:
    types: list
    record_types: list | None = None
    not_before: int | None = None
    not_after: int | None = None
    may_delegate: bool = False
    presence: bool = False
    contracts: list | None = None
    functions: list | None = None
    request_kinds: list | None = None


@dataclass
class Credential:
    id: bytes
    key: crypto.PublicKey
    rp_id: str | None  # None for a hardware key
    label: str | None

    @property
    def hardware(self) -> bool:
        return self.rp_id is None


@dataclass
class PresenceProof:
    credential_id: bytes
    authenticator_data: bytes | None
    client_data: bytes | None
    signature: bytes


@dataclass
class Provenance:
    model: str | None
    model_version: str | None
    input_commitment: bytes | None
    tools: list  # [(name, digest)]


@dataclass
class Statement:
    sign1: cose.Sign1
    payload: dict
    type: int
    ledger_id: bytes | None
    actor: bytes | None
    delegation: bytes | None
    issued_at: int
    nonce: bytes
    body: dict
    presence: PresenceProof | None
    provenance: Provenance | None
    # Parsed body fields, by type.
    fields: dict = field(default_factory=dict)

    @property
    def type_name(self) -> str:
        return STATEMENT_TYPE_NAMES[self.type]


def parse_scope(value) -> Scope:
    m = _map(value, "a scope", {1}, {2, 3, 4, 5, 6, 7, 8, 9})
    types = m[1]
    _check(isinstance(types, list) and types, "a scope's statement types are not a non-empty list")
    for t in types:
        _check(_is_int(t) and t in STATEMENT_TYPE_NAMES, f"a scope names an unknown statement type ({t})")
    _check(_strictly_ascending(types), "a scope's statement types are not strictly ascending")
    scope = Scope(types=list(types))
    if 2 in m:
        record_types = m[2]
        _check(isinstance(record_types, list) and record_types
               and all(isinstance(t, str) for t in record_types),
               "a scope's record types are not a non-empty list of text")
        _check(_strictly_ascending(record_types, lambda t: t.encode()),
               "a scope's record types are not strictly ascending")
        scope.record_types = list(record_types)
    if 3 in m:
        scope.not_before = _uint(m[3], "a scope's not-before time")
    if 4 in m:
        scope.not_after = _uint(m[4], "a scope's not-after time")
    # Keys 5 and 6 are "encoded only when true".
    for key, name in ((5, "may_delegate"), (6, "presence")):
        if key in m:
            _check(m[key] is True, f"scope key {key} is encoded only when true")
            setattr(scope, name, True)
    if 7 in m:
        contracts = m[7]
        _check(isinstance(contracts, list) and contracts and all(_is_id(c) for c in contracts)
               and _strictly_ascending(contracts), "a scope's contracts are not strictly ascending ids")
        scope.contracts = list(contracts)
    if 8 in m:
        functions = m[8]
        _check(isinstance(functions, list) and functions
               and all(isinstance(f, str) and 1 <= len(f.encode()) <= 64 for f in functions)
               and _strictly_ascending(functions, lambda f: f.encode()),
               "a scope's functions are not strictly ascending names")
        scope.functions = list(functions)
    if 9 in m:
        kinds = m[9]
        _check(isinstance(kinds, list) and kinds
               and all(isinstance(k, str) and REQUEST_KIND.fullmatch(k) for k in kinds)
               and _strictly_ascending(kinds, lambda k: k.encode()),
               "a scope's request kinds are not strictly ascending request kinds")
        scope.request_kinds = list(kinds)
    return scope


def parse_credential(value) -> Credential:
    if isinstance(value, dict) and 5 in value:
        m = _map(value, "a hardware-key credential", {2, 3, 5}, {4})
        _check(m[5] == 2 and _is_int(m[5]), "a hardware-key credential's method is not 2")
        rp_id = None
    else:
        m = _map(value, "a WebAuthn credential", {1, 2, 3}, {4})
        rp_id = m[1]
        _check(isinstance(rp_id, str) and 1 <= len(rp_id) <= 253, "a credential's relying party id is malformed")
    credential_id = _bstr(m[2], "a credential id", 1, 1023)
    key = crypto.parse_public_key(m[3], "a presence credential's key")
    if rp_id is not None:
        _check(key.alg in (crypto.ESP256, crypto.ED25519), "a passkey's key is not ESP256 or Ed25519")
    label = _tstr(m[4], "a credential label") if 4 in m else None
    return Credential(id=credential_id, key=key, rp_id=rp_id, label=label)


def parse_presence_proof(value) -> PresenceProof:
    m = _map(value, "a proof of presence", {1, 4}, {2, 3})
    _check((2 in m) == (3 in m), "a proof of presence has only one of authenticatorData and clientDataJSON")
    return PresenceProof(
        credential_id=_bstr(m[1], "a proof's credential id"),
        authenticator_data=_bstr(m[2], "authenticatorData", 37, 4096) if 2 in m else None,
        client_data=_bstr(m[3], "clientDataJSON", 1, 4096) if 3 in m else None,
        signature=_bstr(m[4], "a proof's signature", 1, 8192),
    )


def parse_provenance(value) -> Provenance:
    m = _map(value, "a provenance", set(), {1, 2, 3, 4})
    tools = []
    if 4 in m:
        _check(isinstance(m[4], list) and m[4], "provenance tools are not a non-empty list")
        for pin in m[4]:
            _check(isinstance(pin, list) and len(pin) == 2 and isinstance(pin[0], str)
                   and isinstance(pin[1], bytes), "a tool pin is not [name, digest]")
            tools.append((pin[0], pin[1]))
    return Provenance(
        model=_tstr(m[1], "a provenance model") if 1 in m else None,
        model_version=_tstr(m[2], "a provenance model version") if 2 in m else None,
        input_commitment=_bstr(m[3], "a provenance input commitment") if 3 in m else None,
        tools=tools,
    )


def _parse_attachment(value) -> tuple:
    _check(isinstance(value, list) and len(value) == 4, "an attachment is not [name, media type, size, commitment]")
    name, media_type, size, commitment = value
    _tstr(name, "an attachment name")
    _tstr(media_type, "an attachment media type")
    _uint(size, "an attachment size")
    _bstr(commitment, "an attachment commitment")
    return name, media_type, size, commitment


def _parse_body(kind: int, body) -> dict:
    """The body of a statement of `kind`, as a dict of named fields."""
    if kind == GENESIS:
        m = _map(body, "a genesis body", {1, 2, 3, 4})
        _check(_is_int(m[1]) and m[1] in HASHES, "the genesis names an unknown hash algorithm")
        return {"hash": m[1], "name": _tstr(m[2], "the organization's name"),
                "root_key": crypto.parse_public_key(m[3], "the root key"),
                "log_key": crypto.parse_public_key(m[4], "the log key")}
    if kind == ACTOR_REGISTER:
        m = _map(body, "an actor registration", {1, 2, 3}, {4, 5})
        _check(m[1] in (PERSON, AGENT, DEVICE) and _is_int(m[1]), "an actor's kind is not person, agent, or device")
        profile = None
        if 5 in m:
            _check(m[1] == AGENT, "only agents carry an agent profile")
            p = _map(m[5], "an agent profile", set(), {1, 2, 3})
            profile = {k: _tstr(v, "an agent profile field") for k, v in p.items()}
        return {"kind": m[1], "name": _tstr(m[2], "an actor's name"),
                "key": crypto.parse_public_key(m[3], "an actor's key"),
                "responsible": _id(m[4], "a responsible person") if 4 in m else None,
                "profile": profile}
    if kind == ACTOR_ROTATE_KEY:
        m = _map(body, "a key rotation", {1, 2})
        return {"actor": _id(m[1], "the actor"), "key": crypto.parse_public_key(m[2], "the new key")}
    if kind in (ACTOR_REVOKE, DELEGATION_REVOKE, RECORD_REVOKE):
        m = _map(body, f"a {STATEMENT_TYPE_NAMES[kind]} body", {1}, {2})
        return {"target": _id(m[1], "the revoked object"),
                "reason": _tstr(m[2], "a reason") if 2 in m else None}
    if kind == DELEGATION_GRANT:
        m = _map(body, "a delegation grant", {1, 2})
        return {"grantee": _id(m[1], "the grantee"), "scope": parse_scope(m[2])}
    if kind == ACTOR_SET_PRESENCE:
        m = _map(body, "a presence registration", {1, 2})
        _check(isinstance(m[2], list) and len(m[2]) <= 16, "a person has at most 16 presence credentials")
        credentials = [parse_credential(c) for c in m[2]]
        ids = [c.id for c in credentials]
        _check(len(set(ids)) == len(ids), "presence credential ids are not unique")
        return {"actor": _id(m[1], "the person"), "credentials": credentials}
    if kind == LEDGER_ROTATE_LOG_KEY:
        m = _map(body, "a log key rotation", {1})
        return {"key": crypto.parse_public_key(m[1], "the new log key")}
    if kind == RECORD_REGISTER:
        m = _map(body, "a record registration", {1, 2, 3}, {4, 5, 6})
        attachments = []
        if 4 in m:
            _check(isinstance(m[4], list) and m[4], "a record's attachments are not a non-empty list")
            attachments = [_parse_attachment(a) for a in m[4]]
        metadata = None
        if 5 in m:
            _check(isinstance(m[5], dict) and m[5] and all(isinstance(k, str) for k in m[5]),
                   "a record's metadata is not a non-empty map with text keys")
            metadata = m[5]
        return {"record_type": _tstr(m[1], "a record type"),
                # The root of an RFC 9162 tree under the ledger's hash: 32 bytes.
                "field_root": _bstr(m[2], "a field root", 32, 32),
                "field_count": _uint(m[3], "a field count"),
                "attachments": attachments, "metadata": metadata,
                "supersedes": _id(m[6], "the superseded record") if 6 in m else None}
    if kind == RECORD_ENDORSE:
        m = _map(body, "an endorsement", {1, 2})
        return {"record": _id(m[1], "the record"), "role": _tstr(m[2], "a role")}
    if kind == RECORD_TRANSITION:
        m = _map(body, "a transition", {1, 2, 3})
        return {"record": _id(m[1], "the record"), "from": _tstr(m[2], "a from state"),
                "to": _tstr(m[3], "a to state")}
    if kind == CONTRACT_DEPLOY:
        m = _map(body, "a contract deploy", {1, 2, 3, 4}, {5, 6})
        return {"code": _bstr(m[1], "a contract's code", 0, MAX_CODE), "interface": _parse_interface(m[2]),
                "language": _tstr(m[3], "a contract's language", 1, 32),
                "compiler": _tstr(m[4], "a contract's compiler", 1, 128),
                "source": _bstr(m[5], "a contract's source", 0, MAX_SOURCE) if 5 in m else None,
                "name": _tstr(m[6], "a contract's name", 1, 256) if 6 in m else None}
    if kind == CONTRACT_CALL:
        return _parse_call(body)
    if kind == CONTRACT_RETIRE:
        m = _map(body, "a contract retire", {1}, {2})
        return {"contract": _id(m[1], "the retired contract"),
                "reason": _tstr(m[2], "a reason") if 2 in m else None}
    raise VerifyError(f"unknown statement type {kind}")


def function_name(v, what: str) -> str:
    return _tstr(v, what, 1, 64)


def _parse_interface(value) -> dict:
    """contract-interface: 1 to 256 function names of 1 to 64 bytes, each of
    kind 1 (creates) or 2 (calls), at least one of kind 1."""
    _check(isinstance(value, dict) and value and all(isinstance(k, str) for k in value),
           "a contract's interface is not a non-empty map of function names")
    _check(len(value) <= MAX_FUNCTIONS, "a contract's interface has more than 256 functions")
    for name, kind in value.items():
        function_name(name, "a function's name")
        _check(_is_int(kind) and kind in (CREATE, CALL), f"the function {name!r} is of an unknown kind")
    _check(CREATE in value.values(), "a contract's interface has no function that creates an instance")
    return dict(value)


@dataclass
class ConsentRef:
    """contract-consent-ref: [ledger, record, bundle hash, signer]."""
    ledger: bytes
    record: bytes
    bundle: bytes
    signer: dict  # {1: kind, ? 2: presence method, ? 3: model}


def parse_signer(value, what: str) -> dict:
    m = _map(value, what, {1}, {2, 3})
    _check(_is_int(m[1]) and m[1] in (ORGANIZATION, PERSON, AGENT, DEVICE), f"{what}'s kind is unknown")
    _check(2 not in m or (_is_int(m[2]) and m[2] in (1, 2)), f"{what}'s presence method is unknown")
    if 3 in m:
        _tstr(m[3], f"{what}'s model")
    return dict(m)


def _parse_call(body) -> dict:
    m = _map(body, "a contract call", {3, 4}, {1, 2, 5, 6, 7, 8})
    _check((1 in m) != (2 in m), "a contract call names exactly one of a contract and an instance")
    _check((5 in m) == (2 in m), "a contract call has a head exactly when it names an instance")
    _check(8 not in m or 2 in m, "an answer is a call on an instance")
    _check(len(cbor.encode(m[4])) <= MAX_VALUE, "a call's arguments are more than 65,536 bytes encoded")
    consents = []
    if 6 in m:
        refs = m[6]
        _check(isinstance(refs, list) and 1 <= len(refs) <= MAX_CONSENTS, "a call cites 1 to 16 consents")
        for ref in refs:
            _check(isinstance(ref, list) and len(ref) == 4,
                   "a consent citation is not [ledger, record, bundle, signer]")
            consents.append(ConsentRef(ledger=_id(ref[0], "a consent's ledger"),
                                       record=_id(ref[1], "a consent's record"),
                                       bundle=_bstr(ref[2], "a consent's bundle hash", 32, 32),
                                       signer=parse_signer(ref[3], "a consent's signer")))
        _check(_strictly_ascending(consents, lambda c: c.ledger),
               "a call's consents are not strictly ascending by ledger")
    answer = None
    if 8 in m:
        a = m[8]
        _check(isinstance(a, list) and len(a) == 2 and _is_int(a[1]) and a[1] in ANSWER_STATUS_NAMES,
               "an answer is not [request, status]")
        answer = (_id(a[0], "an answer's request"), a[1])
    return {"contract": _id(m[1], "the called contract") if 1 in m else None,
            "instance": _id(m[2], "the called instance") if 2 in m else None,
            "function": _tstr(m[3], "a call's function"), "arguments": m[4],
            "head": _uint(m[5], "a call's head") if 5 in m else None, "consents": consents,
            "reference": _tstr(m[7], "a call's reference", 1, 1024) if 7 in m else None, "answer": answer}


def parse_statement(signed: bytes) -> Statement:
    """A signed statement: COSE_Sign1 over a statement-payload."""
    sign1 = cose.parse_sign1(signed, cose.STATEMENT_TYPE, "a statement")
    payload = cbor.decode(sign1.payload, max_items=cbor.MAX_PAYLOAD_ITEMS)
    m = _map(payload, "a statement payload", {0, 1, 5, 6, 7}, {2, 3, 4, 8, 9})
    _check(m[0] == 1 and _is_int(m[0]), "the statement is not of protocol version 1")
    kind = m[1]
    if not _is_int(kind) or kind not in STATEMENT_TYPE_NAMES:
        raise VerifyError(f"unknown statement type {kind}")
    if kind == GENESIS:
        _check(2 not in m and 3 not in m and 4 not in m, "a genesis names no ledger, actor, or delegation")
    else:
        _check(2 in m and 3 in m, "a statement lacks its ledger id or actor id")
    statement = Statement(
        sign1=sign1, payload=m, type=kind,
        ledger_id=_id(m[2], "the ledger id") if 2 in m else None,
        actor=_id(m[3], "the actor id") if 3 in m else None,
        delegation=_id(m[4], "the delegation id") if 4 in m else None,
        issued_at=_uint(m[5], "issued at"),
        nonce=_bstr(m[6], "the nonce", 16, 16),
        body=m[7],
        presence=parse_presence_proof(m[8]) if 8 in m else None,
        provenance=parse_provenance(m[9]) if 9 in m else None,
    )
    statement.fields = _parse_body(kind, m[7])
    return statement


# ---------------------------------------------------------------------------
# The log (section 8) and state commitments (section 9)
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    encoded: bytes
    id: bytes
    registered_at: int
    statement: bytes | None
    commitment: bytes | None


def parse_log_entry(encoded: bytes) -> LogEntry:
    m = _map(cbor.decode(encoded), "a log entry", {1, 2}, {3, 4})
    _check((3 in m) != (4 in m), "a log entry must hold exactly one of a statement and a state commitment")
    return LogEntry(encoded=encoded, id=_id(m[1], "a log entry's id"),
                    registered_at=_uint(m[2], "a registration time"),
                    statement=_bstr(m[3], "a signed statement") if 3 in m else None,
                    commitment=_bstr(m[4], "a signed state commitment") if 4 in m else None)


@dataclass
class TreeHead:
    """A checkpoint payload or a state commitment payload: {1: ledger id,
    2: hash, 3: tree size, 4: root, 5: timestamp}."""
    sign1: cose.Sign1
    ledger_id: bytes
    hash: int
    tree_size: int
    root: bytes
    timestamp: int


def parse_tree_head(signed: bytes, content_type: str, what: str) -> TreeHead:
    sign1 = cose.parse_sign1(signed, content_type, what)
    m = _map(cbor.decode(sign1.payload), f"{what}'s payload", {1, 2, 3, 4, 5})
    _check(_is_int(m[2]) and m[2] in HASHES, f"{what} names an unknown tree hash")
    size = _uint(m[3], f"{what}'s tree size")
    _check(size >= 1, f"{what}'s tree size is 0")
    return TreeHead(sign1=sign1, ledger_id=_id(m[1], f"{what}'s ledger id"), hash=m[2], tree_size=size,
                    root=_bstr(m[4], f"{what}'s root", 32, 32), timestamp=_uint(m[5], f"{what}'s timestamp"))


# ---------------------------------------------------------------------------
# Evidence bundles (section 11)
# ---------------------------------------------------------------------------

@dataclass
class Disclosure:
    leaf: bytes
    index: int
    path: list


@dataclass
class StateProof:
    kind: int
    id: bytes
    history: list
    siblings: list

    @property
    def leaf(self) -> list:
        return [self.kind, self.id, self.history]


@dataclass
class Anchor:
    checkpoint: bytes
    tokens: list  # time-stamp tokens over its payload (v0.11)
    consistency: list | None
    cosignatures: list  # [(name, bytes)]: open-network witnesses' cosignatures of its note (v0.13)


@dataclass
class Bundle:
    subject: bytes
    entries: list  # [(encoded log entry, encoded receipt)]
    checkpoint: bytes
    cosignatures: list
    disclosures: list
    openings: list  # [(name, salt)]
    proofs: list
    anchors: list
    memberships: list = field(default_factory=list)  # v0.16: membership proofs, each an encoded bundle


# A bundle carries at most this many membership proofs (key 9, v0.16).
MAX_MEMBERSHIP_PROOFS = 16


def _nonempty_list(value, what: str) -> list:
    _check(isinstance(value, list) and value, f"{what} is not a non-empty list")
    return value


def _hashes(value, what: str) -> list:
    _check(isinstance(value, list) and all(isinstance(h, bytes) and len(h) == 32 for h in value),
           f"{what} is not a list of 32-byte hashes")
    return value


def parse_bundle(data: bytes) -> Bundle:
    value = cbor.decode(data)
    _check(not is_contract_evidence(value), "this is an instance's contract evidence, not an evidence bundle: "
           "verify it as contract evidence")
    m = _map(value, "an evidence bundle", {0, 1, 2, 3}, {4, 5, 6, 7, 8, 9})
    _check(m[0] == 1 and _is_int(m[0]), "the bundle is not of format version 1")
    entries = []
    for item in _nonempty_list(m[2], "the bundle's entries"):
        _check(isinstance(item, list) and len(item) == 2 and all(isinstance(x, bytes) for x in item),
               "a bundle entry is not [log entry, receipt]")
        entries.append((item[0], item[1]))
    cosignatures = []
    if 4 in m:
        cosignatures = _nonempty_list(m[4], "the cosignatures")
        _check(all(isinstance(c, bytes) for c in cosignatures), "a cosignature is not a byte string")
    disclosures = []
    for d in (_nonempty_list(m[5], "the disclosures") if 5 in m else []):
        _check(isinstance(d, list) and len(d) == 3 and isinstance(d[0], bytes) and _is_uint(d[1]),
               "a disclosure is not [leaf, index, path]")
        disclosures.append(Disclosure(leaf=d[0], index=d[1], path=_hashes(d[2], "a disclosure's path")))
    openings = []
    for o in (_nonempty_list(m[6], "the attachment openings") if 6 in m else []):
        _check(isinstance(o, list) and len(o) == 2 and isinstance(o[0], str)
               and isinstance(o[1], bytes) and len(o[1]) == 16, "an attachment opening is not [name, salt]")
        openings.append((o[0], o[1]))
    proofs = []
    for p in (_nonempty_list(m[7], "the state proofs") if 7 in m else []):
        _check(isinstance(p, list) and len(p) == 2, "a state proof is not [leaf, siblings]")
        leaf, siblings = p
        _check(isinstance(leaf, list) and len(leaf) == 3 and _is_int(leaf[0]) and 1 <= leaf[0] <= 5
               and _is_id(leaf[1]) and isinstance(leaf[2], list) and leaf[2]
               and all(_is_uint(i) for i in leaf[2]) and _strictly_ascending(leaf[2]),
               "a state proof's leaf is not [kind, id, strictly ascending history]")
        _hashes(siblings, "a state proof's siblings")
        _check(len(siblings) <= 256, "a state proof has more than 256 siblings")
        proofs.append(StateProof(kind=leaf[0], id=leaf[1], history=list(leaf[2]), siblings=siblings))
    anchors = [parse_anchor(a) for a in (_nonempty_list(m[8], "the anchors") if 8 in m else [])]
    # v0.16: 1 to 16 membership proofs, each an encoded evidence bundle,
    # verified in evidence.py (section 11, step 9).
    memberships = []
    if 9 in m:
        memberships = _nonempty_list(m[9], "the list of membership proofs (key 9)")
        _check(len(memberships) <= MAX_MEMBERSHIP_PROOFS, "the bundle carries more than 16 membership proofs")
        _check(all(isinstance(p, bytes) for p in memberships), "a membership proof is not a byte string")
    return Bundle(subject=_id(m[1], "the bundle's subject"), entries=entries,
                  checkpoint=_bstr(m[3], "the checkpoint"), cosignatures=cosignatures,
                  disclosures=disclosures, openings=openings, proofs=proofs, anchors=anchors,
                  memberships=list(memberships))


def parse_anchor(value) -> Anchor:
    """An anchor (v0.11): a checkpoint with time-stamp tokens over its
    payload (key 2), open-network witnesses' cosignatures of its note (key 4,
    v0.13), or both; and a consistency proof to the bundle's checkpoint
    unless it is that checkpoint (key 3)."""
    am = _map(value, "an anchor", {1}, {2, 3, 4})
    _check(isinstance(am[1], bytes), "an anchor's checkpoint is not a byte string")
    _check(2 in am or 4 in am, "an anchor holds neither time-stamp tokens nor network cosignatures")
    tokens = []
    if 2 in am:
        tokens = _nonempty_list(am[2], "an anchor's tokens")
        _check(all(isinstance(t, bytes) for t in tokens), "a time-stamp token is not a byte string")
    consistency = None
    if 3 in am:
        consistency = _hashes(_nonempty_list(am[3], "an anchor's consistency proof"),
                              "an anchor's consistency proof")
    cosignatures = []
    for c in (_nonempty_list(am[4], "an anchor's network cosignatures") if 4 in am else []):
        _check(isinstance(c, list) and len(c) == 2 and network.valid_name(c[0]) and isinstance(c[1], bytes)
               and network.PREFIX_SIZE <= len(c[1]) <= 8192,
               "a network cosignature is not [name, 12 to 8,192 bytes] (section 10.2)")
        cosignatures.append((c[0], c[1]))
    return Anchor(checkpoint=am[1], tokens=tokens, consistency=consistency, cosignatures=cosignatures)


def parse_field_leaf(leaf: bytes) -> tuple:
    """A disclosed field: [name, salt, value] (section 6)."""
    value = cbor.decode(leaf)
    _check(isinstance(value, list) and len(value) == 3 and isinstance(value[0], str)
           and isinstance(value[1], bytes) and len(value[1]) == 16,
           "a disclosed field is not [name, salt, value]")
    return value[0], value[1], value[2]


# ---------------------------------------------------------------------------
# Contract evidence (section 15)
# ---------------------------------------------------------------------------

def is_contract_evidence(value) -> bool:
    """contract-evidence {0: 1, 1: bundle, ? 2: consent bundles}, told apart
    from an evidence bundle, which has key 3 and a 32-byte key 1."""
    return (isinstance(value, dict) and 1 in value and 3 not in value and set(value) <= {0, 1, 2}
            and isinstance(value[1], bytes) and len(value[1]) != 32)


def parse_contract_evidence(data: bytes) -> tuple[bytes, list]:
    """(the instance's evidence bundle, the consent bundles)."""
    m = _map(cbor.decode(data), "contract evidence", {0, 1}, {2})
    _check(m[0] == 1 and _is_int(m[0]), "the contract evidence is not of format version 1")
    consents = []
    if 2 in m:
        consents = m[2]
        _check(isinstance(consents, list) and 1 <= len(consents) <= 4096
               and all(isinstance(b, bytes) for b in consents), "the consent bundles are not 1 to 4096 byte strings")
    return _bstr(m[1], "the instance's evidence bundle"), list(consents)
