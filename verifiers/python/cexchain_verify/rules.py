# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Replaying statements under the ledger rules (spec section 5), with
records' lifecycles (section 6), proof of presence (section 7), the log key
in effect (section 8), state histories (section 9), and contracts (section
15, in contracts.py).

A verifier holds only the statements a bundle includes, so the replayed
state is partial: rules about objects the bundle does not hold (another
actor's key, an earlier nonce) are checked against what it holds. Section 11
says how far that goes; completeness (state proofs) is checked in
evidence.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import contracts, cose, crypto, presence, protocol
from .errors import VerifyError
from .protocol import (ACTOR_REGISTER, ACTOR_REVOKE, ACTOR_ROTATE_KEY, ACTOR_SET_PRESENCE, AGENT,
                       CONTRACT_CALL, CONTRACT_DEPLOY, CONTRACT_RETIRE, DELEGATION_GRANT, DELEGATION_REVOKE,
                       GENESIS, LEDGER_ROTATE_LOG_KEY, ORGANIZATION, PERSON, RECORD_ENDORSE, RECORD_REGISTER,
                       RECORD_REVOKE, RECORD_STATEMENTS, RECORD_TRANSITION)

# `issued at` may be at most this far after the registration time.
MAX_FUTURE_MS = 5 * 60 * 1000
# A delegation chain holds at most this many delegations.
MAX_CHAIN = 16

# Records (section 6): the generic lifecycle, and the mechanism types with
# their initial states and transitions. Mechanism types take no endorsements.
GENERIC_INITIAL = "registered"
RESERVED_PREFIX = "cexchain."
MECHANISM_TYPES = {
    "cexchain.access-request/1": ("requested", {("requested", "withdrawn")}),
    "cexchain.access-grant/1": ("granted", set()),
    "cexchain.access-receipt/1": ("received", set()),
    "cexchain.contract-consent/1": ("given", {("given", "withdrawn")}),
}

KIND_NAMES = {ORGANIZATION: "organization", PERSON: "person", AGENT: "agent", protocol.DEVICE: "device"}


@dataclass
class Actor:
    id: bytes
    kind: int
    name: str
    key: crypto.PublicKey
    responsible: bytes | None = None
    profile: dict | None = None
    revoked: bool = False
    credentials: list = field(default_factory=list)
    history: list = field(default_factory=list)


@dataclass
class Delegation:
    id: bytes
    grantor: bytes
    grantee: bytes
    scope: protocol.Scope
    parent: bytes | None
    revoked: bool = False
    history: list = field(default_factory=list)


@dataclass
class Record:
    id: bytes
    type: str
    field_root: bytes
    field_count: int
    attachments: list
    metadata: dict | None
    supersedes: bytes | None
    registrant: bytes
    state: str
    revoked: bool = False
    superseded_by: bytes | None = None
    endorsements: set = field(default_factory=set)
    history: list = field(default_factory=list)


@dataclass
class Applied:
    """A statement as replayed: who signed it, under which delegations,
    with what proof of presence."""
    index: int
    registered_at: int
    statement: protocol.Statement
    id: bytes
    signer: bytes
    chain: list  # delegation ids, the signer's own first
    presence: presence.PresenceResult | None


def fail(message: str):
    raise VerifyError(message)


class Ledger(contracts.ContractRules):
    """The state a replay of the included entries reaches."""

    def __init__(self, entry: protocol.LogEntry, index: int):
        if index != 0 or entry.statement is None:
            fail("the bundle does not start with the genesis entry")
        statement = protocol.parse_statement(entry.statement)
        if statement.type != GENESIS:
            fail("the bundle does not start with the genesis entry")
        body = statement.fields
        self.hash_alg = body["hash"]
        self.h = crypto.hash_function(self.hash_alg)
        sid = self.h(statement.sign1.to_be_signed())
        # ledger_id = the genesis statement's id (section 3).
        self.id = sid
        self.name = body["name"]
        root, log = body["root_key"], body["log_key"]
        if entry.id != sid:
            fail("the genesis entry's id is not its statement id")
        for key in (root, log):
            if crypto.is_weak(key):
                fail("the genesis names a weak key")
        if root.encoded == log.encoded:
            fail("the genesis root key is also its log key")
        self._check_signed_by(statement, root, "the genesis is not signed by its root key")
        if statement.issued_at > entry.registered_at + MAX_FUTURE_MS:
            fail("the genesis is issued more than 5 minutes after its registration")
        if statement.presence is not None:
            fail("the organization does not prove presence")
        self.actors: dict[bytes, Actor] = {
            sid: Actor(id=sid, kind=ORGANIZATION, name=self.name, key=root, history=[0])}
        self.delegations: dict[bytes, Delegation] = {}
        self.records: dict[bytes, Record] = {}
        self.statement_ids = {sid}
        self.nonces = {(sid, statement.nonce)}
        self.log_keys = [(0, log)]  # (index of the statement that set it, key)
        self.root_rotations = 0
        self.applied: dict[int, Applied] = {
            0: Applied(index=0, registered_at=entry.registered_at, statement=statement, id=sid, signer=sid,
                       chain=[], presence=None)}
        self.commitments: dict[int, protocol.TreeHead] = {}
        self._init_contracts()

    # -- keys -------------------------------------------------------------

    def log_key_for_size(self, size: int) -> crypto.PublicKey:
        """The log key in effect for a tree of `size` entries: the one set by
        the last rotation at an index below it, or the genesis key."""
        key = self.log_keys[0][1]
        for index, k in self.log_keys:
            if index < size:
                key = k
        return key

    def _check_signed_by(self, statement, key: crypto.PublicKey, message: str):
        sign1 = statement.sign1
        if sign1.alg != key.alg or sign1.kid != key.kid(self.h):
            fail(message + " (its kid or algorithm is not the key's)")
        if not crypto.verify_signature(key, sign1.to_be_signed(), sign1.signature):
            fail(message)

    def check_signed_head(self, head: protocol.TreeHead, key: crypto.PublicKey, what: str):
        sign1 = head.sign1
        if sign1.alg != key.alg or sign1.kid != key.kid(self.h):
            fail(f"{what} is not signed by the log key in effect")
        if not crypto.verify_signature(key, sign1.to_be_signed(), sign1.signature):
            fail(f"{what}'s signature does not verify with the log key in effect")

    def _is_log_key(self, key: crypto.PublicKey) -> bool:
        return any(k.encoded == key.encoded for _, k in self.log_keys)

    def _actor_with_key(self, key: crypto.PublicKey, other_than: bytes | None = None):
        for actor in self.actors.values():
            if actor.id != other_than and actor.key.encoded == key.encoded:
                return actor
        return None

    def _is_presence_key(self, key: crypto.PublicKey) -> bool:
        return any(c.key.encoded == key.encoded for a in self.actors.values() for c in a.credentials)

    def _check_new_actor_key(self, key: crypto.PublicKey, actor: Actor | None):
        """Section 5, actors: not weak, not another actor's, not one of the
        actor's presence keys, not a log key of the ledger (current or past)."""
        if crypto.is_weak(key):
            fail("the new key is weak")
        if self._actor_with_key(key, other_than=actor.id if actor else None) is not None:
            fail("the new key already belongs to an actor")
        if self._is_presence_key(key):
            fail("the new key is a presence key")
        if self._is_log_key(key):
            fail("the new key is (or was) a log key of the ledger")

    # -- entries ----------------------------------------------------------

    def apply_commitment(self, entry: protocol.LogEntry, index: int) -> protocol.TreeHead:
        """A state commitment (section 9): signed by the log key in effect at
        its index, for this ledger and hash, of tree size its own index. Its
        root is checked against the replayed state by the caller, which
        holds the state proofs."""
        head = protocol.parse_tree_head(entry.commitment, cose.STATE_TYPE, "a state commitment")
        if head.ledger_id != self.id or head.hash != self.hash_alg:
            fail("a state commitment is for another ledger or hash")
        if head.tree_size != index:
            fail("a state commitment's tree size is not its own index")
        self.check_signed_head(head, self.log_key_for_size(index), "a state commitment")
        if entry.id != self.h(head.sign1.to_be_signed()):
            fail("a state commitment's entry id is not its id")
        self.commitments[index] = head
        return head

    def apply(self, entry: protocol.LogEntry, index: int) -> Applied:
        """Replays one signed statement at its registration time."""
        statement = protocol.parse_statement(entry.statement)
        now = entry.registered_at
        sid = self.h(statement.sign1.to_be_signed())
        if entry.id != sid:
            fail(f"entry {index}'s id is not its statement's id")
        if statement.type == GENESIS:
            fail(f"entry {index} is a second genesis")
        # Identity and integrity.
        if statement.ledger_id != self.id:
            fail(f"the statement at {index} is for another ledger")
        if sid in self.statement_ids:
            fail(f"the statement at {index} is registered already")
        if (statement.actor, statement.nonce) in self.nonces:
            fail(f"the statement at {index} repeats an (actor, nonce) pair")
        if statement.issued_at > now + MAX_FUTURE_MS:
            fail(f"the statement at {index} is issued more than 5 minutes after its registration")
        signer = self.actors.get(statement.actor)
        if signer is None:
            fail(f"the statement at {index} is signed by an actor the bundle does not register")
        if signer.revoked:
            fail(f"the statement at {index} is signed by a revoked actor")
        self._check_signed_by(statement, signer.key,
                              f"the statement at {index} is not signed with its actor's current key")
        if signer.kind == AGENT and (statement.provenance is None or statement.provenance.model is None):
            fail(f"the agent's statement at {index} names no model in its provenance")
        proven = None
        if statement.presence is not None:
            if signer.kind != PERSON:
                fail(f"the statement at {index} carries proof of presence, but only people prove presence")
            proven = presence.verify(self.h, statement, signer.credentials)

        record_types = self._record_types(statement)
        chain = self._authorize(statement, signer, proven, now, record_types, index)

        handler = {
            ACTOR_REGISTER: self._actor_register,
            ACTOR_ROTATE_KEY: self._actor_rotate_key,
            ACTOR_REVOKE: self._actor_revoke,
            DELEGATION_GRANT: self._delegation_grant,
            DELEGATION_REVOKE: self._delegation_revoke,
            ACTOR_SET_PRESENCE: self._actor_set_presence,
            LEDGER_ROTATE_LOG_KEY: self._ledger_rotate_log_key,
            RECORD_REGISTER: self._record_register,
            RECORD_ENDORSE: self._record_endorse,
            RECORD_TRANSITION: self._record_transition,
            RECORD_REVOKE: self._record_revoke,
            CONTRACT_DEPLOY: self._contract_deploy,
            CONTRACT_CALL: self._contract_call,
            CONTRACT_RETIRE: self._contract_retire,
        }[statement.type]
        applied = Applied(index=index, registered_at=now, statement=statement, id=sid, signer=signer.id,
                          chain=[d.id for d in chain], presence=proven)
        handler(applied, signer, chain)
        self.statement_ids.add(sid)
        self.nonces.add((statement.actor, statement.nonce))
        self.applied[index] = applied
        return applied

    # -- authority --------------------------------------------------------

    def _record_types(self, statement) -> list[str] | None:
        """The record types a record statement's scope must cover: the
        registration's type and, for a new version, the superseded record's
        type (when the bundle holds it); the target record's otherwise."""
        f = statement.fields
        if statement.type == RECORD_REGISTER:
            types = [f["record_type"]]
            old = self.records.get(f["supersedes"]) if f["supersedes"] else None
            if old is not None:
                types.append(old.type)
            return types
        if statement.type in RECORD_STATEMENTS:
            record = self.records.get(f["target"] if statement.type == RECORD_REVOKE else f["record"])
            if record is None:
                fail("a record statement names a record the bundle does not register")
            return [record.type]
        return None

    def _authorize(self, statement, signer: Actor, proven, now: int, record_types, index: int) -> list:
        """Section 5, authority. Returns the delegation chain, the signer's
        own delegation first; empty for the organization and the
        exceptions."""
        kind = statement.type
        if signer.kind == ORGANIZATION:
            if statement.delegation is not None:
                fail(f"the organization acts without a delegation (statement {index})")
            return []
        if kind in (GENESIS, LEDGER_ROTATE_LOG_KEY):
            fail(f"only the organization may submit a {protocol.STATEMENT_TYPE_NAMES[kind]} (statement {index})")
        own = kind in (ACTOR_ROTATE_KEY, ACTOR_SET_PRESENCE) and statement.fields["actor"] == signer.id
        if statement.delegation is None:
            if own:
                # The exceptions: an actor rotates its own key; a person
                # replaces their own credentials (proof checked by the body).
                return []
            fail(f"the statement at {index} is not authorized: its signer acts without a delegation")
        delegation = self.delegations.get(statement.delegation)
        if delegation is None:
            fail(f"the statement at {index} acts under a delegation the bundle does not hold")
        if delegation.grantee != signer.id:
            fail(f"the statement at {index} acts under a delegation granted to another actor")
        chain = []
        current = delegation
        while current is not None:
            chain.append(current)
            if len(chain) > MAX_CHAIN:
                fail(f"the statement at {index} acts under a chain of more than 16 delegations")
            current = self.delegations[current.parent] if current.parent is not None else None
        for d in chain:
            if d.revoked:
                fail(f"the statement at {index} acts under a revoked delegation")
            if d.scope.not_before is not None and now < d.scope.not_before:
                fail(f"the statement at {index} acts under a delegation not valid yet")
            if d.scope.not_after is not None and now > d.scope.not_after:
                fail(f"the statement at {index} acts under an expired delegation")
            if self.actors[d.grantor].revoked:
                fail(f"the statement at {index} acts under a delegation granted by a revoked actor")
        scope = delegation.scope
        if kind not in scope.types:
            fail(f"the statement at {index} is not covered by its delegation's statement types")
        if record_types is not None and scope.record_types is not None:
            for t in record_types:
                if t not in scope.record_types:
                    fail(f"the statement at {index} is not covered by its delegation's record types")
        self.check_contract_scope(statement, scope, index)
        if any(d.scope.presence for d in chain) and proven is None:
            fail(f"the statement at {index} lacks the proof of presence its delegation requires")
        return chain

    # -- bodies -----------------------------------------------------------

    def _actor_register(self, applied: Applied, signer, chain):
        f = applied.statement.fields
        self._check_new_actor_key(f["key"], None)
        if f["kind"] == AGENT and f["responsible"] is None:
            fail("an agent's registration names no responsible person")
        if f["responsible"] is not None:
            person = self.actors.get(f["responsible"])
            if person is None:
                fail("an agent's responsible person is not in the bundle")
            if person.kind != PERSON:
                fail("an agent's responsible actor is not a person")
            if person.revoked:
                fail("an agent's responsible person has been revoked")
        self.actors[applied.id] = Actor(id=applied.id, kind=f["kind"], name=f["name"], key=f["key"],
                                        responsible=f["responsible"], profile=f["profile"],
                                        history=[applied.index])

    def _target_actor(self, actor_id: bytes) -> Actor:
        actor = self.actors.get(actor_id)
        if actor is None:
            fail("a statement names an actor the bundle does not register")
        if actor.revoked:
            fail("a statement names a revoked actor")
        return actor

    def _actor_rotate_key(self, applied: Applied, signer: Actor, chain):
        f = applied.statement.fields
        target = self._target_actor(f["actor"])
        if target.id == self.id and signer.id != self.id:
            fail("only the organization rotates its root key")
        self._check_new_actor_key(f["key"], target)
        if target.id == signer.id and signer.kind == PERSON and signer.credentials:
            if applied.presence is None or not applied.presence.user_verified:
                fail("a person with presence credentials rotates their own key only with user-verified presence")
        target.key = f["key"]
        target.history.append(applied.index)
        if target.id == self.id:
            self.root_rotations += 1

    def _actor_revoke(self, applied: Applied, signer, chain):
        target = self._target_actor(applied.statement.fields["target"])
        if target.id == self.id:
            fail("the organization actor cannot be revoked")
        target.revoked = True
        target.history.append(applied.index)

    def _delegation_grant(self, applied: Applied, signer: Actor, chain):
        f = applied.statement.fields
        grantee = self._target_actor(f["grantee"])
        scope: protocol.Scope = f["scope"]
        if GENESIS in scope.types or LEDGER_ROTATE_LOG_KEY in scope.types:
            fail("a scope never covers genesis or ledger-rotate-log-key")
        parent = None
        if signer.kind != ORGANIZATION:
            parent_delegation = chain[0]
            parent = parent_delegation.id
            p = parent_delegation.scope
            if not p.may_delegate:
                fail("the grantor's delegation may not be delegated further")
            if not set(scope.types) <= set(p.types):
                fail("delegated statement types exceed the grantor's")
            if p.record_types is not None and (scope.record_types is None
                                               or not set(scope.record_types) <= set(p.record_types)):
                fail("delegated record types exceed the grantor's")
            if p.not_before is not None and (scope.not_before is None or scope.not_before < p.not_before):
                fail("delegated validity starts before the grantor's")
            if p.not_after is not None and (scope.not_after is None or scope.not_after > p.not_after):
                fail("delegated validity ends after the grantor's")
            if p.presence and not scope.presence:
                fail("a delegation under one that requires presence must require it too")
            for name in ("contracts", "functions", "request_kinds"):
                theirs, ours = getattr(p, name), getattr(scope, name)
                if theirs is not None and (ours is None or not set(ours) <= set(theirs)):
                    fail(f"delegated {name.replace('_', ' ')} exceed the grantor's")
            if len(chain) + 1 > MAX_CHAIN:
                fail("a delegation chain holds at most 16 delegations")
        self.delegations[applied.id] = Delegation(id=applied.id, grantor=signer.id, grantee=grantee.id,
                                                  scope=scope, parent=parent, history=[applied.index])

    def _delegation_revoke(self, applied: Applied, signer: Actor, chain):
        delegation = self.delegations.get(applied.statement.fields["target"])
        if delegation is None:
            fail("a delegation revocation names a delegation the bundle does not hold")
        if signer.id not in (delegation.grantor, self.id):
            fail("only the grantor or the organization may revoke a delegation")
        if delegation.revoked:
            fail("the delegation is revoked already")
        delegation.revoked = True
        delegation.history.append(applied.index)

    def _actor_set_presence(self, applied: Applied, signer: Actor, chain):
        f = applied.statement.fields
        person = self._target_actor(f["actor"])
        if person.kind != PERSON:
            fail("only people have presence credentials")
        for credential in f["credentials"]:
            key = credential.key
            if crypto.is_weak(key):
                fail("a presence credential's key is weak")
            if self._actor_with_key(key) is not None:
                fail("a presence credential's key is an actor's key")
            if self._is_log_key(key):
                fail("a presence credential's key is a log key")
        if person.id == signer.id and (not chain or person.credentials):
            # A person replaces their own credentials while proving presence
            # with one already registered, user-verified (sections 5 and 7).
            if applied.presence is None or not applied.presence.user_verified:
                fail("a person replaces their own credentials only with user-verified presence")
        person.credentials = list(f["credentials"])
        person.history.append(applied.index)

    def _ledger_rotate_log_key(self, applied: Applied, signer: Actor, chain):
        key = applied.statement.fields["key"]
        if signer.id != self.id:
            fail("only the organization rotates the log key")
        if crypto.is_weak(key):
            fail("the new log key is weak")
        if self._actor_with_key(key) is not None:
            fail("the new log key is an actor's key")
        if self._is_log_key(key):
            fail("the new log key was a log key of this ledger before")
        self.log_keys.append((applied.index, key))
        self.actors[self.id].history.append(applied.index)

    def _record(self, record_id: bytes) -> Record:
        record = self.records.get(record_id)
        if record is None:
            fail("a record statement names a record the bundle does not register")
        if record.revoked:
            fail("a revoked record accepts no further statements")
        return record

    def _record_register(self, applied: Applied, signer: Actor, chain):
        f = applied.statement.fields
        kind = f["record_type"]
        if kind.encode("utf-8").startswith(RESERVED_PREFIX.encode()) and kind not in MECHANISM_TYPES:
            fail(f"the record type {kind!r} is reserved")
        old = None
        if f["supersedes"] is not None:
            if kind in MECHANISM_TYPES:
                fail("a mechanism type supersedes no record")
            old = self.records.get(f["supersedes"])
            # A superseded record the bundle does not hold is checked by its
            # own bundle (section 11, step 3).
            if old is not None:
                if old.type in MECHANISM_TYPES:
                    fail("a record of a mechanism type is not superseded")
                if old.superseded_by is not None:
                    fail("the record was superseded already")
        initial = MECHANISM_TYPES[kind][0] if kind in MECHANISM_TYPES else GENERIC_INITIAL
        self.records[applied.id] = Record(
            id=applied.id, type=kind, field_root=f["field_root"], field_count=f["field_count"],
            attachments=f["attachments"], metadata=f["metadata"], supersedes=f["supersedes"],
            registrant=signer.id, state=initial, history=[applied.index])
        if old is not None:
            # The registration is a statement about both records (section 9).
            old.superseded_by = applied.id
            old.history.append(applied.index)

    def _record_endorse(self, applied: Applied, signer: Actor, chain):
        f = applied.statement.fields
        record = self._record(f["record"])
        if record.type in MECHANISM_TYPES:
            fail("the role is not defined for this record type")
        if (signer.id, f["role"]) in record.endorsements:
            fail("an actor endorses a record at most once per role")
        record.endorsements.add((signer.id, f["role"]))
        record.history.append(applied.index)

    def _record_transition(self, applied: Applied, signer: Actor, chain):
        f = applied.statement.fields
        record = self._record(f["record"])
        if f["from"] != record.state:
            fail("a transition does not start from the record's current state")
        allowed = MECHANISM_TYPES[record.type][1] if record.type in MECHANISM_TYPES else set()
        if (f["from"], f["to"]) not in allowed:
            fail("the record type does not allow this transition")
        record.state = f["to"]
        record.history.append(applied.index)

    def _record_revoke(self, applied: Applied, signer: Actor, chain):
        record = self._record(applied.statement.fields["target"])
        record.revoked = True
        record.history.append(applied.index)

    # -- the replayed state (section 9) ----------------------------------

    def leaf(self, object_id: bytes):
        """The replayed state leaf [kind, id, history] of an object."""
        if object_id in self.actors:
            return [1, object_id, list(self.actors[object_id].history)]
        if object_id in self.delegations:
            return [2, object_id, list(self.delegations[object_id].history)]
        if object_id in self.records:
            return [3, object_id, list(self.records[object_id].history)]
        if object_id in self.contracts:
            return [4, object_id, list(self.contracts[object_id].history)]
        if object_id in self.instances:
            return [5, object_id, list(self.instances[object_id].history)]
        return None
