# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Contracts on a ledger (spec section 15): deploys, calls, and retires
replayed under the ledger rules, each call's contract run again in the
profile of section 14 (wasm.py), with instances created by a call (v0.7) and
requests and answers (v0.8).

ContractRules is the part of rules.Ledger that keeps contracts, instances,
and requests. Like the rest of the replay, it holds only what a bundle
includes: a call on an instance the bundle does not hold is refused, since
its state cannot be known.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import cbor, crypto, wasm
from .errors import VerifyError
from .protocol import CALL, CONTRACT_CALL, CONTRACT_RETIRE, CREATE, EXPIRED, MAX_VALUE, REQUEST_KIND

MAX_DEPTH = 8  # generations below an instance made by a creation (v0.7)
MAX_LIST = 16  # children, requests, and needs in one output
MAX_OPEN = 64  # open requests of one instance (v0.8)
MAX_PARAMS = 4096
MAX_DEADLINE_MS = 31_622_400_000  # 366 days
MAX_PARTIES = 64
MAX_EVENTS = 64
HASH_NAMES = {crypto.SHA256: "sha256", crypto.SM3: "sm3"}
PRESENCE_METHODS = {"webauthn": 1, "hardware-key": 2}


def fail(message: str):
    raise VerifyError(message)


@dataclass
class Contract:
    id: bytes
    code: bytes
    interface: dict  # function name -> CREATE or CALL
    language: str
    compiler: str
    source: bytes | None
    name: str | None
    module: wasm.Module
    retired: bool = False
    history: list = field(default_factory=list)


@dataclass
class Instance:
    id: bytes
    contract: bytes
    head: int
    created_by: int  # the log index of the call that created it
    parent: bytes | None = None
    depth: int = 0
    position: int = 0  # its index among its creating call's children
    state: object = None
    status: str | None = None
    parties: dict = field(default_factory=dict)  # role -> ledger id
    final: bool = False
    history: list = field(default_factory=list)
    requests: list = field(default_factory=list)  # the ids of the requests its calls made, in order
    open: list = field(default_factory=list)


@dataclass
class Request:
    id: bytes
    instance: bytes
    call: int  # the log index of the call that made it
    position: int
    kind: str
    params: object
    deadline: int
    reply: str
    asked_at: int
    status: int | None = None  # the answer's status once answered
    answered_by: int | None = None
    answered_at: int | None = None


@dataclass
class Child:
    state: object
    status: str | None
    parties: dict | None


@dataclass
class Accept:
    state: object
    status: str | None = None
    parties: dict | None = None
    events: list = field(default_factory=list)  # [(name, data)]
    final: bool = False
    children: list = field(default_factory=list)  # [Child]
    requests: list = field(default_factory=list)  # [(kind, params, deadline, reply)]


@dataclass
class Run:
    """A call as replayed: the instance it acted on or created, what the
    contract accepted, and the instances and requests the call made."""
    instance: bytes
    accept: Accept
    children: list  # child ids, by position
    requests: list  # request ids, by position


# ---------------------------------------------------------------------------
# Identifiers (section 15)
# ---------------------------------------------------------------------------

def child_id(h, call: bytes, position: int) -> bytes:
    """HASH(deterministic-CBOR([call, position])) (child-id-input, v0.7)."""
    return h(cbor.encode([call, position]))


def request_id(h, call: bytes, position: int) -> bytes:
    """HASH(deterministic-CBOR(["request", call, position])) (v0.8)."""
    return h(cbor.encode(["request", call, position]))


# ---------------------------------------------------------------------------
# The output (contract-output)
# ---------------------------------------------------------------------------

def _text(v, low: int, high: int) -> bool:
    return isinstance(v, str) and low <= len(v.encode("utf-8")) <= high


def _is_ledger(v) -> bool:
    return isinstance(v, bytes) and len(v) == 32


def _is_uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _value(v, what: str, limit: int = MAX_VALUE):
    if len(cbor.encode(v)) > limit:
        fail(f"{what} is more than {limit:,} bytes encoded")
    return v


def _parties(v, what: str) -> dict:
    if not (isinstance(v, dict) and 1 <= len(v) <= MAX_PARTIES
            and all(_text(role, 1, 64) and _is_ledger(ledger) for role, ledger in v.items())):
        fail(f"{what} are not 1 to 64 roles of 1 to 64 bytes, each a ledger id")
    return dict(v)


def _keys(v, what: str, required: set, optional: set) -> dict:
    if not (isinstance(v, dict) and all(isinstance(k, int) and not isinstance(k, bool) for k in v)):
        fail(f"{what} is not a map with integer keys")
    if not required <= set(v) or not set(v) <= required | optional:
        fail(f"{what} has missing or unknown keys")
    return v


def _list(v, what: str, high: int) -> list:
    if not (isinstance(v, list) and 1 <= len(v) <= high):
        fail(f"{what} are not a list of 1 to {high}")
    return v


def parse_output(output: bytes, home: bytes):
    """A contract's output (section 15): ("accept", Accept) or ("needs",
    ledgers). An output that is not well formed raises VerifyError."""
    try:
        value = cbor.decode(output, max_items=cbor.MAX_PAYLOAD_ITEMS)
    except cbor.CborError as e:
        fail(f"the contract's output is not well formed ({e})")
    if not (isinstance(value, list) and len(value) == 2 and value[0] in (1, 2) and not isinstance(value[0], bool)):
        fail("the contract's output is neither [1, accept] nor [2, needs]")
    if value[0] == 2:
        needs = _list(value[1], "the ledgers a needs output names", MAX_LIST)
        if not all(map(_is_ledger, needs)) or any(a >= b for a, b in zip(needs, needs[1:])) or home in needs:
            fail("the ledgers a needs output names are not strictly ascending ledger ids other than the home")
        return "needs", list(needs)
    m = _keys(value[1], "the contract's accept", {1}, {2, 3, 4, 5, 6, 7})
    accept = Accept(state=_value(m[1], "the accept's state"))
    if 2 in m:
        if not _text(m[2], 1, 64):
            fail("the accept's status is not 1 to 64 bytes of text")
        accept.status = m[2]
    if 3 in m:
        accept.parties = _parties(m[3], "the accept's parties")
    if 4 in m:
        for event in _list(m[4], "the accept's events", MAX_EVENTS):
            if not (isinstance(event, list) and len(event) == 2 and _text(event[0], 1, 64)):
                fail("an event is not [name of 1 to 64 bytes, data]")
            accept.events.append((event[0], event[1]))
    if 5 in m:
        if m[5] is not True:
            fail("the accept's key 5 is not true")
        accept.final = True
    for child in _list(m[6], "the accept's children", MAX_LIST) if 6 in m else []:
        c = _keys(child, "a child", {1}, {2, 3})
        if 2 in c and not _text(c[2], 1, 64):
            fail("a child's status is not 1 to 64 bytes of text")
        accept.children.append(Child(state=_value(c[1], "a child's state"), status=c.get(2),
                                     parties=_parties(c[3], "a child's parties") if 3 in c else None))
    for request in _list(m[7], "the accept's requests", MAX_LIST) if 7 in m else []:
        r = _keys(request, "a request", {1, 2, 3, 4}, set())
        if not (isinstance(r[1], str) and REQUEST_KIND.fullmatch(r[1])):
            fail("a request's kind is not a request kind")
        if not _is_uint(r[3]):
            fail("a request's deadline is not a time")
        if not _text(r[4], 1, 64):
            fail("a request's reply is not a function name")
        accept.requests.append((r[1], _value(r[2], "a request's params", MAX_PARAMS), r[3], r[4]))
    return "accept", accept


# ---------------------------------------------------------------------------
# The input (contract-input)
# ---------------------------------------------------------------------------

def signer_map(kind: int, presence_method: int | None, model: str | None) -> dict:
    """signer: {1: kind, ? 2: presence method, ? 3: model} (section 15)."""
    out = {1: kind}
    if presence_method is not None:
        out[2] = presence_method
    if model is not None:
        out[3] = model
    return out


def applied_signer(ledger, applied) -> dict:
    """The signer map of a replayed statement."""
    statement = applied.statement
    provenance = statement.provenance
    return signer_map(ledger.actors[applied.signer].kind,
                      PRESENCE_METHODS[applied.presence.method] if applied.presence is not None else None,
                      provenance.model if provenance is not None else None)


def instance_view(instance: Instance) -> dict:
    view = {1: instance.id, 2: instance.head, 3: instance.state}
    if instance.status is not None:
        view[4] = instance.status
    if instance.parties:
        view[5] = instance.parties
    if instance.parent is not None:
        view[6] = [instance.parent, instance.depth]
    return view


def request_view(request: Request, status: int) -> dict:
    return {1: request.id, 2: request.kind, 3: request.params, 4: request.deadline, 5: request.asked_at, 6: status}


# ---------------------------------------------------------------------------
# The ledger rules for contracts (sections 5 and 15)
# ---------------------------------------------------------------------------

class ContractRules:
    """Mixed into rules.Ledger, which provides h, hash_alg, id, and actors."""

    def _init_contracts(self):
        self.contracts: dict[bytes, Contract] = {}
        self.instances: dict[bytes, Instance] = {}
        self.requests: dict[bytes, Request] = {}
        self.runs: dict[int, Run] = {}

    def contract_target(self, statement) -> bytes | None:
        """The contract a call or a retire acts on (scope key 7): a call on
        an instance acts on the instance's contract."""
        f = statement.fields
        if statement.type == CONTRACT_RETIRE:
            return f["contract"]
        if statement.type != CONTRACT_CALL:
            return None
        if f["contract"] is not None:
            return f["contract"]
        instance = self.instances.get(f["instance"])
        if instance is None:
            fail("a call names an instance the bundle does not hold")
        return instance.contract

    def check_contract_scope(self, statement, scope, index: int):
        """Scope keys 7 to 9 (sections 5 and 15), on the signer's delegation."""
        if statement.type not in (CONTRACT_CALL, CONTRACT_RETIRE):
            return
        if scope.contracts is not None and self.contract_target(statement) not in scope.contracts:
            fail(f"the statement at {index} acts on a contract its delegation does not list")
        if statement.type != CONTRACT_CALL:
            return
        f = statement.fields
        if scope.functions is not None and f["function"] not in scope.functions:
            fail(f"the call at {index} names a function its delegation does not list")
        if scope.request_kinds is not None:
            request = self.requests.get(f["answer"][0]) if f["answer"] is not None else None
            if request is None or request.kind not in scope.request_kinds:
                fail(f"the call at {index} is not an answer to a request of a kind its delegation lists")

    def ancestors(self, instance: Instance) -> list:
        """The instance's ancestors, oldest first."""
        out = []
        while instance.parent is not None:
            instance = self.instances[instance.parent]
            out.insert(0, instance)
        return out

    # -- statements -------------------------------------------------------

    def _contract_deploy(self, applied, signer, chain):
        f = applied.statement.fields
        try:
            module = wasm.load(f["code"])
        except Exception as e:  # any failure to load untrusted code refuses it
            fail(f"a contract's code does not load under the profile ({e})")
        self.contracts[applied.id] = Contract(
            id=applied.id, code=f["code"], interface=f["interface"], language=f["language"],
            compiler=f["compiler"], source=f["source"], name=f["name"], module=module, history=[applied.index])

    def _contract_retire(self, applied, signer, chain):
        contract = self.contracts.get(applied.statement.fields["contract"])
        if contract is None:
            fail("a retire names a contract the bundle does not hold")
        if contract.retired:
            fail("the contract is retired already")
        contract.retired = True
        contract.history.append(applied.index)

    def _contract_call(self, applied, signer, chain):
        f = applied.statement.fields
        now, index = applied.registered_at, applied.index
        answer, consents = f["answer"], f["consents"]
        instance, request = None, None
        if f["contract"] is not None:
            contract = self.contracts.get(f["contract"])
            if contract is None:
                fail("a creation names a contract the bundle does not hold")
            if contract.retired:
                fail("a retired contract creates no more instances")
            if contract.interface.get(f["function"]) != CREATE:
                fail(f"the contract has no function {f['function']!r} that creates an instance")
            if consents:
                fail("a creation cites no consents")
        else:
            instance = self.instances.get(f["instance"])
            if instance is None:
                fail("a call names an instance the bundle does not hold")
            if f["head"] != instance.head:
                fail("a call's head is not its instance's head")
            contract = self.contracts[instance.contract]
            if contract.interface.get(f["function"]) != CALL:
                fail(f"the contract has no function {f['function']!r} that acts on an instance")
            if instance.final and answer is None:
                fail("the instance is final: it takes only answers to its open requests")
        if any(c.ledger == self.id for c in consents):
            fail("a call cites a consent from its home")
        if answer is not None:
            request = self.requests.get(answer[0])
            if request is None or request.instance != instance.id:
                fail("an answer names a request that is not its instance's")
            if request.status is not None:
                fail("the request is answered already")
            if f["function"] != request.reply:
                fail("an answer does not call its request's reply")
            if answer[1] == EXPIRED and now < request.deadline:
                fail("a request expires only once its deadline is reached")
            if consents:
                fail("an answer cites no consents")

        accept = self._run(contract, applied)
        was_final = instance is not None and instance.final
        if accept.children:
            if contract.retired:
                fail("a retired contract creates no more instances, children included")
            if instance is not None and instance.depth >= MAX_DEPTH:
                fail(f"an instance at depth {MAX_DEPTH} creates no children")
        for _, _, deadline, reply in accept.requests:
            if not now < deadline <= now + MAX_DEADLINE_MS:
                fail("a request's deadline is not after the call and within 366 days of it")
            if contract.interface.get(reply) != CALL:
                fail("a request's reply is not a function of the contract that acts on an instance")
        still_open = len(instance.open) - (1 if request is not None else 0) if instance is not None else 0
        if still_open + len(accept.requests) > MAX_OPEN:
            fail(f"the call would leave its instance more than {MAX_OPEN} open requests")
        if was_final and (accept.children or accept.requests):
            fail("a final instance makes no requests and creates no children")

        # The accept applies: the request closes, the instance changes, then
        # its children are created and its requests opened, in order.
        if instance is None:
            instance = Instance(id=applied.id, contract=contract.id, head=index, created_by=index)
            self.instances[instance.id] = instance
        if request is not None:
            request.status, request.answered_by, request.answered_at = answer[1], index, now
            instance.open.remove(request.id)
        instance.head, instance.state = index, accept.state
        if accept.status is not None:
            instance.status = accept.status
        if accept.parties is not None:
            instance.parties = accept.parties
        instance.final = instance.final or accept.final
        instance.history.append(index)
        made = []
        for position, child in enumerate(accept.children):
            cid = child_id(self.h, applied.id, position)
            if cid in self.instances:
                fail("a child's id is an instance's already")
            self.instances[cid] = Instance(
                id=cid, contract=contract.id, head=index, created_by=index, parent=instance.id,
                depth=instance.depth + 1, position=position, state=child.state, status=child.status,
                parties=child.parties or {}, history=[index])
            made.append(cid)
        asked = []
        for position, (kind, params, deadline, reply) in enumerate(accept.requests):
            rid = request_id(self.h, applied.id, position)
            self.requests[rid] = Request(id=rid, instance=instance.id, call=index, position=position, kind=kind,
                                         params=params, deadline=deadline, reply=reply, asked_at=now)
            instance.requests.append(rid)
            instance.open.append(rid)
            asked.append(rid)
        self.runs[index] = Run(instance=instance.id, accept=accept, children=made, requests=asked)

    def call_input(self, applied) -> bytes:
        """contract-input: what a call's contract reads, as the home built it
        when it registered the call (the instance and request it names are
        those the bundle holds)."""
        f = applied.statement.fields
        instance = self.instances[f["instance"]] if f["instance"] is not None else None
        caller = [applied.signer, applied_signer(self, applied)]
        data = {1: f["function"], 2: f["arguments"], 3: self.id,
                4: instance.contract if instance is not None else f["contract"], 6: caller, 7: applied.registered_at}
        if instance is not None:
            data[5] = instance_view(instance)
        if f["consents"]:
            data[8] = [[c.ledger, c.signer] for c in f["consents"]]
        if f["answer"] is not None:
            data[9] = request_view(self.requests[f["answer"][0]], f["answer"][1])
        return cbor.encode(data)

    def _run(self, contract: Contract, applied):
        """Runs the contract on the call's input; the call is refused unless
        it accepts."""
        outcome, output, _, reason = wasm.run(contract.module, self.call_input(applied), HASH_NAMES[self.hash_alg])
        if outcome == "aborted":
            fail("the contract refuses the call: " + reason.decode("utf-8", errors="replace"))
        if outcome != "ok":
            fail(f"the contract traps on the call ({outcome})")
        verdict, result = parse_output(output, self.id)
        if verdict == "needs":
            fail("the contract asks for consents the call does not cite")
        return result


__all__ = ["Accept", "ContractRules", "Contract", "Instance", "Request", "Run", "child_id", "parse_output",
           "request_id"]
