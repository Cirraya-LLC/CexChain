# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The report of contract evidence (spec section 15, "The report shows each
call" and "Requests in evidence"), as JSON and as text for people.

The JSON uses the field names of `kanhe contract verify --json`, so that
the two verifiers' reports can be compared field by field. CBOR values
(arguments, states, params, event data) are shown in CBOR diagnostic
notation (RFC 8949, section 8), and also as hex where that report does.
"""

from __future__ import annotations

from . import cbor, crypto, report, rules
from .contract_evidence import ContractReport
from .protocol import AGENT, ANSWER_STATUS_NAMES, DEVICE, ORGANIZATION, PERSON
from .report import human_time, iso_time


def _text(s: str) -> str:
    out = []
    for ch in s:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def diagnostic(value) -> str:
    """A CBOR value in diagnostic notation: JSON for what JSON has, h'..' for
    byte strings, N(..) for tags, any keys, map entries in canonical order."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return f"h'{value.hex()}'"
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, list):
        return "[" + ", ".join(diagnostic(v) for v in value) + "]"
    if isinstance(value, (dict, cbor.Map)):
        pairs = value.items() if isinstance(value, dict) else value.pairs
        ordered = sorted(pairs, key=lambda kv: cbor.encode(kv[0]))
        return "{" + ", ".join(f"{diagnostic(k)}: {diagnostic(v)}" for k, v in ordered) + "}"
    if isinstance(value, cbor.Tag):
        return f"{value.tag}({diagnostic(value.value)})"
    raise TypeError(f"not a CBOR value: {type(value).__name__}")


def presence_words(ledger: rules.Ledger, applied: rules.Applied) -> str:
    """How a consent was given: by the organization, a person present, or a
    machine."""
    kind = ledger.actors[applied.signer].kind
    if kind == ORGANIZATION:
        return "the organization's own key"
    if kind == PERSON:
        proof = applied.presence
        if proof is None:
            return "a person's key, presence not proven"
        if proof.method != "webauthn":
            return "a person, present: hardware key"
        return "a person, present: passkey" + (", user verified" if proof.user_verified else "")
    return "a machine: " + {AGENT: "AI agent", DEVICE: "device"}[kind]


class _Json:
    def __init__(self, r: ContractReport):
        self.r = r
        self.ledger = r.ledger

    def parties(self, parties: dict | None):
        if parties is None:
            return None
        return {role: {"ledger_id": ledger.hex(), "organization": self.r.names.get(ledger)}
                for role, ledger in parties.items()}

    def request(self, rid: bytes) -> dict:
        q = self.ledger.requests[rid]
        return {"position": q.position, "id": q.id.hex(), "kind": q.kind, "params": diagnostic(q.params),
                "params_cbor": cbor.encode(q.params).hex(), "deadline": iso_time(q.deadline), "reply": q.reply}

    def own_request(self, q) -> dict:
        late = max(0, q.answered_at - q.deadline) if q.answered_at is not None else 0
        return {"id": q.id.hex(), "call": q.call, "position": q.position, "kind": q.kind,
                "params": diagnostic(q.params), "params_cbor": cbor.encode(q.params).hex(),
                "deadline": iso_time(q.deadline), "reply": q.reply, "asked_at": iso_time(q.asked_at),
                "status": ANSWER_STATUS_NAMES.get(q.status, "open"), "answered_by": q.answered_by,
                "answered_at": iso_time(q.answered_at), "late_by_ms": late, "overdue": self.r.overdue(q)}

    def outcome(self, run) -> dict:
        a = run.accept
        out = {"status": a.status, "parties": self.parties(a.parties),
               "events": [{"name": name, "data": diagnostic(data)} for name, data in a.events],
               "final": a.final, "state": diagnostic(a.state)}
        if a.requests:
            out["requests"] = [self.request(rid) for rid in run.requests]
        if a.children:
            out["children"] = [{"position": i, "id": cid.hex(), "status": child.status,
                                "parties": self.parties(child.parties or {}), "state": diagnostic(child.state)}
                               for i, (cid, child) in enumerate(zip(run.children, a.children))]
        return out

    def answer(self, applied: rules.Applied) -> dict | None:
        answer = applied.statement.fields["answer"]
        if answer is None:
            return None
        q = self.ledger.requests[answer[0]]
        late = applied.registered_at - q.deadline
        return {"request": q.id.hex(), "status": ANSWER_STATUS_NAMES[answer[1]], "kind": q.kind, "asked_by": q.call,
                "deadline": iso_time(q.deadline), "late": late > 0, "late_by_ms": max(0, late)}

    def consent(self, c) -> dict:
        ledger, registration = c.report.ledger, c.registration
        names = [ledger.actors[ledger.delegations[d].grantor].name for d in registration.chain]
        return {"ledger_id": c.ref.ledger.hex(), "organization": ledger.name,
                "hash": crypto.HASH_NAMES[ledger.hash_alg], "record": c.ref.record.hex(),
                "signer": report.actor_json(ledger, registration.signer), "authority": names,
                "presence": presence_words(ledger, registration),
                "provenance": report.provenance_json(registration.statement.provenance),
                "given_at": iso_time(registration.registered_at), "until": iso_time(c.terms["until"]),
                "reference": c.terms.get("reference"), "witnesses": report.witnesses_json(c.report)}

    def call(self, applied: rules.Applied) -> dict:
        f = applied.statement.fields
        verb = "create with" if f["contract"] is not None else "call"
        return {"index": applied.index, "registered_at": iso_time(applied.registered_at), "function": f["function"],
                "creates": f["contract"] is not None, "arguments": diagnostic(f["arguments"]),
                "arguments_cbor": cbor.encode(f["arguments"]).hex(), "reference": f["reference"],
                "summary": f"{verb} {f['function']} {report.by_whom(self.ledger, applied)}",
                "called_by": report.actor_json(self.ledger, applied.signer),
                "authority": report.authority_json(self.ledger, applied),
                "presence": report.presence_json(applied.presence),
                "provenance": report.provenance_json(applied.statement.provenance),
                "outcome": self.outcome(self.ledger.runs[applied.index]), "answer": self.answer(applied),
                "consents": [self.consent(c) for c in self.r.consents[applied.index]]}

    def instance(self) -> dict:
        r, i, c = self.r, self.r.instance, self.r.contract
        out = {"id": i.id.hex(), "status": i.status, "parties": self.parties(i.parties), "final": i.final,
               "head": i.head, "state": diagnostic(i.state), "state_cbor": cbor.encode(i.state).hex(),
               "contract": {"id": c.id.hex(), "name": c.name, "language": c.language, "compiler": c.compiler,
                            "retired": c.retired},
               "requests": [self.own_request(q) for q in r.own_requests()],
               "open_requests": [q.id.hex() for q in r.open_requests()],
               "overdue_requests": [q.id.hex() for q in r.open_requests() if r.overdue(q)]}
        if i.parent is not None:
            out.update({"parent": i.parent.hex(), "position": i.position, "depth": i.depth,
                        "created_by": i.created_by, "ancestors": self.ancestors()})
        return out

    def ancestors(self) -> list:
        out, generations = [], self.ledger.ancestors(self.r.instance) + [self.r.instance]
        for ancestor, next_one in zip(generations, generations[1:]):
            until = next_one.created_by
            out.append({"id": ancestor.id.hex(), "depth": ancestor.depth,
                        "parent": ancestor.parent.hex() if ancestor.parent is not None else None,
                        "position": ancestor.position, "created_by": ancestor.created_by, "until": until,
                        "calls": [i for i in ancestor.history if i <= until]})
        return out


def to_json(r: ContractReport) -> dict:
    bundle = report.to_json(r.bundle)
    j = _Json(r)
    return {
        "verified": True,
        "instance": j.instance(),
        "home": bundle["ledger"],
        "checkpoint": bundle["checkpoint"],
        "witnesses": bundle["witnesses"],
        "timestamps": bundle["timestamps"],
        "calls": [j.call(applied) for applied in r.calls],
        "complete": True,
        # The instance's bundle, reported as `verify` reports any bundle.
        "report": bundle,
    }


def to_text(r: ContractReport) -> str:
    ledger, i, c, b = r.ledger, r.instance, r.contract, r.bundle

    def party(ledger_id: bytes) -> str:
        name = r.names.get(ledger_id)
        return f"{name} (ledger {ledger_id.hex()[:12]})" if name else f"ledger {ledger_id.hex()[:12]}"

    def parties(p: dict) -> str:
        return ", ".join(f"{role}: {party(lid)}" for role, lid in sorted(p.items()))

    lines = ["Kanhe contract report (independent Python verifier)", ""]
    name = f' "{c.name}"' if c.name else ""
    lines.append(f"  Instance     {i.id.hex()[:12]} of contract{name} (id {c.id.hex()[:12]})")
    if i.parent is not None:
        lines.append(f"  Part of      {i.parent.hex()[:12]}: part {i.position} of its call #{i.created_by}, "
                     f"depth {i.depth}")
    lines.append(f"  Contract     {c.language}, compiled with {c.compiler}" + ("; RETIRED" if c.retired else ""))
    if c.language == "bo":
        lines.append("               its source was not rebuilt here (no Bo compiler): the code is checked as run")
    lines.append(f"  Home         {ledger.name} (ledger {ledger.id.hex()[:12]}, {crypto.HASH_NAMES[ledger.hash_alg]})")
    if not b.id_checked:
        lines.append("               ! not compared with an expected ledger id")
    lines.append(f"  Status       {i.status or '(none)'}")
    if i.final:
        lines.append("               FINAL: it takes no more calls" +
                     (", except answers to its open requests" if r.open_requests() else ""))
    if i.parties:
        lines.append(f"  Parties      {parties(i.parties)}")
    lines.append(f"  State        {diagnostic(i.state)}")
    lines.append(f"  Checkpoint   size {b.checkpoint.tree_size}, signed {human_time(b.checkpoint.timestamp)} "
                 "by the home's log key")
    lines += report.witnesses_text(b)
    if b.tokens:
        lines.append(f"  Time-stamps  {b.trusted_authorities} trusted authorities")
    lines += ["", "  Calls" + (" (its ancestors' first, up to each one that created the next generation)"
                               if i.parent is not None else "")]
    for applied in r.calls:
        f = applied.statement.fields
        run = ledger.runs[applied.index]
        verb = "create with" if f["contract"] is not None else "call"
        lines.append(f"    #{applied.index:<4} {human_time(applied.registered_at)}  {verb} {f['function']} "
                     f"{report.by_whom(ledger, applied)}")
        if applied.chain:
            names = [ledger.actors[ledger.delegations[d].grantor].name for d in applied.chain]
            lines.append("           authorized by " + " <- ".join(names))
        lines.append(f"           arguments  {diagnostic(f['arguments'])}")
        if f["reference"]:
            lines.append(f"           reference  {f['reference']}")
        a = run.accept
        outcome = [f"status {a.status}" if a.status else "no status"]
        if a.final:
            outcome.append("final")
        if a.parties:
            outcome.append(f"parties {parties(a.parties)}")
        outcome += [f"event {name} {diagnostic(data)}" for name, data in a.events]
        outcome += [f"part {n} {cid.hex()[:12]}: {child.status or 'no status'}"
                    for n, (cid, child) in enumerate(zip(run.children, a.children))]
        lines.append("           outcome    " + "; ".join(outcome))
        for rid in run.requests:
            q = ledger.requests[rid]
            lines.append(f"           request    {q.position} {rid.hex()[:12]}: {q.kind}, due "
                         f"{human_time(q.deadline)}, reply {q.reply}; params {diagnostic(q.params)}")
        answer = f["answer"]
        if answer is not None:
            q = ledger.requests[answer[0]]
            late = applied.registered_at - q.deadline
            when = f"LATE by {late} ms" if late > 0 else "on time"
            lines.append(f"           answers    {q.id.hex()[:12]} ({q.kind}, asked by #{q.call}): "
                         f"{ANSWER_STATUS_NAMES[answer[1]]}, {when}")
        for consent in r.consents[applied.index]:
            cl = consent.report.ledger
            signer = cl.actors[consent.registration.signer]
            reference = consent.terms.get("reference")
            lines.append(f"           consent of {cl.name} ({crypto.HASH_NAMES[cl.hash_alg]}): given by "
                         f'"{signer.name}" ({presence_words(cl, consent.registration)})'
                         + (f", ref. {reference}" if reference else ""))
    own = r.own_requests()
    if own:
        still_open = r.open_requests()
        overdue = [q for q in still_open if r.overdue(q)]
        lines += ["", f"  Requests     {len(own)} made by its calls, {len(own) - len(still_open)} answered, "
                  f"{len(still_open)} open" + (f", {len(overdue)} OVERDUE at the checkpoint" if overdue else "")]
        for q in still_open:
            flag = " - OVERDUE" if r.overdue(q) else ""
            lines.append(f"    {q.id.hex()[:12]} {q.kind}, asked by #{q.call}, due {human_time(q.deadline)}{flag}")
    lines += ["", "  Verified: the instance's complete history is proven against its home's state",
              "  commitment, and its contract was run again on every call, reaching the state above;",
              "  each consent is verified on the consenting party's own ledger."]
    return "\n".join(lines)


__all__ = ["diagnostic", "presence_words", "to_json", "to_text"]
