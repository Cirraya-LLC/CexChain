# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The verification report of an evidence bundle (spec section 11, "A
report states"), as JSON and as text for people. An instance's bundle is
reported the same way, its calls as its events (contract_report.py reports
contract evidence).

The JSON uses the field names of `cexchain verify --json`, so that the two
verifiers' reports can be compared field by field.
"""

from __future__ import annotations

import datetime

from . import cbor, crypto, rules
from .evidence import Report
from .protocol import (AGENT, CONTRACT_CALL, ORGANIZATION, PERSON, RECORD_ENDORSE, RECORD_REGISTER, RECORD_REVOKE,
                       RECORD_TRANSITION)

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
INCOMPLETE = ("The checkpoint does not end with a state commitment, so the bundle cannot prove that nothing, "
              "such as a later revocation, was left out.")


def iso_time(ms: int | None) -> str | None:
    if ms is None:
        return None
    t = _EPOCH + datetime.timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def human_time(ms: int) -> str:
    t = _EPOCH + datetime.timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%d %H:%M:%S UTC")


def json_value(value):
    """A CBOR value as JSON: byte strings in CBOR diagnostic notation
    (h'...'), as `cexchain verify --json` writes them."""
    if isinstance(value, bytes):
        return f"h'{value.hex()}'"
    if isinstance(value, list):
        return [json_value(v) for v in value]
    if isinstance(value, dict):
        return {k if isinstance(k, str) else str(json_value(k)): json_value(v) for k, v in value.items()}
    if isinstance(value, cbor.Map):
        return [[json_value(k), json_value(v)] for k, v in value.pairs]
    if isinstance(value, cbor.Tag):
        return {"tag": value.tag, "value": json_value(value.value)}
    return value


def _key(public: crypto.PublicKey) -> dict:
    return {"algorithm": public.name, "key": public.key.hex()}


def actor_json(ledger: rules.Ledger, actor_id: bytes) -> dict:
    actor = ledger.actors[actor_id]
    out = {"id": actor.id.hex(), "kind": rules.KIND_NAMES[actor.kind], "name": actor.name}
    if actor.kind == AGENT:
        profile = actor.profile or {}
        responsible = ledger.actors.get(actor.responsible) if actor.responsible else None
        out["model"] = profile.get(1)
        out["model_version"] = profile.get(2)
        out["responsible"] = responsible.name if responsible else None
    out["revoked"] = actor.revoked
    return out


def _signer_tags(ledger: rules.Ledger, applied: rules.Applied) -> str:
    actor = ledger.actors[applied.signer]
    if actor.kind == ORGANIZATION:
        return "organization"
    since = ", since revoked" if actor.revoked else ""
    if actor.kind == PERSON:
        if applied.presence is None:
            return f"person{since}; presence not proven"
        if applied.presence.method == "webauthn":
            verified = ", user verified" if applied.presence.user_verified else ""
            return f"person{since}; present: passkey{verified}"
        return f"person{since}; present: hardware key"
    if actor.kind == AGENT:
        provenance = applied.statement.provenance
        model = provenance.model if provenance and provenance.model else (actor.profile or {}).get(1)
        responsible = ledger.actors.get(actor.responsible) if actor.responsible else None
        tags = f"AI agent{since}: {model}; responsible: {responsible.name if responsible else 'unknown'}"
        if provenance and provenance.tools:
            tags += "; via " + ", ".join(name for name, _ in provenance.tools)
        return tags
    return f"device{since}"


def by_whom(ledger: rules.Ledger, applied: rules.Applied) -> str:
    return f'by "{ledger.actors[applied.signer].name}" [{_signer_tags(ledger, applied)}]'


def _event_text(ledger: rules.Ledger, record: rules.Record | None, applied: rules.Applied):
    """(summary, detail, new version) of one event of the record, or one
    call of the instance."""
    statement = applied.statement
    f = statement.fields
    by = by_whom(ledger, applied)
    if statement.type == CONTRACT_CALL:
        verb = "create with" if f["contract"] is not None else "call"
        return f"{verb} {f['function']} {by}", f["function"], None
    if statement.type == RECORD_REGISTER:
        if applied.id != record.id:
            new = ledger.records[applied.id]
            return (f"superseded by a new version ({new.type}, id {new.id.hex()[:12]}) registered {by}",
                    new.type, new.id.hex())
        return f"registered {by}", "", None
    if statement.type == RECORD_ENDORSE:
        return f"endorsed as {f['role']} {by}", f["role"], None
    if statement.type == RECORD_TRANSITION:
        return f"moved {f['from']} -> {f['to']} {by}", f"{f['from']} -> {f['to']}", None
    if statement.type == RECORD_REVOKE:
        reason = f["reason"] or ""
        return f"revoked {by}" + (f" ({reason})" if reason else ""), reason, None
    return f"{statement.type_name} {by}", "", None


def provenance_json(p) -> dict | None:
    if p is None:
        return None
    return {"model": p.model, "model_version": p.model_version,
            "input_commitment": p.input_commitment.hex() if p.input_commitment is not None else None,
            "tools": [{"name": n, "digest": d.hex()} for n, d in p.tools]}


def presence_json(r) -> dict | None:
    if r is None:
        return None
    return {"method": r.method, "user_verified": r.user_verified, "origin": r.origin, "rp_id": r.rp_id,
            "label": r.label}


def authority_json(ledger: rules.Ledger, applied: rules.Applied) -> list:
    """The grantors of the delegation chain, the signer's own first."""
    out = []
    for delegation_id in applied.chain:
        grantor = ledger.actors[ledger.delegations[delegation_id].grantor]
        out.append({"id": grantor.id.hex(), "kind": rules.KIND_NAMES[grantor.kind], "name": grantor.name,
                    "revoked": grantor.revoked})
    return out


def _subject_json(report: Report) -> dict:
    """The record; an instance is shown as a record without a type, its
    status as its state."""
    record = report.record
    if record is None:
        instance = report.instance
        return {"id": instance.id.hex(), "type": "", "state": instance.status or "", "revoked": False,
                "metadata": None, "supersedes": None, "superseded_by": None}
    return {"id": record.id.hex(), "type": record.type, "state": record.state, "revoked": record.revoked,
            "metadata": json_value(record.metadata) if record.metadata is not None else None,
            "supersedes": record.supersedes.hex() if record.supersedes else None,
            "superseded_by": record.superseded_by.hex() if record.superseded_by else None}


def _event_json(report: Report, applied: rules.Applied) -> dict:
    ledger = report.ledger
    statement = applied.statement
    summary, detail, new_version = _event_text(ledger, report.record, applied)
    return {
        "index": applied.index,
        "registered_at": iso_time(applied.registered_at),
        "issued_at": iso_time(statement.issued_at),
        "type": statement.type_name,
        "summary": summary,
        "actor": actor_json(ledger, applied.signer),
        "authority": authority_json(ledger, applied),
        "provenance": provenance_json(statement.provenance),
        "presence": presence_json(applied.presence),
        "detail": detail,
        "new_version": new_version,
        "existed_by": iso_time(report.existed_by.get(applied.index)),
    }


def to_json(report: Report) -> dict:
    ledger, checkpoint = report.ledger, report.checkpoint
    registration = report.events[0].index
    return {
        "verified": True,
        "ledger": {"id": ledger.id.hex(), "organization": ledger.name,
                   "hash": crypto.HASH_NAMES[ledger.hash_alg], "id_checked": report.id_checked},
        "checkpoint": {"ledger_id": checkpoint.ledger_id.hex(), "tree_hash": crypto.HASH_NAMES[checkpoint.hash],
                       "tree_size": checkpoint.tree_size, "root": checkpoint.root.hex(),
                       "timestamp": iso_time(checkpoint.timestamp)},
        "keys": {"log_key": _key(report.log_key), "log_key_rotations": len(ledger.log_keys) - 1,
                 "root_key_rotations": ledger.root_rotations},
        "witnesses": {"trusted": report.witnesses_trusted, "untrusted": report.witnesses_untrusted},
        "timestamps": {
            "trusted_authorities": report.trusted_authorities,
            "existed_by": iso_time(report.existed_by.get(registration)),
            "tokens": [{"checkpoint_size": t.checkpoint_size, "time": iso_time(t.info.time_ms),
                        "accuracy_ms": t.info.accuracy_ms, "authority": t.info.authority,
                        "trusted": t.info.trusted} for t in report.tokens],
        },
        "record": _subject_json(report),
        "events": [_event_json(report, applied) for applied in report.events],
        "disclosed_fields": {name: json_value(value) for name, value in report.disclosed},
        "attachments": [{"name": n, "media_type": m, "size": s, "status": st} for n, m, s, st in report.attachments],
        "complete": report.complete,
        "state_commitment": None if report.commitment is None else {
            "index": report.commitment_index, "state_root": report.commitment.root.hex(),
            "timestamp": iso_time(report.commitment.timestamp)},
        # Why the report is not complete, for people (section 11, step 7).
        "limits": None if report.complete else INCOMPLETE,
    }


def to_text(report: Report) -> str:
    ledger, record, checkpoint = report.ledger, report.record, report.checkpoint
    lines = ["CexChain evidence report (independent Python verifier)", ""]
    lines.append(f"  Ledger       {ledger.name} (id {ledger.id.hex()[:12]}, {crypto.HASH_NAMES[ledger.hash_alg]})")
    if not report.id_checked:
        lines.append("               ! not compared with an expected ledger id")
    lines.append(f"  Checkpoint   size {checkpoint.tree_size}, signed {human_time(checkpoint.timestamp)} "
                 "by the ledger's log key")
    log_rotations = len(ledger.log_keys) - 1
    if log_rotations or ledger.root_rotations:
        lines.append(f"  Keys         log key rotated {log_rotations} time(s), root key "
                     f"{ledger.root_rotations} time(s); every rotation checked")
    witnesses = f"  Witnesses    {report.witnesses_trusted} trusted"
    if report.witnesses_untrusted:
        witnesses += f", {report.witnesses_untrusted} not trusted (not counted)"
    lines.append(witnesses)
    if report.tokens:
        lines.append(f"  Time-stamps  {report.trusted_authorities} trusted authorit"
                     f"{'y' if report.trusted_authorities == 1 else 'ies'}")
        for t in report.tokens:
            trust = "" if t.info.trusted else " (not trusted)"
            lines.append(f"               {t.info.authority} saw checkpoint size {t.checkpoint_size} at "
                         f"{human_time(t.info.time_ms)} (+/- {t.info.accuracy_ms} ms){trust}")
        existed = report.existed_by.get(report.events[0].index)
        if existed is not None:
            lines.append(f"  Existed by   {human_time(existed)}, as a time-stamp authority you trust saw it")
    if record is None:
        instance = report.instance
        lines.append(f"  Instance     id {instance.id.hex()[:12]} of contract {instance.contract.hex()[:12]}")
        lines.append(f"  Status       {instance.status or '(none)'}" + (" - FINAL" if instance.final else ""))
        lines.append("               (contract verify reports its calls' outcomes and consents)")
    else:
        lines.append(f"  Record       {record.type} (id {record.id.hex()[:12]})")
        lines.append(f"  State        {record.state}" + (" - REVOKED" if record.revoked else ""))
        for key, value in (record.metadata or {}).items():
            lines.append(f"  Metadata     {key} = {json_value(value)}")
        if record.supersedes:
            lines.append(f"  Supersedes   id {record.supersedes.hex()[:12]}")
        if record.superseded_by:
            lines.append(f"  Superseded   by a newer version, id {record.superseded_by.hex()[:12]} "
                         "(verify it to see whether it is the latest)")
    lines += ["", "  History"]
    for applied in report.events:
        summary, _, _ = _event_text(ledger, record, applied)
        lines.append(f"    #{applied.index:<4} {human_time(applied.registered_at)}  {summary}")
        if applied.chain:
            names = [ledger.actors[ledger.delegations[d].grantor].name for d in applied.chain]
            lines.append("           authorized by " + " <- ".join(names))
        provenance = applied.statement.provenance
        if provenance is not None and provenance.model:
            version = f" {provenance.model_version}" if provenance.model_version else ""
            lines.append(f"           AI provenance: {provenance.model}{version}")
        if report.existed_by.get(applied.index) is not None:
            lines.append(f"           existed by {human_time(report.existed_by[applied.index])}")
    if report.disclosed:
        lines += ["", "  Disclosed fields (each proven against the record's commitment)"]
        lines += [f"    {name} = {json_value(value)}" for name, value in report.disclosed]
    if report.attachments:
        lines += ["", "  Attachments"]
        words = {"verified": "matches", "mismatch": "DOES NOT MATCH",
                 "not-provided": "not checked (attachment content or opening not provided)"}
        lines += [f"    {n} ({m}, {s} bytes): {words[st]}" for n, m, s, st in report.attachments]
    lines += ["", "  Verified: every statement above is signed, authorized under the ledger's rules,",
              "  and included in the checkpointed log."]
    if report.complete:
        lines += [f"  Complete: the history of the {'record' if record is not None else 'instance'} and of "
                  "everyone involved is proven",
                  "  against the state commitment in the log; nothing was left out."]
    else:
        lines += ["  NOT complete: the bundle carries no state commitment for its checkpoint, so it",
                  "  cannot prove that nothing, such as a later revocation, was left out."]
    return "\n".join(lines)


__all__ = ["actor_json", "authority_json", "by_whom", "human_time", "iso_time", "presence_json", "provenance_json",
           "to_json", "to_text"]
