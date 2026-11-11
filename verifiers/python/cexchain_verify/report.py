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

from . import cbor, claims, crypto, rules
from .evidence import Report
from .protocol import (AGENT, CONTRACT_CALL, ORGANIZATION, PERSON, RECORD_ENDORSE, RECORD_REGISTER, RECORD_REVOKE,
                       RECORD_TRANSITION)

INCOMPLETE = ("The checkpoint does not end with a state commitment, so the bundle cannot prove that nothing, "
              "such as a later revocation, was left out.")


def _utc(ms: int) -> tuple:
    """(year, month, day, hour, minute, second, millisecond) of a POSIX time
    in milliseconds, in the proleptic Gregorian calendar, for any integer:
    a network witness's time is 8 bytes, beyond the years datetime knows
    (days to civil date, as in H. Hinnant's "chrono-Compatible Low-Level
    Date Algorithms")."""
    days, rest = divmod(ms, 86_400_000)
    z = days + 719_468
    era = z // 146_097
    doe = z - era * 146_097
    yoe = (doe - doe // 1460 + doe // 36_524 - doe // 146_096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    year = yoe + era * 400 + (month <= 2)
    seconds, millis = divmod(rest, 1000)
    return year, month, day, seconds // 3600, seconds // 60 % 60, seconds % 60, millis


def iso_time(ms: int | None) -> str | None:
    if ms is None:
        return None
    y, mo, d, h, mi, s, millis = _utc(ms)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{millis:03d}Z"


def human_time(ms: int) -> str:
    y, mo, d, h, mi, s, _ = _utc(ms)
    return f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d} UTC"


def witnesses_json(report: Report) -> dict:
    """The witnesses (section 11, "A report states"): how many trusted ones
    cosigned, each once, the open networks' among them, how many others did,
    and each open-network cosignature with the size it cosigned and its
    time (v0.13)."""
    return {"trusted": report.witnesses_trusted, "untrusted": report.witnesses_untrusted,
            "network": [{"witness": n.witness, "size": n.size, "time": iso_time(n.time * 1000), "trusted": n.trusted}
                        for n in report.network]}


def witnesses_text(report: Report) -> list:
    line = f"  Witnesses    {report.witnesses_trusted} trusted"
    if report.witnesses_untrusted:
        line += f", {report.witnesses_untrusted} not trusted (not counted)"
    lines = [line]
    for n in report.network:
        trust = "a network witness you trust" if n.trusted else "not trusted, not checked"
        lines.append(f"               {n.witness} saw size {n.size} by {human_time(n.time * 1000)} ({trust})")
    if report.network:
        lines.append("               (a network witness's time is its own clock's, relied on for nothing)")
    return lines


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


def source_status(ledger: rules.Ledger, claim: claims.Claim) -> str:
    """A claim's source as the replay leaves it (section 11): live, revoked,
    or replaced by a newer version. A revoked source that a newer version
    also superseded is reported revoked."""
    source = ledger.records[claim.source]
    if source.revoked:
        return "revoked"
    return "replaced" if source.superseded_by is not None else "live"


def lapsed(report: Report, claim: claims.Claim) -> bool:
    """Whether the checkpoint's time is past the claim's until."""
    return claim.until is not None and report.checkpoint.timestamp > claim.until


def claim_json(report: Report, claim: claims.Claim) -> dict:
    """What a report states of a claim (section 11, v0.14): its condition, as
    terms and in words, whether it holds, the subject, as_of and until, whether
    it has lapsed, the access request it answers, and its source's id, type,
    and status. Nothing of the source's fields."""
    return {"source": claim.source.hex(), "source_type": report.ledger.records[claim.source].type,
            "source_status": source_status(report.ledger, claim),
            "condition": [[t.field, t.op, t.type, json_value(t.value)] for t in claim.condition],
            "text": claims.words(claim.condition), "holds": claim.holds, "as_of": iso_time(claim.as_of),
            "until": iso_time(claim.until), "lapsed": lapsed(report, claim), "subject": claim.subject,
            "for": [x.hex() for x in claim.for_] if claim.for_ is not None else None}


def membership_json(m) -> dict:
    """What a report states of a membership proof (section 11, v0.16): the
    trust node's ledger id, whether it is trusted, and the name the
    verifier's list gives it (None when untrusted: never a name from the
    evidence); the membership's id and values; and where it stood when the
    record was registered and at the proof's checkpoint, with both times.
    Times are ISO 8601, as everywhere in the report."""
    v = m.values
    return {"trust_node": m.trust_node.hex(), "trusted": m.trusted, "trust_node_name": m.trust_node_name,
            "membership": m.membership.hex(), "kind": v.kind, "name": v.name, "verified": v.verified,
            "registration": v.registration, "jurisdiction": v.jurisdiction, "until": iso_time(v.until),
            "registered_at": iso_time(m.registered_at), "record_time": iso_time(m.record_time),
            "at_record": m.at_record, "checkpoint_time": iso_time(m.checkpoint_time),
            "at_checkpoint": m.at_checkpoint}


_STANDING_WORDS = {"not_yet": "NOT YET a member", "active": "active", "suspended": "SUSPENDED", "ended": "ENDED",
                   "revoked": "REVOKED", "lapsed": "LAPSED"}


def membership_text(m, subject: str) -> list:
    v = m.values
    if m.trusted:
        lines = [f"  Member       per {m.trust_node_name} (trust node {m.trust_node.hex()[:12]}), which you trust"]
    else:
        lines = [f"  Member       per trust node {m.trust_node.hex()[:12]}, which you have not chosen: not relied on"]
    who = f"{v.name} ({v.kind}, {'verified' if v.verified else 'self-declared'})"
    if v.registration is not None:
        who += f", registration {v.registration}"
    if v.jurisdiction is not None:
        who += f", {v.jurisdiction}"
    lines.append(f"               {who}")
    if v.until is not None:
        lines.append(f"               until {human_time(v.until)}")
    lines.append(f"               {_STANDING_WORDS[m.at_record]} when the {subject} was registered; "
                 f"{_STANDING_WORDS[m.at_checkpoint]} at the proof's checkpoint ({human_time(m.checkpoint_time)})")
    return lines


def _subject_json(report: Report) -> dict:
    """The record; an instance is shown as a record without a type, its
    status as its state."""
    record = report.record
    if record is None:
        instance = report.instance
        return {"id": instance.id.hex(), "type": "", "state": instance.status or "", "revoked": False,
                "metadata": None, "supersedes": None, "superseded_by": None, "claim": None}
    return {"id": record.id.hex(), "type": record.type, "state": record.state, "revoked": record.revoked,
            "metadata": json_value(record.metadata) if record.metadata is not None else None,
            "supersedes": record.supersedes.hex() if record.supersedes else None,
            "superseded_by": record.superseded_by.hex() if record.superseded_by else None,
            "claim": claim_json(report, record.claim) if record.claim is not None else None}


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
        "witnesses": witnesses_json(report),
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
        "memberships": [membership_json(m) for m in report.memberships],
        "complete": report.complete,
        "state_commitment": None if report.commitment is None else {
            "index": report.commitment_index, "state_root": report.commitment.root.hex(),
            "timestamp": iso_time(report.commitment.timestamp)},
        # Why the report is not complete, for people (section 11, step 7).
        "limits": None if report.complete else INCOMPLETE,
    }


def _claim_text(report: Report, claim: claims.Claim) -> list:
    source = report.ledger.records[claim.source]
    status = source_status(report.ledger, claim)
    lines = [f"  Claim        {claims.words(claim.condition)}",
             f"               {'HOLDS' if claim.holds else 'DOES NOT HOLD'}, as of {human_time(claim.as_of)} "
             "(the issuer's word; the source's fields stay sealed)"]
    if claim.subject is not None:
        lines.append(f"  About        {claim.subject}")
    if claim.until is not None:
        lines.append(f"  Until        {human_time(claim.until)}"
                     + (" - LAPSED at the checkpoint" if lapsed(report, claim) else ""))
    if claim.for_ is not None:
        lines.append(f"  Answers      the access request {claim.for_[1].hex()[:12]} on ledger "
                     f"{claim.for_[0].hex()[:12]}")
    words = {"live": "live", "revoked": "REVOKED since", "replaced": "REPLACED by a newer version since"}
    lines.append(f"  Source       {source.type} (id {source.id.hex()[:12]}), {words[status]}")
    return lines


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
    lines += witnesses_text(report)
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
        if record.claim is not None:
            lines += _claim_text(report, record.claim)
    for m in report.memberships:
        lines += membership_text(m, "record" if record is not None else "instance")
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


__all__ = ["actor_json", "authority_json", "by_whom", "claim_json", "human_time", "iso_time", "membership_json",
           "membership_text", "presence_json", "provenance_json", "source_status", "to_json", "to_text",
           "witnesses_json", "witnesses_text"]
