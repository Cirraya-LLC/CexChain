# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Memberships (spec v0.16, sections 6 and 11): a `kanhe.membership/1`
record is a trust node's word that another ledger (the member) belongs to
the organization or person it names, as it checked them.

The ledger checks a membership's metadata (record key 5, `membership` in the
CDDL) and refuses other keys; parse() does that here. A membership is active
when registered; transitions suspend, resume, and end it, and a revocation
ends it for cause. standing() says where it stood at a time, from its
history; history() reads that history from a replayed ledger. Evidence
bundles carry memberships of their own ledger as proofs (bundle key 9),
which evidence.py verifies (section 11, step 9).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import cbor
from .errors import VerifyError
from .protocol import RECORD_REVOKE, RECORD_TRANSITION

MEMBERSHIP_TYPE = "kanhe.membership/1"
INITIAL = "active"
TRANSITIONS = {("active", "suspended"), ("suspended", "active"), ("active", "ended"), ("suspended", "ended")}
KINDS = ("organization", "person")
# A bundle carries 1 to 16 membership proofs (key 9).
MAX_PROOFS = 16
# Where a membership stood at a time (section 11, step 9).
NOT_YET, ACTIVE, SUSPENDED, ENDED, REVOKED, LAPSED = "not_yet", "active", "suspended", "ended", "revoked", "lapsed"

_REQUIRED = ("member", "kind", "name", "verified")
_OPTIONAL = ("registration", "jurisdiction", "until")
_JURISDICTION = re.compile(r"[A-Z]{2}(-[A-Z0-9]{1,3})?")


class MembershipError(VerifyError):
    """Metadata the ledger refuses as a membership's. `why` names the rule,
    as the test vectors do."""

    def __init__(self, why: str, message: str):
        super().__init__(message)
        self.why = why


@dataclass(frozen=True)
class Membership:
    member: bytes              # the member's ledger id
    kind: str                  # organization or person
    name: str
    verified: bool             # False: the member's own word (self-declared)
    registration: str | None   # a company or registry number
    jurisdiction: str | None   # ISO 3166-1 alpha-2, optionally with an ISO 3166-2 subdivision
    until: int | None          # ms: lapsed after it


def _fail(why: str, message: str):
    raise MembershipError(why, message)


def _text(v, low: int, high: int) -> bool:
    return isinstance(v, str) and low <= len(v.encode("utf-8")) <= high


def parse(metadata) -> Membership:
    """A membership's metadata, as deterministic CBOR bytes or as the decoded
    map, checked as the ledger checks it (section 6). A key whose value is
    not of its type, null included, breaks that key's rule."""
    if isinstance(metadata, (bytes, bytearray)):
        metadata = cbor.decode(bytes(metadata))
    if isinstance(metadata, cbor.Map):
        # The decoder keeps a map as pairs only when a key is not an integer
        # or a string, so some key is not one of the named texts.
        _fail("unknown key", "a membership's metadata has a key that is not text")
    if not isinstance(metadata, dict):
        _fail("no metadata", "a membership has no membership metadata (record key 5)")
    if any(not isinstance(k, str) for k in metadata):
        _fail("unknown key", "a membership's metadata has a key that is not text")
    unknown = set(metadata) - set(_REQUIRED) - set(_OPTIONAL)
    if unknown:
        _fail("unknown key", f"a membership's metadata has an unknown key ({sorted(unknown)[0]!r})")
    missing = [k for k in _REQUIRED if k not in metadata]
    if missing:
        _fail("missing key", f"a membership's metadata lacks {missing[0]!r}")
    m = metadata
    if not (isinstance(m["member"], bytes) and len(m["member"]) == 32):
        _fail("member", "a membership's member is not a 32-byte ledger id")
    if not (isinstance(m["kind"], str) and m["kind"] in KINDS):
        _fail("kind", "a membership's kind is not organization or person")
    if not _text(m["name"], 1, 256):
        _fail("name", "a membership's name is not a text of 1 to 256 bytes")
    if not isinstance(m["verified"], bool):
        _fail("verified", "a membership's verified is not a boolean")
    if "registration" in m and not _text(m["registration"], 1, 64):
        _fail("registration", "a membership's registration is not a text of 1 to 64 bytes")
    if "jurisdiction" in m and not (isinstance(m["jurisdiction"], str)
                                    and _JURISDICTION.fullmatch(m["jurisdiction"])):
        _fail("jurisdiction", "a membership's jurisdiction is not an ISO 3166 code (two upper-case letters, "
                              "optionally - and 1 to 3 upper-case letters or digits)")
    until = m.get("until")
    # bool is an int in Python, but CBOR's true is not an unsigned integer.
    if "until" in m and not (isinstance(until, int) and not isinstance(until, bool) and until > 0):
        _fail("until", "a membership's until is not an unsigned integer above 0")
    return Membership(member=m["member"], kind=m["kind"], name=m["name"], verified=m["verified"],
                      registration=m.get("registration"), jurisdiction=m.get("jurisdiction"), until=until)


def standing(registered_at: int, until: int | None, changes, t: int) -> str:
    """Where a membership stood at time t (section 11, step 9): not yet a
    member before its registration; else revoked if it was revoked at or
    before t; else lapsed if t is after its until; else the state its last
    transition at or before t left, or active if none.

    `changes` are its transitions and revocation in log order, each
    (registration time, the state it moved to, or None for the revocation).
    Of two at one time, the later in the log counts. A proof's history ends
    at its checkpoint, so for a t after it this is the state as of the
    checkpoint, with until applied."""
    if t < registered_at:
        return NOT_YET
    if any(to is None and at <= t for at, to in changes):
        return REVOKED
    if until is not None and t > until:
        return LAPSED
    state = INITIAL
    for at, to in changes:
        if to is not None and at <= t:
            state = to
    return state


def history(ledger, record) -> tuple:
    """(registration time, changes) of a membership record from a replayed
    ledger: its transitions and revocation in log order, as standing() takes
    them. A membership's history holds only its registration, transitions,
    and revocation: it takes no endorsement and has no versions."""
    registered_at = ledger.applied[record.history[0]].registered_at
    changes = []
    for index in record.history[1:]:
        applied = ledger.applied[index]
        kind = applied.statement.type
        if kind == RECORD_TRANSITION:
            changes.append((applied.registered_at, applied.statement.fields["to"]))
        elif kind == RECORD_REVOKE:
            changes.append((applied.registered_at, None))
    return registered_at, changes


__all__ = ["ACTIVE", "ENDED", "INITIAL", "KINDS", "LAPSED", "MAX_PROOFS", "MEMBERSHIP_TYPE", "Membership",
           "MembershipError", "NOT_YET", "REVOKED", "SUSPENDED", "TRANSITIONS", "history", "parse", "standing"]
