# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Access requests (spec section 12), and claims as answers to them (v0.15).

A `kanhe.access-request/1` record's metadata (record key 5,
`access-request` in the CDDL) takes one of two forms: a request for a
record's data, with the X25519 key the delivery is sealed to and optionally
the fields and attachments wanted; or (v0.15) a request that asks whether a
condition holds in the record, with 1 to 16 terms of a claim's condition and
nothing sealed to the requester. decode_access_request() reads either and
refuses anything else, as parties do.

The granter answers a request about a condition with a claim whose `for`
names the request. claim_answers() makes the requester's acceptance checks 3
and 4 on the claim's metadata: its `for` names the requester's ledger and the
request, its `source` is the record asked about, and its condition is the
request's, term for term. Checks 1, 2, and 5 need the claim's evidence: that
it verifies, complete, for the ledger the request asked; that the claim is
live and has not lapsed; and that its source is live.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import cbor, claims
from .errors import VerifyError

ACCESS_REQUEST_TYPE = "kanhe.access-request/1"

_COMMON = ("ledger", "record", "purpose", "until")
_DATA = ("recipient", "fields", "attachments")  # the other form has "condition"
_KEYS = set(_COMMON) | set(_DATA) | {"condition"}
MAX_NAMES = 256  # names in a list of fields or attachments (access-names)


class AccessError(VerifyError):
    """An access request that a party refuses, or a claim that does not
    answer one. `why` names the rule, as the test vectors do."""

    def __init__(self, why: str, message: str):
        super().__init__(message)
        self.why = why


@dataclass(frozen=True)
class AccessRequest:
    ledger: bytes            # the ledger asked
    record: bytes            # the record wanted there, or asked about
    purpose: str
    until: int               # ms: access wanted, or the question open, until then
    recipient: bytes | None  # a request for data: the X25519 key deliveries are sealed to
    fields: tuple | None     # wanted fields; None: all
    attachments: tuple | None  # wanted attachments; None: all
    condition: tuple | None  # a request about a condition (v0.15): its terms (claims.Term)


def _fail(why: str, message: str):
    raise AccessError(why, message)


def _id(v) -> bool:
    return isinstance(v, bytes) and len(v) == 32


def _names(v) -> bool:
    """`access-names`: at most 256 names, each a non-empty text, none twice."""
    return (isinstance(v, list) and len(v) <= MAX_NAMES and all(isinstance(x, str) and x for x in v)
            and len(set(v)) == len(v))


def decode_access_request(metadata) -> AccessRequest:
    """An access request's metadata, as deterministic CBOR bytes or as the
    decoded map, checked as parties check it (sections 12 and 6)."""
    if isinstance(metadata, (bytes, bytearray)):
        metadata = cbor.decode(bytes(metadata))
    if isinstance(metadata, cbor.Map):
        # The decoder keeps a map as pairs only when a key is not an integer
        # or a string, so some key is not one of the named texts.
        _fail("unknown key", "an access request's metadata has a key that is not text")
    if not isinstance(metadata, dict):
        _fail("no metadata", "an access request has no access-request metadata (record key 5)")
    keys = set(metadata)
    unknown = keys - _KEYS
    if unknown:
        _fail("unknown key", f"an access request's metadata has an unknown key ({sorted(map(repr, unknown))[0]})")
    missing = set(_COMMON) - keys
    if missing:
        _fail("missing key", f"an access request's metadata lacks {sorted(missing)[0]!r}")
    # The group choice: a condition and no recipient, fields, or attachments,
    # or a recipient. A key counts by its presence, an empty list included.
    asking = "condition" in keys
    if asking and keys & set(_DATA):
        _fail("both forms", "an access request asks about a condition and for data (a recipient, fields, or "
                            "attachments) at once")
    if not asking and "recipient" not in keys:
        _fail("neither form", "an access request has neither a condition nor a recipient key")
    # From here, a key whose value is not of its type (null included) is
    # refused, by that key's rule.
    m = metadata
    if not _id(m["ledger"]):
        _fail("ledger", "an access request's ledger is not a 32-byte id")
    if not _id(m["record"]):
        _fail("record", "an access request's record is not a 32-byte id")
    if not (isinstance(m["purpose"], str) and m["purpose"]):
        _fail("purpose", "an access request's purpose is not a non-empty text")
    until = m["until"]
    # bool is an int in Python, but CBOR's true is not an unsigned integer.
    if not (isinstance(until, int) and not isinstance(until, bool) and until > 0):
        _fail("until", "an access request's until is not an unsigned integer above 0")
    if asking:
        try:
            terms = claims.parse_condition(m["condition"], "an access request")
        except VerifyError as e:
            raise AccessError("condition", str(e)) from None
        return AccessRequest(ledger=m["ledger"], record=m["record"], purpose=m["purpose"], until=until,
                             recipient=None, fields=None, attachments=None, condition=terms)
    if not _id(m["recipient"]):
        _fail("recipient", "an access request's recipient is not a 32-byte X25519 key")
    for key in ("fields", "attachments"):
        if key in m and not _names(m[key]):
            _fail("names", f"an access request's {key} are not a list of at most {MAX_NAMES} non-empty names, "
                           "none twice")
    return AccessRequest(ledger=m["ledger"], record=m["record"], purpose=m["purpose"], until=until,
                         recipient=m["recipient"],
                         fields=tuple(m["fields"]) if "fields" in m else None,
                         attachments=tuple(m["attachments"]) if "attachments" in m else None,
                         condition=None)


def _encoded(terms) -> list:
    # Each term in its deterministic encoding. The decoder accepts only
    # deterministic CBOR, so this gives back the bytes each term came in.
    return [cbor.encode([t.field, t.op, t.type, t.value]) for t in terms]


def claim_answers(claim, this_ledger: bytes, request_id: bytes, request) -> None:
    """Raises AccessError unless `claim` answers the access request
    `request_id` that this ledger (the requester's) recorded (section 12,
    "Asking about a condition", acceptance checks 3 and 4).

    `claim` is a claims.Claim, or a claim's metadata (bytes or the decoded
    map); `request` an AccessRequest, or its metadata."""
    if not isinstance(claim, claims.Claim):
        claim = claims.parse(cbor.decode(bytes(claim)) if isinstance(claim, (bytes, bytearray)) else claim)
    if not isinstance(request, AccessRequest):
        request = decode_access_request(request)
    if request.condition is None:
        _fail("data request", "the access request asks for data, which a delivery answers, not a claim")
    # 3. Its for names the requester's ledger and the request.
    if claim.for_ is None:
        _fail("no for", "the claim names no access request it answers (no for)")
    ledger, asked = claim.for_
    if ledger != this_ledger:
        _fail("for ledger", "the claim answers an access request of another ledger")
    if asked != request_id:
        _fail("for request", "the claim answers another access request")
    # 4. Its source is the record asked about, and its condition the
    # request's, term for term and in the same deterministic encoding: a
    # value written another way (money at another scale, 2 as "2.0"), or the
    # values of "in" in another order, is another condition. The claim's
    # until may end before or after the request's, and its as_of is the
    # granter's word: neither is checked.
    if claim.source != request.record:
        _fail("source", "the claim is about another record than the one the request asks about")
    if _encoded(claim.condition) != _encoded(request.condition):
        _fail("condition", "the claim's condition is not the request's, term for term")


__all__ = ["ACCESS_REQUEST_TYPE", "AccessError", "AccessRequest", "claim_answers", "decode_access_request"]
