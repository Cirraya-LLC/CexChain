# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Claims (spec v0.14, sections 6 and 11): a `kanhe.claim/1` record says
that, in another record of the same ledger (its source), a condition on the
source's fields holds, or does not, as of a time, without disclosing them.

The ledger checks a claim's metadata (record key 5, `claim` in the CDDL) and
refuses other keys; parse() does that here, and parse_condition() checks a
condition alone, as an access request about one carries it (v0.15, section
12). words() states the condition as one line of English, as every
verifier's report gives it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fractions import Fraction

from .errors import VerifyError

CLAIM_TYPE = "kanhe.claim/1"

_REQUIRED = {"source", "condition", "holds", "as_of"}
_OPTIONAL = {"until", "subject", "for"}
_ORDER = (">", ">=", "<", "<=")
OPERATORS = _ORDER + ("=", "!=", "between", "in", "exists")
TYPES = ("number", "money", "date", "text")
MAX_TERMS = 16
MAX_IN = 64
_DECIMAL = re.compile(r"-?[0-9]+(\.[0-9]+)?")
_CURRENCY = re.compile(r"[A-Z]{3}")
_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_WORDS = {">": "is above", ">=": "is at least", "<": "is below", "<=": "is at most", "=": "is", "!=": "is not"}


@dataclass(frozen=True)
class Term:
    field: str
    op: str
    type: str
    value: object  # a value; [low, high]; a list of values; or None (exists)


@dataclass(frozen=True)
class Claim:
    source: bytes
    condition: tuple  # of Term
    holds: bool
    as_of: int
    until: int | None
    subject: str | None
    for_: tuple | None  # (ledger, record): the access request it answers


def fail(message: str):
    raise VerifyError(message)


def _int(v) -> bool:
    """A CBOR integer: what the decoder gives for major types 0 and 1."""
    return isinstance(v, int) and not isinstance(v, bool)


def _text(v, low: int, high: int) -> bool:
    return isinstance(v, str) and low <= len(v.encode("utf-8")) <= high


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _check_value(kind: str, v, what: str):
    """One value of the term's type (section 6)."""
    if kind == "number":
        # An integer, or a decimal text of at most 40 characters.
        if _int(v) or (isinstance(v, str) and len(v) <= 40 and _DECIMAL.fullmatch(v)):
            return
        fail(f"{what} is not a number (an integer, or a decimal text of at most 40 characters)")
    if kind == "money":
        # [amount, currency, scale]: an integer amount in units of 10^-scale,
        # three upper-case letters, a scale of 0 to 4.
        if (isinstance(v, list) and len(v) == 3 and _int(v[0]) and isinstance(v[1], str)
                and _CURRENCY.fullmatch(v[1]) and _int(v[2]) and 0 <= v[2] <= 4):
            return
        fail(f"{what} is not money ([amount, currency, scale])")
    if kind == "date":
        m = _DATE.fullmatch(v) if isinstance(v, str) else None
        if m:
            year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1 <= month <= 12 and 1 <= day <= _days_in_month(year, month):
                return
        fail(f"{what} is not a valid date (YYYY-MM-DD)")
    if not _text(v, 1, 256):
        fail(f"{what} is not a text of 1 to 256 bytes")


def _key(kind: str, v):
    """A value as it compares: a number exactly, money as its currency and
    exact amount, a date as its text (YYYY-MM-DD orders so), a text as is."""
    if kind == "number":
        return Fraction(v)
    if kind == "money":
        return v[1], Fraction(v[0], 10 ** v[2])
    return v


def _parse_term(raw, n: int, owner: str) -> Term:
    what = f"{owner}'s term {n}"
    if not (isinstance(raw, list) and len(raw) == 4):
        fail(f"{what} is not [field, op, type, value]")
    field, op, kind, value = raw
    if not _text(field, 1, 64):
        fail(f"{what}'s field is not a name of 1 to 64 bytes")
    if not (isinstance(op, str) and op in OPERATORS):
        fail(f"{what}'s operator is unknown")
    if not (isinstance(kind, str) and kind in TYPES):
        fail(f"{what}'s type is not number, money, date, or text")
    if kind == "text" and (op in _ORDER or op == "between"):
        # Texts have no order: >, >=, <, <= take numbers, money, and dates,
        # and between names a low and a high.
        fail(f"{what} orders a text ({op})")
    if op == "exists":
        if kind != "text":
            fail(f"{what}: exists takes the type text")
        if value is not None:
            fail(f"{what}: exists takes the value null")
        return Term(field, op, kind, None)
    if op == "between":
        if not (isinstance(value, list) and len(value) == 2):
            fail(f"{what}: between takes [low, high]")
        values = value
    elif op == "in":
        if not (isinstance(value, list) and 1 <= len(value) <= MAX_IN):
            fail(f"{what}: in takes 1 to 64 values")
        values = value
    else:
        if value is None:
            fail(f"{what}'s value is null")
        values = [value]
    for v in values:
        _check_value(kind, v, f"{what}'s value")
    if op == "between":
        low, high = _key(kind, value[0]), _key(kind, value[1])
        if kind == "money" and low[0] != high[0]:
            fail(f"{what}: between two amounts of different currencies")
        if low > high:
            fail(f"{what}: between a low above its high")
    if op == "in":
        keys = [_key(kind, v) for v in value]
        if len(set(keys)) != len(keys):
            fail(f"{what}: in holds a value twice")
    return Term(field, op, kind, value)


def parse_condition(condition, owner: str = "a claim") -> tuple:
    """A condition, 1 to 16 terms that must all hold, checked as a claim's is
    (section 6): a claim's, or (v0.15) an access request's, which asks about
    one. Returns its terms."""
    if not (isinstance(condition, list) and 1 <= len(condition) <= MAX_TERMS):
        fail(f"{owner}'s condition is not 1 to 16 terms")
    return tuple(_parse_term(t, n, owner) for n, t in enumerate(condition))


def parse(metadata) -> Claim:
    """A claim's metadata, checked as the ledger checks it (section 6)."""
    if not isinstance(metadata, dict):
        fail("a claim has no claim metadata (record key 5)")
    keys = set(metadata)
    unknown = keys - _REQUIRED - _OPTIONAL
    if unknown:
        fail(f"a claim's metadata has an unknown key ({sorted(unknown)[0]!r})")
    missing = _REQUIRED - keys
    if missing:
        fail(f"a claim's metadata lacks {sorted(missing)[0]!r}")
    m = metadata
    if not (isinstance(m["source"], bytes) and len(m["source"]) == 32):
        fail("a claim's source is not a 32-byte id")
    terms = parse_condition(m["condition"])
    if not isinstance(m["holds"], bool):
        fail("a claim's holds is not a boolean")
    if not (_int(m["as_of"]) and m["as_of"] >= 0):
        fail("a claim's as_of is not an unsigned integer")
    until = m.get("until")
    if "until" in m and not (_int(until) and until > m["as_of"]):
        fail("a claim's until is not a time after its as_of")
    if "subject" in m and not _text(m["subject"], 1, 256):
        fail("a claim's subject is not a text of 1 to 256 bytes")
    answers = m.get("for")
    if "for" in m and not (isinstance(answers, list) and len(answers) == 2
                           and all(isinstance(x, bytes) and len(x) == 32 for x in answers)):
        fail("a claim's for is not [ledger, record]")
    return Claim(source=m["source"], condition=terms, holds=m["holds"], as_of=m["as_of"], until=until,
                 subject=m.get("subject"), for_=tuple(answers) if answers is not None else None)


def value_words(kind: str, v) -> str:
    """A value in words (section 11): a number as it is encoded; money as its
    currency, a space, and the amount with its sign, groups of three, and
    `scale` decimals; a date as it is encoded; a text between double quotes,
    as it is."""
    if kind == "number":
        return str(v)
    if kind == "money":
        amount, currency, scale = v
        units, cents = divmod(abs(amount), 10 ** scale)
        digits = str(units)
        groups = []
        while len(digits) > 3:
            groups.insert(0, digits[-3:])
            digits = digits[:-3]
        groups.insert(0, digits)
        out = f"{currency} {'-' if amount < 0 else ''}{','.join(groups)}"
        if scale:
            out += "." + str(cents).rjust(scale, "0")
        return out
    if kind == "date":
        return v
    return f'"{v}"'


def term_words(t: Term) -> str:
    if t.op == "exists":
        return f"{t.field} is given"
    if t.op == "between":
        return f"{t.field} is between {value_words(t.type, t.value[0])} and {value_words(t.type, t.value[1])}"
    if t.op == "in":
        return f"{t.field} is one of " + ", ".join(value_words(t.type, v) for v in t.value)
    return f"{t.field} {_WORDS[t.op]} {value_words(t.type, t.value)}"


def words(condition) -> str:
    """The condition as one line of English, its terms joined by " and "."""
    return " and ".join(term_words(t) for t in condition)


__all__ = ["CLAIM_TYPE", "Claim", "Term", "parse", "parse_condition", "value_words", "words"]
