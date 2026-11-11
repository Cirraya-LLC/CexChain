# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Deterministic CBOR in the Kanhe profile (spec section 2).

The decoder accepts exactly the bytes the encoder produces for the decoded
value (RFC 8949 section 4.2.1, restricted further):

- integers and lengths in their shortest form, definite lengths only;
- map keys sorted by the bytewise order of their encodings, no duplicates;
- no floating-point numbers, no simple values other than false, true, and
  null, no bignums (tags 2 and 3);
- text strings in valid UTF-8;
- at most 32 levels of nesting (each array, map, and tag is one level), and,
  where the caller asks, at most a number of data items.

Every check is made while decoding, and the result is then re-encoded and
compared with the input as a second, independent check.

Values decode to Python as: int, bytes, str, list, dict (maps whose keys are
all integers, text, or byte strings), Map (any other map, as ordered pairs),
Tag, False, True, None.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import VerifyError

MAX_DEPTH = 32
# Statement payloads and contract outputs hold at most this many data items.
MAX_PAYLOAD_ITEMS = 131_072


class CborError(VerifyError):
    """Bytes that are not deterministic CBOR in the Kanhe profile."""


@dataclass(frozen=True)
class Tag:
    tag: int
    value: object


class Map:
    """A map with keys Python cannot hold in a dict (arrays, maps, tags,
    booleans, null), as its pairs in encoded-key order."""

    def __init__(self, pairs):
        self.pairs = list(pairs)

    def __eq__(self, other):
        return isinstance(other, Map) and encode(self) == encode(other)

    def __repr__(self):
        return f"Map({self.pairs!r})"


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _head(major: int, n: int) -> bytes:
    if n < 0:
        raise ValueError("negative length")
    if n < 24:
        return bytes([(major << 5) | n])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | info]) + n.to_bytes(width, "big")
    raise ValueError("integer too large for CBOR")


def encode(value) -> bytes:
    """Deterministic CBOR encoding of a Python value."""
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        return _head(2, len(data)) + data
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        items = sorted((encode(k), encode(v)) for k, v in value.items())
        if len({k for k, _ in items}) != len(items):
            raise ValueError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, Map):
        items = sorted((encode(k), encode(v)) for k, v in value.pairs)
        if len({k for k, _ in items}) != len(items):
            raise ValueError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, Tag):
        return _head(6, value.tag) + encode(value.value)
    raise TypeError(f"cannot encode {type(value).__name__} as CBOR")


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

class _Decoder:
    def __init__(self, data: bytes, max_items: int | None):
        self.data = data
        self.pos = 0
        self.items = 0
        self.max_items = max_items

    def fail(self, why: str):
        raise CborError(f"not deterministic CBOR: {why} (at byte {self.pos})")

    def take(self, n: int) -> bytes:
        if n > len(self.data) - self.pos:
            self.fail("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def head(self):
        """Returns (major type, additional information, argument)."""
        first = self.take(1)[0]
        major, info = first >> 5, first & 0x1F
        if major == 7:
            return major, info, None
        if info < 24:
            return major, info, info
        if info == 31:
            self.fail("indefinite length")
        if info > 27:
            self.fail("reserved additional information")
        width = 1 << (info - 24)
        n = int.from_bytes(self.take(width), "big")
        # Shortest form: the value must not fit a narrower head.
        if (info == 24 and n < 24) or (info > 24 and n < 1 << (8 * (width // 2))):
            self.fail("integer or length not in its shortest form")
        return major, info, n

    def item(self, depth: int):
        self.items += 1
        if self.max_items is not None and self.items > self.max_items:
            self.fail(f"more than {self.max_items} data items")
        major, info, n = self.head()
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return self.take(n)
        if major == 3:
            raw = self.take(n)
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                self.fail("text string not valid UTF-8")
        if major in (4, 5, 6):
            if depth + 1 > MAX_DEPTH:
                self.fail(f"more than {MAX_DEPTH} levels of nesting")
        if major == 4:
            return [self.item(depth + 1) for _ in range(n)]
        if major == 5:
            pairs = []
            previous = None
            for _ in range(n):
                start = self.pos
                key = self.item(depth + 1)
                key_bytes = self.data[start:self.pos]
                if previous is not None and key_bytes <= previous:
                    self.fail("map keys not in bytewise order, or duplicated")
                previous = key_bytes
                pairs.append((key, self.item(depth + 1)))
            if all(isinstance(k, (str, bytes)) or (isinstance(k, int) and not isinstance(k, bool))
                   for k, _ in pairs):
                return dict(pairs)
            return Map(pairs)
        if major == 6:
            if n in (2, 3):
                self.fail("bignums are not allowed")
            return Tag(n, self.item(depth + 1))
        # Major type 7: simple values and floats.
        if info == 20:
            return False
        if info == 21:
            return True
        if info == 22:
            return None
        if info in (25, 26, 27):
            self.fail("floating-point numbers are not allowed")
        self.fail("simple values other than false, true, and null are not allowed")


def decode(data: bytes, max_items: int | None = None):
    """Decodes exactly one deterministic CBOR item that spans all of `data`."""
    if not isinstance(data, (bytes, bytearray)):
        raise CborError("not deterministic CBOR: expected bytes")
    data = bytes(data)
    decoder = _Decoder(data, max_items)
    value = decoder.item(0)
    if decoder.pos != len(data):
        decoder.fail("trailing bytes after the item")
    # Section 2: encode(decode(x)) == x for every accepted input.
    if encode(value) != data:
        raise CborError("not deterministic CBOR: re-encoding differs")
    return value
