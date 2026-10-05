#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Derives the curve constants that CexChain hard-codes, from first principles.

Run this to re-check the constants in core/src/crypto.cpp:
  - the y-coordinates of Ed25519's small-order (torsion) points, used to reject weak keys;
  - the Ed25519 group order L, used to reject non-canonical signature scalars;
  - half the P-256 group order, used to enforce low-S ECDSA signatures.
"""

P = 2**255 - 19
D = (-121665 * pow(121666, -1, P)) % P
L = 2**252 + 27742317777372353535851937790883648493
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
IDENTITY = (0, 1)


def add(p1, p2):
    """Twisted Edwards addition on -x^2 + y^2 = 1 + d x^2 y^2."""
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, -1, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P
    return (x3, y3)


def mul(k, point):
    result = IDENTITY
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def recover_x(y):
    """Returns x for y on the curve, or None."""
    u = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(u, (P + 3) // 8, P)
    if x * x % P != u:
        x = x * pow(2, (P - 1) // 4, P) % P
    return x if x * x % P == u else None


def encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little").hex()


def torsion_points():
    # [L]P lies in the 8-element torsion subgroup for any curve point P. Find one of
    # order exactly 8, which generates the whole subgroup.
    for y in range(2, 1000):
        x = recover_x(y)
        if x is None:
            continue
        t = mul(L, (x, y))
        if mul(4, t) != IDENTITY:
            return [mul(k, t) for k in range(8)]
    raise RuntimeError("no generator found")


def main():
    points = torsion_points()
    assert all(mul(8, pt) == IDENTITY for pt in points)
    ys = sorted({pt[1] for pt in points})
    print("Ed25519 torsion points (order, encoding):")
    for pt in points:
        order = next(k for k in (1, 2, 4, 8) if mul(k, pt) == IDENTITY)
        print(f"  {order}  {encode(pt)}")
    print("Distinct y-coordinates (little-endian):")
    for y in ys:
        print("  " + y.to_bytes(32, "little").hex())
    print("Ed25519 L (little-endian):", L.to_bytes(32, "little").hex())
    print("P-256 n/2 (big-endian):   ", (P256_N // 2).to_bytes(32, "big").hex())
    print("P-256 n   (big-endian):   ", P256_N.to_bytes(32, "big").hex())


if __name__ == "__main__":
    main()
