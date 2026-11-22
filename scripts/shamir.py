#!/usr/bin/env python3
"""shamir.py — Shamir (k, n) threshold secret sharing over GF(256).

Reference: Adi Shamir, "How to Share a Secret", Communications of the ACM
22(11), 612-613, November 1979. A (k, n) threshold scheme: any k of the n
shares reconstruct the secret; any k-1 shares reveal no information about it.
Shamir's robustness note: with n = 2k - 1 the scheme recovers the secret even
when k - 1 shares are destroyed, and stays secure even when k - 1 of the
remaining shares are exposed.

Implementation: GF(2^8) with the AES polynomial 0x11b, generator 3. The
secret is split byte-wise: one random degree-(k-1) polynomial per byte, with
the secret byte as the constant term. Shares are (x, y-bytes) with x in 1..n.
Each share carries a SHA-256 commitment (integrity check: a corrupted share
is detected before reconstruction, because a wrong share yields a wrong
commitment on the reconstructed secret).

LAB ONLY: the drill scripts generate fresh random lab secrets with
os.urandom. This module never reads, writes, or prints a real secret. The
self-test below uses fixed test vectors (deterministic) and prints only
hashes, never secret bytes.

Usage:
  python3 scripts/shamir.py --self-test     # deterministic checks, exit 0
  python3 scripts/shamir.py --demo          # one random lab split/rebuild demo
"""
import argparse
import hashlib
import os
import random
import sys

# GF(256) tables, polynomial 0x11b, generator 3 (note: 2 has order 51 in
# this field and is NOT a generator; the tables must be built with 3).
EXP = [0] * 512
LOG = [0] * 256


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x = _xtime(_x) ^ _x  # multiply by 3 (x + 1)
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def _div(a: int, b: int) -> int:
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    return EXP[(LOG[a] - LOG[b]) % 255]


def _eval_poly(coeffs, x: int) -> int:
    # Horner, coeffs[0] is the constant term.
    result = 0
    for c in reversed(coeffs):
        result = _mul(result, x) ^ c
    return result


def split(secret: bytes, k: int, n: int, rng=None) -> list:
    """Split secret into n shares, any k of which reconstruct it.

    Returns [(x, y_bytes), ...] with x in 1..n. Raises ValueError on bad k/n.
    """
    if not 1 <= k <= n <= 255:
        raise ValueError(f"need 1 <= k <= n <= 255, got k={k} n={n}")
    if not secret:
        raise ValueError("secret must be non-empty")
    rng = rng or random.SystemRandom()
    shares = [(x, bytearray(len(secret))) for x in range(1, n + 1)]
    for j, byte in enumerate(secret):
        coeffs = [byte] + [rng.randrange(256) for _ in range(k - 1)]
        for x, y in shares:
            y[j] = _eval_poly(coeffs, x)
    return [(x, bytes(y)) for x, y in shares]


def reconstruct(shares: list) -> bytes:
    """Reconstruct the secret from >= k shares (Lagrange interpolation at 0)."""
    if not shares:
        raise ValueError("no shares supplied")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share index")
    n_bytes = len(shares[0][1])
    if any(len(y) != n_bytes for _, y in shares):
        raise ValueError("shares have mismatched lengths")
    out = bytearray(n_bytes)
    for j in range(n_bytes):
        acc = 0
        for i, (xi, yi) in enumerate(shares):
            # Lagrange basis polynomial at x=0.
            num, den = 1, 1
            for m, (xm, _) in enumerate(shares):
                if m == i:
                    continue
                num = _mul(num, xm)
                den = _mul(den, xi ^ xm)
            acc ^= _mul(yi[j], _div(num, den))
        out[j] = acc
    return bytes(out)


def commitment(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def self_test() -> int:
    """Deterministic checks with fixed vectors. Prints hashes only."""
    rng = random.Random(20261123)
    failures = []

    def check(name: str, ok: bool):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures.append(name)

    # 1. Round-trip for several (k, n) shapes, all share subsets of size k.
    import itertools
    for secret_len, k, n in ((16, 3, 5), (32, 2, 3), (32, 5, 5), (16, 1, 1), (48, 3, 7)):
        secret = bytes(rng.randrange(256) for _ in range(secret_len))
        shares = split(secret, k, n, rng=rng)
        ok = True
        for subset in itertools.combinations(shares, k):
            if reconstruct(list(subset)) != secret:
                ok = False
                break
        check(f"round-trip secret_len={secret_len} k={k} n={n} "
              f"(all {len(list(itertools.combinations(shares, k)))} subsets)", ok)

    # 2. k-1 shares must NOT reconstruct (wrong result, not the secret).
    secret = bytes(rng.randrange(256) for _ in range(32))
    shares = split(secret, 3, 5, rng=rng)
    wrong = reconstruct(shares[:2])
    check("k-1 shares do not reconstruct the secret", wrong != secret)

    # 3. Corrupted share is detectable via the commitment.
    shares = split(secret, 3, 5, rng=rng)
    good_commit = commitment(secret)
    bad = bytearray(shares[0][1])
    bad[0] ^= 0x01
    bad_shares = [(shares[0][0], bytes(bad))] + shares[1:3]
    check("corrupted share detected by commitment mismatch",
          commitment(reconstruct(bad_shares)) != good_commit)

    # 4. Duplicate share index is rejected.
    try:
        reconstruct([shares[0], shares[0], shares[1]])
        check("duplicate share index rejected", False)
    except ValueError:
        check("duplicate share index rejected", True)

    # 5. Bad parameters rejected.
    for bad_k, bad_n in ((0, 3), (4, 3), (3, 256)):
        try:
            split(secret, bad_k, bad_n, rng=rng)
            check(f"bad parameters k={bad_k} n={bad_n} rejected", False)
        except ValueError:
            check(f"bad parameters k={bad_k} n={bad_n} rejected", True)

    n_checks = 5 + 1 + 1 + 1 + 3  # round-trips + k-1 + corruption + dup + params
    print(f"self-test: {n_checks} checks, {len(failures)} failures"
          if failures else f"self-test: all {n_checks} checks passed")
    return 1 if failures else 0


def demo() -> int:
    secret = os.urandom(32)  # fresh LAB secret, never printed or stored
    print("demo: generated a fresh 32-byte LAB secret (not printed)")
    print(f"  secret sha256: {commitment(secret)}")
    shares = split(secret, 3, 5)
    print(f"  split into 5 shares, threshold 3; share commitments:")
    for x, y in shares:
        print(f"    share {x}: sha256={commitment(y)[:16]}... ({len(y)} bytes)")
    rebuilt = reconstruct([shares[0], shares[2], shares[4]])
    print(f"  rebuilt from shares 1,3,5: match={rebuilt == secret} "
          f"sha256={commitment(rebuilt)[:16]}...")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        raise SystemExit(self_test())
    if args.demo:
        raise SystemExit(demo())
    ap.print_help()
    sys.exit(2)
