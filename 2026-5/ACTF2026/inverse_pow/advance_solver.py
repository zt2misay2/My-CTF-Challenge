#!/usr/bin/env python3
"""
advance-attack.md implementation for inverse_pow.

Solve minimal n >= 0 such that decimal representation of 2^n starts with m.
Equivalently find minimal n with { n * log10(2) } in [L, U).

This uses Euclidean / continued-fraction style fractional-part inversion, not BSGS.
"""
from __future__ import annotations

import random
import time
from decimal import Decimal, getcontext, ROUND_FLOOR, ROUND_CEILING

# 120 decimal digits is plenty for n around 1e8~1e10 and interval width ~1e-8.
# Increase if you intentionally search much larger ranges / narrower prefixes.
getcontext().prec = 140

THETA = Decimal(2).log10()
ONE = Decimal(1)
ZERO = Decimal(0)


def floor_d(x: Decimal) -> int:
    return int(x.to_integral_value(rounding=ROUND_FLOOR))


def ceil_d(x: Decimal) -> int:
    return int(x.to_integral_value(rounding=ROUND_CEILING))


def frac(x: Decimal) -> Decimal:
    return x - Decimal(floor_d(x))


def interval_for_m(m: int) -> tuple[Decimal, Decimal]:
    if not (1 <= m <= 99_999_999):
        raise ValueError("challenge m must be in [1, 99999999]")
    k = len(str(m))
    scale = Decimal(10) ** (k - 1)
    L = (Decimal(m) / scale).log10()
    U = (Decimal(m + 1) / scale).log10()
    # For m = 9, 99, ..., U is exactly log10(10) = 1.
    return L, U


def in_interval(x: Decimal, L: Decimal, U: Decimal) -> bool:
    # The challenge condition is half-open [L, U).
    return L <= x < U


def solve_rotation(theta: Decimal, L: Decimal, U: Decimal, depth: int = 0, trace: bool = False) -> tuple[int, int]:
    """Return minimal x >= 0 such that {x*theta} in [L,U), plus recursion depth.

    Assumes 0 < theta < 1 and 0 <= L < U <= 1.
    The recursive step is the pull-back:
      theta' = {1/theta}
      L' = 1 - {U/theta}
      U' = 1 - {L/theta}
    then x = ceil((y + L)/theta), where y solves the child problem.
    """
    if not (ZERO < theta < ONE):
        raise ValueError(f"theta out of range: {theta}")
    if not (ZERO <= L < U <= ONE):
        raise ValueError(f"bad interval: [{L}, {U})")

    a = L / theta
    b = U / theta

    # Base case: y=0 already has an integer x in [L/theta, U/theta).
    x0 = ceil_d(a)
    if Decimal(x0) < b:
        if trace:
            print(f"{'  '*depth}base depth={depth}: theta={theta} L={L} U={U} -> x={x0}")
        return x0, depth

    # No integer in [a,b). Normally a,b lie between the same consecutive integers.
    # For an exclusive right endpoint equal to an integer, b's fractional part is 0;
    # the pull-back interval should be [0, 1-frac(a)) rather than [1, ...).
    af = frac(a)
    bf = frac(b)
    theta2 = frac(ONE / theta)

    if bf == ZERO:
        L2 = ZERO
    else:
        L2 = ONE - bf
    U2 = ONE - af

    if trace:
        width = U - L
        print(f"{'  '*depth}recur depth={depth}: width={width} theta={theta}")
        print(f"{'  '*depth}  a={a} b={b} af={af} bf={bf}")
        print(f"{'  '*depth}  -> theta'={theta2} interval'=[{L2},{U2})")

    y, d = solve_rotation(theta2, L2, U2, depth + 1, trace)

    x = ceil_d((Decimal(y) + L) / theta)
    return x, d


def _find_n_from_lower_bound(m: int, lower: int, trace: bool = False) -> tuple[int, int]:
    """Find minimal n >= lower satisfying the log interval and digit-length constraint."""
    L, U = interval_for_m(m)
    off = (Decimal(lower) * THETA) % ONE
    Ls = L - off
    Us = U - off

    intervals = []
    if Ls < ZERO:
        Ls += ONE
        Us += ONE
    if Us <= ONE:
        intervals.append((Ls, Us))
    else:
        intervals.append((Ls, ONE))
        intervals.append((ZERO, Us - ONE))

    best = None
    best_depth = 0
    for aL, aU in intervals:
        if aL == aU:
            continue
        r, depth = solve_rotation(THETA, aL, aU, trace=trace)
        cand = lower + r
        if best is None or cand < best:
            best = cand
            best_depth = depth

    if best is None:
        raise RuntimeError("no interval candidates")
    return best, best_depth


def find_n(m: int, trace: bool = False) -> tuple[int, int]:
    # Need len(str(2**n)) >= len(str(m)); otherwise the log fractional
    # condition can falsely accept n=0 for m=10,100,1000,...
    k = len(str(m))
    lower = max(0, ceil_d((Decimal(k - 1)) / THETA))
    n, depth = _find_n_from_lower_bound(m, lower, trace=trace)

    # Boundary correction: Decimal arithmetic is high precision but still finite.
    # Check a few nearby candidates, but never below the digit-length lower bound.
    best = None
    for cand in range(max(lower, n - 8), n + 9):
        if verify_log(m, cand):
            best = cand
            break
    if best is None:
        for cand in range(max(lower, n - 1000), n + 1001):
            if verify_log(m, cand):
                best = cand
                break
    if best is None:
        raise RuntimeError(f"candidate failed verification: m={m} n={n} depth={depth} lower={lower}")
    return best, depth

def attack_pow(m: int) -> int:
    """Return an n such that str(2**n) starts with decimal string m.

    This is the public interface for the inverse_pow POW.
    Input:  integer m in [1, 99999999]
    Output: valid integer n
    """
    n, _depth = find_n(int(m), trace=False)
    return n

def verify_log(m: int, n: int) -> bool:
    # Program also checks len(str(m)) <= len(str(2**n)).
    # The fractional-prefix condition alone is insufficient for cases like m=10, n=0.
    k = len(str(m))
    if floor_d(Decimal(n) * THETA) + 1 < k:
        return False
    L, U = interval_for_m(m)
    x = (Decimal(n) * THETA) % ONE
    return in_interval(x, L, U)


def leading_digits_by_log(n: int, digits: int) -> int:
    x = (Decimal(n) * THETA) % ONE
    return int((Decimal(10) ** (x + digits - 1)).to_integral_value(rounding=ROUND_FLOOR))


def demo() -> None:
    tests = [1, 2, 9, 10, 99, 99999999, 68050557, 34783948, 88751717, 77954251, 994886, 35909074]
    random.seed(20260510)
    tests += [random.randint(1, 99_999_999) for _ in range(30)]

    t0 = time.perf_counter()
    rows = []
    for m in tests:
        s0 = time.perf_counter()
        n, depth = find_n(m)
        dt = time.perf_counter() - s0
        lead = leading_digits_by_log(n, len(str(m)))
        rows.append((m, n, depth, dt, str(lead).startswith(str(m))))
    wall = time.perf_counter() - t0

    for m, n, depth, dt, ok in rows:
        print(f"m={m:8d}  n={n:12d}  depth={depth:2d}  time={dt*1000:8.3f} ms  ok={ok}")
    ns = [r[1] for r in rows]
    print("---")
    print(f"cases={len(rows)} wall={wall:.4f}s avg={sum(r[3] for r in rows)/len(rows)*1000:.3f} ms max={max(r[3] for r in rows)*1000:.3f} ms")
    print(f"n_min={min(ns)} n_max={max(ns)} n_avg={sum(ns)//len(ns)}")


if __name__ == "__main__":
    demo()
