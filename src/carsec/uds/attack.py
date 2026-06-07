"""
Security Access seed–key attack.

Online key guessing is throttled by the ECU (attempt counter + time delay), so
the practical break against a weak algorithm is *offline*: sniff a single
legitimate (seed, key) exchange from a workshop tester, then recover the secret
and impersonate the tester forever.

This module recovers the 16-bit secret of :class:`WeakXorSeedKey` from one pair
in microseconds, and shows the same approach is hopeless against
:class:`HmacSeedKey` (128-bit secret).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from carsec.uds.security_access import HmacSeedKey, WeakXorSeedKey


@dataclass
class BruteForceResult:
    recovered: bool
    secret: Optional[int]
    tries: int
    seconds: float


def recover_weak_secret(seed: bytes, key: bytes) -> BruteForceResult:
    """
    Recover the 16-bit secret of a :class:`WeakXorSeedKey` from one (seed, key)
    pair by exhaustive search of the 65 536-value keyspace.
    """
    start = time.perf_counter()
    for candidate in range(0x10000):
        if WeakXorSeedKey(candidate).compute_key(seed) == key:
            return BruteForceResult(True, candidate, candidate + 1, time.perf_counter() - start)
    return BruteForceResult(False, None, 0x10000, time.perf_counter() - start)


def attempt_hmac_secret(seed: bytes, key: bytes, max_tries: int = 100_000) -> BruteForceResult:
    """
    Try (and fail) to recover an :class:`HmacSeedKey` secret by brute force.

    We treat the secret as if it were small to illustrate the futility: even
    millions of guesses cover a negligible fraction of the 2¹²⁸ keyspace, so the
    search returns unsuccessful.  This is the control case that shows why a
    proper KDF defeats the offline attack.
    """
    start = time.perf_counter()
    for candidate in range(max_tries):
        guess = candidate.to_bytes(16, "big")
        if HmacSeedKey(guess).compute_key(seed) == key:
            return BruteForceResult(True, candidate, candidate + 1, time.perf_counter() - start)
    return BruteForceResult(False, None, max_tries, time.perf_counter() - start)
