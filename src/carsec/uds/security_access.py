"""
Security Access (UDS service 0x27) seed–key algorithms.

The tester requests a *seed* (random challenge); it must answer with the *key*
derived from that seed.  Only a party that knows the secret algorithm/key can
compute the right answer, so the ECU stays locked to everyone else — in theory.

In practice many production seed–key schemes used short secrets or invertible
("proprietary obscurity") math, and were broken by recovering the secret from a
single sniffed seed/key pair.  We model both ends of that spectrum:

* :class:`WeakXorSeedKey` — a 16-bit secret fed through an invertible mixing
  function.  One captured (seed, key) pair is enough to recover the secret by
  brute force in microseconds (see :mod:`carsec.uds.attack`).
* :class:`HmacSeedKey` — key = truncated HMAC-SHA256(secret, seed) with a
  128-bit secret.  No captured pair helps; the secret cannot be brute-forced.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from abc import ABC, abstractmethod

SEED_LEN = 4
KEY_LEN = 4


class SeedKeyAlgorithm(ABC):
    """Computes the expected key for a given seed."""

    seed_len: int = SEED_LEN
    key_len: int = KEY_LEN

    @abstractmethod
    def compute_key(self, seed: bytes) -> bytes:
        """Return the key the ECU expects for ``seed``."""


def _mix(seed_int: int, secret: int) -> int:
    """Invertible 32-bit mixing of a seed with a 16-bit secret."""
    x = (seed_int ^ (secret * 0x9E3779B1)) & 0xFFFFFFFF  # multiply by an odd constant
    x = ((x << 7) | (x >> 25)) & 0xFFFFFFFF  # rotate left 7
    return x ^ 0xA5A5A5A5


class WeakXorSeedKey(SeedKeyAlgorithm):
    """Intentionally weak: a 16-bit secret, recoverable from one seed/key pair."""

    SECRET_BITS = 16

    def __init__(self, secret: int = 0xBEEF) -> None:
        if not 0 <= secret <= 0xFFFF:
            raise ValueError("secret must be 16-bit")
        self.secret = secret

    def compute_key(self, seed: bytes) -> bytes:
        seed_int = struct.unpack(">I", seed[:SEED_LEN].ljust(SEED_LEN, b"\x00"))[0]
        return struct.pack(">I", _mix(seed_int, self.secret))


class HmacSeedKey(SeedKeyAlgorithm):
    """Strong: key = truncated HMAC-SHA256(secret, seed) with a 128-bit secret."""

    def __init__(self, secret: bytes = b"\x9f\x12\x4a\xb7\x00\xc3\xd1\xee\x55\x6a\x88\x21\x0f\xfe\x33\x90") -> None:
        if len(secret) < 16:
            raise ValueError("secret should be at least 128 bits")
        self.secret = secret

    def compute_key(self, seed: bytes) -> bytes:
        return hmac.new(self.secret, seed, hashlib.sha256).digest()[:KEY_LEN]
