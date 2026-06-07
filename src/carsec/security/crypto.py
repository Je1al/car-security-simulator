"""
Cryptographic primitives for SecOC.

Why HMAC?
---------
Classic CAN has no authentication: any node can transmit any frame and every
receiver trusts it.  Remote attacks on production vehicles (Miller & Valasek's
2015 Jeep Cherokee, and a string of later demonstrations) all exploit this.

The industry response — AUTOSAR Secure Onboard Communication (SecOC), referenced
by ISO/SAE 21434 — appends a **Message Authentication Code** to each secured
frame.  We use HMAC-SHA256 because it is:

* keyed — unforgeable without the shared secret;
* fast — microsecond-range even on constrained ECU hardware;
* truncatable — we keep 64 bits (8 bytes) to fit the CAN(-FD) payload budget,
  giving a per-attempt forgery probability of ~2⁻⁶⁴.

Key management (simplified)
---------------------------
Production SecOC provisions a unique symmetric key per ECU/PDU group, stored in
a Hardware Security Module (HSM).  Here a single key is derived from a passphrase
with a SHA-256 KDF for readability; the API leaves room for per-Data-ID keys.
"""

from __future__ import annotations

import hashlib
import hmac

# Pre-shared master secret.  In production this lives in an HSM and is never in
# source — the name makes the intent unmistakable.
_MASTER_SECRET = b"carsec-PoC-master-secret-DO-NOT-USE-IN-PRODUCTION"

# Truncated MAC length in bytes (AUTOSAR allows configurable truncation).
MAC_LEN = 8


def derive_key(context: str = "SecOC-CAN-HMAC-v1") -> bytes:
    """Derive a 32-byte key from the master secret and a context string."""
    return hashlib.sha256(_MASTER_SECRET + context.encode()).digest()


SHARED_KEY: bytes = derive_key()


def compute_mac(authentic_data: bytes, key: bytes = SHARED_KEY) -> bytes:
    """Return the truncated HMAC-SHA256 over ``authentic_data``."""
    full = hmac.new(key, authentic_data, hashlib.sha256).digest()
    return full[:MAC_LEN]


def verify_mac(authentic_data: bytes, tag: bytes, key: bytes = SHARED_KEY) -> bool:
    """
    Constant-time verification of a truncated MAC.

    Uses :func:`hmac.compare_digest` to avoid leaking the position of the first
    mismatching byte through timing — the same precaution a real SecOC verifier
    must take.
    """
    expected = compute_mac(authentic_data, key)
    return hmac.compare_digest(expected, tag)
