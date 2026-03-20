"""
security.py
────────────────────────────────────────────────────────────────────────────────
Cryptographic security layer for the CAN bus simulator.

Why HMAC for CAN?
─────────────────
Classic CAN has NO authentication mechanism. Any node can send any message.
Automotive attack research (Miller & Valasek 2015, Tesla hacks 2016–2020) has
repeatedly demonstrated that an attacker who gains access to the CAN bus can
send arbitrary control messages — brakes, steering, throttle.

The automotive industry response (AUTOSAR SecOC, ISO 21434) specifies adding
a Message Authentication Code (MAC) to CAN/CAN-FD frames.

We use HMAC-SHA256 because:
  • Keyed hash — cannot be forged without the shared secret key
  • Fast — software implementation is microsecond-range on ECU hardware
  • Truncatable — we use 8 bytes (64 bits) of output to fit in CAN-FD frame
  • Collision-resistant — forgery probability ≈ 2⁻⁶⁴ per attempt

Three-layer protection implemented
────────────────────────────────────
  1. HMAC integrity/authentication — detects tampering and forged senders
  2. Nonce uniqueness — each sender increments a counter; replayed old nonces
     are rejected
  3. Timestamp freshness — messages older than TIMESTAMP_WINDOW_SEC are stale

Key management (simplified)
────────────────────────────
In real automotive systems (AUTOSAR SecOC) each ECU pair shares a unique
symmetric key provisioned at manufacturing time. We use a single shared key
for the simulation — production systems would use per-ECU derived keys.
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Set, Tuple

from can_protocol import CANMessage, TIMESTAMP_WINDOW_SEC


# ─── Shared secret key (pre-shared between all trusted ECUs) ──────────────────
# In production: 128–256 bit key provisioned via Hardware Security Module (HSM)
# Here we derive from a passphrase for readability.
_MASTER_SECRET = b"automotive-PoC-key-DO-NOT-USE-IN-PROD"


def _derive_key(context: str = "CAN-HMAC-v1") -> bytes:
    """Derive a 32-byte key using SHA-256 KDF."""
    return hashlib.sha256(_MASTER_SECRET + context.encode()).digest()


SHARED_KEY: bytes = _derive_key()


# ─── HMAC signing ─────────────────────────────────────────────────────────────

def _mac_input(msg: CANMessage) -> bytes:
    """
    Construct the authenticated data blob for HMAC computation.

    What we authenticate:
      msg_id | payload_len | payload | timestamp | nonce
    The sender field is NOT included (not on the wire).
    We authenticate the timestamp and nonce to bind them to this MAC.
    """
    return struct.pack(
        ">IH8sdI",
        msg.msg_id,
        msg.payload_len,
        msg.payload.ljust(8, b"\x00"),
        msg.timestamp,
        msg.nonce,
    )


def sign_message(msg: CANMessage, key: bytes = SHARED_KEY) -> CANMessage:
    """
    Compute HMAC-SHA256 over the message fields and store the first 8 bytes
    as the hmac_tag.  Returns the same message object (mutated in place).

    The 8-byte truncation balances security (2⁻⁶⁴ forgery probability) with
    the CAN-FD payload constraint.
    """
    raw     = _mac_input(msg)
    full_mac = hmac.new(key, raw, hashlib.sha256).digest()
    msg.hmac_tag = full_mac[:8]   # truncate to 8 bytes
    return msg


def verify_mac(msg: CANMessage, key: bytes = SHARED_KEY) -> bool:
    """
    Constant-time HMAC verification (prevents timing side-channel attacks).
    Returns True if the tag matches, False otherwise.
    """
    raw      = _mac_input(msg)
    expected = hmac.new(key, raw, hashlib.sha256).digest()[:8]
    return hmac.compare_digest(expected, msg.hmac_tag)


# ─── Nonce manager ────────────────────────────────────────────────────────────

class NonceManager:
    """
    Tracks per-sender nonce counters to prevent replay attacks.

    Strategy: monotonic counter
    ───────────────────────────
    Each ECU maintains a counter starting at 1.  Every new message increments
    the counter.  The receiver tracks the last-seen nonce per sender and
    rejects any message whose nonce is ≤ the last accepted value.

    This is equivalent to a sequence number in TLS record layer.

    Alternative: random nonce (used by some implementations)
      • Pro: no synchronisation needed
      • Con: requires a separate freshness mechanism (timestamp only)

    We use monotonic counters because they are cheap and deterministic.
    """

    def __init__(self) -> None:
        # sender_name → next nonce to send
        self._send_counters: Dict[str, int] = defaultdict(lambda: 1)
        # sender_name → highest nonce seen so far (receive side)
        self._seen: Dict[str, int] = defaultdict(int)

    def next_nonce(self, sender: str) -> int:
        """Return the next nonce for this sender and advance the counter."""
        n = self._send_counters[sender]
        self._send_counters[sender] += 1
        return n

    def is_fresh(self, sender: str, nonce: int) -> bool:
        """
        Return True if this nonce is strictly greater than any previously
        accepted nonce from this sender (prevents replay).
        """
        if nonce <= self._seen[sender]:
            return False
        self._seen[sender] = nonce
        return True

    def reset(self, sender: str) -> None:
        """Reset state for a sender (e.g. after ECU reboot)."""
        self._send_counters[sender] = 1
        self._seen[sender] = 0


# ─── Timestamp validation ─────────────────────────────────────────────────────

def is_timestamp_fresh(ts: float, window: float = TIMESTAMP_WINDOW_SEC) -> bool:
    """
    Return True if the message timestamp is within [now - window, now + 1s].

    The +1s tolerance handles minor clock skew between ECUs.
    In real vehicles a shared clock (CAN time sync, PTP IEEE 1588) would be
    used to keep ECU clocks within microseconds of each other.
    """
    now = time.time()
    age = now - ts
    return -1.0 <= age <= window


# ─── Security layer facade ────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    """Result of verifying an incoming message."""
    accepted:       bool
    mac_valid:      bool
    nonce_fresh:    bool
    timestamp_fresh:bool
    reason:         str


class SecurityLayer:
    """
    Unified security facade used by each ECU.

    Usage (sender side):
        sec = SecurityLayer(ecu_name="ECU_Engine")
        msg = sec.prepare(CANMessage(msg_id=MSG_ID["ENGINE_RPM"], payload=b"\\x0F\\xA0"))

    Usage (receiver side):
        result = sec.verify(msg)
        if not result.accepted:
            print(result.reason)
    """

    def __init__(
        self,
        ecu_name:  str,
        secure:    bool  = True,
        key:       bytes = SHARED_KEY,
    ) -> None:
        self.ecu_name = ecu_name
        self.secure   = secure
        self.key      = key
        self._nonces  = NonceManager()

    def prepare(self, msg: CANMessage) -> CANMessage:
        """
        Prepare a message for sending:
          - set sender name
          - assign fresh timestamp
          - assign monotonic nonce
          - compute and attach HMAC (secure mode only)
        """
        msg.sender    = self.ecu_name
        msg.timestamp = time.time()

        if self.secure:
            msg.nonce   = self._nonces.next_nonce(self.ecu_name)
            sign_message(msg, self.key)
        else:
            msg.nonce   = 0
            msg.hmac_tag = b"\x00" * 8

        return msg

    def verify(self, msg: CANMessage) -> VerificationResult:
        """
        Verify an incoming message.
        In insecure mode all checks are skipped and message is always accepted.
        """
        if not self.secure:
            return VerificationResult(
                accepted=True, mac_valid=True,
                nonce_fresh=True, timestamp_fresh=True,
                reason="insecure mode — no checks performed",
            )

        # Check 1: HMAC integrity / authentication
        mac_ok = verify_mac(msg, self.key)

        # Check 2: Timestamp freshness (must be evaluated even if mac fails,
        # because the attacker might have a valid MAC for an old message)
        ts_ok  = is_timestamp_fresh(msg.timestamp)

        # Check 3: Nonce uniqueness (replay prevention)
        #   Only advance the seen-counter if the MAC is valid — otherwise an
        #   attacker could burn nonces to cause DoS.
        if mac_ok:
            nonce_ok = self._nonces.is_fresh(msg.sender, msg.nonce)
        else:
            nonce_ok = False   # can't trust the nonce without valid MAC

        accepted = mac_ok and ts_ok and nonce_ok

        if not mac_ok:
            reason = "HMAC verification FAILED — message tampered or forged"
        elif not ts_ok:
            reason = f"Timestamp too old/future (age={time.time()-msg.timestamp:.2f}s)"
        elif not nonce_ok:
            reason = f"Nonce {msg.nonce} already seen — REPLAY ATTACK detected"
        else:
            reason = "OK"

        return VerificationResult(
            accepted=accepted,
            mac_valid=mac_ok,
            nonce_fresh=nonce_ok,
            timestamp_fresh=ts_ok,
            reason=reason,
        )
