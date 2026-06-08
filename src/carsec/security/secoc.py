"""
SecOC layer — the per-ECU facade that turns a raw frame into a secured frame and
verifies incoming frames.

Each ECU owns one :class:`SecOCLayer`.  In secure mode every transmitted frame is
authenticated with three independent, layered protections:

1. **MAC integrity / authenticity** — HMAC-SHA256 over
   ``Data ID | DLC | data | freshness | timestamp``, truncated to 64 bits.
   Any single-bit change to the frame, or any forged frame from a node without
   the key, fails verification.
2. **Counter-based freshness** — a monotonic Freshness Value bound into the MAC
   (see :mod:`carsec.security.freshness`) defeats exact replay.
3. **Time-based freshness** — a timestamp staleness window provides
   defence-in-depth and bounds the replay opportunity even across counter
   re-synchronisation.

This maps onto AUTOSAR SecOC (Data ID, Freshness Value, Authenticator) and the
ISO/SAE 21434 requirement for message authenticity on safety-relevant buses.
See ``docs/secoc.md`` for the full mapping.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from carsec.can.message import CANMessage
from carsec.security.crypto import SHARED_KEY, compute_mac, verify_mac
from carsec.security.freshness import FreshnessManager

# Maximum tolerated age of a frame (seconds) for the time-based freshness check.
TIMESTAMP_WINDOW_SEC = 5.0
# Tolerance for clock skew / future-dated frames.
CLOCK_SKEW_SEC = 1.0


def _authentic_data(msg: CANMessage) -> bytes:
    """
    Build the byte string the MAC is computed over.

    Layout (big-endian): Data ID | DLC | data(8, padded) | freshness | timestamp.
    The Data ID is the CAN arbitration ID — binding it prevents an attacker from
    moving a valid MAC onto a different message type.
    """
    return struct.pack(
        ">IB8sId",
        msg.arbitration_id,
        msg.dlc,
        msg.data.ljust(8, b"\x00"),
        msg.freshness,
        msg.timestamp,
    )


@dataclass
class VerificationResult:
    """Outcome of verifying an incoming frame."""

    accepted: bool
    mac_valid: bool
    freshness_ok: bool
    timestamp_ok: bool
    reason: str


class SecOCLayer:
    """Per-ECU authenticator / verifier."""

    def __init__(
        self,
        ecu_name: str,
        secure: bool = True,
        key: bytes = SHARED_KEY,
        timestamp_window: float = TIMESTAMP_WINDOW_SEC,
    ) -> None:
        self.ecu_name = ecu_name
        self.secure = secure
        self.key = key
        self.timestamp_window = timestamp_window
        self._freshness = FreshnessManager()

    # ── Sender side ────────────────────────────────────────────────────────────

    def authenticate(self, msg: CANMessage) -> CANMessage:
        """
        Stamp a frame for transmission: sender, timestamp, freshness, MAC.

        In insecure mode the freshness and MAC are left empty so the frame is a
        plain classic-CAN frame.  Returns the same object, mutated in place.
        """
        msg.sender = self.ecu_name
        msg.timestamp = time.time()

        if self.secure:
            msg.freshness = self._freshness.next_value(msg.arbitration_id)
            msg.mac = compute_mac(_authentic_data(msg), self.key)
        else:
            msg.freshness = 0
            msg.mac = b""
        return msg

    # ── Receiver side ──────────────────────────────────────────────────────────

    def verify(self, msg: CANMessage) -> VerificationResult:
        """Verify an incoming frame.  In insecure mode all frames are accepted."""
        if not self.secure:
            return VerificationResult(
                accepted=True,
                mac_valid=True,
                freshness_ok=True,
                timestamp_ok=True,
                reason="insecure mode — no verification performed",
            )

        mac_ok = verify_mac(_authentic_data(msg), msg.mac, self.key)
        ts_ok = self._timestamp_fresh(msg.timestamp)

        # Only consult / advance the freshness counter once the MAC is trusted:
        # an attacker must not be able to burn freshness values to cause a DoS.
        fv_ok = self._freshness.is_fresh(msg.arbitration_id, msg.freshness) if mac_ok else False

        accepted = mac_ok and ts_ok and fv_ok
        if accepted:
            self._freshness.commit(msg.arbitration_id, msg.freshness)

        if not mac_ok:
            reason = "MAC verification failed — frame forged or tampered"
        elif not fv_ok:
            reason = f"stale freshness value {msg.freshness} — replay detected"
        elif not ts_ok:
            age = time.time() - msg.timestamp
            reason = f"timestamp outside freshness window (age={age:.2f}s) — replay detected"
        else:
            reason = "OK"

        return VerificationResult(
            accepted=accepted,
            mac_valid=mac_ok,
            freshness_ok=fv_ok,
            timestamp_ok=ts_ok,
            reason=reason,
        )

    def _timestamp_fresh(self, ts: float) -> bool:
        age = time.time() - ts
        return -CLOCK_SKEW_SEC <= age <= self.timestamp_window
