"""
CAN frame model.

The :class:`CANMessage` is the single object that flows across the simulated
bus.  Field names deliberately mirror ``python-can``'s ``can.Message``
(``arbitration_id``, ``data``, ``dlc``, ``is_extended_id``) so the optional
hardware backend can convert between the two with zero friction.

On top of the classic-CAN fields we carry the AUTOSAR SecOC additions used by
:mod:`carsec.security`:

    freshness   Freshness Value (monotonic counter) bound into the MAC.
    mac         Truncated Message Authentication Code (empty in insecure mode).

and a few simulation-only metadata fields (``sender``, ``is_attack``,
``attack_type``) that are *not* part of the wire frame — they exist so the
logger, IDS, and visualizer can label traffic. ``to_bytes``/``from_bytes`` round
trips only the real on-wire fields.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from carsec.can.identifiers import MAX_PAYLOAD, name_for_id

# Wire layout for the *secured* PDU used in the simulator.
#   arbitration_id : uint32
#   dlc            : uint8
#   data           : 8 bytes (zero padded)
#   timestamp      : float64
#   freshness      : uint32
#   mac            : 8 bytes (zero in insecure mode)
_WIRE_FMT = "<IB8sdI8s"
WIRE_SIZE = struct.calcsize(_WIRE_FMT)


@dataclass
class CANMessage:
    """A single CAN frame as it appears on the simulated bus."""

    arbitration_id: int
    data: bytes
    timestamp: float = field(default_factory=time.time)
    freshness: int = 0
    mac: bytes = b""
    is_extended_id: bool = False

    # Simulation metadata (never serialized to the wire) ──────────────────────
    sender: str = "UNKNOWN"
    is_attack: bool = False
    attack_type: str = ""

    def __post_init__(self) -> None:
        if len(self.data) > MAX_PAYLOAD:
            raise ValueError(f"CAN data field too long: {len(self.data)} > {MAX_PAYLOAD}")

    @property
    def name(self) -> str:
        """Symbolic message name (or hex fallback)."""
        return name_for_id(self.arbitration_id)

    @property
    def dlc(self) -> int:
        """Data Length Code — number of valid payload bytes."""
        return len(self.data)

    @property
    def is_secured(self) -> bool:
        """True if a MAC is attached (i.e. produced in secure mode)."""
        return bool(self.mac)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_bytes(self) -> bytes:
        """Serialize the on-wire fields to a fixed-size secured PDU."""
        return struct.pack(
            _WIRE_FMT,
            self.arbitration_id,
            self.dlc,
            self.data.ljust(MAX_PAYLOAD, b"\x00"),
            self.timestamp,
            self.freshness,
            self.mac.ljust(8, b"\x00"),
        )

    @classmethod
    def from_bytes(cls, raw: bytes, sender: str = "UNKNOWN") -> CANMessage:
        if len(raw) < WIRE_SIZE:
            raise ValueError(f"frame too short: {len(raw)} < {WIRE_SIZE}")
        arb, dlc, padded, ts, fresh, mac = struct.unpack(_WIRE_FMT, raw[:WIRE_SIZE])
        return cls(
            arbitration_id=arb,
            data=padded[:dlc],
            timestamp=ts,
            freshness=fresh,
            mac=mac if any(mac) else b"",
            sender=sender,
        )

    def clone(self) -> CANMessage:
        """Deep copy (bytes are immutable but we copy to be explicit)."""
        return CANMessage(
            arbitration_id=self.arbitration_id,
            data=bytes(self.data),
            timestamp=self.timestamp,
            freshness=self.freshness,
            mac=bytes(self.mac),
            is_extended_id=self.is_extended_id,
            sender=self.sender,
            is_attack=self.is_attack,
            attack_type=self.attack_type,
        )

    def __repr__(self) -> str:
        mac = f"mac={self.mac.hex()}" if self.mac else "no-mac"
        flag = f" [{self.attack_type.upper()}]" if self.is_attack else ""
        return (
            f"CANMessage(id={self.name}, "
            f"data={self.data.hex()}, "
            f"fv={self.freshness}, {mac}){flag}"
        )
