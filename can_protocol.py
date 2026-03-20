"""
can_protocol.py
────────────────────────────────────────────────────────────────────────────────
Defines the CAN-like message format used throughout the simulation.

Real CAN Bus background
───────────────────────
Controller Area Network (CAN) is a broadcast serial bus developed by Bosch in
1986. It is the dominant in-vehicle communication standard, found in every
modern production vehicle.

Key real-CAN properties modelled here:
  • Message ID (arbitration ID) — identifies message type, NOT the sender.
    Lower ID = higher priority. 11-bit standard frame (0–2047) or 29-bit
    extended frame used in practice.
  • Payload (data field) — up to 8 bytes in classic CAN, up to 64 bytes in
    CAN-FD (Flexible Data Rate).
  • Broadcast semantics — every node on the bus sees every message.
    There is NO built-in addressing or authentication in classic CAN.
  • No built-in security — anyone on the bus can send ANY message.
    This is the fundamental weakness exploited by the replay/inject attacks
    simulated here.

Our extensions over raw CAN
───────────────────────────
Since real CAN has no security, automotive security researchers propose
adding metadata fields (analogous to SAE J1939 / AUTOSAR SecOC):
  • timestamp  — when the message was created (Unix float)
  • nonce      — random 4-byte value used exactly once per sender per session
  • hmac_tag   — HMAC-SHA256 truncated to 8 bytes for integrity + auth

Message wire format (struct pack '<IH8sfI8s')
  offset  size  field
  ──────  ────  ─────────
       0     4  msg_id      (uint32, little-endian)
       4     2  payload_len (uint16)
       6     8  payload     (8 bytes, zero-padded)
      14     8  timestamp   (double / float64)
      22     4  nonce       (uint32)
      26     8  hmac_tag    (8 bytes, zeros if insecure mode)
  total = 34 bytes
────────────────────────────────────────────────────────────────────────────────
"""

import struct
import time
import os
import hmac as _hmac
import hashlib
from dataclasses import dataclass, field
from typing import Optional


# ─── Wire format constants ────────────────────────────────────────────────────

_WIRE_FMT   = "<IH8sdI8s"   # see layout above
WIRE_SIZE   = struct.calcsize(_WIRE_FMT)   # 38 bytes

# Well-known message IDs (analogous to SAE J1939 PGNs)
MSG_ID = {
    "ENGINE_RPM":    0x0A0,   # Engine RPM broadcast
    "ENGINE_TEMP":   0x0A1,   # Engine coolant temperature
    "BRAKE_PRESS":   0x0B0,   # Brake pressure
    "BRAKE_STATUS":  0x0B1,   # Brake system status
    "GATEWAY_FWD":   0x0C0,   # Gateway forward
    "GATEWAY_ACK":   0x0C1,   # Gateway acknowledge
    "ATTACKER_INJ":  0xDEAD,  # Injected / malicious message
}

# Reverse map for display
MSG_NAME = {v: k for k, v in MSG_ID.items()}

# Maximum allowed age of a message before it is considered stale (seconds)
TIMESTAMP_WINDOW_SEC = 5.0

# Maximum payload size (bytes) — classic CAN DLC = 8
MAX_PAYLOAD = 8


# ─── Message dataclass ────────────────────────────────────────────────────────

@dataclass
class CANMessage:
    """
    A single CAN-like message as it flows on the simulated bus.

    In secure mode the hmac_tag field is populated by SecurityLayer.sign().
    In insecure mode hmac_tag is left as b'\\x00' * 8 and nonce is 0.
    """
    msg_id:     int                     # Arbitration / message type ID
    payload:    bytes                   # Up to 8 bytes of application data
    timestamp:  float = field(default_factory=time.time)
    nonce:      int   = 0               # 32-bit random nonce
    hmac_tag:   bytes = field(default_factory=lambda: b"\x00" * 8)
    sender:     str   = "UNKNOWN"       # Logical sender name (not in wire fmt)
    is_replay:  bool  = False           # Metadata flag set by attacker
    is_tampered:bool  = False           # Metadata flag set by attacker

    def __post_init__(self):
        if len(self.payload) > MAX_PAYLOAD:
            raise ValueError(f"Payload too long: {len(self.payload)} > {MAX_PAYLOAD}")
        # Zero-pad payload to 8 bytes for wire format
        self._padded_payload = self.payload.ljust(MAX_PAYLOAD, b"\x00")

    @property
    def msg_name(self) -> str:
        return MSG_NAME.get(self.msg_id, f"0x{self.msg_id:03X}")

    @property
    def payload_len(self) -> int:
        return len(self.payload)

    def to_bytes(self) -> bytes:
        """Serialise to wire format (34 bytes)."""
        return struct.pack(
            _WIRE_FMT,
            self.msg_id,
            self.payload_len,
            self._padded_payload,
            self.timestamp,
            self.nonce,
            self.hmac_tag,
        )

    @classmethod
    def from_bytes(cls, data: bytes, sender: str = "UNKNOWN") -> "CANMessage":
        """Deserialise from wire format."""
        if len(data) < WIRE_SIZE:
            raise ValueError(f"Too short: {len(data)} < {WIRE_SIZE}")
        msg_id, payload_len, padded, timestamp, nonce, hmac_tag = struct.unpack(
            _WIRE_FMT, data[:WIRE_SIZE]
        )
        payload = padded[:payload_len]
        return cls(
            msg_id=msg_id,
            payload=payload,
            timestamp=timestamp,
            nonce=nonce,
            hmac_tag=hmac_tag,
            sender=sender,
        )

    def clone(self) -> "CANMessage":
        """Return a deep copy of this message."""
        return CANMessage(
            msg_id=self.msg_id,
            payload=bytes(self.payload),
            timestamp=self.timestamp,
            nonce=self.nonce,
            hmac_tag=bytes(self.hmac_tag),
            sender=self.sender,
            is_replay=self.is_replay,
            is_tampered=self.is_tampered,
        )

    def __repr__(self) -> str:
        tag = f"hmac={self.hmac_tag.hex()}" if any(self.hmac_tag) else "no-hmac"
        flags = ""
        if self.is_replay:   flags += " [REPLAY]"
        if self.is_tampered: flags += " [TAMPERED]"
        return (
            f"CANMessage(id={self.msg_name}, "
            f"payload={self.payload.hex()}, "
            f"nonce={self.nonce:#010x}, "
            f"{tag}){flags}"
        )


# ─── Payload helpers ──────────────────────────────────────────────────────────

def encode_rpm(rpm: int) -> bytes:
    """Encode engine RPM as 2-byte big-endian uint16."""
    return struct.pack(">H", min(rpm, 0xFFFF))

def decode_rpm(payload: bytes) -> int:
    return struct.unpack(">H", payload[:2])[0]

def encode_temperature(celsius: float) -> bytes:
    """Encode temperature as int16 (× 10 for 0.1°C precision)."""
    return struct.pack(">h", int(celsius * 10))

def decode_temperature(payload: bytes) -> float:
    return struct.unpack(">h", payload[:2])[0] / 10.0

def encode_brake_pressure(bar: float) -> bytes:
    """Encode brake pressure (bar × 100 → uint16)."""
    return struct.pack(">H", int(bar * 100))

def decode_brake_pressure(payload: bytes) -> float:
    return struct.unpack(">H", payload[:2])[0] / 100.0

def encode_status(code: int) -> bytes:
    """Encode a 1-byte status code."""
    return bytes([code & 0xFF])

def decode_status(payload: bytes) -> int:
    return payload[0] if payload else 0
