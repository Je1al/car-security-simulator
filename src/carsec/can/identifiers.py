"""
CAN message identifiers and signal codecs.

Real-CAN background
-------------------
A CAN frame is identified by its *arbitration ID*, which names the **message
type, not the sender**.  Lower IDs win bus arbitration (higher priority).  The
mapping below is a tiny didactic "DBC" — in a real vehicle the equivalent table
lives in a manufacturer DBC database with hundreds of messages and thousands of
signals.  The IDs are loosely modelled on powertrain/chassis traffic.

Each signal codec packs an application value into the CAN data field using a
fixed scale/offset, exactly as a real DBC signal definition does (factor,
offset, byte order, length).
"""

from __future__ import annotations

import struct

# ── Well-known message IDs (11-bit standard frame range) ──────────────────────
MSG_ID = {
    "ENGINE_RPM": 0x0A0,  # Engine revolutions per minute
    "ENGINE_TEMP": 0x0A1,  # Engine coolant temperature
    "BRAKE_PRESS": 0x0B0,  # Hydraulic brake pressure
    "BRAKE_STATUS": 0x0B1,  # Brake system status byte
    "GATEWAY_FWD": 0x0C0,  # Gateway forwarded frame
    "GATEWAY_ACK": 0x0C1,  # Gateway acknowledge
    "DIAG_REQUEST": 0x7E0,  # UDS diagnostic request (tester → ECU)
    "DIAG_RESPONSE": 0x7E8,  # UDS diagnostic response (ECU → tester)
    "ATTACKER_INJ": 0x666,  # Marker ID used by injection demos
}

MSG_NAME = {v: k for k, v in MSG_ID.items()}

# Classic CAN data field length code (DLC) maximum, in bytes.
MAX_PAYLOAD = 8


def name_for_id(arbitration_id: int) -> str:
    """Return the symbolic name for an arbitration ID, or a hex fallback."""
    return MSG_NAME.get(arbitration_id, f"0x{arbitration_id:03X}")


# ── Signal codecs (factor/offset like a DBC) ──────────────────────────────────


def encode_rpm(rpm: int) -> bytes:
    """Engine RPM → uint16 big-endian (range 0..65535 rpm)."""
    return struct.pack(">H", max(0, min(rpm, 0xFFFF)))


def decode_rpm(data: bytes) -> int:
    return struct.unpack(">H", data[:2])[0]


def encode_temperature(celsius: float) -> bytes:
    """Coolant temperature → int16, factor 0.1 °C."""
    return struct.pack(">h", int(round(celsius * 10)))


def decode_temperature(data: bytes) -> float:
    return struct.unpack(">h", data[:2])[0] / 10.0


def encode_brake_pressure(bar: float) -> bytes:
    """Brake pressure → uint16, factor 0.01 bar."""
    return struct.pack(">H", max(0, min(int(round(bar * 100)), 0xFFFF)))


def decode_brake_pressure(data: bytes) -> float:
    return struct.unpack(">H", data[:2])[0] / 100.0


def encode_status(code: int) -> bytes:
    """1-byte status code."""
    return bytes([code & 0xFF])


def decode_status(data: bytes) -> int:
    return data[0] if data else 0
