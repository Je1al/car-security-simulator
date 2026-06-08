"""
DBC signal decoding.

A DBC file is the industry-standard description of a CAN network: for every
message ID it defines the named signals packed into the data field (start bit,
length, byte order, scale, offset, unit).  Decoding raw bytes into engineering
values is the first thing any CAN analysis or IDS pipeline does, and the bundled
``vehicle.dbc`` mirrors the signals this simulator transmits.

If `cantools <https://cantools.readthedocs.io>`_ is installed (the ``hardware``
extra) it is used for full DBC support; otherwise a small built-in fallback
decodes the known messages with the same scaling, so the feature degrades
gracefully without the dependency.
"""

from __future__ import annotations

import os
from typing import Any

from carsec.can.identifiers import (
    MSG_ID,
    decode_brake_pressure,
    decode_rpm,
    decode_status,
    decode_temperature,
)
from carsec.can.message import CANMessage

DEFAULT_DBC = os.path.join(os.path.dirname(__file__), "..", "data", "vehicle.dbc")

try:
    import cantools as _cantools

    _HAS_CANTOOLS = True
except ImportError:  # pragma: no cover
    _HAS_CANTOOLS = False


# Built-in fallback: arbitration id → (signal name, decoder).
_FALLBACK = {
    MSG_ID["ENGINE_RPM"]: ("EngineRPM", decode_rpm),
    MSG_ID["ENGINE_TEMP"]: ("EngineTemp", decode_temperature),
    MSG_ID["BRAKE_PRESS"]: ("BrakePressure", decode_brake_pressure),
    MSG_ID["BRAKE_STATUS"]: ("BrakeStatus", decode_status),
    MSG_ID["GATEWAY_FWD"]: ("FwdRPM", decode_rpm),
}


class DbcDatabase:
    """Decode CAN frames into named signals from a DBC (or the fallback table)."""

    def __init__(self, path: str | None = None) -> None:
        self.path = os.path.normpath(path or DEFAULT_DBC)
        self._db: Any = None
        if _HAS_CANTOOLS and os.path.exists(self.path):
            self._db = _cantools.database.load_file(self.path)

    @property
    def uses_cantools(self) -> bool:
        return self._db is not None

    def decode(self, msg: CANMessage) -> dict:
        """Return a ``{signal: value}`` dict for a frame, or ``{}`` if unknown."""
        if self._db is not None:
            try:
                message = self._db.get_message_by_frame_id(msg.arbitration_id)
            except KeyError:
                return {}
            # On-wire DLC may be shorter than the DBC message length; pad so
            # cantools can unpack the fixed-layout signals.
            data = bytes(msg.data).ljust(message.length, b"\x00")
            return dict(message.decode(data))
        entry = _FALLBACK.get(msg.arbitration_id)
        if entry is None or not msg.data:
            return {}
        name, decoder = entry
        return {name: decoder(msg.data)}
