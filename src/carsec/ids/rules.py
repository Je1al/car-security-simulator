"""
Rule-based ("specification-based") detector.

A vehicle network is highly deterministic: the set of valid arbitration IDs is
fixed, each signal has a known physical range, and DLCs are constant.  A
specification-based IDS encodes that knowledge as an allowlist and flags anything
outside it.  This is cheap, has (near) zero false positives on known traffic, and
catches injection of unknown IDs and physically-impossible signal values — but,
by construction, cannot catch a *plausible* spoofed value (that is what the
frequency detector is for).
"""

from __future__ import annotations

from typing import Optional

from carsec.can.identifiers import (
    MSG_ID,
    decode_brake_pressure,
    decode_rpm,
)
from carsec.can.message import CANMessage

# Allowlist: arbitration ID → expected DLC (number of payload bytes).
_KNOWN_IDS = {
    MSG_ID["ENGINE_RPM"]: 2,
    MSG_ID["ENGINE_TEMP"]: 2,
    MSG_ID["BRAKE_PRESS"]: 2,
    MSG_ID["BRAKE_STATUS"]: 1,
    MSG_ID["GATEWAY_FWD"]: 2,
    MSG_ID["GATEWAY_ACK"]: 1,
}

# Physical plausibility ranges for decoded signals.
_RPM_MAX = 8000
_BRAKE_BAR_MAX = 250.0


class RuleDetector:
    """Allowlist + DLC + physical-range checks."""

    name = "rule"

    def inspect(self, msg: CANMessage, now: float = 0.0) -> Optional[str]:
        arb = msg.arbitration_id

        if arb not in _KNOWN_IDS:
            return f"unknown arbitration id 0x{arb:03X}"

        if msg.dlc != _KNOWN_IDS[arb] and msg.dlc != 0:
            return f"unexpected DLC {msg.dlc} for {msg.name} (want {_KNOWN_IDS[arb]})"

        if arb == MSG_ID["ENGINE_RPM"] and msg.dlc >= 2:
            if decode_rpm(msg.data) > _RPM_MAX:
                return f"implausible RPM {decode_rpm(msg.data)} > {_RPM_MAX}"

        if arb == MSG_ID["BRAKE_PRESS"] and msg.dlc >= 2:
            if decode_brake_pressure(msg.data) > _BRAKE_BAR_MAX:
                return f"implausible brake pressure {decode_brake_pressure(msg.data):.1f} bar"

        return None
