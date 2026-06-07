"""Brake Control Module (ABS ECU)."""

from __future__ import annotations

import random

from carsec.can.identifiers import (
    MSG_ID,
    decode_rpm,
    encode_brake_pressure,
    encode_status,
)
from carsec.can.message import CANMessage
from carsec.ecu.base import BaseECU


class BrakeECU(BaseECU):
    """
    Brake Control Module (models an ABS ECU).

    Transmits BRAKE_PRESS and BRAKE_STATUS; consumes ENGINE_RPM to track engine
    speed.  This is the safety-critical ECU whose frames an attacker most wants
    to spoof — disabling braking, or faking a brake event.
    """

    name = "ECU_Brake"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._pressure = 0.0  # bar
        self._engine_rpm = 800

    def build_messages(self) -> list[CANMessage]:
        if random.random() < 0.3:
            self._pressure = random.uniform(5.0, 80.0)
        else:
            self._pressure *= 0.85  # pressure bleeds off

        status = 0x01 if self._pressure > 10.0 else 0x00
        return [
            CANMessage(arbitration_id=MSG_ID["BRAKE_PRESS"], data=encode_brake_pressure(self._pressure)),
            CANMessage(arbitration_id=MSG_ID["BRAKE_STATUS"], data=encode_status(status)),
        ]

    def process(self, msg: CANMessage) -> None:
        if msg.arbitration_id == MSG_ID["ENGINE_RPM"]:
            self._engine_rpm = decode_rpm(msg.data)
