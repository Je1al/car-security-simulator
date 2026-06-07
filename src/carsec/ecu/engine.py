"""Engine Control Unit."""

from __future__ import annotations

import random

from carsec.can.identifiers import (
    MSG_ID,
    decode_status,
    encode_rpm,
    encode_temperature,
)
from carsec.can.message import CANMessage
from carsec.ecu.base import BaseECU


class EngineECU(BaseECU):
    """
    Engine Control Unit.

    Transmits ENGINE_RPM and ENGINE_TEMP.  Reacts to BRAKE_STATUS (eases the
    throttle when the brakes are applied) and GATEWAY_ACK.
    """

    name = "ECU_Engine"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._rpm = 800  # idle
        self._temp = 20.0  # cold start

    def build_messages(self) -> list[CANMessage]:
        self._temp = min(90.0, self._temp + random.uniform(0.5, 2.0))
        self._rpm = random.randint(800, 3500)
        return [
            CANMessage(arbitration_id=MSG_ID["ENGINE_RPM"], data=encode_rpm(self._rpm)),
            CANMessage(arbitration_id=MSG_ID["ENGINE_TEMP"], data=encode_temperature(self._temp)),
        ]

    def process(self, msg: CANMessage) -> None:
        if msg.arbitration_id == MSG_ID["BRAKE_STATUS"]:
            if decode_status(msg.data) > 0:
                self._rpm = max(800, self._rpm - 200)
                self._logger.log_event(
                    "INFO", self.name, f"brake detected — easing throttle to {self._rpm} rpm"
                )
        elif msg.arbitration_id == MSG_ID["GATEWAY_ACK"]:
            self._logger.log_event("INFO", self.name, "gateway acknowledged")
