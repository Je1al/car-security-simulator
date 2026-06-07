"""Gateway ECU."""

from __future__ import annotations

from carsec.can.identifiers import MSG_ID, decode_rpm, encode_rpm
from carsec.can.message import CANMessage
from carsec.ecu.base import BaseECU


class GatewayECU(BaseECU):
    """
    Gateway ECU.

    In a real vehicle the gateway bridges bus segments (powertrain CAN ↔ body
    CAN ↔ infotainment Ethernet) and is a natural place to host an intrusion
    detection function — it already sees cross-domain traffic.  Here it forwards
    ENGINE_RPM frames and is the recommended host for :class:`carsec.ids.IDS`.
    """

    name = "ECU_Gateway"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._last_rpm = 0
        self._fwd_count = 0

    def build_messages(self) -> list[CANMessage]:
        if self._last_rpm > 0:
            self._fwd_count += 1
            return [CANMessage(arbitration_id=MSG_ID["GATEWAY_FWD"], data=encode_rpm(self._last_rpm))]
        return []

    def process(self, msg: CANMessage) -> None:
        if msg.arbitration_id == MSG_ID["ENGINE_RPM"]:
            self._last_rpm = decode_rpm(msg.data)
            self._logger.log_event("INFO", self.name, f"forwarding ENGINE_RPM={self._last_rpm}", msg)
