"""
Simulation runner — owns the ECU lifecycle and drives attack scenarios.

One logger is created up front and shared by the bus, every ECU, the attacker,
and (optionally) the IDS, so all statistics come from a single source of truth.
"""

from __future__ import annotations

import time

from carsec.attacks.base import Attacker
from carsec.can.bus import CANBus, VirtualCANBus
from carsec.can.identifiers import MSG_ID
from carsec.ecu.brake import BrakeECU
from carsec.ecu.engine import EngineECU
from carsec.ecu.gateway import GatewayECU
from carsec.ids.detector import IDS
from carsec.telemetry.logger import EventLogger


class SimulationRunner:
    """Wire up a vehicle network and run attack scenarios against it."""

    def __init__(
        self,
        secure: bool = True,
        delay_ms: float = 0.0,
        verbose: bool = False,
        log_prefix: str = "session",
        logger: EventLogger | None = None,
        with_ids: bool = False,
        bus: CANBus | None = None,
    ) -> None:
        self.secure = secure
        self.logger = logger or EventLogger(prefix=log_prefix, console=True, verbose=verbose)
        self.bus = bus or VirtualCANBus(delay_ms=delay_ms, logger=self.logger)
        self.attacker = Attacker("ATTACKER", self.bus, self.logger)

        self.ids: IDS | None = None
        if with_ids:
            self.ids = IDS(self.logger)
            self.bus.add_tap(self.ids.observe)

        self.ecus = [
            EngineECU(bus=self.bus, logger=self.logger, secure=secure),
            BrakeECU(bus=self.bus, logger=self.logger, secure=secure),
            GatewayECU(bus=self.bus, logger=self.logger, secure=secure),
        ]

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        for ecu in self.ecus:
            ecu.start()

    def stop(self) -> None:
        for ecu in self.ecus:
            ecu.stop()
        time.sleep(0.2)

    # ── Scenario bodies ────────────────────────────────────────────────────────

    def run_normal(self, duration: float = 2.5) -> None:
        self.start()
        time.sleep(duration)
        self.stop()

    def run_replay(self, duration: float = 2.0, wait_capture: float = 1.5) -> None:
        self.start()
        time.sleep(wait_capture)
        captured = self.attacker.list_captured()
        if captured:
            target = next(iter(captured))
            self.attacker.replay(target)
            time.sleep(0.3)
            self.attacker.replay(target)
        time.sleep(duration)
        self.stop()

    def run_tamper(self, duration: float = 2.0, wait_capture: float = 1.5) -> None:
        self.start()
        time.sleep(wait_capture)
        captured = self.attacker.list_captured()
        if captured:
            target = next(iter(captured))
            self.attacker.tamper(target)
            time.sleep(0.2)
            self.attacker.tamper("ENGINE_RPM", new_data=b"\xff\xff")
        time.sleep(duration)
        self.stop()

    def run_injection(self, duration: float = 2.0) -> None:
        self.start()
        time.sleep(0.5)
        self.attacker.inject(MSG_ID["BRAKE_PRESS"])
        time.sleep(0.2)
        self.attacker.inject(MSG_ID["BRAKE_STATUS"])
        time.sleep(0.2)
        self.attacker.inject(MSG_ID["ENGINE_RPM"])
        time.sleep(duration)
        self.stop()

    # ── Reporting ──────────────────────────────────────────────────────────────

    def summary(self) -> dict[str, int]:
        return self.logger.summary()
