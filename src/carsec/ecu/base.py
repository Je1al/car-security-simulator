"""
Base ECU.

An ECU is a small embedded computer that controls one or more vehicle
subsystems; a modern car has 70–150 of them.  Each simulated ECU runs two
daemon threads, mirroring an RTOS task split:

  * a **TX loop** that periodically builds and transmits status frames;
  * an **RX loop** that drains its inbox, verifies frames through the SecOC
    layer, and processes the accepted ones.

Subclasses implement :meth:`build_messages` (what to send each cycle) and
:meth:`process` (how to react to an accepted frame).
"""

from __future__ import annotations

import queue
import random
import threading
import time
from abc import ABC, abstractmethod

from carsec.can.bus import CANBus
from carsec.can.message import CANMessage
from carsec.security.secoc import SecOCLayer
from carsec.telemetry.logger import EventLogger


class BaseECU(ABC):
    """Abstract base for all ECUs."""

    name: str = "ECU"

    def __init__(
        self,
        bus: CANBus,
        logger: EventLogger,
        secure: bool = True,
        tx_interval: float = 0.5,
        name: str | None = None,
    ) -> None:
        if name is not None:
            self.name = name
        self._bus = bus
        self._logger = logger
        self._secure = secure
        self._tx_interval = tx_interval
        self._security = SecOCLayer(ecu_name=self.name, secure=secure)
        self._inbox = bus.register_node(self.name)
        self._running = False
        self._threads: list[threading.Thread] = []

        self.messages_sent = 0
        self.messages_received = 0
        self.messages_rejected = 0

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._threads = [
            threading.Thread(target=self._tx_loop, name=f"{self.name}-TX", daemon=True),
            threading.Thread(target=self._rx_loop, name=f"{self.name}-RX", daemon=True),
        ]
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._running = False

    def wait(self) -> None:
        for t in self._threads:
            t.join(timeout=2.0)

    # ── Threads ────────────────────────────────────────────────────────────────

    def _tx_loop(self) -> None:
        time.sleep(random.uniform(0.0, 0.1))  # de-synchronise startup
        while self._running:
            for raw in self.build_messages():
                signed = self._security.authenticate(raw)
                self._bus.send(signed, self.name)
                self.messages_sent += 1
            time.sleep(self._tx_interval)

    def _rx_loop(self) -> None:
        while self._running:
            try:
                msg = self._inbox.get(timeout=0.1)
            except queue.Empty:
                continue
            self.messages_received += 1
            result = self._security.verify(msg)
            self._logger.log_rx(msg, self.name, result.accepted, result.reason)
            if result.accepted:
                self.process(msg)
            else:
                self.messages_rejected += 1

    # ── Subclass interface ─────────────────────────────────────────────────────

    @abstractmethod
    def build_messages(self) -> list[CANMessage]:
        """Frames to transmit this cycle."""

    @abstractmethod
    def process(self, msg: CANMessage) -> None:
        """React to an accepted frame."""

    def __repr__(self) -> str:
        mode = "SECURE" if self._secure else "INSECURE"
        return f"{self.name}({mode}, sent={self.messages_sent}, recv={self.messages_received})"
