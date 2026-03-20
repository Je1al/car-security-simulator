"""
ecu.py
────────────────────────────────────────────────────────────────────────────────
Electronic Control Unit (ECU) simulation.

What is an ECU?
───────────────
An ECU is a small embedded computer inside a vehicle that controls one or more
subsystems.  Modern vehicles contain 70–150 ECUs.  Examples:
  • Engine Control Unit (ECU/ECM) — manages fuel injection, ignition, RPM
  • Brake Control Module (BCM/ABS) — anti-lock braking, electronic stability
  • Gateway ECU — bridges different bus segments (CAN, LIN, Ethernet)
  • Telematics Control Unit (TCU) — cellular connectivity (attack surface!)

In this simulation we implement three ECUs that communicate over the shared
CAN bus.  Each ECU runs its own thread (simulating an RTOS task on real hardware).

Thread model
─────────────
  ECU thread 1: _tx_loop — periodically sends status messages
  ECU thread 2: _rx_loop — reads inbox and processes/validates messages

────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import queue
import random
import struct
import threading
import time
from abc import ABC, abstractmethod
from typing import List, Optional

from can_protocol import (
    CANMessage, MSG_ID,
    encode_rpm, encode_temperature, encode_brake_pressure, encode_status,
    decode_rpm, decode_temperature, decode_brake_pressure, decode_status,
)
from security  import SecurityLayer, VerificationResult
from network   import CANBus
from logger    import EventLogger


# ─── Base ECU ─────────────────────────────────────────────────────────────────

class BaseECU(ABC):
    """
    Abstract base for all ECU implementations.

    Subclasses must implement:
      _build_messages() → list of messages to transmit each cycle
      _process(msg)     → handle a received and validated message
    """

    def __init__(
        self,
        name:       str,
        bus:        CANBus,
        logger:     EventLogger,
        secure:     bool  = True,
        tx_interval:float = 0.5,   # seconds between transmit cycles
    ) -> None:
        self.name        = name
        self._bus        = bus
        self._logger     = logger
        self._secure     = secure
        self._tx_interval= tx_interval
        self._security   = SecurityLayer(ecu_name=name, secure=secure)
        self._inbox      = bus.register_node(name)
        self._running    = False
        self._threads: List[threading.Thread] = []

        # State
        self.messages_sent     = 0
        self.messages_received = 0
        self.messages_rejected = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start TX and RX threads."""
        self._running = True
        tx = threading.Thread(target=self._tx_loop, name=f"{self.name}-TX", daemon=True)
        rx = threading.Thread(target=self._rx_loop, name=f"{self.name}-RX", daemon=True)
        self._threads = [tx, rx]
        tx.start()
        rx.start()

    def stop(self) -> None:
        """Signal threads to stop."""
        self._running = False

    def wait(self) -> None:
        """Wait for all threads to finish."""
        for t in self._threads:
            t.join(timeout=2.0)

    # ── Transmit loop ─────────────────────────────────────────────────────────

    def _tx_loop(self) -> None:
        """Periodically build and transmit messages."""
        # Small random startup jitter to avoid lockstep behaviour
        time.sleep(random.uniform(0.0, 0.1))
        while self._running:
            for raw_msg in self._build_messages():
                signed = self._security.prepare(raw_msg)
                self._bus.transmit(signed, self.name)
                self.messages_sent += 1
            time.sleep(self._tx_interval)

    # ── Receive loop ──────────────────────────────────────────────────────────

    def _rx_loop(self) -> None:
        """Continuously drain inbox and process valid messages."""
        while self._running:
            try:
                msg: CANMessage = self._inbox.get(timeout=0.1)
            except queue.Empty:
                continue

            self.messages_received += 1
            result = self._security.verify(msg)
            self._logger.log_rx(msg, self.name, result.accepted, result.reason)

            if result.accepted:
                self._process(msg)
            else:
                self.messages_rejected += 1

    # ── Abstract interface ────────────────────────────────────────────────────

    @abstractmethod
    def _build_messages(self) -> List[CANMessage]:
        """Return a list of messages to transmit this cycle."""
        ...

    @abstractmethod
    def _process(self, msg: CANMessage) -> None:
        """Handle a received, verified message."""
        ...

    def __repr__(self) -> str:
        mode = "SECURE" if self._secure else "INSECURE"
        return f"{self.name}({mode}, sent={self.messages_sent}, recv={self.messages_received})"


# ─── ECU_Engine ───────────────────────────────────────────────────────────────

class ECU_Engine(BaseECU):
    """
    Engine Control Unit.

    Transmits:
      • ENGINE_RPM    — current engine revolutions per minute
      • ENGINE_TEMP   — coolant temperature (°C)

    Processes:
      • BRAKE_STATUS  — reduces fuel injection if brakes are hard-applied
      • GATEWAY_ACK   — acknowledges gateway forwarding
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="ECU_Engine", **kwargs)
        self._rpm   = 800    # idle RPM
        self._temp  = 20.0   # cold start temperature

    def _build_messages(self) -> List[CANMessage]:
        # Simulate engine warm-up
        self._temp = min(90.0, self._temp + random.uniform(0.5, 2.0))
        self._rpm  = random.randint(800, 3500)

        return [
            CANMessage(msg_id=MSG_ID["ENGINE_RPM"],  payload=encode_rpm(self._rpm)),
            CANMessage(msg_id=MSG_ID["ENGINE_TEMP"], payload=encode_temperature(self._temp)),
        ]

    def _process(self, msg: CANMessage) -> None:
        if msg.msg_id == MSG_ID["BRAKE_STATUS"]:
            status = decode_status(msg.payload)
            if status > 0:
                self._rpm = max(800, self._rpm - 200)
                self._logger.log_event(
                    "INFO", self.name,
                    f"Brake detected (status={status:#04x}) — reducing RPM to {self._rpm}",
                )
        elif msg.msg_id == MSG_ID["GATEWAY_ACK"]:
            self._logger.log_event("INFO", self.name, "Gateway acknowledged")


# ─── ECU_Brake ────────────────────────────────────────────────────────────────

class ECU_Brake(BaseECU):
    """
    Brake Control Module (simulates ABS ECU).

    Transmits:
      • BRAKE_PRESS   — hydraulic brake pressure (bar)
      • BRAKE_STATUS  — combined brake status byte

    Processes:
      • ENGINE_RPM    — uses RPM to adjust brake sensitivity
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="ECU_Brake", **kwargs)
        self._pressure = 0.0   # bar
        self._engine_rpm = 800

    def _build_messages(self) -> List[CANMessage]:
        # Simulate sporadic braking
        if random.random() < 0.3:
            self._pressure = random.uniform(5.0, 80.0)
        else:
            self._pressure *= 0.85   # pressure release

        status = 0x01 if self._pressure > 10.0 else 0x00

        return [
            CANMessage(msg_id=MSG_ID["BRAKE_PRESS"],  payload=encode_brake_pressure(self._pressure)),
            CANMessage(msg_id=MSG_ID["BRAKE_STATUS"],  payload=encode_status(status)),
        ]

    def _process(self, msg: CANMessage) -> None:
        if msg.msg_id == MSG_ID["ENGINE_RPM"]:
            self._engine_rpm = decode_rpm(msg.payload)


# ─── ECU_Gateway ──────────────────────────────────────────────────────────────

class ECU_Gateway(BaseECU):
    """
    Gateway ECU — in real vehicles this bridges different bus segments
    (e.g. powertrain CAN ↔ body CAN ↔ infotainment Ethernet).

    Here it:
      • Receives all messages and logs their content (intrusion detection point)
      • Forwards ENGINE_RPM messages as GATEWAY_FWD
      • Sends GATEWAY_ACK to engine
      • Acts as the primary anomaly detector in secure mode
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(name="ECU_Gateway", **kwargs)
        self._last_rpm  = 0
        self._fwd_count = 0

    def _build_messages(self) -> List[CANMessage]:
        if self._last_rpm > 0:
            self._fwd_count += 1
            return [
                CANMessage(
                    msg_id=MSG_ID["GATEWAY_FWD"],
                    payload=encode_rpm(self._last_rpm),
                ),
            ]
        return []

    def _process(self, msg: CANMessage) -> None:
        if msg.msg_id == MSG_ID["ENGINE_RPM"]:
            self._last_rpm = decode_rpm(msg.payload)
            self._logger.log_event(
                "INFO", self.name,
                f"Forwarding ENGINE_RPM={self._last_rpm}",
                msg,
            )
