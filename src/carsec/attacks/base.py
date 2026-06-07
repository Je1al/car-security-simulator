"""
Passive sniffer + active attacker.

The attacker attaches as a bus *tap* — it sees a copy of every frame without
appearing as a registered node (modelling a rogue device spliced onto CAN_H /
CAN_L, or a compromised ECU listening promiscuously).  Captured frames feed the
replay and tamper techniques; the injection technique fabricates frames from
scratch.
"""

from __future__ import annotations

import os
import random
import threading
import time
from typing import Optional

from carsec.can.bus import CANBus
from carsec.can.identifiers import (
    MSG_ID,
    encode_brake_pressure,
    encode_rpm,
    encode_status,
)
from carsec.can.message import CANMessage
from carsec.telemetry.logger import EventLogger


class Attacker:
    """Sniff the bus, then replay / tamper / inject frames onto it."""

    def __init__(self, name: str, bus: CANBus, logger: EventLogger) -> None:
        self.name = name
        self._bus = bus
        self._logger = logger

        self._capture: dict[str, list[CANMessage]] = {}
        self._lock = threading.Lock()

        self.replays = 0
        self.tampers = 0
        self.injections = 0

        bus.add_tap(self._sniff)

    # ── Passive sniffing ───────────────────────────────────────────────────────

    def _sniff(self, msg: CANMessage) -> None:
        if msg.sender == self.name:
            return  # don't capture our own injected frames
        with self._lock:
            self._capture.setdefault(msg.name, []).append(msg.clone())
            if len(self._capture[msg.name]) > 32:  # bound memory
                self._capture[msg.name].pop(0)

    def captured_count(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._capture.values())

    def list_captured(self) -> dict[str, int]:
        with self._lock:
            return {k: len(v) for k, v in self._capture.items()}

    def wait_for_capture(self, count: int = 5, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.captured_count() >= count:
                return True
            time.sleep(0.05)
        return False

    # ── Attack 1: Replay ───────────────────────────────────────────────────────

    def replay(self, msg_name: str = "ENGINE_RPM") -> bool:
        """
        Re-transmit a captured frame verbatim.

        On an insecure bus the receiver re-acts to the stale frame.  Under SecOC
        the frame carries an already-seen Freshness Value (and a stale
        timestamp), so it is rejected as a replay.
        """
        with self._lock:
            pool = self._capture.get(msg_name, [])
            if not pool:
                self._logger.log_event("WARN", self.name, f"no captured {msg_name} to replay")
                return False
            frame = random.choice(pool).clone()

        frame.is_attack = True
        frame.attack_type = "replay"
        self.replays += 1
        self._logger.log_event(
            "REPLAY",
            self.name,
            f"replaying {msg_name} (fv={frame.freshness}, age={time.time() - frame.timestamp:.2f}s)",
            frame,
        )
        self._bus.inject(frame, injector=self.name)
        return True

    # ── Attack 2: Tamper ───────────────────────────────────────────────────────

    def tamper(self, msg_name: str = "ENGINE_RPM", new_data: Optional[bytes] = None) -> bool:
        """
        Modify a captured frame's payload and re-transmit.

        The MAC still authenticates the *original* payload, so under SecOC the
        recomputed MAC will not match — the frame is rejected.  On an insecure
        bus the change is accepted silently.
        """
        with self._lock:
            pool = self._capture.get(msg_name, [])
            if not pool:
                self._logger.log_event("WARN", self.name, f"no captured {msg_name} to tamper")
                return False
            frame = pool[-1].clone()

        original = frame.data
        if new_data is not None:
            frame.data = new_data[: len(frame.data)] if frame.data else new_data[:8]
        else:
            mutated = bytearray(frame.data or b"\x00")
            mutated[0] ^= 0xFF
            frame.data = bytes(mutated)

        frame.is_attack = True
        frame.attack_type = "tamper"
        self.tampers += 1
        self._logger.log_event(
            "TAMPER",
            self.name,
            f"{msg_name} payload {original.hex()} → {frame.data.hex()} (MAC still references original)",
            frame,
        )
        self._bus.inject(frame, injector=self.name)
        return True

    # ── Attack 3: Injection ────────────────────────────────────────────────────

    def inject(self, arbitration_id: Optional[int] = None, data: Optional[bytes] = None) -> bool:
        """
        Fabricate and inject a brand-new frame.

        The attacker does not know the key, so the frame has no valid MAC and is
        rejected under SecOC.  On an insecure bus it impersonates a trusted ECU.
        """
        if arbitration_id is None:
            arbitration_id = random.choice(
                [MSG_ID["BRAKE_PRESS"], MSG_ID["ENGINE_RPM"], MSG_ID["BRAKE_STATUS"]]
            )

        if data is None:
            if arbitration_id == MSG_ID["BRAKE_PRESS"]:
                data, desc = encode_brake_pressure(0.0), "brake_pressure=0.0 bar (DISABLE BRAKES)"
            elif arbitration_id == MSG_ID["ENGINE_RPM"]:
                data, desc = encode_rpm(9999), "rpm=9999 (FALSE OVER-REV)"
            elif arbitration_id == MSG_ID["BRAKE_STATUS"]:
                data, desc = encode_status(0xFF), "brake_status=0xFF (FAKE FAULT)"
            else:
                data, desc = os.urandom(2), "random payload"
        else:
            desc = f"data={data.hex()}"

        frame = CANMessage(
            arbitration_id=arbitration_id,
            data=data,
            freshness=random.randint(0, 2**32 - 1),  # bogus FV, no valid MAC
            sender=self.name,
            is_attack=True,
            attack_type="injection",
        )
        self.injections += 1
        self._logger.log_event("INJECT", self.name, f"fabricated {frame.name}: {desc}", frame)
        self._bus.inject(frame, injector=self.name)
        return True

    def summary(self) -> dict[str, int]:
        return {
            "captured": self.captured_count(),
            "replays": self.replays,
            "tampers": self.tampers,
            "injections": self.injections,
        }
