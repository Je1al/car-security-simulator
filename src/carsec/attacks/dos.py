"""
Denial-of-Service via bus flooding.

CAN arbitration is priority-based: when two nodes transmit at once, the frame
with the numerically lower ID wins and the loser backs off.  An attacker who
continuously transmits a very high-priority frame (ID close to 0) therefore
*starves* every other ECU — legitimate safety frames never get bus time.  This
is the CAN equivalent of a flood DoS, and unlike injection it cannot be stopped
by a MAC: SecOC authenticates content, not bus access.  Defence lives elsewhere
(rate-based IDS, hardware bus guardians) — which is exactly why the IDS module
detects flooding by frequency rather than by signature.
"""

from __future__ import annotations

import os
import threading
import time

from carsec.can.bus import CANBus
from carsec.can.message import CANMessage
from carsec.telemetry.logger import EventLogger

# A deliberately high-priority (very low) arbitration ID — wins arbitration.
HIGH_PRIORITY_ID = 0x000


class BusFlooder:
    """Flood the bus with high-priority frames to deny service to other ECUs."""

    def __init__(self, name: str, bus: CANBus, logger: EventLogger) -> None:
        self.name = name
        self._bus = bus
        self._logger = logger
        self.frames_sent = 0

    def flood(
        self,
        duration: float = 1.0,
        rate_hz: float = 2000.0,
        arbitration_id: int = HIGH_PRIORITY_ID,
    ) -> int:
        """
        Blast frames for ``duration`` seconds at ``rate_hz`` frames/second.

        Returns the number of frames injected.  The frames carry no valid MAC —
        they don't need one; the harm is bus saturation, not acceptance.
        """
        interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
        self._logger.log_event(
            "DOS",
            self.name,
            f"flooding id=0x{arbitration_id:03X} for {duration:.1f}s @ {rate_hz:.0f} fps",
        )
        end = time.time() + duration
        sent = 0
        while time.time() < end:
            frame = CANMessage(
                arbitration_id=arbitration_id,
                data=os.urandom(8),
                sender=self.name,
                is_attack=True,
                attack_type="dos",
            )
            self._bus.inject(frame, injector=self.name)
            sent += 1
            if interval:
                time.sleep(interval)
        self.frames_sent += sent
        self._logger.log_event("DOS", self.name, f"flood complete — {sent} frames injected")
        return sent

    def flood_async(self, **kwargs) -> threading.Thread:
        """Run :meth:`flood` on a background daemon thread."""
        t = threading.Thread(target=self.flood, kwargs=kwargs, daemon=True)
        t.start()
        return t
