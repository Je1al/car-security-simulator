"""
CAN fuzzing.

Fuzzing feeds malformed or unexpected frames to ECUs to discover inputs they
mishandle — out-of-range signals, unknown IDs, reserved values.  It is a staple
of automotive penetration testing (and ISO/SAE 21434 verification): a robust ECU
must safely ignore frames it does not expect.

Two strategies:
  * ``random``   — random arbitration IDs and random payloads (broad coverage);
  * ``mutation`` — flip bits / bytes in a seed frame (focused, finds boundary
    bugs near valid traffic).
"""

from __future__ import annotations

import os
import random

from carsec.can.bus import CANBus
from carsec.can.message import CANMessage
from carsec.telemetry.logger import EventLogger


class CANFuzzer:
    """Generate and inject malformed CAN frames."""

    def __init__(self, name: str, bus: CANBus, logger: EventLogger) -> None:
        self.name = name
        self._bus = bus
        self._logger = logger
        self.frames_sent = 0

    def _emit(self, frame: CANMessage) -> None:
        frame.sender = self.name
        frame.is_attack = True
        frame.attack_type = "fuzz"
        self._bus.inject(frame, injector=self.name)
        self.frames_sent += 1

    def fuzz_random(self, count: int = 50, id_range: int = 0x7FF) -> int:
        """Inject ``count`` frames with random IDs (0..id_range) and payloads."""
        self._logger.log_event("FUZZ", self.name, f"random fuzzing — {count} frames")
        for _ in range(count):
            self._emit(
                CANMessage(
                    arbitration_id=random.randint(0, id_range),
                    data=os.urandom(random.randint(0, 8)),
                )
            )
        return count

    def fuzz_mutation(self, seed: CANMessage, count: int = 50) -> int:
        """Inject ``count`` bit/byte-mutated variants of a seed frame."""
        self._logger.log_event(
            "FUZZ", self.name, f"mutation fuzzing {seed.name} — {count} frames"
        )
        for _ in range(count):
            data = bytearray(seed.data or b"\x00" * 8)
            if data:
                idx = random.randrange(len(data))
                data[idx] ^= 1 << random.randrange(8)
            self._emit(CANMessage(arbitration_id=seed.arbitration_id, data=bytes(data)))
        return count
