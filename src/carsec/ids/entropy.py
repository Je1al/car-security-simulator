"""
Payload-entropy detector.

Genuine signal payloads are highly structured: an RPM value occupies two bytes
with most bits rarely changing, so their Shannon entropy is low.  Random fuzzing
payloads (and many crafted injections) are close to uniformly random, giving high
entropy.  This detector learns a per-ID baseline mean entropy and flags payloads
whose entropy is far above it — a cheap complement that specifically targets
fuzzing.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Optional

from carsec.can.message import CANMessage


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string in bits/byte (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyDetector:
    """Per-ID payload-entropy anomaly detection."""

    name = "entropy"

    def __init__(
        self,
        warmup_frames: int = 4,
        abs_threshold: float = 2.5,
        margin: float = 1.5,
    ) -> None:
        # Flag when entropy exceeds both an absolute floor and baseline + margin.
        self.warmup_frames = warmup_frames
        self.abs_threshold = abs_threshold
        self.margin = margin
        self._baseline: dict[int, float] = {}
        self._count: dict[int, int] = defaultdict(int)

    def inspect(self, msg: CANMessage, now: float = 0.0) -> Optional[str]:
        arb = msg.arbitration_id
        ent = shannon_entropy(msg.data)
        self._count[arb] += 1

        base = self._baseline.get(arb)
        if base is None or self._count[arb] <= self.warmup_frames:
            self._baseline[arb] = ent if base is None else (base + ent) / 2
            return None

        if ent > self.abs_threshold and ent > base + self.margin:
            return f"payload entropy {ent:.2f} bits/byte >> baseline {base:.2f} for {msg.name}"

        self._baseline[arb] = 0.9 * base + 0.1 * ent
        return None
