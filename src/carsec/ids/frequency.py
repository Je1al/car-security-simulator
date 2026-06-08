"""
Frequency / inter-arrival-time detector.

The most effective and widely-published CAN IDS technique exploits the fact that
periodic CAN frames arrive at a near-constant rate.  Injecting, replaying, or
flooding a message necessarily *adds* frames, shrinking the gap between
consecutive frames of that ID below its learned period.

This detector learns a per-ID baseline period (exponentially-weighted moving
average) during a warm-up window, then flags any frame that arrives sooner than
``tolerance × baseline``.  It needs no payload knowledge, so it catches replay
of valid frames and flooding of unknown IDs that the rule detector also sees.
"""

from __future__ import annotations

from collections import defaultdict

from carsec.can.message import CANMessage


class FrequencyDetector:
    """Per-ID inter-arrival anomaly detection."""

    name = "frequency"

    def __init__(
        self,
        warmup_frames: int = 4,
        tolerance: float = 0.4,
        ewma_alpha: float = 0.3,
    ) -> None:
        # A frame is anomalous if it arrives in less than tolerance × baseline.
        self.tolerance = tolerance
        self.warmup_frames = warmup_frames
        self.alpha = ewma_alpha
        self._last_ts: dict[int, float] = {}
        self._period: dict[int, float] = {}
        self._count: dict[int, int] = defaultdict(int)

    def inspect(self, msg: CANMessage, now: float) -> str | None:
        # ``now`` is the *arrival* time supplied by the IDS, not the frame's
        # embedded timestamp — a passive monitor times frames as it sees them, so
        # a replayed frame (carrying a stale timestamp) still shows a short gap.
        arb = msg.arbitration_id
        self._count[arb] += 1

        last = self._last_ts.get(arb)
        self._last_ts[arb] = now
        if last is None:
            return None

        gap = now - last
        baseline = self._period.get(arb)

        # Still learning this ID's cadence — update the baseline, don't judge.
        if baseline is None or self._count[arb] <= self.warmup_frames:
            self._period[arb] = gap if baseline is None else (
                self.alpha * gap + (1 - self.alpha) * baseline
            )
            return None

        if gap < self.tolerance * baseline:
            return (
                f"inter-arrival {gap * 1000:.1f}ms << baseline "
                f"{baseline * 1000:.1f}ms for {msg.name}"
            )

        # Normal frame: keep the baseline adapting to slow drift.
        self._period[arb] = self.alpha * gap + (1 - self.alpha) * baseline
        return None
