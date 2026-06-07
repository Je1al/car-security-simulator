"""
IDS aggregator + detection metrics.

The :class:`IDS` attaches to the bus as a passive tap and runs every registered
sub-detector against each observed frame.  A frame is flagged if *any* detector
flags it (logical OR — favouring recall, the right trade-off for a safety bus).

Because the simulator labels every frame with ground truth (``msg.is_attack``),
the IDS can score itself with a real confusion matrix and report
precision / recall / F1 — the same way an automotive IDS is benchmarked against a
labelled CAN dataset.  This turns "I built an IDS" into "my IDS detects N% of
attacks at M% precision", which is what actually matters.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from carsec.can.message import CANMessage
from carsec.ids.entropy import EntropyDetector
from carsec.ids.frequency import FrequencyDetector
from carsec.ids.rules import RuleDetector
from carsec.telemetry.logger import EventLogger


@dataclass
class DetectionMetrics:
    """Confusion matrix and derived scores."""

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.true_positives + self.true_negatives) / self.total if self.total else 1.0

    def as_dict(self) -> dict[str, float]:
        return {
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "accuracy": round(self.accuracy, 3),
        }


class IDS:
    """Composite, passive CAN intrusion detection system."""

    def __init__(self, logger: EventLogger | None = None, detectors=None, alert: bool = True) -> None:
        self._logger = logger
        self._alert = alert
        self.detectors = detectors or [
            RuleDetector(),
            FrequencyDetector(),
            EntropyDetector(),
        ]
        self.metrics = DetectionMetrics()
        self.alerts: list[tuple[CANMessage, str, str]] = []
        # Per-detector hit counts for attribution.
        self.by_detector: dict[str, int] = {d.name: 0 for d in self.detectors}
        # The bus calls observe() from every ECU/attacker thread, so all detector
        # state and metrics updates are serialised here.
        self._lock = threading.Lock()

    def observe(self, msg: CANMessage) -> bool:
        """
        Inspect a frame; return True if flagged as anomalous.

        Updates the confusion matrix against ``msg.is_attack`` and (optionally)
        emits an ALERT log event on the first detector that fires.
        """
        now = time.time()
        with self._lock:
            flagged_by = None
            reason = ""
            for det in self.detectors:
                verdict = det.inspect(msg, now)
                if verdict is not None:
                    self.by_detector[det.name] += 1
                    if flagged_by is None:  # remember the first hit for the log line
                        flagged_by, reason = det.name, verdict

            is_alert = flagged_by is not None
            self._score(is_alert, msg.is_attack)
            if is_alert:
                self.alerts.append((msg.clone(), flagged_by, reason))

        # Log outside the lock to avoid holding it across I/O.
        if is_alert and self._alert and self._logger is not None:
            self._logger.log_event("ALERT", "IDS", f"[{flagged_by}] {reason}", msg)
        return is_alert

    def _score(self, predicted_attack: bool, actual_attack: bool) -> None:
        if predicted_attack and actual_attack:
            self.metrics.true_positives += 1
        elif predicted_attack and not actual_attack:
            self.metrics.false_positives += 1
        elif not predicted_attack and actual_attack:
            self.metrics.false_negatives += 1
        else:
            self.metrics.true_negatives += 1

    def report(self) -> dict:
        return {
            "metrics": self.metrics.as_dict(),
            "by_detector": dict(self.by_detector),
            "alerts": len(self.alerts),
        }
