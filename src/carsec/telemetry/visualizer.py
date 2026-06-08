"""
Chart generation from a completed session (optional — requires matplotlib).

Install with ``pip install carsec[viz]``.  Without matplotlib the functions
degrade gracefully and print a hint instead of failing.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.patches as mpatches
    import matplotlib.pyplot as plt

    _HAS_MPL = True
except ImportError:  # pragma: no cover - exercised only without matplotlib
    _HAS_MPL = False

if TYPE_CHECKING:
    from carsec.telemetry.logger import EventLogger

_PALETTE = {
    "normal": "#2196F3",
    "secure": "#4CAF50",
    "rejected": "#FF5722",
    "attack": "#F44336",
    "alert": "#FF9800",
    "bg": "#1a1a2e",
    "panel": "#16213e",
    "text": "#e0e0e0",
    "grid": "#0f3460",
}


class Visualizer:
    """Render summary charts for a session."""

    def __init__(self, output_dir: str = "logs") -> None:
        self._out = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def available(self) -> bool:
        return _HAS_MPL

    def generate_all(self, logger: EventLogger, prefix: str = "sim") -> list[str]:
        if not _HAS_MPL:
            print("  [hint] install matplotlib (pip install carsec[viz]) for charts")
            return []
        paths = []
        for fn in (self._timeline, self._summary_bars):
            try:
                p = fn(logger, prefix)
                if p:
                    paths.append(p)
            except Exception as exc:  # pragma: no cover
                print(f"  [warn] chart failed: {exc}")
        return paths

    def _timeline(self, logger: EventLogger, prefix: str) -> str:
        events = logger.events
        if not events:
            return ""
        base = events[0].timestamp
        rows = {"TX": 0, "INFO": 0.5, "ACCEPT": 1, "REJECT": 2, "ALERT": 2.5}
        colors = {
            "TX": _PALETTE["normal"],
            "ACCEPT": _PALETTE["secure"],
            "REJECT": _PALETTE["rejected"],
            "ALERT": _PALETTE["alert"],
            "REPLAY": _PALETTE["attack"],
            "TAMPER": _PALETTE["attack"],
            "INJECT": "#9C27B0",
            "DOS": _PALETTE["attack"],
        }
        fig, ax = plt.subplots(figsize=(12, 4))
        fig.patch.set_facecolor(_PALETTE["bg"])
        ax.set_facecolor(_PALETTE["panel"])
        for e in events:
            y = rows.get(e.level, 3)
            ax.scatter(e.timestamp - base, y, color=colors.get(e.level, "#888"), s=28, alpha=0.85)
        ax.set_title("Event Timeline", color=_PALETTE["text"], fontweight="bold")
        ax.set_xlabel("Time (s)", color=_PALETTE["text"])
        ax.tick_params(colors=_PALETTE["text"])
        ax.spines[:].set_color(_PALETTE["grid"])
        ax.grid(True, color=_PALETTE["grid"], alpha=0.4)
        ax.legend(
            handles=[
                mpatches.Patch(color=_PALETTE["normal"], label="TX"),
                mpatches.Patch(color=_PALETTE["secure"], label="ACCEPT"),
                mpatches.Patch(color=_PALETTE["rejected"], label="REJECT"),
                mpatches.Patch(color=_PALETTE["alert"], label="IDS ALERT"),
            ],
            facecolor=_PALETTE["panel"], labelcolor=_PALETTE["text"], fontsize=8,
        )
        plt.tight_layout()
        path = os.path.join(self._out, f"{prefix}_timeline.png")
        fig.savefig(path, dpi=120, facecolor=_PALETTE["bg"])
        plt.close(fig)
        return path

    def _summary_bars(self, logger: EventLogger, prefix: str) -> str:
        s = logger.summary()
        labels = ["TX", "Accept", "Reject", "Injected", "Alerts"]
        values = [s["tx"], s["accepted"], s["rejected"], s["injected"], s["alerts"]]
        colors = [
            _PALETTE["normal"], _PALETTE["secure"], _PALETTE["rejected"],
            "#9C27B0", _PALETTE["alert"],
        ]
        fig, ax = plt.subplots(figsize=(8, 4))
        fig.patch.set_facecolor(_PALETTE["bg"])
        ax.set_facecolor(_PALETTE["panel"])
        bars = ax.bar(labels, values, color=colors)
        ax.bar_label(bars, color=_PALETTE["text"], fontweight="bold")
        ax.set_title("Session Summary", color=_PALETTE["text"], fontweight="bold")
        ax.tick_params(colors=_PALETTE["text"])
        ax.spines[:].set_color(_PALETTE["grid"])
        plt.tight_layout()
        path = os.path.join(self._out, f"{prefix}_summary.png")
        fig.savefig(path, dpi=120, facecolor=_PALETTE["bg"])
        plt.close(fig)
        return path
