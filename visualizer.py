"""
visualizer.py
────────────────────────────────────────────────────────────────────────────────
Generates visual charts from simulation log data.

Charts produced
  1. Message flow timeline   — who sent what and when
  2. Attack vs normal split  — bar chart of event categories
  3. Accept/Reject by mode   — comparing secure vs insecure outcomes
  4. Message sequence diagram (text-art) — printed to console
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
from typing import Dict, List, TYPE_CHECKING

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import matplotlib.gridspec as gridspec
    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False

if TYPE_CHECKING:
    from logger import EventLogger


# ─── Colour palette (dark automotive theme) ───────────────────────────────────

_C = {
    "normal":   "#2196F3",   # blue — normal traffic
    "attack":   "#F44336",   # red  — attacks
    "secure":   "#4CAF50",   # green — accepted
    "rejected": "#FF5722",   # deep-orange — rejected
    "warn":     "#FF9800",   # amber — warnings
    "bg":       "#1a1a2e",   # dark navy background
    "panel":    "#16213e",
    "text":     "#e0e0e0",
    "grid":     "#0f3460",
}


def _require_mpl() -> bool:
    if not _HAS_MPL:
        print("  [WARN] matplotlib not available — skipping charts")
        return False
    return True


class Visualizer:
    """Generate charts from a completed simulation session."""

    def __init__(self, output_dir: str = "logs") -> None:
        self._out = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(self, logger: "EventLogger", prefix: str = "sim") -> List[str]:
        if not _require_mpl():
            return []
        paths = []
        try:
            paths.append(self._event_timeline(logger, prefix))
        except Exception as e:
            print(f"  [WARN] Timeline chart failed: {e}")
        try:
            paths.append(self._attack_summary(logger, prefix))
        except Exception as e:
            print(f"  [WARN] Summary chart failed: {e}")
        try:
            paths.append(self._message_flow(logger, prefix))
        except Exception as e:
            print(f"  [WARN] Flow chart failed: {e}")
        return [p for p in paths if p]

    # ── Chart 1: Event timeline ───────────────────────────────────────────────

    def _event_timeline(self, logger: "EventLogger", prefix: str) -> str:
        events = logger._events
        if not events:
            return ""

        base_ts = events[0].timestamp
        times   = [e.timestamp - base_ts for e in events]

        level_map = {
            "TX":      (0,   _C["normal"]),
            "ACCEPT":  (1,   _C["secure"]),
            "REJECT":  (2,   _C["rejected"]),
            "REPLAY":  (3,   _C["attack"]),
            "TAMPER":  (3,   "#E91E63"),
            "INJECT":  (3,   "#9C27B0"),
            "ATTACK":  (3,   _C["attack"]),
            "INFO":    (0.5, _C["warn"]),
        }

        fig, ax = plt.subplots(figsize=(12, 4))
        fig.patch.set_facecolor(_C["bg"])
        ax.set_facecolor(_C["panel"])

        for e, t in zip(events, times):
            y_off, color = level_map.get(e.level, (0, "#888"))
            ax.scatter(t, y_off, color=color, s=30, alpha=0.8, zorder=3)

        ax.set_xlabel("Time (seconds)", color=_C["text"], fontsize=9)
        ax.set_title("Event Timeline", color=_C["text"], fontsize=12, fontweight="bold")
        ax.set_yticks([0, 0.5, 1, 2, 3])
        ax.set_yticklabels(["TX", "INFO", "ACCEPT", "REJECT", "ATTACK"], color=_C["text"], fontsize=8)
        ax.tick_params(colors=_C["text"])
        ax.spines[:].set_color(_C["grid"])
        ax.grid(True, color=_C["grid"], linewidth=0.5, alpha=0.5)

        legend_items = [
            mpatches.Patch(color=_C["normal"],   label="TX"),
            mpatches.Patch(color=_C["secure"],   label="ACCEPT"),
            mpatches.Patch(color=_C["rejected"], label="REJECT"),
            mpatches.Patch(color=_C["attack"],   label="ATTACK"),
        ]
        ax.legend(handles=legend_items, facecolor=_C["panel"],
                  labelcolor=_C["text"], fontsize=8, loc="upper right")

        plt.tight_layout()
        path = os.path.join(self._out, f"{prefix}_timeline.png")
        fig.savefig(path, dpi=120, bbox_inches="tight", facecolor=_C["bg"])
        plt.close(fig)
        return path

    # ── Chart 2: Attack summary bar ───────────────────────────────────────────

    def _attack_summary(self, logger: "EventLogger", prefix: str) -> str:
        summary = logger.summary()
        labels  = ["TX", "ACCEPT", "REJECT", "ATTACKS", "INJECTED"]
        values  = [
            summary.get("tx", 0),
            summary.get("accepted", 0),
            summary.get("rejected", 0),
            summary.get("attacks", 0),
            summary.get("injected", 0),
        ]
        colors = [_C["normal"], _C["secure"], _C["rejected"], _C["attack"], "#9C27B0"]

        fig, ax = plt.subplots(figsize=(8, 4))
        fig.patch.set_facecolor(_C["bg"])
        ax.set_facecolor(_C["panel"])

        bars = ax.bar(labels, values, color=colors, edgecolor=_C["bg"], linewidth=1.5,
                      width=0.6)
        ax.bar_label(bars, padding=4, color=_C["text"], fontsize=10, fontweight="bold")

        ax.set_title("Simulation Event Summary", color=_C["text"], fontsize=12, fontweight="bold")
        ax.set_ylabel("Count", color=_C["text"], fontsize=9)
        ax.tick_params(colors=_C["text"])
        ax.spines[:].set_color(_C["grid"])
        ax.grid(True, axis="y", color=_C["grid"], linewidth=0.5, alpha=0.5)

        plt.tight_layout()
        path = os.path.join(self._out, f"{prefix}_summary.png")
        fig.savefig(path, dpi=120, bbox_inches="tight", facecolor=_C["bg"])
        plt.close(fig)
        return path

    # ── Chart 3: Message flow matrix ─────────────────────────────────────────

    def _message_flow(self, logger: "EventLogger", prefix: str) -> str:
        actors = ["ECU_Engine", "ECU_Brake", "ECU_Gateway", "ATTACKER"]
        events = [e for e in logger._events if e.level in ("TX","ACCEPT","REJECT","REPLAY","TAMPER","INJECT")]
        if len(events) < 2:
            return ""

        # Count events per actor
        actor_counts = {a: 0 for a in actors}
        attack_counts= {a: 0 for a in actors}
        for e in logger._events:
            if e.actor in actor_counts:
                actor_counts[e.actor] += 1
            if e.level in ("REPLAY","TAMPER","INJECT","ATTACK") and e.actor in attack_counts:
                attack_counts[e.actor] += 1

        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        fig.patch.set_facecolor(_C["bg"])
        for ax in axes:
            ax.set_facecolor(_C["panel"])

        # Left: total events per actor
        ax = axes[0]
        bars = ax.barh(
            list(actor_counts.keys()),
            list(actor_counts.values()),
            color=[_C["normal"], _C["secure"], _C["warn"], _C["attack"]],
            edgecolor=_C["bg"],
        )
        ax.bar_label(bars, padding=4, color=_C["text"], fontsize=9)
        ax.set_title("Events per Actor", color=_C["text"], fontsize=11, fontweight="bold")
        ax.tick_params(colors=_C["text"])
        ax.spines[:].set_color(_C["grid"])

        # Right: attack events per actor
        ax = axes[1]
        attack_vals = [attack_counts[a] for a in actors]
        bars = ax.barh(actors, attack_vals, color=_C["attack"], edgecolor=_C["bg"])
        ax.bar_label(bars, padding=4, color=_C["text"], fontsize=9)
        ax.set_title("Attack Events per Actor", color=_C["text"], fontsize=11, fontweight="bold")
        ax.tick_params(colors=_C["text"])
        ax.spines[:].set_color(_C["grid"])

        plt.tight_layout()
        path = os.path.join(self._out, f"{prefix}_flow.png")
        fig.savefig(path, dpi=120, bbox_inches="tight", facecolor=_C["bg"])
        plt.close(fig)
        return path


# ─── Console sequence diagram (text-art) ─────────────────────────────────────

class SequenceDiagram:
    """
    Prints a simple ASCII sequence diagram of message flow.
    
    Example output:
      ECU_Engine    ECU_Brake    ECU_Gateway   ATTACKER
          │              │            │             │
          │─ENGINE_RPM──▶│            │             │
          │──────────────┼─ENGINE_RPM▶│             │
          │              │─BRAKE_PRESS┼────────────▶│ (sniff)
    """

    ACTORS = ["ECU_Engine", "ECU_Brake", "ECU_Gateway", "ATTACKER"]
    COL_W  = 14

    def __init__(self, logger: "EventLogger") -> None:
        self._events = logger._events

    def print(self, max_events: int = 30) -> None:
        from logger import C

        actors = self.ACTORS
        header = "".join(f"{a:<{self.COL_W}}" for a in actors)
        print(f"\n  {C.CYAN}{C.BOLD}{header}{C.RESET}")

        sep = "│" + " " * (self.COL_W - 1)
        print("  " + (sep * len(actors)))

        shown = 0
        for e in self._events:
            if shown >= max_events:
                print(f"  {C.DIM}  ... (truncated){C.RESET}")
                break
            if e.level not in ("TX", "REPLAY", "INJECT", "TAMPER"):
                continue

            actor_idx = actors.index(e.actor) if e.actor in actors else -1
            if actor_idx < 0:
                continue

            color = {
                "TX":     C.BLUE,
                "REPLAY": C.ORANGE if hasattr(C, "ORANGE") else C.YELLOW,
                "INJECT": C.MAGENTA,
                "TAMPER": C.RED,
            }.get(e.level, C.WHITE)

            label = e.msg_id[:8] if e.msg_id else "???"
            flag  = {"REPLAY": "[RPL]", "TAMPER": "[TMP]", "INJECT": "[INJ]"}.get(e.level, "")

            row = ["│" + " " * (self.COL_W - 1)] * len(actors)
            row[actor_idx] = f"{color}{'─'*(self.COL_W-3)}▶ {C.RESET}"

            line = "  " + "".join(row)
            print(f"  {C.DIM}{e.actor:<14}{C.RESET} {color}{label}{flag}{C.RESET}")
            shown += 1

        print("  " + (sep * len(actors)))
