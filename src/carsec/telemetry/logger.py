"""
Structured event logging for the simulation.

Three sinks:
  * colour-coded console output (ANSI, suppressible with ``--no-color``);
  * a JSON log (machine-readable, SIEM/analysis friendly);
  * a CSV log (spreadsheet friendly).

Thread-safe: every ECU and attacker thread logs through one shared instance.
"""

from __future__ import annotations

import csv
import datetime
import json
import os
import threading
import time

from carsec.can.message import CANMessage


class C:
    """ANSI colour codes."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    ORANGE = "\033[38;5;208m"

    _ENABLED = True

    @classmethod
    def disable(cls) -> None:
        """Strip all colours (for ``--no-color`` / non-TTY output)."""
        cls._ENABLED = False
        for attr in (
            "RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW",
            "BLUE", "MAGENTA", "CYAN", "WHITE", "ORANGE",
        ):
            setattr(cls, attr, "")


# Map a log level to the C colour attribute names it uses.  Resolved live at
# print time so that C.disable() (──no-color) takes effect after import.
_LEVEL_COLORS = {
    "TX": ("BLUE",),
    "ACCEPT": ("GREEN",),
    "REJECT": ("RED", "BOLD"),
    "INJECT": ("MAGENTA", "BOLD"),
    "REPLAY": ("ORANGE", "BOLD"),
    "TAMPER": ("RED", "BOLD"),
    "DOS": ("RED", "BOLD"),
    "FUZZ": ("MAGENTA",),
    "ALERT": ("ORANGE", "BOLD"),
    "INFO": ("CYAN",),
    "WARN": ("YELLOW",),
}


def _color_for(level: str) -> str:
    return "".join(getattr(C, attr) for attr in _LEVEL_COLORS.get(level, ("WHITE",)))


class EventRecord:
    __slots__ = ("timestamp", "level", "actor", "message", "msg_id", "data", "freshness", "mac")

    def __init__(
        self,
        level: str,
        actor: str,
        message: str,
        msg: CANMessage | None = None,
    ) -> None:
        self.timestamp = time.time()
        self.level = level
        self.actor = actor
        self.message = message
        self.msg_id = msg.name if msg else ""
        self.data = msg.data.hex() if msg else ""
        self.freshness = msg.freshness if msg else 0
        self.mac = msg.mac.hex() if msg else ""

    def to_dict(self) -> dict:
        return {
            "timestamp": datetime.datetime.fromtimestamp(self.timestamp).isoformat(),
            "level": self.level,
            "actor": self.actor,
            "message": self.message,
            "msg_id": self.msg_id,
            "data": self.data,
            "freshness": self.freshness,
            "mac": self.mac,
        }


class EventLogger:
    """Thread-safe multi-sink event logger."""

    _CSV_FIELDS = ["timestamp", "level", "actor", "message", "msg_id", "data", "freshness", "mac"]

    def __init__(
        self,
        log_dir: str = "logs",
        prefix: str = "session",
        console: bool = True,
        verbose: bool = True,
        to_file: bool = True,
    ) -> None:
        self.console = console
        self.verbose = verbose
        self.to_file = to_file
        self._lock = threading.Lock()
        self._events: list[EventRecord] = []

        self._json_path = ""
        self._csv_path = ""
        if to_file:
            os.makedirs(log_dir, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            self._json_path = os.path.join(log_dir, f"{prefix}_{ts}.json")
            self._csv_path = os.path.join(log_dir, f"{prefix}_{ts}.csv")
            with open(self._csv_path, "w", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=self._CSV_FIELDS).writeheader()

    # ── Core ───────────────────────────────────────────────────────────────────

    def _record(self, rec: EventRecord) -> None:
        with self._lock:
            self._events.append(rec)
            if self.console:
                self._print(rec)
            if self.to_file:
                with open(self._csv_path, "a", newline="", encoding="utf-8") as fh:
                    csv.DictWriter(fh, fieldnames=self._CSV_FIELDS).writerow(rec.to_dict())

    def _print(self, rec: EventRecord) -> None:
        ts = datetime.datetime.fromtimestamp(rec.timestamp).strftime("%H:%M:%S.%f")[:-3]
        col = _color_for(rec.level)
        lvl = f"{col}{rec.level:<7}{C.RESET}"
        act = f"{C.DIM}[{rec.actor:<14}]{C.RESET}"
        msg_part = f" {C.DIM}⟨{rec.msg_id}⟩{C.RESET}" if rec.msg_id else ""
        print(f"  {C.DIM}{ts}{C.RESET}  {lvl}  {act}  {rec.message}{msg_part}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def log_tx(self, msg: CANMessage, sender: str) -> None:
        if not self.verbose:
            with self._lock:
                self._events.append(EventRecord("TX", sender, "", msg))
            return
        self._record(EventRecord("TX", sender, f"→ data={msg.data.hex()} fv={msg.freshness}", msg))

    def log_rx(self, msg: CANMessage, receiver: str, accepted: bool, reason: str) -> None:
        level = "ACCEPT" if accepted else "REJECT"
        status = "✓ accepted" if accepted else f"✗ REJECTED: {reason}"
        self._record(EventRecord(level, receiver, f"← {status}", msg))

    def log_event(
        self,
        level: str,
        actor: str,
        message: str,
        msg: CANMessage | None = None,
    ) -> None:
        self._record(EventRecord(level, actor, message, msg))

    def banner(self, title: str, subtitle: str = "") -> None:
        if not self.console:
            return
        print()
        print(f"{C.CYAN}{C.BOLD}  {'═' * 66}")
        print(f"    {title}")
        if subtitle:
            print(f"    {C.DIM}{subtitle}{C.RESET}{C.CYAN}{C.BOLD}")
        print(f"  {'═' * 66}{C.RESET}")
        print()

    # ── Sinks / summaries ──────────────────────────────────────────────────────

    def flush_json(self) -> str:
        if not self.to_file:
            return ""
        with self._lock:
            data = [e.to_dict() for e in self._events]
        with open(self._json_path, "w", encoding="utf-8") as fh:
            json.dump({"session": data}, fh, indent=2)
        return self._json_path

    def summary(self) -> dict[str, int]:
        with self._lock:
            levels = [e.level for e in self._events]
        return {
            "total": len(levels),
            "tx": levels.count("TX"),
            "accepted": levels.count("ACCEPT"),
            "rejected": levels.count("REJECT"),
            "attacks": levels.count("REPLAY") + levels.count("TAMPER") + levels.count("DOS"),
            "injected": levels.count("INJECT"),
            "alerts": levels.count("ALERT"),
        }

    @property
    def events(self) -> list[EventRecord]:
        return self._events

    @property
    def json_path(self) -> str:
        return self._json_path

    @property
    def csv_path(self) -> str:
        return self._csv_path
