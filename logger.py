"""
logger.py
────────────────────────────────────────────────────────────────────────────────
Structured event logging for the CAN bus simulation.

Outputs
  • Colour-coded console output (ANSI)
  • JSON log file  (machine-readable for SIEM / analysis)
  • CSV  log file  (human-readable spreadsheet)
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import csv
import datetime
import json
import os
import threading
import time
from typing import Dict, List, Optional

from can_protocol import CANMessage


# ─── ANSI colours ─────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m";  BOLD    = "\033[1m";  DIM    = "\033[2m"
    RED     = "\033[91m"; GREEN   = "\033[92m"; YELLOW = "\033[93m"
    CYAN    = "\033[96m"; BLUE    = "\033[94m"; MAGENTA= "\033[95m"
    WHITE   = "\033[97m"; ORANGE  = "\033[38;5;208m"


_LEVEL_COLORS = {
    "TX":      C.BLUE,
    "RX":      C.GREEN,
    "ACCEPT":  C.GREEN,
    "REJECT":  C.RED + C.BOLD,
    "ATTACK":  C.RED  + C.BOLD,
    "INJECT":  C.MAGENTA + C.BOLD,
    "REPLAY":  C.ORANGE + C.BOLD,
    "TAMPER":  C.RED + C.BOLD,
    "INFO":    C.CYAN,
    "WARN":    C.YELLOW,
    "SECURE":  C.GREEN + C.BOLD,
    "INSECURE":C.YELLOW + C.BOLD,
    "SECTION": C.CYAN + C.BOLD,
}


# ─── Event record ─────────────────────────────────────────────────────────────

class EventRecord:
    __slots__ = ("timestamp", "level", "actor", "message", "msg_id", "payload", "nonce", "hmac")

    def __init__(
        self,
        level:   str,
        actor:   str,
        message: str,
        msg:     Optional[CANMessage] = None,
    ) -> None:
        self.timestamp = time.time()
        self.level     = level
        self.actor     = actor
        self.message   = message
        self.msg_id    = msg.msg_name if msg else ""
        self.payload   = msg.payload.hex() if msg else ""
        self.nonce     = msg.nonce  if msg else 0
        self.hmac      = msg.hmac_tag.hex() if msg else ""

    def to_dict(self) -> Dict:
        return {
            "timestamp": datetime.datetime.fromtimestamp(self.timestamp).isoformat(),
            "level":     self.level,
            "actor":     self.actor,
            "message":   self.message,
            "msg_id":    self.msg_id,
            "payload":   self.payload,
            "nonce":     self.nonce,
            "hmac":      self.hmac,
        }


# ─── Logger ───────────────────────────────────────────────────────────────────

class EventLogger:
    """
    Thread-safe event logger.  Call log_*() methods from any thread.
    """

    def __init__(
        self,
        log_dir:   str  = "logs",
        prefix:    str  = "session",
        console:   bool = True,
        verbose:   bool = True,
    ) -> None:
        self.console = console
        self.verbose = verbose
        self._lock   = threading.Lock()
        self._events: List[EventRecord] = []

        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self._json_path = os.path.join(log_dir, f"{prefix}_{ts}.json")
        self._csv_path  = os.path.join(log_dir, f"{prefix}_{ts}.csv")

        # Write CSV header
        with open(self._csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "timestamp","level","actor","message","msg_id","payload","nonce","hmac"
            ])
            writer.writeheader()

    # ── Core logging ──────────────────────────────────────────────────────────

    def _record(self, rec: EventRecord) -> None:
        with self._lock:
            self._events.append(rec)
            if self.console:
                self._print(rec)
            # Append to CSV
            with open(self._csv_path, "a", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=list(rec.to_dict().keys())).writerow(rec.to_dict())

    def _print(self, rec: EventRecord) -> None:
        ts  = datetime.datetime.fromtimestamp(rec.timestamp).strftime("%H:%M:%S.%f")[:-3]
        col = _LEVEL_COLORS.get(rec.level, C.WHITE)
        lvl = f"{col}{rec.level:<9}{C.RESET}"
        act = f"{C.DIM}[{rec.actor:<14}]{C.RESET}"
        msg_part = ""
        if rec.msg_id:
            msg_part = f" {C.DIM}⟨{rec.msg_id}⟩{C.RESET}"
        print(f"  {C.DIM}{ts}{C.RESET}  {lvl}  {act}  {rec.message}{msg_part}")

    # ── Public API ────────────────────────────────────────────────────────────

    def log_tx(self, msg: CANMessage, sender: str) -> None:
        if not self.verbose:
            return
        rec = EventRecord("TX", sender, f"→ payload={msg.payload.hex()} nonce={msg.nonce}", msg)
        self._record(rec)

    def log_rx(self, msg: CANMessage, receiver: str, accepted: bool, reason: str) -> None:
        level  = "ACCEPT" if accepted else "REJECT"
        status = "✓ accepted" if accepted else f"✗ REJECTED: {reason}"
        rec = EventRecord(level, receiver, f"← {status}", msg)
        self._record(rec)

    def log_event(self, level: str, actor: str, message: str, msg: Optional[CANMessage] = None) -> None:
        rec = EventRecord(level, actor, message, msg)
        self._record(rec)

    def section(self, title: str) -> None:
        """Print a visible section separator."""
        line = "─" * (62 - len(title) - 2)
        print()
        print(f"  {C.CYAN}{C.BOLD}{'─'*4} {title} {line}{C.RESET}")

    def banner(self, title: str, subtitle: str = "") -> None:
        print()
        print(f"{C.CYAN}{C.BOLD}  {'═'*66}")
        print(f"    {title}")
        if subtitle:
            print(f"    {C.DIM}{subtitle}{C.RESET}{C.CYAN}{C.BOLD}")
        print(f"  {'═'*66}{C.RESET}")
        print()

    def flush_json(self) -> str:
        """Write all events to the JSON log file and return the path."""
        with self._lock:
            data = [e.to_dict() for e in self._events]
        with open(self._json_path, "w", encoding="utf-8") as fh:
            json.dump({"session": data}, fh, indent=2)
        return self._json_path

    def summary(self) -> Dict[str, int]:
        with self._lock:
            levels = [e.level for e in self._events]
        return {
            "total":    len(levels),
            "tx":       levels.count("TX"),
            "rx":       levels.count("RX"),
            "accepted": levels.count("ACCEPT"),
            "rejected": levels.count("REJECT"),
            "attacks":  levels.count("ATTACK") + levels.count("REPLAY") + levels.count("TAMPER"),
            "injected": levels.count("INJECT"),
        }

    @property
    def json_path(self) -> str:
        return self._json_path

    @property
    def csv_path(self) -> str:
        return self._csv_path
