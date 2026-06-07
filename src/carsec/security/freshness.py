"""
Freshness Value management (AUTOSAR SecOC).

The MAC alone authenticates *content* but not *recency*: an attacker can capture
a perfectly valid secured frame and replay it byte-for-byte.  SecOC defeats this
with a **Freshness Value (FV)** — a monotonically increasing value bound into the
MAC computation.

This module implements the *counter-based* freshness profile (the simplest of
the AUTOSAR profiles, equivalent in spirit to the TLS record sequence number):

* Each secured I-PDU (keyed here by its Data ID) has an independent counter.
* The **sender** increments its counter for every secured frame and binds the
  full counter value into the MAC.
* The **receiver** tracks the highest FV accepted per Data ID and rejects any
  frame whose FV is not strictly greater (with a small forward window to tolerate
  lost frames), defeating replay.

A real ECU additionally synchronises a truncated FV over the wire and a master
FV via a dedicated message; we carry the full FV on the simulated wire to keep
the focus on the security property rather than the synchronisation plumbing.
"""

from __future__ import annotations

from collections import defaultdict


class FreshnessManager:
    """Per-Data-ID monotonic Freshness Value counters (send + receive sides)."""

    def __init__(self, accept_window: int = 64) -> None:
        # How far ahead of the last-accepted FV a frame may jump and still be
        # accepted (tolerates legitimately lost frames). Replays — which carry an
        # FV <= the last accepted one — are always rejected.
        self.accept_window = accept_window
        self._tx_counter: dict[int, int] = defaultdict(int)
        self._rx_highest: dict[int, int] = defaultdict(int)

    # ── Sender side ────────────────────────────────────────────────────────────

    def next_value(self, data_id: int) -> int:
        """Return the next freshness value for a Data ID and advance the counter."""
        self._tx_counter[data_id] += 1
        return self._tx_counter[data_id]

    # ── Receiver side ──────────────────────────────────────────────────────────

    def is_fresh(self, data_id: int, value: int) -> bool:
        """
        Check freshness *without* committing it.

        Returns True if ``value`` is strictly greater than the last accepted FV
        for this Data ID and within the forward acceptance window.
        """
        last = self._rx_highest[data_id]
        return last < value <= last + self.accept_window

    def commit(self, data_id: int, value: int) -> None:
        """Record ``value`` as accepted (call only after the MAC verifies)."""
        if value > self._rx_highest[data_id]:
            self._rx_highest[data_id] = value

    def reset(self, data_id: int | None = None) -> None:
        """Reset counters (e.g. on ECU reboot / re-sync)."""
        if data_id is None:
            self._tx_counter.clear()
            self._rx_highest.clear()
        else:
            self._tx_counter.pop(data_id, None)
            self._rx_highest.pop(data_id, None)
