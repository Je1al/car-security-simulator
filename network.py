"""
network.py
────────────────────────────────────────────────────────────────────────────────
Simulates the physical CAN bus as a shared broadcast medium.

Real CAN bus properties modelled
──────────────────────────────────
  • Broadcast — every node on the bus receives every message, regardless of
    intended recipient.  Filtering is done in software (acceptance masks).
  • Single shared medium — in a real vehicle all ECUs connect to two wires
    (CAN_H / CAN_L).  We model this as a shared Python queue.
  • Propagation delay — real CAN at 500 kbit/s: one frame (~108 bits) takes
    ~216 µs.  We support configurable artificial delay for realism.
  • Arbitration — when two nodes transmit simultaneously the lower ID wins.
    Not modelled here (no concurrent transmitters in our simulation).
  • Eavesdropping — because CAN is broadcast, any node (including a rogue one)
    can passively listen.  This is the prerequisite for replay attacks.

Architecture
──────────────
  CANBus
    ├── _queue     : thread-safe queue of (CANMessage, sender_name) tuples
    ├── _listeners : dict[str, queue.Queue] — one inbox per registered node
    ├── _sniffer   : optional eavesdropper callback (used by Attacker)
    └── _log       : EventLogger reference
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Callable, Dict, List, Optional

from can_protocol import CANMessage


# ─── Type aliases ─────────────────────────────────────────────────────────────

SnifferCallback = Callable[[CANMessage], None]


# ─── CANBus ───────────────────────────────────────────────────────────────────

class CANBus:
    """
    Thread-safe simulated CAN bus.

    Nodes register with register_node() to get a personal inbox.
    Any node can call transmit() to broadcast a message to all other nodes.
    The bus optionally forwards every frame to a sniffer (the Attacker).
    """

    def __init__(
        self,
        name:        str   = "CAN0",
        delay_ms:    float = 0.0,   # artificial propagation delay
        logger=None,
    ) -> None:
        self.name     = name
        self.delay_ms = delay_ms
        self._logger  = logger

        # Per-node inbox queues (node_name → queue)
        self._listeners: Dict[str, queue.Queue] = {}
        self._lock = threading.Lock()

        # Passive sniffer (e.g. Attacker)
        self._sniffer: Optional[SnifferCallback] = None

        # Statistics
        self.total_transmitted = 0
        self.total_dropped     = 0

    def register_node(self, name: str) -> queue.Queue:
        """Register a node and return its personal inbox queue."""
        with self._lock:
            if name not in self._listeners:
                self._listeners[name] = queue.Queue()
        return self._listeners[name]

    def set_sniffer(self, callback: SnifferCallback) -> None:
        """Install a passive sniffer that receives a copy of every frame."""
        self._sniffer = callback

    def transmit(self, msg: CANMessage, sender_name: str) -> None:
        """
        Broadcast msg to all nodes except the sender itself.
        Runs in a daemon thread to avoid blocking the transmitting ECU.
        """
        t = threading.Thread(
            target=self._deliver,
            args=(msg.clone(), sender_name),
            daemon=True,
        )
        t.start()

    def _deliver(self, msg: CANMessage, sender_name: str) -> None:
        """Internal: deliver message after optional delay."""
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

        self.total_transmitted += 1

        with self._lock:
            recipients = list(self._listeners.keys())

        for node in recipients:
            if node == sender_name:
                continue   # CAN nodes do not receive their own frames
            self._listeners[node].put(msg.clone())

        # Notify sniffer (passive — copy only, no delivery to attacker inbox)
        if self._sniffer:
            self._sniffer(msg.clone())

        if self._logger:
            self._logger.log_tx(msg, sender_name)

    def inject(self, msg: CANMessage, injector_name: str = "ATTACKER") -> None:
        """
        Inject a message directly onto the bus (used by Attacker).
        Delivered to all registered nodes including legitimate ECUs.
        """
        t = threading.Thread(
            target=self._inject_deliver,
            args=(msg.clone(), injector_name),
            daemon=True,
        )
        t.start()

    def _inject_deliver(self, msg: CANMessage, injector_name: str) -> None:
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

        with self._lock:
            recipients = list(self._listeners.keys())

        for node in recipients:
            self._listeners[node].put(msg.clone())

        if self._logger:
            self._logger.log_event(
                "INJECT",
                injector_name,
                f"Injected msg_id={msg.msg_name} payload={msg.payload.hex()}",
            )

    def stats(self) -> Dict[str, int]:
        return {
            "transmitted": self.total_transmitted,
            "dropped":     self.total_dropped,
            "nodes":       len(self._listeners),
        }
