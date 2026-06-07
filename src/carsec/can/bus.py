"""
CAN bus abstraction.

Real CAN is a shared broadcast medium: every node electrically connected to the
two-wire bus (CAN_H / CAN_L) receives every frame, and filtering happens in
software (acceptance masks).  There is **no addressing and no authentication** —
the property that every attack in :mod:`carsec.attacks` relies on.

:class:`CANBus` is the abstract contract.  :class:`VirtualCANBus` is a pure
in-process implementation backed by thread-safe queues.  A SocketCAN-backed
implementation (:class:`carsec.can.socketcan.SocketCANBus`) is provided behind
the optional ``hardware`` extra and honours the same contract.

Taps
----
Any number of *taps* may be attached with :meth:`CANBus.add_tap`.  A tap is a
callback that receives a copy of **every** frame on the bus, modelling passive
eavesdropping.  Both the :class:`~carsec.attacks.base.Attacker` (to sniff
traffic) and the :class:`~carsec.ids.detector.IDS` (to monitor traffic) attach
as taps.
"""

from __future__ import annotations

import queue
import threading
from abc import ABC, abstractmethod
from typing import Callable, Optional

from carsec.can.message import CANMessage

Tap = Callable[[CANMessage], None]


class CANBus(ABC):
    """Abstract broadcast CAN bus."""

    name: str

    @abstractmethod
    def register_node(self, name: str) -> "queue.Queue[CANMessage]":
        """Register a receiving node and return its personal inbox queue."""

    @abstractmethod
    def send(self, msg: CANMessage, sender: str) -> None:
        """Broadcast ``msg`` to every node except ``sender``."""

    @abstractmethod
    def inject(self, msg: CANMessage, injector: str = "ATTACKER") -> None:
        """Inject ``msg`` to every node (used by attackers — no sender exclusion)."""

    def add_tap(self, callback: Tap) -> None:
        """Attach a passive observer that receives a copy of every frame."""
        raise NotImplementedError

    # Backwards-compatible alias kept for the attacker's single-sniffer model.
    def set_sniffer(self, callback: Tap) -> None:
        self.add_tap(callback)


class VirtualCANBus(CANBus):
    """
    Thread-safe in-process broadcast bus.

    Nodes call :meth:`register_node` to obtain an inbox; any node calls
    :meth:`send` to broadcast.  Delivery is synchronous (deterministic for
    tests) unless ``delay_ms`` is set, in which case delivery happens on a
    short-lived daemon thread to model propagation delay without blocking the
    transmitting ECU.
    """

    def __init__(
        self,
        name: str = "vcan0",
        delay_ms: float = 0.0,
        logger=None,
    ) -> None:
        self.name = name
        self.delay_ms = delay_ms
        self._logger = logger

        self._listeners: dict[str, queue.Queue[CANMessage]] = {}
        self._taps: list[Tap] = []
        self._lock = threading.Lock()

        self.total_transmitted = 0
        self.total_injected = 0

    # ── Registration ──────────────────────────────────────────────────────────

    def register_node(self, name: str) -> "queue.Queue[CANMessage]":
        with self._lock:
            if name not in self._listeners:
                self._listeners[name] = queue.Queue()
            return self._listeners[name]

    def add_tap(self, callback: Tap) -> None:
        with self._lock:
            self._taps.append(callback)

    # ── Transmission ──────────────────────────────────────────────────────────

    def send(self, msg: CANMessage, sender: str) -> None:
        self._dispatch(msg, sender=sender, exclude_sender=True, injected=False)

    def inject(self, msg: CANMessage, injector: str = "ATTACKER") -> None:
        self._dispatch(msg, sender=injector, exclude_sender=False, injected=True)

    def _dispatch(
        self,
        msg: CANMessage,
        sender: str,
        exclude_sender: bool,
        injected: bool,
    ) -> None:
        if self.delay_ms > 0:
            t = threading.Thread(
                target=self._deliver,
                args=(msg, sender, exclude_sender, injected),
                daemon=True,
            )
            t.start()
        else:
            self._deliver(msg, sender, exclude_sender, injected)

    def _deliver(
        self,
        msg: CANMessage,
        sender: str,
        exclude_sender: bool,
        injected: bool,
    ) -> None:
        if self.delay_ms > 0:
            import time

            time.sleep(self.delay_ms / 1000.0)

        with self._lock:
            recipients = list(self._listeners.items())
            taps = list(self._taps)
            if injected:
                self.total_injected += 1
            else:
                self.total_transmitted += 1

        for node, inbox in recipients:
            if exclude_sender and node == sender:
                continue  # a CAN node does not receive its own frame
            inbox.put(msg.clone())

        for tap in taps:
            try:
                tap(msg.clone())
            except Exception:  # a faulty observer must not break the bus
                pass

        if self._logger is not None:
            if injected:
                self._logger.log_event(
                    "INJECT",
                    sender,
                    f"injected {msg.name} data={msg.data.hex()}",
                    msg,
                )
            else:
                self._logger.log_tx(msg, sender)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "transmitted": self.total_transmitted,
                "injected": self.total_injected,
                "nodes": len(self._listeners),
                "taps": len(self._taps),
            }


def open_bus(
    backend: str = "virtual",
    channel: Optional[str] = None,
    delay_ms: float = 0.0,
    logger=None,
) -> CANBus:
    """
    Factory that returns a bus for the requested backend.

    ``virtual``   pure in-process broadcast bus (default, no dependencies).
    ``socketcan`` Linux SocketCAN via python-can (requires the ``hardware`` extra
                  and a ``vcan``/``can`` interface).  Falls back with a clear
                  error if python-can or the interface is unavailable.
    """
    if backend == "virtual":
        return VirtualCANBus(name=channel or "vcan0", delay_ms=delay_ms, logger=logger)
    if backend == "socketcan":
        from carsec.can.socketcan import SocketCANBus

        return SocketCANBus(channel=channel or "vcan0", logger=logger)
    raise ValueError(f"unknown CAN backend: {backend!r}")
