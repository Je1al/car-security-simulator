"""
python-can backend (SocketCAN and other real/virtual interfaces).

This bridges the in-process simulation to a *real* CAN interface via
`python-can <https://python-can.readthedocs.io>`_.  Every frame the simulated
ECUs transmit is both delivered in-process (so the simulation runs unchanged)
and mirrored onto the wire, and every frame arriving from the wire is injected
into the simulation.  That means you can:

* watch the simulation with ``candump vcan0``;
* inject attacks from outside with ``cansend`` or another tool;
* point an external IDS at the same bus.

The secured PDU (data + freshness + MAC + timestamp) does not fit in a classic
8-byte CAN frame, so the backend uses **CAN-FD** (up to 64 bytes) and carries the
serialized :meth:`CANMessage.to_bytes` form — mirroring how AUTOSAR SecOC relies
on CAN-FD's larger payload to fit the authenticator.

Requires the ``hardware`` extra (``pip install carsec[hardware]``).  SocketCAN is
Linux-only; the cross-platform ``virtual`` interface (``interface="virtual"``)
behaves identically for development and CI on any OS.
"""

from __future__ import annotations

import contextlib
import threading

from carsec.can.bus import VirtualCANBus
from carsec.can.message import WIRE_SIZE, CANMessage

try:
    import can as _pycan

    _HAS_PYCAN = True
except ImportError:  # pragma: no cover
    _HAS_PYCAN = False


class SocketCANBus(VirtualCANBus):
    """A :class:`VirtualCANBus` that mirrors to / from a python-can interface."""

    def __init__(
        self,
        channel: str = "vcan0",
        interface: str = "socketcan",
        fd: bool = True,
        logger=None,
    ) -> None:
        if not _HAS_PYCAN:
            raise RuntimeError(
                "python-can is not installed — run `pip install carsec[hardware]`"
            )
        super().__init__(name=channel, delay_ms=0.0, logger=logger)
        self.fd = fd
        self._pycan_bus = _pycan.Bus(channel=channel, interface=interface, fd=fd)
        self._rx_running = True
        self._rx_thread = threading.Thread(target=self._rx_loop, name=f"{channel}-vcan-rx", daemon=True)
        self._rx_thread.start()

    # ── Conversion ─────────────────────────────────────────────────────────────

    def _to_pycan(self, msg: CANMessage):
        return _pycan.Message(
            arbitration_id=msg.arbitration_id,
            data=msg.to_bytes(),
            is_extended_id=msg.is_extended_id,
            is_fd=self.fd,
        )

    @staticmethod
    def _from_pycan(frame) -> CANMessage:
        return CANMessage.from_bytes(bytes(frame.data), sender="vcan")

    # ── Outbound mirroring ─────────────────────────────────────────────────────

    def _mirror(self, msg: CANMessage, injected: bool) -> None:
        try:
            self._pycan_bus.send(self._to_pycan(msg))
        except Exception as exc:  # pragma: no cover - hardware/IO errors
            if self._logger is not None:
                self._logger.log_event("WARN", self.name, f"vcan send failed: {exc}")

    # ── Inbound injection ──────────────────────────────────────────────────────

    def _rx_loop(self) -> None:  # pragma: no cover - exercised on a live bus
        while self._rx_running:
            try:
                frame = self._pycan_bus.recv(timeout=0.2)
            except Exception:
                continue
            if frame is None or len(frame.data) < WIRE_SIZE:
                continue
            msg = self._from_pycan(frame)
            # Deliver to in-process nodes + taps without mirroring back out.
            self._deliver(msg, sender="vcan", exclude_sender=False, injected=True, mirror=False)

    def close(self) -> None:
        self._rx_running = False
        with contextlib.suppress(Exception):  # pragma: no cover
            self._pycan_bus.shutdown()
