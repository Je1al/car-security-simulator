"""
UDS transports.

A transport turns a request byte string into the server's response byte string.

* :class:`DirectTransport` hands the bytes straight to the server — ideal for
  unit tests and the brute-force demo where ISO-TP framing is noise.
* :class:`IsoTpTransport` exercises the full ISO-TP stack: it segments the
  request into CAN frames, reassembles them on the server side, then segments the
  response back.  When given a bus + logger it also emits the real 0x7E0/0x7E8
  diagnostic frames so the exchange is visible alongside normal CAN traffic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from carsec.can.identifiers import MSG_ID
from carsec.can.message import CANMessage
from carsec.uds import isotp
from carsec.uds.server import UdsServer


class UdsTransport(ABC):
    @abstractmethod
    def request(self, payload: bytes) -> bytes:
        """Send a UDS request and return the response payload."""


class DirectTransport(UdsTransport):
    """Bypass framing — call the server directly."""

    def __init__(self, server: UdsServer) -> None:
        self.server = server

    def request(self, payload: bytes) -> bytes:
        return self.server.request(payload)


class IsoTpTransport(UdsTransport):
    """Full ISO-TP segmentation/reassembly between client and server."""

    def __init__(self, server: UdsServer, bus=None, logger=None, sender: str = "Tester") -> None:
        self.server = server
        self._bus = bus
        self._logger = logger
        self._sender = sender

    def _emit(self, arbitration_id: int, data: bytes, who: str) -> None:
        if self._bus is None:
            return
        frame = CANMessage(arbitration_id=arbitration_id, data=data, sender=who)
        self._bus.inject(frame, injector=who)

    def request(self, payload: bytes) -> bytes:
        # Client → server.
        req_frames = isotp.segment(payload)
        reasm = isotp.Reassembler()
        server_message: Optional[bytes] = None
        for f in req_frames:
            self._emit(MSG_ID["DIAG_REQUEST"], f, self._sender)
            result = reasm.push(f)
            if result is not None:
                server_message = result
        assert server_message is not None

        response = self.server.request(server_message)

        # Server → client.
        resp_frames = isotp.segment(response)
        reasm2 = isotp.Reassembler()
        client_message: Optional[bytes] = None
        for f in resp_frames:
            self._emit(MSG_ID["DIAG_RESPONSE"], f, self.server.name)
            result = reasm2.push(f)
            if result is not None:
                client_message = result
        assert client_message is not None
        return client_message
