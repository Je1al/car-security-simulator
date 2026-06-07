"""
UDS client (the tester side).

Thin, typed wrappers over the raw services that raise :class:`UdsError` on a
negative response, plus a :meth:`unlock` helper that runs the full Security
Access seed→key handshake using a supplied seed-key algorithm.
"""

from __future__ import annotations

from carsec.uds.security_access import SeedKeyAlgorithm
from carsec.uds.services import (
    SID,
    UdsError,
    is_negative,
    positive_response,
)
from carsec.uds.transport import UdsTransport


class UdsClient:
    """Issues UDS requests over a transport."""

    def __init__(self, transport: UdsTransport) -> None:
        self.transport = transport

    def _send(self, payload: bytes) -> bytes:
        response = self.transport.request(payload)
        if is_negative(response):
            raise UdsError(payload[0], response[2])
        return response

    # ── Services ───────────────────────────────────────────────────────────────

    def diagnostic_session_control(self, session: int) -> bytes:
        return self._send(bytes([SID.DIAGNOSTIC_SESSION_CONTROL, session]))

    def ecu_reset(self, reset_type: int = 0x01) -> bytes:
        return self._send(bytes([SID.ECU_RESET, reset_type]))

    def tester_present(self) -> bytes:
        return self._send(bytes([SID.TESTER_PRESENT, 0x00]))

    def request_seed(self, level: int = 0x01) -> bytes:
        resp = self._send(bytes([SID.SECURITY_ACCESS, level]))
        return resp[2:]  # strip SID + sub-function echo

    def send_key(self, key: bytes, level: int = 0x02) -> bytes:
        return self._send(bytes([SID.SECURITY_ACCESS, level]) + key)

    def read_data_by_identifier(self, did: int) -> bytes:
        resp = self._send(bytes([SID.READ_DATA_BY_IDENTIFIER, (did >> 8) & 0xFF, did & 0xFF]))
        return resp[3:]  # strip SID + DID echo

    def write_data_by_identifier(self, did: int, data: bytes) -> bytes:
        return self._send(
            bytes([SID.WRITE_DATA_BY_IDENTIFIER, (did >> 8) & 0xFF, did & 0xFF]) + data
        )

    # ── Composite ──────────────────────────────────────────────────────────────

    def unlock(self, algorithm: SeedKeyAlgorithm, level: int = 0x01) -> bool:
        """
        Run the Security Access handshake with ``algorithm``.

        Returns True on success.  Raises :class:`UdsError` if the ECU rejects the
        key (e.g. wrong algorithm/secret, or lockout).
        """
        seed = self.request_seed(level)
        if not any(seed):
            return True  # all-zero seed → already unlocked
        key = algorithm.compute_key(seed)
        resp = self.send_key(key, level + 1)
        return resp[0] == positive_response(SID.SECURITY_ACCESS)
