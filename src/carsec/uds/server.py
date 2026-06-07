"""
UDS server (the ECU side).

Implements a focused subset of ISO 14229 with the real on-wire encoding and a
correct Security Access state machine, including the anti-brute-force controls
the standard mandates: an attempt counter (``exceededNumberOfAttempts``) and a
mandatory time delay (``requiredTimeDelayNotExpired``).  Those controls are what
make *online* key guessing impractical — and what make the *offline* secret
recovery in :mod:`carsec.uds.attack` the realistic break against a weak
algorithm.
"""

from __future__ import annotations

import os
import time

from carsec.uds.security_access import SeedKeyAlgorithm, WeakXorSeedKey
from carsec.uds.services import (
    NRC,
    SID,
    Session,
    negative_response,
    positive_response,
)

# Data identifiers.  PROTECTED ones require an unlocked security session.
DID_VIN = 0xF190  # public: vehicle identification number
DID_SW_VERSION = 0xF195  # public: software version
DID_SECRET_CALIBRATION = 0x0200  # protected: needs Security Access


class UdsServer:
    """A single diagnosable ECU."""

    def __init__(
        self,
        name: str = "ECU_Diag",
        algorithm: SeedKeyAlgorithm | None = None,
        max_attempts: int = 3,
        delay_after_lockout: float = 10.0,
    ) -> None:
        self.name = name
        self.algorithm = algorithm or WeakXorSeedKey()
        self.max_attempts = max_attempts
        self.delay_after_lockout = delay_after_lockout

        self.session = Session.DEFAULT
        self.unlocked = False
        self._pending_seed: bytes | None = None
        self._failed_attempts = 0
        self._locked_until = 0.0

        self.data_store: dict[int, bytes] = {
            DID_VIN: b"WBA-CARSEC-0000001",
            DID_SW_VERSION: b"1.0.0",
            DID_SECRET_CALIBRATION: b"\xde\xad\xbe\xef",
        }

    # ── Request dispatch ───────────────────────────────────────────────────────

    def request(self, payload: bytes) -> bytes:
        """Process a UDS request and return the response bytes."""
        if not payload:
            return negative_response(0x00, NRC.INCORRECT_MESSAGE_LENGTH)
        sid = payload[0]
        handlers = {
            SID.DIAGNOSTIC_SESSION_CONTROL: self._session_control,
            SID.ECU_RESET: self._ecu_reset,
            SID.SECURITY_ACCESS: self._security_access,
            SID.TESTER_PRESENT: self._tester_present,
            SID.READ_DATA_BY_IDENTIFIER: self._read_did,
            SID.WRITE_DATA_BY_IDENTIFIER: self._write_did,
        }
        handler = handlers.get(sid)
        if handler is None:
            return negative_response(sid, NRC.SERVICE_NOT_SUPPORTED)
        return handler(payload)

    # ── Services ───────────────────────────────────────────────────────────────

    def _session_control(self, payload: bytes) -> bytes:
        if len(payload) < 2:
            return negative_response(SID.DIAGNOSTIC_SESSION_CONTROL, NRC.INCORRECT_MESSAGE_LENGTH)
        session = payload[1]
        if session not in (Session.DEFAULT, Session.PROGRAMMING, Session.EXTENDED):
            return negative_response(SID.DIAGNOSTIC_SESSION_CONTROL, NRC.SUB_FUNCTION_NOT_SUPPORTED)
        self.session = session
        if session == Session.DEFAULT:
            self.unlocked = False  # leaving extended/programming re-locks
        return bytes([positive_response(SID.DIAGNOSTIC_SESSION_CONTROL), session])

    def _ecu_reset(self, payload: bytes) -> bytes:
        if len(payload) < 2:
            return negative_response(SID.ECU_RESET, NRC.INCORRECT_MESSAGE_LENGTH)
        self.session = Session.DEFAULT
        self.unlocked = False
        self._pending_seed = None
        return bytes([positive_response(SID.ECU_RESET), payload[1]])

    def _security_access(self, payload: bytes) -> bytes:
        if len(payload) < 2:
            return negative_response(SID.SECURITY_ACCESS, NRC.INCORRECT_MESSAGE_LENGTH)
        sub = payload[1]

        # Time-delay lockout after too many failures.
        now = time.time()
        if now < self._locked_until:
            return negative_response(SID.SECURITY_ACCESS, NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED)

        request_seed = sub % 2 == 1  # odd = requestSeed, even = sendKey

        if request_seed:
            if self.unlocked:
                # Already unlocked → seed of zeros (ISO 14229 convention).
                return bytes([positive_response(SID.SECURITY_ACCESS), sub]) + b"\x00" * self.algorithm.seed_len
            self._pending_seed = os.urandom(self.algorithm.seed_len)
            return bytes([positive_response(SID.SECURITY_ACCESS), sub]) + self._pending_seed

        # sendKey
        if self._pending_seed is None:
            return negative_response(SID.SECURITY_ACCESS, NRC.REQUEST_SEQUENCE_ERROR)
        provided_key = payload[2:]
        expected = self.algorithm.compute_key(self._pending_seed)
        if provided_key == expected:
            self.unlocked = True
            self._pending_seed = None
            self._failed_attempts = 0
            return bytes([positive_response(SID.SECURITY_ACCESS), sub])

        # Wrong key → count it and possibly lock out.
        self._failed_attempts += 1
        self._pending_seed = None
        if self._failed_attempts >= self.max_attempts:
            self._locked_until = now + self.delay_after_lockout
            self._failed_attempts = 0
            return negative_response(SID.SECURITY_ACCESS, NRC.EXCEEDED_NUMBER_OF_ATTEMPTS)
        return negative_response(SID.SECURITY_ACCESS, NRC.INVALID_KEY)

    def _tester_present(self, payload: bytes) -> bytes:
        return bytes([positive_response(SID.TESTER_PRESENT), 0x00])

    def _read_did(self, payload: bytes) -> bytes:
        if len(payload) < 3:
            return negative_response(SID.READ_DATA_BY_IDENTIFIER, NRC.INCORRECT_MESSAGE_LENGTH)
        did = (payload[1] << 8) | payload[2]
        if did not in self.data_store:
            return negative_response(SID.READ_DATA_BY_IDENTIFIER, NRC.REQUEST_OUT_OF_RANGE)
        if did == DID_SECRET_CALIBRATION and not self.unlocked:
            return negative_response(SID.READ_DATA_BY_IDENTIFIER, NRC.SECURITY_ACCESS_DENIED)
        return bytes([positive_response(SID.READ_DATA_BY_IDENTIFIER), payload[1], payload[2]]) + self.data_store[did]

    def _write_did(self, payload: bytes) -> bytes:
        if len(payload) < 4:
            return negative_response(SID.WRITE_DATA_BY_IDENTIFIER, NRC.INCORRECT_MESSAGE_LENGTH)
        if not self.unlocked:
            return negative_response(SID.WRITE_DATA_BY_IDENTIFIER, NRC.SECURITY_ACCESS_DENIED)
        did = (payload[1] << 8) | payload[2]
        self.data_store[did] = payload[3:]
        return bytes([positive_response(SID.WRITE_DATA_BY_IDENTIFIER), payload[1], payload[2]])
