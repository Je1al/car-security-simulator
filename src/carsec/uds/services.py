"""
UDS (ISO 14229) service identifiers, negative-response codes, and helpers.

Only the services needed for the security demonstration are modelled, but with
the real on-wire encoding: a positive response echoes ``SID + 0x40``, and a
negative response is ``0x7F <SID> <NRC>``.
"""

from __future__ import annotations


class SID:
    """Service IDs (request values)."""

    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    SECURITY_ACCESS = 0x27
    TESTER_PRESENT = 0x3E
    READ_DATA_BY_IDENTIFIER = 0x22
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    ROUTINE_CONTROL = 0x31

    POSITIVE_RESPONSE_OFFSET = 0x40
    NEGATIVE_RESPONSE = 0x7F


class Session:
    """Diagnostic session types (sub-function of 0x10)."""

    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED = 0x03


class NRC:
    """Negative Response Codes (the subset we use)."""

    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_MESSAGE_LENGTH = 0x13
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    INVALID_KEY = 0x35
    EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37

    _NAMES = {
        0x10: "generalReject",
        0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported",
        0x13: "incorrectMessageLength",
        0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError",
        0x31: "requestOutOfRange",
        0x33: "securityAccessDenied",
        0x35: "invalidKey",
        0x36: "exceededNumberOfAttempts",
        0x37: "requiredTimeDelayNotExpired",
    }

    @classmethod
    def name(cls, code: int) -> str:
        return cls._NAMES.get(code, f"0x{code:02X}")


class UdsError(Exception):
    """Raised by the client when the server returns a negative response."""

    def __init__(self, sid: int, nrc: int) -> None:
        self.sid = sid
        self.nrc = nrc
        super().__init__(f"UDS 0x{sid:02X} negative response: {NRC.name(nrc)} (0x{nrc:02X})")


def positive_response(sid: int) -> int:
    return sid + SID.POSITIVE_RESPONSE_OFFSET


def negative_response(sid: int, nrc: int) -> bytes:
    return bytes([SID.NEGATIVE_RESPONSE, sid, nrc])


def is_negative(response: bytes) -> bool:
    return len(response) >= 1 and response[0] == SID.NEGATIVE_RESPONSE
