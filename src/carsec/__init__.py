"""
carsec — Automotive CAN bus security research platform.

A self-contained simulation of an in-vehicle network used to study, demonstrate,
and defend against CAN bus attacks.  The package models several Electronic
Control Units (ECUs) exchanging CAN frames over a shared broadcast bus and lets
you toggle between an insecure bus and an AUTOSAR SecOC–protected bus to see how
the same attack succeeds or fails.

Subpackages
-----------
    carsec.can        CAN frame model + bus abstraction (virtual / python-can)
    carsec.security   AUTOSAR SecOC: HMAC, Freshness Value management
    carsec.ecu        Engine / Brake / Gateway ECU simulations
    carsec.attacks    Replay, tamper, injection, DoS, fuzzing
    carsec.ids        Intrusion Detection System + detection metrics
    carsec.uds        ISO 14229 UDS over ISO-TP + Security Access
    carsec.telemetry  Structured logging + charts
    carsec.scenarios  Orchestrated demo scenarios

Educational / defensive use only.  See README and docs/threat-model.md.
"""

__version__ = "0.2.0"
__author__ = "Je1al"

from carsec.can.identifiers import MSG_ID, MSG_NAME
from carsec.can.message import CANMessage

__all__ = ["CANMessage", "MSG_ID", "MSG_NAME", "__version__"]
