"""
Attack simulation modules (defensive research / education only).

Real-world context
------------------
In 2015 Charlie Miller and Chris Valasek remotely controlled a Jeep Cherokee by
injecting CAN frames through its telematics unit — killing the engine, disabling
brakes, and steering at low speed.  Every technique here exploits the same root
cause: classic CAN has no authentication, so any node that reaches the bus is
implicitly trusted.

The point of simulating these attacks is to show, side by side, how each one
succeeds on an insecure bus and is defeated by SecOC and/or detected by the IDS.
"""

from carsec.attacks.base import Attacker
from carsec.attacks.dos import BusFlooder
from carsec.attacks.fuzz import CANFuzzer

__all__ = ["Attacker", "BusFlooder", "CANFuzzer"]
