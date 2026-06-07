"""
UDS (ISO 14229) diagnostics over ISO-TP (ISO 15765-2).

Diagnostics is the most security-relevant "legitimate" channel in a vehicle: it
is how a workshop tester flashes firmware, reads fault memory, and unlocks
protected routines.  Access to the privileged services is gated by **Security
Access** (service 0x27), a seed–key challenge/response.  Weak seed–key algorithms
have repeatedly let attackers unlock ECUs — which is exactly what
:mod:`carsec.uds.attack` demonstrates against the intentionally-weak algorithm,
and what the HMAC-based algorithm defeats.
"""

from carsec.uds import attack, isotp
from carsec.uds.client import UdsClient
from carsec.uds.security_access import (
    HmacSeedKey,
    SeedKeyAlgorithm,
    WeakXorSeedKey,
)
from carsec.uds.server import UdsServer
from carsec.uds.services import NRC, SID, UdsError
from carsec.uds.transport import DirectTransport, IsoTpTransport

__all__ = [
    "isotp",
    "attack",
    "UdsServer",
    "UdsClient",
    "DirectTransport",
    "IsoTpTransport",
    "SID",
    "NRC",
    "UdsError",
    "SeedKeyAlgorithm",
    "WeakXorSeedKey",
    "HmacSeedKey",
]
