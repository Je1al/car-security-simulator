"""
UDS Security Access scenarios.

Two runs of the same attack, differing only in the seed–key algorithm:

* ``uds-weak``   — a 16-bit weak algorithm; the attacker sniffs one tester
  exchange, recovers the secret offline, and unlocks the ECU to read a protected
  Data Identifier.
* ``uds-secure`` — an HMAC seed–key; the identical attack fails.
"""

from __future__ import annotations

import os

from carsec.telemetry.logger import C
from carsec.uds.attack import attempt_hmac_secret, recover_weak_secret
from carsec.uds.client import UdsClient
from carsec.uds.security_access import HmacSeedKey, WeakXorSeedKey
from carsec.uds.server import DID_SECRET_CALIBRATION, UdsServer
from carsec.uds.services import Session, UdsError
from carsec.uds.transport import DirectTransport


def _hdr(title: str, sub: str) -> None:
    print()
    print(f"{C.CYAN}{C.BOLD}  {'═' * 66}")
    print(f"    {title}")
    print(f"    {C.DIM}{sub}{C.RESET}{C.CYAN}{C.BOLD}")
    print(f"  {'═' * 66}{C.RESET}\n")


def _ok(m: str) -> None:
    print(f"  {C.GREEN}✓{C.RESET}  {m}")


def _err(m: str) -> None:
    print(f"  {C.RED}✗{C.RESET}  {m}")


def _info(m: str) -> None:
    print(f"  {C.CYAN}ℹ{C.RESET}  {m}")


def uds_weak(verbose: bool = False) -> None:
    _hdr("UDS Security Access — WEAK seed-key", "16-bit secret recovered offline from one sniffed pair")
    secret = 0xBEEF
    algo = WeakXorSeedKey(secret)

    # A legitimate workshop tester unlocks the ECU; the attacker sniffs it.
    seed = os.urandom(algo.seed_len)
    key = algo.compute_key(seed)
    _info(f"sniffed one tester exchange: seed={seed.hex()} key={key.hex()}")

    res = recover_weak_secret(seed, key)
    if not res.recovered or res.secret is None:
        _err("secret not recovered (unexpected)")
        return
    _err(f"secret recovered: 0x{res.secret:04X} in {res.tries} tries / {res.seconds * 1000:.2f} ms")

    victim = UdsServer(algorithm=WeakXorSeedKey(secret))
    client = UdsClient(DirectTransport(victim))
    client.diagnostic_session_control(Session.EXTENDED)
    unlocked = client.unlock(WeakXorSeedKey(res.secret))
    if unlocked:
        data = client.read_data_by_identifier(DID_SECRET_CALIBRATION)
        _err(f"ATTACK SUCCEEDED: ECU unlocked, protected calibration read = {data.hex()}")
    print()


def uds_secure(verbose: bool = False) -> None:
    _hdr("UDS Security Access — HMAC seed-key", "Same attack; 128-bit secret cannot be recovered")
    algo = HmacSeedKey()
    seed = os.urandom(algo.seed_len)
    key = algo.compute_key(seed)
    _info(f"sniffed one tester exchange: seed={seed.hex()} key={key.hex()}")

    res = attempt_hmac_secret(seed, key, max_tries=100_000)
    _ok(f"brute force exhausted {res.tries:,} guesses — secret NOT recovered")

    # Attacker also cannot unlock online: wrong key is rejected and rate-limited.
    victim = UdsServer(algorithm=HmacSeedKey(), max_attempts=3)
    client = UdsClient(DirectTransport(victim))
    client.diagnostic_session_control(Session.EXTENDED)
    try:
        client.unlock(WeakXorSeedKey(0x0000))  # attacker guesses the wrong algorithm
        _err("unexpected: unlock succeeded")
    except UdsError as e:
        _ok(f"ATTACK DEFEATED: ECU rejected the key ({e})")
    print()


SCENARIOS = {
    "uds-weak": uds_weak,
    "uds-secure": uds_secure,
}
