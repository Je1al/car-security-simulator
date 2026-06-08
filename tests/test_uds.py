"""UDS: ISO-TP framing, services, Security Access, and the seed-key attack."""

import os

import pytest

from carsec.uds import isotp
from carsec.uds.attack import attempt_hmac_secret, recover_weak_secret
from carsec.uds.client import UdsClient
from carsec.uds.security_access import HmacSeedKey, WeakXorSeedKey
from carsec.uds.server import DID_SECRET_CALIBRATION, DID_VIN, UdsServer
from carsec.uds.services import NRC, Session, UdsError
from carsec.uds.transport import DirectTransport, IsoTpTransport

# ── ISO-TP ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("size", [0, 1, 7, 8, 12, 40, 255, 4095])
def test_isotp_roundtrip(size):
    payload = os.urandom(size)
    frames = isotp.segment(payload)
    assert all(len(f) <= 8 for f in frames)
    assert isotp.reassemble(frames) == payload


def test_isotp_single_frame_for_short():
    assert len(isotp.segment(b"\x01\x02\x03")) == 1


def test_isotp_rejects_oversized():
    with pytest.raises(isotp.IsoTpError):
        isotp.segment(b"\x00" * 5000)


def test_isotp_out_of_order_cf_detected():
    r = isotp.Reassembler()
    frames = isotp.segment(os.urandom(20))
    r.push(frames[0])
    with pytest.raises(isotp.IsoTpError):
        r.push(frames[2])  # skip CF #1


# ── UDS over both transports ──────────────────────────────────────────────────

@pytest.mark.parametrize("make_transport", [
    lambda s: DirectTransport(s),
    lambda s: IsoTpTransport(s),
])
def test_public_did_readable_protected_gated(make_transport):
    secret = 0x1234
    server = UdsServer(algorithm=WeakXorSeedKey(secret))
    client = UdsClient(make_transport(server))

    assert client.read_data_by_identifier(DID_VIN).startswith(b"WBA")
    with pytest.raises(UdsError) as ei:
        client.read_data_by_identifier(DID_SECRET_CALIBRATION)
    assert ei.value.nrc == NRC.SECURITY_ACCESS_DENIED

    client.diagnostic_session_control(Session.EXTENDED)
    assert client.unlock(WeakXorSeedKey(secret))
    assert client.read_data_by_identifier(DID_SECRET_CALIBRATION) == b"\xde\xad\xbe\xef"


def test_wrong_key_rejected_and_counted():
    server = UdsServer(algorithm=WeakXorSeedKey(0x1111), max_attempts=3)
    client = UdsClient(DirectTransport(server))
    client.diagnostic_session_control(Session.EXTENDED)
    with pytest.raises(UdsError) as ei:
        client.unlock(WeakXorSeedKey(0x2222))  # wrong secret
    assert ei.value.nrc in (NRC.INVALID_KEY, NRC.EXCEEDED_NUMBER_OF_ATTEMPTS)
    assert not server.unlocked


def test_lockout_after_max_attempts():
    server = UdsServer(algorithm=WeakXorSeedKey(0x1111), max_attempts=2, delay_after_lockout=60)
    client = UdsClient(DirectTransport(server))
    client.diagnostic_session_control(Session.EXTENDED)
    nrcs = []
    for _ in range(2):
        try:
            client.unlock(WeakXorSeedKey(0x9999))
        except UdsError as e:
            nrcs.append(e.nrc)
    assert NRC.EXCEEDED_NUMBER_OF_ATTEMPTS in nrcs
    # subsequent request is time-delayed
    with pytest.raises(UdsError) as ei:
        client.request_seed()
    assert ei.value.nrc == NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED


# ── Seed-key attack ───────────────────────────────────────────────────────────

def test_weak_secret_recovered_from_one_pair():
    secret = 0xBEEF
    algo = WeakXorSeedKey(secret)
    seed = os.urandom(algo.seed_len)
    key = algo.compute_key(seed)
    res = recover_weak_secret(seed, key)
    assert res.recovered and res.secret == secret


def test_recovered_secret_unlocks_victim():
    secret = 0x4242
    seed = os.urandom(4)
    key = WeakXorSeedKey(secret).compute_key(seed)
    recovered = recover_weak_secret(seed, key).secret

    victim = UdsServer(algorithm=WeakXorSeedKey(secret))
    client = UdsClient(DirectTransport(victim))
    client.diagnostic_session_control(Session.EXTENDED)
    assert client.unlock(WeakXorSeedKey(recovered))


def test_hmac_secret_not_brute_forced():
    algo = HmacSeedKey()
    seed = os.urandom(4)
    key = algo.compute_key(seed)
    res = attempt_hmac_secret(seed, key, max_tries=2000)
    assert not res.recovered
