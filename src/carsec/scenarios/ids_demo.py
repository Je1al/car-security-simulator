"""
IDS scenarios.

* ``dos`` — live bus flooding while ECUs run; the frequency detector flags the
  flood that SecOC alone cannot stop.
* ``ids-benchmark`` — a deterministic, labelled synthetic trace (normal periodic
  traffic interleaved with replay / injection / DoS / fuzz frames) scored with a
  full confusion matrix.  This is the headline, reproducible detection result.
"""

from __future__ import annotations

import os
import random
import time

from carsec.attacks.dos import BusFlooder
from carsec.can.identifiers import (
    MSG_ID,
    encode_brake_pressure,
    encode_rpm,
    encode_status,
    encode_temperature,
)
from carsec.can.message import CANMessage
from carsec.ids.detector import IDS
from carsec.scenarios.runner import SimulationRunner
from carsec.telemetry.logger import C

# Periodic baseline traffic: arbitration id → (period seconds, payload factory).
_BASELINE = {
    MSG_ID["ENGINE_RPM"]: (0.010, lambda: encode_rpm(random.randint(800, 3000))),
    MSG_ID["ENGINE_TEMP"]: (0.100, lambda: encode_temperature(random.uniform(70, 95))),
    MSG_ID["BRAKE_PRESS"]: (0.020, lambda: encode_brake_pressure(random.uniform(0, 60))),
    MSG_ID["BRAKE_STATUS"]: (0.020, lambda: encode_status(random.choice([0, 1]))),
}


def _build_trace(seconds: float = 2.0):
    """Return a time-sorted list of (arrival_time, CANMessage) with ground truth."""
    rng = random.Random(1337)
    events: list[tuple[float, CANMessage]] = []

    # Normal periodic frames.
    for arb, (period, payload) in _BASELINE.items():
        t = 0.0
        while t < seconds:
            jitter = rng.uniform(-0.1, 0.1) * period
            events.append((t + jitter, CANMessage(arbitration_id=arb, data=payload())))
            t += period

    # Replay: re-emit captured BRAKE_PRESS frames mid-stream.
    for t in [0.5, 0.9, 1.3]:
        events.append((t, CANMessage(arbitration_id=MSG_ID["BRAKE_PRESS"],
                                     data=encode_brake_pressure(0.0),
                                     is_attack=True, attack_type="replay")))
    # Injection: implausible / spoofed values.
    for t in [0.6, 1.1, 1.6]:
        events.append((t, CANMessage(arbitration_id=MSG_ID["ENGINE_RPM"],
                                     data=encode_rpm(9999),
                                     is_attack=True, attack_type="injection")))
    # DoS: a burst of high-priority unknown-id frames.
    t = 1.70
    for _ in range(40):
        events.append((t, CANMessage(arbitration_id=0x000, data=os.urandom(8),
                                     is_attack=True, attack_type="dos")))
        t += 0.0005
    # Fuzz: random unknown ids / payloads.
    for t in [0.4, 0.8, 1.2, 1.5]:
        events.append((t, CANMessage(arbitration_id=rng.randint(0x100, 0x7FF),
                                     data=os.urandom(8),
                                     is_attack=True, attack_type="fuzz")))

    events.sort(key=lambda e: e[0])
    return events


def ids_benchmark(verbose: bool = False) -> dict:
    """Score the IDS on the deterministic labelled trace and print the report."""
    print()
    print(f"{C.CYAN}{C.BOLD}  IDS BENCHMARK — deterministic labelled trace{C.RESET}\n")
    ids = IDS(logger=None, alert=False)
    trace = _build_trace()
    base = trace[0][0]
    for t, msg in trace:
        ids.observe(msg, now=t - base)

    m = ids.metrics
    print(f"  frames analysed : {m.total}")
    print(f"  attacks present : {m.true_positives + m.false_negatives}")
    print(f"  confusion       : TP={m.true_positives} FP={m.false_positives} "
          f"TN={m.true_negatives} FN={m.false_negatives}")
    print(f"  {C.BOLD}precision={m.precision:.3f}  recall={m.recall:.3f}  "
          f"f1={m.f1:.3f}  accuracy={m.accuracy:.3f}{C.RESET}")
    print(f"  detector hits   : {ids.by_detector}")
    print()
    return ids.report()


def dos(verbose: bool = False) -> SimulationRunner:
    """Live DoS: flood the bus while ECUs run; the IDS flags the flood."""
    r = SimulationRunner(secure=True, verbose=verbose, log_prefix="dos", with_ids=True)
    r.logger.banner("Denial of Service — bus flooding", "SecOC cannot stop a flood; the IDS detects it by rate")
    flooder = BusFlooder("ATTACKER", r.bus, r.logger)
    r.start()
    time.sleep(0.6)
    flooder.flood(duration=0.3, rate_hz=1500)
    time.sleep(0.4)
    r.stop()
    s = r.summary()
    print(f"\n  flood frames : {flooder.frames_sent}")
    print(f"  IDS alerts   : {C.ORANGE}{s['alerts']}{C.RESET}")
    if r.ids:
        mm = r.ids.metrics
        print(f"  IDS recall on flood: {mm.recall:.2f} (precision={mm.precision:.2f})")
    r.logger.flush_json()
    print()
    return r


SCENARIOS = {
    "dos": dos,
    "ids-benchmark": ids_benchmark,
}
