"""Higher-level integration: scenarios and the live secure pipeline."""

import time

from carsec.can.identifiers import MSG_ID
from carsec.scenarios import library
from carsec.scenarios.ids_demo import ids_benchmark
from carsec.scenarios.runner import SimulationRunner
from carsec.telemetry.logger import EventLogger


def test_scenario_registry_complete():
    for name in [
        "normal-secure", "replay-secure", "tamper-secure", "inject-secure",
        "uds-weak", "uds-secure", "dos", "ids-benchmark",
    ]:
        assert name in library.ALL


def test_ids_benchmark_metrics_strong():
    report = ids_benchmark()
    m = report["metrics"]
    assert m["recall"] >= 0.9
    assert m["precision"] >= 0.85


def test_secure_pipeline_rejects_injection():
    quiet = EventLogger(console=False, to_file=False)
    runner = SimulationRunner(secure=True, verbose=False, with_ids=True, logger=quiet)
    runner.start()
    time.sleep(0.4)
    for _ in range(5):
        runner.attacker.inject(MSG_ID["BRAKE_PRESS"])
        time.sleep(0.05)
    time.sleep(0.4)
    runner.stop()
    summary = runner.summary()
    # injected frames carry no valid MAC → ECUs must reject them
    assert summary["rejected"] >= 1
    # and the IDS should have raised at least one alert
    assert summary["alerts"] >= 1
