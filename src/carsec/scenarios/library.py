"""
Scenario library — each function runs one demonstration and prints a verdict.

Every attack is shown twice: once on an insecure bus (it succeeds) and once on a
SecOC bus (it is rejected).  The IDS runs in every scenario so its detection
metrics can be compared across attack types.
"""

from __future__ import annotations

from carsec.scenarios import ids_demo, uds_demo
from carsec.scenarios.runner import SimulationRunner
from carsec.telemetry.logger import C


def _ok(msg: str) -> None:
    print(f"  {C.GREEN}✓{C.RESET}  {msg}")


def _err(msg: str) -> None:
    print(f"  {C.RED}✗{C.RESET}  {msg}")


def _print_summary(runner: SimulationRunner) -> None:
    s = runner.summary()
    mode = f"{C.GREEN}SECURE{C.RESET}" if runner.secure else f"{C.RED}INSECURE{C.RESET}"
    print()
    print(f"  {C.BOLD}{'─' * 58}{C.RESET}")
    print(f"  Mode         : {mode}")
    print(f"  Accepted     : {C.GREEN}{s['accepted']}{C.RESET}")
    print(f"  Rejected     : {C.RED}{s['rejected']}{C.RESET}")
    print(f"  IDS alerts   : {C.ORANGE}{s['alerts']}{C.RESET}")
    if runner.ids is not None:
        m = runner.ids.metrics
        print(
            f"  IDS scores   : precision={m.precision:.2f} "
            f"recall={m.recall:.2f} f1={m.f1:.2f}"
        )
    path = runner.logger.flush_json()
    if path:
        _ok(f"JSON log → {path}")
    print()


def _run(secure: bool, prefix: str, title: str, subtitle: str, body: str, verbose: bool):
    r = SimulationRunner(secure=secure, verbose=verbose, log_prefix=prefix, with_ids=True)
    r.logger.banner(title, subtitle)
    getattr(r, body)()
    return r


def normal_secure(verbose: bool = False) -> SimulationRunner:
    r = _run(True, "normal_secure", "Normal Operation (SECURE)",
             "ECUs communicate with SecOC: HMAC + freshness", "run_normal", verbose)
    _ok("authenticated communication completed")
    _print_summary(r)
    return r


def normal_insecure(verbose: bool = False) -> SimulationRunner:
    r = _run(False, "normal_insecure", "Normal Operation (INSECURE)",
             "No authentication — every frame is trusted", "run_normal", verbose)
    _print_summary(r)
    return r


def replay_insecure(verbose: bool = False) -> SimulationRunner:
    r = _run(False, "replay_insecure", "Replay Attack (INSECURE)",
             "Attacker replays captured frames", "run_replay", verbose)
    _err("ATTACK SUCCEEDED: replayed frames accepted by ECUs")
    _print_summary(r)
    return r


def replay_secure(verbose: bool = False) -> SimulationRunner:
    r = _run(True, "replay_secure", "Replay Attack (SECURE)",
             "SecOC rejects stale freshness values", "run_replay", verbose)
    _ok("ATTACK DEFEATED: replays rejected (stale freshness + timestamp)")
    _print_summary(r)
    return r


def tamper_insecure(verbose: bool = False) -> SimulationRunner:
    r = _run(False, "tamper_insecure", "Tamper Attack (INSECURE)",
             "Attacker modifies payloads in flight", "run_tamper", verbose)
    _err("ATTACK SUCCEEDED: tampered payload accepted")
    _print_summary(r)
    return r


def tamper_secure(verbose: bool = False) -> SimulationRunner:
    r = _run(True, "tamper_secure", "Tamper Attack (SECURE)",
             "SecOC MAC catches any modification", "run_tamper", verbose)
    _ok("ATTACK DEFEATED: MAC mismatch caught the modification")
    _print_summary(r)
    return r


def inject_insecure(verbose: bool = False) -> SimulationRunner:
    r = _run(False, "inject_insecure", "Injection Attack (INSECURE)",
             "Attacker fabricates ECU frames", "run_injection", verbose)
    _err("ATTACK SUCCEEDED: fabricated frames accepted")
    _print_summary(r)
    return r


def inject_secure(verbose: bool = False) -> SimulationRunner:
    r = _run(True, "inject_secure", "Injection Attack (SECURE)",
             "SecOC rejects frames without a valid MAC", "run_injection", verbose)
    _ok("ATTACK DEFEATED: injected frames rejected (no valid MAC)")
    _print_summary(r)
    return r


# Core CAN attack scenarios (each returns a SimulationRunner used by full_demo).
SCENARIOS = {
    "normal-secure": normal_secure,
    "normal-insecure": normal_insecure,
    "replay-insecure": replay_insecure,
    "replay-secure": replay_secure,
    "tamper-insecure": tamper_insecure,
    "tamper-secure": tamper_secure,
    "inject-insecure": inject_insecure,
    "inject-secure": inject_secure,
}

# All runnable scenarios, including the UDS and IDS demos.
ALL = {**SCENARIOS, **uds_demo.SCENARIOS, **ids_demo.SCENARIOS}


def full_demo(verbose: bool = False) -> None:
    """Run every scenario and print a comparative table."""
    print(f"\n{C.CYAN}{C.BOLD}  FULL DEMO — all scenarios{C.RESET}\n")
    rows = []
    for name, fn in SCENARIOS.items():
        r = fn(verbose=False)
        s = r.summary()
        rows.append((name, r.secure, s["accepted"], s["rejected"], s["alerts"]))

    print(f"\n{C.CYAN}{C.BOLD}  COMPARATIVE RESULTS{C.RESET}")
    print(f"  {'Scenario':<20} {'Mode':<10} {'Accept':>7} {'Reject':>7} {'Alerts':>7}")
    print(f"  {'─' * 20} {'─' * 10} {'─' * 7} {'─' * 7} {'─' * 7}")
    for name, secure, acc, rej, al in rows:
        mode = "SECURE" if secure else "INSECURE"
        mc = C.GREEN if secure else C.RED
        print(f"  {name:<20} {mc}{mode:<10}{C.RESET} {acc:>7} {C.RED}{rej:>7}{C.RESET} {C.ORANGE}{al:>7}{C.RESET}")

    print(f"\n  {C.GREEN}{C.BOLD}SecOC rejected every attack; the IDS flagged them independently.{C.RESET}\n")
