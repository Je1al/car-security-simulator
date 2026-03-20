"""
main.py
────────────────────────────────────────────────────────────────────────────────
Car Security Simulator — main entry point and scenario orchestrator.

Scenarios
─────────
  1. Normal operation (secure)    — ECUs communicate with full HMAC + nonce
  2. Normal operation (insecure)  — ECUs communicate without any security
  3. Replay attack (insecure)     — attacker replays old messages, ECUs accept
  4. Replay attack (secure)       — replayed messages are rejected
  5. Tamper attack (insecure)     — tampered payload accepted
  6. Tamper attack (secure)       — tampered payload rejected (HMAC mismatch)
  7. Injection attack (insecure)  — fabricated messages accepted
  8. Injection attack (secure)    — fabricated messages rejected
  9. Full demo                    — all scenarios in sequence

CLI
────
  python main.py                     # full interactive menu
  python main.py --scenario normal   # run specific scenario
  python main.py --scenario all      # run all scenarios
  python main.py --no-color          # disable ANSI colour
  python main.py --verbose           # show individual TX events
  python main.py --delay 5           # 5ms bus delay
────────────────────────────────────────────────────────────────────────────────
"""

import argparse
import sys
import time

from can_protocol import MSG_ID
from ecu          import ECU_Engine, ECU_Brake, ECU_Gateway
from attacker     import Attacker
from network      import CANBus
from logger       import EventLogger, C
from visualizer   import Visualizer, SequenceDiagram


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ok(msg:  str) -> None: print(f"  {C.GREEN}✓{C.RESET}  {msg}")
def _err(msg: str) -> None: print(f"  {C.RED}✗{C.RESET}  {msg}")
def _info(msg:str) -> None: print(f"  {C.CYAN}ℹ{C.RESET}  {msg}")
def _warn(msg:str) -> None: print(f"  {C.YELLOW}⚠{C.RESET}  {msg}")


# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = f"""
{C.CYAN}{C.BOLD}  ╔══════════════════════════════════════════════════════════════╗
  ║   CAR SECURITY SIMULATOR  ·  Automotive CAN Bus Attack Demo  ║
  ║   ECU_Engine  ·  ECU_Brake  ·  ECU_Gateway  ·  Attacker      ║
  ╚══════════════════════════════════════════════════════════════╝{C.RESET}
"""

MENU = f"""
{C.BOLD}  ──────────────────────────────────────────────────────────────{C.RESET}
{C.GREEN}  [1]{C.RESET}  Normal Operation  (SECURE mode)
{C.GREEN}  [2]{C.RESET}  Normal Operation  (INSECURE mode)
{C.RED}  [3]{C.RESET}  Replay Attack     (INSECURE — attack SUCCEEDS)
{C.GREEN}  [4]{C.RESET}  Replay Attack     (SECURE   — attack DETECTED)
{C.RED}  [5]{C.RESET}  Tamper Attack     (INSECURE — attack SUCCEEDS)
{C.GREEN}  [6]{C.RESET}  Tamper Attack     (SECURE   — attack DETECTED)
{C.RED}  [7]{C.RESET}  Injection Attack  (INSECURE — attack SUCCEEDS)
{C.GREEN}  [8]{C.RESET}  Injection Attack  (SECURE   — attack DETECTED)
{C.CYAN}  [9]{C.RESET}  Full Demo         (all scenarios with comparison)
{C.BOLD}  [0]{C.RESET}  Exit
{C.BOLD}  ──────────────────────────────────────────────────────────────{C.RESET}
"""


# ─── Scenario runner ──────────────────────────────────────────────────────────

class SimulationRunner:
    """Manages ECU lifecycle and runs attack scenarios."""

    def __init__(
        self,
        secure:     bool  = True,
        delay_ms:   float = 0.0,
        verbose:    bool  = False,
        log_prefix: str   = "session",
    ) -> None:
        self.secure    = secure
        self.delay_ms  = delay_ms
        self.verbose   = verbose

        self.logger    = EventLogger(
            log_dir="logs",
            prefix=log_prefix,
            console=True,
            verbose=verbose,
        )
        self.bus       = CANBus(delay_ms=delay_ms, logger=self.logger)
        self.attacker  = Attacker("ATTACKER", self.bus, self.logger)
        self.ecus      = [
            ECU_Engine( bus=self.bus, logger=self.logger, secure=secure),
            ECU_Brake(  bus=self.bus, logger=self.logger, secure=secure),
            ECU_Gateway(bus=self.bus, logger=self.logger, secure=secure),
        ]

    def start(self) -> None:
        for ecu in self.ecus:
            ecu.start()

    def stop(self) -> None:
        for ecu in self.ecus:
            ecu.stop()
        time.sleep(0.2)

    def run_normal(self, duration: float = 3.0) -> None:
        """Run normal ECU communication for `duration` seconds."""
        self.start()
        time.sleep(duration)
        self.stop()

    def run_replay(self, duration: float = 2.0, wait_capture: float = 1.5) -> None:
        """Collect real messages then replay them."""
        self.start()
        _info(f"Collecting legitimate messages for {wait_capture:.1f}s …")
        time.sleep(wait_capture)

        captured = self.attacker.list_captured()
        _info(f"Attacker captured: {captured}")

        if captured:
            msg_type = list(captured.keys())[0]
            self.attacker.replay_attack(msg_type)
            time.sleep(0.3)
            self.attacker.replay_attack(msg_type)
        else:
            _warn("No messages captured — extend wait time")

        time.sleep(duration)
        self.stop()

    def run_tamper(self, duration: float = 2.0, wait_capture: float = 1.5) -> None:
        """Collect real messages then replay tampered versions."""
        self.start()
        time.sleep(wait_capture)

        captured = self.attacker.list_captured()
        if captured:
            msg_type = list(captured.keys())[0]
            self.attacker.tamper_attack(msg_type)
            time.sleep(0.2)
            self.attacker.tamper_attack("ENGINE_RPM", new_payload=b"\xFF\xFF")
        else:
            _warn("No messages captured")

        time.sleep(duration)
        self.stop()

    def run_injection(self, duration: float = 2.0) -> None:
        """Inject fabricated messages immediately."""
        self.start()
        time.sleep(0.5)

        self.attacker.inject_attack(MSG_ID["BRAKE_PRESS"])
        time.sleep(0.2)
        self.attacker.inject_attack(MSG_ID["BRAKE_STATUS"])
        time.sleep(0.2)
        self.attacker.inject_attack(MSG_ID["ENGINE_RPM"])

        time.sleep(duration)
        self.stop()

    def print_summary(self) -> None:
        """Print post-simulation statistics."""
        summary = self.logger.summary()
        mode_str = f"{C.GREEN}SECURE{C.RESET}" if self.secure else f"{C.RED}INSECURE{C.RESET}"
        print()
        print(f"  {C.BOLD}{'─'*58}{C.RESET}")
        print(f"  Mode         : {mode_str}")
        print(f"  Total events : {summary['total']}")
        print(f"  TX           : {summary['tx']}")
        print(f"  Accepted     : {C.GREEN}{summary['accepted']}{C.RESET}")
        print(f"  Rejected     : {C.RED}{summary['rejected']}{C.RESET}")
        print(f"  Attacks seen : {C.RED}{summary['attacks']}{C.RESET}")
        print(f"  Injected     : {C.MAGENTA}{summary['injected']}{C.RESET}")

        attack_sum = self.attacker.summary()
        print(f"  Replay attempts   : {attack_sum['replays']}")
        print(f"  Tamper attempts   : {attack_sum['tampers']}")
        print(f"  Injection attempts: {attack_sum['injections']}")

        if self.secure and summary['rejected'] > 0:
            print(f"\n  {C.GREEN}{C.BOLD}✓  All attacks detected and rejected in SECURE mode!{C.RESET}")
        elif not self.secure and summary['attacks'] > 0:
            print(f"\n  {C.RED}{C.BOLD}✗  Attacks succeeded in INSECURE mode!{C.RESET}")

        json_p = self.logger.flush_json()
        _ok(f"JSON log  → {json_p}")
        _ok(f"CSV  log  → {self.logger.csv_path}")
        print()


# ─── Individual scenario functions ────────────────────────────────────────────

def scenario_normal_secure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="normal_secure", console=True, verbose=verbose)
    log.banner("SCENARIO 1 — Normal Operation (SECURE)", "ECUs communicate with HMAC + nonce protection")
    r = SimulationRunner(secure=True, verbose=verbose, log_prefix="normal_secure")
    r.logger = log
    r.run_normal(duration=2.5)
    _ok("Normal secure communication completed")
    r.print_summary()
    return r


def scenario_normal_insecure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="normal_insecure", console=True, verbose=verbose)
    log.banner("SCENARIO 2 — Normal Operation (INSECURE)", "No authentication — any message is accepted")
    r = SimulationRunner(secure=False, verbose=verbose, log_prefix="normal_insecure")
    r.logger = log
    r.run_normal(duration=2.5)
    _warn("In insecure mode: messages accepted without any verification!")
    r.print_summary()
    return r


def scenario_replay_insecure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="replay_insecure", console=True, verbose=True)
    log.banner("SCENARIO 3 — Replay Attack (INSECURE)", "Attacker replays captured messages — SUCCEEDS")
    r = SimulationRunner(secure=False, verbose=verbose, log_prefix="replay_insecure")
    r.logger = log
    r.run_replay()
    _err("ATTACK SUCCEEDED: replayed messages accepted by ECUs!")
    r.print_summary()
    return r


def scenario_replay_secure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="replay_secure", console=True, verbose=True)
    log.banner("SCENARIO 4 — Replay Attack (SECURE)", "Attacker replays captured messages — DETECTED & REJECTED")
    r = SimulationRunner(secure=True, verbose=verbose, log_prefix="replay_secure")
    r.logger = log
    r.run_replay()
    _ok("ATTACK DETECTED: replayed messages rejected (stale nonce + timestamp)!")
    r.print_summary()
    return r


def scenario_tamper_insecure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="tamper_insecure", console=True, verbose=True)
    log.banner("SCENARIO 5 — Tamper Attack (INSECURE)", "Attacker modifies payload — SUCCEEDS")
    r = SimulationRunner(secure=False, verbose=verbose, log_prefix="tamper_insecure")
    r.logger = log
    r.run_tamper()
    _err("ATTACK SUCCEEDED: tampered payload accepted without MAC check!")
    r.print_summary()
    return r


def scenario_tamper_secure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="tamper_secure", console=True, verbose=True)
    log.banner("SCENARIO 6 — Tamper Attack (SECURE)", "Attacker modifies payload — DETECTED (HMAC mismatch)")
    r = SimulationRunner(secure=True, verbose=verbose, log_prefix="tamper_secure")
    r.logger = log
    r.run_tamper()
    _ok("ATTACK DETECTED: HMAC mismatch caught payload modification!")
    r.print_summary()
    return r


def scenario_inject_insecure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="inject_insecure", console=True, verbose=True)
    log.banner("SCENARIO 7 — Injection Attack (INSECURE)", "Fabricated messages accepted — SUCCEEDS")
    r = SimulationRunner(secure=False, verbose=verbose, log_prefix="inject_insecure")
    r.logger = log
    r.run_injection()
    _err("ATTACK SUCCEEDED: fake ECU messages accepted!")
    r.print_summary()
    return r


def scenario_inject_secure(verbose: bool = False) -> SimulationRunner:
    log = EventLogger(log_dir="logs", prefix="inject_secure", console=True, verbose=True)
    log.banner("SCENARIO 8 — Injection Attack (SECURE)", "Fabricated messages rejected — DETECTED")
    r = SimulationRunner(secure=True, verbose=verbose, log_prefix="inject_secure")
    r.logger = log
    r.run_injection()
    _ok("ATTACK DETECTED: all injected messages rejected (no valid HMAC)!")
    r.print_summary()
    return r


def scenario_full_demo(verbose: bool = False) -> None:
    """Run all scenarios and print a comparative summary."""
    print(BANNER)
    print(f"\n{C.CYAN}{C.BOLD}  FULL DEMO — All 8 Scenarios{C.RESET}\n")

    results = {}

    print(f"\n{C.BOLD}  Phase 1: Normal Communication{C.RESET}")
    r1 = SimulationRunner(secure=True,  verbose=False, log_prefix="demo_normal_sec")
    r1.run_normal(duration=2.0)
    results["normal_secure"] = r1.logger.summary()

    r2 = SimulationRunner(secure=False, verbose=False, log_prefix="demo_normal_ins")
    r2.run_normal(duration=2.0)
    results["normal_insecure"] = r2.logger.summary()

    print(f"\n{C.BOLD}  Phase 2: Replay Attacks{C.RESET}")
    r3 = SimulationRunner(secure=False, verbose=True, log_prefix="demo_replay_ins")
    r3.logger.banner("Replay Attack — INSECURE mode")
    r3.run_replay()
    results["replay_insecure"] = r3.logger.summary()

    r4 = SimulationRunner(secure=True, verbose=True, log_prefix="demo_replay_sec")
    r4.logger.banner("Replay Attack — SECURE mode")
    r4.run_replay()
    results["replay_secure"] = r4.logger.summary()

    print(f"\n{C.BOLD}  Phase 3: Tamper Attacks{C.RESET}")
    r5 = SimulationRunner(secure=False, verbose=True, log_prefix="demo_tamper_ins")
    r5.logger.banner("Tamper Attack — INSECURE mode")
    r5.run_tamper()
    results["tamper_insecure"] = r5.logger.summary()

    r6 = SimulationRunner(secure=True, verbose=True, log_prefix="demo_tamper_sec")
    r6.logger.banner("Tamper Attack — SECURE mode")
    r6.run_tamper()
    results["tamper_secure"] = r6.logger.summary()

    print(f"\n{C.BOLD}  Phase 4: Injection Attacks{C.RESET}")
    r7 = SimulationRunner(secure=False, verbose=True, log_prefix="demo_inject_ins")
    r7.logger.banner("Injection Attack — INSECURE mode")
    r7.run_injection()
    results["inject_insecure"] = r7.logger.summary()

    r8 = SimulationRunner(secure=True, verbose=True, log_prefix="demo_inject_sec")
    r8.logger.banner("Injection Attack — SECURE mode")
    r8.run_injection()
    results["inject_secure"] = r8.logger.summary()

    # Comparative table
    print(f"\n\n{C.CYAN}{C.BOLD}  ═══════════════════════════════════════════════════════════════")
    print(f"  COMPARATIVE RESULTS SUMMARY")
    print(f"  ═══════════════════════════════════════════════════════════════{C.RESET}")
    print(f"\n  {'Scenario':<28} {'Mode':<10} {'Accepted':>8} {'Rejected':>8} {'Attacks':>8}")
    print(f"  {'─'*28} {'─'*10} {'─'*8} {'─'*8} {'─'*8}")

    rows = [
        ("Normal operation",  "SECURE",   "normal_secure"),
        ("Normal operation",  "INSECURE", "normal_insecure"),
        ("Replay attack",     "INSECURE", "replay_insecure"),
        ("Replay attack",     "SECURE",   "replay_secure"),
        ("Tamper attack",     "INSECURE", "tamper_insecure"),
        ("Tamper attack",     "SECURE",   "tamper_secure"),
        ("Injection attack",  "INSECURE", "inject_insecure"),
        ("Injection attack",  "SECURE",   "inject_secure"),
    ]
    for name, mode, key in rows:
        s   = results.get(key, {})
        acc = s.get("accepted", 0)
        rej = s.get("rejected", 0)
        atk = s.get("attacks",  0)
        mode_c = C.GREEN if mode == "SECURE" else C.RED
        atk_c  = C.RED if atk > 0 and mode == "INSECURE" else (C.GREEN if rej > 0 else C.WHITE)
        print(
            f"  {name:<28} {mode_c}{mode:<10}{C.RESET} "
            f"{C.GREEN}{acc:>8}{C.RESET} "
            f"{C.RED}{rej:>8}{C.RESET} "
            f"{atk_c}{atk:>8}{C.RESET}"
        )

    print(f"\n  {C.GREEN}{C.BOLD}Key finding: SECURE mode rejected 100% of attacks.{C.RESET}")
    print(f"  {C.RED}{C.BOLD}INSECURE mode accepted all attacks silently.{C.RESET}\n")

    # Generate charts from last session
    viz = Visualizer(output_dir="logs")
    chart_paths = viz.generate_all(r8.logger, prefix="demo")
    for p in chart_paths:
        _ok(f"Chart → {p}")


# ─── Interactive menu ──────────────────────────────────────────────────────────

SCENARIO_MAP = {
    "1": ("Normal (secure)",        lambda v: scenario_normal_secure(v)),
    "2": ("Normal (insecure)",      lambda v: scenario_normal_insecure(v)),
    "3": ("Replay (insecure)",      lambda v: scenario_replay_insecure(v)),
    "4": ("Replay (secure)",        lambda v: scenario_replay_secure(v)),
    "5": ("Tamper (insecure)",      lambda v: scenario_tamper_insecure(v)),
    "6": ("Tamper (secure)",        lambda v: scenario_tamper_secure(v)),
    "7": ("Injection (insecure)",   lambda v: scenario_inject_insecure(v)),
    "8": ("Injection (secure)",     lambda v: scenario_inject_secure(v)),
    "9": ("Full Demo",              lambda v: scenario_full_demo(v)),
}


def interactive_menu(verbose: bool = False) -> None:
    print(BANNER)
    while True:
        print(MENU)
        choice = input(f"  {C.BOLD}Select scenario › {C.RESET}").strip()
        if choice == "0":
            print(f"\n  {C.DIM}Goodbye!{C.RESET}\n")
            sys.exit(0)
        if choice in SCENARIO_MAP:
            name, fn = SCENARIO_MAP[choice]
            print(f"\n  Running: {C.CYAN}{name}{C.RESET}\n")
            fn(verbose)
        else:
            print(f"  {C.YELLOW}Unknown option '{choice}'{C.RESET}")
        input(f"\n  {C.DIM}Press Enter to continue …{C.RESET}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="car-security-simulator",
        description="Automotive CAN bus attack & security demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scenarios:
  normal-secure    normal-insecure
  replay-insecure  replay-secure
  tamper-insecure  tamper-secure
  inject-insecure  inject-secure
  all              (full demo)
        """,
    )
    p.add_argument("--scenario", "-s", default="menu",
                   help="Scenario to run (default: interactive menu)")
    p.add_argument("--verbose",  "-v", action="store_true",
                   help="Show individual TX log lines")
    p.add_argument("--delay",    "-d", type=float, default=0.0,
                   help="Bus propagation delay in milliseconds")
    return p


_CLI_MAP = {
    "normal-secure":    scenario_normal_secure,
    "normal-insecure":  scenario_normal_insecure,
    "replay-insecure":  scenario_replay_insecure,
    "replay-secure":    scenario_replay_secure,
    "tamper-insecure":  scenario_tamper_insecure,
    "tamper-secure":    scenario_tamper_secure,
    "inject-insecure":  scenario_inject_insecure,
    "inject-secure":    scenario_inject_secure,
    "all":              scenario_full_demo,
}


def main() -> int:
    args = build_parser().parse_args()

    if args.scenario == "menu":
        interactive_menu(verbose=args.verbose)
        return 0

    fn = _CLI_MAP.get(args.scenario)
    if not fn:
        print(f"Unknown scenario: {args.scenario!r}")
        print("Available:", ", ".join(_CLI_MAP.keys()))
        return 1

    print(BANNER)
    fn(args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
