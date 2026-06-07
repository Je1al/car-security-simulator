"""Command-line interface for the car security simulator."""

from __future__ import annotations

import argparse
import sys

from carsec import __version__
from carsec.scenarios import library
from carsec.telemetry.logger import C

BANNER = """
  ╔══════════════════════════════════════════════════════════════╗
  ║   CAR SECURITY SIMULATOR · Automotive CAN Bus Attack Lab      ║
  ║   ECUs · SecOC · Intrusion Detection · UDS                    ║
  ╚══════════════════════════════════════════════════════════════╝
"""


def _menu() -> None:
    items = [
        ("1", "Normal Operation (SECURE)", "normal-secure"),
        ("2", "Normal Operation (INSECURE)", "normal-insecure"),
        ("3", "Replay Attack (INSECURE — succeeds)", "replay-insecure"),
        ("4", "Replay Attack (SECURE — defeated)", "replay-secure"),
        ("5", "Tamper Attack (INSECURE — succeeds)", "tamper-insecure"),
        ("6", "Tamper Attack (SECURE — defeated)", "tamper-secure"),
        ("7", "Injection Attack (INSECURE — succeeds)", "inject-insecure"),
        ("8", "Injection Attack (SECURE — defeated)", "inject-secure"),
        ("9", "Full Demo (all CAN scenarios + comparison)", "all"),
        ("u", "UDS Security Access — WEAK seed-key (attack succeeds)", "uds-weak"),
        ("U", "UDS Security Access — HMAC seed-key (attack defeated)", "uds-secure"),
        ("d", "Denial of Service — bus flooding (IDS detects)", "dos"),
        ("b", "IDS Benchmark — precision/recall on labelled trace", "ids-benchmark"),
    ]
    print(f"{C.CYAN}{C.BOLD}{BANNER}{C.RESET}")
    while True:
        print(f"\n  {C.BOLD}{'─' * 58}{C.RESET}")
        for key, label, _ in items:
            print(f"  {C.GREEN}[{key}]{C.RESET}  {label}")
        print(f"  {C.BOLD}[0]{C.RESET}  Exit")
        print(f"  {C.BOLD}{'─' * 58}{C.RESET}")
        choice = input(f"  {C.BOLD}Select › {C.RESET}").strip()
        if choice == "0":
            print(f"\n  {C.DIM}Goodbye!{C.RESET}\n")
            return
        match = next((s for k, _, s in items if k == choice), None)
        if match == "all":
            library.full_demo()
        elif match:
            library.ALL[match]()
        else:
            print(f"  {C.YELLOW}unknown option {choice!r}{C.RESET}")
        input(f"\n  {C.DIM}Press Enter to continue …{C.RESET}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="carsec",
        description="Automotive CAN bus attack & security demonstration platform",
    )
    p.add_argument(
        "-s", "--scenario", default="menu",
        help="scenario to run, 'all', or 'menu' (default). Use --list to see all.",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="show individual TX frames")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("--list", action="store_true", help="list available scenarios and exit")
    p.add_argument("--version", action="version", version=f"carsec {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if args.list:
        print("Available scenarios:")
        for name in library.ALL:
            print(f"  {name}")
        print("  all")
        return 0

    if args.scenario == "menu":
        try:
            _menu()
        except (KeyboardInterrupt, EOFError):
            print()
        return 0

    print(f"{C.CYAN}{C.BOLD}{BANNER}{C.RESET}")
    if args.scenario == "all":
        library.full_demo(verbose=args.verbose)
        return 0
    fn = library.ALL.get(args.scenario)
    if fn is None:
        print(f"unknown scenario {args.scenario!r}; try --list")
        return 1
    fn(verbose=args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
