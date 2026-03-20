# Car Security Simulator

> **Automotive CAN bus security research tool** — simulates ECU communication, replay attacks, message tampering, and injection attacks with HMAC + nonce protection.  
> Pure Python · No external dependencies · ISO 21434 / AUTOSAR SecOC inspired

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Automotive Background](#automotive-background)
  - [What is a CAN Bus?](#what-is-a-can-bus)
  - [What is an ECU?](#what-is-an-ecu)
  - [Why CAN is Insecure by Design](#why-can-is-insecure-by-design)
- [System Architecture](#system-architecture)
- [CAN-like Protocol Design](#can-like-protocol-design)
- [Security Implementation](#security-implementation)
  - [HMAC Authentication](#hmac-authentication)
  - [Nonce Replay Prevention](#nonce-replay-prevention)
  - [Timestamp Freshness](#timestamp-freshness)
- [Attack Simulations](#attack-simulations)
  - [Replay Attack](#1-replay-attack)
  - [Tampering Attack](#2-tampering-attack)
  - [Injection Attack](#3-injection-attack)
- [Scenarios](#scenarios)
- [CLI Reference](#cli-reference)
- [Repository Structure](#repository-structure)
- [Demo Results](#demo-results)
- [Security Analysis](#security-analysis)
- [Real-World References](#real-world-references)

---

## Overview

`car-security-simulator` models an in-vehicle network where three ECUs exchange CAN-like messages over a simulated broadcast bus. It demonstrates:

- **Normal operation** — authenticated ECU communication
- **Three attack types** — replay, tampering, message injection
- **Two security modes** — insecure (raw CAN) vs. secure (HMAC + nonce + timestamp)
- **Side-by-side comparison** — what attacks succeed without security, and why they fail with it

```
ECU_Engine ──┐
             ├── [ CAN Bus ] ── ECU_Gateway
ECU_Brake  ──┘         │
                    ATTACKER (passive sniffer + active injector)
```

---

## Quick Start

```bash
git clone https://github.com/yourusername/car-security-simulator.git
cd car-security-simulator

# No dependencies required for core simulation
# Optional: pip install matplotlib  (for charts)

# Interactive menu
python main.py

# Run all 8 scenarios with comparison table
python main.py --scenario all

# Single scenario
python main.py --scenario replay-secure --verbose
python main.py --scenario inject-insecure
```

---

## Automotive Background

### What is a CAN Bus?

Controller Area Network (CAN) was developed by Bosch in 1986 and became the dominant in-vehicle communication standard. Every modern production vehicle uses it.

```
ECU 1 ──┐
ECU 2 ──┼── CAN_H / CAN_L (two-wire differential bus)
ECU 3 ──┤
ECU N ──┘
```

Key properties:
- **Broadcast** — every node sees every message. There is no addressing.
- **Message ID** — identifies the *type* of data (e.g. engine RPM), not the sender
- **Priority arbitration** — lower message ID = higher priority (non-destructive)
- **Up to 8 bytes payload** (classic CAN) or 64 bytes (CAN-FD)
- **Speed** — 125 kbit/s to 1 Mbit/s depending on segment

### What is an ECU?

An Electronic Control Unit is a small embedded computer that controls one vehicle subsystem. Modern cars contain **70–150 ECUs**:

| ECU | Function |
|---|---|
| Engine Control Module (ECM) | Fuel injection, ignition timing, RPM |
| Brake Control Module (BCM) | ABS, ESC, brake pressure |
| Transmission Control Unit | Gear selection, clutch control |
| Gateway ECU | Bridges different bus segments |
| Telematics Control Unit (TCU) | Cellular connectivity ← **primary attack surface** |
| Body Control Module | Lights, windows, door locks |

### Why CAN is Insecure by Design

Classic CAN was designed in the 1980s for reliability and real-time performance — **not security**. The threat model at the time assumed physical access was required to attack a vehicle.

CAN has **no built-in**:
- Authentication (any node can send any message)
- Encryption (all data is plaintext)
- Access control (all nodes see all messages)
- Integrity protection (no MAC or checksum over data)

This means: **if an attacker reaches the bus, they can send any message, impersonate any ECU, and disable any system.**

Attack vectors that provide bus access:
- OBD-II port (under dashboard, no authentication)
- Compromised infotainment system via Bluetooth/Wi-Fi
- Compromised TCU via cellular network (Miller & Valasek 2015)
- Malicious USB device
- Supply chain compromise of a component

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    car-security-simulator                   │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  ECU_Engine  │  ECU_Brake   │ ECU_Gateway  │   ATTACKER     │
│              │              │              │                │
│  TX: RPM     │  TX: Brake   │  TX: FWD     │  Sniff all     │
│  TX: Temp    │      Pressure│  RX: All     │  Replay old    │
│  RX: Brake   │  TX: Status  │  Forward RPM │  Tamper payload│
│  RX: GW_ACK  │  RX: RPM    │              │  Inject fake   │
└──────┬───────┴──────┬───────┴──────┬───────┴────────┬───────┘
       │              │              │                │
       └──────────────┴──────────────┴────────────────┘
                         CAN Bus (broadcast queue)
                         
Each ECU runs two threads:
  TX thread: build and transmit messages every 500ms
  RX thread: drain inbox, verify security, process payload
```

### Module Map

```
can_protocol.py   ← Wire format, message IDs, payload encode/decode
security.py       ← HMAC-SHA256, NonceManager, timestamp validation
ecu.py            ← Base ECU class + ECU_Engine, ECU_Brake, ECU_Gateway
network.py        ← Broadcast CAN bus simulation (thread-safe queues)
attacker.py       ← Passive sniffer + replay / tamper / inject attacks
logger.py         ← ANSI console + JSON + CSV structured logging
visualizer.py     ← matplotlib charts (timeline, summary, flow)
main.py           ← 8 scenarios + interactive menu + argparse CLI
```

---

## CAN-like Protocol Design

Our extended CAN frame adds security fields absent from real CAN:

```
┌────────────┬────────────┬──────────────┬─────────────┬───────────┬─────────────┐
│  msg_id    │payload_len │   payload    │  timestamp  │   nonce   │  hmac_tag   │
│  4 bytes   │  2 bytes   │   8 bytes    │   8 bytes   │  4 bytes  │   8 bytes   │
│  uint32    │  uint16    │  zero-padded │  float64    │  uint32   │  SHA256[:8] │
└────────────┴────────────┴──────────────┴─────────────┴───────────┴─────────────┘
Total wire size: 34 bytes
```

**msg_id** — identifies message type (analogous to SAE J1939 PGN):

| ID | Name | Content |
|---|---|---|
| `0x0A0` | ENGINE_RPM | uint16 RPM (0–65535) |
| `0x0A1` | ENGINE_TEMP | int16 × 10 (°C with 0.1 precision) |
| `0x0B0` | BRAKE_PRESS | uint16 × 100 (bar) |
| `0x0B1` | BRAKE_STATUS | uint8 status flags |
| `0x0C0` | GATEWAY_FWD | forwarded engine RPM |
| `0xDEAD` | ATTACKER_INJ | fabricated malicious message |

**Security extensions** (inspired by AUTOSAR SecOC):
- `timestamp` — creation time (Unix float); enables freshness check
- `nonce` — monotonic counter per sender; prevents replay
- `hmac_tag` — HMAC-SHA256 truncated to 8 bytes; ensures integrity and authenticity

---

## Security Implementation

### HMAC Authentication

```
HMAC-SHA256(key, msg_id ‖ payload_len ‖ payload ‖ timestamp ‖ nonce)
```

- **Key**: 32-byte pre-shared secret derived from a master passphrase via SHA-256 KDF
- **Truncation**: first 8 bytes used (2⁻⁶⁴ forgery probability per attempt)
- **Constant-time comparison**: `hmac.compare_digest()` prevents timing attacks
- **What it covers**: all fields that affect interpretation — any single-bit change in payload invalidates the tag

```python
# security.py — core signing
def sign_message(msg: CANMessage, key: bytes = SHARED_KEY) -> CANMessage:
    raw      = _mac_input(msg)                          # serialize authenticated fields
    full_mac = hmac.new(key, raw, hashlib.sha256).digest()
    msg.hmac_tag = full_mac[:8]                         # truncate to 8 bytes
    return msg
```

### Nonce Replay Prevention

Each sender maintains a **monotonic counter** starting at 1. The receiver tracks the highest accepted nonce per sender and rejects anything ≤ that value.

```
Sender:   nonce=1 → nonce=2 → nonce=3 → ...
Receiver: accepts 1, accepts 2, accepts 3 ...
          REJECTS nonce=1 again (replay!)
```

```python
# security.py — NonceManager
def is_fresh(self, sender: str, nonce: int) -> bool:
    if nonce <= self._seen[sender]:
        return False          # replay detected
    self._seen[sender] = nonce
    return True
```

**Important**: the nonce counter only advances when the HMAC is valid. This prevents an attacker from burning nonces to cause denial-of-service.

### Timestamp Freshness

Messages older than `TIMESTAMP_WINDOW_SEC` (5 seconds) are rejected regardless of nonce validity. This handles the case where an attacker stores a valid message and replays it after a long delay.

```python
def is_timestamp_fresh(ts: float, window: float = 5.0) -> bool:
    age = time.time() - ts
    return -1.0 <= age <= window    # ±1s tolerance for clock skew
```

### Three-Layer Verification (receive path)

```python
# security.py — SecurityLayer.verify()
mac_ok   = verify_mac(msg, key)           # Layer 1: integrity + auth
ts_ok    = is_timestamp_fresh(msg.ts)     # Layer 2: freshness
nonce_ok = nonce_mgr.is_fresh(sender, n) # Layer 3: replay prevention

accepted = mac_ok AND ts_ok AND nonce_ok
```

All three checks must pass. If any fails, the message is dropped and the reason is logged.

---

## Attack Simulations

### 1. Replay Attack

**What**: Capture a legitimate message and re-transmit it later, unchanged.

**Why dangerous in vehicles**:
```
Scenario: Attacker captures BRAKE_PRESS=0.0 (no braking)
          Driver presses brake pedal
          Attacker replays BRAKE_PRESS=0.0
          BCM receives and acts on stale "no braking" command
          → Vehicle fails to decelerate
```

**Real example**: Replay of "unlock" commands captured from key fob (RF relay attacks) — same principle, different physical layer.

**Detection in secure mode**:
```
REJECT ← ✗ Nonce 1 already seen — REPLAY ATTACK detected
REJECT ← ✗ Timestamp too old (age=4.32s)
```

### 2. Tampering Attack

**What**: Capture a legitimate message, modify its payload, re-transmit. The original HMAC tag remains — but it covers the *original* payload.

**Why dangerous**:
```
Attacker captures:  ENGINE_RPM payload=0x09f3 (2547 RPM)
Attacker modifies:  ENGINE_RPM payload=0xf29f (62111 RPM — impossible!)
Receiver sees:      ENGINE_RPM=62111 → false over-rev alarm → fuel cut-off
```

**Detection in secure mode**:
```
REJECT ← ✗ HMAC verification FAILED — message tampered or forged
```
A single bit change in the payload produces a completely different HMAC. The attacker cannot compute a valid tag without the shared key.

### 3. Injection Attack

**What**: Fabricate a completely new message with arbitrary payload. No valid HMAC (attacker doesn't know the key).

**Why dangerous** (insecure mode — fully accepted):
```
11:04:09  INJECT  [ATTACKER]  brake_pressure=0.0 bar (DISABLE BRAKES)
11:04:09  ACCEPT  [ECU_Engine] ← ✓ accepted ⟨BRAKE_PRESS⟩

11:04:09  INJECT  [ATTACKER]  brake_status=0xFF (FAKE FAULT)
11:04:09  ACCEPT  [ECU_Engine] ← ✓ accepted ⟨BRAKE_STATUS⟩
          INFO    [ECU_Engine]  Brake detected (status=0xff) — reducing RPM

11:04:10  INJECT  [ATTACKER]  rpm=9999 (FALSE OVER-REV)
11:04:10  ACCEPT  [ECU_Gateway] Forwarding ENGINE_RPM=9999
```

**Detection in secure mode**:
```
REJECT ← ✗ HMAC verification FAILED — message tampered or forged
```

---

## Scenarios

| # | Scenario | Mode | Outcome |
|---|---|---|---|
| 1 | Normal operation | SECURE | All messages accepted, ECUs communicate correctly |
| 2 | Normal operation | INSECURE | Same — no difference without attack |
| 3 | Replay attack | INSECURE | ✗ Attack **succeeds** — replayed messages accepted |
| 4 | Replay attack | SECURE | ✓ Attack **detected** — nonce + timestamp rejection |
| 5 | Tamper attack | INSECURE | ✗ Attack **succeeds** — corrupted RPM=62111 accepted |
| 6 | Tamper attack | SECURE | ✓ Attack **detected** — HMAC mismatch |
| 7 | Injection attack | INSECURE | ✗ Attack **succeeds** — fake brake/RPM commands accepted |
| 8 | Injection attack | SECURE | ✓ Attack **detected** — no valid HMAC |

---

## CLI Reference

```bash
# Interactive menu (recommended for demos)
python main.py

# Run specific scenario
python main.py --scenario normal-secure
python main.py --scenario normal-insecure
python main.py --scenario replay-insecure
python main.py --scenario replay-secure
python main.py --scenario tamper-insecure
python main.py --scenario tamper-secure
python main.py --scenario inject-insecure
python main.py --scenario inject-secure
python main.py --scenario all           # full demo with comparison table

# Options
python main.py --scenario all --verbose         # show TX log lines
python main.py --scenario replay-secure --delay 5   # 5ms bus propagation delay

# Python API
from main import SimulationRunner

runner = SimulationRunner(secure=True, verbose=True)
runner.run_replay(duration=3.0)
runner.print_summary()
```

---

## Repository Structure

```
car-security-simulator/
│
├── main.py              ← Entry point — 8 scenarios + interactive menu + CLI
├── can_protocol.py      ← CAN-like wire format, message IDs, payload helpers
├── security.py          ← HMAC signing, NonceManager, timestamp validation
├── ecu.py               ← Base ECU class + ECU_Engine, ECU_Brake, ECU_Gateway
├── network.py           ← Simulated broadcast CAN bus (thread-safe)
├── attacker.py          ← Replay / tamper / inject attack module
├── logger.py            ← Structured logging: ANSI console + JSON + CSV
├── visualizer.py        ← matplotlib charts
│
└── logs/                ← Generated at runtime (gitignored except .gitkeep)
    ├── demo_timeline.png
    ├── demo_summary.png
    ├── demo_flow.png
    └── *.json / *.csv
```

---

## Demo Results

### Comparative Summary (python main.py --scenario all)

```
Scenario                     Mode       Accepted  Rejected  Attacks
──────────────────────────── ────────── ────────  ────────  ───────
Normal operation             SECURE           40         0        0
Normal operation             INSECURE         40         0        0
Replay attack                INSECURE         86         0        2  ← attack succeeds
Replay attack                SECURE           79         5        2  ← 100% detected
Tamper attack                INSECURE         84         0        2  ← attack succeeds
Tamper attack                SECURE           80         6        2  ← 100% detected
Injection attack             INSECURE         67         0        3  ← attack succeeds
Injection attack             SECURE           58         9        3  ← 100% detected

Key finding: SECURE mode rejected 100% of attacks.
INSECURE mode accepted all attacks silently.
```

### Log excerpt — Replay attack detected

```
11:03:58  REPLAY   [ATTACKER]      REPLAY ATTACK → replaying ENGINE_RPM (nonce=1, age=1.43s)
11:03:58  INJECT   [ATTACKER]      Injected msg_id=ENGINE_RPM payload=0b7f
11:03:58  REJECT   [ECU_Brake]     ← ✗ REJECTED: Nonce 1 already seen — REPLAY ATTACK detected
11:03:58  REJECT   [ECU_Gateway]   ← ✗ REJECTED: Nonce 1 already seen — REPLAY ATTACK detected
```

### Log excerpt — Tamper attack detected

```
11:04:06  TAMPER   [ATTACKER]      TAMPER ATTACK → ENGINE_RPM payload changed 093b → f63b
11:04:06  REJECT   [ECU_Engine]    ← ✗ REJECTED: HMAC verification FAILED — message tampered or forged
11:04:06  REJECT   [ECU_Brake]     ← ✗ REJECTED: HMAC verification FAILED — message tampered or forged
11:04:06  REJECT   [ECU_Gateway]   ← ✗ REJECTED: HMAC verification FAILED — message tampered or forged
```

### Log excerpt — Injection attack in INSECURE mode (danger!)

```
11:04:09  INJECT   [ATTACKER]      INJECTION ATTACK → brake_pressure=0.0 bar (DISABLE BRAKES)
11:04:09  ACCEPT   [ECU_Engine]    ← ✓ accepted ⟨BRAKE_PRESS⟩    ← no authentication!
11:04:09  INJECT   [ATTACKER]      INJECTION ATTACK → rpm=9999 (FALSE OVER-REV)
11:04:10  ACCEPT   [ECU_Gateway]   Forwarding ENGINE_RPM=9999
```

---

## Security Analysis

### Strengths

| Property | Mechanism | Benefit |
|---|---|---|
| Authenticity | HMAC-SHA256 | Only nodes with the shared key can send valid messages |
| Integrity | HMAC covers all fields | Any single-bit modification is detected |
| Replay prevention | Monotonic nonce | Old captured messages are rejected |
| Freshness | Timestamp window | Long-delayed replays are rejected independently |
| Timing-safe | `hmac.compare_digest()` | No timing side-channel on verification |

### Weaknesses and Limitations

| Weakness | Explanation | Production fix |
|---|---|---|
| Single shared key | All ECUs share one key — compromise of one = compromise of all | Per-ECU derived keys (AUTOSAR SecOC) |
| Simple KDF | SHA-256 of passphrase — no salt, no iterations | PBKDF2-HMAC-SHA256 or HKDF |
| Nonce not persistent | Counter resets on ECU restart — replay window reopens briefly | AUTOSAR SecOC uses persistent counters in NVM |
| No encryption | Payload is plaintext — eavesdropper learns vehicle state | CAN-FD with payload encryption (less common) |
| Python simulation | Not suitable for real-time ECU use (GIL, GC) | C implementation on RTOS (FreeRTOS, AUTOSAR OS) |
| Thread timing | Python threads have non-deterministic scheduling | RTOS tasks with fixed deadlines |

### Production Standards

This simulator is inspired by:
- **AUTOSAR SecOC** (Secure Onboard Communication) — per-message MAC + freshness counter
- **ISO 21434** — Road vehicles cybersecurity engineering standard
- **SAE J3061** — Cybersecurity guidebook for cyber-physical vehicle systems
- **UNECE WP.29 / R155** — UN regulation requiring type-approved cybersecurity management

---

## Real-World References

- **Miller & Valasek (2015)** — Remote exploitation of a Jeep Cherokee via Uconnect telematics, demonstrating CAN bus injection to disable brakes and kill the engine at highway speed. Led to recall of 1.4 million vehicles.
- **Tesla Model S (2016)** — Keen Security Lab demonstrated remote CAN bus access via the browser and Wi-Fi stack.
- **BMW ConnectedDrive (2015)** — Remote unlock via GSM without authentication.
- **Volkswagen/Megamos crypto (2015)** — Key fob cryptography reverse-engineered, enabling cloning and replay.

These attacks all exploit the same fundamental issue demonstrated in this simulator: **CAN buses implicitly trust every message they receive.**

---

## Installation

```bash
git clone https://github.com/yourusername/car-security-simulator.git
cd car-security-simulator

# Core simulation — no dependencies (Python 3.9+ stdlib only)
python main.py

# For charts
pip install matplotlib
python main.py --scenario all
```

**Python 3.9+** required (uses `dataclasses`, `hmac.compare_digest`, `typing` generics).

---

*Built for educational purposes in automotive cybersecurity.*  
*Do not use the cryptographic primitives in this project for production vehicle systems.*  
*For production: use AUTOSAR SecOC with HSM-backed key storage.*
