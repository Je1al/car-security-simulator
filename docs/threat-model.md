# Threat model (STRIDE)

A STRIDE analysis of the simulated in-vehicle CAN network, the threats it models,
and the controls that mitigate each one. This mirrors the kind of item-level
threat analysis and risk assessment (TARA) required by ISO/SAE 21434.

## Assets

- **Safety-relevant signals** — brake pressure/status, engine RPM (spoofing these
  can cause unsafe vehicle behaviour).
- **Bus availability** — ECUs must be able to transmit safety frames in time.
- **Protected diagnostic data & routines** — gated behind UDS Security Access.
- **Secrets** — the SecOC key and the Security Access seed-key secret.

## Trust boundary

The CAN bus is a shared broadcast medium with **no inherent trust boundary** — any
connected node is implicitly trusted. The attacker is modelled as a node that has
reached the bus (e.g. via a compromised infotainment/telematics ECU, an OBD-II
device, or a spliced rogue device) and can both **sniff** and **transmit**.

## STRIDE

| STRIDE category | Threat in this model | Demonstrated by | Mitigation in `carsec` |
| --- | --- | --- | --- |
| **S**poofing | A rogue node impersonates a trusted ECU by sending frames with its arbitration ID | `attacks` injection; `inject-insecure` | SecOC MAC (no key → no valid MAC); IDS rule/frequency detectors |
| **T**ampering | Modifying a captured frame's payload in flight | `attacks` tamper; `tamper-insecure` | SecOC MAC over the payload |
| **R**epudiation | An ECU denies sending a frame; no audit trail | — | Authenticated frames + structured JSON/CSV event log |
| **I**nformation disclosure | Reading protected diagnostic data; recovering a weak seed-key secret from sniffed traffic | `uds.attack`; `uds-weak` | Security Access gating; HMAC seed-key (`uds-secure`) |
| **D**enial of service | Flooding the bus with high-priority frames to starve safety traffic | `attacks` DoS; `dos` | **Not** stopped by SecOC — detected by the frequency IDS; mitigated in practice by bus guardians/rate limiting |
| **E**levation of privilege | Unlocking privileged UDS services without authorisation | `uds.attack`; seed-key brute force | Security Access with attempt counter + time-delay lockout; strong seed-key algorithm |

## Residual risk & assumptions

- **DoS is detectable, not preventable** at the protocol layer. SecOC
  authenticates content, not bus access; a flood of dominant high-priority frames
  wins arbitration regardless of MACs. Real mitigations are hardware bus
  guardians, transceivers with TX rate limiting, and network segmentation via the
  gateway — the IDS here provides the *detection* half.
- **Key compromise is out of scope.** A single shared SecOC key is assumed
  secret; production systems use per-ECU keys in an HSM (see
  [secoc.md](secoc.md)). If the key leaks, authentication collapses — hence the
  emphasis on key management.
- **Physical attacks** (glitching, bus dominance at the transceiver level) are not
  modelled.
- **The IDS favours recall** (logical-OR of detectors) — appropriate for a safety
  bus where a missed attack is worse than a false alarm — at the cost of some
  false positives, quantified in the IDS benchmark.

## Security controls summary

1. **Authenticated communication** (SecOC) — integrity + authenticity + freshness.
2. **Defence in depth** (IDS) — independent anomaly detection, including for
   threats SecOC cannot stop (DoS).
3. **Access control** (UDS Security Access) — gates privileged diagnostics, with
   anti-brute-force controls and a strong challenge-response algorithm.
4. **Auditing** (telemetry) — every accept/reject/alert is logged with a reason.
