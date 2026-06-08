# SecOC design & standards mapping

This document explains the Secure Onboard Communication (SecOC) layer implemented
in `carsec.security` and how it maps onto **AUTOSAR SecOC** and **ISO/SAE 21434**.

## The problem

Classic CAN frames carry an arbitration ID and up to 8 data bytes — and nothing
else. There is no sender identity and no integrity check. Any node on the bus can
transmit any frame, and every receiver trusts it. An attacker who reaches the bus
(through a compromised telematics/infotainment unit, an OBD-II dongle, or a
physically spliced device) can therefore forge brake, throttle, or steering
messages. This is the root cause exploited by every attack in `carsec.attacks`.

## The countermeasure: an authenticator + freshness

AUTOSAR SecOC adds two things to a secured I-PDU:

1. an **Authenticator** — a Message Authentication Code (MAC) over the payload,
   so any modification or forgery is detected; and
2. a **Freshness Value (FV)** — a monotonic value bound into the MAC, so a
   captured-and-replayed frame is detected even though its MAC is valid.

`carsec` implements both, plus a time-based freshness check for defence in depth.

### 1. MAC (`security/crypto.py`)

```
tag = HMAC-SHA256(key, Data ID ‖ DLC ‖ data ‖ freshness ‖ timestamp)[:8]
```

- **HMAC-SHA256** — keyed, unforgeable without the shared secret.
- **Truncated to 64 bits** — AUTOSAR permits configurable truncation to fit the
  CAN(-FD) payload budget; forgery probability ≈ 2⁻⁶⁴ per attempt.
- **Constant-time verification** via `hmac.compare_digest` to avoid a timing
  side-channel.
- The **Data ID** (here, the CAN arbitration ID) is bound into the MAC so a valid
  tag cannot be moved onto a different message type.

### 2. Counter-based freshness (`security/freshness.py`)

The `FreshnessManager` keeps a monotonic counter per Data ID on the sender side
and the highest accepted value per Data ID on the receiver side. A frame is fresh
only if its FV is strictly greater than the last accepted one (within a forward
window that tolerates legitimately lost frames). A replay carries an already-seen
FV and is rejected. This is the counter-based AUTOSAR freshness profile, analogous
to the TLS record sequence number.

The receiver only advances its counter **after** the MAC verifies — otherwise an
attacker could "burn" freshness values to cause a denial of service.

### 3. Time-based freshness (`security/secoc.py`)

Each frame's timestamp must fall inside a freshness window (default 5 s, with a
1 s clock-skew tolerance). This bounds the replay opportunity even across counter
re-synchronisation and provides a second, independent reason to reject stale
frames.

## How each attack is defeated

| Attack | Why it fails under SecOC |
| --- | --- |
| **Replay** | the FV was already accepted → rejected; timestamp also stale |
| **Tampering** | recomputed MAC ≠ attached MAC → rejected |
| **Injection** | attacker has no key → no valid MAC → rejected |
| **DoS / flooding** | *not* stopped by SecOC (it authenticates content, not bus access) → this is what the **IDS** is for |

That last row is deliberate: it shows the limits of cryptographic authentication
and motivates the intrusion-detection layer.

## Mapping to standards

| `carsec` concept | AUTOSAR SecOC | ISO/SAE 21434 relevance |
| --- | --- | --- |
| `compute_mac` / 64-bit tag | Authenticator, `SecOCAuthInfoTxLength` | message authenticity control |
| `FreshnessManager` | Freshness Value & FV Manager | anti-replay control |
| Data-ID binding | `SecOCDataId` | message confusion prevention |
| per-ECU shared key | per-PDU key, HSM-provisioned | key management requirement |
| `VerificationResult` reasons | verification status / drop | security event logging |

## Simplifications (and why they're acceptable here)

- A **single shared key** is derived from a passphrase for readability; production
  uses per-ECU/per-PDU keys provisioned in a Hardware Security Module. The API
  already accepts a `key` per layer, so per-ECU keys are a drop-in change.
- The **full Freshness Value** travels on the (CAN-FD) wire rather than a
  truncated FV plus a separately-synchronised master FV. This keeps the focus on
  the security property instead of the synchronisation plumbing.

These are documentation-honest abstractions: the *security properties* are real
and demonstrated by the test suite (`tests/test_secoc.py`).
