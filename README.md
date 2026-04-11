# axonos-consent

![version](https://img.shields.io/badge/version-0.2.2-blue)
![MMP](https://img.shields.io/badge/MMP-v0.2.2-purple)
![consent](https://img.shields.io/badge/consent--ext-v0.1.0-green)
![no\_std](https://img.shields.io/badge/no__std-✓-brightgreen)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-red)
![alloc](https://img.shields.io/badge/alloc-zero-orange)
![interop](https://img.shields.io/badge/interop-15%2F15-success)
![tests](https://img.shields.io/badge/tests-60%2B-blue)
![fuzz](https://img.shields.io/badge/fuzz-✓-yellow)
![license](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)

**Deterministic consent enforcement layer for brain-computer interfaces.**

Reference implementation of the [MMP Consent Extension v0.1.0](https://sym.bot/spec/mmp-consent), co-designed with [Hongwei Xu](https://github.com/sym-bot) ([SYM.BOT](https://sym.bot)). Aligned with [Mesh Memory Protocol v0.2.2](https://sym.bot/spec/mmp), Section 16.4.

> *"The consent primitive was designed together — your BCI domain constraints shaped the spec."*
> — Hongwei Xu, Founder of SYM.BOT

---

## Interoperability

Two independent implementations — Rust `#![no_std]` ([axonos-consent](https://github.com/AxonOS-org/axonos-consent)) and Node.js ([sym](https://github.com/sym-bot/sym)) — produce identical state transitions for all canonical test vectors.

**15/15 canonical interop vectors — PASS**

Validated against [SYM.BOT](https://sym.bot) production mesh (5 active nodes, April 2026). Four consent frames (`withdraw`, `suspend`, `resume`, `STIMGUARD_LOCKOUT`) forwarded by relay, silently ignored by all production nodes per MMP §7 forward compatibility. Zero errors across 122 lines of WebSocket log.

### Integrity lock

```
SHA-256: 29a8bf9f2b4dabe5d9641a8a4c416f361c2ba9815cca9b8e9e1d222d002fa50a
```
Any modification to `tests/vectors/consent-interop-vectors-v0.1.0.json` invalidates the test suite.

---

## API

```rust
let result = engine.process_raw(&peer_id, cbor_bytes, now_us)?;
```

Single entry point. Executes the full pipeline:

```
process_raw → CBOR decode (bounded) → invariant check (MUST/SHOULD) → state transition (3×3) → StimGuard
```

---

## State machine

![states](https://img.shields.io/badge/GRANTED-●-brightgreen) ![states](https://img.shields.io/badge/SUSPENDED-●-yellow) ![states](https://img.shields.io/badge/WITHDRAWN-●-red)

```text
 ┌─────────┐  consent-suspend   ┌───────────┐
 │ GRANTED │ ─────────────────→ │ SUSPENDED │
 │         │ ←───────────────── │           │
 └────┬────┘  consent-resume    └─────┬─────┘
      │                               │
      │  consent-withdraw             │  consent-withdraw
      ▼                               ▼
 ┌──────────────────────────────────────┐
 │          WITHDRAWN (terminal)         │
 └──────────────────────────────────────┘
```

| | Withdraw | Suspend | Resume |
|---|---|---|---|
| **GRANTED** | → WITHDRAWN | → SUSPENDED | → GRANTED *(idempotent)* |
| **SUSPENDED** | → WITHDRAWN | → SUSPENDED *(idempotent)* | → GRANTED |
| **WITHDRAWN** | ![reject](https://img.shields.io/badge/-REJECT-red) | ![reject](https://img.shields.io/badge/-REJECT-red) | ![reject](https://img.shields.io/badge/-REJECT-red) |

`apply_frame()`: exhaustive 3×3 match, zero wildcards. New variant → compile error.

---

## Guarantees

| Property | Guarantee |
|---|---|
| ![no_std](https://img.shields.io/badge/no__std-✓-brightgreen) | Default build, no heap |
| ![zero-alloc](https://img.shields.io/badge/zero--alloc-✓-brightgreen) | `ReasonBuf` 64B fixed, encoder writes to `&mut [u8]` |
| ![bounded](https://img.shields.io/badge/bounded-✓-brightgreen) | `MAX_MAP=8` `MAX_STR=128` `MAX_DEPTH=4` |
| ![forbid](https://img.shields.io/badge/unsafe-forbidden-red) | `#![forbid(unsafe_code)]` — compile-time |
| ![fsm](https://img.shields.io/badge/FSM-exhaustive-blue) | 3×3 table, compiler-checked |
| ![must_use](https://img.shields.io/badge/must__use-✓-orange) | `#[must_use]` on `Error` and transitions |
| ![terminal](https://img.shields.io/badge/WITHDRAWN-terminal-red) | Any frame after WITHDRAWN → REJECT |
| ![layer2](https://img.shields.io/badge/Layer_2-consent-purple) | Below coupling (Layer 4), below SVAF |

---

## Threat model

| Threat | Mitigation | Bound |
|---|---|---|
| Map bomb | `MAX_MAP_FIELDS` | 8 |
| String bomb | `MAX_STRING_LEN` | 128 B |
| Stack overflow | `MAX_NESTING_DEPTH` | 4 |
| Type confusion | Bitmask duplicate key detection | 7 keys |
| Unsupported CBOR | Explicit reject: types 1,2,4,6,7 | — |
| Buffer overflow | `Err(BufferTooSmall)` | 256 B |
| State violation | `apply_frame()` reject | Compiler |

## Error taxonomy

```text
L1 (Wire)    → Error::Decode     — malformed CBOR, bounds, unsupported types
L2 (Struct)  → Error::Invariant  — MUST violations (§10)
L3 (State)   → Error::Transition — WITHDRAWN→any, peer not found
L4 (System)  → Error::Encode     — buffer too small
```

---

## MMP v0.2.2 alignment

| MMP § | Reference |
|---|---|
| §3.5 | `consent-withdraw` triggers CONNECTED → DISCONNECTED |
| §7 | Forward compat: unknown types silently ignored |
| §7.2 | Error code `2002 CONSENT_WITHDRAWN` |
| §16 | Extension mechanism: `consent-v0.1.0` in handshake |
| §16.4 | Published extension: [sym.bot/spec/mmp-consent](https://sym.bot/spec/mmp-consent) |

## Consent spec mapping

| § | Module | Enforcement |
|---|---|---|
| §3 | `frames` | Type-safe enum |
| §3.1 | `ConsentWithdraw` | `scope` non-optional |
| §3.4 | `reason` | 0x00–0x0F spec / 0x10–0xFF impl |
| §4 | `state::apply_frame` | Exhaustive 3×3 |
| §5.1 | `engine::process_raw` | Single entry point |
| §6.1 | `allows_cognitive_frames` | `false` for SUSPENDED/WITHDRAWN |
| §8 | `stim_guard` | DacGate, <1µs |
| §10 | `invariants` | MUST→violation, SHOULD→warning |

---

## Reason codes

| Code | Name | Range |
|---|---|---|
| `0x00` | UNSPECIFIED | spec |
| `0x01` | USER_INITIATED | spec |
| `0x02` | SAFETY_VIOLATION | spec |
| `0x03` | HARDWARE_FAULT | spec |
| `0x10` | **STIMGUARD_LOCKOUT** | AxonOS |
| `0x11` | SESSION_ATTESTATION_FAILURE | AxonOS |
| `0x12` | EMERGENCY_BUTTON | AxonOS |
| `0x13` | SWARM_FAULT_DETECTED | AxonOS |

---

## Crate structure

```
src/
├── lib.rs           # crate root, version, spec mapping
├── state.rs         # ConsentState + apply_frame (exhaustive 3×3)
├── engine.rs        # ConsentEngine, process_raw, process_frame
├── frames.rs        # Frame types, ReasonBuf (zero-alloc)
├── reason.rs        # ReasonCode registry (§3.4)
├── invariants.rs    # MUST/SHOULD/MAY (§10), check_transition
├── error.rs         # Layered error taxonomy (L1–L4)
├── stim_guard.rs    # DacGate trait, timing contract
└── codec/
    ├── cbor.rs      # Bounded encoder/decoder, security hardened
    └── json.rs      # JSON codec (feature-gated: alloc+std)
tests/
├── consent_interop.rs    # 60+ tests
└── vectors/              # 15 canonical interop vectors
fuzz/
└── fuzz_targets/         # cargo-fuzz: decode + roundtrip
```

---

## Testing

```bash
cargo test                  # no_std: CBOR, state machine, engine, invariants
cargo test --features json  # + JSON round-trip (15 vectors)
cargo +nightly fuzz run fuzz_cbor_decode
cargo +nightly fuzz run fuzz_cbor_roundtrip
```

---

## Licence

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

## Links

**AxonOS:** [axonos.org](https://axonos.org) · [medium.com/@AxonOS](https://medium.com/@AxonOS) · axonosorg@gmail.com

**SYM.BOT:** [sym.bot](https://sym.bot) · [sym.bot/spec/mmp](https://sym.bot/spec/mmp) · [sym.bot/spec/mmp-consent](https://sym.bot/spec/mmp-consent) · [github.com/sym-bot](https://github.com/sym-bot)
