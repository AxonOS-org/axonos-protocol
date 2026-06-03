<div align="center">

# axonos-protocol

### The AxonOS Consent Protocol — consent that travels across the cognitive mesh.

#### Reference implementation · `no_std` · zero-alloc · `#![forbid(unsafe_code)]`

[![CI](https://github.com/AxonOS-org/axonos-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/AxonOS-org/axonos-protocol/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/badge/crate-v0.4.0-0a4a8f?style=flat-square)](https://github.com/AxonOS-org/axonos-protocol/releases)
[![Spec](https://img.shields.io/badge/ACP-rev%200.3-0a4a8f?style=flat-square)](SPEC.md)
[![Standard](https://img.shields.io/badge/Standard-v1.0.0-0a4a8f?style=flat-square)](https://github.com/AxonOS-org/axonos-standard)
[![Rust](https://img.shields.io/badge/Rust-no__std-CE422B?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-475569?style=flat-square)](#license)

</div>

---

`axonos-protocol` is the **wire-level consent layer** of AxonOS — the reference
implementation of the **AxonOS Consent Protocol (ACP)**, specified in [`SPEC.md`](SPEC.md).
It carries a person's consent — *grant, suspend, withdraw* — across the AxonOS cognitive
mesh as bounded CBOR frames, enforces it with an exhaustive state machine, and engages a
hardware **StimGuard** the instant consent is withdrawn. The default build is `no_std`,
allocates nothing, and forbids `unsafe` at compile time.

ACP is an AxonOS protocol end to end: the specification and this implementation are
developed and maintained entirely within the AxonOS project. Where
[`axonos-consent`](https://github.com/AxonOS-org/axonos-consent) is the **kernel-level**
consent primitive — an in-process FSM with formally-bounded withdrawal latency —
`axonos-protocol` is the **network-level** layer that makes that consent interoperable
between independent nodes on the wire.

> **Frozen vectors.** Any change to the files under `tests/vectors/` changes the protocol —
> the vectors are the contract, not a fixture.

## Within AxonOS

| Repository | Role |
|:--|:--|
| [`axonos-kernel`](https://github.com/AxonOS-org/axonos-kernel) | The real-time `no_std` kernel — scheduler, SPSC, time, capability |
| [`axonos-consent`](https://github.com/AxonOS-org/axonos-consent) | **Kernel-level** consent FSM, formally-bounded withdrawal latency |
| **`axonos-protocol`** *(this crate)* | **Network-level** consent — the AxonOS Consent Protocol, on the wire |
| [`axonos-swarm`](https://github.com/AxonOS-org/axonos-swarm) | The cognitive mesh transport ACP travels over |
| [`axonos-conformance`](https://github.com/AxonOS-org/axonos-conformance) | Byte-exact wire-format vectors + codecs in seven languages |
| [`axonos-standard`](https://github.com/AxonOS-org/axonos-standard) | The normative AxonOS Standard and claims catalogue |

## API

```rust
let result = engine.process_raw(&peer_id, cbor_bytes, now_us)?;
```

A single entry point. It executes the full pipeline (SPEC §5.1):

```text
process_raw → CBOR decode (bounded) → invariant check (MUST/SHOULD) → state transition (3×3) → StimGuard
```

---

## State machine — SPEC §4

![GRANTED](https://img.shields.io/badge/GRANTED-●-brightgreen) ![SUSPENDED](https://img.shields.io/badge/SUSPENDED-●-yellow) ![WITHDRAWN](https://img.shields.io/badge/WITHDRAWN-●-red)

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

`apply_frame()` is an exhaustive 3×3 match with zero wildcards. A new state variant is a
compile error, not a silent fall-through.

---

## Guarantees

| Property | Guarantee |
|---|---|
| ![no_std](https://img.shields.io/badge/no__std-✓-brightgreen) | Default build, no heap |
| ![zero-alloc](https://img.shields.io/badge/zero--alloc-✓-brightgreen) | `ReasonBuf` 64 B fixed; the encoder writes to `&mut [u8]` |
| ![bounded](https://img.shields.io/badge/bounded-✓-brightgreen) | `MAX_MAP=8` · `MAX_STR=128` · `MAX_DEPTH=4` |
| ![forbid](https://img.shields.io/badge/unsafe-forbidden-red) | `#![forbid(unsafe_code)]` — compile-time |
| ![fsm](https://img.shields.io/badge/FSM-exhaustive-blue) | 3×3 table, compiler-checked |
| ![must_use](https://img.shields.io/badge/must__use-✓-orange) | `#[must_use]` on `Error` and transitions |
| ![terminal](https://img.shields.io/badge/WITHDRAWN-terminal-red) | Any frame after WITHDRAWN → REJECT |

---

## Security bounds — SPEC §9

| Threat | Mitigation | Bound |
|---|---|---|
| Map bomb | `MAX_MAP_FIELDS` | 8 |
| String bomb | `MAX_STRING_LEN` | 128 B |
| Stack overflow | `MAX_NESTING_DEPTH` | 4 |
| Type confusion | Bitmask duplicate-key detection | 7 keys |
| Unsupported CBOR | Explicit reject: major types 1, 2, 4, 6, 7 | — |
| Buffer overflow | `Err(BufferTooSmall)` | 256 B |
| State violation | `apply_frame()` reject | Compiler |

## Error taxonomy — SPEC §10

```text
L1 (Wire)    → Error::Decode     — malformed CBOR, bounds, unsupported types
L2 (Struct)  → Error::Invariant  — MUST violations
L3 (State)   → Error::Transition — WITHDRAWN→any, peer not found
L4 (System)  → Error::Encode     — buffer too small
```

---

## Specification mapping

Every module maps to a section of [`SPEC.md`](SPEC.md); the spec and the implementation
are a single contract.

| SPEC § | Module | Enforcement |
|---|---|---|
| §3 | `frames` | Type-safe frame enum |
| §3.1 | `ConsentWithdraw` | `scope` non-optional |
| §3.4 | `reason` | Reason-code registry (0x00–0x0F spec / 0x10–0xFF AxonOS) |
| §4 | `state::apply_frame` | Exhaustive 3×3 |
| §5.1 | `engine::process_raw` | Single entry point |
| §6.1 | `engine::allows_cognitive_frames` | `false` for SUSPENDED / WITHDRAWN |
| §6.4 | `state::to_gossip_bits` | 2-bit state propagation |
| §7 | `codec::cbor` / `codec::json` | CBOR wire format, forward-compatible |
| §7.2 | `Error` | Status `2002 CONSENT_WITHDRAWN` |
| §8 | `stim_guard` | `DacGate`, < 1 µs |
| §10 | `invariants` | MUST → violation, SHOULD → warning |
| §11 | `engine` (peer) | `consent-withdraw` → peer DISCONNECTED on the mesh |

---

## Reason codes — SPEC §3.4

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

Codes `0x00–0x0F` are reserved by the specification; `0x10–0xFF` are AxonOS extensions.

---

## Crate structure

```text
src/
├── lib.rs           # crate root, protocol version, spec mapping
├── state.rs         # ConsentState + apply_frame (exhaustive 3×3)
├── engine.rs        # ConsentEngine, process_raw, process_frame
├── frames.rs        # Frame types, ReasonBuf (zero-alloc)
├── reason.rs        # ReasonCode registry (§3.4)
├── invariants.rs    # MUST/SHOULD/MAY (§10), check_transition
├── error.rs         # Layered error taxonomy (L1–L4)
├── stim_guard.rs    # DacGate trait, timing contract (§8)
└── codec/
    ├── cbor.rs      # Bounded encoder/decoder, security-hardened (§7, §9)
    └── json.rs      # JSON codec (feature-gated: alloc + std)
tests/
├── consent_interop.rs    # 60+ tests
└── vectors/              # canonical interop vectors (frozen)
fuzz/
└── fuzz_targets/         # cargo-fuzz: decode + roundtrip
```

---

## Testing

```bash
cargo test                  # no_std: CBOR, state machine, engine, invariants
cargo test --features json  # + JSON round-trip vectors
cargo +nightly fuzz run fuzz_cbor_decode
cargo +nightly fuzz run fuzz_cbor_roundtrip
```

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

**The AxonOS Project** · [axonos.org](https://axonos.org) · connect@axonos.org · security@axonos.org
[medium.com/@AxonOS](https://medium.com/@AxonOS) · [github.com/AxonOS-org](https://github.com/AxonOS-org)
Singapore · Zurich · Berlin · Milano · San Mateo

</div>
