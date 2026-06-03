# The AxonOS Consent Protocol (ACP)

**Specification — revision 0.3** · normative · part of the [AxonOS Standard](https://github.com/AxonOS-org/axonos-standard)

The AxonOS Consent Protocol (ACP) is the normative wire protocol by which a person's
consent — *granted, suspended, withdrawn* — propagates across the AxonOS cognitive
mesh and is enforced at every node. It is an AxonOS protocol end to end: the
specification and its reference implementation ([`axonos-protocol`](https://github.com/AxonOS-org/axonos-protocol))
are developed and maintained entirely within the AxonOS project.

This document defines the wire format, the consent state machine, the processing
pipeline, the security bounds, and the conformance criteria. The reference
implementation references this document by section number; the two are a single
contract.

---

## §0 Status and scope

ACP governs **consent as a per-peer state** on the AxonOS mesh. It is a control-plane
protocol: it carries no neural data. It sits beside the kernel-level consent primitive
([`axonos-consent`](https://github.com/AxonOS-org/axonos-consent)) — the kernel owns
the in-process, formally-bounded withdrawal guarantee; ACP makes that consent
**interoperable between independent nodes** on the wire.

- **Wire version.** `CONSENT_PROTOCOL_VERSION = 1`. The wire format is stable; this
  document, revision 0.3, refines its prose and conformance without changing the bytes.
- **Status.** Pre-clinical. ACP is an engineering contract, not a medical device.

## §1 Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in
RFC 2119. A conforming implementation satisfies every MUST in this document; the
conformance vectors (§10) are the executable form of that obligation.

## §2 Model

Each remote peer holds exactly one **consent state** at every node. State changes only
in response to an authenticated consent frame (§3) and only along the transitions of
the state machine (§4). The mesh transport (§11) carries frames between nodes; ACP
defines what the bytes mean and what an implementation MUST do with them.

## §3 Frames

ACP defines three control frames. Each is identified on the wire by a string type
identifier (§7) and carries a minimal, fixed set of fields.

| Frame | Type identifier | Effect |
|:--|:--|:--|
| Withdraw | `consent-withdraw` | Irrevocably ends consent for a scope |
| Suspend | `consent-suspend` | Temporarily pauses consent |
| Resume | `consent-resume` | Restores consent from suspension |

### §3.1 ConsentWithdraw

A `consent-withdraw` frame MUST carry a non-optional `scope`. Withdrawal is terminal
(§4): once a peer reaches WITHDRAWN, no later frame may revive it.

### §3.4 Reason codes

Every frame MAY carry a reason code. Codes `0x00–0x0F` are reserved by this
specification; codes `0x10–0xFF` are AxonOS implementation extensions.

| Code | Name | Range |
|:--|:--|:--|
| `0x00` | UNSPECIFIED | spec |
| `0x01` | USER_INITIATED | spec |
| `0x02` | SAFETY_VIOLATION | spec |
| `0x03` | HARDWARE_FAULT | spec |
| `0x10` | STIMGUARD_LOCKOUT | AxonOS |
| `0x11` | SESSION_ATTESTATION_FAILURE | AxonOS |
| `0x12` | EMERGENCY_BUTTON | AxonOS |
| `0x13` | SWARM_FAULT_DETECTED | AxonOS |

A reason buffer MUST be bounded (the reference implementation fixes it at 64 bytes,
zero-allocation).

## §4 State machine

Consent is a three-state machine. The transition table is total and exhaustive — every
(state, frame) pair has a defined outcome, and there is no wildcard arm.

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

| from \ frame | Withdraw | Suspend | Resume |
|:--|:--|:--|:--|
| **GRANTED** | → WITHDRAWN | → SUSPENDED | → GRANTED *(idempotent)* |
| **SUSPENDED** | → WITHDRAWN | → SUSPENDED *(idempotent)* | → GRANTED |
| **WITHDRAWN** | REJECT | REJECT | REJECT |

An implementation MUST implement the transition as an exhaustive match; introducing a
new state MUST be a compile-time error, not a silent fall-through. Any frame applied to
a WITHDRAWN peer MUST be rejected (§7.2).

## §5 Processing

### §5.1 Single entry point

An implementation MUST expose a single processing entry point that executes the full
pipeline atomically:

```text
process_raw → CBOR decode (bounded, §7/§9) → invariant check (§10) → state transition (§4) → StimGuard (§8)
```

No partial application: a frame that fails any stage MUST NOT mutate peer state, except
the terminal guarantee of §8 on withdrawal.

## §6 Cognitive-frame gating and state propagation

### §6.1 Gating

A node MUST NOT accept cognitive (data-plane) frames from a peer unless that peer's
consent state is GRANTED. SUSPENDED and WITHDRAWN both gate cognitive frames off.

### §6.4 Compact state propagation

For propagation in size-constrained peer-info frames (e.g. a BLE ATT MTU), consent state
MUST be encodable in **2 bits** and decodable without loss. The reference implementation
provides `to_gossip_bits` / `from_gossip_bits` for this mapping.

## §7 Wire format

Frames are encoded as **CBOR**. Frame types are identified by the string identifiers of
§3. A decoder MUST be forward-compatible: an unknown frame type MUST be ignored, not
rejected, so that future frame types do not break existing nodes.

### §7.2 Status codes

A node that receives a frame for a WITHDRAWN peer MUST surface status code
`2002 CONSENT_WITHDRAWN`. This is an AxonOS status code defined by this specification.

## §8 StimGuard binding

On a transition to WITHDRAWN, an implementation that drives stimulation hardware MUST
engage a hardware gate (the `DacGate` contract) that halts output. The reference
implementation specifies a sub-microsecond (< 1 µs) gate engagement as its timing
contract.

## §9 Security bounds

A conforming decoder MUST enforce hard, constant bounds so that a hostile or malformed
frame cannot exhaust memory or stack. The reference implementation fixes:

| Threat | Bound |
|:--|:--|
| Map fields (`MAX_MAP_FIELDS`) | 8 |
| String length (`MAX_STRING_LEN`) | 128 B |
| Nesting depth (`MAX_NESTING_DEPTH`) | 4 |
| Duplicate keys | bitmask detection over 7 keys |
| Unsupported CBOR major types | 1, 2, 4, 6, 7 → explicit reject |
| Output buffer | 256 B → `BufferTooSmall` |

A decoder MUST allocate nothing on the heap in its critical path.

## §10 Conformance

Conformance is defined by the frozen interop vectors in
[`tests/vectors/`](tests/vectors). The vectors are the contract: any change to a vector
file changes the protocol. Invariants are graded — MUST violations are rejections;
SHOULD violations are warnings — per the error taxonomy:

```text
L1 (Wire)    → Decode      — malformed CBOR, bounds, unsupported types
L2 (Struct)  → Invariant   — MUST violations
L3 (State)   → Transition  — WITHDRAWN→any, unknown peer
L4 (System)  → Encode      — buffer too small
```

## §11 Transport binding

ACP frames travel over the AxonOS cognitive mesh ([`axonos-swarm`](https://github.com/AxonOS-org/axonos-swarm)).
Peers are identified by an opaque AxonOS mesh node id (UUID v4). A `consent-withdraw`
MUST drive the affected peer's connection to a DISCONNECTED state at the transport layer;
the control-plane state (§4) and the transport state MUST agree.

## §12 Versioning

- **Wire:** `CONSENT_PROTOCOL_VERSION = 1` — the on-wire format. Stable.
- **Specification:** revision 0.3 — this document.
- **Reference implementation:** the [`axonos-protocol`](https://github.com/AxonOS-org/axonos-protocol)
  crate, v0.3.0.

A change that alters the bytes MUST increment the wire version. A change that refines
prose, bounds, or conformance without altering the bytes increments the specification
revision only.

## §13 References

ACP is one organ of the [AxonOS](https://github.com/AxonOS-org) system and is defined
against AxonOS documents only:

- [`axonos-standard`](https://github.com/AxonOS-org/axonos-standard) — the AxonOS Standard and claims catalogue
- [`axonos-consent`](https://github.com/AxonOS-org/axonos-consent) — the kernel-level consent primitive
- [`axonos-swarm`](https://github.com/AxonOS-org/axonos-swarm) — the cognitive mesh transport
- [`axonos-conformance`](https://github.com/AxonOS-org/axonos-conformance) — byte-exact conformance vectors and codecs

## Evidence discipline

Every quantitative claim in this specification (timing contracts, bounds) is held to the
AxonOS evidence discipline: a bound that is proven is marked proven; a value that is
measured carries its measurement; an unmeasured figure stays publication-pending. See
the [claims catalogue](https://github.com/AxonOS-org/axonos-standard).

---

*The AxonOS Project · axonos.org · connect@axonos.org · security@axonos.org · github.com/AxonOS-org*
