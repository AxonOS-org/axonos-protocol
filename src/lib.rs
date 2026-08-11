// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Part of the AxonOS Consent Protocol (ACP) reference implementation.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! # axonos-protocol
//!
//! Reference implementation of the **AxonOS Consent Protocol (ACP)**.
//! Specification: `SPEC.md` (revision 0.3).
//! On-wire protocol version: `CONSENT_PROTOCOL_VERSION = 1`.
//!
//! ACP carries a person's consent — grant, suspend, withdraw — across the AxonOS
//! cognitive mesh, enforces it with an exhaustive state machine, and engages a
//! hardware StimGuard on withdrawal. `no_std`, zero-alloc, `forbid(unsafe)`.
//!
//! ## Single entry point
//!
//! ```rust,no_run
//! use axonos_protocol::ConsentEngine;
//!
//! let mut engine = ConsentEngine::new();
//! let peer_id = [0u8; 16];
//! engine.register_peer(peer_id, 0).unwrap();
//! // Full pipeline: engine.process_raw(&peer_id, &cbor_bytes, now_us)
//! ```
//!
//! This is the **only** function external code should call. It executes (SPEC §5.1):
//! 1. CBOR decode (bounded, security-hardened) — SPEC §7, §9
//! 2. Invariant check (MUST → reject, SHOULD → warn) — SPEC §10
//! 3. State transition (exhaustive 3×3, no wildcards) — SPEC §4
//! 4. StimGuard callback (on withdrawal, if feature enabled) — SPEC §8
//!
//! ## Specification mapping
//!
//! | SPEC § | Module | Purpose |
//! |--------|--------|---------|
//! | §3   | `frames` | ConsentWithdraw / Suspend / Resume |
//! | §3.4 | `reason` | ReasonCode registry |
//! | §4   | `state`  | ConsentState + `apply_frame()` (exhaustive) |
//! | §5.1 | `engine` | ConsentEngine + `process_raw()` |
//! | §6.1 | `engine::allows_cognitive_frames` | Frame gating |
//! | §6.4 | `state::to_gossip_bits` | 2-bit state propagation |
//! | §7   | `codec::cbor` / `codec::json` | CBOR wire format (forward-compatible) |
//! | §7.2 | Status code `2002 CONSENT_WITHDRAWN` |
//! | §8   | `stim_guard` | DAC gate + timing contract |
//! | §10  | `invariants` | MUST / SHOULD / MAY enforcement |
//! | §11  | `engine` | consent-withdraw → peer DISCONNECTED on the mesh |

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// On-wire protocol version. See SPEC §12.
pub const CONSENT_PROTOCOL_VERSION: u8 = 1;

/// Specification revision implemented by this crate. See `SPEC.md` and SPEC §12.
pub const SPEC_REVISION: &str = "0.3";

/// Status code signalled to a peer when consent has been withdrawn (SPEC §7.2).
///
/// Transport-level: the mesh binding puts this on the wire when a session ends
/// because consent was withdrawn, so that a peer can distinguish a *withdrawal*
/// from an ordinary disconnect. The distinction matters — a disconnect invites a
/// reconnect, a withdrawal must not.
pub const STATUS_CONSENT_WITHDRAWN: u16 = 2002;

// On `#[non_exhaustive]`, and where it is deliberately absent.
//
// Error and registry enums — `Error`, `DecodeError`, `EncodeError`,
// `InvariantViolation`, `InvariantWarning`, `TransitionError`, `ReasonCode` —
// are `#[non_exhaustive]`. They grow as the implementation learns to reject
// more, and a downstream `match` that breaks on every new rejection reason is
// a maintenance tax with no safety return.
//
// `ConsentState`, `ConsentFrame` and `Scope` are deliberately NOT marked. They
// are fixed by the wire format (§3, §4, §6.4 spends exactly two bits on state),
// and their exhaustiveness is load-bearing: it is what makes a new state a
// compile error rather than a silent `_ =>` arm in someone's consent handler.
// Marking them would buy API flexibility by taking away the guarantee the
// protocol exists to provide. If the wire ever gains a state or a frame type,
// that is a `CONSENT_PROTOCOL_VERSION` bump and every implementor *should* be
// made to look.

// Three version numbers travel together and are deliberately independent:
//
//   crate version  (Cargo.toml, currently 0.9.x) — this implementation
//   SPEC_REVISION  ("0.3")                       — the document it implements
//   CONSENT_PROTOCOL_VERSION (1)                 — the bytes on the wire
//
// The wire version is the only one a peer can observe, and it moves only when
// the encoding changes incompatibly. An implementation may be rewritten many
// times, and the spec revised, without the wire version moving at all — which
// is the point: interoperability is pinned to the format, not to the source.

/// Wire codecs.
///
/// # These functions bypass the pipeline
///
/// [`codec::cbor::decode`] gives back a syntactically valid frame and nothing
/// more. It does **not** run the §10 invariant checks and does **not** apply
/// the §4 state transition — a frame decoded here may carry a zero timestamp,
/// an out-of-registry reason code, or arrive at a peer whose consent is already
/// `WITHDRAWN`.
///
/// [`engine::ConsentEngine::process_raw`] is the single entry point external
/// code should use (SPEC §5.1): it decodes, checks invariants, applies the
/// transition and drives the StimGuard callback, in that order and without a
/// way to skip a step. This module is public because conformance suites, fuzz
/// targets and other-language implementations need the codec on its own — not
/// because decoding by hand is a supported way to consume consent frames.
pub mod codec;
pub mod engine;
pub mod error;
pub mod frames;
pub mod invariants;
pub mod reason;
pub mod state;

#[cfg(feature = "stim-guard")]
pub mod stim_guard;

pub use engine::ConsentEngine;
pub use error::Error;
pub use frames::{ConsentFrame, Scope};
pub use reason::ReasonCode;
pub use state::ConsentState;
