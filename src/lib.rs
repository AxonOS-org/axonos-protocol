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
