// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! # axonos-consent
//!
//! MMP Consent Extension v0.1.0 — reference implementation.
//! Aligned with MMP v0.2.2 (Section 16.4).
//!
//! Spec: <https://sym.bot/spec/mmp-consent>
//! Protocol version: `CONSENT_PROTOCOL_VERSION = 1`
//!
//! ## Single entry point
//!
//! ```rust,no_run
//! use axonos_consent::ConsentEngine;
//!
//! let mut engine = ConsentEngine::new();
//! let peer_id = [0u8; 16];
//! engine.register_peer(peer_id, 0).unwrap();
//! // Full pipeline: engine.process_raw(&peer_id, &cbor_bytes, now_us)
//! ```
//!
//! This is the **only** function external code should call. It executes:
//! 1. CBOR decode (bounded, security-hardened)
//! 2. Invariant check (MUST violations → reject, SHOULD → warn)
//! 3. State transition (exhaustive 3×3 table, no wildcards)
//! 4. StimGuard callback (if withdrawal + feature enabled)
//!
//! ## Spec-to-code mapping
//!
//! | Spec § | Module | Purpose |
//! |--------|--------|---------|
//! | Consent §3   | `frames` | ConsentWithdraw/Suspend/Resume |
//! | Consent §3.4 | `reason` | ReasonCode registry |
//! | Consent §4   | `state`  | ConsentState + `apply_frame()` (exhaustive) |
//! | Consent §5.1 | `engine` | ConsentEngine + `process_raw()` |
//! | Consent §6.1 | `engine::allows_cognitive_frames` | Frame gating |
//! | Consent §6.4 | `state::to_gossip_bits` | 2-bit encoding |
//! | Consent §8   | `stim_guard` | DAC gate + timing contract |
//! | Consent §10  | `invariants` | MUST/SHOULD/MAY enforcement |
//! | MMP §7       | `codec::cbor` / `codec::json` | Frame registry (Section 7 forward compat) |
//! | MMP §7.2     | Error code 2002 CONSENT_WITHDRAWN |
//! | MMP §3.5     | Connection state machine: consent-withdraw triggers DISCONNECTED |
//! | MMP §16.4    | Published extension: `consent-v0.1.0` |

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Protocol version. Wire-encoded in future handshake extensions.
pub const CONSENT_PROTOCOL_VERSION: u8 = 1;

pub mod state;
pub mod engine;
pub mod frames;
pub mod reason;
pub mod codec;
pub mod invariants;
pub mod error;

#[cfg(feature = "stim-guard")]
pub mod stim_guard;

pub use state::ConsentState;
pub use engine::ConsentEngine;
pub use frames::{ConsentFrame, Scope};
pub use reason::ReasonCode;
pub use error::Error;
