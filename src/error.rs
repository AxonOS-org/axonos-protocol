// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Unified error taxonomy for axonos-consent.
//!
//! All errors across decode, validation, invariants, engine, and encoding
//! are representable through this type. Zero-alloc, Copy.
//!
//! ## Classification
//!
//! | Category | Severity | Examples |
//! |----------|----------|---------|
//! | Decode | Hard reject | Malformed CBOR, unsupported type |
//! | Validation | Hard reject | Zero timestamp, reason too long |
//! | Invariant | Hard reject (MUST) | WITHDRAWN → RESUME |
//! | Invariant | Soft warning (SHOULD) | Missing timestamp on withdraw |
//! | Engine | Operational | Peer not found, table full |
//! | Encode | Operational | Buffer too small |

use crate::codec::cbor::{DecodeError, EncodeError};
use crate::invariants::InvariantViolation;
use crate::state::TransitionError;

/// Top-level error enum. Every error path in the crate maps here.
///
/// ## Layer hierarchy
///
/// ```text
/// L1 (Wire)    → Decode     — malformed CBOR, bounds, unsupported types
/// L2 (Struct)  → Invariant  — MUST violations (zero timestamp, reason too long)
/// L3 (State)   → Transition — WITHDRAWN→any, peer not found
/// L4 (System)  → Encode     — buffer too small
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Error {
    /// L1: Wire-level decode failure (malformed CBOR, bounds exceeded).
    Decode(DecodeError),
    /// L2: Structural invariant violation (MUST-level, §10).
    Invariant(InvariantViolation),
    /// L3: State machine transition rejected (§4).
    Transition(TransitionError),
    /// L4: Encode buffer too small.
    Encode(EncodeError),
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Error::Decode(e)
    }
}
impl From<InvariantViolation> for Error {
    fn from(e: InvariantViolation) -> Self {
        Error::Invariant(e)
    }
}
impl From<TransitionError> for Error {
    fn from(e: TransitionError) -> Self {
        Error::Transition(e)
    }
}
impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self {
        Error::Encode(e)
    }
}
