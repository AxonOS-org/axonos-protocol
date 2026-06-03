// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Consent state machine per MMP Consent Extension v0.1.0, §4.
//!
//! ## State × Frame transition table (exhaustive)
//!
//! ```text
//! Current    | Withdraw | Suspend   | Resume    |
//! -----------|----------|-----------|-----------|
//! GRANTED    | → WITHDRAWN | → SUSPENDED | → GRANTED (idempotent) |
//! SUSPENDED  | → WITHDRAWN | → SUSPENDED (idempotent) | → GRANTED |
//! WITHDRAWN  | REJECT   | REJECT    | REJECT    |
//! ```
//!
//! Every cell is explicitly handled. No wildcard matches.

use crate::frames::ConsentFrame;

/// Per-peer consent state (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConsentState {
    /// Normal coupling. Cognitive frames flow.
    Granted = 0x00,
    /// Coupling paused. Connection maintained. No cognitive frames.
    Suspended = 0x01,
    /// Terminal. Connection closed. No recovery without new handshake.
    Withdrawn = 0x02,
}

/// Transition error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// WITHDRAWN is terminal (§4). No transitions allowed.
    AlreadyWithdrawn,
    /// Peer not found in engine peer table.
    PeerNotFound,
}

impl ConsentState {
    /// Apply a consent frame to the current state.
    ///
    /// **Formal closure guarantee:** This match is exhaustive over
    /// `ConsentState` × `ConsentFrame` (3 states × 3 frame types = 9 cells).
    /// Every cell is explicitly handled. No wildcard `_` arms exist.
    /// Adding a new state or frame type will produce a compile error.
    pub fn apply_frame(self, frame: &ConsentFrame) -> Result<ConsentState, TransitionError> {
        match (self, frame) {
            // WITHDRAWN is terminal — reject everything
            (Self::Withdrawn, ConsentFrame::Withdraw(_)) => Err(TransitionError::AlreadyWithdrawn),
            (Self::Withdrawn, ConsentFrame::Suspend(_)) => Err(TransitionError::AlreadyWithdrawn),
            (Self::Withdrawn, ConsentFrame::Resume(_)) => Err(TransitionError::AlreadyWithdrawn),

            // GRANTED transitions
            (Self::Granted, ConsentFrame::Withdraw(_)) => Ok(Self::Withdrawn),
            (Self::Granted, ConsentFrame::Suspend(_)) => Ok(Self::Suspended),
            (Self::Granted, ConsentFrame::Resume(_)) => Ok(Self::Granted), // idempotent

            // SUSPENDED transitions
            (Self::Suspended, ConsentFrame::Withdraw(_)) => Ok(Self::Withdrawn),
            (Self::Suspended, ConsentFrame::Suspend(_)) => Ok(Self::Suspended), // idempotent
            (Self::Suspended, ConsentFrame::Resume(_)) => Ok(Self::Granted),
        }
    }

    // --- Convenience methods (delegate to apply_frame semantics) ---

    pub fn suspend(self) -> Result<ConsentState, TransitionError> {
        match self {
            Self::Granted => Ok(Self::Suspended),
            Self::Suspended => Ok(Self::Suspended),
            Self::Withdrawn => Err(TransitionError::AlreadyWithdrawn),
        }
    }

    pub fn resume(self) -> Result<ConsentState, TransitionError> {
        match self {
            Self::Suspended => Ok(Self::Granted),
            Self::Granted => Ok(Self::Granted),
            Self::Withdrawn => Err(TransitionError::AlreadyWithdrawn),
        }
    }

    pub fn withdraw(self) -> Result<ConsentState, TransitionError> {
        match self {
            Self::Granted | Self::Suspended => Ok(Self::Withdrawn),
            Self::Withdrawn => Err(TransitionError::AlreadyWithdrawn),
        }
    }

    /// §6.4: 2-bit gossip encoding.
    pub fn to_gossip_bits(self) -> u8 {
        self as u8
    }

    pub fn from_gossip_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0 => Some(Self::Granted),
            1 => Some(Self::Suspended),
            2 => Some(Self::Withdrawn),
            _ => None,
        }
    }

    /// §6.1: cognitive frames allowed only in GRANTED.
    pub fn allows_cognitive_frames(self) -> bool {
        matches!(self, Self::Granted)
    }
}
