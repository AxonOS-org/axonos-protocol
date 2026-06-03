// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! ConsentEngine — per-peer state machine with mandatory invariant enforcement.
//!
//! §5.1 enforcement sequence. Zero-alloc. Fixed peer table.
//!
//! ## Entry point
//!
//! `process_frame()` is the **single entry point** for all consent frames.
//! It enforces the full validation pipeline:
//!
//! 1. `invariants::check_frame()` — MUST/SHOULD validation
//! 2. `state.apply_frame()` — exhaustive transition check
//! 3. State update + StimGuard callback (if withdrawal)
//!
//! Direct `suspend()/resume()/withdraw()` methods exist for internal use
//! (e.g., emergency button bypass) but skip frame-level validation.

use crate::error::Error;
use crate::frames::ConsentFrame;
use crate::invariants;
use crate::reason::ReasonCode;
use crate::state::{ConsentState, TransitionError};

/// Maximum peers. BLE mesh constraint. §6.4.
pub const MAX_PEERS: usize = 8;

/// Opaque peer identifier (MMP nodeId, UUID v4).
pub type PeerId = [u8; 16];

#[derive(Debug, Clone)]
pub struct PeerConsent {
    pub peer_id: PeerId,
    pub state: ConsentState,
    pub last_reason: Option<ReasonCode>,
    pub last_transition_us: u64,
}

/// Processing result with optional warnings.
#[derive(Debug)]
pub struct ProcessResult {
    pub new_state: ConsentState,
    pub warnings: [Option<invariants::InvariantWarning>; 4],
    pub warning_count: u8,
}

pub struct ConsentEngine {
    peers: [Option<PeerConsent>; MAX_PEERS],
    #[cfg(feature = "stim-guard")]
    on_withdraw: Option<fn(peer_id: &PeerId)>,
}

/// Result of withdraw_all(). Carries withdrawn peer IDs for audit trail.
#[derive(Debug)]
pub struct WithdrawAllResult {
    pub count: usize,
    pub withdrawn_peers: [Option<PeerId>; MAX_PEERS],
}

impl Default for ConsentEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsentEngine {
    pub const fn new() -> Self {
        const NONE: Option<PeerConsent> = None;
        Self {
            peers: [NONE; MAX_PEERS],
            #[cfg(feature = "stim-guard")]
            on_withdraw: None,
        }
    }

    #[cfg(feature = "stim-guard")]
    pub fn set_withdraw_callback(&mut self, cb: fn(peer_id: &PeerId)) {
        self.on_withdraw = Some(cb);
    }

    pub fn register_peer(&mut self, peer_id: PeerId, now_us: u64) -> Result<(), &'static str> {
        if self.find_peer(&peer_id).is_some() {
            return Err("peer already registered");
        }
        for slot in self.peers.iter_mut() {
            if slot.is_none() {
                *slot = Some(PeerConsent {
                    peer_id,
                    state: ConsentState::Granted,
                    last_reason: None,
                    last_transition_us: now_us,
                });
                return Ok(());
            }
        }
        Err("peer table full")
    }

    pub fn get_state(&self, peer_id: &PeerId) -> Option<ConsentState> {
        self.find_peer(peer_id).map(|p| p.state)
    }

    /// **Single entry point from wire.** Decode → validate → transition.
    ///
    /// This is the function external code calls. It executes the full pipeline:
    /// 1. CBOR decode (bounded, security-hardened)
    /// 2. Frame invariant check (MUST violations → reject, SHOULD → warn)
    /// 3. State transition (exhaustive 3×3 table)
    /// 4. StimGuard callback on withdrawal
    ///
    /// No other function needs to be called for incoming consent frames.
    ///
    /// WCET: decode O(n≤8) + invariants O(1) + transition O(1) = O(n≤8). <10µs on M4F.
    pub fn process_raw(
        &mut self,
        peer_id: &PeerId,
        cbor_data: &[u8],
        now_us: u64,
    ) -> Result<ProcessResult, Error> {
        // Step 0: Decode CBOR
        let frame = crate::codec::cbor::decode(cbor_data).map_err(Error::Decode)?;

        // Extract reason_code from frame (if present)
        let reason = match &frame {
            ConsentFrame::Withdraw(w) => w.reason_code,
            ConsentFrame::Suspend(s) => s.reason_code,
            ConsentFrame::Resume(_) => None,
        };

        // Steps 1-4: delegate to process_frame
        self.process_frame(peer_id, &frame, reason, now_us)
    }

    /// Process a pre-decoded consent frame with full validation.
    ///
    /// Pipeline:
    /// 1. Check frame invariants (MUST violations → reject, SHOULD → warn)
    /// 2. Check state transition legality (WITHDRAWN → any = reject)
    /// 3. Apply state transition
    /// 4. Trigger StimGuard on withdrawal (if feature enabled)
    ///
    /// WCET: O(1) — fixed field checks + single state match. <1µs on M4F.
    pub fn process_frame(
        &mut self,
        peer_id: &PeerId,
        frame: &ConsentFrame,
        reason: Option<ReasonCode>,
        now_us: u64,
    ) -> Result<ProcessResult, Error> {
        // Step 1: Frame-level invariant check
        let inv = invariants::check_frame(frame);
        if !inv.is_valid() {
            // Return first violation
            return Err(Error::Invariant(
                inv.violations[0].unwrap(), // safe: violation_count > 0
            ));
        }

        // Step 2: Find peer + check transition legality
        let peer = self
            .find_peer_mut(peer_id)
            .ok_or(Error::Transition(TransitionError::PeerNotFound))?;

        let new_state = peer.state.apply_frame(frame).map_err(Error::Transition)?;

        // Step 3: Apply transition
        peer.state = new_state;
        peer.last_reason = reason;
        peer.last_transition_us = now_us;

        // Step 4: StimGuard callback on withdrawal
        if new_state == ConsentState::Withdrawn {
            #[cfg(feature = "stim-guard")]
            if let Some(cb) = self.on_withdraw {
                cb(peer_id);
            }
        }

        Ok(ProcessResult {
            new_state,
            warnings: inv.warnings,
            warning_count: inv.warning_count,
        })
    }

    // --- Direct methods (bypass frame validation, for internal/emergency use) ---

    pub fn suspend(
        &mut self,
        peer_id: &PeerId,
        reason: Option<ReasonCode>,
        now_us: u64,
    ) -> Result<ConsentState, TransitionError> {
        let peer = self
            .find_peer_mut(peer_id)
            .ok_or(TransitionError::PeerNotFound)?;
        let s = peer.state.suspend()?;
        peer.state = s;
        peer.last_reason = reason;
        peer.last_transition_us = now_us;
        Ok(s)
    }

    pub fn resume(
        &mut self,
        peer_id: &PeerId,
        now_us: u64,
    ) -> Result<ConsentState, TransitionError> {
        let peer = self
            .find_peer_mut(peer_id)
            .ok_or(TransitionError::PeerNotFound)?;
        let s = peer.state.resume()?;
        peer.state = s;
        peer.last_transition_us = now_us;
        Ok(s)
    }

    /// Direct withdrawal. Used by emergency button (bypasses frame validation).
    /// §8: physical button → direct interrupt → this function.
    ///
    /// WCET: state write + optional StimGuard callback. <1µs on M4F.
    pub fn withdraw(
        &mut self,
        peer_id: &PeerId,
        reason: Option<ReasonCode>,
        now_us: u64,
    ) -> Result<ConsentState, TransitionError> {
        let peer = self
            .find_peer_mut(peer_id)
            .ok_or(TransitionError::PeerNotFound)?;
        let s = peer.state.withdraw()?;
        peer.state = s;
        peer.last_reason = reason;
        peer.last_transition_us = now_us;
        #[cfg(feature = "stim-guard")]
        if let Some(cb) = self.on_withdraw {
            cb(peer_id);
        }
        Ok(s)
    }

    pub fn withdraw_all(&mut self, reason: Option<ReasonCode>, now_us: u64) -> WithdrawAllResult {
        let mut result = WithdrawAllResult {
            count: 0,
            withdrawn_peers: [None; MAX_PEERS],
        };
        for peer in self.peers.iter_mut().flatten() {
            if peer.state != ConsentState::Withdrawn {
                peer.state = ConsentState::Withdrawn;
                peer.last_reason = reason;
                peer.last_transition_us = now_us;
                if result.count < MAX_PEERS {
                    result.withdrawn_peers[result.count] = Some(peer.peer_id);
                }
                #[cfg(feature = "stim-guard")]
                if let Some(cb) = self.on_withdraw {
                    cb(&peer.peer_id);
                }
                result.count += 1;
            }
        }
        result
    }

    /// §6.1: check if cognitive frames should be processed for this peer.
    pub fn allows_cognitive_frames(&self, peer_id: &PeerId) -> bool {
        self.find_peer(peer_id)
            .map(|p| p.state.allows_cognitive_frames())
            .unwrap_or(false)
    }

    fn find_peer(&self, id: &PeerId) -> Option<&PeerConsent> {
        self.peers
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|p| &p.peer_id == id)
    }
    fn find_peer_mut(&mut self, id: &PeerId) -> Option<&mut PeerConsent> {
        self.peers
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|p| &p.peer_id == id)
    }
}
