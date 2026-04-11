// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Formal invariants per MMP Consent Extension v0.1.0, §10 Conformance.
//!
//! Each invariant corresponds to a spec requirement with RFC 2119 keywords:
//! - MUST: violation = `InvariantViolation` (hard reject)
//! - SHOULD: violation = `InvariantWarning` (log, continue)
//! - MAY: no enforcement (optional fields)
//!
//! ## Determinism guarantee
//!
//! `check_frame()` executes in O(1) — fixed number of field checks.
//! No loops, no recursion, no allocation. WCET: <0.5µs on Cortex-M4F.

use crate::frames::*;
use crate::state::ConsentState;

// ═══════════════════════════════════════════════════════════════════
//  INVARIANT RESULTS
// ═══════════════════════════════════════════════════════════════════

/// Hard violation — frame MUST be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantViolation {
    /// §3.1: consent-withdraw MUST have scope.
    WithdrawMissingScope,
    /// §4: WITHDRAWN is terminal. No transitions from WITHDRAWN.
    TransitionFromWithdrawn,
    /// §3.1: timestamp_us MUST be positive if present.
    ZeroTimestampUs,
    /// §3.1: timestamp MUST be positive if present.
    ZeroTimestampMs,
    /// Local: reason exceeds MAX_REASON_LEN.
    ReasonTooLong,
}

/// Soft warning — frame is valid but suboptimal per spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantWarning {
    /// §3.1: consent-withdraw SHOULD have timestamp or timestamp_us.
    WithdrawMissingTimestamp,
    /// §3.2: consent-suspend SHOULD have reasonCode.
    SuspendMissingReasonCode,
    /// §3.1: consent-withdraw SHOULD have reasonCode for audit trail.
    WithdrawMissingReasonCode,
}

/// Combined check result.
#[derive(Debug)]
pub struct InvariantResult {
    pub violations: [Option<InvariantViolation>; 4],
    pub violation_count: u8,
    pub warnings: [Option<InvariantWarning>; 4],
    pub warning_count: u8,
}

impl InvariantResult {
    const fn empty() -> Self {
        Self {
            violations: [None; 4], violation_count: 0,
            warnings: [None; 4], warning_count: 0,
        }
    }

    fn add_violation(&mut self, v: InvariantViolation) {
        if (self.violation_count as usize) < self.violations.len() {
            self.violations[self.violation_count as usize] = Some(v);
            self.violation_count += 1;
        }
    }

    fn add_warning(&mut self, w: InvariantWarning) {
        if (self.warning_count as usize) < self.warnings.len() {
            self.warnings[self.warning_count as usize] = Some(w);
            self.warning_count += 1;
        }
    }

    /// True if no MUST violations. Warnings are acceptable.
    pub fn is_valid(&self) -> bool { self.violation_count == 0 }

    /// True if there are SHOULD warnings.
    pub fn has_warnings(&self) -> bool { self.warning_count > 0 }
}

// ═══════════════════════════════════════════════════════════════════
//  FRAME INVARIANT CHECK
// ═══════════════════════════════════════════════════════════════════

/// Check all invariants for a decoded frame. O(1), no allocation.
///
/// ```text
/// consent-withdraw:
///   MUST  scope ∈ {"peer", "all"}         (enforced by Scope enum)
///   SHOULD timestamp OR timestamp_us      (warning if neither)
///   SHOULD reasonCode                     (warning if absent)
///   MAY   reason                          (no enforcement)
///   MAY   epoch                           (no enforcement)
///
/// consent-suspend:
///   SHOULD reasonCode                     (warning if absent)
///   MAY   reason, timestamp               (no enforcement)
///
/// consent-resume:
///   MAY   timestamp                       (no enforcement)
/// ```
pub fn check_frame(frame: &ConsentFrame) -> InvariantResult {
    let mut r = InvariantResult::empty();

    match frame {
        ConsentFrame::Withdraw(w) => {
            // MUST: scope is enforced by type system (non-optional Scope enum)

            // MUST: timestamps positive if present
            if let Some(0) = w.timestamp_ms {
                r.add_violation(InvariantViolation::ZeroTimestampMs);
            }
            if let Some(0) = w.timestamp_us {
                r.add_violation(InvariantViolation::ZeroTimestampUs);
            }

            // MUST: reason length bounded
            if let Some(reason) = &w.reason {
                if reason.len() > MAX_REASON_LEN {
                    r.add_violation(InvariantViolation::ReasonTooLong);
                }
            }

            // SHOULD: at least one timestamp
            if w.timestamp_ms.is_none() && w.timestamp_us.is_none() {
                r.add_warning(InvariantWarning::WithdrawMissingTimestamp);
            }

            // SHOULD: reasonCode for audit
            if w.reason_code.is_none() {
                r.add_warning(InvariantWarning::WithdrawMissingReasonCode);
            }
        }

        ConsentFrame::Suspend(s) => {
            if let Some(0) = s.timestamp_ms {
                r.add_violation(InvariantViolation::ZeroTimestampMs);
            }
            if let Some(0) = s.timestamp_us {
                r.add_violation(InvariantViolation::ZeroTimestampUs);
            }
            if let Some(reason) = &s.reason {
                if reason.len() > MAX_REASON_LEN {
                    r.add_violation(InvariantViolation::ReasonTooLong);
                }
            }

            // SHOULD: reasonCode
            if s.reason_code.is_none() {
                r.add_warning(InvariantWarning::SuspendMissingReasonCode);
            }
        }

        ConsentFrame::Resume(re) => {
            if let Some(0) = re.timestamp_ms {
                r.add_violation(InvariantViolation::ZeroTimestampMs);
            }
            if let Some(0) = re.timestamp_us {
                r.add_violation(InvariantViolation::ZeroTimestampUs);
            }
            // MAY: no required fields beyond type
        }
    }

    r
}

// ═══════════════════════════════════════════════════════════════════
//  STATE TRANSITION GUARD
// ═══════════════════════════════════════════════════════════════════

/// Validate that a state transition is legal. Delegates to `ConsentState::apply_frame()`.
///
/// Returns the target state if valid, or `TransitionFromWithdrawn` if rejected.
pub fn check_transition(
    current: ConsentState,
    frame: &ConsentFrame,
) -> Result<ConsentState, InvariantViolation> {
    current.apply_frame(frame)
        .map_err(|_| InvariantViolation::TransitionFromWithdrawn)
}
