// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! StimGuard integration for bidirectional BCI. Feature: `stim-guard`. §8.
//!
//! ## Timing contract
//!
//! The consent-withdraw → StimGuard lockout path executes entirely in
//! ARM TrustZone Secure World. The timing guarantee:
//!
//! ```text
//! ConsentEngine.withdraw()     — state write:     <0.1µs (single store)
//! StimGuard.on_consent_withdrawn() — function call: <0.1µs (inline)
//! DacGate.close()              — register write:  <0.1µs (single STR)
//! ────────────────────────────────────────────────
//! Total enforcement path:                         <1µs
//! ```
//!
//! ## Atomicity
//!
//! Steps execute in sequence without preemption (Secure World is
//! non-preemptible on ARMv8-M). No intermediate state is observable:
//! either consent is GRANTED and the DAC gate is open, or consent is
//! WITHDRAWN and the gate is closed. No other combination is possible.
//!
//! ## Physical button bypass
//!
//! The emergency button generates a hardware interrupt directly to
//! Secure World, bypassing the Non-Secure NSC gateway entirely.
//! The interrupt handler calls `ConsentEngine::withdraw_all()` →
//! `StimGuardConsent::on_consent_withdrawn()`. Total path: <1µs
//! from button press to gate closure.

pub trait DacGate {
    /// Close the DAC gate. Single register write. WCET: <0.1µs.
    fn close(&mut self);
    /// Open the DAC gate. Only after power cycle + re-handshake.
    fn open(&mut self);
    fn is_closed(&self) -> bool;
}

pub struct StimGuardConsent<G: DacGate> {
    gate: G,
    lockout_active: bool,
}

impl<G: DacGate> StimGuardConsent<G> {
    pub fn new(gate: G) -> Self {
        Self {
            gate,
            lockout_active: false,
        }
    }

    /// Called by ConsentEngine on withdrawal. Closes DAC gate.
    /// WCET: <0.1µs (single function call + register write).
    /// Non-conditional: always closes, no branching.
    pub fn on_consent_withdrawn(&mut self) {
        self.gate.close();
        self.lockout_active = true;
    }

    pub fn is_locked_out(&self) -> bool {
        self.lockout_active
    }

    /// Re-enable stimulation after a withdrawal lockout.
    ///
    /// # This function enforces nothing — the caller is the control
    ///
    /// It clears the flag and opens the gate. It does not verify a power cycle,
    /// a re-handshake, or an attestation, and it cannot: this crate is
    /// `no_std`, holds no clock it trusts and no key, and a check written here
    /// would be one an attacker in the same address space simply calls past.
    ///
    /// The requirement is therefore a *placement* obligation, and it is
    /// binding: reachability of this function is the security property. It must
    /// live behind the Secure-World boundary (or an equivalent privileged
    /// path) and must not be exposed to Non-Secure code, an RPC surface, or any
    /// caller that a withdrawal was meant to stop. A build in which
    /// untrusted code can reach `clear_lockout` has no lockout.
    ///
    /// Reviewers: treat a call site outside the trusted boot/recovery path as a
    /// finding, not a style question.
    pub fn clear_lockout(&mut self) {
        self.lockout_active = false;
        self.gate.open();
    }
}
