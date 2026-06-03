// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Reason code registry per MMP Consent Extension v0.1.0, Section 3.4.
//! 0x00–0x0F: spec-reserved. 0x10–0xFF: implementation-specific.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReasonCode {
    Unspecified = 0x00,
    UserInitiated = 0x01,
    SafetyViolation = 0x02,
    HardwareFault = 0x03,
    StimGuardLockout = 0x10,
    SessionAttestationFailure = 0x11,
    EmergencyButton = 0x12,
    SwarmFaultDetected = 0x13,
}

impl ReasonCode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::UserInitiated,
            0x02 => Self::SafetyViolation,
            0x03 => Self::HardwareFault,
            0x10 => Self::StimGuardLockout,
            0x11 => Self::SessionAttestationFailure,
            0x12 => Self::EmergencyButton,
            0x13 => Self::SwarmFaultDetected,
            _ => Self::Unspecified,
        }
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn is_spec_reserved(self) -> bool {
        (self as u8) <= 0x0F
    }
    pub fn is_implementation_specific(self) -> bool {
        (self as u8) >= 0x10
    }
}
