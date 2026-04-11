// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Consent frame types per MMP Consent Extension v0.1.0, Section 3.
//!
//! Frame types use string identifiers per MMP Section 7:
//! `"consent-withdraw"`, `"consent-suspend"`, `"consent-resume"`
//!
//! ## Zero-allocation design
//!
//! The `reason` field uses a fixed-size buffer (`ReasonBuf`) on the critical
//! path. With `feature = "alloc"`, an `alloc::string::String` variant is
//! available for relay boundary use where message size is not bounded.

use crate::reason::ReasonCode;

/// Maximum length of human-readable reason string on the embedded path.
/// 64 bytes covers all spec-defined reason strings with margin.
pub const MAX_REASON_LEN: usize = 64;

/// Fixed-size reason buffer for no_std environments.
#[derive(Clone, PartialEq, Eq)]
pub struct ReasonBuf {
    buf: [u8; MAX_REASON_LEN],
    len: u8,
}

impl ReasonBuf {
    pub const fn empty() -> Self {
        Self { buf: [0u8; MAX_REASON_LEN], len: 0 }
    }

    /// Create from a string slice. Truncates if longer than MAX_REASON_LEN.
    pub fn new(s: &str) -> Self {
        let bytes = s.as_bytes();
        let copy_len = if bytes.len() > MAX_REASON_LEN { MAX_REASON_LEN } else { bytes.len() };
        let mut buf = [0u8; MAX_REASON_LEN];
        let mut i = 0;
        while i < copy_len {
            buf[i] = bytes[i];
            i += 1;
        }
        Self { buf, len: copy_len as u8 }
    }

    pub fn as_str(&self) -> &str {
        // Safety: we only ever write valid UTF-8 from from_str()
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }

    pub fn len(&self) -> usize { self.len as usize }
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

impl core::fmt::Debug for ReasonBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\"{}\"", self.as_str())
    }
}

/// Scope for consent-withdraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Peer,
    All,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self { Scope::Peer => "peer", Scope::All => "all" }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s { "peer" => Some(Scope::Peer), "all" => Some(Scope::All), _ => None }
    }
}

/// Section 3.1: consent-withdraw. Fully no_std, zero-alloc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentWithdraw {
    pub scope: Scope,
    pub reason_code: Option<ReasonCode>,
    pub reason: Option<ReasonBuf>,
    pub epoch: Option<u64>,
    pub timestamp_ms: Option<u64>,
    pub timestamp_us: Option<u64>,
}

/// Section 3.2: consent-suspend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentSuspend {
    pub reason_code: Option<ReasonCode>,
    pub reason: Option<ReasonBuf>,
    pub timestamp_ms: Option<u64>,
    pub timestamp_us: Option<u64>,
}

/// Section 3.3: consent-resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentResume {
    pub timestamp_ms: Option<u64>,
    pub timestamp_us: Option<u64>,
}

/// Unified consent frame enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentFrame {
    Withdraw(ConsentWithdraw),
    Suspend(ConsentSuspend),
    Resume(ConsentResume),
}

impl ConsentFrame {
    /// MMP frame type string identifier (Section 7).
    pub fn type_str(&self) -> &'static str {
        match self {
            ConsentFrame::Withdraw(_) => "consent-withdraw",
            ConsentFrame::Suspend(_) => "consent-suspend",
            ConsentFrame::Resume(_) => "consent-resume",
        }
    }
}
