// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! CBOR codec — security-bounded, zero-alloc. MMP §7 wire format.
//!
//! ## Supported CBOR major types (RFC 8949)
//!
//! | Major | Type | Used | Handling |
//! |-------|------|------|----------|
//! | 0 | Unsigned int | ✓ | reasonCode, epoch, timestamps |
//! | 1 | Negative int | ✗ | **Rejected** (consent frames use only unsigned) |
//! | 2 | Byte string | ✗ | **Rejected** (all strings are text) |
//! | 3 | Text string | ✓ | type, scope, reason |
//! | 4 | Array | ✗ | **Rejected** (consent frames use only maps) |
//! | 5 | Map | ✓ | Top-level frame structure |
//! | 6 | Tag | ✗ | **Rejected** (no tagged values in consent) |
//! | 7 | Simple/float | ✗ | **Rejected** (no booleans or floats) |
//!
//! ## Security bounds
//!
//! - `MAX_MAP_FIELDS = 8`: consent frames have ≤7 fields
//! - `MAX_STRING_LEN = 128`: bounds all text strings
//! - `MAX_NESTING = 4`: prevents recursive structure attacks
//! - Duplicate key detection: bitmask over 7 known keys
//!
//! ## WCET analysis
//!
//! Decoder: O(n) where n ≤ MAX_MAP_FIELDS = 8.
//! Each field: 1 key read + 1 value read = O(1).
//! Total: ≤ 8 × 2 = 16 CBOR item reads, each O(1).
//! Measured WCET target: <10µs on Cortex-M4F @ 168 MHz.
//!
//! Encoder: O(n) where n = number of present optional fields, ≤ 7.
//! Each field: key write + value write. No loops beyond field count.

use crate::frames::*;
use crate::reason::ReasonCode;

// ═══════════════════════════════════════════════════════════════════
//  SECURITY LIMITS
// ═══════════════════════════════════════════════════════════════════

pub const MAX_MAP_FIELDS: u64 = 8; // §3: max 7 fields + margin
pub const MAX_STRING_LEN: usize = 128;
const MAX_NESTING: u8 = 4;

// ═══════════════════════════════════════════════════════════════════
//  ERRORS
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof,
    InvalidCbor,
    /// CBOR major type not supported by consent protocol.
    /// Consent uses only: 0 (uint), 3 (text), 5 (map).
    UnsupportedMajorType(u8),
    ExpectedMap,
    ExpectedText,
    MissingTypeField, // §3: "type" MUST be present
    UnknownFrameType,
    MissingScopeField, // §3.1: scope MUST be present for withdraw
    UnknownScope,
    MapTooLarge,
    StringTooLong,
    NestingTooDeep,
    DuplicateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// Output buffer too small for the encoded frame.
    BufferTooSmall,
}

// ═══════════════════════════════════════════════════════════════════
//  ENCODER — zero-alloc, writes to caller buffer, returns Result
// ═══════════════════════════════════════════════════════════════════

pub const MAX_ENCODED_SIZE: usize = 256;

/// Encode a ConsentFrame. Returns bytes written or BufferTooSmall.
pub fn encode(frame: &ConsentFrame, out: &mut [u8]) -> Result<usize, EncodeError> {
    let mut w = Writer { buf: out, pos: 0 };

    match frame {
        ConsentFrame::Withdraw(f) => {
            // §3.1: consent-withdraw frame
            let n = 2
                + f.reason_code.is_some() as u64
                + f.reason.is_some() as u64
                + f.epoch.is_some() as u64
                + f.timestamp_ms.is_some() as u64
                + f.timestamp_us.is_some() as u64;
            w.map(n)?;
            w.text("type")?;
            w.text("consent-withdraw")?;
            w.text("scope")?;
            w.text(f.scope.as_str())?; // §3.1: MUST
                                       // §3.4
            if let Some(rc) = f.reason_code {
                w.text("reasonCode")?;
                w.uint(rc.to_u8() as u64)?;
            }
            if let Some(r) = &f.reason {
                w.text("reason")?;
                w.text(r.as_str())?;
            }
            if let Some(e) = f.epoch {
                w.text("epoch")?;
                w.uint(e)?;
            }
            if let Some(t) = f.timestamp_ms {
                w.text("timestamp")?;
                w.uint(t)?;
            }
            if let Some(t) = f.timestamp_us {
                w.text("timestamp_us")?;
                w.uint(t)?;
            }
        }
        ConsentFrame::Suspend(f) => {
            // §3.2: consent-suspend frame
            let n = 1
                + f.reason_code.is_some() as u64
                + f.reason.is_some() as u64
                + f.timestamp_ms.is_some() as u64
                + f.timestamp_us.is_some() as u64;
            w.map(n)?;
            w.text("type")?;
            w.text("consent-suspend")?;
            if let Some(rc) = f.reason_code {
                w.text("reasonCode")?;
                w.uint(rc.to_u8() as u64)?;
            }
            if let Some(r) = &f.reason {
                w.text("reason")?;
                w.text(r.as_str())?;
            }
            if let Some(t) = f.timestamp_ms {
                w.text("timestamp")?;
                w.uint(t)?;
            }
            if let Some(t) = f.timestamp_us {
                w.text("timestamp_us")?;
                w.uint(t)?;
            }
        }
        ConsentFrame::Resume(f) => {
            // §3.3: consent-resume frame
            let n = 1 + f.timestamp_ms.is_some() as u64 + f.timestamp_us.is_some() as u64;
            w.map(n)?;
            w.text("type")?;
            w.text("consent-resume")?;
            if let Some(t) = f.timestamp_ms {
                w.text("timestamp")?;
                w.uint(t)?;
            }
            if let Some(t) = f.timestamp_us {
                w.text("timestamp_us")?;
                w.uint(t)?;
            }
        }
    }
    Ok(w.pos)
}

// ═══════════════════════════════════════════════════════════════════
//  DECODER — bounded, duplicate-safe, explicit type rejection
// ═══════════════════════════════════════════════════════════════════

/// Decode a ConsentFrame from CBOR bytes. Security-bounded.
///
/// ## Key-to-bit mapping for duplicate detection
///
/// ```text
/// bit 0 (0x01) = "type"          §3
/// bit 1 (0x02) = "scope"         §3.1
/// bit 2 (0x04) = "reasonCode"    §3.4
/// bit 3 (0x08) = "reason"        §3.1
/// bit 4 (0x10) = "epoch"         §3.1
/// bit 5 (0x20) = "timestamp"     §3.1
/// bit 6 (0x40) = "timestamp_us"  §3.1 (AxonOS extension)
/// ```
pub fn decode(data: &[u8]) -> Result<ConsentFrame, DecodeError> {
    let mut c = Cursor { data, pos: 0 };

    let map_len = c.read_map_len()?;
    if map_len > MAX_MAP_FIELDS {
        return Err(DecodeError::MapTooLarge);
    }

    // Duplicate key bitmask (see docstring above)
    let mut seen: u8 = 0;

    let mut frame_type: Option<FrameType> = None;
    let mut scope: Option<Scope> = None;
    let mut reason_code: Option<ReasonCode> = None;
    let mut reason: Option<ReasonBuf> = None;
    let mut epoch: Option<u64> = None;
    let mut timestamp_ms: Option<u64> = None;
    let mut timestamp_us: Option<u64> = None;

    for _ in 0..map_len {
        let key = c.read_text_bounded()?;

        // bit 0 = type
        match key {
            "type" => {
                if seen & 0x01 != 0 {
                    return Err(DecodeError::DuplicateKey);
                }
                seen |= 0x01;
                frame_type = Some(match c.read_text_bounded()? {
                    "consent-withdraw" => FrameType::Withdraw,
                    "consent-suspend" => FrameType::Suspend,
                    "consent-resume" => FrameType::Resume,
                    _ => return Err(DecodeError::UnknownFrameType),
                });
            }
            // bit 1 = scope
            "scope" => {
                if seen & 0x02 != 0 {
                    return Err(DecodeError::DuplicateKey);
                }
                seen |= 0x02;
                let s = c.read_text_bounded()?;
                scope = Some(Scope::parse(s).ok_or(DecodeError::UnknownScope)?);
            }
            // bit 2 = reasonCode
            "reasonCode" => {
                if seen & 0x04 != 0 {
                    return Err(DecodeError::DuplicateKey);
                }
                seen |= 0x04;
                reason_code = Some(ReasonCode::from_u8(c.read_uint()? as u8));
            }
            // bit 3 = reason
            "reason" => {
                if seen & 0x08 != 0 {
                    return Err(DecodeError::DuplicateKey);
                }
                seen |= 0x08;
                reason = Some(ReasonBuf::new(c.read_text_bounded()?));
            }
            // bit 4 = epoch
            "epoch" => {
                if seen & 0x10 != 0 {
                    return Err(DecodeError::DuplicateKey);
                }
                seen |= 0x10;
                epoch = Some(c.read_uint()?);
            }
            // bit 5 = timestamp
            "timestamp" => {
                if seen & 0x20 != 0 {
                    return Err(DecodeError::DuplicateKey);
                }
                seen |= 0x20;
                timestamp_ms = Some(c.read_uint()?);
            }
            // bit 6 = timestamp_us
            "timestamp_us" => {
                if seen & 0x40 != 0 {
                    return Err(DecodeError::DuplicateKey);
                }
                seen |= 0x40;
                timestamp_us = Some(c.read_uint()?);
            }
            // §7: unknown keys skipped (forward-compat)
            _ => {
                c.skip_value(0)?;
            }
        }
    }

    // §3: "type" MUST be present
    let ft = frame_type.ok_or(DecodeError::MissingTypeField)?;
    match ft {
        FrameType::Withdraw => {
            let s = scope.ok_or(DecodeError::MissingScopeField)?; // §3.1: MUST
            Ok(ConsentFrame::Withdraw(ConsentWithdraw {
                scope: s,
                reason_code,
                reason,
                epoch,
                timestamp_ms,
                timestamp_us,
            }))
        }
        FrameType::Suspend => Ok(ConsentFrame::Suspend(ConsentSuspend {
            reason_code,
            reason,
            timestamp_ms,
            timestamp_us,
        })),
        FrameType::Resume => Ok(ConsentFrame::Resume(ConsentResume {
            timestamp_ms,
            timestamp_us,
        })),
    }
}

#[derive(Clone, Copy)]
enum FrameType {
    Withdraw,
    Suspend,
    Resume,
}

// ═══════════════════════════════════════════════════════════════════
//  CBOR PRIMITIVES — with explicit major type rejection
// ═══════════════════════════════════════════════════════════════════

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn put(&mut self, b: u8) -> Result<(), EncodeError> {
        if self.pos >= self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        self.buf[self.pos] = b;
        self.pos += 1;
        Ok(())
    }
    fn put_slice(&mut self, s: &[u8]) -> Result<(), EncodeError> {
        if self.pos + s.len() > self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        self.buf[self.pos..self.pos + s.len()].copy_from_slice(s);
        self.pos += s.len();
        Ok(())
    }
    fn type_val(&mut self, major: u8, v: u64) -> Result<(), EncodeError> {
        let mt = major << 5;
        if v < 24 {
            self.put(mt | v as u8)
        } else if v <= 0xFF {
            self.put(mt | 24)?;
            self.put(v as u8)
        } else if v <= 0xFFFF {
            self.put(mt | 25)?;
            self.put_slice(&(v as u16).to_be_bytes())
        } else if v <= 0xFFFF_FFFF {
            self.put(mt | 26)?;
            self.put_slice(&(v as u32).to_be_bytes())
        } else {
            self.put(mt | 27)?;
            self.put_slice(&v.to_be_bytes())
        }
    }
    fn map(&mut self, n: u64) -> Result<(), EncodeError> {
        self.type_val(5, n)
    }
    fn text(&mut self, s: &str) -> Result<(), EncodeError> {
        self.type_val(3, s.len() as u64)?;
        self.put_slice(s.as_bytes())
    }
    fn uint(&mut self, v: u64) -> Result<(), EncodeError> {
        self.type_val(0, v)
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }
    fn advance(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.data.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn argument(&mut self, ai: u8) -> Result<u64, DecodeError> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => Ok(self.byte()? as u64),
            25 => {
                let b = self.advance(2)?;
                Ok(u16::from_be_bytes([b[0], b[1]]) as u64)
            }
            26 => {
                let b = self.advance(4)?;
                Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            27 => {
                let b = self.advance(8)?;
                Ok(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            _ => Err(DecodeError::InvalidCbor),
        }
    }

    fn read_uint(&mut self) -> Result<u64, DecodeError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        if major != 0 {
            return Err(DecodeError::UnsupportedMajorType(major));
        }
        self.argument(ib & 0x1F)
    }

    fn read_text_bounded(&mut self) -> Result<&'a str, DecodeError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        if major != 3 {
            return Err(DecodeError::ExpectedText);
        }
        let len = self.argument(ib & 0x1F)? as usize;
        if len > MAX_STRING_LEN {
            return Err(DecodeError::StringTooLong);
        }
        core::str::from_utf8(self.advance(len)?).map_err(|_| DecodeError::InvalidCbor)
    }

    fn read_map_len(&mut self) -> Result<u64, DecodeError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        if major != 5 {
            return Err(DecodeError::ExpectedMap);
        }
        self.argument(ib & 0x1F)
    }

    /// Skip one CBOR value. **Explicitly rejects unsupported major types.**
    fn skip_value(&mut self, depth: u8) -> Result<(), DecodeError> {
        if depth > MAX_NESTING {
            return Err(DecodeError::NestingTooDeep);
        }
        let ib = self.byte()?;
        let major = ib >> 5;
        let arg = self.argument(ib & 0x1F)?;
        match major {
            0 => {} // unsigned int — consumed
            3 => {
                // text string
                if arg as usize > MAX_STRING_LEN {
                    return Err(DecodeError::StringTooLong);
                }
                self.advance(arg as usize)?;
            }
            5 => {
                // map
                if arg > MAX_MAP_FIELDS {
                    return Err(DecodeError::MapTooLarge);
                }
                for _ in 0..arg {
                    self.skip_value(depth + 1)?;
                    self.skip_value(depth + 1)?;
                }
            }
            // Explicitly reject all unsupported types
            1 => return Err(DecodeError::UnsupportedMajorType(1)), // negative int
            2 => return Err(DecodeError::UnsupportedMajorType(2)), // byte string
            4 => return Err(DecodeError::UnsupportedMajorType(4)), // array
            6 => return Err(DecodeError::UnsupportedMajorType(6)), // tag
            7 => return Err(DecodeError::UnsupportedMajorType(7)), // simple/float
            _ => return Err(DecodeError::InvalidCbor),
        }
        Ok(())
    }
}
