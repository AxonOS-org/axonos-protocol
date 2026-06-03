// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! JSON codec for relay boundary. Feature-gated: requires `json` (implies `alloc` + `std`).

#[cfg(feature = "json")]
use crate::frames::*;
#[cfg(feature = "json")]
use crate::reason::ReasonCode;

#[cfg(feature = "json")]
pub fn decode_value(v: &serde_json::Value) -> Result<ConsentFrame, &'static str> {
    let obj = v.as_object().ok_or("expected JSON object")?;
    let ft = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("missing type")?;
    let rc = obj
        .get("reasonCode")
        .and_then(|v| v.as_u64())
        .map(|v| ReasonCode::from_u8(v as u8));
    let reason = obj
        .get("reason")
        .and_then(|v| v.as_str())
        .map(ReasonBuf::new);
    let ts_ms = obj.get("timestamp").and_then(|v| v.as_u64());
    let ts_us = obj.get("timestamp_us").and_then(|v| v.as_u64());

    match ft {
        "consent-withdraw" => {
            let scope = Scope::parse(
                obj.get("scope")
                    .and_then(|v| v.as_str())
                    .ok_or("missing scope")?,
            )
            .ok_or("unknown scope")?;
            let epoch = obj.get("epoch").and_then(|v| v.as_u64());
            Ok(ConsentFrame::Withdraw(ConsentWithdraw {
                scope,
                reason_code: rc,
                reason,
                epoch,
                timestamp_ms: ts_ms,
                timestamp_us: ts_us,
            }))
        }
        "consent-suspend" => Ok(ConsentFrame::Suspend(ConsentSuspend {
            reason_code: rc,
            reason,
            timestamp_ms: ts_ms,
            timestamp_us: ts_us,
        })),
        "consent-resume" => Ok(ConsentFrame::Resume(ConsentResume {
            timestamp_ms: ts_ms,
            timestamp_us: ts_us,
        })),
        _ => Err("unknown frame type"),
    }
}

#[cfg(feature = "json")]
pub fn encode_value(frame: &ConsentFrame) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    match frame {
        ConsentFrame::Withdraw(f) => {
            m.insert("type".into(), "consent-withdraw".into());
            m.insert("scope".into(), f.scope.as_str().into());
            if let Some(rc) = f.reason_code {
                m.insert("reasonCode".into(), (rc.to_u8() as u64).into());
            }
            if let Some(r) = &f.reason {
                m.insert("reason".into(), r.as_str().into());
            }
            if let Some(e) = f.epoch {
                m.insert("epoch".into(), e.into());
            }
            if let Some(t) = f.timestamp_ms {
                m.insert("timestamp".into(), t.into());
            }
            if let Some(t) = f.timestamp_us {
                m.insert("timestamp_us".into(), t.into());
            }
        }
        ConsentFrame::Suspend(f) => {
            m.insert("type".into(), "consent-suspend".into());
            if let Some(rc) = f.reason_code {
                m.insert("reasonCode".into(), (rc.to_u8() as u64).into());
            }
            if let Some(r) = &f.reason {
                m.insert("reason".into(), r.as_str().into());
            }
            if let Some(t) = f.timestamp_ms {
                m.insert("timestamp".into(), t.into());
            }
            if let Some(t) = f.timestamp_us {
                m.insert("timestamp_us".into(), t.into());
            }
        }
        ConsentFrame::Resume(f) => {
            m.insert("type".into(), "consent-resume".into());
            if let Some(t) = f.timestamp_ms {
                m.insert("timestamp".into(), t.into());
            }
            if let Some(t) = f.timestamp_us {
                m.insert("timestamp_us".into(), t.into());
            }
        }
    }
    serde_json::Value::Object(m)
}
