// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Integration tests: round-trip, security bounds, invariants, engine.
//! Run: cargo test --features json

use axonos_consent::*;
use axonos_consent::codec::cbor;
use axonos_consent::frames::*;
use axonos_consent::reason::ReasonCode;
use axonos_consent::state::{ConsentState, TransitionError};
use axonos_consent::engine::{ConsentEngine, MAX_PEERS};
use axonos_consent::invariants;

fn rt(f: &ConsentFrame) {
    let mut buf = [0u8; cbor::MAX_ENCODED_SIZE];
    let n = cbor::encode(f, &mut buf).expect("encode failed");
    let d = cbor::decode(&buf[..n]).expect("decode failed");
    assert_eq!(f, &d, "round-trip failed for {}", f.type_str());
}

// ═══════════════════════════════════════════════════════════════════
//  CBOR ROUND-TRIP
// ═══════════════════════════════════════════════════════════════════

#[test]
fn rt_withdraw_peer() { rt(&ConsentFrame::Withdraw(ConsentWithdraw {
    scope: Scope::Peer, reason_code: Some(ReasonCode::UserInitiated),
    reason: Some(ReasonBuf::new("disconnect")),
    epoch: None, timestamp_ms: Some(1711540800000), timestamp_us: None,
})); }

#[test]
fn rt_withdraw_all() { rt(&ConsentFrame::Withdraw(ConsentWithdraw {
    scope: Scope::All, reason_code: Some(ReasonCode::SafetyViolation),
    reason: None, epoch: Some(48291), timestamp_ms: None, timestamp_us: Some(1711540800000000),
})); }

#[test]
fn rt_withdraw_stimguard() { rt(&ConsentFrame::Withdraw(ConsentWithdraw {
    scope: Scope::Peer, reason_code: Some(ReasonCode::StimGuardLockout),
    reason: Some(ReasonBuf::new("charge violation")),
    epoch: None, timestamp_ms: None, timestamp_us: Some(1711540800123456),
})); }

#[test]
fn rt_suspend_min() { rt(&ConsentFrame::Suspend(ConsentSuspend {
    reason_code: None, reason: None, timestamp_ms: None, timestamp_us: None,
})); }

#[test]
fn rt_resume() { rt(&ConsentFrame::Resume(ConsentResume {
    timestamp_ms: Some(1711540860000), timestamp_us: None,
})); }

#[test]
fn rt_both_ts() { rt(&ConsentFrame::Withdraw(ConsentWithdraw {
    scope: Scope::Peer, reason_code: Some(ReasonCode::UserInitiated), reason: None,
    epoch: None, timestamp_ms: Some(1000), timestamp_us: Some(1000000),
})); }

#[test]
fn rt_emergency() { rt(&ConsentFrame::Withdraw(ConsentWithdraw {
    scope: Scope::All, reason_code: Some(ReasonCode::EmergencyButton),
    reason: Some(ReasonBuf::new("physical button")),
    epoch: None, timestamp_ms: None, timestamp_us: Some(1),
})); }

// ═══════════════════════════════════════════════════════════════════
//  CBOR SECURITY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn sec_rejects_oversized_map() {
    let bad = [0xB4u8]; // map(20)
    assert_eq!(cbor::decode(&bad), Err(cbor::DecodeError::MapTooLarge));
}

#[test]
fn sec_rejects_oversized_string() {
    let mut bad = vec![0xA1u8, 0x78, 200]; // map(1), text(200)
    bad.extend(vec![b'x'; 200]);
    bad.push(0x01);
    assert_eq!(cbor::decode(&bad), Err(cbor::DecodeError::StringTooLong));
}

#[test]
fn sec_rejects_negative_int() {
    // map(1), text(4)"type", negative int(-1) = major 1
    let bad = [0xA1, 0x64, b't', b'y', b'p', b'e', 0x20]; // 0x20 = major 1, value 0
    assert_eq!(cbor::decode(&bad), Err(cbor::DecodeError::ExpectedText));
    // Negative int where uint expected (e.g., in reasonCode value position)
}

#[test]
fn sec_rejects_byte_string_in_skip() {
    // map(2), text(4)"type", text(16)"consent-withdraw", text(3)"foo", bytestring(1)
    let mut bad = vec![0xA2]; // map(2)
    // key "type"
    bad.extend_from_slice(&[0x64, b't', b'y', b'p', b'e']);
    // value "consent-withdraw"
    bad.push(0x70); // text(16)
    bad.extend_from_slice(b"consent-withdraw");
    // key "foo" (unknown, will be skipped)
    bad.extend_from_slice(&[0x63, b'f', b'o', b'o']);
    // value = byte string(1) = major 2 → should be REJECTED
    bad.extend_from_slice(&[0x41, 0x00]); // bytes(1)
    assert_eq!(cbor::decode(&bad), Err(cbor::DecodeError::UnsupportedMajorType(2)));
}

#[test]
fn sec_rejects_duplicate_key() {
    // Craft: map(3), type→withdraw, scope→peer, type→resume (DUPLICATE)
    let mut dup = vec![0xA3]; // map(3)
    dup.extend_from_slice(&[0x64, b't', b'y', b'p', b'e']); // "type"
    dup.push(0x70); dup.extend_from_slice(b"consent-withdraw"); // "consent-withdraw"
    dup.extend_from_slice(&[0x65, b's', b'c', b'o', b'p', b'e']); // "scope"
    dup.extend_from_slice(&[0x64, b'p', b'e', b'e', b'r']); // "peer"
    dup.extend_from_slice(&[0x64, b't', b'y', b'p', b'e']); // "type" AGAIN
    dup.push(0x6E); dup.extend_from_slice(b"consent-resume"); // "consent-resume"
    assert_eq!(cbor::decode(&dup), Err(cbor::DecodeError::DuplicateKey));
}

#[test]
fn sec_empty_input() {
    assert_eq!(cbor::decode(&[]), Err(cbor::DecodeError::UnexpectedEof));
}

// ═══════════════════════════════════════════════════════════════════
//  BUFFER OVERFLOW PROTECTION
// ═══════════════════════════════════════════════════════════════════

#[test]
fn enc_buffer_too_small() {
    let f = ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer, reason_code: Some(ReasonCode::UserInitiated),
        reason: Some(ReasonBuf::new("test")),
        epoch: None, timestamp_ms: Some(1000), timestamp_us: None,
    });
    let mut tiny = [0u8; 4]; // way too small
    assert_eq!(cbor::encode(&f, &mut tiny), Err(cbor::EncodeError::BufferTooSmall));
}

#[test]
fn enc_exact_fit() {
    let f = ConsentFrame::Resume(ConsentResume { timestamp_ms: None, timestamp_us: None });
    let mut buf = [0u8; cbor::MAX_ENCODED_SIZE];
    let n = cbor::encode(&f, &mut buf).unwrap();
    // Re-encode into exact-size buffer
    let mut exact = vec![0u8; n];
    assert_eq!(cbor::encode(&f, &mut exact), Ok(n));
}

// ═══════════════════════════════════════════════════════════════════
//  INVARIANTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn inv_valid_withdraw() {
    let f = ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer, reason_code: Some(ReasonCode::UserInitiated),
        reason: None, epoch: None, timestamp_ms: Some(1000), timestamp_us: None,
    });
    let r = invariants::check_frame(&f);
    assert!(r.is_valid());
    assert!(!r.has_warnings());
}

#[test]
fn inv_withdraw_missing_timestamp_warns() {
    let f = ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer,
        reason_code: Some(ReasonCode::UserInitiated),
        reason: None,
        epoch: None,
        timestamp_ms: None,
        timestamp_us: None,
    });
    let r = invariants::check_frame(&f);
    assert!(r.is_valid()); // SHOULD, not MUST
    assert!(r.has_warnings());
}

#[test]
fn inv_withdraw_zero_timestamp_violates() {
    let f = ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer,
        reason_code: None,
        reason: None,
        epoch: None,
        timestamp_ms: None,
        timestamp_us: Some(0),
    });
    let r = invariants::check_frame(&f);
    assert!(!r.is_valid());
}

#[test]
fn inv_transition_withdrawn_blocked() {
    let f = ConsentFrame::Resume(ConsentResume { timestamp_ms: None, timestamp_us: None });
    assert_eq!(
        invariants::check_transition(ConsentState::Withdrawn, &f),
        Err(invariants::InvariantViolation::TransitionFromWithdrawn)
    );
}

#[test]
fn inv_transition_granted_withdraw_ok() {
    let f = ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer, reason_code: None, reason: None,
        epoch: None, timestamp_ms: None, timestamp_us: None,
    });
    assert_eq!(
        invariants::check_transition(ConsentState::Granted, &f),
        Ok(ConsentState::Withdrawn)
    );
}

#[test]
fn inv_suspend_missing_reason_warns() {
    let f = ConsentFrame::Suspend(ConsentSuspend {
        reason_code: None, reason: None, timestamp_ms: None, timestamp_us: None,
    });
    let r = invariants::check_frame(&f);
    assert!(r.is_valid());
    assert!(r.has_warnings());
}

// ═══════════════════════════════════════════════════════════════════
//  JSON VECTOR ROUND-TRIP
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "json")]
mod json_tests {
    use super::*;
    use axonos_consent::codec::json;

    #[test] fn all_15_vectors() {
        let raw = include_str!("vectors/consent-interop-vectors-v0.1.0.json");
        let root: serde_json::Value = serde_json::from_str(raw).unwrap();
        let vecs = root["vectors"].as_array().unwrap();
        assert_eq!(vecs.len(), 15);
        let mut ok = 0;
        for tv in vecs {
            let id = tv["id"].as_str().unwrap_or("?");
            let jf = match tv.get("json") { Some(v) if v.is_object() => v, _ => continue };
            let frame = json::decode_value(jf).unwrap_or_else(|e| panic!("{}: {}", id, e));
            // CBOR round-trip
            let mut buf = [0u8; cbor::MAX_ENCODED_SIZE];
            let n = cbor::encode(&frame, &mut buf).unwrap();
            let d = cbor::decode(&buf[..n]).unwrap();
            assert_eq!(frame, d, "{}: CBOR rt", id);
            // JSON round-trip
            let jv2 = json::encode_value(&frame);
            let d2 = json::decode_value(&jv2).unwrap();
            assert_eq!(frame, d2, "{}: JSON rt", id);
            // Invariants
            let inv = invariants::check_frame(&frame);
            if !inv.is_valid() { eprintln!("  WARN {}: invariant violation", id); }
            eprintln!("  PASS {} ({}B)", id, n);
            ok += 1;
        }
        assert!(ok >= 14);
    }

    #[test] fn state_transitions() {
        let raw = include_str!("vectors/consent-interop-vectors-v0.1.0.json");
        let root: serde_json::Value = serde_json::from_str(raw).unwrap();
        for tv in root["vectors"].as_array().unwrap() {
            let id = tv["id"].as_str().unwrap_or("?");
            let sb = tv.get("state_before").and_then(|v| v.as_str());
            let sa = tv.get("state_after").and_then(|v| v.as_str());
            let (b, a) = match (sb, sa) {
                (Some(b), Some(a)) => (b, a), _ => continue,
            };
            let jf = match tv.get("json") { Some(v) if v.is_object() => v, _ => continue };
            let frame = match json::decode_value(jf) { Ok(f) => f, _ => continue };
            let initial = ps(b); let expected = ps(a);
            let got = invariants::check_transition(initial, &frame).unwrap_or(initial);
            assert_eq!(got, expected, "{}: {:?}→{:?} got {:?}", id, initial, expected, got);
        }
    }
    fn ps(s: &str) -> ConsentState { match s {
        "granted" => ConsentState::Granted, "suspended" => ConsentState::Suspended,
        "withdrawn" => ConsentState::Withdrawn, _ => panic!("{}", s),
    }}
}

// ═══════════════════════════════════════════════════════════════════
//  STATE MACHINE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn sm_grant_suspend() {
    assert_eq!(ConsentState::Granted.suspend(), Ok(ConsentState::Suspended));
}
#[test]
fn sm_suspend_resume() {
    assert_eq!(ConsentState::Suspended.resume(), Ok(ConsentState::Granted));
}
#[test]
fn sm_withdrawn_terminal() {
    assert_eq!(
        ConsentState::Withdrawn.suspend(),
        Err(TransitionError::AlreadyWithdrawn)
    );
    assert_eq!(
        ConsentState::Withdrawn.resume(),
        Err(TransitionError::AlreadyWithdrawn)
    );
    assert_eq!(
        ConsentState::Withdrawn.withdraw(),
        Err(TransitionError::AlreadyWithdrawn)
    );
}
#[test]
fn sm_idempotent() {
    assert_eq!(
        ConsentState::Suspended.suspend(),
        Ok(ConsentState::Suspended)
    );
    assert_eq!(
        ConsentState::Granted.resume(),
        Ok(ConsentState::Granted)
    );
}
#[test]
fn sm_gossip() {
    for s in [
        ConsentState::Granted,
        ConsentState::Suspended,
        ConsentState::Withdrawn,
    ] {
        assert_eq!(ConsentState::from_gossip_bits(s.to_gossip_bits()), Some(s));
    }
}

// ═══════════════════════════════════════════════════════════════════
//  ENGINE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn eng_register() {
    let mut e = ConsentEngine::new();
    e.register_peer([1; 16], 0).unwrap();
    assert_eq!(e.get_state(&[1; 16]), Some(ConsentState::Granted));
}
#[test]
fn eng_dup() {
    let mut e = ConsentEngine::new();
    e.register_peer([2; 16], 0).unwrap();
    assert!(e.register_peer([2; 16], 0).is_err());
}
#[test]
fn eng_full() {
    let mut e = ConsentEngine::new();
    for i in 0..MAX_PEERS as u8 {
        let mut p = [0; 16];
        p[0] = i;
        e.register_peer(p, 0).unwrap();
    }
    assert!(e.register_peer([0xFF; 16], 0).is_err());
}
#[test]
fn eng_unknown() {
    let mut e = ConsentEngine::new();
    assert_eq!(
        e.withdraw(&[0xFF; 16], None, 0),
        Err(TransitionError::PeerNotFound)
    );
}
#[test]
fn eng_withdraw_all() {
    let mut e = ConsentEngine::new();
    for i in 0..3u8 { let mut p=[0; 16]; p[0]=i; e.register_peer(p,0).unwrap(); }
    let r = e.withdraw_all(Some(ReasonCode::EmergencyButton), 100);
    assert_eq!(r.count, 3);
    // Verify peer IDs are captured for audit trail
    assert!(r.withdrawn_peers[0].is_some());
    assert!(r.withdrawn_peers[1].is_some());
    assert!(r.withdrawn_peers[2].is_some());
}

// ═══════════════════════════════════════════════════════════════════
//  APPLY_FRAME — EXHAUSTIVE STATE×FRAME TABLE
// ═══════════════════════════════════════════════════════════════════

fn wf() -> ConsentFrame {
    ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer,
        reason_code: None,
        reason: None,
        epoch: None,
        timestamp_ms: Some(1),
        timestamp_us: None,
    })
}
fn sf() -> ConsentFrame {
    ConsentFrame::Suspend(ConsentSuspend {
        reason_code: None,
        reason: None,
        timestamp_ms: Some(1),
        timestamp_us: None,
    })
}
fn rf() -> ConsentFrame {
    ConsentFrame::Resume(ConsentResume {
        timestamp_ms: Some(1),
        timestamp_us: None,
    })
}

// Row 1: GRANTED
#[test]
fn af_granted_withdraw() {
    assert_eq!(
        ConsentState::Granted.apply_frame(&wf()),
        Ok(ConsentState::Withdrawn)
    );
}
#[test]
fn af_granted_suspend() {
    assert_eq!(
        ConsentState::Granted.apply_frame(&sf()),
        Ok(ConsentState::Suspended)
    );
}
#[test]
fn af_granted_resume() {
    assert_eq!(
        ConsentState::Granted.apply_frame(&rf()),
        Ok(ConsentState::Granted)
    );
}

// Row 2: SUSPENDED
#[test]
fn af_suspended_withdraw() {
    assert_eq!(
        ConsentState::Suspended.apply_frame(&wf()),
        Ok(ConsentState::Withdrawn)
    );
}
#[test]
fn af_suspended_suspend() {
    assert_eq!(
        ConsentState::Suspended.apply_frame(&sf()),
        Ok(ConsentState::Suspended)
    );
}
#[test]
fn af_suspended_resume() {
    assert_eq!(
        ConsentState::Suspended.apply_frame(&rf()),
        Ok(ConsentState::Granted)
    );
}

// Row 3: WITHDRAWN — all rejected
#[test]
fn af_withdrawn_withdraw() {
    assert_eq!(
        ConsentState::Withdrawn.apply_frame(&wf()),
        Err(TransitionError::AlreadyWithdrawn)
    );
}
#[test]
fn af_withdrawn_suspend() {
    assert_eq!(
        ConsentState::Withdrawn.apply_frame(&sf()),
        Err(TransitionError::AlreadyWithdrawn)
    );
}
#[test]
fn af_withdrawn_resume() {
    assert_eq!(
        ConsentState::Withdrawn.apply_frame(&rf()),
        Err(TransitionError::AlreadyWithdrawn)
    );
}

// ═══════════════════════════════════════════════════════════════════
//  PROCESS_FRAME — FULL PIPELINE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pf_valid_withdraw() {
    let mut e = ConsentEngine::new();
    e.register_peer([10; 16], 0).unwrap();
    let r = e
        .process_frame(&[10; 16], &wf(), Some(ReasonCode::UserInitiated), 100)
        .unwrap();
    assert_eq!(r.new_state, ConsentState::Withdrawn);
}

#[test]
fn pf_rejects_zero_timestamp() {
    let mut e = ConsentEngine::new();
    e.register_peer([11; 16], 0).unwrap();
    let bad = ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer,
        reason_code: None,
        reason: None,
        epoch: None,
        timestamp_ms: None,
        timestamp_us: Some(0),
    });
    assert!(e
        .process_frame(&[11; 16], &bad, None, 100)
        .is_err());
}

#[test]
fn pf_rejects_withdrawn_resume() {
    let mut e = ConsentEngine::new();
    e.register_peer([12; 16], 0).unwrap();
    e.withdraw(&[12; 16], None, 50).unwrap();
    assert!(e
        .process_frame(&[12; 16], &rf(), None, 100)
        .is_err());
}

#[test]
fn pf_warns_missing_timestamp() {
    let mut e = ConsentEngine::new();
    e.register_peer([13; 16], 0).unwrap();
    let no_ts = ConsentFrame::Withdraw(ConsentWithdraw {
        scope: Scope::Peer,
        reason_code: Some(ReasonCode::UserInitiated),
        reason: None,
        epoch: None,
        timestamp_ms: None,
        timestamp_us: None,
    });
    let r = e
        .process_frame(
            &[13; 16],
            &no_ts,
            Some(ReasonCode::UserInitiated),
            100,
        )
        .unwrap();
    assert_eq!(r.new_state, ConsentState::Withdrawn);
    assert!(r.warning_count > 0); // SHOULD warning for missing timestamp
}

// ═══════════════════════════════════════════════════════════════════
//  PROCESS_RAW — SINGLE ENTRY POINT (decode→validate→transition)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pr_valid_cbor_withdraw() {
    let mut e = ConsentEngine::new();
    e.register_peer([20; 16], 0).unwrap();
    // Encode a valid withdraw frame to CBOR, then process_raw
    let frame = wf();
    let mut buf = [0u8; cbor::MAX_ENCODED_SIZE];
    let n = cbor::encode(&frame, &mut buf).unwrap();
    let r = e.process_raw(&[20; 16], &buf[..n], 100).unwrap();
    assert_eq!(r.new_state, ConsentState::Withdrawn);
}

#[test]
fn pr_rejects_malformed_cbor() {
    let mut e = ConsentEngine::new();
    e.register_peer([21; 16], 0).unwrap();
    let garbage = [0xFF, 0x00, 0xDE, 0xAD];
    let err = e.process_raw(&[21; 16], &garbage, 100);
    assert!(matches!(err, Err(axonos_consent::Error::Decode(_))));
}

#[test]
fn pr_rejects_empty_input() {
    let mut e = ConsentEngine::new();
    e.register_peer([22; 16], 0).unwrap();
    let err = e.process_raw(&[22; 16], &[], 100);
    assert!(matches!(err, Err(axonos_consent::Error::Decode(_))));
}

#[test]
fn pr_full_pipeline_suspend_resume() {
    let mut e = ConsentEngine::new();
    e.register_peer([23; 16], 0).unwrap();
    // Suspend
    let mut buf = [0u8; cbor::MAX_ENCODED_SIZE];
    let n = cbor::encode(&sf(), &mut buf).unwrap();
    let r = e.process_raw(&[23; 16], &buf[..n], 100).unwrap();
    assert_eq!(r.new_state, ConsentState::Suspended);
    // Resume
    let n = cbor::encode(&rf(), &mut buf).unwrap();
    let r = e.process_raw(&[23; 16], &buf[..n], 200).unwrap();
    assert_eq!(r.new_state, ConsentState::Granted);
}

// ═══════════════════════════════════════════════════════════════════
//  ERROR TAXONOMY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn err_from_decode() {
    let e: axonos_consent::error::Error = cbor::DecodeError::MapTooLarge.into();
    assert!(matches!(e, axonos_consent::error::Error::Decode(_)));
}

#[test]
fn err_from_transition() {
    let e: axonos_consent::error::Error = TransitionError::AlreadyWithdrawn.into();
    assert!(matches!(e, axonos_consent::error::Error::Transition(_)));
}

#[test]
fn err_from_invariant() {
    let e: axonos_consent::error::Error = invariants::InvariantViolation::ZeroTimestampUs.into();
    assert!(matches!(e, axonos_consent::error::Error::Invariant(_)));
}
