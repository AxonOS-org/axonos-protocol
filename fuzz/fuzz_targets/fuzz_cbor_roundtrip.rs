// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Fuzz target: encode → decode round-trip invariant.
//!
//! If decode succeeds on arbitrary input, re-encoding the result
//! and decoding again must produce the same frame.
//! Run: cargo +nightly fuzz run fuzz_cbor_roundtrip

#![no_main]
use libfuzzer_sys::fuzz_target;
use axonos_consent::codec::cbor;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = cbor::decode(data) {
        let mut buf = [0u8; cbor::MAX_ENCODED_SIZE];
        if let Ok(n) = cbor::encode(&frame, &mut buf) {
            let frame2 = cbor::decode(&buf[..n])
                .expect("re-decode of encoded frame must succeed");
            assert_eq!(frame, frame2, "round-trip invariant violated");
        }
    }
});
