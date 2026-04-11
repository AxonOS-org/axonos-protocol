// Copyright (c) 2026 Denis Yermakou / AxonOS
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This file is part of the AxonOS Consent Engine.
// See LICENSE-APACHE or LICENSE-MIT for details.

//! Fuzz target: `axonos_consent::codec::cbor::decode()`
//!
//! Goal: no panic, no OOB, no infinite loop on arbitrary input.
//! Run: cargo +nightly fuzz run fuzz_cbor_decode

#![no_main]
use libfuzzer_sys::fuzz_target;
use axonos_consent::codec::cbor;

fuzz_target!(|data: &[u8]| {
    // Must never panic. Errors are expected and fine.
    let _ = cbor::decode(data);
});
