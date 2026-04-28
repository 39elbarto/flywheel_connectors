#![no_main]

//! Fuzz target for `SessionCryptoSuite` id/try_from_id + serde round-trip
//! (session.rs:122-168).
//!
//! `SessionCryptoSuite` carries a u8 wire identifier (Suite1=1,
//! Suite2=2). `try_from_id` rejects any other byte with
//! `SessionError::InvalidSuiteId(byte)`. Serde uses a custom impl that
//! serializes/deserializes via u8.
//!
//! NOT covered by existing fuzz as a discrete MR.
//!
//! Properties asserted:
//!
//!   1. **id round-trip**: `try_from_id(s.id()) == Ok(s)` for both
//!      Suite1 and Suite2.
//!   2. **InvalidSuiteId carries byte**: `try_from_id(byte)` for any
//!      byte not in {1, 2} MUST return `InvalidSuiteId(byte)` with
//!      the rejected byte preserved.
//!   3. **Serde u8 round-trip (JSON)**: serialize → deserialize
//!      preserves variant.
//!   4. **Serde u8 round-trip (CBOR)**: same via canonical CBOR.
//!   5. **as_str labels distinct**: Suite1 vs Suite2 produce
//!      byte-distinct human-readable strings.
//!
//!   Once-gated anchors verify documented labels + each known/unknown
//!   id outcome.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::to_canonical_cbor;
use fcp_protocol::{SessionCryptoSuite, SessionError};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static SUITE_SERDE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    raw_id: u8,
}

fuzz_target!(|data: &[u8]| {
    SUITE_SERDE_ANCHOR.call_once(assert_suite_serde_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let result = SessionCryptoSuite::try_from_id(input.raw_id);
    match result {
        Ok(suite) => {
            // ── PROPERTY 1: id round-trip ─────────────────────────────
            assert_eq!(
                suite.id(),
                input.raw_id,
                "try_from_id({}) → {suite:?}, but id() returned {}",
                input.raw_id,
                suite.id()
            );

            // ── PROPERTY 3: JSON round-trip ───────────────────────────
            let json = serde_json::to_string(&suite).expect("JSON serialize");
            let from_json: SessionCryptoSuite =
                serde_json::from_str(&json).expect("JSON deserialize");
            assert_eq!(suite, from_json, "JSON round-trip lost variant");

            // ── PROPERTY 4: canonical-CBOR round-trip ────────────────
            let cbor = to_canonical_cbor(&suite).expect("canonical-CBOR serialize");
            let from_cbor: SessionCryptoSuite =
                ciborium::from_reader(&cbor[..]).expect("ciborium deserialize");
            assert_eq!(suite, from_cbor, "CBOR round-trip lost variant");
        }
        Err(SessionError::InvalidSuiteId(byte)) => {
            // ── PROPERTY 2: InvalidSuiteId carries byte ──────────────
            assert_eq!(
                byte, input.raw_id,
                "InvalidSuiteId carried wrong byte: {byte} vs input {}",
                input.raw_id
            );
            assert!(
                input.raw_id != 1 && input.raw_id != 2,
                "InvalidSuiteId for known suite id {}",
                input.raw_id
            );
        }
        Err(other) => panic!(
            "try_from_id({}) returned {other:?}; expected Ok(suite) or InvalidSuiteId",
            input.raw_id
        ),
    }
});

/// Once-gated anchors verifying documented labels + each known/unknown
/// id outcome.
fn assert_suite_serde_anchored() {
    // (a) Known ids round-trip.
    assert_eq!(
        SessionCryptoSuite::try_from_id(1).expect("anchor Suite1"),
        SessionCryptoSuite::Suite1
    );
    assert_eq!(
        SessionCryptoSuite::try_from_id(2).expect("anchor Suite2"),
        SessionCryptoSuite::Suite2
    );
    assert_eq!(SessionCryptoSuite::Suite1.id(), 1, "ANCHOR: Suite1 id != 1");
    assert_eq!(SessionCryptoSuite::Suite2.id(), 2, "ANCHOR: Suite2 id != 2");

    // (b) Unknown ids → InvalidSuiteId(byte).
    for bad in [0u8, 3, 4, 100, 254, 255] {
        match SessionCryptoSuite::try_from_id(bad) {
            Err(SessionError::InvalidSuiteId(byte)) => {
                assert_eq!(
                    byte, bad,
                    "ANCHOR: InvalidSuiteId carried wrong byte for input {bad}"
                );
            }
            other => panic!(
                "ANCHOR REGRESSION: try_from_id({bad}) returned {other:?}; \
                 expected InvalidSuiteId({bad})"
            ),
        }
    }

    // (c) Documented labels.
    assert_eq!(
        SessionCryptoSuite::Suite1.as_str(),
        "suite1-hmacsha256",
        "ANCHOR REGRESSION: Suite1 label changed"
    );
    assert_eq!(
        SessionCryptoSuite::Suite2.as_str(),
        "suite2-blake3",
        "ANCHOR REGRESSION: Suite2 label changed"
    );
    assert_ne!(
        SessionCryptoSuite::Suite1.as_str(),
        SessionCryptoSuite::Suite2.as_str(),
        "ANCHOR: Suite1/Suite2 labels collide"
    );

    // (d) JSON serde round-trip on both variants.
    for s in [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2] {
        let json = serde_json::to_string(&s).expect("anchor JSON ser");
        // Documented behavior: serializes as u8.
        assert_eq!(
            json,
            s.id().to_string(),
            "ANCHOR REGRESSION: SessionCryptoSuite JSON encoding != u8 number"
        );
        let back: SessionCryptoSuite = serde_json::from_str(&json).expect("anchor JSON de");
        assert_eq!(back, s, "ANCHOR: JSON round-trip lost variant");
    }

    // (e) CBOR round-trip.
    for s in [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2] {
        let cbor = to_canonical_cbor(&s).expect("anchor CBOR ser");
        // u8 1 encodes as 0x01, u8 2 encodes as 0x02 (single-byte CBOR
        // major-type 0).
        assert_eq!(
            cbor,
            vec![s.id()],
            "ANCHOR REGRESSION: SessionCryptoSuite CBOR encoding {cbor:?} != [{}]",
            s.id()
        );
        let back: SessionCryptoSuite = ciborium::from_reader(&cbor[..]).expect("anchor CBOR de");
        assert_eq!(back, s, "ANCHOR: CBOR round-trip lost variant");
    }
}
