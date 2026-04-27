#![no_main]

//! Fuzz target for `compute_session_mac` / `verify_session_mac`
//! cross-suite (Suite1 ↔ Suite2) rejection (session.rs:1032-1088).
//!
//! `compute_session_mac` dispatches between:
//!   - Suite1: HMAC-SHA256 keyed by mac_key
//!   - Suite2: BLAKE3-keyed by mac_key
//!
//! Existing `session_metamorphic` covers per-field binding (mac_key,
//! session_id, direction, seq, frame) but NOT cross-suite rejection.
//! A regression that allowed cross-suite verification would let an
//! attacker downgrade an HMAC-SHA256 verification path to BLAKE3 (or
//! vice versa), preserving frame authenticity claims while changing
//! the underlying primitive.
//!
//! Properties asserted:
//!
//!   1. **Suite1 round-trip**: compute(Suite1) → verify(Suite1) Ok.
//!   2. **Suite2 round-trip**: compute(Suite2) → verify(Suite2) Ok.
//!   3. **Cross-suite rejection 1→2**: a MAC computed under Suite1
//!      MUST NOT verify under Suite2.
//!   4. **Cross-suite rejection 2→1**: same in reverse.
//!   5. **Cross-suite tag-distinct**: same (key, session_id,
//!      direction, seq, frame) computed under Suite1 vs Suite2 MUST
//!      produce distinct tag bytes.
//!
//!   Once-gated regression anchor: known input under both suites
//!   produces distinct tags AND cross-verify rejects.

use arbitrary::{Arbitrary, Unstructured};
use fcp_protocol::{
    MeshSessionId, SessionCryptoSuite, SessionDirection, SessionError, compute_session_mac,
    verify_session_mac,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const KEY_SIZE: usize = 32;
const SESSION_ID_SIZE: usize = 16;

static CROSS_SUITE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    mac_key: [u8; KEY_SIZE],
    session_id: [u8; SESSION_ID_SIZE],
    seq: u64,
    direction_bit: bool,
    frame: Vec<u8>,
}

const MAX_FRAME_LEN: usize = 1024;

fn pick_direction(b: bool) -> SessionDirection {
    if b {
        SessionDirection::InitiatorToResponder
    } else {
        SessionDirection::ResponderToInitiator
    }
}

fuzz_target!(|data: &[u8]| {
    CROSS_SUITE_ANCHOR.call_once(assert_cross_suite_anchored);

    let mut u = Unstructured::new(data);
    let Ok(mut input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.frame.len() > MAX_FRAME_LEN {
        input.frame.truncate(MAX_FRAME_LEN);
    }

    let session_id = MeshSessionId(input.session_id);
    let direction = pick_direction(input.direction_bit);

    // ── PROPERTY 1: Suite1 round-trip ─────────────────────────────────
    let tag_s1 = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        &input.frame,
    )
    .expect("compute Suite1");
    verify_session_mac(
        SessionCryptoSuite::Suite1,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        &input.frame,
        &tag_s1,
    )
    .expect("Suite1 self-verify");

    // ── PROPERTY 2: Suite2 round-trip ─────────────────────────────────
    let tag_s2 = compute_session_mac(
        SessionCryptoSuite::Suite2,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        &input.frame,
    )
    .expect("compute Suite2");
    verify_session_mac(
        SessionCryptoSuite::Suite2,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        &input.frame,
        &tag_s2,
    )
    .expect("Suite2 self-verify");

    // ── PROPERTY 5: cross-suite tag-distinct ──────────────────────────
    assert_ne!(
        tag_s1, tag_s2,
        "Suite1 and Suite2 produced identical MAC tags for the same inputs — \
         primitive degeneration; HMAC-SHA256 and BLAKE3-keyed MUST byte-differ"
    );

    // ── PROPERTY 3: cross-suite rejection 1 → 2 ──────────────────────
    match verify_session_mac(
        SessionCryptoSuite::Suite2,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        &input.frame,
        &tag_s1,
    ) {
        Err(SessionError::InvalidSignature) => {}
        Err(other) => panic!("Suite1 tag verified under Suite2 with error {other:?}"),
        Ok(()) => panic!(
            "Suite1-computed tag verified under Suite2 — cross-suite rejection broken; \
             attacker can downgrade primitive while preserving authenticity claim"
        ),
    }

    // ── PROPERTY 4: cross-suite rejection 2 → 1 ──────────────────────
    match verify_session_mac(
        SessionCryptoSuite::Suite1,
        &input.mac_key,
        &session_id,
        direction,
        input.seq,
        &input.frame,
        &tag_s2,
    ) {
        Err(SessionError::InvalidSignature) => {}
        Err(other) => panic!("Suite2 tag verified under Suite1 with error {other:?}"),
        Ok(()) => {
            panic!("Suite2-computed tag verified under Suite1 — cross-suite rejection broken")
        }
    }
});

/// Once-gated anchor: known inputs under both suites produce distinct
/// tags AND cross-verify rejects.
fn assert_cross_suite_anchored() {
    let key = [0x42u8; KEY_SIZE];
    let session_id = MeshSessionId([0xAAu8; SESSION_ID_SIZE]);
    let direction = SessionDirection::InitiatorToResponder;
    let seq = 0x0123_4567_89AB_CDEF;
    let frame = b"anchor frame payload";

    let tag_s1 = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &key,
        &session_id,
        direction,
        seq,
        frame,
    )
    .expect("anchor Suite1");
    let tag_s2 = compute_session_mac(
        SessionCryptoSuite::Suite2,
        &key,
        &session_id,
        direction,
        seq,
        frame,
    )
    .expect("anchor Suite2");

    assert_ne!(
        tag_s1, tag_s2,
        "ANCHOR REGRESSION: Suite1 (HMAC-SHA256) and Suite2 (BLAKE3-keyed) produced \
         identical tags for the same inputs — primitive degeneration"
    );

    // Cross-verify must reject.
    assert!(
        verify_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            direction,
            seq,
            frame,
            &tag_s1,
        )
        .is_err(),
        "ANCHOR REGRESSION: Suite1 tag verified under Suite2 — cross-suite \
         rejection at session.rs:1083 broken"
    );
    assert!(
        verify_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            direction,
            seq,
            frame,
            &tag_s2,
        )
        .is_err(),
        "ANCHOR REGRESSION: Suite2 tag verified under Suite1 — cross-suite \
         rejection broken"
    );

    // Acceptance: same-suite verify works (otherwise rejection is vacuous).
    verify_session_mac(
        SessionCryptoSuite::Suite1,
        &key,
        &session_id,
        direction,
        seq,
        frame,
        &tag_s1,
    )
    .expect("ANCHOR: Suite1 self-verify must succeed");
    verify_session_mac(
        SessionCryptoSuite::Suite2,
        &key,
        &session_id,
        direction,
        seq,
        frame,
        &tag_s2,
    )
    .expect("ANCHOR: Suite2 self-verify must succeed");
}
