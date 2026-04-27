//! Session MAC input-binding conformance.
//!
//! `compute_session_mac` is the per-frame data-plane authenticator. It
//! takes (suite, mac_key, session_id, direction, seq, frame_bytes) and
//! produces a 16-byte tag. Existing conformance tests in
//! `datagram_golden_vectors.rs` and `negative_path_conformance.rs`
//! cover direction-binding, seq-binding, wrong-key rejection, and
//! byte-level tamper rejection. They do NOT cover two adversarial
//! axes that flow directly from the docstring & code:
//!
//! 1. **Suite binding.** Suite1 (HMAC-SHA256) and Suite2 (BLAKE3-keyed)
//!    are distinct primitives. A MAC produced under Suite1 MUST NOT
//!    verify under Suite2 even when every other input is identical —
//!    otherwise a downgrade-the-suite-negotiation attacker could
//!    forge a Suite1 MAC for a session that the responder believes is
//!    running Suite2.
//!
//! 2. **session_id binding.** The session id is mixed in via
//!    `mac.update(session_id.as_bytes())`. A MAC produced for session
//!    A MUST NOT verify for session B even with the same key, suite,
//!    direction, seq, and frame — otherwise an attacker observing
//!    traffic on session A could replay frames into session B.
//!
//! These tests freshly mint MACs (no golden vectors) so they pin the
//! cross-input independence directly rather than re-checking captured
//! tags.

use fcp_protocol::session::{
    MeshSessionId, SessionCryptoSuite, SessionDirection, SessionError, compute_session_mac,
    verify_session_mac,
};

const KEY: [u8; 32] = [0x42; 32];
const SESSION_A: MeshSessionId = MeshSessionId([0x11; 16]);
const SESSION_B: MeshSessionId = MeshSessionId([0x22; 16]);
const FRAME: &[u8] = b"FCPS-frame-payload-canonical-test-bytes";
const SEQ: u64 = 42;
const DIRECTION: SessionDirection = SessionDirection::InitiatorToResponder;

#[test]
fn suite1_and_suite2_macs_differ_for_identical_inputs() {
    // Distinct MAC primitives (HMAC-SHA256 vs BLAKE3-keyed) MUST yield
    // different tags. If they ever collide on the same inputs that's
    // either an astronomical accident (which would still make the
    // assertion fail and surface a real divergence) or a production
    // regression where one suite silently delegates to the other.
    let mac_s1 = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("Suite1 MAC");
    let mac_s2 = compute_session_mac(
        SessionCryptoSuite::Suite2,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("Suite2 MAC");
    assert_ne!(
        mac_s1, mac_s2,
        "Suite1 and Suite2 MUST produce distinct MACs for identical inputs — \
         otherwise a suite-downgrade attacker can forge tags across suites"
    );
}

#[test]
fn suite1_mac_does_not_verify_under_suite2() {
    let mac_s1 = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("Suite1 MAC");

    let err = verify_session_mac(
        SessionCryptoSuite::Suite2,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
        &mac_s1,
    )
    .expect_err("Suite1-issued MAC must not verify under Suite2");
    assert!(
        matches!(err, SessionError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn suite2_mac_does_not_verify_under_suite1() {
    let mac_s2 = compute_session_mac(
        SessionCryptoSuite::Suite2,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("Suite2 MAC");

    let err = verify_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
        &mac_s2,
    )
    .expect_err("Suite2-issued MAC must not verify under Suite1");
    assert!(
        matches!(err, SessionError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn distinct_session_ids_produce_distinct_macs_under_suite1() {
    let mac_a = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("MAC for session A");
    let mac_b = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_B,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("MAC for session B");
    assert_ne!(
        mac_a, mac_b,
        "Suite1: same (key, direction, seq, frame) under different MeshSessionId \
         MUST yield distinct MACs — otherwise frames are replayable across sessions"
    );
}

#[test]
fn distinct_session_ids_produce_distinct_macs_under_suite2() {
    let mac_a = compute_session_mac(
        SessionCryptoSuite::Suite2,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("MAC for session A");
    let mac_b = compute_session_mac(
        SessionCryptoSuite::Suite2,
        &KEY,
        &SESSION_B,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("MAC for session B");
    assert_ne!(
        mac_a, mac_b,
        "Suite2: same (key, direction, seq, frame) under different MeshSessionId \
         MUST yield distinct MACs — otherwise frames are replayable across sessions"
    );
}

#[test]
fn mac_minted_for_session_a_does_not_verify_for_session_b() {
    let mac_a = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        FRAME,
    )
    .expect("MAC for session A");

    let err = verify_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_B,
        DIRECTION,
        SEQ,
        FRAME,
        &mac_a,
    )
    .expect_err("MAC issued for session A must not verify against session B");
    assert!(
        matches!(err, SessionError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn suite_and_session_id_combine_into_four_distinct_macs() {
    // Joint independence: the (suite, session_id) cross-product of two
    // values each MUST give four distinct MACs when other inputs are
    // held fixed. A regression that, for example, mixed session_id
    // into Suite1 but not Suite2 would still pass the per-suite
    // session-binding tests but fail this joint check.
    let inputs = [
        (SessionCryptoSuite::Suite1, &SESSION_A),
        (SessionCryptoSuite::Suite1, &SESSION_B),
        (SessionCryptoSuite::Suite2, &SESSION_A),
        (SessionCryptoSuite::Suite2, &SESSION_B),
    ];
    let mut tags: Vec<[u8; 16]> = Vec::with_capacity(inputs.len());
    for (suite, sid) in &inputs {
        let tag = compute_session_mac(*suite, &KEY, sid, DIRECTION, SEQ, FRAME)
            .expect("compute MAC for joint independence fixture");
        tags.push(tag);
    }

    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(
                tags[i], tags[j],
                "tags[{i}] and tags[{j}] collided — (suite, session_id) cross-product \
                 must produce distinct MACs but tag {i:?} matched tag {j:?}"
            );
        }
    }
}

#[test]
fn empty_frame_macs_remain_suite_and_session_bound() {
    // Edge case: frame_bytes is empty. The MAC is still well-defined
    // and MUST still bind to suite and session_id. Otherwise a
    // zero-payload heartbeat could be replayed across suites or
    // sessions.
    let s1_a = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        b"",
    )
    .expect("Suite1 empty-frame MAC for session A");
    let s2_a = compute_session_mac(
        SessionCryptoSuite::Suite2,
        &KEY,
        &SESSION_A,
        DIRECTION,
        SEQ,
        b"",
    )
    .expect("Suite2 empty-frame MAC for session A");
    let s1_b = compute_session_mac(
        SessionCryptoSuite::Suite1,
        &KEY,
        &SESSION_B,
        DIRECTION,
        SEQ,
        b"",
    )
    .expect("Suite1 empty-frame MAC for session B");

    assert_ne!(
        s1_a, s2_a,
        "empty-frame MAC must still suite-bind (Suite1 vs Suite2)"
    );
    assert_ne!(
        s1_a, s1_b,
        "empty-frame MAC must still session-bind (session A vs session B)"
    );
}
