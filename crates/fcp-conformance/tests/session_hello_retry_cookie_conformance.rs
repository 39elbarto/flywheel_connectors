//! Stateless HelloRetry cookie conformance.
//!
//! `compute_cookie` and `verify_cookie` in `fcp_protocol::session` form
//! the stateless anti-DoS MAC used for the HelloRetry challenge. The
//! responder issues a `MeshSessionHelloRetry { cookie }` and only
//! commits resources once the initiator echoes back a Hello whose
//! transcript still produces the same cookie under the responder's
//! private cookie key. The MAC therefore binds to the entire Hello
//! transcript except `hello.cookie` and `hello.signature` — any
//! tampered field MUST invalidate the cookie.
//!
//! These properties live inline in `fcp-protocol/src/session.rs` but
//! had no cross-crate conformance coverage. A regression that drops
//! one of the bound fields from the MAC input would silently allow an
//! attacker to replay a cookie issued for a different Hello.

use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_prelude::TailscaleNodeId;
use fcp_protocol::session::{
    MeshSessionHello, SESSION_COOKIE_SIZE, SessionCookie, SessionCryptoSuite, SessionError,
    SessionNonce, compute_cookie, current_timestamp, verify_cookie,
};

const COOKIE_KEY_A: [u8; 32] = [0xA1; 32];
const COOKIE_KEY_B: [u8; 32] = [0xB2; 32];

fn make_hello() -> MeshSessionHello {
    let signing_key = Ed25519SigningKey::generate();
    let eph_key = X25519SecretKey::generate();
    let mut hello = MeshSessionHello {
        from: TailscaleNodeId::new("node-initiator"),
        to: TailscaleNodeId::new("node-responder"),
        eph_pubkey: eph_key.public_key(),
        nonce: SessionNonce([0x44; 16]),
        cookie: None,
        timestamp: current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        transport_limits: None,
        signature: None,
    };
    hello.sign(&signing_key).expect("sign hello");
    hello
}

#[test]
fn compute_then_verify_round_trips() {
    let hello = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello).expect("compute cookie");
    verify_cookie(&COOKIE_KEY_A, &hello, &cookie)
        .expect("verify_cookie must accept the cookie produced by compute_cookie");
}

#[test]
fn cookie_issued_under_a_different_key_is_rejected() {
    // The cookie key is the responder's private state. An attacker who
    // does not hold that key cannot forge a cookie that verifies.
    let hello = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello).expect("compute cookie under key A");

    let err = verify_cookie(&COOKIE_KEY_B, &hello, &cookie)
        .expect_err("cookie verified with the wrong key must be rejected");
    assert!(
        matches!(err, SessionError::InvalidCookie),
        "expected InvalidCookie, got {err:?}"
    );
}

#[test]
fn flipped_cookie_byte_is_rejected() {
    // Direct cookie tampering: flipping any byte of the 32-byte MAC
    // output must cause verify_cookie to surface InvalidCookie.
    let hello = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello).expect("compute cookie");
    let mut bytes = *cookie.as_bytes();
    bytes[SESSION_COOKIE_SIZE - 1] ^= 0x01;
    let tampered = SessionCookie(bytes);

    let err = verify_cookie(&COOKIE_KEY_A, &hello, &tampered)
        .expect_err("single-byte cookie tamper must be rejected");
    assert!(
        matches!(err, SessionError::InvalidCookie),
        "expected InvalidCookie, got {err:?}"
    );
}

#[test]
fn cookie_binds_to_hello_from() {
    // A cookie issued for hello_a MUST NOT verify against hello_b that
    // differs only in `from` — otherwise an attacker could replay a
    // legitimately-issued cookie under a different identity claim.
    let hello_a = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello_a).expect("compute cookie");

    let mut hello_b = hello_a.clone();
    hello_b.from = TailscaleNodeId::new("node-other-initiator");

    let err = verify_cookie(&COOKIE_KEY_A, &hello_b, &cookie)
        .expect_err("cookie issued for hello_a must not verify against tampered from");
    assert!(matches!(err, SessionError::InvalidCookie));
}

#[test]
fn cookie_binds_to_hello_to() {
    let hello_a = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello_a).expect("compute cookie");

    let mut hello_b = hello_a.clone();
    hello_b.to = TailscaleNodeId::new("node-other-responder");

    let err =
        verify_cookie(&COOKIE_KEY_A, &hello_b, &cookie).expect_err("cookie must bind to hello.to");
    assert!(matches!(err, SessionError::InvalidCookie));
}

#[test]
fn cookie_binds_to_hello_eph_pubkey() {
    // The ephemeral public key is the entropy that prevents handshake
    // pinning attacks — the cookie must bind to it so a captured
    // cookie cannot be replayed against a fresh hello with a new eph.
    let hello_a = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello_a).expect("compute cookie");

    let mut hello_b = hello_a.clone();
    let other_eph = X25519SecretKey::generate();
    hello_b.eph_pubkey = other_eph.public_key();

    let err = verify_cookie(&COOKIE_KEY_A, &hello_b, &cookie)
        .expect_err("cookie must bind to hello.eph_pubkey");
    assert!(matches!(err, SessionError::InvalidCookie));
}

#[test]
fn cookie_binds_to_hello_nonce() {
    let hello_a = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello_a).expect("compute cookie");

    let mut hello_b = hello_a.clone();
    hello_b.nonce = SessionNonce([0x55; 16]);

    let err = verify_cookie(&COOKIE_KEY_A, &hello_b, &cookie)
        .expect_err("cookie must bind to hello.nonce");
    assert!(matches!(err, SessionError::InvalidCookie));
}

#[test]
fn cookie_binds_to_hello_timestamp() {
    let hello_a = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello_a).expect("compute cookie");

    let mut hello_b = hello_a.clone();
    hello_b.timestamp = hello_a.timestamp.wrapping_add(1);

    let err = verify_cookie(&COOKIE_KEY_A, &hello_b, &cookie)
        .expect_err("cookie must bind to hello.timestamp");
    assert!(matches!(err, SessionError::InvalidCookie));
}

#[test]
fn cookie_binds_to_hello_suites() {
    // The suites field carries cryptographic-suite negotiation. A
    // cookie that did not bind to it would let an attacker re-use a
    // cookie issued for {Suite1, Suite2} against a hello that only
    // offers a downgraded suite list.
    let hello_a = make_hello();
    let cookie = compute_cookie(&COOKIE_KEY_A, &hello_a).expect("compute cookie");

    let mut hello_b = hello_a.clone();
    hello_b.suites = vec![SessionCryptoSuite::Suite1];

    let err = verify_cookie(&COOKIE_KEY_A, &hello_b, &cookie)
        .expect_err("cookie must bind to hello.suites");
    assert!(matches!(err, SessionError::InvalidCookie));
}

#[test]
fn compute_cookie_is_deterministic_for_fixed_inputs() {
    // The MAC output must be a pure function of (cookie_key, hello).
    // Re-issuing for the same inputs must produce byte-identical
    // cookies so the verifier can recompute and compare.
    let hello = make_hello();
    let cookie_1 = compute_cookie(&COOKIE_KEY_A, &hello).expect("first compute");
    let cookie_2 = compute_cookie(&COOKIE_KEY_A, &hello).expect("second compute");
    assert_eq!(
        cookie_1.as_bytes(),
        cookie_2.as_bytes(),
        "compute_cookie must be deterministic — caller cannot recompute otherwise"
    );
}
