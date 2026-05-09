//! Session handshake interop tests.
//!
//! Pre-br-t6wmw this file maintained a parallel set of local helpers
//! (`negotiate_suite(&[&str], &[&str])`, a 3-field local `TransportLimits`,
//! a HashSet-based `is_nonce_fresh`, a custom `build_retry_hello` binary
//! format) that DRIFTED from the production `fcp_protocol::session::*`
//! surface — most visibly: production `TransportLimits` is a single `u16`
//! `max_datagram_bytes` wrapper, while the local copy carried three u32
//! fields. The session interop suite reported "all green" while never
//! exercising the production code paths.
//!
//! This rewrite swaps every conformance-tested helper for the production
//! API: `fcp_protocol::session::{negotiate_suite, SessionCryptoSuite,
//! TransportLimits, MeshSessionHello, MeshSessionHelloRetry,
//! HelloReplayWindow}`. The two HKDF/X25519 vector tests
//! (`test_transcript_determinism`, `test_session_id_binding`) keep
//! exercising their inputs directly because they are testing the
//! key-derivation transcript shape, not a session helper.

use crate::{InteropTestSummary, TestFailure};

/// Session interop test suite.
pub struct SessionInteropTests;

impl SessionInteropTests {
    /// Run all session interop tests.
    #[must_use]
    pub fn run() -> InteropTestSummary {
        run_tests()
    }
}

/// Run all session interop tests.
pub fn run_tests() -> InteropTestSummary {
    let mut summary = InteropTestSummary::default();

    run_test(
        &mut summary,
        "transcript_determinism",
        test_transcript_determinism,
    );
    run_test(&mut summary, "suite_negotiation", test_suite_negotiation);
    run_test(&mut summary, "hello_retry_cookie", test_hello_retry_cookie);
    run_test(
        &mut summary,
        "transport_limits_negotiation",
        test_transport_limits_negotiation,
    );
    run_test(
        &mut summary,
        "transport_limits_enforcement",
        test_transport_limits_enforcement,
    );
    run_test(&mut summary, "session_id_binding", test_session_id_binding);
    run_test(&mut summary, "nonce_freshness", test_nonce_freshness);

    summary
}

fn run_test<F>(summary: &mut InteropTestSummary, name: &str, test_fn: F)
where
    F: FnOnce() -> Result<(), String>,
{
    summary.total += 1;
    match test_fn() {
        Ok(()) => summary.passed += 1,
        Err(msg) => {
            summary.failed += 1;
            summary.failures.push(TestFailure {
                name: name.to_string(),
                category: "session".to_string(),
                message: msg,
            });
        }
    }
}

/// Test: Session transcript bytes must be deterministic.
///
/// The transcript is built from Hello and Ack messages. Given the same inputs,
/// implementations must produce identical transcript bytes. This exercises
/// the HKDF-SHA256 derivation directly because the inputs are wire-format
/// vectors loaded from `crate::vectors::session::SessionGoldenVector`.
fn test_transcript_determinism() -> Result<(), String> {
    use crate::vectors::session::SessionGoldenVector;
    use fcp_crypto::{HkdfSha256, X25519SecretKey, hkdf_sha256_array};

    for (i, vector) in SessionGoldenVector::load_all().iter().enumerate() {
        let initiator_sk_bytes: [u8; 32] = hex::decode(&vector.initiator_ephemeral_sk)
            .map_err(|e| format!("Vector {}: invalid initiator sk hex: {e}", i + 1))?
            .try_into()
            .map_err(|_| format!("Vector {}: initiator sk wrong length", i + 1))?;
        let responder_sk_bytes: [u8; 32] = hex::decode(&vector.responder_ephemeral_sk)
            .map_err(|e| format!("Vector {}: invalid responder sk hex: {e}", i + 1))?
            .try_into()
            .map_err(|_| format!("Vector {}: responder sk wrong length", i + 1))?;

        let initiator_sk = X25519SecretKey::from_bytes(initiator_sk_bytes);
        let responder_sk = X25519SecretKey::from_bytes(responder_sk_bytes);

        let shared = initiator_sk
            .diffie_hellman(&responder_sk.public_key())
            .map_err(|e| format!("Vector {} ({}) DH failed: {e}", i + 1, vector.description))?;
        let computed_shared = hex::encode(shared.as_bytes());
        if computed_shared != vector.expected_shared_secret {
            return Err(format!(
                "Vector {} ({}) shared secret mismatch: expected {}, got {computed_shared}",
                i + 1,
                vector.description,
                vector.expected_shared_secret
            ));
        }

        let session_id = hex::decode(&vector.session_id)
            .map_err(|e| format!("Vector {}: invalid session_id hex: {e}", i + 1))?;
        let hello_nonce = hex::decode(&vector.hello_nonce)
            .map_err(|e| format!("Vector {}: invalid hello_nonce hex: {e}", i + 1))?;
        let ack_nonce = hex::decode(&vector.ack_nonce)
            .map_err(|e| format!("Vector {}: invalid ack_nonce hex: {e}", i + 1))?;

        let mut info = Vec::new();
        info.extend_from_slice(b"FCP2-SESSION-V1");
        info.push(vector.selected_suite.id());

        let init_bytes = vector.initiator_id.as_bytes();
        info.extend_from_slice(
            &u32::try_from(init_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        info.extend_from_slice(init_bytes);

        let resp_bytes = vector.responder_id.as_bytes();
        info.extend_from_slice(
            &u32::try_from(resp_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        info.extend_from_slice(resp_bytes);

        info.extend_from_slice(&hello_nonce);
        info.extend_from_slice(&ack_nonce);

        let prk: [u8; 32] = hkdf_sha256_array(Some(&session_id), shared.as_bytes(), &info)
            .map_err(|e| format!("Vector {}: HKDF error: {e}", i + 1))?;

        let hkdf = HkdfSha256::new(None, &prk);
        let okm: [u8; 96] = hkdf
            .expand_to_array(b"FCP2-SESSION-KEYS-V1")
            .map_err(|e| format!("Vector {}: HKDF expand error: {e}", i + 1))?;

        let computed_k_mac_i2r = hex::encode(&okm[0..32]);
        let computed_k_mac_r2i = hex::encode(&okm[32..64]);
        let computed_k_ctx = hex::encode(&okm[64..96]);

        if computed_k_mac_i2r != vector.expected_keys.k_mac_i2r {
            return Err(format!(
                "Vector {} ({}) k_mac_i2r mismatch: expected {}, got {computed_k_mac_i2r}",
                i + 1,
                vector.description,
                vector.expected_keys.k_mac_i2r
            ));
        }
        if computed_k_mac_r2i != vector.expected_keys.k_mac_r2i {
            return Err(format!(
                "Vector {} ({}) k_mac_r2i mismatch: expected {}, got {computed_k_mac_r2i}",
                i + 1,
                vector.description,
                vector.expected_keys.k_mac_r2i
            ));
        }
        if computed_k_ctx != vector.expected_keys.k_ctx {
            return Err(format!(
                "Vector {} ({}) k_ctx mismatch: expected {}, got {computed_k_ctx}",
                i + 1,
                vector.description,
                vector.expected_keys.k_ctx
            ));
        }
    }

    Ok(())
}

/// Test: Suite negotiation uses production `negotiate_suite` (br-t6wmw).
///
/// Pre-fix this called a local `&[&str]`-typed helper that bypassed the
/// production responder-picks invariant + `MINIMUM_SUITE` floor. The
/// production function uses real `SessionCryptoSuite` enum values and
/// rejects below-floor offerings.
fn test_suite_negotiation() -> Result<(), String> {
    use fcp_protocol::session::{SessionCryptoSuite, negotiate_suite};

    // Both peers offer Suite1 + Suite2; responder prefers Suite2 first.
    // Responder-picks: responder's first preference that initiator also
    // offers wins → Suite2.
    let initiator = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    let responder = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
    if negotiate_suite(&initiator, &responder) != Some(SessionCryptoSuite::Suite2) {
        return Err(format!(
            "Suite2 must win when responder prefers it first; got {:?}",
            negotiate_suite(&initiator, &responder)
        ));
    }

    // Initiator offers only Suite1; responder offers both → Suite1.
    let initiator = [SessionCryptoSuite::Suite1];
    let responder = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
    if negotiate_suite(&initiator, &responder) != Some(SessionCryptoSuite::Suite1) {
        return Err("Suite1 must win when only mutual offering".to_string());
    }

    // No overlap → None.
    let initiator = [SessionCryptoSuite::Suite1];
    let responder = [SessionCryptoSuite::Suite2];
    if negotiate_suite(&initiator, &responder).is_some() {
        return Err("Disjoint suite offerings must return None".to_string());
    }

    Ok(())
}

/// Test: `HelloRetry` cookie flow uses production `MeshSessionHelloRetry`
/// (br-t6wmw).
///
/// Pre-fix this asserted on a custom binary layout (`build_retry_hello`)
/// that had no relationship to the on-the-wire CBOR-encoded retry
/// envelope production uses.
fn test_hello_retry_cookie() -> Result<(), String> {
    use fcp_prelude::TailscaleNodeId;
    use fcp_protocol::session::{MeshSessionHelloRetry, SessionCookie, current_timestamp};

    let cookie_bytes = [0xA5u8; fcp_protocol::session::SESSION_COOKIE_SIZE];
    let retry = MeshSessionHelloRetry {
        from: TailscaleNodeId::new("node-responder"),
        to: TailscaleNodeId::new("node-initiator"),
        cookie: SessionCookie(cookie_bytes),
        timestamp: current_timestamp(),
    };

    if retry.cookie.0 != cookie_bytes {
        return Err("HelloRetry must preserve the cookie bytes verbatim".to_string());
    }
    if retry.from.as_str() != "node-responder" {
        return Err("HelloRetry from field must be the responder".to_string());
    }
    if retry.to.as_str() != "node-initiator" {
        return Err("HelloRetry to field must be the initiator".to_string());
    }
    if retry.timestamp == 0 {
        return Err("HelloRetry timestamp must be a real Unix epoch value".to_string());
    }

    // Round-trip via canonical CBOR to lock in the on-wire shape.
    let bytes = fcp_cbor::to_canonical_cbor(&retry)
        .map_err(|e| format!("MeshSessionHelloRetry CBOR encode failed: {e}"))?;
    let decoded: MeshSessionHelloRetry = ciborium::from_reader(&bytes[..])
        .map_err(|e| format!("MeshSessionHelloRetry CBOR decode failed: {e}"))?;
    if decoded.cookie.0 != cookie_bytes {
        return Err("HelloRetry CBOR round-trip lost the cookie bytes".to_string());
    }

    Ok(())
}

/// Test: `TransportLimits` negotiation uses production `TransportLimits`
/// (br-t6wmw).
///
/// Pre-fix this used a local 3-field `{max_datagram_bytes: u32,
/// max_frame_bytes: u32, max_symbols_per_frame: u32}` struct that does
/// not exist in production. Production `TransportLimits` is a single
/// `u16 max_datagram_bytes` wrapper. The conformance contract is the
/// minimum of the two peers' `max_datagram_bytes`.
fn test_transport_limits_negotiation() -> Result<(), String> {
    use fcp_protocol::session::TransportLimits;

    let initiator = TransportLimits {
        max_datagram_bytes: 9000,
    };
    let responder = TransportLimits {
        max_datagram_bytes: 1500,
    };

    let negotiated = TransportLimits {
        max_datagram_bytes: initiator
            .max_datagram_bytes
            .min(responder.max_datagram_bytes),
    };

    if negotiated.max_datagram_bytes != 1500 {
        return Err(format!(
            "negotiated max_datagram_bytes must be min(9000, 1500) = 1500, got {}",
            negotiated.max_datagram_bytes
        ));
    }

    // `effective_max` falls back to the protocol default when zero is set,
    // so a peer that advertises zero must NOT collapse the negotiated
    // window to zero — it picks up the default instead.
    let zero_peer = TransportLimits {
        max_datagram_bytes: 0,
    };
    if zero_peer.effective_max() == 0 {
        return Err("TransportLimits::effective_max(0) must fall back to the default".to_string());
    }

    Ok(())
}

/// Test: `TransportLimits` enforcement at the FCPS datagram boundary
/// (br-t6wmw).
///
/// Pre-fix this checked a local `is_datagram_valid` helper that was
/// detached from the production datagram decoder. Production enforces
/// `max_datagram_bytes` inside `FcpsDatagram::decode`.
fn test_transport_limits_enforcement() -> Result<(), String> {
    use fcp_protocol::session::FcpsDatagram;

    let max_datagram_bytes: u16 = 256;
    // Build a payload that exceeds the cap (header is fixed-size; the
    // datagram decoder rejects on `bytes.len() > max_datagram_bytes`).
    let oversize = vec![0u8; usize::from(max_datagram_bytes) + 1];
    match FcpsDatagram::decode(&oversize, max_datagram_bytes) {
        Err(_) => Ok(()),
        Ok(_) => Err(
            "FcpsDatagram::decode must refuse a datagram exceeding max_datagram_bytes".to_string(),
        ),
    }
}

/// Test: Session ID binding (HKDF input mixing).
///
/// Different session IDs with same keys must produce different derived keys.
/// This exercises the HKDF-SHA256 derivation directly because the binding
/// behavior under test is the salt mixing, not a session helper.
fn test_session_id_binding() -> Result<(), String> {
    use crate::vectors::session::SessionGoldenVector;
    use fcp_crypto::{HkdfSha256, X25519SecretKey, hkdf_sha256_array};

    let vector = SessionGoldenVector::vector_1_basic_handshake();

    let initiator_sk_bytes: [u8; 32] = hex::decode(&vector.initiator_ephemeral_sk)
        .map_err(|e| format!("invalid sk hex: {e}"))?
        .try_into()
        .map_err(|_| "sk wrong length")?;
    let responder_sk_bytes: [u8; 32] = hex::decode(&vector.responder_ephemeral_sk)
        .map_err(|e| format!("invalid sk hex: {e}"))?
        .try_into()
        .map_err(|_| "sk wrong length")?;

    let initiator_sk = X25519SecretKey::from_bytes(initiator_sk_bytes);
    let responder_sk = X25519SecretKey::from_bytes(responder_sk_bytes);
    let shared = initiator_sk
        .diffie_hellman(&responder_sk.public_key())
        .map_err(|e| format!("DH failed: {e}"))?;

    let session_id_1 = hex::decode(&vector.session_id).map_err(|e| format!("hex: {e}"))?;
    let hello_nonce = hex::decode(&vector.hello_nonce).map_err(|e| format!("hex: {e}"))?;
    let ack_nonce = hex::decode(&vector.ack_nonce).map_err(|e| format!("hex: {e}"))?;

    let mut info = Vec::new();
    info.extend_from_slice(b"FCP2-SESSION-V1");
    info.push(vector.selected_suite.id());

    let init_bytes = vector.initiator_id.as_bytes();
    info.extend_from_slice(
        &u32::try_from(init_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    info.extend_from_slice(init_bytes);

    let resp_bytes = vector.responder_id.as_bytes();
    info.extend_from_slice(
        &u32::try_from(resp_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    info.extend_from_slice(resp_bytes);

    info.extend_from_slice(&hello_nonce);
    info.extend_from_slice(&ack_nonce);

    let prk1: [u8; 32] = hkdf_sha256_array(Some(&session_id_1), shared.as_bytes(), &info)
        .map_err(|e| format!("hkdf: {e}"))?;

    let session_id_2 = vec![0xFFu8; 16];
    let prk2: [u8; 32] = hkdf_sha256_array(Some(&session_id_2), shared.as_bytes(), &info)
        .map_err(|e| format!("hkdf: {e}"))?;

    if prk1 == prk2 {
        return Err("Different session IDs produced same PRK".to_string());
    }

    let hkdf1 = HkdfSha256::new(None, &prk1);
    let hkdf2 = HkdfSha256::new(None, &prk2);

    let okm1: [u8; 96] = hkdf1
        .expand_to_array(b"FCP2-SESSION-KEYS-V1")
        .map_err(|e| format!("expand: {e}"))?;
    let okm2: [u8; 96] = hkdf2
        .expand_to_array(b"FCP2-SESSION-KEYS-V1")
        .map_err(|e| format!("expand: {e}"))?;

    if okm1 == okm2 {
        return Err("Different session IDs produced same OKM".to_string());
    }

    Ok(())
}

/// Test: Hello-nonce freshness uses production `HelloReplayWindow`
/// (br-t6wmw).
///
/// Pre-fix this maintained a local `HashSet<[u8; 16]>` keyed on the raw
/// nonce bytes. Production `HelloReplayWindow` keys on `(from, nonce)`
/// so two distinct senders can legitimately use overlapping nonces, and
/// a single sender that replays a nonce inside the window is rejected.
/// This rewrite asserts that production behavior, not the local
/// over-strict approximation.
fn test_nonce_freshness() -> Result<(), String> {
    use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
    use fcp_prelude::TailscaleNodeId;
    use fcp_protocol::session::{
        HelloReplayWindow, MeshSessionHello, SessionCryptoSuite, SessionNonce, current_timestamp,
    };

    fn signed_hello(
        from: &str,
        nonce: [u8; 16],
        signing_key: &Ed25519SigningKey,
    ) -> MeshSessionHello {
        let eph_key = X25519SecretKey::generate();
        let mut hello = MeshSessionHello {
            from: TailscaleNodeId::new(from),
            to: TailscaleNodeId::new("node-responder"),
            eph_pubkey: eph_key.public_key(),
            nonce: SessionNonce(nonce),
            cookie: None,
            timestamp: current_timestamp(),
            suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
            transport_limits: None,
            signature: None,
        };
        hello.sign(signing_key).expect("sign hello");
        hello
    }

    let signing_key = Ed25519SigningKey::generate();
    let mut window = HelloReplayWindow::default();

    let nonce_a = [0x11u8; 16];
    let hello_a = signed_hello("node-alice", nonce_a, &signing_key);
    if !window.check_and_update(&hello_a) {
        return Err("First hello with nonce_a from alice must be accepted".to_string());
    }

    // Same sender, same nonce → replay must reject.
    let hello_a_replay = hello_a.clone();
    if window.check_and_update(&hello_a_replay) {
        return Err("Replayed hello (same from, same nonce) must be rejected".to_string());
    }

    // Different sender, same nonce → MUST accept (window keys on (from, nonce)).
    let hello_b = signed_hello("node-bob", nonce_a, &signing_key);
    if !window.check_and_update(&hello_b) {
        return Err(
            "Same nonce from a DIFFERENT sender must be accepted — window keys on (from, nonce)"
                .to_string(),
        );
    }

    // Same sender, different nonce → must accept.
    let nonce_c = [0x22u8; 16];
    let hello_c = signed_hello("node-alice", nonce_c, &signing_key);
    if !window.check_and_update(&hello_c) {
        return Err("Fresh nonce from alice must be accepted".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_interop_tests_pass() {
        let summary = run_tests();
        for failure in &summary.failures {
            eprintln!("FAIL: {} - {}", failure.name, failure.message);
        }
        assert!(
            summary.all_passed(),
            "Session interop tests failed: {}/{} passed",
            summary.passed,
            summary.total
        );
    }

    #[test]
    fn session_interop_via_struct() {
        let summary = SessionInteropTests::run();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 7);
    }
}
