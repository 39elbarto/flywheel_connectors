//! Session handshake interop tests.
//!
//! Tests for MeshSessionHello/Ack transcript verification, `HelloRetry` cookie flow,
//! and `TransportLimits` negotiation.

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

    // Test 1: Transcript bytes are deterministic
    run_test(
        &mut summary,
        "transcript_determinism",
        test_transcript_determinism,
    );

    // Test 2: Suite negotiation is deterministic
    run_test(&mut summary, "suite_negotiation", test_suite_negotiation);

    // Test 3: HelloRetry cookie flow
    run_test(&mut summary, "hello_retry_cookie", test_hello_retry_cookie);

    // Test 4: TransportLimits negotiation
    run_test(
        &mut summary,
        "transport_limits_negotiation",
        test_transport_limits_negotiation,
    );

    // Test 5: TransportLimits enforcement
    run_test(
        &mut summary,
        "transport_limits_enforcement",
        test_transport_limits_enforcement,
    );

    // Test 6: Session ID binding
    run_test(&mut summary, "session_id_binding", test_session_id_binding);

    // Test 7: Nonce freshness
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
/// implementations must produce identical transcript bytes.
fn test_transcript_determinism() -> Result<(), String> {
    use crate::vectors::session::SessionGoldenVector;
    use fcp_crypto::{HkdfSha256, X25519SecretKey, hkdf_sha256_array};

    // Load all vectors and verify they produce consistent transcripts
    for (i, vector) in SessionGoldenVector::load_all().iter().enumerate() {
        // Parse keys
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

        // Verify shared secret
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

        // Verify key derivation
        let session_id = hex::decode(&vector.session_id)
            .map_err(|e| format!("Vector {}: invalid session_id hex: {e}", i + 1))?;
        let hello_nonce = hex::decode(&vector.hello_nonce)
            .map_err(|e| format!("Vector {}: invalid hello_nonce hex: {e}", i + 1))?;
        let ack_nonce = hex::decode(&vector.ack_nonce)
            .map_err(|e| format!("Vector {}: invalid ack_nonce hex: {e}", i + 1))?;

        let mut info = Vec::new();
        info.extend_from_slice(b"FCP2-SESSION-V1");

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

/// Test: Suite negotiation must be deterministic.
///
/// Given the same offered + supported suites, implementations must select
/// the same suite. Negotiation uses responder-picks semantics (see
/// `docs/protocol/session-handshake.md`): the responder's first-preferred
/// suite that the initiator also offers wins.
fn test_suite_negotiation() -> Result<(), String> {
    // Suite priority order (NORMATIVE, responder-preference):
    // 1. Suite2 (ChaCha20-Poly1305 + BLAKE3)
    // 2. Suite1 (AES-256-GCM + SHA-256)
    //
    // Initiator offers [Suite1, Suite2], responder supports [Suite2]
    // Result: Suite2 (only mutually-supported suite)

    let offered = ["Suite1", "Suite2"];
    let supported = ["Suite2"];

    let selected = negotiate_suite(&offered, &supported);
    if selected != Some("Suite2") {
        return Err(format!("Expected Suite2, got {selected:?}"));
    }

    // Initiator offers [Suite1], responder supports [Suite1, Suite2]
    // Result: Suite1
    let offered = ["Suite1"];
    let supported = ["Suite1", "Suite2"];
    let selected = negotiate_suite(&offered, &supported);
    if selected != Some("Suite1") {
        return Err(format!("Expected Suite1, got {selected:?}"));
    }

    // No common suite
    let offered = ["Suite1"];
    let supported = ["Suite2"];
    let selected = negotiate_suite(&offered, &supported);
    if selected.is_some() {
        return Err(format!("Expected None, got {selected:?}"));
    }

    Ok(())
}

/// Negotiate a suite from offered and supported lists.
///
/// Uses **responder-picks** semantics: the responder's (supported) first-
/// preferred suite that the initiator (offered) also supports is chosen.
/// Mirrors `fcp_protocol::session::negotiate_suite`. See
/// `docs/protocol/session-handshake.md` for the invariant.
fn negotiate_suite<'a>(offered: &[&str], supported: &[&'a str]) -> Option<&'a str> {
    supported
        .iter()
        .copied()
        .find(|suite| offered.contains(suite))
}

/// Test: `HelloRetry` cookie flow.
///
/// When the responder requests retry, initiator must include the cookie
/// in the retry Hello message.
fn test_hello_retry_cookie() -> Result<(), String> {
    // Simulate HelloRetry flow:
    // 1. Initiator sends Hello
    // 2. Responder sends HelloRetry with cookie
    // 3. Initiator sends Hello with cookie
    // 4. Responder sends Ack

    let cookie = b"test-cookie-12345678";

    // The retry Hello must include the cookie in the correct position
    let retry_hello = build_retry_hello(cookie);

    // Verify cookie is present using slice search
    let contains_cookie = retry_hello
        .windows(cookie.len())
        .any(|window| window == cookie);
    if !contains_cookie {
        return Err("Retry Hello missing cookie".to_string());
    }

    // Cookie must be bound to session transcript
    // Minimum size: magic(4) + version(2) + flags(2) + cookie_len(2) + cookie + nonce(16) + pk(32)
    let min_size = 4 + 2 + 2 + 2 + cookie.len() + 16 + 32;
    if retry_hello.len() < min_size {
        return Err(format!(
            "Retry Hello too short: {} < {}",
            retry_hello.len(),
            min_size
        ));
    }

    Ok(())
}

/// Build a retry Hello message with the given cookie.
fn build_retry_hello(cookie: &[u8]) -> Vec<u8> {
    // Simplified Hello structure for testing:
    // [magic: 4] [version: 2] [flags: 2] [cookie_len: 2] [cookie: N] [nonce: 16] [pk: 32]
    let mut msg = Vec::new();
    msg.extend_from_slice(b"FCPH"); // Magic
    msg.extend_from_slice(&1u16.to_le_bytes()); // Version
    msg.extend_from_slice(&0x01u16.to_le_bytes()); // Flags: HAS_COOKIE
    #[allow(clippy::cast_possible_truncation)] // Cookie length is known to fit in u16
    msg.extend_from_slice(&(cookie.len() as u16).to_le_bytes());
    msg.extend_from_slice(cookie);
    msg.extend_from_slice(&[0u8; 16]); // Nonce
    msg.extend_from_slice(&[0u8; 32]); // Public key placeholder
    msg
}

/// Test: `TransportLimits` negotiation.
///
/// Implementations must agree on limits that satisfy both parties' constraints.
fn test_transport_limits_negotiation() -> Result<(), String> {
    // TransportLimits fields:
    // - max_datagram_bytes: u32
    // - max_frame_bytes: u32
    // - max_symbols_per_frame: u32

    // Initiator proposes, responder accepts or counter-proposes
    let initiator_limits = TransportLimits {
        max_datagram_bytes: 65535,
        max_frame_bytes: 1_048_576,
        max_symbols_per_frame: 1000,
    };

    let responder_limits = TransportLimits {
        max_datagram_bytes: 32768,
        max_frame_bytes: 524_288,
        max_symbols_per_frame: 500,
    };

    // Negotiated limits are the minimum of each field
    let negotiated = negotiate_limits(&initiator_limits, &responder_limits);

    if negotiated.max_datagram_bytes != 32768 {
        return Err(format!(
            "max_datagram_bytes should be 32768, got {}",
            negotiated.max_datagram_bytes
        ));
    }
    if negotiated.max_frame_bytes != 524_288 {
        return Err(format!(
            "max_frame_bytes should be 524_288, got {}",
            negotiated.max_frame_bytes
        ));
    }
    if negotiated.max_symbols_per_frame != 500 {
        return Err(format!(
            "max_symbols_per_frame should be 500, got {}",
            negotiated.max_symbols_per_frame
        ));
    }

    Ok(())
}

/// Transport limits for session negotiation.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)] // max_ prefix is semantically meaningful
struct TransportLimits {
    max_datagram_bytes: u32,
    max_frame_bytes: u32,
    max_symbols_per_frame: u32,
}

/// Negotiate transport limits (take minimum of each field).
fn negotiate_limits(a: &TransportLimits, b: &TransportLimits) -> TransportLimits {
    TransportLimits {
        max_datagram_bytes: a.max_datagram_bytes.min(b.max_datagram_bytes),
        max_frame_bytes: a.max_frame_bytes.min(b.max_frame_bytes),
        max_symbols_per_frame: a.max_symbols_per_frame.min(b.max_symbols_per_frame),
    }
}

/// Test: `TransportLimits` enforcement.
///
/// Datagrams exceeding negotiated limits must be rejected.
fn test_transport_limits_enforcement() -> Result<(), String> {
    let limits = TransportLimits {
        max_datagram_bytes: 1024,
        max_frame_bytes: 4096,
        max_symbols_per_frame: 10,
    };

    // Datagram within limits
    let valid_datagram = vec![0u8; 1024];
    if !is_datagram_valid(&valid_datagram, &limits) {
        return Err("Valid datagram rejected".to_string());
    }

    // Datagram exceeding limits
    let invalid_datagram = vec![0u8; 1025];
    if is_datagram_valid(&invalid_datagram, &limits) {
        return Err("Invalid datagram accepted".to_string());
    }

    Ok(())
}

/// Check if datagram is within transport limits.
const fn is_datagram_valid(datagram: &[u8], limits: &TransportLimits) -> bool {
    datagram.len() <= limits.max_datagram_bytes as usize
}

/// Test: Session ID binding.
///
/// Different session IDs with same keys must produce different derived keys.
fn test_session_id_binding() -> Result<(), String> {
    use crate::vectors::session::SessionGoldenVector;
    use fcp_crypto::{HkdfSha256, X25519SecretKey, hkdf_sha256_array};

    let vector = SessionGoldenVector::vector_1_basic_handshake();

    // Parse keys
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

    // Derive keys with original session ID
    let session_id_1 = hex::decode(&vector.session_id).map_err(|e| format!("hex: {e}"))?;
    let hello_nonce = hex::decode(&vector.hello_nonce).map_err(|e| format!("hex: {e}"))?;
    let ack_nonce = hex::decode(&vector.ack_nonce).map_err(|e| format!("hex: {e}"))?;

    let mut info = Vec::new();
    info.extend_from_slice(b"FCP2-SESSION-V1");

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

    // Derive keys with different session ID
    let session_id_2 = vec![0xFFu8; 16];
    let prk2: [u8; 32] = hkdf_sha256_array(Some(&session_id_2), shared.as_bytes(), &info)
        .map_err(|e| format!("hkdf: {e}"))?;

    // Keys must differ
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

/// Test: Nonce freshness.
///
/// Replaying a Hello with the same nonce must be rejected.
fn test_nonce_freshness() -> Result<(), String> {
    // Simulate replay detection
    let mut seen_nonces: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();

    let nonce1 = [1u8; 16];
    let nonce2 = [2u8; 16];

    // First use of nonce1 should succeed
    if !is_nonce_fresh(&nonce1, &mut seen_nonces) {
        return Err("Fresh nonce rejected".to_string());
    }

    // Second use of nonce1 should fail (replay)
    if is_nonce_fresh(&nonce1, &mut seen_nonces) {
        return Err("Replayed nonce accepted".to_string());
    }

    // First use of nonce2 should succeed
    if !is_nonce_fresh(&nonce2, &mut seen_nonces) {
        return Err("Second fresh nonce rejected".to_string());
    }

    Ok(())
}

/// Check if nonce is fresh (not seen before).
fn is_nonce_fresh(nonce: &[u8; 16], seen: &mut std::collections::HashSet<[u8; 16]>) -> bool {
    seen.insert(*nonce)
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
    fn test_negotiate_suite() {
        assert_eq!(
            negotiate_suite(&["Suite1", "Suite2"], &["Suite2"]),
            Some("Suite2")
        );
        assert_eq!(negotiate_suite(&["Suite1"], &["Suite2"]), None);
    }

    #[test]
    fn test_negotiate_limits() {
        let a = TransportLimits {
            max_datagram_bytes: 1000,
            max_frame_bytes: 2000,
            max_symbols_per_frame: 100,
        };
        let b = TransportLimits {
            max_datagram_bytes: 500,
            max_frame_bytes: 3000,
            max_symbols_per_frame: 50,
        };
        let result = negotiate_limits(&a, &b);
        assert_eq!(result.max_datagram_bytes, 500);
        assert_eq!(result.max_frame_bytes, 2000);
        assert_eq!(result.max_symbols_per_frame, 50);
    }

    // ─── negotiate_suite edge cases ───

    #[test]
    fn negotiate_suite_empty_offered() {
        let empty: [&str; 0] = [];
        assert_eq!(negotiate_suite(&empty, &["Suite1"]), None);
    }

    #[test]
    fn negotiate_suite_empty_supported() {
        let empty: [&str; 0] = [];
        assert_eq!(negotiate_suite(&["Suite1"], &empty), None);
    }

    #[test]
    fn negotiate_suite_both_empty() {
        let empty: [&str; 0] = [];
        assert_eq!(negotiate_suite(&empty, &empty), None);
    }

    #[test]
    fn negotiate_suite_responder_first_preference_wins() {
        // Responder-picks: supported list's first-preferred mutual suite wins.
        // Initiator offers [Suite1, Suite2]; responder prefers Suite2 (first in supported).
        assert_eq!(
            negotiate_suite(&["Suite1", "Suite2"], &["Suite2", "Suite1"]),
            Some("Suite2")
        );
    }

    #[test]
    fn negotiate_suite_single_common() {
        assert_eq!(
            negotiate_suite(&["A", "B", "C"], &["X", "Y", "C"]),
            Some("C")
        );
    }

    // ─── negotiate_limits edge cases ───

    #[test]
    fn negotiate_limits_identical() {
        let limits = TransportLimits {
            max_datagram_bytes: 1024,
            max_frame_bytes: 4096,
            max_symbols_per_frame: 100,
        };
        let result = negotiate_limits(&limits, &limits);
        assert_eq!(result.max_datagram_bytes, 1024);
        assert_eq!(result.max_frame_bytes, 4096);
        assert_eq!(result.max_symbols_per_frame, 100);
    }

    #[test]
    fn negotiate_limits_zero_values() {
        let a = TransportLimits {
            max_datagram_bytes: 0,
            max_frame_bytes: 0,
            max_symbols_per_frame: 0,
        };
        let b = TransportLimits {
            max_datagram_bytes: 1000,
            max_frame_bytes: 1000,
            max_symbols_per_frame: 1000,
        };
        let result = negotiate_limits(&a, &b);
        assert_eq!(result.max_datagram_bytes, 0);
        assert_eq!(result.max_frame_bytes, 0);
        assert_eq!(result.max_symbols_per_frame, 0);
    }

    // ─── build_retry_hello structure ───

    #[test]
    fn retry_hello_magic_prefix() {
        let hello = build_retry_hello(b"cookie");
        assert_eq!(&hello[..4], b"FCPH");
    }

    #[test]
    fn retry_hello_version_field() {
        let hello = build_retry_hello(b"cookie");
        let version = u16::from_le_bytes([hello[4], hello[5]]);
        assert_eq!(version, 1);
    }

    #[test]
    fn retry_hello_flags_has_cookie() {
        let hello = build_retry_hello(b"cookie");
        let flags = u16::from_le_bytes([hello[6], hello[7]]);
        assert_eq!(flags, 0x01);
    }

    #[test]
    fn retry_hello_cookie_length_field() {
        let cookie = b"test-cookie-123";
        let hello = build_retry_hello(cookie);
        let cookie_len = u16::from_le_bytes([hello[8], hello[9]]);
        assert_eq!(cookie_len as usize, cookie.len());
    }

    #[test]
    fn retry_hello_cookie_embedded() {
        let cookie = b"unique-cookie-value";
        let hello = build_retry_hello(cookie);
        assert_eq!(&hello[10..10 + cookie.len()], cookie);
    }

    #[test]
    fn retry_hello_total_length() {
        let cookie = b"cookie";
        let hello = build_retry_hello(cookie);
        // 4 + 2 + 2 + 2 + cookie.len() + 16 + 32
        assert_eq!(hello.len(), 4 + 2 + 2 + 2 + cookie.len() + 16 + 32);
    }

    #[test]
    fn retry_hello_empty_cookie() {
        let hello = build_retry_hello(b"");
        let cookie_len = u16::from_le_bytes([hello[8], hello[9]]);
        assert_eq!(cookie_len, 0);
        assert_eq!(hello.len(), 4 + 2 + 2 + 2 + 16 + 32);
    }

    // ─── is_datagram_valid boundary ───

    #[test]
    fn datagram_valid_exactly_at_limit() {
        let limits = TransportLimits {
            max_datagram_bytes: 100,
            max_frame_bytes: 1000,
            max_symbols_per_frame: 10,
        };
        assert!(is_datagram_valid(&[0u8; 100], &limits));
        assert!(!is_datagram_valid(&[0u8; 101], &limits));
    }

    #[test]
    fn datagram_valid_empty() {
        let limits = TransportLimits {
            max_datagram_bytes: 100,
            max_frame_bytes: 1000,
            max_symbols_per_frame: 10,
        };
        assert!(is_datagram_valid(&[], &limits));
    }

    // ─── is_nonce_fresh edge cases ───

    #[test]
    fn nonce_fresh_all_zeros() {
        let mut seen = std::collections::HashSet::new();
        let zero = [0u8; 16];
        assert!(is_nonce_fresh(&zero, &mut seen));
        assert!(!is_nonce_fresh(&zero, &mut seen));
    }

    #[test]
    fn nonce_fresh_many_distinct() {
        let mut seen = std::collections::HashSet::new();
        for i in 0u16..100 {
            let mut nonce = [0u8; 16];
            nonce[0..2].copy_from_slice(&i.to_le_bytes());
            assert!(is_nonce_fresh(&nonce, &mut seen));
        }
        assert_eq!(seen.len(), 100);
    }

    // ─── SessionInteropTests struct ───

    #[test]
    fn session_interop_via_struct() {
        let summary = SessionInteropTests::run();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 7);
    }

    // ── negotiate_suite: additional tests ──

    #[test]
    fn negotiate_suite_preserves_supported_order() {
        // Responder-picks: first suite in `supported` that is in `offered` wins.
        // Offered: [C, A, B]; supported: [B, A] → B (first mutual in supported order).
        assert_eq!(negotiate_suite(&["C", "A", "B"], &["B", "A"]), Some("B"));
    }

    #[test]
    fn negotiate_suite_duplicate_in_offered() {
        // Supported first: [Y, X]; Y is in offered → Y wins.
        assert_eq!(negotiate_suite(&["X", "X", "Y"], &["Y", "X"]), Some("Y"));
    }

    // ── negotiate_limits: additional tests ──

    #[test]
    fn negotiate_limits_max_values() {
        let max = TransportLimits {
            max_datagram_bytes: u32::MAX,
            max_frame_bytes: u32::MAX,
            max_symbols_per_frame: u32::MAX,
        };
        let small = TransportLimits {
            max_datagram_bytes: 100,
            max_frame_bytes: 200,
            max_symbols_per_frame: 5,
        };
        let result = negotiate_limits(&max, &small);
        assert_eq!(result.max_datagram_bytes, 100);
        assert_eq!(result.max_frame_bytes, 200);
        assert_eq!(result.max_symbols_per_frame, 5);
    }

    #[test]
    fn negotiate_limits_symmetric() {
        let a = TransportLimits {
            max_datagram_bytes: 500,
            max_frame_bytes: 1000,
            max_symbols_per_frame: 10,
        };
        let b = TransportLimits {
            max_datagram_bytes: 800,
            max_frame_bytes: 600,
            max_symbols_per_frame: 20,
        };
        let ab = negotiate_limits(&a, &b);
        let ba = negotiate_limits(&b, &a);
        assert_eq!(ab.max_datagram_bytes, ba.max_datagram_bytes);
        assert_eq!(ab.max_frame_bytes, ba.max_frame_bytes);
        assert_eq!(ab.max_symbols_per_frame, ba.max_symbols_per_frame);
    }

    // ── build_retry_hello: additional tests ──

    #[test]
    fn retry_hello_large_cookie() {
        let cookie = vec![0xABu8; 1024];
        let hello = build_retry_hello(&cookie);
        let cookie_len = u16::from_le_bytes([hello[8], hello[9]]);
        assert_eq!(cookie_len, 1024);
        assert_eq!(&hello[10..10 + 1024], cookie.as_slice());
    }

    // ── is_datagram_valid: additional tests ──

    #[test]
    fn datagram_valid_zero_max() {
        let limits = TransportLimits {
            max_datagram_bytes: 0,
            max_frame_bytes: 0,
            max_symbols_per_frame: 0,
        };
        assert!(is_datagram_valid(&[], &limits));
        assert!(!is_datagram_valid(&[0], &limits));
    }

    // ── is_nonce_fresh: additional tests ──

    #[test]
    fn nonce_fresh_all_ones() {
        let mut seen = std::collections::HashSet::new();
        let all_ones = [0xFF; 16];
        assert!(is_nonce_fresh(&all_ones, &mut seen));
        assert!(!is_nonce_fresh(&all_ones, &mut seen));
    }

    // ── TransportLimits Debug and Copy ──

    #[test]
    fn transport_limits_debug() {
        let limits = TransportLimits {
            max_datagram_bytes: 1280,
            max_frame_bytes: 4096,
            max_symbols_per_frame: 50,
        };
        let dbg = format!("{limits:?}");
        assert!(dbg.contains("TransportLimits"));
        assert!(dbg.contains("1280"));
    }

    #[test]
    fn transport_limits_copy() {
        let a = TransportLimits {
            max_datagram_bytes: 100,
            max_frame_bytes: 200,
            max_symbols_per_frame: 10,
        };
        let b = a;
        assert_eq!(a.max_datagram_bytes, b.max_datagram_bytes);
        assert_eq!(a.max_frame_bytes, b.max_frame_bytes);
    }
}
