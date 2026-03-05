//! FCPS data-plane interop tests.
//!
//! Tests for `FCPS_DATAGRAM` envelope, frame parsing, replay windows,
//! and per-symbol AEAD verification.

use crate::{InteropTestSummary, TestFailure};

/// FCPS interop test suite.
pub struct FcpsInteropTests;

impl FcpsInteropTests {
    /// Run all FCPS interop tests.
    #[must_use]
    pub fn run() -> InteropTestSummary {
        run_tests()
    }
}

/// Run all FCPS interop tests.
pub fn run_tests() -> InteropTestSummary {
    let mut summary = InteropTestSummary::default();

    // Test 1: MAC computation for Suite1 (AES-256-GCM)
    run_test(&mut summary, "mac_suite1", test_mac_suite1);

    // Test 2: MAC computation for Suite2 (ChaCha20-Poly1305)
    run_test(&mut summary, "mac_suite2", test_mac_suite2);

    // Test 3: Bounded replay window
    run_test(&mut summary, "replay_window", test_replay_window);

    // Test 4: MTU enforcement
    run_test(&mut summary, "mtu_enforcement", test_mtu_enforcement);

    // Test 5: Frame header parsing
    run_test(&mut summary, "header_parsing", test_header_parsing);

    // Test 6: Symbol record bounds
    run_test(&mut summary, "symbol_bounds", test_symbol_bounds);

    // Test 7: Per-symbol AEAD nonce derivation
    run_test(
        &mut summary,
        "aead_nonce_derivation",
        test_aead_nonce_derivation,
    );

    // Test 8: Per-symbol AEAD AAD binding
    run_test(&mut summary, "aead_aad_binding", test_aead_aad_binding);

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
                category: "fcps".to_string(),
                message: msg,
            });
        }
    }
}

/// Test: MAC computation for Suite1 (BLAKE3 keyed MAC).
fn test_mac_suite1() -> Result<(), String> {
    use fcp_crypto::{MacKey, blake3_mac_full};

    // Test vector: BLAKE3 keyed MAC with known key and data
    let k_mac = MacKey::from_bytes([0x01u8; 32]);
    let session_id = [0x02u8; 16];
    let seq: u64 = 1;

    // Compute MAC input: session_id || seq (LE) || payload
    let payload = b"test payload";
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&session_id);
    mac_input.extend_from_slice(&seq.to_le_bytes());
    mac_input.extend_from_slice(payload);

    let mac = blake3_mac_full(&k_mac, &mac_input);

    // MAC should be 32 bytes
    if mac.len() != 32 {
        return Err(format!("MAC length {} != 32", mac.len()));
    }

    // Same inputs should produce same MAC (deterministic)
    let mac2 = blake3_mac_full(&k_mac, &mac_input);
    if mac != mac2 {
        return Err("MAC computation not deterministic".to_string());
    }

    // Different seq should produce different MAC
    let mut mac_input_diff = Vec::new();
    mac_input_diff.extend_from_slice(&session_id);
    mac_input_diff.extend_from_slice(&2u64.to_le_bytes()); // Different seq
    mac_input_diff.extend_from_slice(payload);
    let mac3 = blake3_mac_full(&k_mac, &mac_input_diff);
    if mac == mac3 {
        return Err("Different seq produced same MAC".to_string());
    }

    Ok(())
}

/// Test: MAC computation for Suite2 (Poly1305).
fn test_mac_suite2() -> Result<(), String> {
    // Suite2 uses ChaCha20-Poly1305 for MAC
    // The MAC is the Poly1305 tag from AEAD encryption

    // For interop, we verify that:
    // 1. Tag is 16 bytes
    // 2. Same inputs produce same tag
    // 3. Different inputs produce different tag

    use fcp_crypto::{AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher};

    let key = AeadKey::from_bytes([0x03u8; 32]);
    let nonce = ChaCha20Nonce::from_bytes([0x04u8; 12]);
    let aad = b"session_id || seq";
    let plaintext = b"test payload";

    let cipher = ChaCha20Poly1305Cipher::new(&key);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext, aad)
        .map_err(|e| format!("encrypt failed: {e}"))?;

    // Ciphertext = plaintext + 16-byte tag
    if ciphertext.len() != plaintext.len() + 16 {
        return Err(format!(
            "Ciphertext length {} != plaintext {} + 16",
            ciphertext.len(),
            plaintext.len()
        ));
    }

    // Decrypt should recover plaintext
    let decrypted = cipher
        .decrypt(&nonce, &ciphertext, aad)
        .map_err(|e| format!("decrypt failed: {e}"))?;
    if decrypted != plaintext {
        return Err("Decrypted plaintext mismatch".to_string());
    }

    // Wrong nonce should fail decryption
    let wrong_nonce = ChaCha20Nonce::from_bytes([0x05u8; 12]);
    if cipher.decrypt(&wrong_nonce, &ciphertext, aad).is_ok() {
        return Err("Decryption with wrong nonce should fail".to_string());
    }

    // Wrong AAD should fail decryption
    let wrong_aad = b"wrong_aad";
    if cipher.decrypt(&nonce, &ciphertext, wrong_aad).is_ok() {
        return Err("Decryption with wrong AAD should fail".to_string());
    }

    Ok(())
}

/// Test: Bounded replay window behavior.
fn test_replay_window() -> Result<(), String> {
    // FCPS uses a bounded replay window to detect replayed/reordered datagrams
    // Default window size: 64 sequence numbers

    let mut window = ReplayWindow::new(64);

    // Sequence 0 should be accepted
    if !window.accept(0) {
        return Err("Seq 0 rejected".to_string());
    }

    // Replay of seq 0 should be rejected
    if window.accept(0) {
        return Err("Replay of seq 0 accepted".to_string());
    }

    // Sequences 1-63 should be accepted (within window)
    for seq in 1..64 {
        if !window.accept(seq) {
            return Err(format!("Seq {seq} rejected"));
        }
    }

    // Sequence 64 should be accepted and slide window
    if !window.accept(64) {
        return Err("Seq 64 rejected".to_string());
    }

    // Now seq 0 should be rejected (outside window after slide)
    // The window is now [1, 64], so 0 is too old
    if window.accept(0) {
        return Err("Old seq 0 accepted after window slide".to_string());
    }

    // Out-of-order within window should work
    // Reset window for this test
    let mut window2 = ReplayWindow::new(64);
    window2.accept(10); // Mark 10 as seen
    window2.accept(5); // 5 is within window of 10

    if window2.accept(5) {
        return Err("Replay of seq 5 accepted".to_string());
    }

    // But 4 should still be acceptable
    if !window2.accept(4) {
        return Err("Seq 4 rejected".to_string());
    }

    Ok(())
}

/// Replay window for sequence numbers.
struct ReplayWindow {
    size: u64,
    highest_seen: u64,
    seen_bitmap: u64,
}

impl ReplayWindow {
    fn new(size: u64) -> Self {
        Self {
            size: size.min(64), // Max 64 bits in bitmap
            highest_seen: 0,
            seen_bitmap: 0,
        }
    }

    const fn accept(&mut self, seq: u64) -> bool {
        if seq > self.highest_seen {
            // New highest: slide window
            let diff = seq - self.highest_seen;
            if diff >= self.size {
                self.seen_bitmap = 1; // Only current seq is set
            } else {
                self.seen_bitmap <<= diff;
                self.seen_bitmap |= 1;
            }
            self.highest_seen = seq;
            true
        } else if self.highest_seen - seq >= self.size {
            // Too old: outside window
            false
        } else {
            // Within window: check/set bitmap
            let bit_index = self.highest_seen - seq;
            let mask = 1u64 << bit_index;
            if self.seen_bitmap & mask != 0 {
                false // Already seen
            } else {
                self.seen_bitmap |= mask;
                true
            }
        }
    }
}

/// Test: MTU enforcement.
fn test_mtu_enforcement() -> Result<(), String> {
    // FCPS datagrams must not exceed the negotiated MTU
    // Default MTU: 1280 bytes (IPv6 minimum)

    let mtu = 1280u32;

    // Datagram at exactly MTU should be valid
    let valid_datagram = vec![0u8; mtu as usize];
    if !is_within_mtu(&valid_datagram, mtu) {
        return Err("Datagram at MTU rejected".to_string());
    }

    // Datagram exceeding MTU should be invalid
    let invalid_datagram = vec![0u8; (mtu + 1) as usize];
    if is_within_mtu(&invalid_datagram, mtu) {
        return Err("Datagram exceeding MTU accepted".to_string());
    }

    Ok(())
}

const fn is_within_mtu(datagram: &[u8], mtu: u32) -> bool {
    datagram.len() <= mtu as usize
}

/// Test: Frame header parsing.
fn test_header_parsing() -> Result<(), String> {
    use crate::vectors::fcps::FcpsGoldenVector;

    // All golden vectors should parse correctly
    for (i, vector) in FcpsGoldenVector::load_all().iter().enumerate() {
        vector.verify().map_err(|e| {
            format!(
                "Vector {} ({}) header parsing failed: {}",
                i + 1,
                vector.description,
                e
            )
        })?;
    }

    Ok(())
}

/// Test: Symbol record bounds checking.
fn test_symbol_bounds() -> Result<(), String> {
    // Symbol records must fit within declared total_payload_len
    // ESI (4) + K (2) + data (symbol_size) + auth_tag (16) = 22 + symbol_size

    let symbol_size = 1024u16;
    let record_size = 22 + symbol_size as usize;

    // 10 symbols should require exactly 10 * record_size bytes
    let symbol_count = 10u32;
    let total_payload_len = symbol_count as usize * record_size;

    // Verify calculation
    let expected = 10 * (22 + 1024);
    if total_payload_len != expected {
        return Err(format!(
            "Payload length {total_payload_len} != expected {expected}"
        ));
    }

    // Parsing should fail if payload is truncated
    let truncated_payload = vec![0u8; total_payload_len - 1];
    if is_payload_complete(&truncated_payload, symbol_count, symbol_size) {
        return Err("Truncated payload accepted".to_string());
    }

    // Parsing should succeed with exact payload
    let exact_payload = vec![0u8; total_payload_len];
    if !is_payload_complete(&exact_payload, symbol_count, symbol_size) {
        return Err("Exact payload rejected".to_string());
    }

    Ok(())
}

const fn is_payload_complete(payload: &[u8], symbol_count: u32, symbol_size: u16) -> bool {
    let expected_len = symbol_count as usize * (22 + symbol_size as usize);
    payload.len() >= expected_len
}

/// Test: Per-symbol AEAD nonce derivation.
fn test_aead_nonce_derivation() -> Result<(), String> {
    // FCPS per-symbol AEAD nonce is derived deterministically:
    // nonce = zone_key_id (8 bytes) || epoch_id XOR esi (4 bytes)
    //
    // This ensures unique nonces per symbol within an epoch

    let zone_key_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08u8];
    let epoch_id: u32 = 1000;

    // Derive nonce for ESI=0
    let nonce_0 = derive_symbol_nonce(zone_key_id, epoch_id, 0);

    // Derive nonce for ESI=1
    let nonce_1 = derive_symbol_nonce(zone_key_id, epoch_id, 1);

    // Nonces must differ
    if nonce_0 == nonce_1 {
        return Err("Different ESIs produced same nonce".to_string());
    }

    // Same ESI should produce same nonce (deterministic)
    let nonce_0_again = derive_symbol_nonce(zone_key_id, epoch_id, 0);
    if nonce_0 != nonce_0_again {
        return Err("Same ESI produced different nonce".to_string());
    }

    // Different epoch should produce different nonce
    let nonce_diff_epoch = derive_symbol_nonce(zone_key_id, epoch_id + 1, 0);
    if nonce_0 == nonce_diff_epoch {
        return Err("Different epoch produced same nonce".to_string());
    }

    Ok(())
}

fn derive_symbol_nonce(zone_key_id: [u8; 8], epoch_id: u32, esi: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&zone_key_id);
    let mixed = epoch_id ^ esi;
    nonce[8..12].copy_from_slice(&mixed.to_le_bytes());
    nonce
}

/// Test: Per-symbol AEAD AAD binding.
fn test_aead_aad_binding() -> Result<(), String> {
    // AAD for per-symbol AEAD must include:
    // - object_id (32 bytes)
    // - zone_id_hash (32 bytes)
    // - esi (4 bytes LE)
    // - k (2 bytes LE)

    let object_id = [0xAAu8; 32];
    let zone_id_hash = [0xBBu8; 32];
    let esi: u32 = 42;
    let k: u16 = 100;

    let aad = build_symbol_aad(&object_id, &zone_id_hash, esi, k);

    // AAD should be exactly 70 bytes
    if aad.len() != 70 {
        return Err(format!("AAD length {} != 70", aad.len()));
    }

    // Verify structure
    if aad[0..32] != object_id {
        return Err("AAD object_id mismatch".to_string());
    }
    if aad[32..64] != zone_id_hash {
        return Err("AAD zone_id_hash mismatch".to_string());
    }
    if aad[64..68] != esi.to_le_bytes() {
        return Err("AAD esi mismatch".to_string());
    }
    if aad[68..70] != k.to_le_bytes() {
        return Err("AAD k mismatch".to_string());
    }

    Ok(())
}

fn build_symbol_aad(object_id: &[u8; 32], zone_id_hash: &[u8; 32], esi: u32, k: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(70);
    aad.extend_from_slice(object_id);
    aad.extend_from_slice(zone_id_hash);
    aad.extend_from_slice(&esi.to_le_bytes());
    aad.extend_from_slice(&k.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fcps_interop_tests_pass() {
        let summary = run_tests();
        for failure in &summary.failures {
            eprintln!("FAIL: {} - {}", failure.name, failure.message);
        }
        assert!(
            summary.all_passed(),
            "FCPS interop tests failed: {}/{} passed",
            summary.passed,
            summary.total
        );
    }

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new(64);

        // Accept seq 0
        assert!(window.accept(0));

        // Reject replay
        assert!(!window.accept(0));

        // Accept higher seq
        assert!(window.accept(1));
    }

    #[test]
    fn test_symbol_nonce_uniqueness() {
        let zone_key_id = [1u8; 8];
        let epoch = 1u32;

        let mut nonces = std::collections::HashSet::new();
        for esi in 0..1000 {
            let nonce = derive_symbol_nonce(zone_key_id, epoch, esi);
            assert!(nonces.insert(nonce), "Duplicate nonce at esi={esi}");
        }
    }

    // ─── ReplayWindow edge cases ───

    #[test]
    fn replay_window_large_jump() {
        let mut window = ReplayWindow::new(64);
        assert!(window.accept(0));
        assert!(window.accept(1000)); // Large jump beyond window
        assert!(!window.accept(0)); // Far outside window
        assert!(!window.accept(935)); // 1000 - 935 = 65 >= 64, outside
        assert!(window.accept(937)); // 1000 - 937 = 63 < 64, inside
    }

    #[test]
    fn replay_window_sequential() {
        let mut window = ReplayWindow::new(64);
        for i in 0..200 {
            assert!(window.accept(i), "seq {i} should be accepted");
        }
        // Replay any should fail
        for i in 136..200 {
            assert!(!window.accept(i), "replay of {i} should be rejected");
        }
    }

    #[test]
    fn replay_window_size_one() {
        let mut window = ReplayWindow::new(1);
        assert!(window.accept(0));
        assert!(!window.accept(0));
        assert!(window.accept(1));
        assert!(!window.accept(0)); // Outside window
    }

    #[test]
    fn replay_window_out_of_order_acceptance() {
        let mut window = ReplayWindow::new(64);
        assert!(window.accept(5));
        assert!(window.accept(3));
        assert!(window.accept(1));
        assert!(window.accept(4));
        assert!(window.accept(2));
        assert!(window.accept(0));
        // All should now be seen
        for i in 0..=5 {
            assert!(!window.accept(i), "replay of {i} should fail");
        }
    }

    // ─── derive_symbol_nonce structure ───

    #[test]
    fn symbol_nonce_length() {
        let nonce = derive_symbol_nonce([0u8; 8], 0, 0);
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn symbol_nonce_zone_key_prefix() {
        let zone_key_id = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
        let nonce = derive_symbol_nonce(zone_key_id, 0, 0);
        assert_eq!(&nonce[..8], &zone_key_id);
    }

    #[test]
    fn symbol_nonce_epoch_xor_esi() {
        let zone_key_id = [0u8; 8];
        let epoch: u32 = 0x1234;
        let esi: u32 = 0x00FF;
        let nonce = derive_symbol_nonce(zone_key_id, epoch, esi);
        let expected_mixed = (epoch ^ esi).to_le_bytes();
        assert_eq!(&nonce[8..12], &expected_mixed);
    }

    #[test]
    fn symbol_nonce_different_epochs_different_nonces() {
        let zone_key_id = [1u8; 8];
        let n1 = derive_symbol_nonce(zone_key_id, 100, 0);
        let n2 = derive_symbol_nonce(zone_key_id, 200, 0);
        assert_ne!(n1, n2);
    }

    // ─── build_symbol_aad structure ───

    #[test]
    fn symbol_aad_length() {
        let aad = build_symbol_aad(&[0u8; 32], &[0u8; 32], 0, 0);
        assert_eq!(aad.len(), 70);
    }

    #[test]
    fn symbol_aad_components() {
        let obj = [0xAAu8; 32];
        let zone = [0xBBu8; 32];
        let esi: u32 = 42;
        let k: u16 = 7;
        let aad = build_symbol_aad(&obj, &zone, esi, k);
        assert_eq!(&aad[0..32], &obj);
        assert_eq!(&aad[32..64], &zone);
        assert_eq!(&aad[64..68], &esi.to_le_bytes());
        assert_eq!(&aad[68..70], &k.to_le_bytes());
    }

    // ─── is_within_mtu edge cases ───

    #[test]
    fn mtu_empty_datagram() {
        assert!(is_within_mtu(&[], 0));
    }

    #[test]
    fn mtu_zero_rejects_nonempty() {
        assert!(!is_within_mtu(&[1], 0));
    }

    #[test]
    fn mtu_exact_boundary() {
        assert!(is_within_mtu(&vec![0u8; 1280], 1280));
        assert!(!is_within_mtu(&vec![0u8; 1281], 1280));
    }

    // ─── is_payload_complete edge cases ───

    #[test]
    fn payload_complete_zero_symbols() {
        assert!(is_payload_complete(&[], 0, 1024));
    }

    #[test]
    fn payload_complete_one_symbol() {
        let record_size = 22 + 512;
        assert!(is_payload_complete(&vec![0u8; record_size], 1, 512));
        assert!(!is_payload_complete(&vec![0u8; record_size - 1], 1, 512));
    }

    // ─── FcpsInteropTests struct ───

    #[test]
    fn fcps_interop_via_struct() {
        let summary = FcpsInteropTests::run();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 8);
    }
}
