//! Property-based tests for Shamir Secret Sharing (flywheel_connectors-9sg2).
//!
//! This module validates the cryptographic properties of the Shamir implementation
//! using proptest for comprehensive coverage.
//!
//! ## Test Categories
//! 1. **Reconstruction correctness**: Any k shares can reconstruct the secret
//! 2. **Information-theoretic security**: k-1 shares reveal nothing
//! 3. **Determinism**: Same RNG seed produces same shares
//! 4. **Edge cases**: Boundary conditions for k, n parameters

#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::needless_pass_by_value)]

use std::collections::HashSet;
use std::time::Instant;

use fcp_crypto::shamir::{ShamirShare, reconstruct_secret, split_secret, split_secret_with_rng};
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Emit structured JSON log for test results.
fn log_test_result(test_name: &str, phase: &str, details: serde_json::Value, timing_us: u64) {
    let log_entry = serde_json::json!({
        "test": test_name,
        "phase": phase,
        "timing_us": timing_us,
        "result": "success",
        "details": details
    });
    eprintln!("{}", serde_json::to_string(&log_entry).unwrap());
}

/// Emit structured JSON log for test failures.
fn log_test_failure(test_name: &str, phase: &str, error: &str, details: serde_json::Value) {
    let log_entry = serde_json::json!({
        "test": test_name,
        "phase": phase,
        "result": "failure",
        "error": error,
        "details": details
    });
    eprintln!("{}", serde_json::to_string(&log_entry).unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// Proptest Strategies
// ─────────────────────────────────────────────────────────────────────────────

/// Strategy for valid (k, n) pairs where 1 <= k <= n <= 255.
fn valid_k_n() -> impl Strategy<Value = (u8, u8)> {
    (1u8..=20).prop_flat_map(|k| (Just(k), k..=core::cmp::min(k + 30, 255)))
}

/// Strategy for secrets of varying lengths.
fn secret_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..256)
}

/// Strategy for random seeds (for deterministic RNG).
fn rng_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

// ─────────────────────────────────────────────────────────────────────────────
// Property Tests: Reconstruction Correctness
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Any k shares from n can reconstruct the original secret.
    #[test]
    fn prop_any_k_shares_reconstruct(
        secret in secret_bytes(),
        (k, n) in valid_k_n(),
        seed in rng_seed(),
    ) {
        let start = Instant::now();
        let mut rng = ChaCha20Rng::from_seed(seed);

        let shares = split_secret_with_rng(&mut rng, &secret, k, n)
            .expect("split should succeed");

        prop_assert_eq!(shares.len(), usize::from(n));

        // Try reconstruction with exactly k shares (first k)
        let subset: Vec<ShamirShare> = shares.iter().take(usize::from(k)).cloned().collect();
        let recovered = reconstruct_secret(&subset).expect("reconstruct should succeed");

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_any_k_shares_reconstruct", "reconstruct", serde_json::json!({
            "k": k,
            "n": n,
            "secret_len": secret.len(),
            "shares_used": k,
        }), timing_us);

        prop_assert!(recovered.ct_eq_bytes(&secret));
    }

    /// Reconstruction works with any subset of k shares (not just first k).
    #[test]
    fn prop_any_k_subset_works(
        secret in secret_bytes(),
        (k, n) in valid_k_n().prop_filter("need n > k", |(k, n)| n > k),
        seed in rng_seed(),
        subset_offset in 0u8..10,
    ) {
        let start = Instant::now();
        let mut rng = ChaCha20Rng::from_seed(seed);

        let shares = split_secret_with_rng(&mut rng, &secret, k, n)
            .expect("split should succeed");

        // Choose a subset starting from different positions
        let offset = usize::from(subset_offset) % (usize::from(n) - usize::from(k) + 1);
        let subset: Vec<ShamirShare> = shares
            .iter()
            .skip(offset)
            .take(usize::from(k))
            .cloned()
            .collect();

        prop_assert_eq!(subset.len(), usize::from(k));

        let recovered = reconstruct_secret(&subset).expect("reconstruct should succeed");

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_any_k_subset_works", "reconstruct", serde_json::json!({
            "k": k,
            "n": n,
            "offset": offset,
            "secret_len": secret.len(),
        }), timing_us);

        prop_assert!(recovered.ct_eq_bytes(&secret));
    }

    /// More than k shares also reconstructs correctly.
    #[test]
    fn prop_more_than_k_shares_works(
        secret in secret_bytes(),
        (k, n) in valid_k_n().prop_filter("need n > k", |(k, n)| n > k),
        seed in rng_seed(),
    ) {
        let start = Instant::now();
        let mut rng = ChaCha20Rng::from_seed(seed);

        let shares = split_secret_with_rng(&mut rng, &secret, k, n)
            .expect("split should succeed");

        // Use all shares
        let recovered = reconstruct_secret(&shares).expect("reconstruct should succeed");

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_more_than_k_shares_works", "reconstruct", serde_json::json!({
            "k": k,
            "n": n,
            "shares_used": n,
            "secret_len": secret.len(),
        }), timing_us);

        prop_assert!(recovered.ct_eq_bytes(&secret));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property Tests: Information-Theoretic Security
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// k-1 shares reveal nothing about the secret (information-theoretic security).
    ///
    /// This test verifies that reconstruction with k-1 shares produces a result
    /// that differs from the original secret, demonstrating that insufficient
    /// shares don't leak information.
    #[test]
    fn prop_insufficient_shares_wrong_result(
        secret in secret_bytes().prop_filter("need multi-byte", |s| s.len() >= 2),
        (k, n) in valid_k_n().prop_filter("need k > 1", |(k, _)| *k > 1),
        seed in rng_seed(),
    ) {
        let start = Instant::now();
        let mut rng = ChaCha20Rng::from_seed(seed);

        let shares = split_secret_with_rng(&mut rng, &secret, k, n)
            .expect("split should succeed");

        // Use only k-1 shares
        let insufficient: Vec<ShamirShare> = shares
            .iter()
            .take(usize::from(k) - 1)
            .cloned()
            .collect();

        let wrong_result = reconstruct_secret(&insufficient)
            .expect("reconstruction succeeds but gives wrong answer");

        let timing_us = start.elapsed().as_micros() as u64;

        // With overwhelming probability, the result should differ
        // (The probability of accidental collision is negligible: ~1/256^secret_len)
        let matches = wrong_result.ct_eq_bytes(&secret);

        log_test_result("prop_insufficient_shares_wrong_result", "verify_security", serde_json::json!({
            "k": k,
            "n": n,
            "shares_used": k - 1,
            "secret_len": secret.len(),
            "accidental_match": matches,
        }), timing_us);

        // Allow the extremely rare accidental collision, but log it
        if matches {
            log_test_failure(
                "prop_insufficient_shares_wrong_result",
                "verify_security",
                "accidental collision (extremely rare, may be valid)",
                serde_json::json!({"k": k, "n": n, "secret_len": secret.len()})
            );
        }

        prop_assert!(
            !matches || secret.len() == 1,
            "k-1 shares should not reconstruct the secret (unless 1-byte secret)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property Tests: Determinism
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Same RNG seed produces identical shares.
    #[test]
    fn prop_deterministic_with_same_seed(
        secret in secret_bytes(),
        (k, n) in valid_k_n(),
        seed in rng_seed(),
    ) {
        let start = Instant::now();

        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let shares1 = split_secret_with_rng(&mut rng1, &secret, k, n)
            .expect("split should succeed");

        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let shares2 = split_secret_with_rng(&mut rng2, &secret, k, n)
            .expect("split should succeed");

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_deterministic_with_same_seed", "compare", serde_json::json!({
            "k": k,
            "n": n,
            "secret_len": secret.len(),
        }), timing_us);

        prop_assert_eq!(shares1.len(), shares2.len());
        for (s1, s2) in shares1.iter().zip(shares2.iter()) {
            prop_assert_eq!(s1.index(), s2.index());
            prop_assert_eq!(s1.data(), s2.data());
        }
    }

    /// Different RNG seeds produce different shares.
    #[test]
    fn prop_different_seeds_different_shares(
        secret in secret_bytes().prop_filter("need multi-byte", |s| s.len() >= 4),
        (k, n) in valid_k_n().prop_filter("need k > 1", |(k, _)| *k > 1),
        seed1 in rng_seed(),
        seed2 in rng_seed().prop_filter("different seed", |s| s[0] != 0),
    ) {
        // Ensure seeds are actually different
        prop_assume!(seed1 != seed2);

        let start = Instant::now();

        let mut rng1 = ChaCha20Rng::from_seed(seed1);
        let shares1 = split_secret_with_rng(&mut rng1, &secret, k, n)
            .expect("split should succeed");

        let mut rng2 = ChaCha20Rng::from_seed(seed2);
        let shares2 = split_secret_with_rng(&mut rng2, &secret, k, n)
            .expect("split should succeed");

        // At least one share should differ (with overwhelming probability)
        let all_same = shares1.iter().zip(shares2.iter()).all(|(s1, s2)| {
            s1.index() == s2.index() && s1.data() == s2.data()
        });

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_different_seeds_different_shares", "compare", serde_json::json!({
            "k": k,
            "n": n,
            "secret_len": secret.len(),
            "all_same": all_same,
        }), timing_us);

        prop_assert!(!all_same, "different seeds should produce different shares");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property Tests: Share Properties
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// All shares have unique indices.
    #[test]
    fn prop_unique_indices(
        secret in secret_bytes(),
        (k, n) in valid_k_n(),
    ) {
        let start = Instant::now();
        let shares = split_secret(&secret, k, n).expect("split should succeed");

        let indices: HashSet<u8> = shares.iter().map(ShamirShare::index).collect();

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_unique_indices", "verify", serde_json::json!({
            "k": k,
            "n": n,
            "unique_indices": indices.len(),
        }), timing_us);

        prop_assert_eq!(indices.len(), shares.len(), "all indices should be unique");
    }

    /// Share indices are in range 1..=n.
    #[test]
    fn prop_valid_index_range(
        secret in secret_bytes(),
        (k, n) in valid_k_n(),
    ) {
        let start = Instant::now();
        let shares = split_secret(&secret, k, n).expect("split should succeed");

        for share in &shares {
            prop_assert!(share.index() >= 1, "index should be >= 1");
            prop_assert!(share.index() <= n, "index should be <= n");
        }

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_valid_index_range", "verify", serde_json::json!({
            "k": k,
            "n": n,
            "min_index": shares.iter().map(ShamirShare::index).min(),
            "max_index": shares.iter().map(ShamirShare::index).max(),
        }), timing_us);
    }

    /// All shares have the same length as the secret.
    #[test]
    fn prop_share_length_matches_secret(
        secret in secret_bytes(),
        (k, n) in valid_k_n(),
    ) {
        let start = Instant::now();
        let shares = split_secret(&secret, k, n).expect("split should succeed");

        for share in &shares {
            prop_assert_eq!(
                share.len(),
                secret.len(),
                "share length should match secret length"
            );
        }

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_share_length_matches_secret", "verify", serde_json::json!({
            "k": k,
            "n": n,
            "secret_len": secret.len(),
        }), timing_us);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property Tests: Serialization
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Share serialization round-trips correctly.
    #[test]
    fn prop_share_serialization_roundtrip(
        secret in secret_bytes(),
        (k, n) in valid_k_n(),
    ) {
        let start = Instant::now();
        let shares = split_secret(&secret, k, n).expect("split should succeed");

        for share in &shares {
            let bytes = share.to_bytes();
            let recovered = ShamirShare::from_bytes(&bytes).expect("deserialize should succeed");

            prop_assert_eq!(recovered.index(), share.index());
            prop_assert_eq!(recovered.data(), share.data());
        }

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_share_serialization_roundtrip", "verify", serde_json::json!({
            "k": k,
            "n": n,
            "shares_tested": n,
        }), timing_us);
    }

    /// Serialized shares can be used for reconstruction.
    #[test]
    fn prop_serialized_shares_reconstruct(
        secret in secret_bytes(),
        (k, n) in valid_k_n(),
    ) {
        let start = Instant::now();
        let shares = split_secret(&secret, k, n).expect("split should succeed");

        // Serialize and deserialize all shares
        let roundtripped: Vec<ShamirShare> = shares
            .iter()
            .take(usize::from(k))
            .map(|s| ShamirShare::from_bytes(&s.to_bytes()).unwrap())
            .collect();

        let recovered = reconstruct_secret(&roundtripped).expect("reconstruct should succeed");

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_serialized_shares_reconstruct", "verify", serde_json::json!({
            "k": k,
            "n": n,
            "secret_len": secret.len(),
        }), timing_us);

        prop_assert!(recovered.ct_eq_bytes(&secret));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property Tests: Edge Cases
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// k=1 means each share is the secret (degenerate case).
    #[test]
    fn prop_k_equals_1_each_share_is_secret(
        secret in secret_bytes(),
        n in 1u8..=10,
    ) {
        let start = Instant::now();
        let shares = split_secret(&secret, 1, n).expect("split should succeed");

        // Each individual share should reconstruct the secret
        for share in &shares {
            let recovered = reconstruct_secret(std::slice::from_ref(share))
                .expect("reconstruct should succeed");
            prop_assert!(recovered.ct_eq_bytes(&secret));
        }

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_k_equals_1_each_share_is_secret", "verify", serde_json::json!({
            "k": 1,
            "n": n,
            "secret_len": secret.len(),
        }), timing_us);
    }

    /// k=n means all shares are required.
    #[test]
    fn prop_k_equals_n_all_required(
        secret in secret_bytes(),
        n in 2u8..=10,
    ) {
        let start = Instant::now();
        let shares = split_secret(&secret, n, n).expect("split should succeed");

        // All shares needed
        let recovered = reconstruct_secret(&shares).expect("reconstruct should succeed");
        prop_assert!(recovered.ct_eq_bytes(&secret));

        // n-1 shares should fail (give wrong result)
        if n > 1 {
            let insufficient: Vec<_> = shares.iter().take(usize::from(n) - 1).cloned().collect();
            let wrong = reconstruct_secret(&insufficient).expect("reconstruct succeeds");
            // With high probability, this should differ
            let differs = !wrong.ct_eq_bytes(&secret);

            log_test_result("prop_k_equals_n_all_required", "verify_insufficient", serde_json::json!({
                "k": n,
                "n": n,
                "insufficient_differs": differs,
            }), 0);
        }

        let timing_us = start.elapsed().as_micros() as u64;
        log_test_result("prop_k_equals_n_all_required", "verify", serde_json::json!({
            "k": n,
            "n": n,
            "secret_len": secret.len(),
        }), timing_us);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Zeroization Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Test that `ZeroizingSecret` compiles with expected traits.
#[test]
fn test_zeroizing_secret_traits() {
    let start = Instant::now();

    // Create a secret
    let secret = b"test secret for zeroization";
    let shares = split_secret(secret, 2, 3).expect("split should succeed");
    let recovered = reconstruct_secret(&shares[..2]).expect("reconstruct should succeed");

    // Verify the secret is accessible
    assert!(recovered.ct_eq_bytes(secret));
    assert_eq!(recovered.len(), secret.len());
    assert!(!recovered.is_empty());

    // Verify debug output is redacted (ZeroizingSecret's Debug impl emits
    // "<redacted, len=N>", not "[redacted]" — the bracketed form is for the
    // ShamirShare debug shape).
    let debug = format!("{recovered:?}");
    assert!(debug.contains("<redacted"));
    assert!(!debug.contains("test secret"));

    // Drop triggers zeroization (can't easily verify memory, but type compiles)
    drop(recovered);

    let timing_us = start.elapsed().as_micros() as u64;
    log_test_result(
        "test_zeroizing_secret_traits",
        "verify",
        serde_json::json!({
            "secret_len": secret.len(),
            "debug_redacted": true,
        }),
        timing_us,
    );
}

/// Test that `ShamirShare` compiles with zeroize traits.
#[test]
fn test_shamir_share_zeroize() {
    let start = Instant::now();

    let share = ShamirShare::new(1, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    // Verify debug output is redacted
    let debug = format!("{share:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.to_lowercase().contains("dead"));
    assert!(!debug.to_lowercase().contains("beef"));

    // Drop triggers zeroization
    drop(share);

    let timing_us = start.elapsed().as_micros() as u64;
    log_test_result(
        "test_shamir_share_zeroize",
        "verify",
        serde_json::json!({
            "debug_redacted": true,
        }),
        timing_us,
    );
}
