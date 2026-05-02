//! ML-DSA-65 fuzz-style robustness harness via proptest.
//!
//! Goal: prove that `MlDsa65VerifyingKey::verify` and the byte-envelope
//! constructors NEVER panic for ANY caller-supplied byte string and
//! ALWAYS return a decisive `Result`. A panic on a hostile signature
//! would let an attacker crash the host's verification path.
//!
//! Specifically:
//! - Random 3309-byte signatures (the FIPS 204 size) → must surface
//!   `SignatureVerificationFailed`, never panic.
//! - Wrong-length signatures via the byte envelope → must surface
//!   `InvalidSignatureLength` or `SignatureVerificationFailed`, never
//!   panic.
//! - Wrong-length verifying keys → `InvalidKeyLength`, never panic.

use fcp_crypto::{
    CryptoError, ML_DSA_65_SEED_SIZE, MlDsa65SigningKey, MlDsa65VerifyingKey,
    owner_key::{
        ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, MlDsa65SignatureBytes,
        MlDsa65VerifyingKeyBytes,
    },
};
use proptest::prelude::*;

fn deterministic_signer(seed: u8) -> MlDsa65SigningKey {
    MlDsa65SigningKey::from_seed(&[seed; ML_DSA_65_SEED_SIZE]).expect("seed wraps")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Arbitrary 3309-byte signature against an honest verifying key:
    /// must verify=Err (almost certainly `SignatureVerificationFailed`),
    /// never panic, never return any other variant.
    #[test]
    fn ml_dsa_verify_arbitrary_signature_never_panics(
        seed in any::<u8>(),
        sig_bytes in proptest::collection::vec(any::<u8>(), ML_DSA_65_SIGNATURE_SIZE..=ML_DSA_65_SIGNATURE_SIZE),
        message in proptest::collection::vec(any::<u8>(), 0usize..=512),
    ) {
        let signer = deterministic_signer(seed);
        let vk = signer.verifying_key();
        let sig = MlDsa65SignatureBytes::try_from_bytes(sig_bytes)
            .expect("3309-byte envelope wraps");
        let result = std::panic::catch_unwind(|| vk.verify(&message, b"", &sig));
        prop_assert!(result.is_ok(), "verify() panicked on random signature");
        let outcome = result.unwrap();
        prop_assert!(
            matches!(outcome, Err(CryptoError::SignatureVerificationFailed)),
            "random signature must surface SignatureVerificationFailed, got {:?}",
            outcome
        );
    }

    /// Wrong-length signature bytes via the byte envelope must NEVER
    /// panic; the envelope rejects up-front with InvalidSignatureLength.
    #[test]
    fn ml_dsa_signature_envelope_wrong_length_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=8192),
    ) {
        let result = std::panic::catch_unwind(|| {
            MlDsa65SignatureBytes::try_from_bytes(bytes.clone())
        });
        prop_assert!(result.is_ok());
        let outcome = result.unwrap();
        if bytes.len() == ML_DSA_65_SIGNATURE_SIZE {
            prop_assert!(outcome.is_ok());
        } else {
            let is_invalid_len = matches!(
                outcome,
                Err(CryptoError::InvalidSignatureLength { .. })
            );
            prop_assert!(is_invalid_len);
        }
    }

    /// Wrong-length verifying-key bytes must NEVER panic.
    #[test]
    fn ml_dsa_verifying_key_envelope_wrong_length_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=8192),
    ) {
        let result = std::panic::catch_unwind(|| {
            MlDsa65VerifyingKeyBytes::try_from_bytes(bytes.clone())
        });
        prop_assert!(result.is_ok());
        let outcome = result.unwrap();
        if bytes.len() == ML_DSA_65_PUBLIC_KEY_SIZE {
            prop_assert!(outcome.is_ok());
        } else {
            let is_invalid_len =
                matches!(outcome, Err(CryptoError::InvalidKeyLength { .. }));
            prop_assert!(is_invalid_len);
        }
    }

    /// MlDsa65VerifyingKey::from_bytes (the high-level decoder that
    /// also runs structural validation against the upstream ml-dsa
    /// crate) must NEVER panic on any byte input.
    #[test]
    fn ml_dsa_verifying_key_from_bytes_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=8192),
    ) {
        let result = std::panic::catch_unwind(|| MlDsa65VerifyingKey::from_bytes(&bytes));
        prop_assert!(result.is_ok(), "from_bytes panicked on len={}", bytes.len());
    }

    /// Tampered signature on a real, signed message: any single-bit
    /// flip in a real signature must surface SignatureVerificationFailed,
    /// not a panic and not an unrelated error.
    #[test]
    fn ml_dsa_verify_tampered_real_signature_decisive_err(
        seed in any::<u8>(),
        message in proptest::collection::vec(any::<u8>(), 1usize..=128),
        flip_byte in 0usize..ML_DSA_65_SIGNATURE_SIZE,
        flip_mask in 1u8..=255,
    ) {
        let signer = deterministic_signer(seed);
        let vk = signer.verifying_key();
        let real_sig = signer
            .sign_deterministic(&message, b"")
            .expect("sign succeeds for non-empty message");
        let mut bad = real_sig.as_bytes().to_vec();
        bad[flip_byte] ^= flip_mask;
        let tampered = MlDsa65SignatureBytes::try_from_bytes(bad)
            .expect("3309-byte envelope wraps");
        let result = std::panic::catch_unwind(|| vk.verify(&message, b"", &tampered));
        prop_assert!(result.is_ok(), "verify() panicked on tampered signature");
        prop_assert!(matches!(
            result.unwrap(),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    /// Cross-key verify: signature from one key MUST fail under
    /// another key, never panic.
    #[test]
    fn ml_dsa_cross_key_verify_decisive_err(
        seed_a in any::<u8>(),
        seed_b in any::<u8>(),
        message in proptest::collection::vec(any::<u8>(), 1usize..=128),
    ) {
        prop_assume!(seed_a != seed_b);
        let signer_a = deterministic_signer(seed_a);
        let signer_b = deterministic_signer(seed_b);
        let sig = signer_a.sign_deterministic(&message, b"").unwrap();
        let result = std::panic::catch_unwind(|| {
            signer_b.verifying_key().verify(&message, b"", &sig)
        });
        prop_assert!(result.is_ok());
        prop_assert!(matches!(
            result.unwrap(),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }
}
