//! Fuzz-style property tests for hostile signature verification inputs.
//!
//! The cargo-fuzz tree already covers Ed25519 parsing and COSE token paths.
//! This crate-local harness pins the typed-error contract for both classical
//! and ML-DSA owner-key verification under arbitrary caller-supplied envelopes.

use fcp_crypto::{
    CryptoError, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, ML_DSA_65_SEED_SIZE,
    MlDsa65SigningKey, MlDsa65VerifyingKey,
    owner_key::{
        ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, MlDsa65SignatureBytes,
        MlDsa65VerifyingKeyBytes,
    },
};
use proptest::prelude::*;

const ED25519_PUBLIC_KEY_SIZE: usize = 32;
const ED25519_SECRET_KEY_SIZE: usize = 32;
const ED25519_SIGNATURE_SIZE: usize = 64;

fn flip_byte(bytes: &mut [u8], index: usize, mask: u8) {
    bytes[index % bytes.len()] ^= mask.max(1);
}

fn ed25519_signer(seed: [u8; ED25519_SECRET_KEY_SIZE]) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&seed).expect("Ed25519 seed length is fixed")
}

fn ml_dsa_signer(seed_byte: u8) -> MlDsa65SigningKey {
    MlDsa65SigningKey::from_seed(&[seed_byte; ML_DSA_65_SEED_SIZE])
        .expect("ML-DSA seed length is fixed")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        ..ProptestConfig::default()
    })]

    #[test]
    fn ed25519_hostile_verify_inputs_never_panic_or_escape_typed_errors(
        public_key_bytes in any::<[u8; ED25519_PUBLIC_KEY_SIZE]>(),
        signature_bytes in any::<[u8; ED25519_SIGNATURE_SIZE]>(),
        arbitrary_signature_envelope in proptest::collection::vec(any::<u8>(), 0usize..=128),
        signing_seed in any::<[u8; ED25519_SECRET_KEY_SIZE]>(),
        message in proptest::collection::vec(any::<u8>(), 0usize..=512),
        context in proptest::collection::vec(any::<u8>(), 0usize..=64),
        flip_index in 0usize..ED25519_SIGNATURE_SIZE,
        flip_mask in 1u8..=255,
    ) {
        let parsed_key = std::panic::catch_unwind(|| {
            Ed25519VerifyingKey::from_bytes(&public_key_bytes)
        });
        prop_assert!(parsed_key.is_ok(), "Ed25519 public-key decode panicked");

        if let Ok(Ok(verifying_key)) = parsed_key {
            let signature = Ed25519Signature::from_bytes(&signature_bytes);
            let verify_result = std::panic::catch_unwind(|| {
                verifying_key.verify(&message, &signature)
            });
            prop_assert!(verify_result.is_ok(), "Ed25519 verify panicked");
            let _typed_result: Result<(), CryptoError> = verify_result.unwrap();
        }

        let envelope_result = std::panic::catch_unwind(|| {
            Ed25519Signature::try_from_slice(&arbitrary_signature_envelope)
        });
        prop_assert!(envelope_result.is_ok(), "Ed25519 signature envelope parse panicked");
        match envelope_result.unwrap() {
            Ok(_) => prop_assert_eq!(arbitrary_signature_envelope.len(), ED25519_SIGNATURE_SIZE),
            Err(CryptoError::InvalidSignatureLength { expected, actual }) => {
                prop_assert_eq!(expected, ED25519_SIGNATURE_SIZE);
                prop_assert_eq!(actual, arbitrary_signature_envelope.len());
            }
            Err(other) => prop_assert!(false, "unexpected Ed25519 envelope error: {other:?}"),
        }

        let signer = ed25519_signer(signing_seed);
        let verifying_key = signer.verifying_key();
        let signature = signer.sign_with_context(&context, &message);
        verifying_key
            .verify_with_context(&context, &message, &signature)
            .expect("matching Ed25519 context signature must verify");

        let mut tampered_signature = signature.to_bytes();
        flip_byte(&mut tampered_signature, flip_index, flip_mask);
        let tampered_signature = Ed25519Signature::from_bytes(&tampered_signature);
        let tampered_result = std::panic::catch_unwind(|| {
            verifying_key.verify_with_context(&context, &message, &tampered_signature)
        });
        prop_assert!(tampered_result.is_ok(), "Ed25519 tampered verify panicked");
        prop_assert!(matches!(
            tampered_result.unwrap(),
            Err(CryptoError::SignatureVerificationFailed)
        ));

        if !message.is_empty() {
            let mut tampered_message = message.clone();
            flip_byte(&mut tampered_message, flip_index, flip_mask);
            prop_assert!(matches!(
                verifying_key.verify_with_context(&context, &tampered_message, &signature),
                Err(CryptoError::SignatureVerificationFailed)
            ));
        }

        let wrong_context = if context.is_empty() {
            vec![0]
        } else {
            let mut context = context.clone();
            flip_byte(&mut context, flip_index, flip_mask);
            context
        };
        prop_assert!(matches!(
            verifying_key.verify_with_context(&wrong_context, &message, &signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn ml_dsa_hostile_verify_inputs_never_panic_or_escape_typed_errors(
        signer_seed in any::<u8>(),
        signature_bytes in proptest::collection::vec(any::<u8>(), ML_DSA_65_SIGNATURE_SIZE..=ML_DSA_65_SIGNATURE_SIZE),
        arbitrary_signature_envelope in proptest::collection::vec(any::<u8>(), 0usize..=4096),
        arbitrary_verifying_key_envelope in proptest::collection::vec(any::<u8>(), 0usize..=4096),
        message in proptest::collection::vec(any::<u8>(), 0usize..=256),
        context in proptest::collection::vec(any::<u8>(), 0usize..=64),
        flip_index in 0usize..ML_DSA_65_SIGNATURE_SIZE,
        flip_mask in 1u8..=255,
    ) {
        let signer = ml_dsa_signer(signer_seed);
        let verifying_key = signer.verifying_key();

        let signature = MlDsa65SignatureBytes::try_from_bytes(signature_bytes)
            .expect("fixed-size ML-DSA signature envelope wraps");
        let verify_result = std::panic::catch_unwind(|| {
            verifying_key.verify(&message, &context, &signature)
        });
        prop_assert!(verify_result.is_ok(), "ML-DSA verify panicked");
        let _typed_result: Result<(), CryptoError> = verify_result.unwrap();

        let signature_envelope_result = std::panic::catch_unwind(|| {
            MlDsa65SignatureBytes::try_from_bytes(arbitrary_signature_envelope.clone())
        });
        prop_assert!(
            signature_envelope_result.is_ok(),
            "ML-DSA signature envelope parse panicked"
        );
        match signature_envelope_result.unwrap() {
            Ok(_) => prop_assert_eq!(arbitrary_signature_envelope.len(), ML_DSA_65_SIGNATURE_SIZE),
            Err(CryptoError::InvalidSignatureLength { expected, actual }) => {
                prop_assert_eq!(expected, ML_DSA_65_SIGNATURE_SIZE);
                prop_assert_eq!(actual, arbitrary_signature_envelope.len());
            }
            Err(other) => prop_assert!(false, "unexpected ML-DSA signature error: {other:?}"),
        }

        let key_envelope_result = std::panic::catch_unwind(|| {
            MlDsa65VerifyingKeyBytes::try_from_bytes(arbitrary_verifying_key_envelope.clone())
        });
        prop_assert!(
            key_envelope_result.is_ok(),
            "ML-DSA verifying-key envelope parse panicked"
        );
        match key_envelope_result.unwrap() {
            Ok(envelope) => {
                prop_assert_eq!(
                    arbitrary_verifying_key_envelope.len(),
                    ML_DSA_65_PUBLIC_KEY_SIZE
                );
                let decoded = std::panic::catch_unwind(|| {
                    MlDsa65VerifyingKey::from_envelope(envelope)
                });
                prop_assert!(decoded.is_ok(), "ML-DSA verifying-key decode panicked");
            }
            Err(CryptoError::InvalidKeyLength { expected, actual }) => {
                prop_assert_eq!(expected, ML_DSA_65_PUBLIC_KEY_SIZE);
                prop_assert_eq!(actual, arbitrary_verifying_key_envelope.len());
            }
            Err(other) => prop_assert!(false, "unexpected ML-DSA key error: {other:?}"),
        }

        let real_signature = signer
            .sign_deterministic(&message, &context)
            .expect("bounded ML-DSA context signs");
        verifying_key
            .verify(&message, &context, &real_signature)
            .expect("matching ML-DSA context signature must verify");

        let mut tampered_signature = real_signature.as_bytes().to_vec();
        flip_byte(&mut tampered_signature, flip_index, flip_mask);
        let tampered_signature = MlDsa65SignatureBytes::try_from_bytes(tampered_signature)
            .expect("tampered ML-DSA envelope preserves length");
        let tampered_result = std::panic::catch_unwind(|| {
            verifying_key.verify(&message, &context, &tampered_signature)
        });
        prop_assert!(tampered_result.is_ok(), "ML-DSA tampered verify panicked");
        prop_assert!(matches!(
            tampered_result.unwrap(),
            Err(CryptoError::SignatureVerificationFailed)
        ));

        if !message.is_empty() {
            let mut tampered_message = message.clone();
            flip_byte(&mut tampered_message, flip_index, flip_mask);
            prop_assert!(matches!(
                verifying_key.verify(&tampered_message, &context, &real_signature),
                Err(CryptoError::SignatureVerificationFailed)
            ));
        }

        let wrong_context = if context.is_empty() {
            vec![0]
        } else {
            let mut context = context.clone();
            flip_byte(&mut context, flip_index, flip_mask);
            context
        };
        prop_assert!(matches!(
            verifying_key.verify(&message, &wrong_context, &real_signature),
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }
}
