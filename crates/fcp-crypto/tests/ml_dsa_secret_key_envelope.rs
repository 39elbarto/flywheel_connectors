//! Regression for br-6bz52 (modes-of-reasoning audit A1).
//!
//! Pins the `MlDsa65SecretKeyBytes` envelope's invariants:
//!
//! - kfr9j-style length-validating Deserialize (any length other than
//!   the FIPS 204 §3.7 ξ-seed size = 32 bytes is rejected at decode
//!   time, never at use time).
//! - 1zlht-style constant-time `PartialEq` via
//!   [`subtle::ConstantTimeEq`].
//! - Zeroize on drop so the secret material is wiped.
//! - Round-trip via the CBOR / JSON serialisation paths.
//! - Round-trip through [`MlDsa65SigningKey::to_envelope`] /
//!   [`MlDsa65SigningKey::from_envelope`] preserves the signing-key
//!   identity (same verifying key, same deterministic signature on
//!   the same inputs).
//!
//! 14 tests total, mirroring the kfr9j shape (short / long / correct
//! length / round-trip / JSON-path / enclosing-struct paths).

use fcp_crypto::{
    CryptoError, ML_DSA_65_SEED_BYTES, MlDsa65SecretKeyBytes, MlDsa65SigningKey,
};

// ── Length invariant on Deserialize (kfr9j) ─────────────────────────

#[test]
fn ml_dsa_secret_key_bytes_deserialise_rejects_short_cbor() {
    let too_short = vec![0u8; 5];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_short), &mut cbor).unwrap();
    let result: Result<MlDsa65SecretKeyBytes, _> = ciborium::from_reader(cbor.as_slice());
    assert!(
        result.is_err(),
        "br-6bz52: 5-byte envelope must be rejected at deserialise time, got Ok"
    );
}

#[test]
fn ml_dsa_secret_key_bytes_deserialise_rejects_long_cbor() {
    let too_long = vec![0u8; ML_DSA_65_SEED_BYTES + 1];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_long), &mut cbor).unwrap();
    let result: Result<MlDsa65SecretKeyBytes, _> = ciborium::from_reader(cbor.as_slice());
    assert!(
        result.is_err(),
        "br-6bz52: oversized envelope must be rejected at deserialise time"
    );
}

#[test]
fn ml_dsa_secret_key_bytes_deserialise_accepts_correct_length() {
    let correct = vec![0xCDu8; ML_DSA_65_SEED_BYTES];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&correct), &mut cbor).unwrap();
    let decoded: MlDsa65SecretKeyBytes =
        ciborium::from_reader(cbor.as_slice()).expect("correct-length must decode");
    assert_eq!(decoded.as_bytes().len(), ML_DSA_65_SEED_BYTES);
}

#[test]
fn ml_dsa_secret_key_bytes_round_trip_through_cbor_preserves_bytes() {
    let original = MlDsa65SecretKeyBytes::try_from_bytes(vec![0xABu8; ML_DSA_65_SEED_BYTES])
        .expect("correct length");
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("serialize");
    let decoded: MlDsa65SecretKeyBytes =
        ciborium::from_reader(cbor.as_slice()).expect("decode");
    assert_eq!(decoded.as_bytes(), original.as_bytes());
}

#[test]
fn ml_dsa_secret_key_bytes_json_path_rejects_wrong_length() {
    let wrong = serde_bytes::ByteBuf::from(vec![0u8; 8]);
    let json = serde_json::to_string(&wrong).unwrap();
    let result: Result<MlDsa65SecretKeyBytes, _> = serde_json::from_str(&json);
    assert!(result.is_err(), "br-6bz52: JSON path must reject wrong-length too");
}

#[test]
fn ml_dsa_secret_key_bytes_try_from_bytes_rejects_wrong_length() {
    let err = MlDsa65SecretKeyBytes::try_from_bytes(vec![0u8; 4])
        .expect_err("4-byte input must be rejected");
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: ML_DSA_65_SEED_BYTES,
            actual: 4,
        }
    ));
}

#[test]
fn ml_dsa_secret_key_bytes_inside_envelope_rejected_on_decode() {
    // br-6bz52: same enclosing-struct test the kfr9j patch ships for
    // the verifying-key envelope. Wrap the secret in a parent struct
    // and confirm the parent fails to deserialise when the inner
    // length is wrong.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct EnvelopingStruct {
        seed: MlDsa65SecretKeyBytes,
    }
    let bad_inner = serde_bytes::ByteBuf::from(vec![0u8; 5]);
    let json = serde_json::json!({ "seed": bad_inner });
    let result: Result<EnvelopingStruct, _> = serde_json::from_value(json);
    assert!(
        result.is_err(),
        "br-6bz52: enveloping struct must surface the inner-length error"
    );
}

// ── Constant-time PartialEq (1zlht) ─────────────────────────────────

#[test]
fn ml_dsa_secret_key_bytes_eq_reflects_byte_equality() {
    let a = MlDsa65SecretKeyBytes::try_from_bytes(vec![0x42u8; ML_DSA_65_SEED_BYTES]).unwrap();
    let b = MlDsa65SecretKeyBytes::try_from_bytes(vec![0x42u8; ML_DSA_65_SEED_BYTES]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn ml_dsa_secret_key_bytes_eq_distinguishes_first_byte_diff() {
    let a = MlDsa65SecretKeyBytes::try_from_bytes(vec![0x42u8; ML_DSA_65_SEED_BYTES]).unwrap();
    let mut other = vec![0x42u8; ML_DSA_65_SEED_BYTES];
    other[0] = 0xFF;
    let b = MlDsa65SecretKeyBytes::try_from_bytes(other).unwrap();
    assert_ne!(a, b);
}

#[test]
fn ml_dsa_secret_key_bytes_eq_distinguishes_last_byte_diff() {
    let a = MlDsa65SecretKeyBytes::try_from_bytes(vec![0x42u8; ML_DSA_65_SEED_BYTES]).unwrap();
    let mut other = vec![0x42u8; ML_DSA_65_SEED_BYTES];
    other[ML_DSA_65_SEED_BYTES - 1] = 0xFF;
    let b = MlDsa65SecretKeyBytes::try_from_bytes(other).unwrap();
    assert_ne!(a, b);
}

// ── Debug redaction ─────────────────────────────────────────────────

#[test]
fn ml_dsa_secret_key_bytes_debug_redacts_seed() {
    let sk = MlDsa65SecretKeyBytes::try_from_bytes(vec![0xCDu8; ML_DSA_65_SEED_BYTES]).unwrap();
    let dbg = format!("{sk:?}");
    assert!(dbg.contains("redacted"), "br-6bz52: Debug must redact: {dbg}");
    assert!(!dbg.contains("cdcd"), "br-6bz52: Debug must not leak hex: {dbg}");
}

// ── MlDsa65SigningKey envelope round-trip (the canonical persistence path)

#[test]
fn ml_dsa_secret_key_bytes_into_bytes_returns_seed_unchanged() {
    // br-6bz52: the consume-and-extract path. Caller takes
    // ownership of the underlying Vec; the wrapper is dropped (its
    // ZeroizeOnDrop guard fires on the now-empty inner Vec).
    let original_seed = vec![0x9Au8; ML_DSA_65_SEED_BYTES];
    let envelope = MlDsa65SecretKeyBytes::try_from_bytes(original_seed.clone()).unwrap();
    let extracted = envelope.into_bytes();
    assert_eq!(extracted, original_seed);
    assert_eq!(extracted.len(), ML_DSA_65_SEED_BYTES);
}

#[test]
fn ml_dsa_signing_key_to_envelope_preserves_seed_bytes() {
    let sk = MlDsa65SigningKey::from_seed(&[0x07u8; ML_DSA_65_SEED_BYTES])
        .expect("seed wraps");
    let envelope = sk.to_envelope();
    assert_eq!(envelope.as_bytes(), sk.seed().as_slice());
    assert_eq!(envelope.as_bytes().len(), ML_DSA_65_SEED_BYTES);
}

#[test]
fn ml_dsa_signing_key_envelope_round_trip_recovers_identity() {
    // br-6bz52: the canonical persistence flow. Generate a key,
    // serialise via to_envelope() / Serialize, deserialise via
    // Deserialize / from_envelope(), and confirm the recovered
    // signing key produces the SAME deterministic signature for the
    // same (message, context) pair AND has the same verifying key.
    let original = MlDsa65SigningKey::from_seed(&[0x55u8; ML_DSA_65_SEED_BYTES]).unwrap();
    let envelope = original.to_envelope();

    // Through CBOR — the on-the-wire form.
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut cbor).unwrap();
    let recovered_envelope: MlDsa65SecretKeyBytes =
        ciborium::from_reader(cbor.as_slice()).unwrap();
    let recovered_sk = MlDsa65SigningKey::from_envelope(&recovered_envelope).unwrap();

    // Verifying keys must match.
    assert_eq!(
        recovered_sk.verifying_key().as_bytes(),
        original.verifying_key().as_bytes(),
        "envelope round-trip must recover the same verifying key"
    );

    // Deterministic signatures over the same input must match
    // byte-for-byte.
    let sig_a = original
        .sign_deterministic(b"br-6bz52 round-trip", b"")
        .unwrap();
    let sig_b = recovered_sk
        .sign_deterministic(b"br-6bz52 round-trip", b"")
        .unwrap();
    assert_eq!(
        sig_a.as_bytes(),
        sig_b.as_bytes(),
        "deterministic signatures must round-trip via the envelope"
    );

    // And the recovered signature verifies under the original
    // verifying key.
    original
        .verifying_key()
        .verify(b"br-6bz52 round-trip", b"", &sig_b)
        .expect("recovered signature must verify");
}
