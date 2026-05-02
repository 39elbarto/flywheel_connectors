//! Regression for br-kfr9j (security audit A1).
//!
//! Pins the invariant that the three transparent-Deserialize byte
//! envelopes — `MlDsa65VerifyingKeyBytes`, `MlDsa65SignatureBytes`,
//! `XWingPublicKey` — enforce their declared length on the
//! deserialisation path, not just at `try_from_bytes`-construction
//! time. Pre-patch, an attacker-supplied CBOR/JSON envelope with a
//! mis-sized payload deserialised silently and the length error
//! surfaced only at use time (or as an array-conversion panic in
//! less-defensive callers).

use fcp_crypto::{
    XWING_PUBLIC_KEY_SIZE, XWingPublicKey,
    owner_key::{ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, MlDsa65SignatureBytes, MlDsa65VerifyingKeyBytes},
};

// ── ML-DSA-65 verifying key envelope ─────────────────────────────

#[test]
fn ml_dsa_verifying_key_bytes_deserialise_rejects_short_cbor() {
    // 5 bytes — far short of the 1952-byte FIPS 204 ML-DSA-65 PK.
    let too_short_envelope = vec![0u8; 5];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_short_envelope), &mut cbor).unwrap();
    let result: Result<MlDsa65VerifyingKeyBytes, _> = ciborium::from_reader(cbor.as_slice());
    assert!(
        result.is_err(),
        "br-kfr9j: 5-byte envelope must be rejected at deserialise time, got Ok"
    );
}

#[test]
fn ml_dsa_verifying_key_bytes_deserialise_rejects_long_cbor() {
    // One byte too many.
    let too_long = vec![0u8; ML_DSA_65_PUBLIC_KEY_SIZE + 1];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_long), &mut cbor).unwrap();
    let result: Result<MlDsa65VerifyingKeyBytes, _> = ciborium::from_reader(cbor.as_slice());
    assert!(result.is_err(), "br-kfr9j: oversized envelope must be rejected");
}

#[test]
fn ml_dsa_verifying_key_bytes_deserialise_accepts_correct_length() {
    let correct = vec![0xAB; ML_DSA_65_PUBLIC_KEY_SIZE];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&correct), &mut cbor).unwrap();
    let decoded: MlDsa65VerifyingKeyBytes =
        ciborium::from_reader(cbor.as_slice()).expect("correct-length must decode");
    assert_eq!(decoded.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
}

#[test]
fn ml_dsa_verifying_key_bytes_round_trip_through_cbor_preserves_length() {
    let original = MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0xCD; ML_DSA_65_PUBLIC_KEY_SIZE])
        .expect("correct length");
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("serialize");
    let decoded: MlDsa65VerifyingKeyBytes =
        ciborium::from_reader(cbor.as_slice()).expect("decode");
    assert_eq!(decoded.as_bytes(), original.as_bytes());
}

#[test]
fn ml_dsa_verifying_key_bytes_json_deserialise_rejects_wrong_length() {
    // serde_bytes JSON form is a hex array; manufacture a short array.
    let wrong = serde_bytes::ByteBuf::from(vec![0u8; 32]);
    let json = serde_json::to_string(&wrong).unwrap();
    let result: Result<MlDsa65VerifyingKeyBytes, _> = serde_json::from_str(&json);
    assert!(result.is_err(), "br-kfr9j: JSON path must reject too");
}

// ── ML-DSA-65 signature envelope ─────────────────────────────────

#[test]
fn ml_dsa_signature_bytes_deserialise_rejects_short_cbor() {
    let too_short = vec![0u8; 5];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_short), &mut cbor).unwrap();
    let result: Result<MlDsa65SignatureBytes, _> = ciborium::from_reader(cbor.as_slice());
    assert!(result.is_err());
}

#[test]
fn ml_dsa_signature_bytes_deserialise_rejects_long_cbor() {
    let too_long = vec![0u8; ML_DSA_65_SIGNATURE_SIZE + 1];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_long), &mut cbor).unwrap();
    let result: Result<MlDsa65SignatureBytes, _> = ciborium::from_reader(cbor.as_slice());
    assert!(result.is_err());
}

#[test]
fn ml_dsa_signature_bytes_deserialise_accepts_correct_length() {
    let correct = vec![0xCD; ML_DSA_65_SIGNATURE_SIZE];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&correct), &mut cbor).unwrap();
    let decoded: MlDsa65SignatureBytes =
        ciborium::from_reader(cbor.as_slice()).expect("correct-length must decode");
    assert_eq!(decoded.as_bytes().len(), ML_DSA_65_SIGNATURE_SIZE);
}

#[test]
fn ml_dsa_signature_bytes_round_trip_through_cbor_preserves_length() {
    let original = MlDsa65SignatureBytes::try_from_bytes(vec![0xEF; ML_DSA_65_SIGNATURE_SIZE])
        .expect("correct length");
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("serialize");
    let decoded: MlDsa65SignatureBytes = ciborium::from_reader(cbor.as_slice()).expect("decode");
    assert_eq!(decoded.as_bytes(), original.as_bytes());
}

// ── X-Wing public key envelope ───────────────────────────────────

#[test]
fn xwing_public_key_deserialise_rejects_short_cbor() {
    let too_short = vec![0u8; 5];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_short), &mut cbor).unwrap();
    let result: Result<XWingPublicKey, _> = ciborium::from_reader(cbor.as_slice());
    assert!(result.is_err());
}

#[test]
fn xwing_public_key_deserialise_rejects_long_cbor() {
    let too_long = vec![0u8; XWING_PUBLIC_KEY_SIZE + 1];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&too_long), &mut cbor).unwrap();
    let result: Result<XWingPublicKey, _> = ciborium::from_reader(cbor.as_slice());
    assert!(result.is_err());
}

#[test]
fn xwing_public_key_deserialise_accepts_correct_length() {
    let correct = vec![0xAA; XWING_PUBLIC_KEY_SIZE];
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(&correct), &mut cbor).unwrap();
    let decoded: XWingPublicKey =
        ciborium::from_reader(cbor.as_slice()).expect("correct-length must decode");
    assert_eq!(decoded.as_bytes().len(), XWING_PUBLIC_KEY_SIZE);
}

#[test]
fn xwing_public_key_round_trip_through_cbor_preserves_length() {
    let original = XWingPublicKey::from_bytes(&vec![0x11; XWING_PUBLIC_KEY_SIZE])
        .expect("correct length");
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("serialize");
    let decoded: XWingPublicKey = ciborium::from_reader(cbor.as_slice()).expect("decode");
    assert_eq!(decoded.as_bytes(), original.as_bytes());
}

// ── End-to-end: enclosing envelope cannot bypass via a malformed inner field

#[test]
fn ml_dsa_verifying_key_bytes_inside_envelope_rejected_on_decode() {
    // Pre-patch behaviour: the inner field would deserialise silently
    // and the wrapping struct (e.g. NodeKeyAttestation) would carry a
    // 5-byte "verifying key" that downstream code panics on.
    //
    // Post-patch: deserialisation of the wrapping struct fails fast
    // when the inner byte-envelope's length is wrong.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct EnvelopingStruct {
        key: MlDsa65VerifyingKeyBytes,
    }
    let bad_inner = serde_bytes::ByteBuf::from(vec![0u8; 5]);
    let json = serde_json::json!({ "key": bad_inner });
    let result: Result<EnvelopingStruct, _> = serde_json::from_value(json);
    assert!(
        result.is_err(),
        "br-kfr9j: enveloping struct must surface the length error from its inner byte field"
    );
}
