use fcp_crypto::{
    CryptoError, Ed25519SigningKey, MlDsa65SigningKey, PqSigningPolicy, SignedEnvelope,
    canonical_signing_bytes, canonicalize::to_deterministic_cbor,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DowngradeFixture {
    object_type: String,
    sequence: u64,
    body: Vec<u8>,
}

fn fixture_payload(object_type: &str) -> DowngradeFixture {
    DowngradeFixture {
        object_type: object_type.to_string(),
        sequence: 2026,
        body: format!("pq-downgrade-fixture:{object_type}").into_bytes(),
    }
}

fn signing_bytes(payload: &DowngradeFixture) -> Vec<u8> {
    let cbor = to_deterministic_cbor(payload).expect("fixture payload must encode");
    canonical_signing_bytes(
        &format!("fcp.pq-downgrade.{}.v1", payload.object_type),
        &cbor,
    )
}

fn signing_keys() -> (Ed25519SigningKey, MlDsa65SigningKey) {
    let classical =
        Ed25519SigningKey::from_bytes(&[0x52; 32]).expect("test Ed25519 key must decode");
    let pq = MlDsa65SigningKey::from_seed(&[0xA6; 32]).expect("test ML-DSA key must decode");
    (classical, pq)
}

fn hybrid_envelope() -> (
    SignedEnvelope<DowngradeFixture>,
    Vec<u8>,
    Ed25519SigningKey,
    MlDsa65SigningKey,
) {
    let (classical, pq) = signing_keys();
    let payload = fixture_payload("capability_token");
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign("capability_token", payload, &bytes, &classical, &pq)
        .expect("hybrid signing must succeed");
    (envelope, bytes, classical, pq)
}

#[test]
fn test_strip_pq_sig_rejected_in_steady_state() {
    let (mut envelope, bytes, classical, pq) = hybrid_envelope();
    envelope.sig_pq = None;

    let classical_verifier = classical.verifying_key();
    let err = envelope
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::BothRequired,
            Some(&classical_verifier),
            Some(pq.verifying_key()),
        )
        .expect_err("steady-state verification must reject a stripped PQ signature");

    assert!(matches!(
        err,
        CryptoError::MissingPqSignature {
            policy: "BothRequired"
        }
    ));
    assert_eq!(err.hybrid_reason_code(), Some("DowngradeAttempt"));
}

#[test]
fn test_strip_classical_sig_rejected_in_steady_state() {
    let (mut envelope, bytes, classical, pq) = hybrid_envelope();
    envelope.sig_classical = None;

    let classical_verifier = classical.verifying_key();
    let err = envelope
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::BothRequired,
            Some(&classical_verifier),
            Some(pq.verifying_key()),
        )
        .expect_err("steady-state verification must reject a stripped classical signature");

    assert!(matches!(
        err,
        CryptoError::MissingClassicalSignature {
            policy: "BothRequired"
        }
    ));
    assert_eq!(err.hybrid_reason_code(), Some("DowngradeAttempt"));
}

#[test]
fn test_replay_old_classical_only_rejected_in_steady_state() {
    let (classical, pq) = signing_keys();
    let payload = fixture_payload("operation_receipt");
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign_with_policy(
        "operation_receipt",
        payload,
        &bytes,
        PqSigningPolicy::ClassicalOnly,
        Some(&classical),
        None,
    )
    .expect("classical-only transitional envelope must sign");

    let classical_verifier = classical.verifying_key();
    let err = envelope
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::BothRequired,
            Some(&classical_verifier),
            Some(pq.verifying_key()),
        )
        .expect_err("steady-state verification must reject replayed classical-only envelopes");

    assert!(matches!(
        err,
        CryptoError::MissingPqSignature {
            policy: "BothRequired"
        }
    ));
    assert_eq!(err.hybrid_reason_code(), Some("DowngradeAttempt"));
}

#[test]
fn test_transitional_period_accepts_one_with_warning() {
    let (classical, _pq) = signing_keys();
    let payload = fixture_payload("manifest");
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign_with_policy(
        "manifest",
        payload,
        &bytes,
        PqSigningPolicy::EitherOk,
        Some(&classical),
        None,
    )
    .expect("transitional one-signature envelope must sign");

    let classical_verifier = classical.verifying_key();
    let report = envelope
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::EitherOk,
            Some(&classical_verifier),
            None,
        )
        .expect("transitional policy must accept one valid signature");

    assert!(report.signatures_verified.classical);
    assert!(!report.signatures_verified.pq);
    let warning = report
        .warning
        .expect("one-signature transitional verification must carry a warning");
    assert_eq!(warning.reason_code, "PqSignatureMismatch");
    assert_eq!(warning.missing_signature_kind, "ml-dsa-65");
}
