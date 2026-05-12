use fcp_crypto::{
    CryptoError, Ed25519SigningKey, HybridSignedObjectKind, MlDsa65SigningKey, PqSigningPolicy,
    SignedEnvelope,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FixturePayload {
    id: String,
    body: Vec<u8>,
    seq: u64,
}

fn payload(id: &'static str) -> FixturePayload {
    FixturePayload {
        id: id.to_string(),
        body: format!("phase-n-downgrade::{id}").into_bytes(),
        seq: 8_200,
    }
}

fn keys() -> (Ed25519SigningKey, MlDsa65SigningKey) {
    (
        Ed25519SigningKey::from_bytes(&[0x31; 32]).expect("ed25519 test key"),
        MlDsa65SigningKey::from_seed(&[0x41; 32]).expect("ml-dsa test key"),
    )
}

#[test]
fn test_strip_pq_sig_rejected_in_steady_state() {
    let (classical_key, pq_key) = keys();
    let mut envelope = SignedEnvelope::sign(
        HybridSignedObjectKind::CapabilityToken,
        payload("strip-pq"),
        &classical_key,
        &pq_key,
    )
    .expect("hybrid envelope signs");

    envelope.sig_pq = None;
    envelope.pq_kid = None;

    let err = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::BothRequired,
        )
        .expect_err("steady-state policy rejects a stripped PQ signature");

    assert!(matches!(err, CryptoError::PqSignatureMissing));
    assert_eq!(err.reason_code(), Some("DowngradeAttempt"));
}

#[test]
fn test_strip_classical_sig_rejected_in_steady_state() {
    let (classical_key, pq_key) = keys();
    let mut envelope = SignedEnvelope::sign(
        HybridSignedObjectKind::AuditEvent,
        payload("strip-classical"),
        &classical_key,
        &pq_key,
    )
    .expect("hybrid envelope signs");

    envelope.sig_classical = None;
    envelope.classical_kid = None;

    let err = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::BothRequired,
        )
        .expect_err("steady-state policy rejects a stripped classical signature");

    assert!(matches!(err, CryptoError::ClassicalSignatureMissing));
    assert_eq!(err.reason_code(), Some("DowngradeAttempt"));
}

#[test]
fn test_replay_old_classical_only_rejected_in_steady_state() {
    let (classical_key, pq_key) = keys();
    let envelope = SignedEnvelope::sign_classical_only(
        HybridSignedObjectKind::Manifest,
        payload("old-classical-only"),
        &classical_key,
    )
    .expect("transitional envelope signs");

    let err = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::BothRequired,
        )
        .expect_err("steady-state policy rejects replayed transitional envelope");

    assert!(matches!(err, CryptoError::PqSignatureMissing));
    assert_eq!(err.reason_code(), Some("DowngradeAttempt"));
}

#[test]
fn test_transitional_period_accepts_one_with_warning() {
    let (classical_key, pq_key) = keys();
    let envelope = SignedEnvelope::sign_classical_only(
        HybridSignedObjectKind::GossipFrame,
        payload("transitional-warning"),
        &classical_key,
    )
    .expect("transitional envelope signs");

    let receipt = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::EitherOk,
        )
        .expect("transitional policy accepts one valid signature");

    assert_eq!(receipt.sig_kinds_verified, vec!["ed25519"]);
    assert_eq!(receipt.warnings.len(), 1);
    assert_eq!(receipt.warnings[0].reason_code, "PqSignatureMismatch");
    assert_eq!(
        receipt.warnings[0].attempted_downgrade,
        "pq-signature-absent-under-either-ok"
    );
    assert!(
        receipt.warnings[0]
            .attacker_pubkey_fpr
            .starts_with("ed25519:kid:"),
        "warning must carry a redaction-safe key fingerprint"
    );
}
