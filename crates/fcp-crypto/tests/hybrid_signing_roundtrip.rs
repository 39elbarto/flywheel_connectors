use fcp_crypto::{
    CryptoError, CryptoResult, EVENT_PQ_POLICY_DOWNGRADE, Ed25519SigningKey, HybridSignable,
    HybridSignedObjectKind, MlDsa65SigningKey, PqPolicyDowngradeAuthorizer, PqSigningPolicy,
    SignedEnvelope, downgrade_policy_to_either_ok, signing_bytes_for_payload,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FixturePayload {
    id: String,
    body: Vec<u8>,
    seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacySignaturePayload {
    body: String,
    legacy_signature: Vec<u8>,
}

impl HybridSignable for LegacySignaturePayload {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::AuditEvent;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.legacy_signature.clear();
        signing_bytes_for_payload(Self::OBJECT_KIND, &unsigned)
    }
}

struct MockHardwareToken {
    fingerprint: &'static str,
}

impl PqPolicyDowngradeAuthorizer for MockHardwareToken {
    fn operator_fingerprint(&self) -> &str {
        self.fingerprint
    }

    fn authorize_pq_policy_downgrade(
        &self,
        from: PqSigningPolicy,
        to: PqSigningPolicy,
        reason: &str,
    ) -> CryptoResult<()> {
        if from == PqSigningPolicy::BothRequired
            && to == PqSigningPolicy::EitherOk
            && !reason.is_empty()
        {
            Ok(())
        } else {
            Err(CryptoError::TokenValidationError(
                "mock hardware token rejected PQ downgrade".to_string(),
            ))
        }
    }
}

fn payload(id: &'static str) -> FixturePayload {
    FixturePayload {
        id: id.to_string(),
        body: format!("phase-n-hybrid-signing::{id}").into_bytes(),
        seq: 42,
    }
}

fn keys() -> (Ed25519SigningKey, MlDsa65SigningKey) {
    (
        Ed25519SigningKey::from_bytes(&[0x11; 32]).expect("ed25519 test key"),
        MlDsa65SigningKey::from_seed(&[0x22; 32]).expect("ml-dsa test key"),
    )
}

fn assert_classical_only_roundtrip(kind: HybridSignedObjectKind, payload: FixturePayload) {
    let (classical_key, pq_key) = keys();
    let expected = payload.clone();
    let envelope = SignedEnvelope::sign_classical_only(kind, payload, &classical_key).unwrap();

    let receipt = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::ClassicalOnly,
        )
        .expect("classical-only envelope verifies");

    assert_eq!(envelope.payload(), &expected);
    assert_eq!(receipt.object_type, kind);
    assert_eq!(receipt.sig_kinds_verified, vec!["ed25519"]);
}

fn assert_pq_only_roundtrip(kind: HybridSignedObjectKind, payload: FixturePayload) {
    let (classical_key, pq_key) = keys();
    let expected = payload.clone();
    let envelope = SignedEnvelope::sign_pq_only(kind, payload, &pq_key).unwrap();

    let receipt = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::PqOnly,
        )
        .expect("pq-only envelope verifies");

    assert_eq!(envelope.payload(), &expected);
    assert_eq!(receipt.object_type, kind);
    assert_eq!(receipt.sig_kinds_verified, vec!["ml-dsa-65"]);
}

fn assert_both_sigs_roundtrip(kind: HybridSignedObjectKind, payload: FixturePayload) {
    let (classical_key, pq_key) = keys();
    let expected = payload.clone();
    let envelope = SignedEnvelope::sign(kind, payload, &classical_key, &pq_key).unwrap();

    let receipt = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::BothRequired,
        )
        .expect("both-required envelope verifies");

    assert_eq!(envelope.payload(), &expected);
    assert_eq!(receipt.object_type, kind);
    assert_eq!(receipt.sig_kinds_verified, vec!["ed25519", "ml-dsa-65"]);
}

fn assert_either_ok_policy_accepts_one(kind: HybridSignedObjectKind, payload: FixturePayload) {
    let (classical_key, pq_key) = keys();
    let expected = payload.clone();
    let envelope = SignedEnvelope::sign_classical_only(kind, payload, &classical_key).unwrap();

    let receipt = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::EitherOk,
        )
        .expect("either-ok accepts one valid signature");

    assert_eq!(envelope.payload(), &expected);
    assert_eq!(receipt.object_type, kind);
    assert_eq!(receipt.sig_kinds_verified, vec!["ed25519"]);
}

fn assert_both_required_policy_rejects_one(kind: HybridSignedObjectKind, payload: FixturePayload) {
    let (classical_key, pq_key) = keys();
    let expected = payload.clone();
    let envelope = SignedEnvelope::sign_classical_only(kind, payload, &classical_key).unwrap();

    let err = envelope
        .verify(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::BothRequired,
        )
        .expect_err("both-required rejects missing PQ signature");

    assert_eq!(envelope.payload(), &expected);
    assert!(matches!(err, CryptoError::PqSignatureMissing));
}

#[test]
fn test_capability_token_classical_only_roundtrip() {
    assert_classical_only_roundtrip(
        HybridSignedObjectKind::CapabilityToken,
        payload("capability"),
    );
}

#[test]
fn test_capability_token_pq_only_roundtrip() {
    assert_pq_only_roundtrip(
        HybridSignedObjectKind::CapabilityToken,
        payload("capability"),
    );
}

#[test]
fn test_capability_token_both_sigs_roundtrip() {
    assert_both_sigs_roundtrip(
        HybridSignedObjectKind::CapabilityToken,
        payload("capability"),
    );
}

#[test]
fn test_capability_token_either_ok_policy_accepts_one() {
    assert_either_ok_policy_accepts_one(
        HybridSignedObjectKind::CapabilityToken,
        payload("capability"),
    );
}

#[test]
fn test_capability_token_both_required_policy_rejects_one() {
    assert_both_required_policy_rejects_one(
        HybridSignedObjectKind::CapabilityToken,
        payload("capability"),
    );
}

#[test]
fn test_audit_event_classical_only_roundtrip() {
    assert_classical_only_roundtrip(HybridSignedObjectKind::AuditEvent, payload("audit-event"));
}

#[test]
fn test_audit_event_pq_only_roundtrip() {
    assert_pq_only_roundtrip(HybridSignedObjectKind::AuditEvent, payload("audit-event"));
}

#[test]
fn test_audit_event_both_sigs_roundtrip() {
    assert_both_sigs_roundtrip(HybridSignedObjectKind::AuditEvent, payload("audit-event"));
}

#[test]
fn test_audit_event_either_ok_policy_accepts_one() {
    assert_either_ok_policy_accepts_one(HybridSignedObjectKind::AuditEvent, payload("audit-event"));
}

#[test]
fn test_audit_event_both_required_policy_rejects_one() {
    assert_both_required_policy_rejects_one(
        HybridSignedObjectKind::AuditEvent,
        payload("audit-event"),
    );
}

#[test]
fn test_manifest_classical_only_roundtrip() {
    assert_classical_only_roundtrip(HybridSignedObjectKind::Manifest, payload("manifest"));
}

#[test]
fn test_manifest_pq_only_roundtrip() {
    assert_pq_only_roundtrip(HybridSignedObjectKind::Manifest, payload("manifest"));
}

#[test]
fn test_manifest_both_sigs_roundtrip() {
    assert_both_sigs_roundtrip(HybridSignedObjectKind::Manifest, payload("manifest"));
}

#[test]
fn test_manifest_either_ok_policy_accepts_one() {
    assert_either_ok_policy_accepts_one(HybridSignedObjectKind::Manifest, payload("manifest"));
}

#[test]
fn test_manifest_both_required_policy_rejects_one() {
    assert_both_required_policy_rejects_one(HybridSignedObjectKind::Manifest, payload("manifest"));
}

#[test]
fn test_gossip_frame_classical_only_roundtrip() {
    assert_classical_only_roundtrip(HybridSignedObjectKind::GossipFrame, payload("gossip-frame"));
}

#[test]
fn test_gossip_frame_pq_only_roundtrip() {
    assert_pq_only_roundtrip(HybridSignedObjectKind::GossipFrame, payload("gossip-frame"));
}

#[test]
fn test_gossip_frame_both_sigs_roundtrip() {
    assert_both_sigs_roundtrip(HybridSignedObjectKind::GossipFrame, payload("gossip-frame"));
}

#[test]
fn test_gossip_frame_either_ok_policy_accepts_one() {
    assert_either_ok_policy_accepts_one(
        HybridSignedObjectKind::GossipFrame,
        payload("gossip-frame"),
    );
}

#[test]
fn test_gossip_frame_both_required_policy_rejects_one() {
    assert_both_required_policy_rejects_one(
        HybridSignedObjectKind::GossipFrame,
        payload("gossip-frame"),
    );
}

#[test]
fn test_revocation_classical_only_roundtrip() {
    assert_classical_only_roundtrip(HybridSignedObjectKind::Revocation, payload("revocation"));
}

#[test]
fn test_revocation_pq_only_roundtrip() {
    assert_pq_only_roundtrip(HybridSignedObjectKind::Revocation, payload("revocation"));
}

#[test]
fn test_revocation_both_sigs_roundtrip() {
    assert_both_sigs_roundtrip(HybridSignedObjectKind::Revocation, payload("revocation"));
}

#[test]
fn test_revocation_either_ok_policy_accepts_one() {
    assert_either_ok_policy_accepts_one(HybridSignedObjectKind::Revocation, payload("revocation"));
}

#[test]
fn test_revocation_both_required_policy_rejects_one() {
    assert_both_required_policy_rejects_one(
        HybridSignedObjectKind::Revocation,
        payload("revocation"),
    );
}

#[test]
fn test_operation_receipt_classical_only_roundtrip() {
    assert_classical_only_roundtrip(
        HybridSignedObjectKind::OperationReceipt,
        payload("operation-receipt"),
    );
}

#[test]
fn test_operation_receipt_pq_only_roundtrip() {
    assert_pq_only_roundtrip(
        HybridSignedObjectKind::OperationReceipt,
        payload("operation-receipt"),
    );
}

#[test]
fn test_operation_receipt_both_sigs_roundtrip() {
    assert_both_sigs_roundtrip(
        HybridSignedObjectKind::OperationReceipt,
        payload("operation-receipt"),
    );
}

#[test]
fn test_operation_receipt_either_ok_policy_accepts_one() {
    assert_either_ok_policy_accepts_one(
        HybridSignedObjectKind::OperationReceipt,
        payload("operation-receipt"),
    );
}

#[test]
fn test_operation_receipt_both_required_policy_rejects_one() {
    assert_both_required_policy_rejects_one(
        HybridSignedObjectKind::OperationReceipt,
        payload("operation-receipt"),
    );
}

#[test]
fn test_zone_checkpoint_classical_only_roundtrip() {
    assert_classical_only_roundtrip(
        HybridSignedObjectKind::ZoneCheckpoint,
        payload("zone-checkpoint"),
    );
}

#[test]
fn test_zone_checkpoint_pq_only_roundtrip() {
    assert_pq_only_roundtrip(
        HybridSignedObjectKind::ZoneCheckpoint,
        payload("zone-checkpoint"),
    );
}

#[test]
fn test_zone_checkpoint_both_sigs_roundtrip() {
    assert_both_sigs_roundtrip(
        HybridSignedObjectKind::ZoneCheckpoint,
        payload("zone-checkpoint"),
    );
}

#[test]
fn test_zone_checkpoint_either_ok_policy_accepts_one() {
    assert_either_ok_policy_accepts_one(
        HybridSignedObjectKind::ZoneCheckpoint,
        payload("zone-checkpoint"),
    );
}

#[test]
fn test_zone_checkpoint_both_required_policy_rejects_one() {
    assert_both_required_policy_rejects_one(
        HybridSignedObjectKind::ZoneCheckpoint,
        payload("zone-checkpoint"),
    );
}

#[test]
fn hybrid_transcript_binds_object_type() {
    let payload = payload("same-payload");
    let capability_bytes =
        signing_bytes_for_payload(HybridSignedObjectKind::CapabilityToken, &payload).unwrap();
    let revocation_bytes =
        signing_bytes_for_payload(HybridSignedObjectKind::Revocation, &payload).unwrap();

    assert_ne!(
        capability_bytes, revocation_bytes,
        "same payload bytes must not be replayable across object types"
    );
}

#[test]
fn migrated_signable_payload_normalizes_legacy_signature_field() {
    let (classical_key, pq_key) = keys();
    let payload = LegacySignaturePayload {
        body: "audit event payload".to_string(),
        legacy_signature: vec![0xAA; 64],
    };
    let mut envelope = payload.sign_hybrid(&classical_key, &pq_key).unwrap();

    envelope.payload.legacy_signature = vec![0xBB; 64];
    let receipt = envelope
        .verify_signable(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::BothRequired,
        )
        .expect("legacy signature bytes are normalized out of hybrid transcript");
    assert_eq!(receipt.sig_kinds_verified, vec!["ed25519", "ml-dsa-65"]);

    envelope.payload.body.push_str(" tampered");
    let err = envelope
        .verify_signable(
            &classical_key.verifying_key(),
            pq_key.verifying_key(),
            PqSigningPolicy::BothRequired,
        )
        .expect_err("payload body remains signed");
    assert!(matches!(err, CryptoError::SignatureVerificationFailed));
}

#[test]
fn test_policy_downgrade_emits_audit() {
    let token = MockHardwareToken {
        fingerprint: "hw:sha256:0123456789abcdef",
    };

    let audit = downgrade_policy_to_either_ok(
        PqSigningPolicy::BothRequired,
        &token,
        "temporary ML-DSA verifier outage",
    )
    .expect("mock hardware token authorizes downgrade");

    assert_eq!(audit.event_type, EVENT_PQ_POLICY_DOWNGRADE);
    assert_eq!(audit.previous_policy, PqSigningPolicy::BothRequired);
    assert_eq!(audit.new_policy, PqSigningPolicy::EitherOk);
    assert_eq!(audit.operator_fingerprint, token.fingerprint);
    assert_eq!(audit.reason, "temporary ML-DSA verifier outage");
}
