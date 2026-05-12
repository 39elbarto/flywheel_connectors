use fcp_crypto::{
    CryptoError, Ed25519SigningKey, MlDsa65SigningKey, PqSigningPolicy, SignedEnvelope,
    canonical_signing_bytes, canonicalize::to_deterministic_cbor,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FixturePayload {
    object_type: String,
    sequence: u64,
    body: Vec<u8>,
}

fn fixture_payload(object_type: &str) -> FixturePayload {
    FixturePayload {
        object_type: object_type.to_string(),
        sequence: 42,
        body: format!("hybrid-signing-fixture:{object_type}").into_bytes(),
    }
}

fn signing_bytes(payload: &FixturePayload) -> Vec<u8> {
    let cbor = to_deterministic_cbor(payload).expect("fixture payload must encode");
    canonical_signing_bytes(
        &format!("fcp.hybrid-signing.{}.v1", payload.object_type),
        &cbor,
    )
}

fn signing_keys() -> (Ed25519SigningKey, MlDsa65SigningKey) {
    let classical =
        Ed25519SigningKey::from_bytes(&[0x51; 32]).expect("test Ed25519 key must decode");
    let pq = MlDsa65SigningKey::from_seed(&[0xA5; 32]).expect("test ML-DSA key must decode");
    (classical, pq)
}

fn serde_roundtrip(envelope: &SignedEnvelope<FixturePayload>) -> SignedEnvelope<FixturePayload> {
    let encoded = serde_json::to_vec(envelope).expect("envelope must serialize");
    serde_json::from_slice(&encoded).expect("envelope must deserialize")
}

fn assert_classical_only_roundtrip(object_type: &str) {
    let (classical, pq) = signing_keys();
    let payload = fixture_payload(object_type);
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign_with_policy(
        object_type,
        payload.clone(),
        &bytes,
        PqSigningPolicy::ClassicalOnly,
        Some(&classical),
        Some(&pq),
    )
    .expect("classical-only signing must succeed");
    assert!(envelope.sig_classical.is_some());
    assert!(envelope.sig_pq.is_none());

    let decoded = serde_roundtrip(&envelope);
    let classical_verifier = classical.verifying_key();
    let report = decoded
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::ClassicalOnly,
            Some(&classical_verifier),
            None,
        )
        .expect("classical-only verification must succeed");
    assert!(report.signatures_verified.classical);
    assert!(!report.signatures_verified.pq);
    assert_eq!(decoded.payload, payload);
}

fn assert_pq_only_roundtrip(object_type: &str) {
    let (_classical, pq) = signing_keys();
    let payload = fixture_payload(object_type);
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign_with_policy(
        object_type,
        payload.clone(),
        &bytes,
        PqSigningPolicy::PqOnly,
        None,
        Some(&pq),
    )
    .expect("PQ-only signing must succeed");
    assert!(envelope.sig_classical.is_none());
    assert!(envelope.sig_pq.is_some());

    let decoded = serde_roundtrip(&envelope);
    let report = decoded
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::PqOnly,
            None,
            Some(pq.verifying_key()),
        )
        .expect("PQ-only verification must succeed");
    assert!(!report.signatures_verified.classical);
    assert!(report.signatures_verified.pq);
    assert_eq!(decoded.payload, payload);
}

fn assert_both_sigs_roundtrip(object_type: &str) {
    let (classical, pq) = signing_keys();
    let payload = fixture_payload(object_type);
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign(object_type, payload.clone(), &bytes, &classical, &pq)
        .expect("hybrid signing must succeed");
    assert!(envelope.sig_classical.is_some());
    assert!(envelope.sig_pq.is_some());

    let decoded = serde_roundtrip(&envelope);
    let classical_verifier = classical.verifying_key();
    let report = decoded
        .verify(&bytes, &classical_verifier, pq.verifying_key())
        .expect("both-required verification must succeed");
    assert!(report.signatures_verified.classical);
    assert!(report.signatures_verified.pq);
    assert_eq!(decoded.payload, payload);
}

fn assert_either_ok_policy_accepts_one(object_type: &str) {
    let (classical, _pq) = signing_keys();
    let payload = fixture_payload(object_type);
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign_with_policy(
        object_type,
        payload.clone(),
        &bytes,
        PqSigningPolicy::EitherOk,
        Some(&classical),
        None,
    )
    .expect("either-ok signing with one signer must succeed");

    let decoded = serde_roundtrip(&envelope);
    let classical_verifier = classical.verifying_key();
    let report = decoded
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::EitherOk,
            Some(&classical_verifier),
            None,
        )
        .expect("either-ok verification must accept one valid signature");
    assert!(report.signatures_verified.classical);
    assert!(!report.signatures_verified.pq);
    assert_eq!(decoded.payload, payload);
}

fn assert_both_required_policy_rejects_one(object_type: &str) {
    let (classical, _pq) = signing_keys();
    let payload = fixture_payload(object_type);
    let bytes = signing_bytes(&payload);
    let envelope = SignedEnvelope::sign_with_policy(
        object_type,
        payload,
        &bytes,
        PqSigningPolicy::ClassicalOnly,
        Some(&classical),
        None,
    )
    .expect("classical-only signing must succeed");

    let classical_verifier = classical.verifying_key();
    let err = envelope
        .verify_with_policy(
            &bytes,
            PqSigningPolicy::BothRequired,
            Some(&classical_verifier),
            None,
        )
        .expect_err("both-required verification must reject one signature");
    assert!(matches!(
        err,
        CryptoError::MissingPqSignature {
            policy: "BothRequired"
        }
    ));
}

macro_rules! hybrid_roundtrip_suite {
    (
        $object_type:literal,
        $classical_only:ident,
        $pq_only:ident,
        $both_sigs:ident,
        $either_ok:ident,
        $both_required_rejects_one:ident
    ) => {
        #[test]
        fn $classical_only() {
            assert_classical_only_roundtrip($object_type);
        }

        #[test]
        fn $pq_only() {
            assert_pq_only_roundtrip($object_type);
        }

        #[test]
        fn $both_sigs() {
            assert_both_sigs_roundtrip($object_type);
        }

        #[test]
        fn $either_ok() {
            assert_either_ok_policy_accepts_one($object_type);
        }

        #[test]
        fn $both_required_rejects_one() {
            assert_both_required_policy_rejects_one($object_type);
        }
    };
}

hybrid_roundtrip_suite!(
    "capability_token",
    capability_token_classical_only_roundtrip,
    capability_token_pq_only_roundtrip,
    capability_token_both_sigs_roundtrip,
    capability_token_either_ok_policy_accepts_one,
    capability_token_both_required_policy_rejects_one
);
hybrid_roundtrip_suite!(
    "audit_event",
    audit_event_classical_only_roundtrip,
    audit_event_pq_only_roundtrip,
    audit_event_both_sigs_roundtrip,
    audit_event_either_ok_policy_accepts_one,
    audit_event_both_required_policy_rejects_one
);
hybrid_roundtrip_suite!(
    "manifest",
    manifest_classical_only_roundtrip,
    manifest_pq_only_roundtrip,
    manifest_both_sigs_roundtrip,
    manifest_either_ok_policy_accepts_one,
    manifest_both_required_policy_rejects_one
);
hybrid_roundtrip_suite!(
    "gossip_frame",
    gossip_frame_classical_only_roundtrip,
    gossip_frame_pq_only_roundtrip,
    gossip_frame_both_sigs_roundtrip,
    gossip_frame_either_ok_policy_accepts_one,
    gossip_frame_both_required_policy_rejects_one
);
hybrid_roundtrip_suite!(
    "revocation",
    revocation_classical_only_roundtrip,
    revocation_pq_only_roundtrip,
    revocation_both_sigs_roundtrip,
    revocation_either_ok_policy_accepts_one,
    revocation_both_required_policy_rejects_one
);
hybrid_roundtrip_suite!(
    "operation_receipt",
    operation_receipt_classical_only_roundtrip,
    operation_receipt_pq_only_roundtrip,
    operation_receipt_both_sigs_roundtrip,
    operation_receipt_either_ok_policy_accepts_one,
    operation_receipt_both_required_policy_rejects_one
);
hybrid_roundtrip_suite!(
    "zone_checkpoint",
    zone_checkpoint_classical_only_roundtrip,
    zone_checkpoint_pq_only_roundtrip,
    zone_checkpoint_both_sigs_roundtrip,
    zone_checkpoint_either_ok_policy_accepts_one,
    zone_checkpoint_both_required_policy_rejects_one
);
