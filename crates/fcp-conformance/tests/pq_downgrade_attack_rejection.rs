use fcp_crypto::{
    CryptoError, Ed25519SigningKey, HybridSignedObjectKind, MlDsa65SigningKey, PqSigningPolicy,
    SignedEnvelope, signing_bytes_for_payload,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DowngradeProbePayload {
    object_label: String,
    sequence: u64,
    body: Vec<u8>,
}

fn keys() -> (Ed25519SigningKey, MlDsa65SigningKey) {
    (
        Ed25519SigningKey::from_bytes(&[0x51; 32]).expect("ed25519 test key"),
        MlDsa65SigningKey::from_seed(&[0x61; 32]).expect("ml-dsa test key"),
    )
}

fn payload(kind: HybridSignedObjectKind, sequence: u64, body: Vec<u8>) -> DowngradeProbePayload {
    DowngradeProbePayload {
        object_label: kind.as_str().to_string(),
        sequence,
        body,
    }
}

const ALL_KINDS: [HybridSignedObjectKind; 7] = [
    HybridSignedObjectKind::CapabilityToken,
    HybridSignedObjectKind::AuditEvent,
    HybridSignedObjectKind::Manifest,
    HybridSignedObjectKind::GossipFrame,
    HybridSignedObjectKind::Revocation,
    HybridSignedObjectKind::OperationReceipt,
    HybridSignedObjectKind::ZoneCheckpoint,
];

const fn kind_from_index(index: usize) -> HybridSignedObjectKind {
    ALL_KINDS[index % ALL_KINDS.len()]
}

#[test]
fn test_no_code_path_accepts_classical_only_under_steady_state() {
    let (classical_key, pq_key) = keys();
    let classical_verifying_key = classical_key.verifying_key();
    let pq_verifying_key = pq_key.verifying_key();
    let strategy = (
        0usize..ALL_KINDS.len(),
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..128),
    );
    let mut runner = TestRunner::new(Config {
        cases: 1_000,
        ..Config::default()
    });

    runner
        .run(&strategy, |(kind_index, sequence, body)| {
            let kind = kind_from_index(kind_index);
            let payload = payload(kind, sequence, body);
            let signing_bytes = signing_bytes_for_payload(kind, &payload)
                .expect("downgrade probe signing bytes encode");
            let envelope = SignedEnvelope::sign_with_policy(
                kind.as_str(),
                payload,
                &signing_bytes,
                PqSigningPolicy::ClassicalOnly,
                Some(&classical_key),
                None,
            )
            .expect("classical-only envelope signs");

            let err = envelope
                .verify_with_policy(
                    &signing_bytes,
                    PqSigningPolicy::BothRequired,
                    Some(&classical_verifying_key),
                    Some(&pq_verifying_key),
                )
                .expect_err("steady-state verifier must reject classical-only envelopes");

            let missing_pq_signature = matches!(err, CryptoError::MissingPqSignature { .. });
            prop_assert!(missing_pq_signature);
            prop_assert_eq!(err.reason_code(), Some("DowngradeAttempt"));
            Ok(())
        })
        .expect("1000 generated classical-only envelopes are rejected");

    for kind in ALL_KINDS {
        let payload = payload(kind, 0, b"explicit-object-kind-coverage".to_vec());
        let signing_bytes = signing_bytes_for_payload(kind, &payload)
            .expect("downgrade probe signing bytes encode");
        let envelope = SignedEnvelope::sign_with_policy(
            kind.as_str(),
            payload,
            &signing_bytes,
            PqSigningPolicy::ClassicalOnly,
            Some(&classical_key),
            None,
        )
        .expect("classical-only envelope signs");
        let err = envelope
            .verify_with_policy(
                &signing_bytes,
                PqSigningPolicy::BothRequired,
                Some(&classical_verifying_key),
                Some(&pq_verifying_key),
            )
            .expect_err("every signed-object kind rejects classical-only replay");
        assert!(matches!(err, CryptoError::MissingPqSignature { .. }));
        assert_eq!(err.reason_code(), Some("DowngradeAttempt"));
    }
}
