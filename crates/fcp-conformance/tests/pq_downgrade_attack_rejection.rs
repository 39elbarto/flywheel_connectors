use fcp_crypto::{
    CryptoError, Ed25519SigningKey, HybridSignedObjectKind, MlDsa65SigningKey, PqSigningPolicy,
    SignedEnvelope,
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

const fn kind_from_index(index: usize) -> HybridSignedObjectKind {
    HybridSignedObjectKind::ALL[index % HybridSignedObjectKind::ALL.len()]
}

#[test]
fn test_no_code_path_accepts_classical_only_under_steady_state() {
    let (classical_key, pq_key) = keys();
    let strategy = (
        0usize..HybridSignedObjectKind::ALL.len(),
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
            let envelope = SignedEnvelope::sign_classical_only(
                kind,
                payload(kind, sequence, body),
                &classical_key,
            )
            .expect("classical-only envelope signs");

            let err = envelope
                .verify(
                    &classical_key.verifying_key(),
                    pq_key.verifying_key(),
                    PqSigningPolicy::BothRequired,
                )
                .expect_err("steady-state verifier must reject classical-only envelopes");

            prop_assert!(matches!(err, CryptoError::PqSignatureMissing));
            prop_assert_eq!(err.reason_code(), Some("DowngradeAttempt"));
            Ok(())
        })
        .expect("1000 generated classical-only envelopes are rejected");

    for kind in HybridSignedObjectKind::ALL {
        let envelope = SignedEnvelope::sign_classical_only(
            kind,
            payload(kind, 0, b"explicit-object-kind-coverage".to_vec()),
            &classical_key,
        )
        .expect("classical-only envelope signs");
        let err = envelope
            .verify(
                &classical_key.verifying_key(),
                pq_key.verifying_key(),
                PqSigningPolicy::BothRequired,
            )
            .expect_err("every signed-object kind rejects classical-only replay");
        assert!(matches!(err, CryptoError::PqSignatureMissing));
        assert_eq!(err.reason_code(), Some("DowngradeAttempt"));
    }
}
