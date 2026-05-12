use fcp_crypto::{
    CryptoError, Ed25519SigningKey, PqSigningPolicy, SignedEnvelope, canonical_signing_bytes,
    canonicalize::to_deterministic_cbor,
};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

const OBJECT_TYPES: [&str; 7] = [
    "capability_token",
    "audit_event",
    "manifest",
    "gossip_frame",
    "revocation",
    "operation_receipt",
    "zone_checkpoint",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DowngradeFixture {
    object_type: String,
    sequence: u64,
    body: Vec<u8>,
}

fn signing_bytes(payload: &DowngradeFixture) -> Vec<u8> {
    let cbor = to_deterministic_cbor(payload).expect("fixture payload must encode");
    canonical_signing_bytes(
        &format!("fcp.pq-downgrade.{}.v1", payload.object_type),
        &cbor,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn test_no_code_path_accepts_classical_only_under_steady_state(
        object_index in 0usize..OBJECT_TYPES.len(),
        sequence in any::<u64>(),
        body in proptest::collection::vec(any::<u8>(), 0usize..=128),
    ) {
        let object_type = OBJECT_TYPES[object_index];
        let payload = DowngradeFixture {
            object_type: object_type.to_string(),
            sequence,
            body,
        };
        let bytes = signing_bytes(&payload);
        let classical = Ed25519SigningKey::from_bytes(&[0x53; 32])
            .expect("test Ed25519 key must decode");
        let envelope = SignedEnvelope::sign_with_policy(
            object_type,
            payload,
            &bytes,
            PqSigningPolicy::ClassicalOnly,
            Some(&classical),
            None,
        )
        .expect("classical-only envelope must sign");

        let classical_verifier = classical.verifying_key();
        let result = envelope.verify_with_policy(
            &bytes,
            PqSigningPolicy::BothRequired,
            Some(&classical_verifier),
            None,
        );

        let err = result.expect_err("steady-state verification must reject classical-only envelopes");
        prop_assert_eq!(err.hybrid_reason_code(), Some("DowngradeAttempt"));
        match err {
            CryptoError::MissingPqSignature { policy } => prop_assert_eq!(policy, "BothRequired"),
            other => prop_assert!(false, "expected MissingPqSignature, got {other:?}"),
        }
    }
}
