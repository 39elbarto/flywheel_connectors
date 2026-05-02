use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_evidence::{
    ConstraintEnforcementReceipt, ConstraintReceiptVerifier, ConstraintsEvaluatedSummary,
    DEFAULT_RECEIPT_FRESHNESS_WINDOW_MS, EvaluationOutcomeRecord, ObjectId, ReceiptBody,
    ReceiptError, ReceiptNonce, ReceiptVerificationContext, RequestDescriptorHash, ZoneId,
};

const SEALED_AT_UNIX_MS: u64 = 4_000_000_000_000;
const REVOCATION_HEAD_SEQ: u64 = 7;

fn receipt_signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x41_u8; 32]).expect("valid receipt test key")
}

fn host_receipt_body(nonce: ReceiptNonce) -> ReceiptBody {
    ReceiptBody {
        token_id: ObjectId::from_unscoped_bytes(b"host-token-a"),
        zone_id: ZoneId::work(),
        request_nonce: nonce,
        request_descriptor_hash: RequestDescriptorHash::from_canonical_bytes(
            b"host invoke descriptor",
        ),
        constraints_evaluated: ConstraintsEvaluatedSummary {
            evaluated_kinds: vec!["host_allowlist".to_string(), "scope_ceiling".to_string()],
            resource_allow_count: 1,
            resource_deny_count: 0,
            max_calls_set: true,
            max_bytes_set: false,
            credential_allow_count: 0,
        },
        evaluation_outcome: EvaluationOutcomeRecord::Allow,
        sealed_at_unix_ms: SEALED_AT_UNIX_MS,
        expires_at_unix_ms: SEALED_AT_UNIX_MS + DEFAULT_RECEIPT_FRESHNESS_WINDOW_MS,
        revocation_head_seq_observed: REVOCATION_HEAD_SEQ,
        enforcing_node_id: TailscaleNodeId::new("host-enforcer-a"),
    }
}

fn host_receipt_context(now_unix_ms: u64) -> ReceiptVerificationContext {
    ReceiptVerificationContext::new(
        ObjectId::from_unscoped_bytes(b"host-token-a"),
        ZoneId::work(),
        REVOCATION_HEAD_SEQ,
        now_unix_ms,
    )
}

#[test]
fn receipt_replay_host_verifier_rejects_reused_nonce() {
    let key = receipt_signing_key();
    let receipt = ConstraintEnforcementReceipt::seal(
        host_receipt_body(ReceiptNonce::from_bytes([0x11_u8; 16])),
        &key,
    )
    .expect("seal receipt");
    let mut verifier = ConstraintReceiptVerifier::default();
    let context = host_receipt_context(SEALED_AT_UNIX_MS + 1_000);

    verifier
        .verify(&receipt, &key.verifying_key(), &context)
        .expect("first receipt accepted");
    let err = verifier
        .verify(&receipt, &key.verifying_key(), &context)
        .expect_err("second presentation is replay");
    assert!(matches!(err, ReceiptError::ReceiptReplayDetected { .. }));
}

#[test]
fn receipt_replay_host_verifier_rejects_stale_receipts() {
    let key = receipt_signing_key();
    let mut body = host_receipt_body(ReceiptNonce::from_bytes([0x22_u8; 16]));
    body.sealed_at_unix_ms = 1_000;
    body.expires_at_unix_ms = 2_000;
    let receipt = ConstraintEnforcementReceipt::seal(body, &key).expect("seal receipt");
    let mut verifier = ConstraintReceiptVerifier::default();
    let context = host_receipt_context(2_001);

    let err = verifier
        .verify(&receipt, &key.verifying_key(), &context)
        .expect_err("expired receipt is stale");
    assert!(matches!(err, ReceiptError::ReceiptExpired { .. }));
}
