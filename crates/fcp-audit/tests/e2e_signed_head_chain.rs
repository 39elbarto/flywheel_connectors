use fcp_audit::{
    AuditEntry, AuditEntryBuilder, AuditError, ChainHead, HeadSignature, Severity,
    verify_chain_with_signers,
};
use fcp_crypto::KeyId;
use fcp_crypto::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use serde_json::json;
use tracing::{Level, span};

fn build_entry(seq: u64, prev: Option<&str>) -> AuditEntry {
    let mut builder = AuditEntryBuilder::new()
        .id("__provisional__")
        .event_type("epsilon.e2e.invoke")
        .severity(Severity::Info)
        .actor("agent:goldenfinch")
        .zone_id("z:work")
        .seq(seq)
        .occurred_at(1_700_000_000 + seq)
        .connector_id("epsilon-e2e")
        .operation_id("op.audit.e2e")
        .meta("stage", json!(seq));
    if let Some(prev) = prev {
        builder = builder.prev(prev);
    }
    let provisional = builder.clone().build().expect("provisional audit entry");
    let id = provisional.computed_id().expect("canonical id");
    builder.id(id).build().expect("audit entry")
}

fn signed_chain(signing_key: &Ed25519SigningKey) -> Vec<AuditEntry> {
    let mut entries = Vec::new();
    let mut prev = None;
    for seq in 0..3 {
        let mut entry = build_entry(seq, prev.as_deref());
        entry.sign(signing_key).expect("entry signature");
        prev = Some(entry.id.clone());
        entries.push(entry);
    }
    entries
}

fn signed_head(entries: &[AuditEntry], signing_key: &Ed25519SigningKey) -> ChainHead {
    let tip = entries.last().expect("chain tip");
    let mut head = ChainHead {
        zone_id: tip.zone_id.clone(),
        head_entry: tip.id.clone(),
        head_seq: tip.seq,
        coverage: 1.0,
        epoch_id: "epoch-epsilon-e2e".to_string(),
        signature_count: 1,
        signatures: Vec::new(),
    };
    let signature = signing_key.sign(&head.signing_bytes());
    head.signatures.push(HeadSignature {
        issuer_kid: signing_key.key_id().to_hex(),
        signature: signature.to_bytes().to_vec(),
    });
    head
}

#[test]
fn e2e_signed_head_append_verifies_and_detects_tamper() {
    let mut phases = Vec::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let trusted_kid = signing_key.key_id();

    let entries = {
        let span = span!(
            Level::INFO,
            "e2e_audit_phase",
            crate_name = "fcp-audit",
            phase = "append_signed_entries"
        );
        let _entered = span.enter();
        phases.push("append_signed_entries");
        signed_chain(&signing_key)
    };

    let head = {
        let span = span!(
            Level::INFO,
            "e2e_audit_phase",
            crate_name = "fcp-audit",
            phase = "sign_head"
        );
        let _entered = span.enter();
        phases.push("sign_head");
        let head = signed_head(&entries, &signing_key);
        assert!(head.has_quorum());
        head
    };

    let resolver = |kid: &KeyId| -> Option<Ed25519VerifyingKey> {
        if kid.as_slice() == trusted_kid.as_slice() {
            Some(verifying_key.clone())
        } else {
            None
        }
    };

    {
        let span = span!(
            Level::INFO,
            "e2e_audit_phase",
            crate_name = "fcp-audit",
            phase = "verify_round_trip"
        );
        let _entered = span.enter();
        phases.push("verify_round_trip");
        let report = verify_chain_with_signers(&entries, Some(&head), Some("z:work"), resolver)
            .expect("signed chain and head verify");
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        assert_eq!(report.chain_len, 3);
        assert_eq!(report.head_entry.as_deref(), Some(head.head_entry.as_str()));
    }

    {
        let span = span!(
            Level::INFO,
            "e2e_audit_phase",
            crate_name = "fcp-audit",
            phase = "tamper_detection"
        );
        let _entered = span.enter();
        phases.push("tamper_detection");
        let mut tampered = head.clone();
        tampered.coverage = 0.25;
        let resolver = |kid: &KeyId| -> Option<Ed25519VerifyingKey> {
            if kid.as_slice() == trusted_kid.as_slice() {
                Some(verifying_key.clone())
            } else {
                None
            }
        };
        let err = verify_chain_with_signers(&entries, Some(&tampered), Some("z:work"), resolver)
            .expect_err("head coverage tamper invalidates signature");
        assert!(matches!(err, AuditError::SignatureInvalid { .. }));
    }

    assert_eq!(
        phases,
        [
            "append_signed_entries",
            "sign_head",
            "verify_round_trip",
            "tamper_detection"
        ]
    );
}
