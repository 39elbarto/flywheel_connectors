//! Integration tests: supply chain verification gate.
//!
//! Tests the host-side verification pipeline for connector install gating.
//! Covers policy enforcement, caching, determinism, and audit events.
//!
//! Bead: flywheel_connectors-3gzz

use chrono::{TimeZone, Utc};
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType, SBOM_SIGNED_FIELDS,
    SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SbomComponent, SbomDependency,
};
use fcp_evidence::{
    ConnectorId, SbomFormat, SoftwareBillOfMaterials, SupplyChainAttestation, SupplyChainSignature,
    SupplyChainVerificationPolicy, TrustRootBinding, VerificationDecision, VerificationReasonCode,
};
use fcp_host::{GateOutcome, SupplyChainGate, SupplyChainGateConfig};

// ── Test Fixtures ────────────────────────────────────────────────

fn test_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap()
}

fn valid_digest() -> String {
    format!("blake3-256:{}", "a".repeat(64))
}

fn valid_attestation(digest: &str) -> SupplyChainAttestation {
    SupplyChainAttestation {
        format: "fcp-supply-chain-attestation".to_string(),
        schema_version: "1.0".to_string(),
        subject_digest: digest.to_string(),
        predicate_type: AttestationPredicateType::SlsaProvenanceV1,
        builder_id: "ci.example.com/builder".to_string(),
        build_type: "container".to_string(),
        materials: vec![AttestationMaterial {
            uri: "https://github.com/example/repo".to_string(),
            digest: format!("blake3-256:{}", "e".repeat(64)),
        }],
        metadata: AttestationMetadata {
            build_started_at: test_time(),
            build_finished_at: test_time(),
            invocation_id: Some("inv-001".to_string()),
        },
        slsa_level: 2,
        provenance_hash: format!("blake3-256:{}", "b".repeat(64)),
        trust_root: TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "root-001".to_string(),
        },
        builder_allowlist: vec!["ci.example.com/builder".to_string()],
        signature: SupplyChainSignature {
            algorithm: "ed25519".to_string(),
            key_id: "key-001".to_string(),
            signature: "f".repeat(128),
            signed_fields: SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        },
    }
}

fn valid_sbom() -> SoftwareBillOfMaterials {
    SoftwareBillOfMaterials {
        format: "fcp-sbom".to_string(),
        schema_version: "1.0".to_string(),
        bom_format: SbomFormat::Cyclonedx,
        bom_version: "1.0.0".to_string(),
        tool_chain: vec!["cargo".to_string()],
        components: vec![SbomComponent {
            component_id: "comp-001".to_string(),
            name: "fcp-core".to_string(),
            version: "0.1.0".to_string(),
            hashes: vec![format!("blake3-256:{}", "c".repeat(64))],
            licenses: vec!["Apache-2.0".to_string()],
        }],
        dependencies: vec![SbomDependency {
            component_id: "comp-001".to_string(),
            depends_on: vec![],
        }],
        trust_root: TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "root-002".to_string(),
        },
        signature: SupplyChainSignature {
            algorithm: "ed25519".to_string(),
            key_id: "key-002".to_string(),
            signature: "f".repeat(128),
            signed_fields: SBOM_SIGNED_FIELDS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        },
    }
}

// ── Integration: Full Verification Flow ──────────────────────────

#[test]
fn verify_happy_path_produces_allow_with_evidence() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    assert!(outcome.allowed);
    assert_eq!(outcome.evidence.decision, VerificationDecision::Allow);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::Verified
    );
    assert!(!outcome.evidence.steps.is_empty());
    assert!(
        outcome
            .audit_event
            .evidence_digest
            .starts_with("blake3-256:")
    );
    assert!(!outcome.cached);
}

#[test]
fn verify_deny_missing_attestation() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");

    let outcome = gate
        .verify_at(
            &cid,
            "1.0.0",
            &valid_digest(),
            None,
            Some(&valid_sbom()),
            test_time(),
        )
        .unwrap();

    assert!(!outcome.allowed);
    assert_eq!(outcome.evidence.decision, VerificationDecision::Deny);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::AttestationMissing
    );
}

#[test]
fn verify_deny_missing_sbom() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), None, test_time())
        .unwrap();

    assert!(!outcome.allowed);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::SbomMissing
    );
}

#[test]
fn verify_deny_slsa_level_too_low() {
    let config = SupplyChainGateConfig {
        policy: SupplyChainVerificationPolicy {
            min_slsa_level: 3, // att has level 2
            ..SupplyChainVerificationPolicy::default()
        },
        ..SupplyChainGateConfig::default()
    };
    let gate = SupplyChainGate::with_config(config);
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    assert!(!outcome.allowed);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::SlsaLevelInsufficient
    );
}

#[test]
fn verify_deny_untrusted_builder() {
    let config = SupplyChainGateConfig {
        policy: SupplyChainVerificationPolicy {
            trusted_builders: vec!["trusted.ci.example.com".to_string()],
            ..SupplyChainVerificationPolicy::default()
        },
        ..SupplyChainGateConfig::default()
    };
    let gate = SupplyChainGate::with_config(config);
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest); // builder = ci.example.com/builder
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    assert!(!outcome.allowed);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::BuilderUntrusted
    );
}

#[test]
fn verify_deny_digest_mismatch() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let real_digest = valid_digest();
    let wrong_digest = format!("blake3-256:{}", "f".repeat(64));
    let att = valid_attestation(&real_digest); // att.subject_digest != wrong_digest
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(
            &cid,
            "1.0.0",
            &wrong_digest,
            Some(&att),
            Some(&sbom),
            test_time(),
        )
        .unwrap();

    assert!(!outcome.allowed);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::SubjectDigestMismatch
    );
}

#[test]
fn verify_dev_override_allows_unsigned() {
    let config = SupplyChainGateConfig {
        policy: SupplyChainVerificationPolicy::default(),
        allow_dev_overrides: true,
        cache_capacity: 256,
    };
    let gate = SupplyChainGate::with_config(config);
    let cid = ConnectorId::from_static("fcp.test-dev:utility:0.1.0");

    let outcome = gate
        .verify_at(&cid, "0.1.0-dev", &valid_digest(), None, None, test_time())
        .unwrap();

    assert!(outcome.allowed);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::AllowedUnsigned
    );
}

#[test]
fn verify_dev_override_still_rejects_invalid_artifact_digest() {
    let config = SupplyChainGateConfig {
        policy: SupplyChainVerificationPolicy::default(),
        allow_dev_overrides: true,
        cache_capacity: 256,
    };
    let gate = SupplyChainGate::with_config(config);
    let cid = ConnectorId::from_static("fcp.test-dev:utility:0.1.0");

    let outcome = gate
        .verify_at(&cid, "0.1.0-dev", "not-a-digest", None, None, test_time())
        .unwrap();

    assert!(!outcome.allowed);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::ArtifactDigestInvalid
    );
}

// ── Cache Integration ────────────────────────────────────────────

#[test]
fn cache_serves_repeated_verification() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let first = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();
    assert!(!first.cached);
    assert_eq!(gate.cache_size(), 1);

    let second = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();
    assert!(second.cached);
    assert_eq!(second.evidence, first.evidence);
}

#[test]
fn cache_isolates_different_artifacts() {
    let gate = SupplyChainGate::new();
    let cid1 = ConnectorId::from_static("fcp.alpha:utility:1.0.0");
    let cid2 = ConnectorId::from_static("fcp.beta:utility:1.0.0");
    let d1 = valid_digest();
    let d2 = format!("blake3-256:{}", "d".repeat(64));
    let att1 = valid_attestation(&d1);
    let att2 = valid_attestation(&d2);
    let sbom = valid_sbom();

    gate.verify_at(&cid1, "1.0.0", &d1, Some(&att1), Some(&sbom), test_time())
        .unwrap();
    gate.verify_at(&cid2, "2.0.0", &d2, Some(&att2), Some(&sbom), test_time())
        .unwrap();

    assert_eq!(gate.cache_size(), 2);
}

#[test]
fn clear_cache_forces_recomputation() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    gate.verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();
    assert_eq!(gate.cache_size(), 1);

    gate.clear_cache();
    assert_eq!(gate.cache_size(), 0);

    let result = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();
    assert!(!result.cached);
}

// ── Determinism ──────────────────────────────────────────────────

#[test]
fn evidence_is_deterministic_across_calls() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    gate.clear_cache();
    let o1 = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    gate.clear_cache();
    let o2 = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    assert_eq!(o1.evidence, o2.evidence);
    assert_eq!(
        o1.audit_event.evidence_digest,
        o2.audit_event.evidence_digest
    );
}

#[test]
fn evidence_digest_has_correct_format() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    let ed = &outcome.audit_event.evidence_digest;
    assert!(ed.starts_with("blake3-256:"));
    assert_eq!(ed.len(), "blake3-256:".len() + 64);
}

// ── Audit Events ─────────────────────────────────────────────────

#[test]
fn audit_event_fields_are_consistent() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    assert_eq!(outcome.audit_event.connector_id, cid);
    assert_eq!(outcome.audit_event.version, "1.0.0");
    assert_eq!(outcome.audit_event.artifact_digest, digest);
    assert_eq!(
        outcome.audit_event.steps_executed,
        outcome.evidence.steps.len()
    );
    assert_eq!(
        outcome.audit_event.steps_passed,
        outcome.evidence.steps.iter().filter(|s| s.passed).count()
    );
    assert!(!outcome.audit_event.cached);
}

#[test]
fn audit_event_correctly_flags_cache_hit() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let first = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();
    assert!(!first.audit_event.cached);

    let second = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();
    assert!(second.audit_event.cached);
}

// ── JSON Serialization ───────────────────────────────────────────

#[test]
fn gate_outcome_serializes_to_json() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    let json = serde_json::to_string(&outcome).unwrap();
    assert!(json.contains("\"allowed\":true"));
    assert!(json.contains("\"decision\":\"allow\""));
}

#[test]
fn gate_outcome_round_trips_json() {
    let gate = SupplyChainGate::new();
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    let json = serde_json::to_string(&outcome).unwrap();
    let round_tripped: GateOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(round_tripped.allowed, outcome.allowed);
    assert_eq!(round_tripped.evidence, outcome.evidence);
}

// ── Policy Matrix ────────────────────────────────────────────────

#[test]
fn slsa_level_boundary_matrix() {
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest); // slsa_level = 2
    let sbom = valid_sbom();

    for required_level in 0..=4u8 {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: required_level,
                ..SupplyChainVerificationPolicy::default()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let outcome = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();

        if required_level <= 2 {
            assert!(outcome.allowed, "should allow at level {required_level}");
        } else {
            assert!(!outcome.allowed, "should deny at level {required_level}");
        }
    }
}

#[test]
fn policy_snapshot_is_embedded_in_evidence() {
    let config = SupplyChainGateConfig {
        policy: SupplyChainVerificationPolicy {
            min_slsa_level: 1,
            trusted_builders: vec!["ci.example.com/builder".to_string()],
            ..SupplyChainVerificationPolicy::default()
        },
        ..SupplyChainGateConfig::default()
    };
    let gate = SupplyChainGate::with_config(config);
    let cid = ConnectorId::from_static("fcp.test-echo:utility:1.0.0");
    let digest = valid_digest();
    let att = valid_attestation(&digest);
    let sbom = valid_sbom();

    let outcome = gate
        .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
        .unwrap();

    assert_eq!(outcome.evidence.policy_snapshot.min_slsa_level, 1);
    assert_eq!(
        outcome.evidence.policy_snapshot.trusted_builders,
        vec!["ci.example.com/builder"]
    );
}
