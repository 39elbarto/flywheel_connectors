//! Integration tests for `fcp connector` and `fcp install` supply-chain flows.

use assert_cmd::Command;
use blake3::Hasher;
use chrono::{TimeZone, Utc};
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType, SBOM_SIGNED_FIELDS,
    SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SbomComponent, SbomFormat, SoftwareBillOfMaterials,
    SupplyChainAttestation, SupplyChainSignature, TrustRootBinding,
};
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn fcp_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fcp"));
    cmd.env("RUST_LOG", "error");
    cmd
}

fn digest_for_bytes(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    format!("blake3-256:{}", hasher.finalize().to_hex())
}

fn sample_trust_root(root_id: &str) -> TrustRootBinding {
    TrustRootBinding {
        root_type: "sigstore".to_string(),
        root_id: root_id.to_string(),
    }
}

fn sample_attestation(digest: &str, slsa_level: u8) -> SupplyChainAttestation {
    let builder_id = "builder://github/actions".to_string();
    SupplyChainAttestation {
        format: "fcp-supply-chain-attestation".to_string(),
        schema_version: "1.0".to_string(),
        subject_digest: digest.to_string(),
        predicate_type: AttestationPredicateType::SlsaProvenanceV1,
        builder_id: builder_id.clone(),
        build_type: "https://slsa.dev/container-based-build/v1".to_string(),
        materials: vec![AttestationMaterial {
            uri: "git+https://github.com/flywheel/connectors@refs/heads/main".to_string(),
            digest: format!("blake3-256:{}", "a".repeat(64)),
        }],
        metadata: AttestationMetadata {
            build_started_at: Utc
                .with_ymd_and_hms(2026, 2, 1, 12, 0, 0)
                .single()
                .expect("valid build start"),
            build_finished_at: Utc
                .with_ymd_and_hms(2026, 2, 1, 12, 5, 0)
                .single()
                .expect("valid build finish"),
            invocation_id: Some("gha-run-42".to_string()),
        },
        slsa_level,
        provenance_hash: format!("blake3-256:{}", "b".repeat(64)),
        trust_root: sample_trust_root("sigstore-public-good"),
        builder_allowlist: vec![builder_id],
        signature: SupplyChainSignature::new(
            "owner-key-1",
            "sig-data",
            SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        ),
    }
}

fn sample_sbom(digest: &str) -> SoftwareBillOfMaterials {
    SoftwareBillOfMaterials {
        format: "fcp-sbom".to_string(),
        schema_version: "1.0".to_string(),
        bom_format: SbomFormat::Cyclonedx,
        bom_version: "1".to_string(),
        tool_chain: vec!["cargo".to_string(), "rustc".to_string()],
        components: vec![SbomComponent {
            component_id: "fcp.telegram:base:v1".to_string(),
            name: "fcp.telegram:base:v1".to_string(),
            version: "1.0.0".to_string(),
            hashes: vec![digest.to_string()],
            licenses: vec!["Apache-2.0".to_string()],
        }],
        dependencies: vec![],
        trust_root: sample_trust_root("sbom-root"),
        signature: SupplyChainSignature::new(
            "owner-key-1",
            "sig-data",
            SBOM_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        ),
    }
}

fn write_supply_chain_files(temp: &TempDir, digest: &str, slsa_level: u8) -> (String, String) {
    let attestation = sample_attestation(digest, slsa_level);
    let sbom = sample_sbom(digest);
    let attestation_path = temp.path().join("attestation.json");
    let sbom_path = temp.path().join("sbom.json");
    fs::write(
        &attestation_path,
        serde_json::to_vec_pretty(&attestation).expect("serialize attestation"),
    )
    .expect("write attestation");
    fs::write(
        &sbom_path,
        serde_json::to_vec_pretty(&sbom).expect("serialize sbom"),
    )
    .expect("write sbom");
    (
        attestation_path.to_string_lossy().into_owned(),
        sbom_path.to_string_lossy().into_owned(),
    )
}

#[test]
fn connector_verify_json_emits_supply_chain_evidence() {
    let temp = TempDir::new().expect("tempdir");
    let digest = digest_for_bytes(b"connector-verify-fixture");
    let (attestation, sbom) = write_supply_chain_files(&temp, &digest, 3);

    let output = fcp_cmd()
        .args([
            "connector",
            "verify",
            "fcp.telegram:base:v1",
            "--attestation",
            &attestation,
            "--sbom",
            &sbom,
            "--digest",
            &digest,
            "--min-slsa-level",
            "3",
            "--json",
        ])
        .output()
        .expect("run connector verify");

    assert!(
        output.status.success(),
        "connector verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value = serde_json::from_slice(&output.stdout).expect("verify json");
    assert_eq!(payload["connector_id"], "fcp.telegram:base:v1");
    assert_eq!(payload["decision"], "allow");
    assert_eq!(payload["reason_code"], "verified");
    assert_eq!(payload["artifact_digest"], digest);
    assert_eq!(payload["policy"]["min_slsa_level"], 3);
    assert!(
        payload["evidence_digest"]
            .as_str()
            .expect("evidence digest")
            .starts_with("blake3-256:")
    );
    assert!(
        payload["steps"]
            .as_array()
            .expect("steps array")
            .iter()
            .any(|step| step["step"] == "attestation_presence")
    );
}

#[test]
fn connector_report_json_summarizes_provenance_and_sbom() {
    let temp = TempDir::new().expect("tempdir");
    let digest = digest_for_bytes(b"connector-report-fixture");
    let (attestation, sbom) = write_supply_chain_files(&temp, &digest, 3);

    let output = fcp_cmd()
        .args([
            "connector",
            "report",
            "fcp.telegram:base:v1",
            "--supply-chain",
            "--attestation",
            &attestation,
            "--sbom",
            &sbom,
            "--digest",
            &digest,
            "--json",
        ])
        .output()
        .expect("run connector report");

    assert!(
        output.status.success(),
        "connector report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value = serde_json::from_slice(&output.stdout).expect("report json");
    assert_eq!(payload["decision"], "allow");
    assert_eq!(
        payload["attestation"]["builder_id"],
        "builder://github/actions"
    );
    assert_eq!(
        payload["attestation"]["trust_root"]["root_id"],
        "sigstore-public-good"
    );
    assert_eq!(payload["sbom"]["bom_format"], "cyclonedx");
    assert_eq!(payload["sbom"]["component_count"], 1);
    assert_eq!(payload["sbom"]["trust_root"]["root_id"], "sbom-root");
}

#[test]
fn install_verify_only_json_includes_supply_chain_summary() {
    let output = fcp_cmd()
        .args([
            "install",
            "fcp.telegram:base:v1",
            "--zone",
            "z:work",
            "--verify-only",
            "--json",
        ])
        .output()
        .expect("run install verify-only");

    assert!(
        output.status.success(),
        "install verify-only failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value = serde_json::from_slice(&output.stdout).expect("install json");
    assert_eq!(payload["connector_id"], "fcp.telegram:base:v1");
    assert_eq!(
        payload["verification"]["supply_chain_policy_satisfied"],
        Value::Bool(true)
    );
    assert_eq!(
        payload["verification"]["supply_chain_reason_code"],
        "verified"
    );
    assert!(
        payload["verification"]["supply_chain_evidence_digest"]
            .as_str()
            .expect("evidence digest")
            .starts_with("blake3-256:")
    );
}

#[test]
fn install_fails_closed_on_supply_chain_policy_violation() {
    let temp = TempDir::new().expect("tempdir");
    let digest = digest_for_bytes(b"DEMO_BINARY:fcp.telegram:base:v1:1.0.0");
    let (attestation, sbom) = write_supply_chain_files(&temp, &digest, 1);

    let output = fcp_cmd()
        .args([
            "install",
            "fcp.telegram:base:v1",
            "--zone",
            "z:work",
            "--verify-only",
            "--attestation",
            &attestation,
            "--sbom",
            &sbom,
            "--min-slsa-level",
            "4",
            "--json",
        ])
        .output()
        .expect("run install with strict slsa");

    assert!(
        !output.status.success(),
        "install should fail, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value = serde_json::from_slice(&output.stdout).expect("install error json");
    assert_eq!(payload["code"], "FCP-4015");
    assert!(
        payload["message"]
            .as_str()
            .expect("message")
            .contains("slsa_level_insufficient")
    );
}
