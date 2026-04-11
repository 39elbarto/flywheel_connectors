//! Integration tests for the Obsidian connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::fs;

use chrono::{Duration, Utc};
use fcp_core::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_obsidian::connector::{ObsidianConnector, operations_info};
use fcp_testkit::readiness_helpers::{assert_doctor_response_valid, assert_self_check_ready};
use serde_json::json;
use tempfile::TempDir;

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/obsidian_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/obsidian_connector/<timestamp>";
const OP_NOTES_DELETE: &str = "obsidian.notes.delete";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [11u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("obsidian.read"),
            CapabilityId::from_static("obsidian.write"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_NOTES_DELETE => "obsidian.write",
        _ => panic!("unsupported Obsidian integration operation: {op}"),
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("obsidian-integration-1"),
        connector_id: ConnectorId::from_static("fcp.obsidian"),
        operation: OperationId::from_static(op),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

fn seed_vault(dir: &TempDir) {
    fs::create_dir_all(dir.path().join("daily")).unwrap();
    fs::create_dir_all(dir.path().join("projects")).unwrap();
    fs::write(
        dir.path().join("daily/2026-03-21.md"),
        "# Daily Log\n\nReviewed connector metadata.\n#daily\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("projects/flywheel.md"),
        "# Flywheel\n\nSee [[2026-03-21]] for status.\n#project/flywheel\n",
    )
    .unwrap();
}

async fn setup_connector() -> (TempDir, ObsidianConnector, Ed25519SigningKey) {
    let dir = tempfile::tempdir().unwrap();
    seed_vault(&dir);

    let mut connector = ObsidianConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "vault_path": dir.path().to_str().unwrap(),
            "request_timeout_ms": 10_000,
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();

    (dir, connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = ObsidianConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "obsidian_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = ObsidianConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert!(doctor["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "obsidian_doctor_unconfigured={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_vault_evidence() {
    let (_dir, connector, _signing_key) = setup_connector().await;

    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "obsidian_doctor_ready={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(value["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert_eq!(value["details"]["provisioning"]["local_only"], true);
    assert_eq!(value["details"]["live_probe"]["note_count"], 2);
    assert_eq!(value["details"]["live_probe"]["writable"], true);
    println!(
        "obsidian_self_check_ready={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_note_removes_target_file() {
    let (dir, connector, signing_key) = setup_connector().await;
    let note_path = "scratch/delete-me.md";
    fs::create_dir_all(dir.path().join("scratch")).unwrap();
    fs::write(dir.path().join(note_path), "# Delete Me\n").unwrap();

    let response = connector
        .invoke(invoke_req(
            OP_NOTES_DELETE,
            json!({ "path": note_path }),
            generate_valid_token(&signing_key, OP_NOTES_DELETE),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["deleted"], true);
    assert_eq!(result["path"], note_path);
    assert!(!dir.path().join(note_path).exists());
    println!(
        "obsidian_delete_evidence={}",
        serde_json::to_string_pretty(&response).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = ObsidianConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 9);
    assert!(operations.iter().all(|op| {
        op["ai_hints"]["examples"]
            .as_array()
            .is_some_and(|examples| !examples.is_empty())
    }));

    let delete = operations_info()
        .into_iter()
        .find(|op| op.id.as_str() == OP_NOTES_DELETE)
        .expect("delete operation");
    assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));

    println!(
        "obsidian_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
