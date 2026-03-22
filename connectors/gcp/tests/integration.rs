//! Integration tests for the FCP GCP connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_core::{
    ApprovalMode, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HandshakeRequest,
    IdempotencyClass, InvokeRequest, OperationId, RequestId, SafetyTier, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_gcp::connector::GcpConnector;
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_COMPUTE_START_INSTANCE: &str = "gcp.compute.start_instance";
const OP_PROJECTS_GET: &str = "gcp.projects.get";
const OP_STORAGE_DELETE_OBJECT: &str = "gcp.storage.delete_object";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("gcp.compute.read"),
            CapabilityId::from_static("gcp.compute.write"),
            CapabilityId::from_static("gcp.storage.read"),
            CapabilityId::from_static("gcp.storage.write"),
            CapabilityId::from_static("gcp.run.read"),
            CapabilityId::from_static("gcp.run.write"),
            CapabilityId::from_static("gcp.iam.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_STORAGE_DELETE_OBJECT => "gcp.storage.write",
        _ => panic!("unsupported test operation: {op}"),
    };
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken { raw }
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("integration-1"),
        connector_id: ConnectorId::from_static("fcp.gcp"),
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

async fn setup_connector(mock_url: &str, access_token: &str) -> (GcpConnector, Ed25519SigningKey) {
    let mut connector = GcpConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "mode": "access_token",
            "access_token": access_token,
            "project_id": "test-project",
            "compute_base_url": mock_url,
            "storage_base_url": mock_url,
            "run_base_url": mock_url,
            "crm_base_url": mock_url,
            "retry": { "max_retries": 0 },
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured_includes_guidance() {
    let connector = GcpConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert_eq!(
        details["verification_script"],
        "scripts/e2e/gcp_connector_verification.sh"
    );
    assert_eq!(
        details["artifact_root_hint"],
        "artifacts/e2e/gcp_connector/<timestamp>"
    );
    println!(
        "gcp_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_remediation() {
    let connector = GcpConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["status"], "unhealthy");
    assert_eq!(doctor["ready"], false);
    assert_eq!(
        doctor["verification_script"],
        "scripts/e2e/gcp_connector_verification.sh"
    );
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        "artifacts/e2e/gcp_connector/<timestamp>"
    );
    println!(
        "gcp_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_rejects_cross_wired_storage_endpoint_override() {
    let mut connector = GcpConnector::new();
    connector
        .configure(json!({
            "mode": "access_token",
            "access_token": "ya29.test",
            "project_id": "test-project",
            "storage_base_url": "https://compute.googleapis.com",
            "retry": { "max_retries": 0 },
        }))
        .await
        .unwrap();

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["reason_code"], "network_constraints_invalid");
    assert_eq!(value["details"]["provisioning"]["network_ok"], false);

    let endpoints = value["details"]["provisioning"]["service_endpoints"]
        .as_array()
        .expect("service endpoints");
    assert!(
        endpoints
            .iter()
            .any(|endpoint| { endpoint["service"] == "storage" && endpoint["ok"] == false })
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_access_token_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/projects/test-project"))
        .and(header("authorization", "Bearer ya29.test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projectId": "test-project",
            "name": "Test Project",
            "lifecycleState": "ACTIVE"
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri(), "ya29.test").await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    println!(
        "gcp_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["provisioning"]["auth_mode"],
        "access_token"
    );
    assert_eq!(
        value["details"]["verification_script"],
        "scripts/e2e/gcp_connector_verification.sh"
    );
    println!(
        "gcp_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_secretless_requires_runtime_injection() {
    let server = MockServer::start().await;
    let mut connector = GcpConnector::new();
    connector
        .configure(json!({
            "mode": "access_token",
            "access_token": "",
            "project_id": "test-project",
            "compute_base_url": server.uri(),
            "storage_base_url": server.uri(),
            "run_base_url": server.uri(),
            "crm_base_url": server.uri(),
            "retry": { "max_retries": 0 },
        }))
        .await
        .unwrap();

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["reason_code"], "credential_injection_required");
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_project_api_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/projects/test-project"))
        .respond_with(ResponseTemplate::new(503).set_body_string("quota temporarily exhausted"))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri(), "ya29.test").await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
}

#[fcp_async_core::runtime::test]
async fn invoke_dangerous_storage_delete_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/storage/v1/b/test-bucket/o/artifact.txt"))
        .and(header("authorization", "Bearer ya29.test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deleted": true,
            "target": "artifact.txt"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), "ya29.test").await;
    let response = connector
        .invoke(invoke_req(
            OP_STORAGE_DELETE_OBJECT,
            json!({
                "bucket": "test-bucket",
                "object": "artifact.txt"
            }),
            generate_valid_token(&signing_key, OP_STORAGE_DELETE_OBJECT),
        ))
        .await
        .unwrap();

    let result = response.result.expect("storage delete result");
    assert_eq!(result["deleted"], true);
    println!(
        "gcp_risky_mutation_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_v3_compliance_evidence() {
    let connector = GcpConnector::new();
    let operations = connector.introspect().operations;
    assert_eq!(operations.len(), 14);

    let storage_delete = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_STORAGE_DELETE_OBJECT)
        .expect("storage delete operation");
    assert_eq!(storage_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(storage_delete.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        storage_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let compute_start = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_COMPUTE_START_INSTANCE)
        .expect("compute start operation");
    assert_eq!(compute_start.safety_tier, SafetyTier::Risky);
    assert_eq!(compute_start.idempotency, IdempotencyClass::Strict);

    let projects_get = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_PROJECTS_GET)
        .expect("projects get operation");
    assert_eq!(projects_get.safety_tier, SafetyTier::Safe);
    assert_eq!(projects_get.idempotency, IdempotencyClass::None);

    let evidence = json!({
        "operation_ids": operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>(),
        "dangerous_operations": operations
            .iter()
            .filter(|operation| operation.safety_tier == SafetyTier::Dangerous)
            .map(|operation| {
                json!({
                    "id": operation.id.as_str(),
                    "capability": operation.capability.as_str(),
                    "idempotency": format!("{:?}", operation.idempotency),
                    "requires_approval": serde_json::to_value(operation.requires_approval)
                        .unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>(),
    });
    println!(
        "gcp_v3_conformance_evidence={}",
        serde_json::to_string_pretty(&evidence).unwrap()
    );
}
