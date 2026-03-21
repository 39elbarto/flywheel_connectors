//! E2E GCP connector compliance tests.
//!
//! Exercises the GCP connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features gcp --test gcp_compliance_e2e`

#![cfg(feature = "gcp")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::{
    CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest, InstanceId, InvokeRequest,
    InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{
    ComplianceSuite, ConnectorSuite, E2eReport, E2eRunner, InvokeExpectations, scan_log_jsonl,
    validate_log_entry_value,
};
use fcp_gcp::connector::GcpConnector;
use fcp_manifest::ConnectorManifest;
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

fn gcp_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/gcp/manifest.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn gcp_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/gcp/manifest.toml"))
        .expect("gcp manifest TOML")
}

fn gcp_config(base_url: &str) -> serde_json::Value {
    json!({
        "mode": "access_token",
        "access_token": "ya29_test_e2e",
        "project_id": "test-project",
        "compute_base_url": base_url,
        "storage_base_url": base_url,
        "run_base_url": base_url,
        "crm_base_url": base_url,
        "retry": { "max_retries": 0 },
    })
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken { raw: cose }
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("gcp-e2e"),
        connector_id: ConnectorId::from_static("fcp.gcp"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|constraints| constraints.get("host_allow"))
        .and_then(toml::Value::as_array)
        .expect("host_allow array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("host allow entry should be a string")
                .to_string()
        })
        .collect()
}

fn assert_report_logs_validate(report: &E2eReport) {
    let jsonl = report.to_stable_json_lines();
    assert!(
        !jsonl.trim().is_empty(),
        "report should emit stable JSONL evidence"
    );

    let first_line = jsonl.lines().next().expect("at least one JSONL line");
    let first_value: serde_json::Value =
        serde_json::from_str(first_line).expect("first JSONL line should parse");
    assert_eq!(
        first_value
            .get("timestamp")
            .and_then(serde_json::Value::as_str),
        Some("1970-01-01T00:00:00Z")
    );
    assert_eq!(
        first_value
            .get("correlation_id")
            .and_then(serde_json::Value::as_str),
        Some("00000000-0000-4000-8000-000000000000")
    );
    assert_eq!(
        first_value
            .get("duration_ms")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );

    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("jsonl line should parse");
        validate_log_entry_value(&value).expect("jsonl line should satisfy E2E schema");
    }

    let scan = scan_log_jsonl(&jsonl);
    assert_eq!(scan.error_count, 0, "stable evidence should scan cleanly");
}

#[fcp_async_core::runtime::test]
async fn gcp_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = GcpConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["gcp.compute.read"],
    );
    let token = build_token(
        &signing_key,
        "gcp.compute.read",
        &["gcp.compute.list_instances"],
    );
    let invoke = invoke_request(
        "gcp.run.delete_service",
        json!({ "location": "us-central1", "service": "dangerous-service" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: gcp_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new("gcp_default_deny", gcp_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-gcp");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(
        report.passed,
        "default deny compliance should pass: {report:#?}"
    );
    assert_report_logs_validate(&report);
}

#[fcp_async_core::runtime::test]
async fn gcp_happy_path_compute_list_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path(
            "/compute/v1/projects/test-project/zones/us-central1-a/instances",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "items": [] })))
        .mount(mock.inner())
        .await;

    let mut connector = GcpConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["gcp.compute.read"],
    );
    let token = build_token(
        &signing_key,
        "gcp.compute.read",
        &["gcp.compute.list_instances"],
    );
    let invoke = invoke_request(
        "gcp.compute.list_instances",
        json!({ "zone": "us-central1-a" }),
        token,
    );

    let suite = ConnectorSuite {
        test_name: "gcp_compute_list_instances".to_string(),
        config: gcp_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-gcp-happy");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "happy path should pass: {report:#?}");
    let invoke_entry = report
        .logs
        .iter()
        .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke entry");
    assert_eq!(invoke_entry.result, "pass");
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
    assert_report_logs_validate(&report);
}

#[fcp_async_core::runtime::test]
async fn gcp_dangerous_storage_delete_emits_stable_evidence() {
    let mock = MockApiServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/storage/v1/b/test-bucket/o/artifact.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deleted": true,
            "target": "artifact.txt"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = GcpConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["gcp.storage.write"],
    );
    let token = build_token(
        &signing_key,
        "gcp.storage.write",
        &["gcp.storage.delete_object"],
    );
    let invoke = invoke_request(
        "gcp.storage.delete_object",
        json!({ "bucket": "test-bucket", "object": "artifact.txt" }),
        token,
    );

    let suite = ConnectorSuite {
        test_name: "gcp_storage_delete".to_string(),
        config: gcp_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-gcp-delete");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("dangerous delete suite run");

    assert!(
        report.passed,
        "dangerous delete evidence suite should pass: {report:#?}"
    );
    assert_report_logs_validate(&report);
}

#[test]
fn gcp_manifest_network_guards_map_to_service_hosts() {
    let manifest = gcp_manifest_toml();
    let expected = [
        ("gcp.compute.list_instances", "compute.googleapis.com"),
        ("gcp.compute.get_instance", "compute.googleapis.com"),
        ("gcp.compute.start_instance", "compute.googleapis.com"),
        ("gcp.compute.stop_instance", "compute.googleapis.com"),
        ("gcp.compute.delete_instance", "compute.googleapis.com"),
        ("gcp.storage.list_objects", "storage.googleapis.com"),
        ("gcp.storage.get_object", "storage.googleapis.com"),
        ("gcp.storage.upload_object", "storage.googleapis.com"),
        ("gcp.storage.delete_object", "storage.googleapis.com"),
        ("gcp.run.list_services", "run.googleapis.com"),
        ("gcp.run.deploy_service", "run.googleapis.com"),
        ("gcp.run.delete_service", "run.googleapis.com"),
        ("gcp.projects.get", "cloudresourcemanager.googleapis.com"),
        ("gcp.health", "cloudresourcemanager.googleapis.com"),
    ];

    for (operation_name, expected_host) in expected {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec![expected_host.to_string()],
            "operation {operation_name} should use the exact service host"
        );
    }
}
