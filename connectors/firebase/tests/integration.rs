//! Integration tests for the Firebase connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use fcp_firebase::connector::FirebaseConnector;
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/firebase_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/firebase_connector/<timestamp>";
const FIRESTORE_DEFAULT_DATABASE_PATH: &str = "/v1/projects/demo-project/databases/%28default%29";

async fn configure_and_handshake_connector(
    firestore_base_url: &str,
    realtime_database_url: &str,
    access_token: &str,
) -> FirebaseConnector {
    let mut connector = FirebaseConnector::new();
    connector
        .handle_configure(json!({
            "project_id": "demo-project",
            "access_token": access_token,
            "firestore_base_url": firestore_base_url,
            "realtime_database_url": realtime_database_url,
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({ "session_id": "sess_ready" }))
        .await
        .unwrap();
    connector
}

fn find_operation<'a>(operations: &'a [Value], id: &str) -> &'a Value {
    let operation = operations.iter().find(|entry| entry["id"] == id);
    assert!(operation.is_some(), "missing operation {id}");
    operation.expect("operation presence asserted above")
}

#[fcp_async_core::runtime::test]
async fn configure_then_introspect_returns_operations() {
    let mut connector = FirebaseConnector::new();
    connector
        .handle_configure(json!({
            "project_id": "demo-project",
            "access_token": "ya29.test-token"
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({ "session_id": "sess_1" }))
        .await
        .unwrap();

    let intro = connector.handle_introspect().await.unwrap();
    assert_eq!(intro["connector_id"], "fcp.firebase");
    assert!(intro["operations"].as_array().unwrap().len() >= 10);
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = FirebaseConnector::new();
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert_eq!(health["ready"], false);
    assert_eq!(
        health["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert!(health["details"]["operator_guidance"]["prerequisites"].is_array());
    assert_eq!(health["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "firebase_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = FirebaseConnector::new();
    let doctor = connector.handle_doctor().await.unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["status"], "unhealthy");
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "firebase_doctor_unconfigured={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_secretless_requires_injection_and_evidence() {
    let mut connector = FirebaseConnector::new();
    connector
        .handle_configure(json!({
            "project_id": "demo-project",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .unwrap();

    let report = connector.handle_self_check().await.unwrap();
    assert_self_check_not_ready(&report);
    assert_eq!(report["reason_code"], "credential_injection_required");
    assert_eq!(
        report["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(report["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert_eq!(
        report["details"]["provisioning"]["requires_credential_injection"],
        true
    );
    println!(
        "firebase_self_check_secretless={}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_access_token_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(FIRESTORE_DEFAULT_DATABASE_PATH))
        .and(header("authorization", "Bearer ya29.test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "projects/demo-project/databases/(default)",
            "uid": "demo-project-default",
            "type": "FIRESTORE_NATIVE",
        })))
        .mount(&server)
        .await;

    let connector = configure_and_handshake_connector(
        &format!("{}/v1", server.uri()),
        &server.uri(),
        "ya29.test-token",
    )
    .await;
    let doctor = connector.handle_doctor().await.unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["status"], "healthy");
    assert_eq!(doctor["ready"], true);
    println!(
        "firebase_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.handle_self_check().await.unwrap();
    assert_self_check_ready(&report);
    assert_eq!(
        report["details"]["provisioning"]["auth_mode"],
        "access_token"
    );
    assert_eq!(
        report["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(
        report["details"]["live_probe"]["database_resource"],
        "projects/demo-project/databases/(default)"
    );
    println!(
        "firebase_self_check_evidence={}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_rejects_invalid_network_constraints() {
    let mut connector = FirebaseConnector::new();
    connector
        .handle_configure(json!({
            "project_id": "demo-project",
            "access_token": "ya29.test-token",
            "firestore_base_url": "https://example.com/v1",
            "realtime_database_url": "https://demo-project.firebaseio.com"
        }))
        .await
        .unwrap();

    let report = connector.handle_self_check().await.unwrap();
    assert_self_check_not_ready(&report);
    assert_eq!(report["reason_code"], "network_constraints_invalid");
    assert_eq!(report["details"]["provisioning"]["network_ok"], false);
    assert_eq!(
        report["details"]["provisioning"]["firestore"]["host_ok"],
        false
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_firestore_api_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(FIRESTORE_DEFAULT_DATABASE_PATH))
        .respond_with(ResponseTemplate::new(503).set_body_string("quota temporarily exhausted"))
        .mount(&server)
        .await;

    let connector = configure_and_handshake_connector(
        &format!("{}/v1", server.uri()),
        &server.uri(),
        "ya29.test-token",
    )
    .await;
    let report = connector.handle_self_check().await.unwrap();
    assert_self_check_not_ready(&report);
    assert_eq!(report["status"], "degraded");
    assert_eq!(report["reason_code"], "self_check_retryable");
}

#[fcp_async_core::runtime::test]
async fn invoke_rtdb_set_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/presence/alice.json"))
        .and(header("authorization", "Bearer ya29.test-token"))
        .and(wiremock::matchers::body_json(json!({
            "online": true,
            "source": "verification",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "online": true,
            "path": "presence/alice",
            "source": "verification",
        })))
        .mount(&server)
        .await;

    let connector = configure_and_handshake_connector(
        &format!("{}/v1", server.uri()),
        &server.uri(),
        "ya29.test-token",
    )
    .await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "firebase.rtdb.set",
            "input": {
                "path": "presence/alice",
                "value": {
                    "online": true,
                    "source": "verification",
                }
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["data"]["online"], true);
    assert_eq!(result["data"]["path"], "presence/alice");
    assert_eq!(result["data"]["source"], "verification");
    println!(
        "firebase_risky_mutation_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_v3_compliance_evidence() {
    let connector = FirebaseConnector::new();
    let intro = connector.handle_introspect().await.unwrap();
    let operations = intro["operations"].as_array().unwrap();

    let firestore_create = find_operation(operations, "firebase.firestore.create");
    let firestore_delete = find_operation(operations, "firebase.firestore.delete");
    let rtdb_set = find_operation(operations, "firebase.rtdb.set");
    let rtdb_delete = find_operation(operations, "firebase.rtdb.delete");

    assert_eq!(firestore_create["requires_approval"], "policy");
    assert_eq!(firestore_delete["requires_approval"], "interactive");
    assert_eq!(rtdb_set["requires_approval"], "policy");
    assert_eq!(rtdb_delete["requires_approval"], "interactive");
    assert_eq!(firestore_delete["safety_tier"], "dangerous");
    assert_eq!(rtdb_delete["risk_level"], "high");

    let evidence = json!({
        "operation_ids": operations
            .iter()
            .map(|operation| operation["id"].clone())
            .collect::<Vec<_>>(),
        "dangerous_operations": operations
            .iter()
            .filter(|operation| operation["safety_tier"] == "dangerous")
            .map(|operation| {
                json!({
                    "id": operation["id"],
                    "capability": operation["capability"],
                    "requires_approval": operation["requires_approval"],
                    "idempotency": operation["idempotency"],
                })
            })
            .collect::<Vec<_>>(),
    });
    println!(
        "firebase_v3_conformance_evidence={}",
        serde_json::to_string_pretty(&evidence).unwrap()
    );
}
