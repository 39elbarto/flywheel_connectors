//! Integration tests for the Firebase connector readiness and compliance surface.

use fcp_firebase::connector::FirebaseConnector;
use fcp_testkit::readiness_helpers::{assert_doctor_response_valid, assert_self_check_not_ready};
use serde_json::{Value, json};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/firebase_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/firebase_connector/<timestamp>";

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
async fn introspection_emits_operation_compliance_evidence() {
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

    println!(
        "firebase_introspection_compliance={}",
        serde_json::to_string_pretty(&intro).unwrap()
    );
}
