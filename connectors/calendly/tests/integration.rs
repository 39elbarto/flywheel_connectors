//! Integration tests for the Calendly connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_calendly::connector::{CalendlyConnector, operations_info};
use fcp_core::{
    ApprovalMode, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HandshakeRequest,
    IdempotencyClass, InvokeRequest, InvokeStatus, OperationId, RequestId, RiskLevel, SafetyTier,
    ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/calendly_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/calendly_connector/<timestamp>";
const CAP_EVENTS_READ: &str = "calendly.events.read";
const CAP_EVENTS_WRITE: &str = "calendly.events.write";
const CAP_SCHEDULING_READ: &str = "calendly.scheduling.read";
const CAP_SCHEDULING_WRITE: &str = "calendly.scheduling.write";
const CAP_USER_READ: &str = "calendly.user.read";
const OP_EVENTS_CANCEL: &str = "calendly.events.cancel";
const OP_SCHEDULING_LINKS_CREATE: &str = "calendly.scheduling_links.create";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [23u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_EVENTS_READ),
            CapabilityId::from_static(CAP_EVENTS_WRITE),
            CapabilityId::from_static(CAP_SCHEDULING_READ),
            CapabilityId::from_static(CAP_SCHEDULING_WRITE),
            CapabilityId::from_static(CAP_USER_READ),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_for_operation(op: &'static str) -> &'static str {
    match op {
        OP_EVENTS_CANCEL => CAP_EVENTS_WRITE,
        OP_SCHEDULING_LINKS_CREATE => CAP_SCHEDULING_WRITE,
        _ => panic!("unsupported Calendly integration operation: {op}"),
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(op))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
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
        id: RequestId::new("calendly-integration-1"),
        connector_id: ConnectorId::from_static("fcp.calendly"),
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

async fn setup_connector(base_url: &str) -> (CalendlyConnector, Ed25519SigningKey) {
    let mut connector = CalendlyConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "access_token": "test_tok",
            "base_url": base_url,
            "request_timeout_ms": 1_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
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
async fn health_unconfigured_includes_guidance() {
    let connector = CalendlyConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "calendly_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[test]
fn doctor_unconfigured_reports_operator_guidance() {
    let connector = CalendlyConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert!(doctor["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    assert!(
        doctor["operator_guidance"]["common_remediation"]
            .as_array()
            .is_some_and(|items| items
                .iter()
                .any(|item| item["code"] == "provider_scope_mismatch"))
    );
    println!(
        "calendly_doctor_unconfigured={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_user_probe_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me"))
        .and(header("authorization", "Bearer test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resource": {
                "uri": "https://api.calendly.com/users/test-user",
                "name": "Test User",
                "email": "test@example.com",
                "scheduling_url": "https://calendly.com/test-user",
                "timezone": "America/New_York",
                "current_organization": "https://api.calendly.com/organizations/test-org"
            }
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    assert_eq!(doctor["provisioning"]["auth_mode"], "bearer_token");
    println!(
        "calendly_doctor_ready={}",
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
    assert_eq!(
        value["details"]["provisioning"]["authenticated_identity_probe"],
        "GET /users/me"
    );
    assert_eq!(
        value["details"]["live_probe"]["current_user_uri"],
        "https://api.calendly.com/users/test-user"
    );
    assert_eq!(
        value["details"]["live_probe"]["current_organization"],
        "https://api.calendly.com/organizations/test-org"
    );
    assert_eq!(
        value["details"]["contract"]["auth_boundary"]["credential_mode"],
        "bearer_token"
    );
    println!(
        "calendly_self_check_ready={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "title": "Service Unavailable",
            "message": "temporary calendly outage"
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["base_url"], server.uri());
    println!(
        "calendly_self_check_retryable={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_scheduling_link_create_emits_mutation_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/scheduling_links"))
        .and(header("authorization", "Bearer test_tok"))
        .and(body_json(json!({
            "owner": "https://api.calendly.com/event_types/evt-type-123",
            "owner_type": "EventType",
            "max_event_count": 1
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "resource": {
                "booking_url": "https://calendly.com/s/test-link",
                "owner": "https://api.calendly.com/event_types/evt-type-123",
                "owner_type": "EventType"
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_SCHEDULING_LINKS_CREATE,
            json!({
                "owner_uri": "https://api.calendly.com/event_types/evt-type-123",
                "owner_type": "EventType",
                "max_event_count": 1
            }),
            generate_valid_token(&signing_key, OP_SCHEDULING_LINKS_CREATE),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(
        result["resource"]["booking_url"],
        "https://calendly.com/s/test-link"
    );
    assert_eq!(
        result["resource"]["owner"],
        "https://api.calendly.com/event_types/evt-type-123"
    );
    println!(
        "calendly_scheduling_link_mutation_evidence={}",
        serde_json::to_string_pretty(&response).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_cancel_event_emits_mutation_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/scheduled_events/event-123/cancellation"))
        .and(header("authorization", "Bearer test_tok"))
        .and(body_json(json!({
            "reason": "Rescheduled by operator"
        })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "status": "accepted"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_EVENTS_CANCEL,
            json!({
                "event_uuid": "event-123",
                "reason": "Rescheduled by operator"
            }),
            generate_valid_token(&signing_key, OP_EVENTS_CANCEL),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["status"], "cancelled");
    println!(
        "calendly_cancel_mutation_evidence={}",
        serde_json::to_string_pretty(&response).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = CalendlyConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 9);
    assert_eq!(value["event_caps"]["streaming"], false);
    assert!(operations.iter().all(|op| {
        op["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    }));

    let scheduling_link_create = operations_info()
        .into_iter()
        .find(|op| op.id.as_str() == OP_SCHEDULING_LINKS_CREATE)
        .expect("scheduling link create operation");
    assert_eq!(scheduling_link_create.safety_tier, SafetyTier::Risky);
    assert_eq!(scheduling_link_create.risk_level, RiskLevel::Medium);
    assert_eq!(scheduling_link_create.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        scheduling_link_create.requires_approval,
        Some(ApprovalMode::None)
    );

    let cancel = operations_info()
        .into_iter()
        .find(|op| op.id.as_str() == OP_EVENTS_CANCEL)
        .expect("cancel operation");
    assert_eq!(cancel.safety_tier, SafetyTier::Risky);
    assert_eq!(cancel.risk_level, RiskLevel::Medium);

    println!(
        "calendly_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
