//! Integration tests for the LINE connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_core::{
    ApprovalMode, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HandshakeRequest,
    IdempotencyClass, InvokeRequest, InvokeStatus, OperationId, RequestId, SafetyTier, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_line::connector::{LineConnector, operations_info};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_GROUP_MEMBERS: &str = "line.group.members";
const OP_RICH_MENU_DELETE: &str = "line.rich_menu.delete";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/line_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/line_connector/<timestamp>";
const TOKEN: &str = "line_test_token";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [29u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("line.messages.write"),
            CapabilityId::from_static("line.profile.read"),
            CapabilityId::from_static("line.menu.read"),
            CapabilityId::from_static("line.menu.write"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_GROUP_MEMBERS => "line.profile.read",
        OP_RICH_MENU_DELETE => "line.menu.write",
        _ => panic!("unsupported LINE integration operation: {op}"),
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
        id: RequestId::new("line-integration-1"),
        connector_id: ConnectorId::from_static("fcp.line"),
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

async fn setup_connector(base_url: &str) -> (LineConnector, Ed25519SigningKey) {
    let mut connector = LineConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": base_url,
            "channel_access_token": TOKEN,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 1_000
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

async fn mock_bot_info(server: &MockServer, status: u16) {
    let response = match status {
        200 => ResponseTemplate::new(200).set_body_json(json!({
            "userId": "Ubot123",
            "basicId": "@fcp-line-test",
            "displayName": "FCP LINE Test Bot"
        })),
        429 => ResponseTemplate::new(429).insert_header("retry-after", "2"),
        _ => ResponseTemplate::new(status),
    };

    Mock::given(method("GET"))
        .and(path("/v2/bot/info"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(response)
        .mount(server)
        .await;
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = LineConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "line_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = LineConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "line_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_line_api_and_evidence() {
    let server = MockServer::start().await;
    mock_bot_info(&server, 200).await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "line_doctor_evidence={}",
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
        value["details"]["provisioning"]["auth_mode"],
        "bearer_channel_access_token"
    );
    assert_eq!(
        value["details"]["live_probe"]["endpoint"],
        "GET /v2/bot/info"
    );
    assert_eq!(value["details"]["live_probe"]["status"], "ok");
    println!(
        "line_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_line_failure_reports_degraded() {
    let server = MockServer::start().await;
    mock_bot_info(&server, 429).await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["retryable"], true);
}

#[fcp_async_core::runtime::test]
async fn invoke_group_members_preserves_pagination_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/bot/group/C123/members/ids"))
        .and(query_param("start", "next-1"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "memberIds": ["U1", "U2"],
            "next": "next-2"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_GROUP_MEMBERS,
            json!({
                "group_id": "C123",
                "start": "next-1"
            }),
            generate_valid_token(&signing_key, OP_GROUP_MEMBERS),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("group members result");
    assert_eq!(result["memberIds"].as_array().unwrap().len(), 2);
    assert_eq!(result["next"], "next-2");
    println!(
        "line_group_members_pagination_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_rich_menu_delete_emits_destructive_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v2/bot/richmenu/richmenu-abc123"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_RICH_MENU_DELETE,
            json!({
                "rich_menu_id": "richmenu-abc123"
            }),
            generate_valid_token(&signing_key, OP_RICH_MENU_DELETE),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("rich menu delete result");
    assert_eq!(result["deleted"], true);
    println!(
        "line_rich_menu_delete_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = LineConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 10);
    assert!(operations.iter().all(|operation| {
        operation["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|when_to_use| !when_to_use.is_empty())
    }));

    let delete = operations_info()
        .into_iter()
        .find(|operation| operation.id.as_str() == OP_RICH_MENU_DELETE)
        .expect("rich menu delete operation");
    assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));

    let group_members = operations
        .iter()
        .find(|operation| operation["id"] == "line.group.members")
        .expect("group members operation");
    assert_eq!(
        group_members["idempotency"],
        serde_json::to_value(IdempotencyClass::Strict).unwrap()
    );

    println!(
        "line_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
