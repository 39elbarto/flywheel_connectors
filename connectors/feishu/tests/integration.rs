//! Integration tests for the Feishu/Lark connector readiness and compliance surface.

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
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, IdempotencyClass, InvokeRequest, InvokeStatus, OperationId, RequestId,
    SafetyTier, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_feishu::connector::{FeishuConnector, operations_info};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_CHATS_LIST: &str = "feishu.chats.list";
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/feishu_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/feishu_connector/<timestamp>";
const APP_ID: &str = "cli_test_app";
const APP_SECRET: &str = "cli_test_secret";
const TENANT_TOKEN: &str = "tenant-token-123";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("feishu.messages.write"),
            CapabilityId::from_static("feishu.messages.read"),
            CapabilityId::from_static("feishu.chats.read"),
            CapabilityId::from_static("feishu.users.read"),
            CapabilityId::from_static("feishu.docs.read"),
            CapabilityId::from_static("feishu.calendar.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_CHATS_LIST => "feishu.chats.read",
        OP_MESSAGES_SEND => "feishu.messages.write",
        _ => panic!("unsupported Feishu integration operation: {op}"),
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
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
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
        id: RequestId::new("feishu-integration-1"),
        connector_id: ConnectorId::from_static("fcp.feishu"),
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

async fn mock_auth_endpoint(server: &MockServer, status: u16) {
    let response = match status {
        200 => ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "tenant_access_token": TENANT_TOKEN,
            "expire": 7200
        })),
        429 => ResponseTemplate::new(429).insert_header("retry-after", "2"),
        401 => ResponseTemplate::new(401).set_body_string("unauthorized"),
        _ => ResponseTemplate::new(status).set_body_string("upstream failure"),
    };

    Mock::given(method("POST"))
        .and(path("/open-apis/auth/v3/tenant_access_token/internal"))
        .respond_with(response)
        .mount(server)
        .await;
}

async fn setup_connector(server: &MockServer) -> (FeishuConnector, Ed25519SigningKey) {
    mock_auth_endpoint(server, 200).await;

    let mut connector = FeishuConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": server.uri(),
            "app_id": APP_ID,
            "app_secret": APP_SECRET,
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

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = FeishuConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "feishu_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[test]
fn doctor_unconfigured_reports_operator_guidance() {
    let connector = FeishuConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "feishu_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_feishu_api_and_evidence() {
    let server = MockServer::start().await;
    let (connector, _signing_key) = setup_connector(&server).await;

    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "feishu_doctor_evidence={}",
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
        "tenant_app_credentials"
    );
    assert_eq!(
        value["details"]["live_probe"]["endpoint"],
        "POST /open-apis/auth/v3/tenant_access_token/internal"
    );
    assert_eq!(value["details"]["live_probe"]["status"], "ok");
    println!(
        "feishu_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_feishu_failure_reports_degraded() {
    let server = MockServer::start().await;
    mock_auth_endpoint(&server, 429).await;

    let mut connector = FeishuConnector::new();
    connector
        .configure(json!({
            "base_url": server.uri(),
            "app_id": APP_ID,
            "app_secret": APP_SECRET,
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

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["retryable"], true);
    assert_eq!(value["details"]["live_probe"]["retry_after_ms"], 2000);
}

#[fcp_async_core::runtime::test]
async fn invoke_chats_list_preserves_pagination_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/open-apis/im/v1/chats"))
        .and(query_param("page_token", "page-1"))
        .and(query_param("page_size", "50"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "items": [
                    {"chat_id": "oc_chat_1", "name": "Platform Team"},
                    {"chat_id": "oc_chat_2", "name": "Ops"}
                ],
                "page_token": "page-2",
                "has_more": true
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;
    let response = connector
        .invoke(invoke_req(
            OP_CHATS_LIST,
            json!({
                "page_token": "page-1",
                "page_size": 50
            }),
            generate_valid_token(&signing_key, OP_CHATS_LIST),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("chat list result");
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
    assert_eq!(result["page_token"], "page-2");
    assert_eq!(result["has_more"], true);
    println!(
        "feishu_chat_pagination_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_messages_send_emits_mutation_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/im/v1/messages"))
        .and(query_param("receive_id_type", "open_id"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "message_id": "om_dc13264520392913993dd051dba21dcf",
                "msg_type": "text"
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;
    let response = connector
        .invoke(invoke_req(
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_123456",
                "receive_id_type": "open_id",
                "msg_type": "text",
                "content": "{\"text\":\"hello from integration\"}"
            }),
            generate_valid_token(&signing_key, OP_MESSAGES_SEND),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("send result");
    assert_eq!(result["message_id"], "om_dc13264520392913993dd051dba21dcf");
    assert_eq!(result["msg_type"], "text");
    println!(
        "feishu_message_send_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = FeishuConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 10);
    assert!(operations.iter().all(|operation| {
        operation["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|when_to_use| !when_to_use.is_empty())
    }));

    let send = operations_info()
        .into_iter()
        .find(|operation| operation.id.as_str() == OP_MESSAGES_SEND)
        .expect("messages.send operation");
    assert_eq!(send.safety_tier, SafetyTier::Risky);

    let chats_list = operations
        .iter()
        .find(|operation| operation["id"] == OP_CHATS_LIST)
        .expect("chats.list operation");
    assert_eq!(
        chats_list["idempotency"],
        serde_json::to_value(IdempotencyClass::Strict).unwrap()
    );
    assert_eq!(value["auth_caps"]["methods"].as_array().unwrap().len(), 2);

    println!(
        "feishu_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
