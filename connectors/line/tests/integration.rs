//! Integration tests for the LINE connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::sync::Arc;

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_line::connector::{LineConnector, operations_info};
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    FcpError, HandshakeRequest, IdempotencyClass, InstanceId, InvokeRequest, InvokeStatus,
    OperationId, RequestId, SafetyTier, ZoneId,
};
use fcp_sdk::{ChatCoordinationBackend, InMemoryThreadOwnershipChecker};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_PUSH: &str = "line.messages.push";
const OP_REPLY: &str = "line.messages.reply";
const OP_MULTICAST: &str = "line.messages.multicast";
const OP_GROUP_MEMBERS: &str = "line.group.members";
const OP_RICH_MENU_DELETE: &str = "line.rich_menu.delete";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/line_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/line_connector/<timestamp>";
const TOKEN: &str = "line_test_token";

fn handshake_req(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
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
        requested_instance_id: Some(instance_id),
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    op: &'static str,
) -> CapabilityToken {
    let capability = capability_for_operation(op).expect("LINE integration operation supported");
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
        .expect("constraints cbor accepted")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn capability_for_operation(op: &str) -> Option<&'static str> {
    match op {
        OP_PUSH | OP_REPLY | OP_MULTICAST => Some("line.messages.write"),
        OP_GROUP_MEMBERS => Some("line.profile.read"),
        OP_RICH_MENU_DELETE => Some("line.menu.write"),
        _ => None,
    }
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

async fn setup_connector(base_url: &str) -> (LineConnector, Ed25519SigningKey, InstanceId) {
    setup_connector_with_checker(base_url, None).await
}

async fn setup_connector_with_checker(
    base_url: &str,
    checker: Option<Arc<InMemoryThreadOwnershipChecker>>,
) -> (LineConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = match checker {
        Some(checker) => LineConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory),
        None => LineConnector::new(),
    };
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
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
        .handshake(handshake_req(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .unwrap();
    (connector, signing_key, instance_id)
}

async fn recorded_json_body(server: &MockServer) -> serde_json::Value {
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 1);
    serde_json::from_slice(&requests[0].body).expect("request body should be JSON")
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

    let (connector, _signing_key, _instance_id) = setup_connector(&server.uri()).await;
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

    let (connector, _signing_key, _instance_id) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["retryable"], true);
}

#[fcp_async_core::runtime::test]
async fn invoke_reply_sends_template_message_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/reply"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_REPLY,
            json!({
                "reply_token": "reply-token-1",
                "messages": [{
                    "type": "template",
                    "altText": "Confirm deployment",
                    "template": {
                        "type": "confirm",
                        "text": "Deploy now?",
                        "actions": [
                            { "type": "message", "label": "Yes", "text": "deploy yes" },
                            { "type": "postback", "label": "No", "data": "deploy=no", "displayText": "No" }
                        ]
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_REPLY),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let body = recorded_json_body(&server).await;
    assert_eq!(body["replyToken"], "reply-token-1");
    assert_eq!(body["messages"][0]["type"], "template");
    assert_eq!(body["messages"][0]["template"]["type"], "confirm");
    assert_eq!(
        body["messages"][0]["template"]["actions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_push_sends_flex_message_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/push"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_PUSH,
            json!({
                "to": "U123",
                "messages": [{
                    "type": "flex",
                    "altText": "Status card",
                    "contents": {
                        "type": "bubble",
                        "body": {
                            "type": "box",
                            "layout": "vertical",
                            "contents": [
                                { "type": "text", "text": "Ready" }
                            ]
                        }
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_PUSH),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let body = recorded_json_body(&server).await;
    assert_eq!(body["to"], "U123");
    assert_eq!(body["messages"][0]["type"], "flex");
    assert_eq!(body["messages"][0]["altText"], "Status card");
    assert_eq!(body["messages"][0]["contents"]["type"], "bubble");
    let result = response.result.expect("push result");
    assert_eq!(result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(result["coordination"][1]["outcome"], "granted");
    assert_eq!(result["coordination"][2]["event"], "send_executed");
    assert!(
        !serde_json::to_string(&result["coordination"])
            .unwrap()
            .contains("U123")
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_push_claims_recipient_and_denies_duplicate_before_http() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/push"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let (connector_a, signing_key_a, instance_id_a) =
        setup_connector_with_checker(&server.uri(), Some(checker.clone())).await;
    let (connector_b, signing_key_b, instance_id_b) =
        setup_connector_with_checker(&server.uri(), Some(checker)).await;

    let input = json!({
        "to": "Ucoord",
        "messages": [{ "type": "text", "text": "claimed once" }]
    });
    let first = connector_a
        .invoke(invoke_req(
            OP_PUSH,
            input.clone(),
            generate_valid_token(&signing_key_a, &instance_id_a, OP_PUSH),
        ))
        .await
        .unwrap();
    assert_eq!(first.status, InvokeStatus::Ok);

    let err = connector_b
        .invoke(invoke_req(
            OP_PUSH,
            input,
            generate_valid_token(&signing_key_b, &instance_id_b, OP_PUSH),
        ))
        .await
        .unwrap_err();
    match err {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 4090);
            assert!(message.starts_with("thread_owned_by_peer:"));
            assert!(message.contains(instance_id_a.as_str()));
        }
        other => panic!("expected duplicate claim unauthorized error, got {other:?}"),
    }

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "duplicate claim must be denied before HTTP"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_multicast_sends_carousel_and_rejects_oversized_carousel() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/multicast"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let column = json!({
        "text": "Column",
        "actions": [{ "type": "message", "label": "Pick", "text": "pick" }]
    });
    let ten_columns = vec![column.clone(); 10];
    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_MULTICAST,
            json!({
                "to": ["U1", "U2"],
                "messages": [{
                    "type": "template",
                    "altText": "Carousel",
                    "template": {
                        "type": "carousel",
                        "columns": ten_columns
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_MULTICAST),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let body = recorded_json_body(&server).await;
    assert_eq!(
        body["messages"][0]["template"]["columns"]
            .as_array()
            .unwrap()
            .len(),
        10
    );

    let too_many_columns = vec![column; 11];
    let err = connector
        .invoke(invoke_req(
            OP_MULTICAST,
            json!({
                "to": ["U1"],
                "messages": [{
                    "type": "template",
                    "altText": "Too many",
                    "template": {
                        "type": "carousel",
                        "columns": too_many_columns
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_MULTICAST),
        ))
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("at most 10 columns"),
        "unexpected error: {err}"
    );
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

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_GROUP_MEMBERS,
            json!({
                "group_id": "C123",
                "start": "next-1"
            }),
            generate_valid_token(&signing_key, &instance_id, OP_GROUP_MEMBERS),
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

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_RICH_MENU_DELETE,
            json!({
                "rich_menu_id": "richmenu-abc123"
            }),
            generate_valid_token(&signing_key, &instance_id, OP_RICH_MENU_DELETE),
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

    let push = operations
        .iter()
        .find(|operation| operation["id"] == OP_PUSH)
        .expect("push operation");
    let message_schema = &push["input_schema"]["properties"]["messages"]["items"]["oneOf"];
    assert!(
        message_schema
            .as_array()
            .expect("message schema oneOf")
            .iter()
            .any(|variant| variant["properties"]["type"]["const"] == "template")
    );
    assert!(
        message_schema
            .as_array()
            .expect("message schema oneOf")
            .iter()
            .any(|variant| variant["properties"]["type"]["const"] == "flex")
    );

    println!(
        "line_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
