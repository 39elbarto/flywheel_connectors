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
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_feishu::connector::{FeishuConnector, operations_info};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, IdempotencyClass, InstanceId, InvokeRequest, InvokeStatus, OperationId,
    RequestId, SafetyTier, ZoneId,
};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_CHATS_LIST: &str = "feishu.chats.list";
const OP_COMMENTS_CONTEXT_GET: &str = "feishu.comments.context.get";
const OP_COMMENTS_PAIRINGS_MANAGE: &str = "feishu.comments.pairings.manage";
const OP_COMMENTS_REACTION: &str = "feishu.comments.reaction";
const OP_COMMENTS_REPLY: &str = "feishu.comments.reply";
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const OP_WEBHOOK_INGEST_REQUEST: &str = "feishu.webhook.ingest_request";
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
            CapabilityId::from_static("feishu.webhook.ingest"),
            CapabilityId::from_static("feishu.comments.read"),
            CapabilityId::from_static("feishu.comments.write"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let capability = match op {
        OP_CHATS_LIST => "feishu.chats.read",
        OP_MESSAGES_SEND => "feishu.messages.write",
        OP_WEBHOOK_INGEST_REQUEST => "feishu.webhook.ingest",
        OP_COMMENTS_CONTEXT_GET => "feishu.comments.read",
        OP_COMMENTS_PAIRINGS_MANAGE | OP_COMMENTS_REPLY | OP_COMMENTS_REACTION => {
            "feishu.comments.write"
        }
        _ => "feishu.webhook.ingest",
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
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn feishu_webhook_signature(
    timestamp: &str,
    nonce: &str,
    encrypt_key: &str,
    raw_body: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(encrypt_key.as_bytes());
    hasher.update(raw_body.as_bytes());
    hex::encode(hasher.finalize())
}

fn signed_webhook_input(raw_body: String, policy: serde_json::Value) -> serde_json::Value {
    let timestamp = "1715000000";
    let nonce = "integration-nonce";
    let encrypt_key = "integration-encrypt-key";
    json!({
        "method": "POST",
        "headers": {
            "x-lark-request-timestamp": timestamp,
            "x-lark-request-nonce": nonce,
            "x-lark-signature": feishu_webhook_signature(timestamp, nonce, encrypt_key, &raw_body),
        },
        "raw_body": raw_body,
        "verification_token": "integration-token",
        "encrypt_key": encrypt_key,
        "policy": policy,
    })
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

async fn setup_connector_with_extra_config(
    server: &MockServer,
    extra_config: serde_json::Value,
) -> (FeishuConnector, Ed25519SigningKey) {
    mock_auth_endpoint(server, 200).await;

    let mut connector = FeishuConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let mut config = json!({
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
    });
    if let (Some(config), serde_json::Value::Object(extra_config)) =
        (config.as_object_mut(), extra_config)
    {
        config.extend(extra_config);
    }
    connector.configure(config).await.unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

async fn setup_connector(server: &MockServer) -> (FeishuConnector, Ed25519SigningKey) {
    setup_connector_with_extra_config(server, json!({})).await
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
            generate_valid_token(&signing_key, OP_CHATS_LIST, connector.instance_id()),
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
            generate_valid_token(&signing_key, OP_MESSAGES_SEND, connector.instance_id()),
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

#[fcp_async_core::runtime::test]
async fn invoke_webhook_ingest_validates_and_normalizes_event_evidence() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server).await;
    let raw_body = serde_json::to_string(&json!({
        "schema": "2.0",
        "header": {
            "event_id": "evt-integration-1",
            "event_type": "im.message.receive_v1",
            "token": "integration-token",
        },
        "event": {
            "sender": { "sender_id": { "open_id": "ou_allowed" } },
            "message": {
                "message_id": "om_integration",
                "chat_id": "oc_allowed",
                "chat_type": "group",
                "message_type": "text",
                "content": "{\"text\":\"hello\"}",
                "mentions": [{ "id": { "open_id": "ou_bot" } }]
            }
        }
    }))
    .unwrap();

    let webhook_input = signed_webhook_input(
        raw_body,
        json!({
            "allowed_sender_open_ids": ["ou_allowed"],
            "allowed_chat_ids": ["oc_allowed"],
            "require_mention": true,
            "bot_open_id": "ou_bot",
        }),
    );

    let response = connector
        .invoke(invoke_req(
            OP_WEBHOOK_INGEST_REQUEST,
            webhook_input.clone(),
            generate_valid_token(
                &signing_key,
                OP_WEBHOOK_INGEST_REQUEST,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("webhook result");
    assert_eq!(result["status_code"], 200);
    assert_eq!(result["reason_code"], "event_accepted");
    assert_eq!(result["event_emitted"], true);
    assert_eq!(
        result["normalized_event"]["topic"],
        "feishu.webhook.message_received"
    );
    assert_eq!(result["normalized_event"]["raw_content_included"], false);
    println!(
        "feishu_webhook_ingest_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );

    let duplicate = connector
        .invoke(invoke_req(
            OP_WEBHOOK_INGEST_REQUEST,
            webhook_input,
            generate_valid_token(
                &signing_key,
                OP_WEBHOOK_INGEST_REQUEST,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap();
    let duplicate = duplicate.result.expect("duplicate result");
    assert_eq!(duplicate["reason_code"], "duplicate_event");
    assert_eq!(duplicate["event_emitted"], false);
    assert_eq!(duplicate["state_summary"]["finalized_entries"], 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_webhook_ingest_configured_host_ingress_emits_fanout_contract() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector_with_extra_config(
        &server,
        json!({
            "webhook_ingress": {
                "enabled": true,
                "path": "/feishu/webhook",
                "verification_token": "integration-token",
                "encrypt_key": "integration-encrypt-key",
                "max_body_bytes": 4096
            }
        }),
    )
    .await;

    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_eq!(doctor["provisioning"]["webhook_ingress"]["enabled"], true);
    assert_eq!(
        doctor["provisioning"]["webhook_ingress"]["listener_socket_opened"],
        false
    );

    let raw_body = serde_json::to_string(&json!({
        "schema": "2.0",
        "header": {
            "event_id": "evt-configured-ingress-1",
            "event_type": "im.message.receive_v1",
            "token": "integration-token",
        },
        "event": {
            "sender": { "sender_id": { "open_id": "ou_allowed" } },
            "message": {
                "message_id": "om_configured_ingress",
                "chat_id": "oc_allowed",
                "chat_type": "group",
                "message_type": "text",
                "content": "{\"text\":\"hello\"}",
                "mentions": [{ "id": { "open_id": "ou_bot" } }]
            }
        }
    }))
    .unwrap();
    let mut webhook_input = signed_webhook_input(
        raw_body,
        json!({
            "allowed_sender_open_ids": ["ou_allowed"],
            "allowed_chat_ids": ["oc_allowed"],
            "require_mention": true,
            "bot_open_id": "ou_bot",
        }),
    );
    let webhook_object = webhook_input.as_object_mut().unwrap();
    webhook_object.remove("verification_token");
    webhook_object.remove("encrypt_key");
    webhook_object.insert("path".to_owned(), json!("/feishu/webhook"));
    webhook_object
        .get_mut("headers")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .insert(
            "content-type".to_owned(),
            json!("application/json; charset=utf-8"),
        );

    let response = connector
        .invoke(invoke_req(
            OP_WEBHOOK_INGEST_REQUEST,
            webhook_input,
            generate_valid_token(
                &signing_key,
                OP_WEBHOOK_INGEST_REQUEST,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("configured ingress webhook result");
    assert_eq!(result["reason_code"], "event_accepted");
    assert_eq!(result["event_emitted"], true);
    assert_eq!(
        result["normalized_event"]["topic"],
        "feishu.webhook.message_received"
    );
    assert_eq!(result["request_region"]["configured_ingress"], true);
    assert_eq!(
        result["request_region"]["transport"],
        "host_forwarded_request_region"
    );
    assert_eq!(result["request_region"]["listener_socket_opened"], false);
    assert_eq!(
        result["request_region"]["event_fanout"],
        "host_consumes_returned_event_record"
    );
    assert_eq!(
        result["request_region"]["security_material_source"],
        "webhook_ingress_config"
    );
    println!(
        "feishu_configured_webhook_ingress_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_comment_automation_operations_emit_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/drive/v1/metas/batch_query"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "metas": [{
                    "doc_token": "doc_context",
                    "doc_type": "docx",
                    "title": "Incident Runbook",
                    "url": "https://example.feishu.cn/docx/doc_context"
                }]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v1/files/doc_context/comments/batch_query",
        ))
        .and(query_param("file_type", "docx"))
        .and(query_param("user_id_type", "open_id"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "items": [{
                    "comment_id": "comment_context",
                    "user_id": "ou_commenter",
                    "is_whole": false,
                    "quote": "restart failed",
                    "reply_list": {
                        "replies": [{
                            "reply_id": "reply_root",
                            "user_id": "ou_commenter",
                            "content": {
                                "elements": [{
                                    "type": "text_run",
                                    "text_run": { "text": "Can you check this?" }
                                }]
                            }
                        }]
                    }
                }]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/open-apis/drive/v1/files/doc_context/comments/comment_context/replies",
        ))
        .and(query_param("file_type", "docx"))
        .and(query_param("page_size", "100"))
        .and(query_param("user_id_type", "open_id"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "items": [{
                    "reply_id": "reply_current",
                    "user_id": "ou_commenter",
                    "content": {
                        "elements": [{
                            "type": "text_run",
                            "text_run": { "text": "Stack trace is in the linked doc" }
                        }]
                    }
                }],
                "has_more": false
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v1/files/doc_context/comments/comment_context/replies",
        ))
        .and(query_param("file_type", "docx"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 1069302,
            "msg": "reply is not allowed for whole-comment fallback"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/open-apis/drive/v1/files/doc_context/new_comments"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "comment_id": "comment_fallback"
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v2/files/doc_context/comments/reaction",
        ))
        .and(query_param("file_type", "docx"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "reaction_id": "reaction_typing"
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;

    let pairing = connector
        .invoke(invoke_req(
            OP_COMMENTS_PAIRINGS_MANAGE,
            json!({
                "action": "add",
                "actor_open_id": "ou_commenter"
            }),
            generate_valid_token(
                &signing_key,
                OP_COMMENTS_PAIRINGS_MANAGE,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap()
        .result
        .expect("pairing result");
    assert_eq!(pairing["changed"], true);
    assert_eq!(pairing["paired_open_ids"][0], "ou_commenter");

    let context = connector
        .invoke(invoke_req(
            OP_COMMENTS_CONTEXT_GET,
            json!({
                "file_token": "doc_context",
                "file_type": "docx",
                "comment_id": "comment_context",
                "reply_id": "reply_current"
            }),
            generate_valid_token(
                &signing_key,
                OP_COMMENTS_CONTEXT_GET,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap()
        .result
        .expect("context result");
    assert_eq!(context["document"]["title"], "Incident Runbook");
    assert_eq!(context["root_comment_text"], "Can you check this?");
    assert_eq!(
        context["target_reply_text"],
        "Stack trace is in the linked doc"
    );
    assert_eq!(context["raw_payload_included"], false);

    let reply = connector
        .invoke(invoke_req(
            OP_COMMENTS_REPLY,
            json!({
                "file_token": "doc_context",
                "file_type": "docx",
                "comment_id": "comment_context",
                "content": "Investigating <safe>",
                "fallback_to_whole_comment": true
            }),
            generate_valid_token(&signing_key, OP_COMMENTS_REPLY, connector.instance_id()),
        ))
        .await
        .unwrap()
        .result
        .expect("reply result");
    assert_eq!(reply["delivered"], true);
    assert_eq!(reply["delivery_mode"], "whole_comment");
    assert_eq!(reply["fallback_used"], true);

    let reaction = connector
        .invoke(invoke_req(
            OP_COMMENTS_REACTION,
            json!({
                "file_token": "doc_context",
                "file_type": "docx",
                "reply_id": "reply_current",
                "action": "add",
                "reaction_type": "Typing"
            }),
            generate_valid_token(&signing_key, OP_COMMENTS_REACTION, connector.instance_id()),
        ))
        .await
        .unwrap()
        .result
        .expect("reaction result");
    assert_eq!(reaction["action"], "add");
    assert_eq!(reaction["reaction_type"], "Typing");

    println!(
        "feishu_comment_automation_evidence={}",
        serde_json::to_string_pretty(&json!({
            "pairing": pairing,
            "context": context,
            "reply": reply,
            "reaction": reaction
        }))
        .unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = FeishuConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 15);
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
    let webhook = operations
        .iter()
        .find(|operation| operation["id"] == OP_WEBHOOK_INGEST_REQUEST)
        .expect("webhook ingest operation");
    assert_eq!(
        webhook["idempotency"],
        serde_json::to_value(IdempotencyClass::BestEffort).unwrap()
    );
    assert_eq!(
        webhook["input_schema"]["required"],
        json!(["method", "headers", "raw_body", "policy"])
    );
    let comment_context = operations
        .iter()
        .find(|operation| operation["id"] == OP_COMMENTS_CONTEXT_GET)
        .expect("comment context operation");
    assert_eq!(
        comment_context["safety_tier"],
        serde_json::to_value(SafetyTier::Safe).unwrap()
    );
    assert!(value["event_caps"]["replay"].as_bool().unwrap());
    assert!(
        value["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["topic"] == "feishu.webhook.message_received")
    );
    assert_eq!(value["auth_caps"]["methods"].as_array().unwrap().len(), 2);

    println!(
        "feishu_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
