//! Integration tests for the Synology Chat connector.

use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    InvokeRequest, OperationId, RequestId, SelfCheckStatus, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_synology_chat::SynologyChatConnector;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

const CAP_READ: &str = "synology_chat.read";
const CAP_WRITE: &str = "synology_chat.write";
const CAP_WEBHOOK: &str = "synology_chat.webhook";

const OP_SEND_MESSAGE: &str = "synology_chat.send_message";
const OP_SEND_PAYLOAD: &str = "synology_chat.send_payload";
const OP_INGEST_OUTGOING_WEBHOOK: &str = "synology_chat.ingest_outgoing_webhook";
const OP_HEALTH: &str = "synology_chat.health";

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [11u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| CapabilityId::new(*capability).expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
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
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .constraints_cbor(&cbor)
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

fn invoke_request(
    connector: &SynologyChatConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("synology-chat-integration"),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(operation),
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
        approval_tokens: Vec::new(),
    }
}

async fn setup_connector(
    incoming_url: &str,
    capabilities: &[&str],
) -> (SynologyChatConnector, Ed25519SigningKey) {
    setup_connector_with_options(incoming_url, None, capabilities).await
}

async fn setup_connector_with_options(
    incoming_url: &str,
    outgoing_token: Option<&str>,
    capabilities: &[&str],
) -> (SynologyChatConnector, Ed25519SigningKey) {
    let mut connector = SynologyChatConnector::new();
    let mut config = json!({
        "incoming_url": incoming_url,
        "request_timeout_ms": 2_000
    });
    if let Some(token) = outgoing_token {
        config["outgoing_token"] = json!(token);
    }
    connector
        .configure(config)
        .await
        .expect("configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            capabilities,
        ))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke_ok(
    connector: &SynologyChatConnector,
    operation: &'static str,
    input: Value,
    capability: &str,
    signing_key: &Ed25519SigningKey,
) -> Value {
    connector
        .invoke(invoke_request(
            connector,
            operation,
            input,
            capability_token(signing_key, capability, &[operation]),
        ))
        .await
        .expect("invoke should succeed")
        .result
        .expect("successful invoke should carry a result")
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_reports_degraded_details() {
    let connector = SynologyChatConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.expect("health details should exist");
    assert_eq!(details["configured"], false);
    assert!(details["delivery_target"].is_null());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_invalid_incoming_url_scheme() {
    let mut connector = SynologyChatConnector::new();
    let error = connector
        .configure(json!({
            "incoming_url": "ftp://nas.example.com/webhook"
        }))
        .await
        .expect_err("invalid scheme should fail");

    match error {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1003);
            assert!(message.contains("http or https"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_zero_timeout() {
    let mut connector = SynologyChatConnector::new();
    let error = connector
        .configure(json!({
            "incoming_url": "https://nas.example.com/webhook",
            "request_timeout_ms": 0
        }))
        .await
        .expect_err("zero timeout should fail");

    match error {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1003);
            assert!(message.contains("greater than zero"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn self_check_reports_configured_metadata() {
    let mut connector = SynologyChatConnector::new();
    connector
        .configure(json!({
            "incoming_url": "https://nas.example.com/webhook",
            "allow_insecure_ssl": true,
            "outgoing_token": "shared-secret"
        }))
        .await
        .expect("configure should succeed");

    let report = connector
        .self_check()
        .await
        .expect("self check should succeed");
    assert_eq!(report.status, SelfCheckStatus::Ok);
    let details = report.details.expect("self check details should exist");
    assert_eq!(
        details["delivery_target"]["incoming_url_redacted"],
        "https://nas.example.com:443/webhook"
    );
    assert_eq!(details["allow_insecure_ssl"], true);
    assert_eq!(details["outgoing_token_configured"], true);
    assert_eq!(details["reply_semantics"], "outgoing_webhook_response");
    assert_eq!(details["receive_path"], "forwarded_outgoing_webhook");
}

#[fcp_async_core::runtime::test]
async fn send_message_posts_expected_payload_and_normalizes_empty_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .and(body_json(json!({
            "text": "Hello from Flywheel",
            "user_ids": ["u-123"],
            "username": "Build Bot"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let (connector, signing_key) =
        setup_connector(&format!("{}/webhook", server.uri()), &[CAP_WRITE]).await;

    let result = invoke_ok(
        &connector,
        OP_SEND_MESSAGE,
        json!({
            "text": "Hello from Flywheel",
            "user_id": "u-123",
            "bot_name": "Build Bot"
        }),
        CAP_WRITE,
        &signing_key,
    )
    .await;

    assert_eq!(result["status"], "ok");
    assert_eq!(result["http_status"], 200);
    assert_eq!(result["response_kind"], "empty");
}

#[fcp_async_core::runtime::test]
async fn send_payload_wraps_plain_text_success_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .and(body_json(json!({
            "text": "Webhook body",
            "attachments": [{ "text": "Details" }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("queued"))
        .mount(&server)
        .await;

    let (connector, signing_key) =
        setup_connector(&format!("{}/webhook", server.uri()), &[CAP_WRITE]).await;

    let result = invoke_ok(
        &connector,
        OP_SEND_PAYLOAD,
        json!({
            "payload": {
                "text": "Webhook body",
                "attachments": [{ "text": "Details" }]
            }
        }),
        CAP_WRITE,
        &signing_key,
    )
    .await;

    assert_eq!(result["status"], "ok");
    assert_eq!(result["http_status"], 200);
    assert_eq!(result["response_kind"], "text");
    assert_eq!(result["raw_body"], "queued");
}

#[fcp_async_core::runtime::test]
async fn send_payload_rejects_non_object_payloads() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        setup_connector(&format!("{}/webhook", server.uri()), &[CAP_WRITE]).await;

    let error = connector
        .invoke(invoke_request(
            &connector,
            OP_SEND_PAYLOAD,
            json!({ "payload": "not-an-object" }),
            capability_token(&signing_key, CAP_WRITE, &[OP_SEND_PAYLOAD]),
        ))
        .await
        .expect_err("non-object payload should fail");

    match error {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1005);
            assert!(message.contains("payload must be a JSON object"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn send_message_surfaces_retryable_api_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(503).set_body_string("temporarily unavailable"))
        .mount(&server)
        .await;

    let (connector, signing_key) =
        setup_connector(&format!("{}/webhook", server.uri()), &[CAP_WRITE]).await;

    let error = connector
        .invoke(invoke_request(
            &connector,
            OP_SEND_MESSAGE,
            json!({ "text": "retry me" }),
            capability_token(&signing_key, CAP_WRITE, &[OP_SEND_MESSAGE]),
        ))
        .await
        .expect_err("503 should surface as an FCP external error");

    match error {
        FcpError::External {
            service,
            message,
            status_code,
            retryable,
            ..
        } => {
            assert_eq!(service, "synology_chat");
            assert_eq!(status_code, Some(503));
            assert!(retryable);
            assert!(message.contains("temporarily unavailable"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_health_reports_runtime_configuration() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        setup_connector(&format!("{}/webhook", server.uri()), &[CAP_READ, CAP_WRITE]).await;

    let result = invoke_ok(&connector, OP_HEALTH, json!({}), CAP_READ, &signing_key).await;

    assert_eq!(result["status"], "ok");
    assert_eq!(
        result["delivery_target"]["incoming_url_redacted"],
        format!("{}{}", server.uri(), "/webhook")
    );
    assert_eq!(result["outgoing_token_configured"], false);
    assert_eq!(result["reply_semantics"], "outbound_only");
}

#[fcp_async_core::runtime::test]
async fn ingest_outgoing_webhook_normalizes_channel_thread_and_attachment_context() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector_with_options(
        &format!("{}/webhook", server.uri()),
        Some("shared-secret"),
        &[CAP_WEBHOOK],
    )
    .await;

    let result = invoke_ok(
        &connector,
        OP_INGEST_OUTGOING_WEBHOOK,
        json!({
            "payload": {
                "token": "shared-secret",
                "channel_id": "34",
                "channel_type": "1",
                "channel_name": "Labb",
                "user_id": "4",
                "username": "mikael",
                "post_id": "146028888128",
                "thread_id": "0",
                "timestamp": "1646827836131",
                "text": "Tjena",
                "trigger_word": "Tjena",
                "file_url": "https://nas.example.com/files/report.pdf"
            }
        }),
        CAP_WEBHOOK,
        &signing_key,
    )
    .await;

    let event = &result["event"];
    assert_eq!(
        event["delivery_id"],
        "synology-chat:34:146028888128:1646827836131"
    );
    assert_eq!(event["channel"]["id"], "34");
    assert_eq!(event["channel"]["type"], "1");
    assert_eq!(event["channel"]["name"], "Labb");
    assert_eq!(event["thread"]["is_threaded"], false);
    assert!(event["thread"]["id"].is_null());
    assert_eq!(event["sender"]["user_id"], "4");
    assert_eq!(event["sender"]["username"], "mikael");
    assert_eq!(event["message"]["post_id"], "146028888128");
    assert_eq!(event["message"]["text"], "Tjena");
    assert_eq!(event["message"]["trigger_word"], "Tjena");
    assert_eq!(event["message"]["timestamp_ms"], 1_646_827_836_131i64);
    assert_eq!(event["attachments"][0]["kind"], "external_file");
    assert_eq!(
        event["attachments"][0]["url"],
        "https://nas.example.com/files/report.pdf"
    );
    assert_eq!(event["reply"]["mode"], "outgoing_webhook_response");
}

#[fcp_async_core::runtime::test]
async fn ingest_outgoing_webhook_rejects_token_mismatch() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector_with_options(
        &format!("{}/webhook", server.uri()),
        Some("shared-secret"),
        &[CAP_WEBHOOK],
    )
    .await;

    let error = connector
        .invoke(invoke_request(
            &connector,
            OP_INGEST_OUTGOING_WEBHOOK,
            json!({
                "payload": {
                    "token": "wrong-secret",
                    "channel_id": "34",
                    "channel_type": "1",
                    "user_id": "4",
                    "username": "mikael",
                    "post_id": "146028888128",
                    "thread_id": "0",
                    "timestamp": "1646827836131",
                    "text": "Tjena"
                }
            }),
            capability_token(&signing_key, CAP_WEBHOOK, &[OP_INGEST_OUTGOING_WEBHOOK]),
        ))
        .await
        .expect_err("token mismatch should fail");

    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert!(message.contains("token verification failed"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn ingest_outgoing_webhook_rejects_non_string_token_values() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector_with_options(
        &format!("{}/webhook", server.uri()),
        Some("true"),
        &[CAP_WEBHOOK],
    )
    .await;

    let error = connector
        .invoke(invoke_request(
            &connector,
            OP_INGEST_OUTGOING_WEBHOOK,
            json!({
                "payload": {
                    "token": true,
                    "channel_id": "34",
                    "channel_type": "1",
                    "user_id": "4",
                    "username": "mikael",
                    "post_id": "146028888128",
                    "thread_id": "0",
                    "timestamp": "1646827836131",
                    "text": "Tjena"
                }
            }),
            capability_token(&signing_key, CAP_WEBHOOK, &[OP_INGEST_OUTGOING_WEBHOOK]),
        ))
        .await
        .expect_err("boolean token values must be rejected");

    match error {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1005);
            assert!(message.contains("payload.token must be a non-empty string"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn ingest_outgoing_webhook_rejects_negative_timestamps() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector_with_options(
        &format!("{}/webhook", server.uri()),
        Some("shared-secret"),
        &[CAP_WEBHOOK],
    )
    .await;

    let error = connector
        .invoke(invoke_request(
            &connector,
            OP_INGEST_OUTGOING_WEBHOOK,
            json!({
                "payload": {
                    "token": "shared-secret",
                    "channel_id": "34",
                    "channel_type": "1",
                    "user_id": "4",
                    "username": "mikael",
                    "post_id": "146028888128",
                    "thread_id": "0",
                    "timestamp": "-1",
                    "text": "Tjena"
                }
            }),
            capability_token(&signing_key, CAP_WEBHOOK, &[OP_INGEST_OUTGOING_WEBHOOK]),
        ))
        .await
        .expect_err("negative timestamps must be rejected");

    match error {
        FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1005);
            assert!(message.contains("payload.timestamp must be a non-negative integer timestamp"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
