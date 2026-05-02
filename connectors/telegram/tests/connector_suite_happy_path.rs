use chrono::{Duration, Utc};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_telegram::connector::TelegramConnector;
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path},
};

const OP_SEND_MESSAGE: &str = "telegram.send_message";
const CAP_SEND: &str = "telegram.send";
const TEST_BOT_ID: &str = "123456";
const TEST_BOT_SUFFIX: &str = "ABCDEFGHIJKLMNOPQRSTUVWXyz012345";

fn test_bot_credential() -> String {
    format!("{TEST_BOT_ID}:{TEST_BOT_SUFFIX}")
}

fn token_path(api_method: &str) -> String {
    format!("/bot{}/{api_method}", test_bot_credential())
}

fn unique_zone_dir(label: &str) -> String {
    let dir = std::env::temp_dir()
        .join("fcp-telegram-connector-suite")
        .join(format!("{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create connector-suite zone dir");
    dir.to_string_lossy().into_owned()
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: Some(unique_zone_dir("happy-path")),
        host_public_key,
        nonce: [11u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_SEND)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_SEND)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_SEND_MESSAGE])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_sends_message() {
    let telegram_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(token_path("getMe")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "id": 123456789,
                "is_bot": true,
                "first_name": "Test Bot",
                "username": "test_bot_fcp"
            }
        })))
        .mount(&telegram_server)
        .await;

    Mock::given(method("POST"))
        .and(path(token_path("getUpdates")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": []
        })))
        .mount(&telegram_server)
        .await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .and(body_partial_json(json!({
            "chat_id": "123456",
            "text": "hello from connector suite"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 42,
                "chat": { "id": 123456, "type": "private", "first_name": "Test" },
                "date": 1234567890,
                "text": "hello from connector suite"
            }
        })))
        .expect(1)
        .mount(&telegram_server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let invoke = InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("telegram-connector-suite"),
        connector_id: ConnectorId::from_static("fcp.telegram"),
        operation: OperationId::from_static(OP_SEND_MESSAGE),
        zone_id: ZoneId::work(),
        input: json!({
            "chat_id": "123456",
            "text": "hello from connector suite"
        }),
        capability_token: build_token(&signing_key),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };

    let suite = ConnectorSuite {
        test_name: "telegram_send_message_happy_path".to_string(),
        config: json!({
            "credential": test_bot_credential(),
            "base_url": telegram_server.uri()
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = TelegramConnector::new();
    let mut runner = E2eRunner::new("fcp-telegram");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector suite");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
