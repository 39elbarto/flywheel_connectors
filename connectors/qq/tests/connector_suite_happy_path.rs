use chrono::{Duration, Utc};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_qq::QqConnector;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_SEND_CHANNEL: &str = "qq.messages.send_channel";
const CAP_MESSAGES_WRITE: &str = "qq.messages.write";

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_MESSAGES_WRITE)],
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
        .capability_id(CAP_MESSAGES_WRITE)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_SEND_CHANNEL])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_sends_channel_message() {
    let api_server = MockServer::start().await;
    let token_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/app/getAppAccessToken"))
        .and(body_partial_json(json!({
            "appId": "qq-app",
            "clientSecret": "test-secret"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "token-123",
            "expires_in": 7200
        })))
        .expect(1)
        .mount(&token_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/channels/channel-1/messages"))
        .and(header("authorization", "QQBot token-123"))
        .and(body_partial_json(json!({
            "content": "hello from connector suite"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg-1",
            "timestamp": "2026-04-27T19:00:00Z"
        })))
        .expect(1)
        .mount(&api_server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let invoke = InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("qq-connector-suite"),
        connector_id: ConnectorId::from_static("fcp.qq"),
        operation: OperationId::from_static(OP_SEND_CHANNEL),
        zone_id: ZoneId::work(),
        input: json!({
            "channel_id": "channel-1",
            "content": "hello from connector suite"
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
        test_name: "qq_send_channel_happy_path".to_string(),
        config: json!({
            "base_url": api_server.uri(),
            "token_base_url": token_server.uri(),
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "request_timeout_ms": 5_000
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = QqConnector::new();
    let mut runner = E2eRunner::new("fcp-qq");
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

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
