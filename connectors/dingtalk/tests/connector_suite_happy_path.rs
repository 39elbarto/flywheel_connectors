use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_dingtalk::DingTalkConnector;
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_SEND_TEXT: &str = "dingtalk.messages.send_text";
const CAP_MESSAGES_WRITE: &str = "dingtalk.messages.write";

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
        .operations(&[OP_SEND_TEXT])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_sends_text_message() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1.0/oauth2/accessToken"))
        .and(body_partial_json(json!({
            "appKey": "ding-app",
            "appSecret": "test-secret"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "token-123",
            "expireIn": 7200
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1.0/robot/oToMessages/batchSend"))
        .and(header("x-acs-dingtalk-access-token", "token-123"))
        .and(body_partial_json(json!({
            "robotCode": "ding-app",
            "userIds": ["user-1"],
            "msgKey": "sampleMarkdown"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "processQueryKey": "msg-1"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let invoke = InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("dingtalk-connector-suite"),
        connector_id: ConnectorId::from_static("fcp.dingtalk"),
        operation: OperationId::from_static(OP_SEND_TEXT),
        zone_id: ZoneId::work(),
        input: json!({
            "to": "user:user-1",
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
        test_name: "dingtalk_send_text_happy_path".to_string(),
        config: json!({
            "base_url": server.uri(),
            "media_base_url": server.uri(),
            "client_id": "ding-app",
            "client_secret": "test-secret",
            "request_timeout_ms": 5_000
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = DingTalkConnector::new();
    let mut runner = E2eRunner::new("fcp-dingtalk");
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
