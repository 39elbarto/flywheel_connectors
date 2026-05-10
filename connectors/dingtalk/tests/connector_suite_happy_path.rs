use std::sync::Arc;

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_dingtalk::DingTalkConnector;
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::{ChatCoordinationBackend, InMemoryThreadOwnershipChecker};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_SEND_TEXT: &str = "dingtalk.messages.send_text";
const CAP_MESSAGES_WRITE: &str = "dingtalk.messages.write";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn handshake_request(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_MESSAGES_WRITE)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn build_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
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
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn send_text_invoke(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &'static str,
) -> InvokeRequest {
    send_text_invoke_for(signing_key, instance_id, id, "user:user-1")
}

fn send_text_invoke_for(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &'static str,
    to: &str,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.dingtalk"),
        operation: OperationId::from_static(OP_SEND_TEXT),
        zone_id: ZoneId::work(),
        input: json!({
            "to": to,
            "content": "hello from connector suite"
        }),
        capability_token: build_token(signing_key, instance_id),
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

async fn setup_connector_with_checker(
    base_url: &str,
    checker: Arc<InMemoryThreadOwnershipChecker>,
) -> (DingTalkConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = DingTalkConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .configure(json!({
            "base_url": base_url,
            "media_base_url": base_url,
            "client_id": "ding-app",
            "client_secret": "test-secret",
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure connector");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake connector");
    (connector, signing_key, instance_id)
}

#[test]
fn dingtalk_manifest_ai_hints_cover_all_operations() {
    let manifest: toml::Value = toml::from_str(MANIFEST_TOML).expect("parse manifest");
    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest operations table");

    assert_eq!(
        operations.len(),
        8,
        "DingTalk manifest operation count should stay explicit"
    );

    for (operation_id, operation) in operations {
        let ai_hints = operation
            .get("ai_hints")
            .unwrap_or_else(|| panic!("{operation_id} must define ai_hints"));

        let when_to_use = ai_hints
            .get("when_to_use")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        assert!(
            !when_to_use.trim().is_empty(),
            "{operation_id} must explain when to use the operation"
        );

        let common_mistakes = ai_hints
            .get("common_mistakes")
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| panic!("{operation_id} must define common_mistakes"));
        assert!(
            !common_mistakes.is_empty(),
            "{operation_id} must include at least one common mistake"
        );

        let examples = ai_hints
            .get("examples")
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| panic!("{operation_id} must define examples"));
        assert!(
            !examples.is_empty(),
            "{operation_id} must include at least one redaction-safe example"
        );

        for example in examples {
            let example = example
                .as_str()
                .unwrap_or_else(|| panic!("{operation_id} example must be a string"));
            let lower = example.to_ascii_lowercase();
            assert!(
                !lower.contains("token")
                    && !lower.contains("password")
                    && !lower.contains("secret"),
                "{operation_id} example should not contain sensitive-looking fields: {example}"
            );
            serde_json::from_str::<serde_json::Value>(example)
                .unwrap_or_else(|error| panic!("{operation_id} example is not JSON: {error}"));
        }
    }
}

#[fcp_async_core::runtime::test]
async fn send_text_claims_target_and_denies_duplicate_before_http() {
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
            "userIds": ["coord-user"],
            "msgKey": "sampleMarkdown"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "processQueryKey": "msg-1"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let (connector_a, signing_key_a, instance_id_a) =
        setup_connector_with_checker(&server.uri(), checker.clone()).await;
    let (connector_b, signing_key_b, instance_id_b) =
        setup_connector_with_checker(&server.uri(), checker).await;

    let first = connector_a
        .invoke(send_text_invoke_for(
            &signing_key_a,
            &instance_id_a,
            "dingtalk-claim-first",
            "user:coord-user",
        ))
        .await
        .expect("first coordinated send");
    assert_eq!(first.status, InvokeStatus::Ok);
    let result = first.result.expect("send result");
    assert_eq!(result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(result["coordination"][1]["outcome"], "granted");
    assert_eq!(result["coordination"][2]["event"], "send_executed");
    assert!(
        !serde_json::to_string(&result["coordination"])
            .expect("serialize coordination")
            .contains("coord-user"),
        "coordination audit must not leak the raw DingTalk user ID"
    );

    let err = connector_b
        .invoke(send_text_invoke_for(
            &signing_key_b,
            &instance_id_b,
            "dingtalk-claim-duplicate",
            "user:coord-user",
        ))
        .await
        .expect_err("duplicate coordinated send should be denied");
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
        2,
        "duplicate claim must be denied before token or send HTTP"
    );
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
    let instance_id = InstanceId::new();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), instance_id.clone());
    let invoke = send_text_invoke(&signing_key, &instance_id, "dingtalk-connector-suite");

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

#[fcp_async_core::runtime::test]
async fn connector_suite_error_path_reports_rate_limited_send_text() {
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
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({
                    "code": "TooManyRequests",
                    "message": "DingTalk rate limit exceeded"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), instance_id.clone());
    let invoke = send_text_invoke(
        &signing_key,
        &instance_id,
        "dingtalk-connector-suite-rate-limited",
    );

    let suite = ConnectorSuite {
        test_name: "dingtalk_send_text_rate_limited".to_string(),
        config: json!({
            "base_url": server.uri(),
            "media_base_url": server.uri(),
            "client_id": "ding-app",
            "client_secret": "test-secret",
            "request_timeout_ms": 5_000
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            ..InvokeExpectations::default()
        },
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
    let execute = report
        .logs
        .iter()
        .map(|entry| serde_json::to_value(entry).expect("serialize report log"))
        .find(|entry| {
            matches!(
                entry.get("phase").and_then(serde_json::Value::as_str),
                Some("execute")
            )
        })
        .expect("execute log entry");
    assert_eq!(
        execute["context"]["expected_error"],
        json!(true),
        "suite must assert the expected error path"
    );
    assert_eq!(
        execute["context"]["reason_code"],
        json!("FCP-3002"),
        "HTTP 429 should map to the FCP rate-limit code"
    );
    assert_eq!(
        execute["context"]["retryable"],
        json!(true),
        "429 responses should be reported as retryable"
    );
    assert_eq!(
        execute["context"]["retry_after_ms"],
        json!(2_000),
        "retry-after header should be preserved as milliseconds"
    );
}
