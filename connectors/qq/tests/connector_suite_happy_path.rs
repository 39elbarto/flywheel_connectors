use std::{collections::BTreeSet, sync::Arc};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_qq::QqConnector;
use fcp_sdk::{ChatCoordinationBackend, InMemoryThreadOwnershipChecker};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_SEND_CHANNEL: &str = "qq.messages.send_channel";
const CAP_MESSAGES_WRITE: &str = "qq.messages.write";

#[derive(Default)]
struct AiHintCoverage {
    missing_when_to_use: Vec<String>,
    missing_common_mistakes: Vec<String>,
    missing_examples: Vec<String>,
    invalid_examples: Vec<String>,
    secret_shaped_examples: Vec<String>,
}

fn qq_manifest_operations(manifest: &toml::Value) -> &toml::Table {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("QQ manifest should define operations")
}

fn expected_qq_manifest_operations() -> BTreeSet<String> {
    [
        "messages_send_channel",
        "messages_send_group",
        "messages_send_c2c",
        "gateway_get",
        "events_normalize",
        "gateway_project_event",
        "health",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn collect_ai_hint_coverage(operations: &toml::Table) -> AiHintCoverage {
    let mut coverage = AiHintCoverage::default();
    for (operation_id, operation) in operations {
        let Some(ai_hints) = operation.get("ai_hints").and_then(toml::Value::as_table) else {
            coverage.missing_when_to_use.push(operation_id.clone());
            coverage.missing_common_mistakes.push(operation_id.clone());
            coverage.missing_examples.push(operation_id.clone());
            continue;
        };

        let when_to_use = ai_hints
            .get("when_to_use")
            .and_then(toml::Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        if when_to_use.is_empty() {
            coverage.missing_when_to_use.push(operation_id.clone());
        }

        let common_mistakes = ai_hints
            .get("common_mistakes")
            .and_then(toml::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if common_mistakes.is_empty()
            || common_mistakes
                .iter()
                .filter_map(toml::Value::as_str)
                .all(|mistake| mistake.trim().is_empty())
        {
            coverage.missing_common_mistakes.push(operation_id.clone());
        }

        let examples = ai_hints
            .get("examples")
            .and_then(toml::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if examples.is_empty() {
            coverage.missing_examples.push(operation_id.clone());
            continue;
        }

        for example in examples {
            let Some(example_text) = example.as_str().map(str::trim) else {
                coverage
                    .invalid_examples
                    .push(format!("{operation_id}: non-string example"));
                continue;
            };
            if example_text.is_empty() {
                coverage
                    .invalid_examples
                    .push(format!("{operation_id}: empty example"));
                continue;
            }
            if let Err(error) = serde_json::from_str::<Value>(example_text) {
                coverage
                    .invalid_examples
                    .push(format!("{operation_id}: invalid json example: {error}"));
            }

            let lower = example_text.to_ascii_lowercase();
            for forbidden in ["api_key", "bearer", "password", "secret", "token"] {
                if lower.contains(forbidden) {
                    coverage
                        .secret_shaped_examples
                        .push(format!("{operation_id}: {forbidden}"));
                }
            }
        }
    }
    coverage
}

#[test]
fn qq_manifest_ai_hints_cover_all_operations() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../manifest.toml")).expect("QQ manifest should parse");
    let operations = qq_manifest_operations(&manifest);
    assert_eq!(
        operations.keys().cloned().collect::<BTreeSet<_>>(),
        expected_qq_manifest_operations(),
        "manifest operation inventory changed; update ai_hints coverage expectations"
    );

    let coverage = collect_ai_hint_coverage(operations);

    assert!(
        coverage.missing_when_to_use.is_empty(),
        "operations missing ai_hints.when_to_use: {:?}",
        coverage.missing_when_to_use
    );
    assert!(
        coverage.missing_common_mistakes.is_empty(),
        "operations missing ai_hints.common_mistakes: {:?}",
        coverage.missing_common_mistakes
    );
    assert!(
        coverage.missing_examples.is_empty(),
        "operations missing ai_hints.examples: {:?}",
        coverage.missing_examples
    );
    assert!(
        coverage.invalid_examples.is_empty(),
        "operations with invalid ai_hints examples: {:?}",
        coverage.invalid_examples
    );
    assert!(
        coverage.secret_shaped_examples.is_empty(),
        "ai_hints examples contain secret-shaped values: {:?}",
        coverage.secret_shaped_examples
    );
}

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
        .operations(&[OP_SEND_CHANNEL])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn channel_send_request(
    request_id: &str,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    content: &str,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(request_id),
        connector_id: ConnectorId::from_static("fcp.qq"),
        operation: OperationId::from_static(OP_SEND_CHANNEL),
        zone_id: ZoneId::work(),
        input: json!({
            "channel_id": "channel-1",
            "content": content
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
    let instance_id = InstanceId::new();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), instance_id.clone());
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
        capability_token: build_token(&signing_key, &instance_id),
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

#[fcp_async_core::runtime::test]
async fn channel_send_claims_thread_and_denies_duplicate_before_http() {
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
            "content": "agent A reply"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg-1",
            "timestamp": "2026-04-27T19:00:00Z"
        })))
        .expect(1)
        .mount(&api_server)
        .await;

    let config = json!({
        "base_url": api_server.uri(),
        "token_base_url": token_server.uri(),
        "app_id": "qq-app",
        "client_secret": "test-secret",
        "request_timeout_ms": 5_000
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = QqConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = QqConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    first
        .configure(config.clone())
        .await
        .expect("first configure should succeed");
    second
        .configure(config)
        .await
        .expect("second configure should succeed");

    let first_key = Ed25519SigningKey::generate();
    let second_key = Ed25519SigningKey::generate();
    let first_instance = InstanceId::new();
    let second_instance = InstanceId::new();
    first
        .handshake(handshake_request(
            first_key.verifying_key().to_bytes(),
            first_instance.clone(),
        ))
        .await
        .expect("first handshake should succeed");
    second
        .handshake(handshake_request(
            second_key.verifying_key().to_bytes(),
            second_instance.clone(),
        ))
        .await
        .expect("second handshake should succeed");

    let first_response = first
        .invoke(channel_send_request(
            "qq-first-send",
            &first_key,
            &first_instance,
            "agent A reply",
        ))
        .await
        .expect("first send should succeed");
    let first_result = first_response.result.expect("first send result");
    let coordination = first_result["coordination"]
        .as_array()
        .expect("coordination audit records should be present");
    assert_eq!(coordination[0]["event"], "claim_attempt");
    assert_eq!(coordination[1]["outcome"], "granted");
    assert_eq!(coordination[2]["event"], "send_executed");
    let coordination_text = Value::Array(coordination.clone()).to_string();
    assert!(!coordination_text.contains("channel-1"));
    assert!(!coordination_text.contains("agent A reply"));
    assert!(!coordination_text.contains(first_instance.as_str()));

    let second_error = second
        .invoke(channel_send_request(
            "qq-second-send",
            &second_key,
            &second_instance,
            "agent B reply",
        ))
        .await
        .expect_err("second send should be denied by duplicate claim");
    match second_error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 4090);
            assert!(message.starts_with("thread_owned_by_peer:"));
            assert!(message.contains(first_instance.as_str()));
        }
        other => panic!("expected duplicate claim denial, got {other:?}"),
    }

    let api_requests = api_server.received_requests().await.unwrap_or_default();
    assert_eq!(
        api_requests.len(),
        1,
        "duplicate QQ claim must not reach the message endpoint"
    );
}
