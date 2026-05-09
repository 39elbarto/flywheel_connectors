//! Integration tests for the Anthropic Vertex connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use chrono::{Duration, Utc};
use fcp_anthropic_vertex::connector::{
    AnthropicVertexConnector, OP_MESSAGES_CREATE, OP_MESSAGES_STREAM, OP_MODELS_NORMALIZE,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, OperationId, RequestId, ZoneId,
};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_ACCESS_TOKEN: &str = "ya29.fcp-test-token";
const TEST_PROJECT: &str = "fcp-test-project";
const TEST_LOCATION: &str = "us-east5";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("anthropic_vertex.messages"),
            CapabilityId::from_static("anthropic_vertex.models.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_capability(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &'static str,
) -> CapabilityToken {
    let capability = match op {
        OP_MESSAGES_CREATE | OP_MESSAGES_STREAM => "anthropic_vertex.messages",
        _ => "anthropic_vertex.models.read",
    };
    generate_capability_for_id(signing_key, instance_id, op, capability)
}

fn generate_capability_for_id(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &'static str,
    capability: &'static str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .target_instance(instance_id)
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
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
        id: RequestId::new("anthropic-vertex-integration-1"),
        connector_id: ConnectorId::from_static("fcp.anthropic-vertex"),
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

async fn setup_connector(mock_url: &str) -> (AnthropicVertexConnector, Ed25519SigningKey) {
    let mut connector = AnthropicVertexConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "project_id": TEST_PROJECT,
            "location": TEST_LOCATION,
            "access_token": TEST_ACCESS_TOKEN,
            "quota_project_id": "billing-project",
            "base_url": mock_url,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure");
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake");
    (connector, signing_key)
}

#[test]
fn manifest_ai_hints_cover_all_anthropic_vertex_operations() {
    let manifest = toml::from_str::<toml::Value>(include_str!("../manifest.toml"))
        .expect("Anthropic Vertex manifest TOML should parse");
    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("Anthropic Vertex manifest should declare operations");

    for (operation_id, operation) in operations {
        let hints = operation.get("ai_hints").and_then(toml::Value::as_table);
        assert!(hints.is_some(), "{operation_id} missing ai_hints");
        let Some(hints) = hints else {
            continue;
        };
        assert!(
            hints
                .get("when_to_use")
                .and_then(toml::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} missing ai_hints.when_to_use"
        );
        assert!(
            hints
                .get("common_mistakes")
                .and_then(toml::Value::as_array)
                .is_some_and(|mistakes| !mistakes.is_empty()),
            "{operation_id} missing ai_hints.common_mistakes"
        );
    }
}

#[fcp_async_core::test]
async fn messages_create_uses_vertex_raw_predict_shape() {
    let server = MockServer::start().await;
    let expected_path = format!(
        "/v1/projects/{TEST_PROJECT}/locations/{TEST_LOCATION}/publishers/anthropic/models/claude-sonnet-4-6:rawPredict"
    );
    Mock::given(method("POST"))
        .and(path(expected_path))
        .and(header(
            "authorization",
            format!("Bearer {TEST_ACCESS_TOKEN}").as_str(),
        ))
        .and(header("x-goog-user-project", "billing-project"))
        .and(body_json(json!({
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 8,
            "anthropic_version": "vertex-2023-10-16",
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_vertex_1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "hello from vertex"}],
            "model": "claude-sonnet-4-6",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 3, "output_tokens": 4}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let capability = generate_valid_capability(
        &signing_key,
        connector.instance_id().as_str(),
        OP_MESSAGES_CREATE,
    );
    let response = connector
        .invoke(invoke_req(
            OP_MESSAGES_CREATE,
            json!({
                "model": "sonnet-4.6",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 8
            }),
            capability,
        ))
        .await
        .expect("invoke");
    let result = response.result.expect("result");
    assert_eq!(result["id"], "msg_vertex_1");
}

#[fcp_async_core::test]
async fn messages_stream_uses_vertex_stream_raw_predict_and_decodes_sse() {
    let server = MockServer::start().await;
    let expected_path = format!(
        "/v1/projects/{TEST_PROJECT}/locations/{TEST_LOCATION}/publishers/anthropic/models/claude-sonnet-4-5@20250929:streamRawPredict"
    );
    Mock::given(method("POST"))
        .and(path(expected_path))
        .and(header("accept", "text/event-stream"))
        .and(body_json(json!({
            "messages": [{"role": "user", "content": "stream"}],
            "max_tokens": 8,
            "anthropic_version": "vertex-2023-10-16",
            "stream": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "event: message_start\ndata: {\"type\":\"message_start\"}\n\n\
             data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n\
             data: [DONE]\n\n",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let capability = generate_valid_capability(
        &signing_key,
        connector.instance_id().as_str(),
        OP_MESSAGES_STREAM,
    );
    let response = connector
        .invoke(invoke_req(
            OP_MESSAGES_STREAM,
            json!({
                "model": "claude-sonnet-4-5-20250929",
                "messages": [{"role": "user", "content": "stream"}],
                "max_tokens": 8
            }),
            capability,
        ))
        .await
        .expect("invoke");
    let result = response.result.expect("stream result");
    assert_eq!(result["event_count"], 2);
    assert_eq!(result["events"][0]["payload_json"]["type"], "message_start");
}

#[fcp_async_core::test]
async fn retryable_vertex_error_retries_once() {
    let server = MockServer::start().await;
    let expected_path = format!(
        "/v1/projects/{TEST_PROJECT}/locations/{TEST_LOCATION}/publishers/anthropic/models/claude-sonnet-4-6:rawPredict"
    );
    Mock::given(method("POST"))
        .and(path(expected_path.clone()))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": {
                        "code": 429,
                        "status": "RESOURCE_EXHAUSTED",
                        "message": "quota"
                    }
                })),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(expected_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_vertex_retry",
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": "claude-sonnet-4-6",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = AnthropicVertexConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "project_id": TEST_PROJECT,
            "location": TEST_LOCATION,
            "access_token": TEST_ACCESS_TOKEN,
            "base_url": server.uri(),
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure");
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake");
    let capability = generate_valid_capability(
        &signing_key,
        connector.instance_id().as_str(),
        OP_MESSAGES_CREATE,
    );
    let response = connector
        .invoke(invoke_req(
            OP_MESSAGES_CREATE,
            json!({
                "model": "sonnet-4.6",
                "messages": [{"role": "user", "content": "retry"}],
                "max_tokens": 8
            }),
            capability,
        ))
        .await
        .expect("retry invoke");
    assert_eq!(response.result.unwrap()["id"], "msg_vertex_retry");
}

#[fcp_async_core::test]
async fn runtime_rejects_adc_and_default_credentials() {
    let mut connector = AnthropicVertexConnector::new();
    let error = connector
        .configure(json!({
            "project_id": TEST_PROJECT,
            "location": "global",
            "application_default_credentials": true
        }))
        .await
        .expect_err("ADC should be provisioning-only");
    assert!(
        error
            .to_string()
            .contains("application_default_credentials"),
        "unexpected error: {error}"
    );
}

#[fcp_async_core::test]
async fn credential_id_mode_configures_but_self_check_is_degraded_until_injected() {
    let credential_id = fcp_prelude::CredentialId::new();
    let mut connector = AnthropicVertexConnector::new();
    connector
        .configure(json!({
            "project_id": TEST_PROJECT,
            "location": "global",
            "credential_id": credential_id.to_string()
        }))
        .await
        .expect("credential config");
    let report = connector.self_check().await.expect("self check");
    assert_eq!(
        report.reason_code.as_deref(),
        Some("self_check_unsupported_on_default_vertex")
    );
    let health = connector.health().await;
    let details = health.details.expect("health details");
    assert_eq!(
        details["provisioning"]["auth_source"].as_str(),
        Some("credential_id")
    );
}

#[fcp_async_core::test]
async fn model_normalization_operation_returns_vertex_id_without_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let capability = generate_valid_capability(
        &signing_key,
        connector.instance_id().as_str(),
        OP_MODELS_NORMALIZE,
    );
    let response = connector
        .invoke(invoke_req(
            OP_MODELS_NORMALIZE,
            json!({ "model": "claude-opus-4-5-20251101" }),
            capability,
        ))
        .await
        .expect("normalize");
    let result = response.result.expect("result");
    assert_eq!(result["vertex_model"], "claude-opus-4-5@20251101");
    assert_eq!(result["catalog_entry"]["display_name"], "Claude Opus 4.5");
}

#[fcp_async_core::test]
async fn capability_denial_blocks_message_invoke() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let wrong_capability = generate_capability_for_id(
        &signing_key,
        connector.instance_id().as_str(),
        OP_MESSAGES_CREATE,
        "anthropic_vertex.models.read",
    );
    let error = connector
        .invoke(invoke_req(
            OP_MESSAGES_CREATE,
            json!({
                "model": "sonnet-4.6",
                "messages": [{"role": "user", "content": "denied"}],
                "max_tokens": 8
            }),
            wrong_capability,
        ))
        .await
        .expect_err("capability must deny");
    assert_eq!(error.error_code(), "FCP-3003");
}
