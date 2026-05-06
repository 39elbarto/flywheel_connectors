#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_groq::GroqConnector;
use fcp_groq::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "groq.chat.completions";
const OP_CHAT_STREAM: &str = "groq.chat.completions_stream";
const OP_MODELS: &str = "groq.models.list";
const OP_HEALTH: &str = "groq.health";
const OP_EMBEDDINGS: &str = "groq.embeddings.create";
const CAP_CHAT: &str = "groq.chat";
const CAP_MODELS: &str = "groq.models.read";
const CAP_HEALTH: &str = "groq.health.read";
const CAP_EMBEDDINGS: &str = "groq.embeddings";

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

async fn configured_connector(
    server: &MockServer,
    capabilities: &[&'static str],
    extra_config: Value,
) -> (GroqConnector, Ed25519SigningKey) {
    let mut connector = GroqConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("groq-test-key"));
    config.insert(
        "base_url".into(),
        json!(format!("{}/openai/v1", server.uri())),
    );
    if let Some(extra) = extra_config.as_object() {
        for (key, value) in extra {
            config.insert(key.clone(), value.clone());
        }
    }
    connector
        .handle_configure(Value::Object(config))
        .await
        .expect("configure should succeed");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let caps = capabilities
        .iter()
        .map(|cap| CapabilityId::from_static(cap))
        .collect();
    connector
        .handshake(test_handshake_request(caps, verifying_key.to_bytes()))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke(
    connector: &GroqConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_grant,
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn chat_completions_uses_shared_oai_surface_and_redacted_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("authorization", "Bearer groq-test-key"))
        .and(body_partial_json(json!({
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-groq",
            "object": "chat.completion",
            "created": 1,
            "model": "llama-3.1-8b-instant",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from Groq"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 3,
                "total_tokens": 5,
                "queue_time": 0.001,
                "prompt_time": 0.002,
                "completion_time": 0.003,
                "total_time": 0.006
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["content"], "hello from Groq");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 5);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(
        !doctor.to_string().contains("groq-test-key"),
        "doctor output must not leak API key"
    );
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_assembles_sse_chunks_without_prompt_logs() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("authorization", "Bearer groq-test-key"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect("stream invoke should succeed");

    assert_eq!(result["content"], "hello");
    assert_eq!(result["chunk_count"], 2);
    assert!(
        !result.to_string().contains("private prompt"),
        "stream response should not echo prompt"
    );
}

#[fcp_async_core::runtime::test]
async fn models_list_is_cached_and_health_reuses_shared_client() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openai/v1/models"))
        .and(header("authorization", "Bearer groq-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": "llama-3.1-8b-instant",
                "object": "model",
                "created": 1_693_721_698,
                "owned_by": "Meta",
                "active": true,
                "context_window": 131_072
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS, CAP_HEALTH], json!({})).await;
    let models_first = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should load");
    let models_cached = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should cache");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should use cached models");

    assert_eq!(models_first["data"][0]["id"], "llama-3.1-8b-instant");
    assert_eq!(models_cached["data"][0]["id"], "llama-3.1-8b-instant");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 1);
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .insert_header("x-ratelimit-remaining-requests", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "too fast"}
                })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-retry",
            "object": "chat.completion",
            "created": 1,
            "model": "llama-3.1-8b-instant",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "recovered"},
                "finish_reason": "stop"
            }]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) =
        configured_connector(&server, &[CAP_CHAT], json!({"wait_on_rate_limit_ms": 1000})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect("retry should recover");

    assert_eq!(result["content"], "recovered");
}

#[fcp_async_core::runtime::test]
async fn provider_errors_map_to_fcp_and_redact_sensitive_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "type": "authentication_error",
                "message": "bad Bearer should-not-leak",
                "prompt": "private prompt"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect_err("401 should fail");

    assert!(matches!(error, FcpError::Unauthorized { .. }));
    let display = error.to_string();
    assert!(!display.contains("should-not-leak"));
    assert!(!display.contains("private prompt"));
}

#[fcp_async_core::runtime::test]
async fn embeddings_are_introspection_only_and_fail_before_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        configured_connector(&server, &[CAP_EMBEDDINGS], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"model": "text-embedding", "input": "hello"}),
    )
    .await
    .expect_err("embeddings are not supported");

    assert!(matches!(error, FcpError::InvalidRequest { .. }));
    assert!(error.to_string().contains("not supported"));
}

#[fcp_async_core::runtime::test]
async fn unsupported_openai_fields_are_rejected_before_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello", "name": "operator"}],
            "logprobs": true
        }),
    )
    .await
    .expect_err("unsupported fields should fail locally");

    assert!(matches!(error, FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openai/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "llama-3.1-8b-instant", "object": "model", "owned_by": "Meta"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_MODELS, OP_MODELS);
    let response = connector
        .invoke(test_invoke_request(
            "groq-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        "llama-3.1-8b-instant"
    );
    connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            reason: Some("test".into()),
            deadline_ms: 1_000,
            drain: false,
        })
        .await
        .expect("shutdown should pass");
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.groq");
}
