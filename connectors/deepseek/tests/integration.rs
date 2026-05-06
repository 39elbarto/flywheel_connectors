#![allow(clippy::too_many_lines)]

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_deepseek::DeepSeekConnector;
use fcp_deepseek::client::{DeepSeekAuth, DeepSeekProvider, normalize_deepseek_base_url};
use fcp_deepseek::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_openai_compat::{OpenAiCompatProvider, header_value, redact_sensitive_text};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "deepseek.chat.completions";
const OP_CHAT_STREAM: &str = "deepseek.chat.completions_stream";
const OP_MODELS: &str = "deepseek.models.list";
const OP_HEALTH: &str = "deepseek.health";
const OP_EMBEDDINGS: &str = "deepseek.embeddings.create";
const CAP_CHAT: &str = "deepseek.chat";
const CAP_MODELS: &str = "deepseek.models.read";
const CAP_HEALTH: &str = "deepseek.health.read";
const CAP_EMBEDDINGS: &str = "deepseek.embeddings";

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
) -> (DeepSeekConnector, Ed25519SigningKey) {
    let mut connector = DeepSeekConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("deepseek-test-key"));
    config.insert("base_url".into(), json!(server.uri()));
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
    connector: &DeepSeekConnector,
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

fn emit_fixture(event: &str, payload: &Value) {
    let mut object = serde_json::Map::new();
    object.insert("event".into(), json!(event));
    object.insert("connector".into(), json!("fcp-deepseek"));
    object.insert("fixture_mode".into(), json!("wiremock"));
    object.insert(
        "git_revision".into(),
        json!(option_env!("GIT_REVISION").unwrap_or("unknown")),
    );
    object.insert(
        "command_line".into(),
        json!(std::env::args().collect::<Vec<_>>().join(" ")),
    );
    if let Some(payload) = payload.as_object() {
        for (key, value) in payload {
            object.insert(key.clone(), value.clone());
        }
    }
    eprintln!("DEEPSEEK_FIXTURE_JSONL {}", Value::Object(object));
}

#[test]
fn provider_construction_base_url_and_auth_policy() {
    let provider = DeepSeekProvider::new(
        "https://api.deepseek.com",
        DeepSeekAuth::ApiKey("direct-key".into()),
    );
    let mut request = fcp_openai_compat::HttpRequest::default();
    provider.auth_header(&mut request);

    assert_eq!(provider.provider_name(), "deepseek");
    assert_eq!(
        normalize_deepseek_base_url(None).unwrap(),
        "https://api.deepseek.com"
    );
    assert_eq!(
        normalize_deepseek_base_url(Some("https://api.deepseek.com/v1")).unwrap(),
        "https://api.deepseek.com/v1"
    );
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer direct-key")
    );
    assert!(normalize_deepseek_base_url(Some("https://example.com")).is_err());
    assert!(normalize_deepseek_base_url(Some("http://api.deepseek.com")).is_err());
}

#[fcp_async_core::runtime::test]
async fn chat_completions_v4_flash_without_reasoning_content() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer deepseek-test-key"))
        .and(body_partial_json(json!({
            "model": "deepseek-v4-flash",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "thinking": {"type": "disabled"}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-deepseek-v4-flash",
            "object": "chat.completion",
            "created": 1,
            "model": "deepseek-v4-flash",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from DeepSeek"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
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
        json!({
            "model": "deepseek-v4-flash",
            "messages": [{"role": "user", "content": "hello"}],
            "thinking": {"type": "disabled"}
        }),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["content"], "hello from DeepSeek");
    assert!(result["reasoning_content"].is_null());
    assert_eq!(result["reasoning_content_bytes"], 0);
    assert_eq!(result["usage"]["total_tokens"], 5);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("deepseek-test-key"));
    emit_fixture(
        "chat_v4_flash_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-flash",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": 0,
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn chat_completions_reasoning_content_stays_separate_for_v4_pro() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer deepseek-test-key"))
        .and(body_partial_json(json!({
            "model": "deepseek-v4-pro",
            "reasoning_effort": "high",
            "thinking": {"type": "enabled"}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-deepseek-v4-pro",
            "object": "chat.completion",
            "created": 1,
            "model": "deepseek-v4-pro",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "reasoning_content": "private reasoning",
                    "content": "final answer"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 3,
                "completion_tokens": 4,
                "total_tokens": 7,
                "completion_tokens_details": {"reasoning_tokens": 2}
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
        json!({
            "messages": [{"role": "user", "content": "reason briefly"}],
            "thinking": {"type": "enabled"},
            "reasoning_effort": "high"
        }),
    )
    .await
    .expect("reasoning chat should succeed");

    assert_eq!(result["content"], "final answer");
    assert_eq!(result["reasoning_content"], "private reasoning");
    assert_eq!(result["content_bytes"], 12);
    assert_eq!(result["reasoning_content_bytes"], 17);
    assert!(!result.to_string().contains("reason briefly"));
    emit_fixture(
        "chat_reasoning_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": 0,
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_assembles_reasoning_and_final_content_separately() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"private \"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"trace\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-3\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"final\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-4\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" answer\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
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

    assert_eq!(result["content"], "final answer");
    assert_eq!(result["reasoning_content"], "private trace");
    assert_eq!(result["chunk_count"], 4);
    assert!(
        !result["chunks"].to_string().contains("private trace"),
        "chunk metadata must only log byte counts"
    );
    assert!(!result.to_string().contains("private prompt"));
    emit_fixture(
        "chat_stream_reasoning_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT_STREAM,
            "model_id": "deepseek-v4-pro",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": result["chunk_count"],
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn models_list_is_cached_and_health_reuses_shared_client() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("authorization", "Bearer deepseek-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": "deepseek-v4-flash", "object": "model", "owned_by": "deepseek"},
                {"id": "deepseek-v4-pro", "object": "model", "owned_by": "deepseek"}
            ]
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

    assert_eq!(models_first["data"][0]["id"], "deepseek-v4-flash");
    assert_eq!(models_cached["data"][1]["id"], "deepseek-v4-pro");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 2);
    emit_fixture(
        "models_list_fixture",
        &json!({
            "status": "passed",
            "operation": OP_MODELS,
            "model_id": "deepseek-v4-flash,deepseek-v4-pro",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": 200,
            "retry_decision": "cache-hit-after-miss",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "too fast"}
                })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-retry",
            "object": "chat.completion",
            "created": 1,
            "model": "deepseek-v4-flash",
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
    emit_fixture(
        "rate_limit_retry_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": 0,
            "http_status": 429,
            "retry_decision": "retry-after-zero-once",
            "error_mapping": "rate_limit",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn provider_errors_map_to_fcp_and_redact_reasoning_content() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "type": "authentication_error",
                "message": "bad Bearer should-not-leak",
                "prompt": "private prompt",
                "reasoning_content": "private reasoning"
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
    assert!(!display.contains("private reasoning"));
    assert!(
        !redact_sensitive_text(r#"{"reasoning_content":"private reasoning"}"#)
            .contains("private reasoning")
    );
    emit_fixture(
        "provider_error_redaction_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": 401,
            "retry_decision": "none",
            "error_mapping": "unauthorized-redacted",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn request_timeout_maps_to_retryable_external_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(500))
                .set_body_json(json!({
                    "id": "late",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "deepseek-v4-pro",
                    "choices": []
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) =
        configured_connector(&server, &[CAP_CHAT], json!({"request_timeout_ms": 100})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect_err("timeout should fail");

    assert!(matches!(error, FcpError::External { .. }));
    emit_fixture(
        "timeout_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": "timeout",
            "retry_decision": "retryable-external",
            "error_mapping": "timeout",
            "cleanup_result": "wiremock-dropped"
        }),
    );
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
    emit_fixture(
        "embeddings_not_supported_fixture",
        &json!({
            "status": "passed",
            "operation": OP_EMBEDDINGS,
            "model_id": "n/a",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": "not_dispatched",
            "retry_decision": "none",
            "error_mapping": "not_supported",
            "cleanup_result": "no-http-request"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "deepseek-v4-pro", "object": "model", "owned_by": "deepseek"}]
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
            "deepseek-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        "deepseek-v4-pro"
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
    assert_eq!(CONNECTOR_ID, "fcp.deepseek");
}
