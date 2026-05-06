#![allow(clippy::too_many_lines)]

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_cerebras::client::{CerebrasAuth, CerebrasProvider, normalize_cerebras_base_url};
use fcp_cerebras::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_cerebras::{CerebrasConnector, DEFAULT_MODEL};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openai_compat::{
    OpenAiCompatProvider, RateLimitConfig, header_value, parse_rate_limit_headers,
};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "cerebras.chat.completions";
const OP_CHAT_STREAM: &str = "cerebras.chat.completions_stream";
const OP_MODELS: &str = "cerebras.models.list";
const OP_HEALTH: &str = "cerebras.health";
const OP_EMBEDDINGS: &str = "cerebras.embeddings.create";
const CAP_CHAT: &str = "cerebras.chat";
const CAP_MODELS: &str = "cerebras.models.read";
const CAP_HEALTH: &str = "cerebras.health.read";
const CAP_EMBEDDINGS: &str = "cerebras.embeddings";

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
) -> (CerebrasConnector, Ed25519SigningKey) {
    let mut connector = CerebrasConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("cerebras-test-key"));
    config.insert("base_url".into(), json!(format!("{}/v1", server.uri())));
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
    connector: &CerebrasConnector,
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

#[test]
fn provider_construction_and_base_url_policy_are_strict() {
    let provider = CerebrasProvider::new(
        "https://api.cerebras.ai/v1",
        CerebrasAuth::ApiKey("secret".into()),
    );
    let mut request = fcp_openai_compat::HttpRequest::default();
    provider.auth_header(&mut request);

    assert_eq!(provider.provider_name(), "cerebras");
    assert_eq!(
        normalize_cerebras_base_url(None).unwrap(),
        "https://api.cerebras.ai/v1"
    );
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer secret")
    );
    assert!(normalize_cerebras_base_url(Some("https://api.cerebras.ai/openai/v1")).is_err());
    assert!(normalize_cerebras_base_url(Some("https://example.com/v1")).is_err());
}

#[test]
fn cerebras_rate_limit_headers_parse_documented_and_cloudflare_shapes() {
    let provider = CerebrasProvider::new(
        "https://api.cerebras.ai/v1",
        CerebrasAuth::CredentialId("cred:cerebras".into()),
    );
    let headers = vec![
        (
            "x-ratelimit-limit-requests-day".to_string(),
            "30".to_string(),
        ),
        (
            "x-ratelimit-remaining-requests-day".to_string(),
            "7".to_string(),
        ),
        (
            "x-ratelimit-reset-requests-day".to_string(),
            "0.25".to_string(),
        ),
        (
            "x-ratelimit-limit-tokens-minute".to_string(),
            "64000".to_string(),
        ),
        (
            "x-ratelimit-remaining-tokens-minute".to_string(),
            "31999".to_string(),
        ),
        (
            "x-ratelimit-reset-tokens-minute".to_string(),
            "11.5".to_string(),
        ),
    ];
    let parsed = parse_rate_limit_headers(&headers, provider.rate_limit_overrides().as_ref());
    assert_eq!(parsed.request_limit, Some(30));
    assert_eq!(parsed.request_remaining, Some(7));
    assert_eq!(parsed.request_reset_after, Some(Duration::from_millis(250)));
    assert_eq!(parsed.token_limit, Some(64_000));
    assert_eq!(parsed.token_remaining, Some(31_999));
    assert_eq!(
        parsed.token_reset_after,
        Some(Duration::from_millis(11_500))
    );

    let cloudflare_headers = vec![("cf-ratelimit-remaining".to_string(), "5".to_string())];
    let cloudflare =
        parse_rate_limit_headers(&cloudflare_headers, Some(&RateLimitConfig::default()));
    assert_eq!(cloudflare.request_remaining, Some(5));
}

#[fcp_async_core::runtime::test]
async fn chat_completions_uses_shared_oai_surface_and_redacted_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer cerebras-test-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "max_completion_tokens": 8
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-cerebras",
            "object": "chat.completion",
            "created": 1,
            "model": DEFAULT_MODEL,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from Cerebras"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 3,
                "total_tokens": 5,
                "time_info": {"total_time": 0.006}
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
            "messages": [{"role": "user", "content": "hello"}],
            "max_completion_tokens": 8
        }),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["content"], "hello from Cerebras");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 5);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(
        !doctor.to_string().contains("cerebras-test-key"),
        "doctor output must not leak API key"
    );
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_assembles_sse_chunks_without_prompt_logs() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.1-8b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"wafer\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.1-8b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" scale\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer cerebras-test-key"))
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

    assert_eq!(result["content"], "wafer scale");
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
        .and(path("/v1/models"))
        .and(header("authorization", "Bearer cerebras-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": DEFAULT_MODEL,
                "object": "model",
                "created": 1_721_692_800,
                "owned_by": "Meta"
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

    assert_eq!(models_first["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(models_cached["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 1);
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .insert_header("x-ratelimit-remaining-requests-day", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "too fast"}
                })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-retry",
            "object": "chat.completion",
            "created": 1,
            "model": DEFAULT_MODEL,
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
async fn long_completion_response_is_handled_without_prompt_leakage() {
    let server = MockServer::start().await;
    let long_text = "x".repeat(1_024);
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-long",
            "object": "chat.completion",
            "created": 1,
            "model": DEFAULT_MODEL,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": long_text},
                "finish_reason": "length"
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1024, "total_tokens": 1026}
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
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect("long response should succeed");

    assert_eq!(
        result["content"].as_str().expect("content string").len(),
        1_024
    );
    assert_eq!(result["usage"]["completion_tokens"], 1024);
    assert!(!result.to_string().contains("private prompt"));
}

#[fcp_async_core::runtime::test]
async fn provider_errors_map_to_fcp_and_redact_sensitive_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
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
async fn invalid_chat_fields_are_rejected_before_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 8,
            "max_completion_tokens": 8
        }),
    )
    .await
    .expect_err("duplicate token budgets should fail locally");

    assert!(matches!(error, FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token_and_shutdown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": DEFAULT_MODEL, "object": "model", "owned_by": "Meta"}]
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
            "cerebras-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        DEFAULT_MODEL
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

    let health = connector.health().await;
    assert!(matches!(
        health.status,
        fcp_prelude::HealthState::Error { .. }
    ));
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.cerebras");
}
