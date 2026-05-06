#![allow(clippy::too_many_lines)]

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_glm::client::{
    GlmAuth, GlmJwtAuth, GlmProvider, generate_glm_jwt as make_bearer_token,
    normalize_glm_base_url, split_bigmodel_api_key,
};
use fcp_glm::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_glm::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, GlmConnector};
use fcp_openai_compat::{OpenAiCompatProvider, header_value};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "glm.chat.completions";
const OP_CHAT_STREAM: &str = "glm.chat.completions_stream";
const OP_EMBEDDINGS: &str = "glm.embeddings.create";
const OP_MODELS: &str = "glm.models.list";
const OP_HEALTH: &str = "glm.health";
const CAP_CHAT: &str = "glm.chat";
const CAP_EMBEDDINGS: &str = "glm.embeddings";
const CAP_MODELS: &str = "glm.models.read";
const CAP_HEALTH: &str = "glm.health.read";

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
) -> (GlmConnector, Ed25519SigningKey) {
    let mut connector = GlmConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("glm-test-key"));
    config.insert(
        "base_url".into(),
        json!(format!("{}/api/paas/v4", server.uri())),
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
    connector: &GlmConnector,
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
fn provider_construction_base_url_and_jwt_golden_vector() {
    let provider = GlmProvider::new(
        "https://open.bigmodel.cn/api/paas/v4",
        GlmAuth::ApiKey("direct-key".into()),
    );
    let mut request = fcp_openai_compat::HttpRequest::default();
    provider.auth_header(&mut request);

    assert_eq!(provider.provider_name(), "glm");
    assert_eq!(
        normalize_glm_base_url(None).unwrap(),
        "https://open.bigmodel.cn/api/paas/v4"
    );
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer direct-key")
    );
    assert!(normalize_glm_base_url(Some("https://open.bigmodel.cn/v1")).is_err());
    assert!(normalize_glm_base_url(Some("https://example.com/api/paas/v4")).is_err());

    let jwt_value = make_bearer_token(
        "id",
        &jwt_test_material(),
        1_700_000_000_000,
        Duration::from_secs(60),
    )
    .expect("jwt signs");
    assert_eq!(
        jwt_value,
        "eyJhbGciOiJIUzI1NiIsInNpZ25fdHlwZSI6IlNJR04ifQ.eyJhcGlfa2V5IjoiaWQiLCJleHAiOjE3MDAwMDAwNjAwMDAsInRpbWVzdGFtcCI6MTcwMDAwMDAwMDAwMH0.6rfOn0rvWaPHi0p6PiygbsFlf_e0XtYfkyT3b_e8yzk"
    );
    assert_eq!(
        split_bigmodel_api_key(&format!("id.{}", jwt_test_material())).expect("split key"),
        ("id".to_string(), jwt_test_material())
    );
}

fn jwt_test_material() -> String {
    ["signing", "material"].join("-")
}

#[test]
fn jwt_cache_reuses_token_then_refreshes_near_expiry() {
    let jwt = GlmJwtAuth::new("id", jwt_test_material(), Duration::from_secs(60));
    let first = jwt.token_at(1_700_000_000_000);
    let cached = jwt.token_at(1_700_000_010_000);
    let refreshed = jwt.token_at(1_700_000_056_000);

    assert_eq!(first, cached);
    assert_ne!(first, refreshed);
}

#[fcp_async_core::runtime::test]
async fn chat_completions_uses_bigmodel_path_and_redacts_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/paas/v4/chat/completions"))
        .and(header("authorization", "Bearer glm-test-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "max_tokens": 8
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-glm",
            "object": "chat.completion",
            "created": 1,
            "model": DEFAULT_MODEL,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from GLM"},
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
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 8
        }),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["content"], "hello from GLM");
    assert_eq!(result["usage"]["total_tokens"], 5);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(
        !doctor.to_string().contains("glm-test-key"),
        "doctor output must not leak API key"
    );
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_assembles_sse_chunks_without_prompt_logs() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"glm-5.1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ni\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"glm-5.1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" hao\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/api/paas/v4/chat/completions"))
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

    assert_eq!(result["content"], "ni hao");
    assert_eq!(result["chunk_count"], 2);
    assert!(!result.to_string().contains("private prompt"));
}

#[fcp_async_core::runtime::test]
async fn embeddings_request_uses_documented_embedding_surface() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/paas/v4/embeddings"))
        .and(header("authorization", "Bearer glm-test-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input": "hello",
            "dimensions": 2
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "object": "list",
            "data": [{
                "index": 0,
                "object": "embedding",
                "embedding": [0.1, 0.2]
            }],
            "usage": {"prompt_tokens": 1, "total_tokens": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) =
        configured_connector(&server, &[CAP_EMBEDDINGS], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "hello", "dimensions": 2}),
    )
    .await
    .expect("embeddings should succeed");

    assert_eq!(result["model"], DEFAULT_EMBEDDING_MODEL);
    let first = result["data"][0]["embedding"][0]
        .as_f64()
        .expect("first embedding value should be numeric");
    assert!((first - 0.1).abs() < 0.000_001);
}

#[fcp_async_core::runtime::test]
async fn static_models_list_and_health_are_prompt_free() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS, CAP_HEALTH], json!({})).await;
    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should load");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should load");

    assert_eq!(models["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(models["source"], "documented_static_catalog");
    assert_eq!(health["status"], "ok");
    assert!(
        !health.to_string().contains("prompt"),
        "health must not include prompt data"
    );
}

#[fcp_async_core::runtime::test]
async fn glm_rate_limit_error_code_maps_to_fcp_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/paas/v4/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_json(json!({
                    "error": {"code": "1302", "message": "too many requests with credential token and prompt"}
                })),
        )
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
    .expect_err("429 should fail");

    assert!(matches!(error, FcpError::RateLimited { .. }));
    assert!(!error.to_string().contains("sk-test"));
}

#[fcp_async_core::runtime::test]
async fn invalid_chat_and_embedding_fields_are_rejected_before_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        configured_connector(&server, &[CAP_CHAT, CAP_EMBEDDINGS], json!({})).await;

    let chat_error = invoke(
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
    assert!(matches!(chat_error, FcpError::InvalidRequest { .. }));

    let embedding_error = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "", "dimensions": 0}),
    )
    .await
    .expect_err("invalid embedding input should fail locally");
    assert!(matches!(embedding_error, FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token_and_shutdown() {
    let server = MockServer::start().await;
    let (mut connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_MODELS, OP_MODELS);
    let response = connector
        .invoke(test_invoke_request(
            "glm-models-suite",
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
    assert_eq!(CONNECTOR_ID, "fcp.glm");
}
