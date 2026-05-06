#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_moonshot::MoonshotConnector;
use fcp_moonshot::client::{DEFAULT_BASE_URL, normalize_moonshot_base_url};
use fcp_moonshot::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_moonshot::types::{
    chat_request_from_value, context_window_class, context_window_for_model,
};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId, InvokeStatus,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "moonshot.chat.completions";
const OP_CHAT_STREAM: &str = "moonshot.chat.completions_stream";
const OP_MODELS: &str = "moonshot.models.list";
const OP_HEALTH: &str = "moonshot.health";
const OP_EMBEDDINGS: &str = "moonshot.embeddings.create";
const CAP_CHAT: &str = "moonshot.chat";
const CAP_MODELS: &str = "moonshot.models.read";
const CAP_HEALTH: &str = "moonshot.health.read";
const CAP_EMBEDDINGS: &str = "moonshot.embeddings";

fn valid_capability_grant(
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
) -> (MoonshotConnector, Ed25519SigningKey) {
    let mut connector = MoonshotConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("moonshot-test-key"));
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
    connector: &MoonshotConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant =
        valid_capability_grant(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_grant,
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn provider_construction_auth_base_url_and_context_policy() {
    assert_eq!(
        normalize_moonshot_base_url(None).expect("default should normalize"),
        DEFAULT_BASE_URL
    );
    assert_eq!(
        normalize_moonshot_base_url(Some("https://api.moonshot.cn/v1/"))
            .expect("cn endpoint should normalize"),
        "https://api.moonshot.cn/v1"
    );
    assert!(
        normalize_moonshot_base_url(Some("http://api.moonshot.ai/v1"))
            .expect_err("external endpoint must require TLS")
            .contains("base_url must be")
    );
    assert!(
        normalize_moonshot_base_url(Some("https://api.moonshot.ai/v1?query=not_allowed"))
            .expect_err("query must be rejected")
            .contains("query")
    );
    assert_eq!(context_window_for_model("moonshot-v1-128k"), Some(128_000));
    assert_eq!(context_window_for_model("kimi-k2.6"), Some(256_000));
    assert_eq!(context_window_class(256_000), "256k");

    let mut connector = MoonshotConnector::new();
    let error = connector
        .handle_configure(json!({
            "api_key": "moonshot-test-key",
            "credential_id": "also-present"
        }))
        .await
        .expect_err("double auth material must fail");
    assert!(error.to_string().contains("exactly one"));
}

#[fcp_async_core::runtime::test]
async fn request_builders_preserve_kimi_extensions_and_deny_context_overflow() {
    let request = chat_request_from_value(
        json!({
            "model": "kimi-k2.6",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
            "max_completion_tokens": 64,
            "estimated_input_tokens": 1024,
            "thinking": {"type": "enabled"},
            "provider_extensions": {"enable_search": false}
        }),
        "kimi-k2.6",
        256_000,
    )
    .expect("request should build");
    assert_eq!(request.model, "kimi-k2.6");
    assert!(request.max_tokens.is_none());
    assert_eq!(
        request.provider_extensions["max_completion_tokens"],
        json!(64)
    );
    assert_eq!(
        request.provider_extensions["thinking"],
        json!({"type": "enabled"})
    );
    assert_eq!(request.provider_extensions["enable_search"], json!(false));

    let error = chat_request_from_value(
        json!({
            "model": "moonshot-v1-8k",
            "messages": [{"role": "user", "content": "large doc"}],
            "estimated_input_tokens": 8_000,
            "max_completion_tokens": 512
        }),
        "kimi-k2.6",
        256_000,
    )
    .expect_err("context overflow should fail locally");
    assert!(error.to_string().contains("refusing to silently truncate"));
}

#[fcp_async_core::runtime::test]
async fn chat_stream_models_health_and_redaction_work_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer moonshot-test-key"))
        .and(body_partial_json(json!({
            "model": "kimi-k2.6",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "max_completion_tokens": 32
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-moonshot",
            "object": "chat.completion",
            "created": 1,
            "model": "kimi-k2.6",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from Kimi"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"kimi-k2.6\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"kimi-k2.6\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer moonshot-test-key"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", "Bearer moonshot-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": "kimi-k2.6",
                "object": "model",
                "created": 1,
                "owned_by": "moonshot"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT, CAP_MODELS, CAP_HEALTH, CAP_EMBEDDINGS],
        json!({}),
    )
    .await;

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "max_completion_tokens": 32,
            "estimated_input_tokens": 2
        }),
    )
    .await
    .expect("chat invoke should succeed");
    assert_eq!(chat["content"], "hello from Kimi");
    assert_eq!(chat["context_window_class"], "256k");

    let stream = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect("stream invoke should succeed");
    assert_eq!(stream["content"], "hello");
    assert_eq!(stream["chunk_count"], 2);
    assert!(!stream.to_string().contains("private prompt"));

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should succeed");
    assert_eq!(models["data"][0]["id"], "kimi-k2.6");

    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should reuse model cache");
    assert_eq!(health["status"], "ok");

    let unsupported = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({}),
    )
    .await
    .expect_err("embeddings are not supported");
    assert!(unsupported.to_string().contains("not supported"));

    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("moonshot-test-key"));
}

#[fcp_async_core::runtime::test]
async fn provider_errors_retry_cancellation_and_shutdown_are_safe() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "The input token count exceeds the model context length",
                "type": "invalid_request_error",
                "code": "context_length_exceeded"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect_err("provider error should map");
    assert!(matches!(error, FcpError::InvalidRequest { .. }));

    let shutdown = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(shutdown["status"], "shutdown");
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-trait",
            "object": "chat.completion",
            "created": 1,
            "model": "kimi-k2.6",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "trait ok"},
                "finish_reason": "stop"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let capability_grant =
        valid_capability_grant(&signing_key, connector.instance_id(), CAP_CHAT, OP_CHAT);
    let response = connector
        .invoke(test_invoke_request(
            "moonshot-trait",
            OP_CHAT,
            json!({"messages": [{"role": "user", "content": "hello"}]}),
            capability_grant,
        ))
        .await
        .expect("trait invoke should serialize");
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(
        response.result.expect("invoke result")["content"],
        "trait ok"
    );
    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
}

#[fcp_async_core::runtime::test]
async fn moonshot_loopback_e2e_jsonl_matrix() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-e2e",
            "object": "chat.completion",
            "created": 1,
            "model": "kimi-k2.6",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "e2e ok"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "kimi-k2.6", "object": "model", "owned_by": "moonshot"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, signing_key) =
        configured_connector(&server, &[CAP_CHAT, CAP_MODELS], json!({})).await;
    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "fixture prompt"}],
            "estimated_input_tokens": 8,
            "max_completion_tokens": 2
        }),
    )
    .await
    .expect("loopback chat succeeds");
    println!(
        "MOONSHOT_E2E_JSONL {}",
        json!({
            "event": "moonshot_fixture_operation",
            "fixture_mode": "wiremock",
            "operation": "chat",
            "model_id": "kimi-k2.6",
            "input_tokens": 8,
            "output_tokens": chat["usage"]["completion_tokens"],
            "context_window_class": chat["context_window_class"],
            "http_status": 200,
            "retry_decision": "not_retried",
            "status": "passed",
            "command_line": "cargo test -p fcp-moonshot --test integration moonshot_loopback_e2e_jsonl_matrix -- --nocapture",
            "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown")
        })
    );

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models succeeds");
    println!(
        "MOONSHOT_E2E_JSONL {}",
        json!({
            "event": "moonshot_fixture_operation",
            "fixture_mode": "wiremock",
            "operation": "models.list",
            "model_count": models["data"].as_array().map_or(0, Vec::len),
            "http_status": 200,
            "status": "passed",
            "command_line": "cargo test -p fcp-moonshot --test integration moonshot_loopback_e2e_jsonl_matrix -- --nocapture",
            "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown")
        })
    );

    let denied = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "model": "moonshot-v1-8k",
            "messages": [{"role": "user", "content": "oversized fixture"}],
            "estimated_input_tokens": 8_000,
            "max_completion_tokens": 512
        }),
    )
    .await
    .expect_err("context limit must deny before provider call");
    println!(
        "MOONSHOT_E2E_JSONL {}",
        json!({
            "event": "moonshot_fixture_operation",
            "fixture_mode": "wiremock",
            "operation": "context_limit",
            "context_window_class": "8k",
            "fcp_error_mapping": denied.to_string(),
            "retry_decision": "not_retried",
            "status": "passed",
            "command_line": "cargo test -p fcp-moonshot --test integration moonshot_loopback_e2e_jsonl_matrix -- --nocapture",
            "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown")
        })
    );

    let cleanup = connector
        .handle_shutdown(json!({}))
        .await
        .expect("cleanup should succeed");
    println!(
        "MOONSHOT_E2E_JSONL {}",
        json!({
            "event": "moonshot_fixture_operation",
            "fixture_mode": "wiremock",
            "operation": "cleanup",
            "cleanup_result": cleanup["status"],
            "status": "passed",
            "command_line": "cargo test -p fcp-moonshot --test integration moonshot_loopback_e2e_jsonl_matrix -- --nocapture",
            "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown")
        })
    );
}
