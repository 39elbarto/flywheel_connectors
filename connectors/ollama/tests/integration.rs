#![allow(clippy::too_many_lines)]

use std::net::{SocketAddr, TcpStream};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::Cx;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_ollama::client::{
    DEFAULT_BASE_URL, DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, OllamaAuth, OllamaClient,
    OllamaProvider, OllamaUrlPolicy, classify_ollama_base_url, normalize_ollama_base_url,
};
use fcp_ollama::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_ollama::types::{
    chat_request_from_value, embeddings_request_from_value, validate_ollama_model_id,
};
use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, EmbeddingInput, HttpRequest, OpenAiCompatProvider,
    RateLimitPolicy, header_value,
};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "ollama.chat.completions";
const OP_CHAT_STREAM: &str = "ollama.chat.completions_stream";
const OP_EMBEDDINGS: &str = "ollama.embeddings.create";
const OP_MODELS: &str = "ollama.models.list";
const OP_HEALTH: &str = "ollama.health";

const CAP_CHAT: &str = "ollama.chat";
const CAP_EMBEDDINGS: &str = "ollama.embeddings";
const CAP_MODELS: &str = "ollama.models.read";
const CAP_HEALTH: &str = "ollama.health.read";

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
        .zone_id("z:owner")
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
) -> (fcp_ollama::OllamaConnector, Ed25519SigningKey) {
    let mut connector = fcp_ollama::OllamaConnector::new();
    let mut config = serde_json::Map::new();
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
    connector: &fcp_ollama::OllamaConnector,
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
fn provider_construction_optional_auth_base_url_and_model_policy() {
    let provider = OllamaProvider::new(DEFAULT_BASE_URL, OllamaAuth::None);
    let mut request = HttpRequest::default();
    provider.auth_header(&mut request);
    assert!(request.headers.is_empty());
    assert_eq!(provider.provider_name(), "ollama");

    let api_key_provider =
        OllamaProvider::new(DEFAULT_BASE_URL, OllamaAuth::ApiKey("ollama-key".into()));
    let mut api_key_request = HttpRequest::default();
    api_key_provider.auth_header(&mut api_key_request);
    assert_eq!(
        header_value(&api_key_request.headers, "authorization"),
        Some("Bearer ollama-key")
    );

    let credential_provider = OllamaProvider::new(
        DEFAULT_BASE_URL,
        OllamaAuth::CredentialId("cred:ollama".into()),
    );
    let mut credential_request = HttpRequest::default();
    credential_provider.auth_header(&mut credential_request);
    assert_eq!(
        header_value(&credential_request.headers, "x-fcp-credential-id"),
        Some("cred:ollama")
    );

    let default_policy = OllamaUrlPolicy::default();
    assert_eq!(
        normalize_ollama_base_url(None, &default_policy).unwrap(),
        DEFAULT_BASE_URL
    );
    assert!(normalize_ollama_base_url(Some("https://api.openai.com/v1"), &default_policy).is_err());
    assert!(
        normalize_ollama_base_url(Some("http://localhost:11434/api"), &default_policy).is_err()
    );

    let allowed = OllamaUrlPolicy::new(false, vec!["ollama.tailnet.ts.net".into()]);
    assert_eq!(
        normalize_ollama_base_url(Some("https://ollama.tailnet.ts.net/v1"), &allowed).unwrap(),
        "https://ollama.tailnet.ts.net/v1"
    );
    let tailnet_only = OllamaUrlPolicy::new(true, vec!["ollama.tailnet.ts.net".into()]);
    assert!(normalize_ollama_base_url(None, &tailnet_only).is_err());
    assert_eq!(
        classify_ollama_base_url("https://ollama.tailnet.ts.net/v1"),
        "tailnet_dns"
    );
    assert!(validate_ollama_model_id("model", DEFAULT_MODEL).is_ok());
    assert!(validate_ollama_model_id("model", "qwen2.5:0.5b").is_ok());
    assert!(validate_ollama_model_id("model", "model with spaces").is_err());
}

#[test]
fn request_builders_validate_chat_embeddings_and_ollama_extensions() {
    let chat = chat_request_from_value(
        json!({
            "messages": [{"role": "user", "content": "private prompt"}],
            "format": "json",
            "keep_alive": "5m"
        }),
        DEFAULT_MODEL,
    )
    .expect("chat request should parse");
    assert_eq!(chat.model, DEFAULT_MODEL);
    assert_eq!(chat.provider_extensions["format"], "json");
    assert_eq!(chat.provider_extensions["keep_alive"], "5m");

    assert!(
        chat_request_from_value(
            json!({
                "model": "bad model",
                "messages": [{"role": "user", "content": "hello"}]
            }),
            DEFAULT_MODEL,
        )
        .is_err()
    );
    assert!(chat_request_from_value(json!({"messages": []}), DEFAULT_MODEL).is_err());

    let embeddings = embeddings_request_from_value(
        json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input": ["doc one", "doc two"],
            "encoding_format": "float"
        }),
        DEFAULT_EMBEDDING_MODEL,
    )
    .expect("embeddings request should parse");
    assert_eq!(
        embeddings.input,
        EmbeddingInput::Batch(vec!["doc one".into(), "doc two".into()])
    );
    assert!(embeddings_request_from_value(json!({"input": ""}), DEFAULT_EMBEDDING_MODEL).is_err());
}

#[fcp_async_core::runtime::test]
async fn chat_stream_embeddings_models_health_and_redaction_work_through_connector() {
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, 1).await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({
            "model": DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "format": "json"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_body("fixture-response")))
        .expect(1)
        .mount(&server)
        .await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(body_partial_json(json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input": "private embedding input"
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, 3)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT, CAP_EMBEDDINGS, CAP_MODELS, CAP_HEALTH],
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
            "format": "json"
        }),
    )
    .await
    .expect("chat should succeed");
    let stream = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private stream prompt"}]}),
    )
    .await
    .expect("stream should succeed");
    let embeddings = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "private embedding input"}),
    )
    .await
    .expect("embeddings should succeed");
    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should succeed");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should reuse cached models");

    assert_eq!(chat["content"], "fixture-response");
    assert_eq!(stream["content"], "hello");
    assert_eq!(stream["chunk_count"], 2);
    assert_eq!(embeddings["dimensions"], 3);
    assert_eq!(models["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(models["base_url_class"], "loopback");
    assert_eq!(health["status"], "ok");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("private stream prompt"));
    assert!(!doctor.to_string().contains("private embedding input"));
    assert!(!stream.to_string().contains("private stream prompt"));
}

#[fcp_async_core::runtime::test]
async fn auth_required_tailnet_policy_rate_limit_cancellation_and_shutdown_are_safe() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer ollama-proxy-key"))
        .and(body_partial_json(json!({"fixture_case": "rate_limit"})))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(
                    json!({"error": {"type": "rate_limit_error", "message": "slow down"}}),
                ),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "rate_limit"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_body("recovered")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "provider_error"})))
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

    let (mut connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT],
        json!({"api_key": "ollama-proxy-key", "wait_on_rate_limit_ms": 1000}),
    )
    .await;
    let recovered = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "provider_extensions": {"fixture_case": "rate_limit"}
        }),
    )
    .await
    .expect("retry should recover");
    assert_eq!(recovered["content"], "recovered");

    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "provider_extensions": {"fixture_case": "provider_error"}
        }),
    )
    .await
    .expect_err("401 should fail");
    assert!(matches!(error, FcpError::Unauthorized { .. }));
    assert!(!error.to_string().contains("should-not-leak"));
    assert!(!error.to_string().contains("private prompt"));

    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let client = OllamaClient::new(
        OllamaProvider::new(format!("{}/v1", server.uri()), OllamaAuth::None),
        StdDuration::from_secs(5),
        StdDuration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let cancelled = client
        .chat_completions(
            &cx,
            ChatCompletionsRequest::new(DEFAULT_MODEL, vec![ChatMessage::user_text("hello")]),
        )
        .await
        .expect_err("cancelled context should fail before dispatch");
    assert!(cancelled.to_string().contains("cancelled"));

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should pass");
    let health = connector
        .handle_health()
        .await
        .expect("health should serialize");
    assert_eq!(health["configured"], false);
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token() {
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, 1).await;

    let (mut connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_MODELS, OP_MODELS);
    let response = connector
        .invoke(test_invoke_request(
            "ollama-models-suite",
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
}

#[fcp_async_core::runtime::test]
async fn ollama_loopback_e2e_jsonl_matrix() {
    let git_revision =
        std::env::var("OLLAMA_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, 1).await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "jsonl_chat"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_body("jsonl-ok")))
        .mount(&server)
        .await;
    let sse = concat!(
        "data: {\"id\":\"chunk-a\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "jsonl_stream"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, 4)),
        )
        .mount(&server)
        .await;

    let (mut connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT, CAP_EMBEDDINGS, CAP_MODELS, CAP_HEALTH],
        json!({"wait_on_rate_limit_ms": 1000}),
    )
    .await;

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "private jsonl prompt"}],
            "provider_extensions": {"fixture_case": "jsonl_chat"}
        }),
    )
    .await
    .expect("jsonl chat should pass");
    emit_jsonl(
        &git_revision,
        "chat",
        "wiremock",
        "passed",
        json!({
            "base_url_class": "loopback",
            "zone_choice": "z:owner",
            "model_id_hash": blake3::hash(DEFAULT_MODEL.as_bytes()).to_hex().to_string(),
            "completion_bytes": chat["content"].as_str().unwrap_or_default().len(),
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let stream = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "private jsonl stream prompt"}],
            "provider_extensions": {"fixture_case": "jsonl_stream"}
        }),
    )
    .await
    .expect("jsonl stream should pass");
    emit_jsonl(
        &git_revision,
        "stream",
        "wiremock",
        "passed",
        json!({
            "base_url_class": "loopback",
            "stream_chunk_count": stream["chunk_count"],
            "completion_bytes": stream["content"].as_str().unwrap_or_default().len(),
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let embeddings = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "private jsonl embedding input"}),
    )
    .await
    .expect("jsonl embeddings should pass");
    emit_jsonl(
        &git_revision,
        "embeddings",
        "wiremock",
        "passed",
        json!({
            "base_url_class": "loopback",
            "model_id_hash": blake3::hash(DEFAULT_EMBEDDING_MODEL.as_bytes()).to_hex().to_string(),
            "embedding_dimensions": embeddings["dimensions"],
            "data_count": embeddings["data_count"],
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("jsonl models should pass");
    emit_jsonl(
        &git_revision,
        "models.list",
        "wiremock",
        "passed",
        json!({
            "base_url_class": "loopback",
            "model_count": models["data"].as_array().map(Vec::len).unwrap_or_default(),
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let cancelled = OllamaClient::new(
        OllamaProvider::new(format!("{}/v1", server.uri()), OllamaAuth::None),
        StdDuration::from_secs(5),
        StdDuration::from_secs(60),
        RateLimitPolicy::FailFast,
    )
    .chat_completions(
        &cx,
        ChatCompletionsRequest::new(DEFAULT_MODEL, vec![ChatMessage::user_text("private")]),
    )
    .await
    .expect_err("cancelled context should fail");
    emit_jsonl(
        &git_revision,
        "cancellation",
        "wiremock",
        "passed",
        json!({
            "base_url_class": "loopback",
            "fcp_error_mapping": cancelled.to_string(),
            "retry_decision": "not_retried"
        }),
    );

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should pass");
    emit_jsonl(
        &git_revision,
        "cleanup",
        "wiremock",
        "passed",
        json!({
            "cleanup_result": "shutdown"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn ollama_local_smoke_or_structured_skip_jsonl() {
    let git_revision =
        std::env::var("OLLAMA_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let base_url = std::env::var("OLLAMA_E2E_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.into());
    let model = std::env::var("OLLAMA_E2E_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());

    if base_url == DEFAULT_BASE_URL && !localhost_ollama_listens() {
        emit_jsonl(
            &git_revision,
            "local_smoke",
            "local",
            "skipped",
            json!({
                "base_url_class": "loopback",
                "skip_reason": "Ollama is not listening on 127.0.0.1:11434",
                "cleanup_result": "not_started_by_test"
            }),
        );
        return;
    }

    let mut connector = fcp_ollama::OllamaConnector::new();
    let configure = connector
        .handle_configure(json!({
            "base_url": base_url,
            "default_model": model,
            "request_timeout_ms": 30_000
        }))
        .await;
    let Ok(configure) = configure else {
        emit_jsonl(
            &git_revision,
            "local_smoke",
            "local",
            "skipped",
            json!({
                "base_url_class": "invalid",
                "skip_reason": "OLLAMA_E2E_BASE_URL failed connector base_url policy",
                "cleanup_result": "not_started_by_test"
            }),
        );
        return;
    };
    let configured_base_url_class = configure["base_url_class"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(test_handshake_request(
            vec![
                CapabilityId::from_static(CAP_MODELS),
                CapabilityId::from_static(CAP_CHAT),
            ],
            verifying_key.to_bytes(),
        ))
        .await
        .expect("handshake should succeed");
    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({})).await;
    match models {
        Ok(models) => {
            let model_present = models["data"].as_array().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry["id"].as_str().is_some_and(|id| id == model))
            });
            emit_jsonl(
                &git_revision,
                "local_models.list",
                "local",
                "passed",
                json!({
                    "base_url_class": configured_base_url_class,
                    "model_count": models["data"].as_array().map(Vec::len).unwrap_or_default(),
                    "model_id_hash": blake3::hash(model.as_bytes()).to_hex().to_string(),
                    "http_status": 200,
                    "cleanup_result": "probe_continues_if_model_present"
                }),
            );
            if model_present {
                match invoke(
                    &connector,
                    &signing_key,
                    OP_CHAT,
                    CAP_CHAT,
                    json!({
                        "model": model,
                        "messages": [{"role": "user", "content": "Return one short word."}],
                        "max_tokens": 2
                    }),
                )
                .await
                {
                    Ok(chat) => emit_jsonl(
                        &git_revision,
                        "local_chat",
                        "local",
                        "passed",
                        json!({
                            "base_url_class": configured_base_url_class,
                            "model_id_hash": blake3::hash(model.as_bytes()).to_hex().to_string(),
                            "completion_bytes": chat["content"].as_str().unwrap_or_default().len(),
                            "http_status": 200,
                            "cleanup_result": "shutdown_after_probe"
                        }),
                    ),
                    Err(error) => emit_jsonl(
                        &git_revision,
                        "local_chat",
                        "local",
                        "skipped",
                        json!({
                            "base_url_class": configured_base_url_class,
                            "model_id_hash": blake3::hash(model.as_bytes()).to_hex().to_string(),
                            "skip_reason": error.to_string(),
                            "cleanup_result": "shutdown_after_probe"
                        }),
                    ),
                }
            } else {
                emit_jsonl(
                    &git_revision,
                    "local_chat",
                    "local",
                    "skipped",
                    json!({
                        "base_url_class": configured_base_url_class,
                        "model_id_hash": blake3::hash(model.as_bytes()).to_hex().to_string(),
                        "skip_reason": "configured model is not installed; connector does not auto-pull models",
                        "cleanup_result": "shutdown_after_probe"
                    }),
                );
            }
        }
        Err(error) => emit_jsonl(
            &git_revision,
            "local_models.list",
            "local",
            "skipped",
            json!({
                "base_url_class": configured_base_url_class,
                "skip_reason": error.to_string(),
                "cleanup_result": "shutdown_after_probe"
            }),
        ),
    }
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should pass");
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.ollama");
}

async fn mount_models(server: &MockServer, model: &str, expected_calls: u64) {
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": model,
                "object": "model",
                "owned_by": "local",
                "created": 1_693_721_698
            }]
        })))
        .expect(expected_calls)
        .mount(server)
        .await;
}

fn chat_body(content: &str) -> Value {
    json!({
        "id": "chatcmpl-ollama",
        "object": "chat.completion",
        "created": 1,
        "model": DEFAULT_MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
    })
}

fn embedding_body(model: &str, dimensions: usize) -> Value {
    json!({
        "object": "list",
        "model": model,
        "data": [{
            "object": "embedding",
            "index": 0,
            "embedding": vec![0.1_f32; dimensions]
        }],
        "usage": {"prompt_tokens": 2, "total_tokens": 2}
    })
}

#[allow(clippy::needless_pass_by_value)]
fn emit_jsonl(
    git_revision: &str,
    operation: &str,
    fixture_mode: &str,
    status: &str,
    fields: Value,
) {
    let mut record = serde_json::Map::new();
    record.insert("event".into(), json!("ollama_fixture_operation"));
    record.insert("git_revision".into(), json!(git_revision));
    record.insert("fixture_mode".into(), json!(fixture_mode));
    record.insert("operation".into(), json!(operation));
    record.insert("status".into(), json!(status));
    record.insert(
        "command_line".into(),
        json!("cargo test -p fcp-ollama --test integration ollama_loopback_e2e_jsonl_matrix -- --nocapture"),
    );
    if let Some(fields) = fields.as_object() {
        for (key, value) in fields {
            record.insert(key.clone(), value.clone());
        }
    }
    println!("OLLAMA_E2E_JSONL {}", Value::Object(record));
}

fn localhost_ollama_listens() -> bool {
    let addr: SocketAddr = "127.0.0.1:11434"
        .parse()
        .expect("static socket addr parses");
    TcpStream::connect_timeout(&addr, StdDuration::from_millis(250)).is_ok()
}
