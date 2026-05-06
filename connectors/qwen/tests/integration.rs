#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::Cx;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ContentPart, ContentParts, EmbeddingInput, HttpRequest,
    ImageUrl, OpenAiCompatProvider, RateLimitPolicy, header_value,
};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use fcp_qwen::client::{
    BEIJING_BASE_URL, DEFAULT_BASE_URL, DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL,
    DEFAULT_VISION_MODEL, QwenAuth, QwenClient, QwenProvider, normalize_qwen_base_url,
};
use fcp_qwen::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_qwen::types::{
    chat_request_from_value, embeddings_request_from_value, validate_qwen_model_id,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "qwen.chat.completions";
const OP_CHAT_STREAM: &str = "qwen.chat.completions_stream";
const OP_EMBEDDINGS: &str = "qwen.embeddings.create";
const OP_MODELS: &str = "qwen.models.list";
const OP_HEALTH: &str = "qwen.health";

const CAP_CHAT: &str = "qwen.chat";
const CAP_EMBEDDINGS: &str = "qwen.embeddings";
const CAP_MODELS: &str = "qwen.models.read";
const CAP_HEALTH: &str = "qwen.health.read";

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
) -> (fcp_qwen::QwenConnector, Ed25519SigningKey) {
    let mut connector = fcp_qwen::QwenConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("qwen-test-key"));
    config.insert(
        "base_url".into(),
        json!(format!("{}/compatible-mode/v1", server.uri())),
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
    connector: &fcp_qwen::QwenConnector,
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
fn provider_construction_auth_base_url_and_model_id_policy() {
    let provider = QwenProvider::new(DEFAULT_BASE_URL, QwenAuth::ApiKey("dashscope-key".into()));
    let mut request = HttpRequest::default();
    provider.auth_header(&mut request);
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer dashscope-key")
    );
    assert_eq!(provider.provider_name(), "qwen");
    assert_eq!(normalize_qwen_base_url(None).unwrap(), DEFAULT_BASE_URL);
    assert_eq!(
        normalize_qwen_base_url(Some(BEIJING_BASE_URL)).unwrap(),
        BEIJING_BASE_URL
    );
    assert!(normalize_qwen_base_url(Some("https://dashscope.aliyuncs.com/v1")).is_err());
    assert!(normalize_qwen_base_url(Some("https://example.com/compatible-mode/v1")).is_err());

    let credential_provider =
        QwenProvider::new(DEFAULT_BASE_URL, QwenAuth::CredentialId("cred:qwen".into()));
    let mut credential_request = HttpRequest::default();
    credential_provider.auth_header(&mut credential_request);
    assert_eq!(
        header_value(&credential_request.headers, "x-fcp-credential-id"),
        Some("cred:qwen")
    );

    assert!(validate_qwen_model_id("model", DEFAULT_MODEL).is_ok());
    assert!(validate_qwen_model_id("model", "qwen3-vl-plus").is_ok());
    assert!(validate_qwen_model_id("model", "qwen plus").is_err());
    assert!(validate_qwen_model_id("model", "qwen\nplus").is_err());
}

#[test]
fn request_builders_validate_text_embeddings_and_qwen_vl_image_blocks() {
    let text = chat_request_from_value(
        json!({
            "messages": [{"role": "user", "content": "private prompt"}],
            "max_completion_tokens": 16
        }),
        DEFAULT_MODEL,
        DEFAULT_VISION_MODEL,
    )
    .expect("chat request should parse");
    assert_eq!(text.model, DEFAULT_MODEL);
    assert_eq!(text.max_tokens, Some(16));

    let multimodal = chat_request_from_value(
        json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this image."},
                    {"type": "image_url", "image_url": {"url": "https://example.com/dog.png"}}
                ]
            }]
        }),
        DEFAULT_MODEL,
        DEFAULT_VISION_MODEL,
    )
    .expect("Qwen-VL image_url request should parse");
    assert_eq!(multimodal.model, DEFAULT_VISION_MODEL);
    assert_eq!(
        multimodal.messages,
        vec![ChatMessage::User {
            content: ContentParts::Multimodal(vec![
                ContentPart::Text {
                    text: "Describe this image.".into()
                },
                ContentPart::ImageUrl {
                    image_url: ImageUrl {
                        url: "https://example.com/dog.png".into(),
                        detail: None
                    }
                }
            ]),
            name: None
        }]
    );

    assert!(
        chat_request_from_value(
            json!({
                "model": DEFAULT_MODEL,
                "messages": [{
                    "role": "user",
                    "content": [{"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}]
                }]
            }),
            DEFAULT_MODEL,
            DEFAULT_VISION_MODEL,
        )
        .is_err()
    );
    assert!(
        chat_request_from_value(
            json!({
                "messages": [{
                    "role": "user",
                    "content": [{"type": "image_url", "image_url": {"url": "http://example.com/a.png"}}]
                }]
            }),
            DEFAULT_MODEL,
            DEFAULT_VISION_MODEL,
        )
        .is_err()
    );
    assert!(
        chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 8,
                "max_completion_tokens": 9
            }),
            DEFAULT_MODEL,
            DEFAULT_VISION_MODEL,
        )
        .is_err()
    );

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
async fn chat_vision_stream_embeddings_models_health_and_redaction_work() {
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, DEFAULT_VISION_MODEL).await;
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
        .and(header("authorization", "Bearer qwen-test-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_body(DEFAULT_MODEL, "text-ok")))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
        .and(body_partial_json(json!({
            "model": DEFAULT_VISION_MODEL,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "private image prompt"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/private.png"}}
                ]
            }]
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(chat_body(DEFAULT_VISION_MODEL, "vision-ok")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen-plus\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ni\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen-plus\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" hao\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
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
        .and(path("/compatible-mode/v1/embeddings"))
        .and(header("authorization", "Bearer qwen-test-key"))
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
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect("chat should succeed");
    let vision = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "private image prompt"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/private.png"}}
                ]
            }]
        }),
    )
    .await
    .expect("vision chat should succeed");
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

    assert_eq!(chat["content"], "text-ok");
    assert_eq!(vision["content"], "vision-ok");
    assert_eq!(vision["image_url_count"], 1);
    assert_eq!(stream["content"], "ni hao");
    assert_eq!(stream["chunk_count"], 2);
    assert_eq!(embeddings["dimensions"], 3);
    assert_eq!(models["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(health["status"], "ok");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("qwen-test-key"));
    assert!(!vision.to_string().contains("private image prompt"));
    assert!(!stream.to_string().contains("private stream prompt"));
}

#[fcp_async_core::runtime::test]
async fn rate_limit_errors_cancellation_trait_and_shutdown_are_safe() {
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, DEFAULT_VISION_MODEL).await;
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
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
        .and(path("/compatible-mode/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "rate_limit"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(chat_body(DEFAULT_MODEL, "recovered")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
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
        &[CAP_CHAT, CAP_MODELS],
        json!({"wait_on_rate_limit_ms": 1000}),
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
    let client = QwenClient::new(
        QwenProvider::new(
            format!("{}/compatible-mode/v1", server.uri()),
            QwenAuth::ApiKey("qwen-test-key".into()),
        ),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(60),
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

    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_MODELS, OP_MODELS);
    let response = connector
        .invoke(test_invoke_request(
            "qwen-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("trait invoke should return response");
    assert!(response.error.is_none(), "response should not carry error");

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
async fn qwen_loopback_e2e_jsonl_matrix() {
    let git_revision =
        std::env::var("QWEN_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, DEFAULT_VISION_MODEL).await;
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "jsonl_chat"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(chat_body(DEFAULT_MODEL, "jsonl-ok")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
        .and(body_partial_json(json!({"model": DEFAULT_VISION_MODEL})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(chat_body(DEFAULT_VISION_MODEL, "vision-ok")),
        )
        .mount(&server)
        .await;
    let sse = concat!(
        "data: {\"id\":\"chunk-a\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"qwen-plus\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "jsonl_stream"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/compatible-mode/v1/embeddings"))
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
            "model_id_hash": blake3::hash(DEFAULT_MODEL.as_bytes()).to_hex().to_string(),
            "completion_bytes": chat["content"].as_str().unwrap_or_default().len(),
            "http_status": 200
        }),
    );

    let vision = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "private vision prompt"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/private.png"}}
                ]
            }]
        }),
    )
    .await
    .expect("jsonl vision should pass");
    emit_jsonl(
        &git_revision,
        "qwen_vl",
        "wiremock",
        "passed",
        json!({
            "model_id_hash": blake3::hash(DEFAULT_VISION_MODEL.as_bytes()).to_hex().to_string(),
            "image_url_count": vision["image_url_count"],
            "text_bytes": 0,
            "image_byte_count": 0,
            "http_status": 200
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
            "stream_chunk_count": stream["chunk_count"],
            "completion_bytes": stream["content"].as_str().unwrap_or_default().len(),
            "http_status": 200
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
            "model_id_hash": blake3::hash(DEFAULT_EMBEDDING_MODEL.as_bytes()).to_hex().to_string(),
            "embedding_dimensions": embeddings["dimensions"],
            "data_count": embeddings["data_count"],
            "http_status": 200
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
            "model_count": models["data"].as_array().map(Vec::len).unwrap_or_default(),
            "http_status": 200
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

fn chat_body(model: &str, content: &str) -> Value {
    json!({
        "id": "chatcmpl-qwen",
        "object": "chat.completion",
        "created": 1,
        "model": model,
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
            "embedding": vec![0.25_f32; dimensions]
        }],
        "usage": {"prompt_tokens": 2, "total_tokens": 2}
    })
}

async fn mount_models(server: &MockServer, text_model: &str, vision_model: &str) {
    Mock::given(method("GET"))
        .and(path("/compatible-mode/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                {"id": text_model, "object": "model", "owned_by": "alibaba-cloud"},
                {"id": vision_model, "object": "model", "owned_by": "alibaba-cloud"},
                {"id": DEFAULT_EMBEDDING_MODEL, "object": "model", "owned_by": "alibaba-cloud"}
            ]
        })))
        .mount(server)
        .await;
}

fn emit_jsonl(
    git_revision: &str,
    operation: &str,
    fixture_mode: &str,
    status: &str,
    fields: Value,
) {
    let mut record = serde_json::Map::new();
    record.insert("event".into(), json!("qwen_e2e_operation"));
    record.insert("connector_id".into(), json!(CONNECTOR_ID));
    record.insert("git_revision".into(), json!(git_revision));
    record.insert("fixture_mode".into(), json!(fixture_mode));
    record.insert("operation".into(), json!(operation));
    record.insert("status".into(), json!(status));
    record.insert(
        "command_line".into(),
        json!("cargo test -p fcp-qwen --test integration qwen_loopback_e2e_jsonl_matrix -- --nocapture"),
    );
    if let Value::Object(fields) = fields {
        for (key, value) in fields {
            record.insert(key, value);
        }
    }
    println!("QWEN_E2E_JSONL {}", Value::Object(record));
}
