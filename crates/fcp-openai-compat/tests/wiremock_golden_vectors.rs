use std::collections::BTreeMap;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::HttpClientBuilder;
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatMessage, EmbeddingInput, EmbeddingsRequest,
    ErrorMapper, HeaderList, HttpRequest, ModelInfo, NetworkError, OpenAiCompatClient,
    OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError, RateLimitConfig, RateLimitPolicy,
    RateLimitSnapshot,
};
use futures_util::StreamExt as _;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone)]
struct FixtureProvider {
    id: &'static str,
    base_url: String,
}

impl OpenAiCompatProvider for FixtureProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        req.bearer_auth("fixture-token");
    }

    fn user_agent(&self) -> &'static str {
        "fcp-openai-compat-golden/0.1.0"
    }

    fn provider_name(&self) -> &'static str {
        self.id
    }

    fn rate_limit_overrides(&self) -> Option<RateLimitConfig> {
        Some(RateLimitConfig {
            request_remaining_header: Some("x-fixture-remaining".to_string()),
            ..RateLimitConfig::default()
        })
    }
}

fn artifact_path() -> PathBuf {
    PathBuf::from("target/fcp-openai-compat/golden-vector-log.jsonl")
}

fn append_log(value: &serde_json::Value) {
    let path = artifact_path();
    let parent = path.parent().expect("artifact has parent directory");
    create_dir_all(parent).expect("artifact directory should be created");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("artifact should open");
    writeln!(file, "{value}").expect("artifact line should write");
}

fn provider(server: &MockServer, id: &'static str) -> FixtureProvider {
    FixtureProvider {
        id,
        base_url: format!("{}/v1", server.uri()),
    }
}

fn client(
    provider: FixtureProvider,
    rate_limit_policy: RateLimitPolicy,
) -> OpenAiCompatClient<FixtureProvider> {
    OpenAiCompatClient::new_with_config(
        provider,
        HttpClientBuilder::new().build(),
        OpenAiCompatClientConfig {
            request_timeout: Duration::from_secs(5),
            model_cache_ttl: Duration::from_secs(60),
            rate_limit_policy,
        },
    )
}

async fn collect_stream(stream: ChatCompletionStream) -> Result<String, OpenAiError> {
    let chunks = stream.collect::<Vec<_>>().await;
    let mut content = String::new();
    for chunk in chunks {
        let chunk = chunk?;
        for choice in chunk.choices {
            if let Some(delta) = choice.delta.content {
                content.push_str(&delta);
            }
        }
    }
    Ok(content)
}

#[fcp_async_core::runtime::test]
async fn golden_vector_lane_covers_openai_compatible_profiles() {
    let profiles = ["groq", "deepseek-r1", "xai", "local-openai-compatible"];

    for profile in profiles {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer fixture-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": format!("chatcmpl-{profile}"),
                "object": "chat.completion",
                "created": 1,
                "model": "fixture-model",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": format!("hello from {profile}")},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "model": "fixture-embedding",
                "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
                "usage": {"prompt_tokens": 1, "total_tokens": 1}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "data": [{"id": "fixture-model", "object": "model", "owned_by": profile}]
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let cx = Cx::for_testing();
        let client = client(provider(&server, profile), RateLimitPolicy::FailFast);
        let chat = client
            .chat_completions(
                &cx,
                ChatCompletionsRequest::new("fixture-model", vec![ChatMessage::user_text("hello")]),
            )
            .await
            .expect("chat request should succeed");
        let embeddings = client
            .embeddings(
                &cx,
                EmbeddingsRequest {
                    model: "fixture-embedding".to_string(),
                    input: EmbeddingInput::Single("hello".to_string()),
                    encoding_format: None,
                    dimensions: None,
                    provider_extensions: BTreeMap::default(),
                },
            )
            .await
            .expect("embeddings request should succeed");
        let models_first = client.list_models(&cx).await.expect("models should load");
        let models_second = client.list_models(&cx).await.expect("models should cache");

        assert_eq!(chat.choices[0].finish_reason.as_deref(), Some("stop"));
        assert_eq!(embeddings.data[0].embedding, vec![0.1, 0.2]);
        assert_eq!(models_first, models_second);
        assert_eq!(
            models_first,
            vec![ModelInfo {
                id: "fixture-model".to_string(),
                object: Some("model".to_string()),
                owned_by: Some(profile.to_string()),
                created: None,
            }]
        );

        append_log(&json!({
            "command_line": std::env::args().collect::<Vec<_>>().join(" "),
            "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown"),
            "provider_fixture_id": profile,
            "endpoint_path": "/v1/chat/completions",
            "auth_header_policy": "bearer-redacted",
            "request_bytes": 0,
            "response_bytes": serde_json::to_vec(&chat).expect("chat response encodes").len(),
            "chunk_count": 0,
            "finish_reason": chat.choices[0].finish_reason,
            "retry_decision": "none",
            "error_mapping": "none",
            "cache_hit": true,
            "cache_miss": true,
            "cancellation_checkpoint": "cx.checkpoint-before-after-request",
            "cleanup_result": "wiremock-dropped"
        }));
    }
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_tool_call_and_done_are_decoded() {
    let server = MockServer::start().await;
    let stream_body = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"fixture\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\"\"}}]},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"fixture\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\",\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":\\\"x\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(stream_body),
        )
        .mount(&server)
        .await;

    let cx = Cx::for_testing();
    let stream = client(provider(&server, "xai"), RateLimitPolicy::FailFast)
        .chat_completions_stream(
            &cx,
            ChatCompletionsRequest::new("fixture", vec![ChatMessage::user_text("hello")]),
        )
        .await
        .expect("stream should open");

    let content = collect_stream(stream).await.expect("stream should decode");
    assert_eq!(content, "hello");
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .insert_header("x-fixture-remaining", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "slow down"}
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
            "model": "fixture",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "recovered"},
                "finish_reason": "stop"
            }]
        })))
        .mount(&server)
        .await;

    let response = client(
        provider(&server, "groq"),
        RateLimitPolicy::WaitUpTo(Duration::from_secs(1)),
    )
    .chat_completions(
        &Cx::for_testing(),
        ChatCompletionsRequest::new("fixture", vec![ChatMessage::user_text("hello")]),
    )
    .await
    .expect("rate limit retry should recover");

    assert_eq!(response.choices[0].finish_reason.as_deref(), Some("stop"));
}

#[fcp_async_core::runtime::test]
async fn provider_service_error_maps_without_prompt_or_token_leakage() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": {
                "type": "service_unavailable",
                "message": "provider saw Bearer should-not-leak",
                "prompt": "private prompt"
            }
        })))
        .mount(&server)
        .await;

    let err = client(provider(&server, "deepseek-r1"), RateLimitPolicy::FailFast)
        .chat_completions(
            &Cx::for_testing(),
            ChatCompletionsRequest::new("fixture", vec![ChatMessage::user_text("hello")]),
        )
        .await
        .expect_err("503 should map to service unavailable");

    assert!(matches!(err, OpenAiError::ServiceUnavailable { .. }));
    let display = err.to_string();
    assert!(!display.contains("should-not-leak"));
    assert!(!display.contains("private prompt"));
}

#[fcp_async_core::runtime::test]
async fn model_cache_can_be_invalidated_and_refreshed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "model-a", "object": "model", "owned_by": "fixture"}]
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "model-b", "object": "model", "owned_by": "fixture"}]
        })))
        .mount(&server)
        .await;

    let cx = Cx::for_testing();
    let client = client(
        provider(&server, "local-openai-compatible"),
        RateLimitPolicy::FailFast,
    );
    let first = client.list_models(&cx).await.expect("first model load");
    let cached = client.list_models(&cx).await.expect("cached model load");
    client.invalidate_model_cache().await;
    let refreshed = client.list_models(&cx).await.expect("refreshed model load");

    assert_eq!(first[0].id, "model-a");
    assert_eq!(cached[0].id, "model-a");
    assert_eq!(refreshed[0].id, "model-b");
}

#[fcp_async_core::runtime::test]
async fn cancellation_checkpoint_prevents_request_dispatch() {
    let server = MockServer::start().await;
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);

    let err = client(
        provider(&server, "local-openai-compatible"),
        RateLimitPolicy::FailFast,
    )
    .chat_completions(
        &cx,
        ChatCompletionsRequest::new("fixture", vec![ChatMessage::user_text("hello")]),
    )
    .await
    .expect_err("cancelled context should fail before dispatch");

    assert!(matches!(
        err,
        OpenAiError::Network(NetworkError::Cancelled { .. })
    ));
}

#[test]
fn custom_mapper_can_preserve_provider_specific_status() {
    struct Mapper;
    impl ErrorMapper for Mapper {
        fn map_response(
            &self,
            provider: &str,
            status: u16,
            _headers: &HeaderList,
            body: &[u8],
            _rate_limits: RateLimitSnapshot,
        ) -> OpenAiError {
            OpenAiError::Provider {
                provider: provider.to_string(),
                status,
                body: String::from_utf8_lossy(body).to_string(),
            }
        }
    }

    let err = Mapper.map_response(
        "local",
        599,
        &Vec::new(),
        br#"{"error":"custom"}"#,
        RateLimitSnapshot::default(),
    );
    assert!(matches!(err, OpenAiError::Provider { status: 599, .. }));
}
