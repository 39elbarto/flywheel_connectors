#![allow(clippy::doc_markdown)]
//! Integration tests for the Google AI (Gemini) connector.
//!
//! Covers the connector testing requirements (flywheel_connectors-e27.6):
//! - Streaming parsing (JSON array and single-object fallback)
//! - Error taxonomy mapping (`GoogleAiError` → `FcpError`)
//! - Redaction (API keys not leaked in error messages)
//! - Usage metrics (token counting across requests)
//!
//! All tests are deterministic — no real API calls.

#![allow(clippy::too_many_lines)]

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration as StdDuration;

use asupersync::net::websocket::{CloseReason, Message, ServerWebSocket, WebSocketAcceptor};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{Duration, Utc};
use fcp_async_core::Cx;
use fcp_async_core::io::{AsyncRead, ReadBuf};
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_async_core::task;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path, query_param},
};

use fcp_google_ai::{
    client::GoogleAiClient,
    connector::GoogleAiConnector,
    error::GoogleAiError,
    realtime::{
        GoogleLiveRealtimeAudioChunk, GoogleLiveRealtimeRunReport, GoogleLiveRealtimeSessionConfig,
        run_google_live_realtime_session,
    },
};

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &str,
    instance_id: &str,
) -> CapabilityToken {
    let cap = match op {
        "google-ai.live.create_browser_session" => "google-ai.live_voice",
        "google-ai.embed_content" | "google-ai.batch_embed_contents" => "google-ai.embed",
        "google-ai.count_tokens" | "google-ai.list_models" | "google-ai.get_model" => {
            "google-ai.models"
        }
        "google-ai.tuning.list"
        | "google-ai.tuning.get"
        | "google-ai.tuning.get_operation"
        | "google-ai.tuning.create"
        | "google-ai.tuning.cancel" => "google-ai.tuning",
        "google-ai.get_usage" => "google-ai.usage",
        _ => "google-ai.generate",
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut GoogleAiConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn setup_configure(connector: &mut GoogleAiConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

type TestLiveServerWebSocket = ServerWebSocket<TcpStream>;

async fn read_live_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut temp = [0_u8; 256];
    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before websocket handshake completed",
            ));
        }
        buf.extend_from_slice(&temp[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake headers too large",
            ));
        }
    }
}

async fn accept_live_websocket(mut stream: TcpStream) -> (String, TestLiveServerWebSocket) {
    let request = read_live_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    let request_text = String::from_utf8_lossy(&request).into_owned();
    let ws = WebSocketAcceptor::new()
        .accept(&Cx::for_testing(), &request, stream)
        .await
        .expect("accept websocket");
    (request_text, ws)
}

fn expect_live_text(message: Message, context: &str) -> String {
    assert!(
        matches!(&message, Message::Text(_)),
        "expected text frame for {context}"
    );
    match message {
        Message::Text(text) => text,
        _ => String::new(),
    }
}

async fn recv_live_json(ws: &mut TestLiveServerWebSocket, context: &str) -> serde_json::Value {
    let message = ws
        .recv(&Cx::for_testing())
        .await
        .expect(context)
        .expect("live websocket message missing");
    serde_json::from_str(&expect_live_text(message, context)).expect("live json frame")
}

async fn send_live_json(ws: &mut TestLiveServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(&Cx::for_testing(), Message::text(value.to_string()))
        .await
        .expect(context);
}

async fn send_live_text(ws: &mut TestLiveServerWebSocket, value: &str, context: &str) {
    ws.send(&Cx::for_testing(), Message::text(value.to_string()))
        .await
        .expect(context);
}

async fn close_live_websocket(ws: &mut TestLiveServerWebSocket) {
    let _ = ws.close(&Cx::for_testing(), CloseReason::normal()).await;
}

fn assert_realtime_report_has_steps(report: &GoogleLiveRealtimeRunReport, expected: &[&str]) {
    let steps: Vec<&str> = report
        .events
        .iter()
        .map(|event| event.step.as_str())
        .collect();
    for expected_step in expected {
        assert!(
            steps.contains(expected_step),
            "missing realtime step {expected_step}; observed {steps:?}"
        );
    }
}

fn assert_redacted_realtime_jsonl(report: &GoogleLiveRealtimeRunReport, forbidden: &[&str]) {
    let jsonl = report.to_jsonl();
    assert!(!jsonl.trim().is_empty(), "JSONL evidence must not be empty");
    for secret in forbidden {
        assert!(!jsonl.contains(secret), "JSONL leaked secret {secret}");
    }
    for (idx, line) in jsonl.lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line).expect("JSONL parses");
        assert_eq!(value["logVersion"], "v1", "line {idx}");
        assert_eq!(
            value["script"], "google_ai_live_realtime_loopback",
            "line {idx}"
        );
        assert!(value["timestamp"].as_str().is_some(), "line {idx}");
        assert!(value["step"].as_str().is_some(), "line {idx}");
        assert!(value["correlationId"].as_str().is_some(), "line {idx}");
        assert!(matches!(value["result"].as_str(), Some("pass" | "fail")));
        assert!(value["durationMs"].as_u64().is_some(), "line {idx}");
    }
}

fn success_response(text: &str, prompt_tokens: u64, candidates_tokens: u64) -> serde_json::Value {
    json!({
        "candidates": [{
            "content": {
                "parts": [{"text": text}],
                "role": "model"
            },
            "finishReason": "STOP",
            "index": 0
        }],
        "usageMetadata": {
            "promptTokenCount": prompt_tokens,
            "candidatesTokenCount": candidates_tokens,
            "totalTokenCount": prompt_tokens + candidates_tokens
        }
    })
}

// ============================================================================
// Streaming parsing tests
// ============================================================================

/// Streaming endpoint returns JSON array of chunks; all should be parsed.
#[fcp_async_core::runtime::test]
async fn streaming_json_array_parses_all_chunks() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{
                "content": { "parts": [{"text": "Hello"}], "role": "model" },
                "index": 0
            }]
        },
        {
            "candidates": [{
                "content": { "parts": [{"text": " world"}], "role": "model" },
                "finishReason": "STOP",
                "index": 0
            }],
            "usageMetadata": {
                "promptTokenCount": 8,
                "candidatesTokenCount": 2,
                "totalTokenCount": 10
            }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let result = client
        .generate_content_stream("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert_eq!(result.len(), 2);
    let text: String = result
        .iter()
        .flat_map(|r| &r.candidates)
        .filter_map(|c| c.content.as_ref())
        .flat_map(|c| &c.parts)
        .filter_map(|p| match p {
            fcp_google_ai::types::Part::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(text, "Hello world");
}

/// Streaming endpoint may return a single object instead of array.
#[fcp_async_core::runtime::test]
async fn streaming_single_object_fallback() {
    let mock_server = MockServer::start().await;

    let single = success_response("single chunk", 5, 3);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(single))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let result = client
        .generate_content_stream("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert_eq!(result.len(), 1, "single object should be wrapped in vec");
    assert_eq!(result[0].candidates.len(), 1);
}

/// Streaming accumulates usage across all chunks.
#[fcp_async_core::runtime::test]
async fn streaming_usage_accumulates_across_chunks() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{"content": {"parts": [{"text": "a"}], "role": "model"}}],
            "usageMetadata": { "promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15 }
        },
        {
            "candidates": [{"content": {"parts": [{"text": "b"}], "role": "model"}}],
            "usageMetadata": { "promptTokenCount": 0, "candidatesTokenCount": 8, "totalTokenCount": 8 }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    client
        .generate_content_stream("gemini-2.0-flash", &body)
        .await
        .unwrap();

    let usage = client.get_usage();
    assert_eq!(usage.input_tokens, 10, "prompt tokens from both chunks");
    assert_eq!(usage.output_tokens, 13, "candidate tokens from both chunks");
    assert_eq!(usage.requests_total, 1);
}

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(401).set_body_string("API key not valid."))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("bad-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        GoogleAiError::Api {
            status_code: Some(401),
            ..
        }
    ));
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden also maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("bad-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let err = client.list_models(None, None).await.unwrap_err();
    assert!(matches!(
        err,
        GoogleAiError::Api {
            status_code: Some(403),
            ..
        }
    ));
    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::Unauthorized { .. }));
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[test]
fn error_429_rate_limit_maps_correctly() {
    let err = GoogleAiError::RateLimit {
        retry_after_ms: 30_000,
    };
    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                ..
            }
        ),
        "expected RateLimited with 30s, got: {fcp_err:?}"
    );
}

/// 404 Not Found returns specific error (not retryable).
#[fcp_async_core::runtime::test]
async fn error_404_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models/nonexistent-model"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_model("nonexistent-model").await.unwrap_err();
    assert!(matches!(
        err,
        GoogleAiError::Api {
            status_code: Some(404),
            ..
        }
    ));
    assert!(!err.is_retryable());
}

/// 500 Server Error is retryable and maps to `FcpError::External`.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external_retryable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                status_code: Some(500),
                ..
            }
        ),
        "expected External(500, retryable), got: {fcp_err:?}"
    );
}

/// Malformed JSON body triggers serialization error.
#[fcp_async_core::runtime::test]
async fn error_malformed_json_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not valid json"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    // Should be a serialization error since the JSON is invalid
    assert!(!err.is_retryable());
}

/// `InvalidConfig` maps to `FcpError::InvalidRequest`.
#[test]
fn error_invalid_config_maps_to_invalid_request() {
    let err = GoogleAiError::InvalidConfig("missing api_key".into());
    assert!(!err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::InvalidRequest { code: 1003, .. }),
        "expected InvalidRequest, got: {fcp_err:?}"
    );
}

// ============================================================================
// Redaction tests
// ============================================================================

/// API key should not appear in error messages from the connector.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_error_message() {
    let mock_server = MockServer::start().await;
    let secret_key = "AIzaSyDSuperSecretKeyThatShouldNotLeak123";

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Invalid API key"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new(secret_key)
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(secret_key),
        "API key should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(secret_key),
        "API key should not appear in FCP error debug output"
    );
}

/// API key should not appear in connector-level errors during configure.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_configure_error() {
    let mut connector = GoogleAiConnector::new();
    let secret_key = "AIzaSyDSuperSecretKeyThatShouldNotLeak456";

    // Configure with a key but with an unreachable URL to trigger error
    let result = connector
        .handle_configure(json!({
            "api_key": secret_key,
            "base_url": "http://127.0.0.1:1/v1beta"
        }))
        .await;

    // The configure should succeed (doesn't validate the URL on configure,
    // or if it fails the error should not contain the key)
    if let Err(err) = result {
        let err_string = format!("{err:?}");
        assert!(
            !err_string.contains(secret_key),
            "API key should not appear in configure error"
        );
    }
}

/// Error messages from invoke should not leak the API key.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_invoke_error() {
    let mock_server = MockServer::start().await;
    let secret_key = "AIzaSyDSuperSecretKeyThatShouldNotLeak789";

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "Invalid argument",
                "status": "INVALID_ARGUMENT",
                "code": 400
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    connector
        .handle_configure(json!({
            "api_key": secret_key,
            "base_url": format!("{}/v1beta", mock_server.uri())
        }))
        .await
        .unwrap();

    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "test"}]}]},
            "capability_token": token
        }))
        .await;

    if let Err(err) = result {
        let err_string = format!("{err:?}");
        assert!(
            !err_string.contains(secret_key),
            "API key should not appear in invoke error: {err_string}"
        );
    }
}

// ============================================================================
// Usage metrics tests
// ============================================================================

/// Single request accumulates token usage correctly.
#[fcp_async_core::runtime::test]
async fn usage_single_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("ok", 12, 8)))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    let usage = client.get_usage();
    assert_eq!(usage.input_tokens, 12);
    assert_eq!(usage.output_tokens, 8);
    assert_eq!(usage.requests_total, 1);
    assert_eq!(usage.requests_error, 0);
}

/// Multiple requests accumulate token usage.
#[fcp_async_core::runtime::test]
async fn usage_multiple_requests_accumulate() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("ok", 10, 20)))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();
    client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    let usage = client.get_usage();
    assert_eq!(usage.input_tokens, 30, "10 * 3 requests");
    assert_eq!(usage.output_tokens, 60, "20 * 3 requests");
    assert_eq!(usage.requests_total, 3);
    assert_eq!(usage.requests_error, 0);
}

/// Error requests increment error counter.
#[fcp_async_core::runtime::test]
async fn usage_error_requests_counted() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("bad-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let _ = client.generate_content("gemini-2.0-flash", &body).await;

    let usage = client.get_usage();
    assert_eq!(usage.requests_total, 1);
    assert_eq!(usage.requests_error, 1);
    assert_eq!(usage.input_tokens, 0, "no tokens on error");
    assert_eq!(usage.output_tokens, 0);
}

/// Usage is exposed via the google-ai.get_usage connector operation.
#[fcp_async_core::runtime::test]
async fn usage_exposed_via_connector_operation() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("hello", 15, 25)))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(
        &mut connector,
        &["google-ai.generate_content", "google-ai.get_usage"],
    )
    .await;

    // Make a generate request to populate usage
    let gen_token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content",
        connector.instance_id(),
    );
    connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "test"}]}]},
            "capability_token": gen_token
        }))
        .await
        .unwrap();

    // Get usage via operation
    let usage_token =
        generate_valid_token(&signing_key, "google-ai.get_usage", connector.instance_id());
    let usage_result = connector
        .handle_invoke(json!({
            "operation": "google-ai.get_usage",
            "input": {},
            "capability_token": usage_token
        }))
        .await
        .unwrap();

    assert_eq!(usage_result["total_input_tokens"], 15);
    assert_eq!(usage_result["total_output_tokens"], 25);
    assert_eq!(usage_result["requests_total"], 1);
    assert_eq!(usage_result["requests_error"], 0);
}

// ============================================================================
// Tool use (function calling) tests
// ============================================================================

/// Generate content returning a function call should parse correctly.
#[fcp_async_core::runtime::test]
async fn tool_use_function_call_in_response() {
    let mock_server = MockServer::start().await;

    let resp = json!({
        "candidates": [{
            "content": {
                "parts": [{
                    "functionCall": {
                        "name": "get_weather",
                        "args": {"location": "San Francisco", "unit": "celsius"}
                    }
                }],
                "role": "model"
            },
            "finishReason": "STOP",
            "index": 0
        }],
        "usageMetadata": {
            "promptTokenCount": 20,
            "candidatesTokenCount": 15,
            "totalTokenCount": 35
        }
    });

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "what is the weather?"}]}],
        "tools": [{"functionDeclarations": [{
            "name": "get_weather",
            "description": "Get the weather",
            "parameters": {
                "type": "object",
                "properties": {"location": {"type": "string"}, "unit": {"type": "string"}}
            }
        }]}]
    });
    let result = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert_eq!(result.candidates.len(), 1);
    let parts = &result.candidates[0].content.as_ref().unwrap().parts;
    assert_eq!(parts.len(), 1);
    assert!(
        matches!(&parts[0], fcp_google_ai::types::Part::FunctionCall { .. }),
        "expected FunctionCall part"
    );
}

/// Provenance metadata from non-streaming generate should flag tool calls.
#[fcp_async_core::runtime::test]
async fn provenance_flags_tool_calls_in_generate() {
    let mock_server = MockServer::start().await;

    let resp = json!({
        "candidates": [{
            "content": {
                "parts": [{
                    "functionCall": {
                        "name": "search",
                        "args": {"query": "rust"}
                    }
                }],
                "role": "model"
            },
            "finishReason": "STOP",
            "index": 0
        }],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 8,
            "totalTokenCount": 18
        }
    });

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(resp))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {
                "contents": [{"role": "user", "parts": [{"text": "search for rust"}]}],
                "tools": [{"functionDeclarations": [{"name": "search", "parameters": {"type": "object"}}]}]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["source"], "google-ai");
    assert_eq!(prov["model"], "gemini-2.0-flash");
    assert_eq!(prov["integrity"], "untrusted");
    assert_eq!(prov["has_tool_calls"], true);
    assert_eq!(prov["chunk_count"], 1);
}

/// Provenance metadata from non-streaming generate should NOT flag tool calls for text-only.
#[fcp_async_core::runtime::test]
async fn provenance_no_tool_calls_for_text_only() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response(
            "hello world",
            5,
            3,
        )))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["has_tool_calls"], false);
    assert_eq!(prov["chunk_count"], 1);
}

// ============================================================================
// Streaming through connector tests
// ============================================================================

/// Streaming through the connector returns provenance with `chunk_count` > 1.
#[fcp_async_core::runtime::test]
async fn streaming_through_connector_has_provenance() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{
                "content": { "parts": [{"text": "Hello"}], "role": "model" },
                "index": 0
            }]
        },
        {
            "candidates": [{
                "content": { "parts": [{"text": " world"}], "role": "model" },
                "finishReason": "STOP",
                "index": 0
            }],
            "usageMetadata": {
                "promptTokenCount": 8,
                "candidatesTokenCount": 2,
                "totalTokenCount": 10
            }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content_stream"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content_stream",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content_stream",
            "input": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["source"], "google-ai");
    assert_eq!(prov["model"], "gemini-2.0-flash");
    assert_eq!(prov["integrity"], "untrusted");
    assert_eq!(prov["has_tool_calls"], false);
    assert_eq!(prov["chunk_count"], 2);
}

/// Streaming with tool calls in one of the chunks should flag `has_tool_calls`.
#[fcp_async_core::runtime::test]
async fn streaming_tool_call_detected_in_provenance() {
    let mock_server = MockServer::start().await;

    let chunks = json!([
        {
            "candidates": [{
                "content": { "parts": [{"text": "Let me search"}], "role": "model" },
                "index": 0
            }]
        },
        {
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": {
                            "name": "web_search",
                            "args": {"query": "weather today"}
                        }
                    }],
                    "role": "model"
                },
                "finishReason": "STOP",
                "index": 0
            }],
            "usageMetadata": {
                "promptTokenCount": 12,
                "candidatesTokenCount": 10,
                "totalTokenCount": 22
            }
        }
    ]);

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(chunks))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content_stream"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content_stream",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content_stream",
            "input": {"contents": [{"role": "user", "parts": [{"text": "weather?"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    let prov = &result["provenance"];
    assert_eq!(prov["has_tool_calls"], true);
    assert_eq!(prov["chunk_count"], 2);
}

/// Wrong capability token rejects `generate_content` invocation.
#[fcp_async_core::runtime::test]
async fn wrong_capability_rejects_generate() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("ok", 1, 1)))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.list_models"]).await;
    // Use a token for list_models, not generate_content
    let token = generate_valid_token(
        &signing_key,
        "google-ai.list_models",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "test"}]}]},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject mismatched capability");
}

// ============================================================================
// Operation happy-path tests (connector-level invoke)
// ============================================================================

/// embed_content through connector invoke returns embedding values.
#[fcp_async_core::runtime::test]
async fn invoke_embed_content_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/text-embedding-004:embedContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "embedding": { "values": [0.1, 0.2, 0.3] }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.embed_content"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.embed_content",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.embed_content",
            "input": {"content": {"parts": [{"text": "hello"}]}},
            "capability_token": token
        }))
        .await
        .unwrap();

    let values = result["embedding"]["values"].as_array().unwrap();
    assert_eq!(values.len(), 3);
}

/// batch_embed_contents through connector invoke returns multiple embeddings.
#[fcp_async_core::runtime::test]
async fn invoke_batch_embed_contents_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/text-embedding-004:batchEmbedContents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "embeddings": [
                {"values": [0.1, 0.2]},
                {"values": [0.3, 0.4]}
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.batch_embed_contents"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.batch_embed_contents",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.batch_embed_contents",
            "input": {
                "requests": [
                    {"content": {"parts": [{"text": "doc 1"}]}},
                    {"content": {"parts": [{"text": "doc 2"}]}}
                ]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    let embeddings = result["embeddings"].as_array().unwrap();
    assert_eq!(embeddings.len(), 2);
}

/// count_tokens through connector invoke returns total_tokens.
#[fcp_async_core::runtime::test]
async fn invoke_count_tokens_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:countTokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "totalTokens": 99
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.count_tokens"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.count_tokens",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.count_tokens",
            "input": {"contents": [{"role": "user", "parts": [{"text": "Hello world"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["total_tokens"], 99);
}

/// list_models through connector invoke returns model list.
#[fcp_async_core::runtime::test]
async fn invoke_list_models_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [
                {
                    "name": "models/gemini-2.0-flash",
                    "displayName": "Gemini 2.0 Flash",
                    "supportedGenerationMethods": ["generateContent"],
                    "inputTokenLimit": 1_048_576,
                    "outputTokenLimit": 8192
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.list_models"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.list_models",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.list_models",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    let models = result["models"].as_array().unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0]["name"], "models/gemini-2.0-flash");
}

/// get_model through connector invoke returns model info.
#[fcp_async_core::runtime::test]
async fn invoke_get_model_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models/gemini-2.0-flash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "models/gemini-2.0-flash",
            "displayName": "Gemini 2.0 Flash",
            "supportedGenerationMethods": ["generateContent", "countTokens"],
            "inputTokenLimit": 1_048_576,
            "outputTokenLimit": 8192
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.get_model"]).await;
    let token = generate_valid_token(&signing_key, "google-ai.get_model", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.get_model",
            "input": {"model": "gemini-2.0-flash"},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["name"], "models/gemini-2.0-flash");
    assert_eq!(result["inputTokenLimit"], 1_048_576);
}

// ============================================================================
// Error handling tests (additional HTTP status codes)
// ============================================================================

/// 429 from client-level wiremock returns rate limit header.
#[fcp_async_core::runtime::test]
async fn error_429_with_retry_after_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "5"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    match &err {
        GoogleAiError::RateLimit { retry_after_ms } => {
            assert_eq!(
                *retry_after_ms, 5000,
                "retry-after header of 5 seconds = 5000ms"
            );
        }
        other => panic!("expected RateLimit, got: {other:?}"),
    }
}

/// Non-JSON 200 response on streaming endpoint triggers serialization error.
#[fcp_async_core::runtime::test]
async fn error_non_json_streaming_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content_stream("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    assert!(
        !err.is_retryable(),
        "serialization errors are not retryable"
    );
}

/// 502 Bad Gateway maps to retryable External error.
#[fcp_async_core::runtime::test]
async fn error_502_maps_to_external_retryable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                status_code: Some(502),
                ..
            }
        ),
        "expected External(502, retryable), got: {fcp_err:?}"
    );
}

/// 400 Bad Request from API returns structured error.
#[fcp_async_core::runtime::test]
async fn error_400_structured_api_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "code": 400,
                "message": "Request contains an invalid argument.",
                "status": "INVALID_ARGUMENT"
            }
        })))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()))
        .with_retry_config(0);

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let err = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap_err();

    assert!(!err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                status_code: Some(400),
                retryable: false,
                ..
            }
        ),
        "expected External(400, not retryable), got: {fcp_err:?}"
    );
}

// ============================================================================
// Input validation tests
// ============================================================================

/// get_model invoke with missing required `model` field returns InvalidRequest.
#[fcp_async_core::runtime::test]
async fn invoke_get_model_missing_model_field() {
    let mock_server = MockServer::start().await;

    // Mount a dummy mock so we don't need a real API
    Mock::given(method("GET"))
        .and(path("/v1beta/models/anything"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.get_model"]).await;
    let token = generate_valid_token(&signing_key, "google-ai.get_model", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.get_model",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("model"),
                "error should mention missing field 'model'"
            );
        }
        e => panic!("expected InvalidRequest, got: {e:?}"),
    }
}

/// Invoke with missing `operation` field returns InvalidRequest.
#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_field() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.list_models"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.list_models",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("operation"),
                "error should mention missing 'operation'"
            );
        }
        e => panic!("expected InvalidRequest, got: {e:?}"),
    }
}

/// Invoke with missing `capability_token` field returns InvalidRequest.
#[fcp_async_core::runtime::test]
async fn invoke_missing_capability_token() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let _signing_key = setup_handshake(&mut connector, &["google-ai.list_models"]).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.list_models",
            "input": {}
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("capability_token"));
        }
        e => panic!("expected InvalidRequest, got: {e:?}"),
    }
}

// ============================================================================
// Configuration edge-case tests
// ============================================================================

/// Empty api_key (whitespace only) is rejected.
#[fcp_async_core::runtime::test]
async fn configure_empty_whitespace_api_key_rejected() {
    let mut connector = GoogleAiConnector::new();
    let result = connector
        .handle_configure(json!({ "api_key": "   " }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("Missing api_key or credential_id"));
        }
        e => panic!("expected InvalidRequest, got: {e:?}"),
    }
}

/// credential_id as a non-string value is rejected.
#[fcp_async_core::runtime::test]
async fn configure_credential_id_non_string_rejected() {
    let mut connector = GoogleAiConnector::new();
    let result = connector
        .handle_configure(json!({ "credential_id": 12345 }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("credential_id must be a string"));
        }
        e => panic!("expected InvalidRequest, got: {e:?}"),
    }
}

/// Both api_key and credential_id provided is rejected.
#[fcp_async_core::runtime::test]
async fn configure_both_auth_modes_rejected() {
    let mut connector = GoogleAiConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "my-key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("exactly one"));
        }
        e => panic!("expected InvalidRequest, got: {e:?}"),
    }
}

/// Neither auth method provided is rejected.
#[fcp_async_core::runtime::test]
async fn configure_no_auth_rejected() {
    let mut connector = GoogleAiConnector::new();
    let result = connector
        .handle_configure(json!({"base_url": "http://localhost:9999"}))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("Missing api_key or credential_id"));
        }
        e => panic!("expected InvalidRequest, got: {e:?}"),
    }
}

/// Configure with custom base_url overrides default.
#[fcp_async_core::runtime::test]
async fn configure_custom_base_url() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [{"name": "models/gemini-2.0-flash"}]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    let custom_url = format!("{}/v1beta", mock_server.uri());
    setup_configure(&mut connector, &custom_url).await;

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["base_url"], custom_url);
}

// ============================================================================
// Lifecycle tests
// ============================================================================

/// Health check before configuration returns not_configured.
#[fcp_async_core::runtime::test]
async fn health_before_configure_returns_not_configured() {
    let connector = GoogleAiConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
    assert_eq!(result["auth"], "unconfigured");
}

/// Health check after configuration returns healthy.
#[fcp_async_core::runtime::test]
async fn health_after_configure_returns_healthy() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
    assert_eq!(result["auth"], "api_key:redacted");
}

/// Doctor report returns structured checks with expected fields.
#[fcp_async_core::runtime::test]
async fn doctor_report_has_all_checks_when_configured() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;

    let result = connector.handle_doctor().await.unwrap();
    let checks = result["checks"].as_array().unwrap();

    let check_names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(check_names.contains(&"configuration"));
    assert!(check_names.contains(&"client_initialized"));
    assert!(check_names.contains(&"base_url"));
    assert!(check_names.contains(&"auth_mode"));
    assert!(check_names.contains(&"network_constraints"));
    assert!(check_names.contains(&"credential_injection"));
    assert!(
        checks.len() >= 6,
        "expected at least 6 checks, got {}",
        checks.len()
    );
}

/// Self-check before configuration returns degraded.
#[fcp_async_core::runtime::test]
async fn self_check_before_configure_returns_degraded() {
    let connector = GoogleAiConnector::new();
    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "degraded");
    assert_eq!(result["reason_code"], "not_configured");
}

/// Self-check with valid API key and working endpoint returns ok.
#[fcp_async_core::runtime::test]
async fn self_check_success_returns_ok() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [{"name": "models/gemini-2.0-flash"}]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;

    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "ok");
}

/// Shutdown returns status and connector can be re-invoked after re-configure.
#[fcp_async_core::runtime::test]
async fn shutdown_then_reinvoke() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("hello", 5, 3)))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;

    // Shutdown
    let shutdown = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(shutdown["status"], "shutdown");

    // Re-configure and re-handshake
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key2 = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(
        &signing_key2,
        "google-ai.generate_content",
        connector.instance_id(),
    );

    // Should work after re-init
    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["candidates"].is_array());
    // Suppress unused variable warning
    let _ = signing_key;
}

/// Introspect returns the full operation catalog with correct structure.
#[fcp_async_core::runtime::test]
async fn introspect_returns_complete_operation_catalog() {
    let connector = GoogleAiConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 14, "should have 14 operations");

    let op_ids: Vec<&str> = ops.iter().filter_map(|op| op["id"].as_str()).collect();
    for expected in [
        "google-ai.generate_content",
        "google-ai.generate_content_stream",
        "google-ai.live.create_browser_session",
        "google-ai.embed_content",
        "google-ai.batch_embed_contents",
        "google-ai.count_tokens",
        "google-ai.list_models",
        "google-ai.get_model",
        "google-ai.tuning.create",
        "google-ai.tuning.list",
        "google-ai.tuning.get",
        "google-ai.tuning.get_operation",
        "google-ai.tuning.cancel",
        "google-ai.get_usage",
    ] {
        assert!(op_ids.contains(&expected), "missing operation {expected}");
    }

    for op in ops {
        assert!(op["id"].is_string(), "each op should have an id");
        assert!(op["summary"].is_string(), "each op should have a summary");
        assert!(
            op["input_schema"].is_object(),
            "each op should have input_schema"
        );
        assert!(
            op["output_schema"].is_object(),
            "each op should have output_schema"
        );
    }
}

// ============================================================================
// Simulate tests
// ============================================================================

/// Simulate with a known operation returns allowed.
#[fcp_async_core::runtime::test]
async fn simulate_known_operation_returns_allowed() {
    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, "http://localhost:9999/v1beta").await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content",
        connector.instance_id(),
    );

    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "req-001",
            "connector_id": "google-ai",
            "operation": "google-ai.generate_content",
            "zone_id": "z:work",
            "input": {"contents": [{"role": "user", "parts": [{"text": "test"}]}]},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["would_succeed"], true);
}

/// Simulate with an unknown operation still returns allowed (current impl).
#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation_returns_allowed() {
    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, "http://localhost:9999/v1beta").await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.nonexistent_operation"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.nonexistent_operation",
        connector.instance_id(),
    );

    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "req-002",
            "connector_id": "google-ai",
            "operation": "google-ai.nonexistent_operation",
            "zone_id": "z:work",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    // Current implementation always returns allowed
    assert_eq!(result["would_succeed"], true);
}

// ============================================================================
// Empty results / edge-case response tests
// ============================================================================

/// list_models returning empty array is handled correctly.
#[fcp_async_core::runtime::test]
async fn invoke_list_models_empty_result() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": []
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.list_models"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.list_models",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.list_models",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    let models = result["models"].as_array().unwrap();
    assert!(
        models.is_empty(),
        "empty model list should be returned as empty array"
    );
}

/// generate_content response with no usage_metadata is handled.
#[fcp_async_core::runtime::test]
async fn generate_content_no_usage_metadata() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [{
                "content": {
                    "parts": [{"text": "response without usage"}],
                    "role": "model"
                },
                "finishReason": "STOP",
                "index": 0
            }]
        })))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let result = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert_eq!(result.candidates.len(), 1);
    assert!(result.usage_metadata.is_none());
    let usage = client.get_usage();
    assert_eq!(usage.input_tokens, 0, "no usage metadata means 0 tokens");
    assert_eq!(usage.output_tokens, 0);
    assert_eq!(usage.requests_total, 1);
}

/// generate_content with empty candidates list.
#[fcp_async_core::runtime::test]
async fn generate_content_empty_candidates() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 0,
                "totalTokenCount": 5
            }
        })))
        .mount(&mock_server)
        .await;

    let client = GoogleAiClient::new("test-key")
        .unwrap()
        .with_base_url(&format!("{}/v1beta", mock_server.uri()));

    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let result = client
        .generate_content("gemini-2.0-flash", &body)
        .await
        .unwrap();

    assert!(result.candidates.is_empty());
    assert_eq!(
        result.usage_metadata.as_ref().unwrap().prompt_token_count,
        5
    );
}

// ============================================================================
// Invoke without handshake
// ============================================================================

/// Invoke without prior handshake returns NotConfigured.
#[fcp_async_core::runtime::test]
async fn invoke_without_handshake_returns_not_configured() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-2.0-flash:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response("ok", 1, 1)))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    // Deliberately skip handshake

    // Build a dummy token
    let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "invoke without handshake should fail");
    assert!(
        matches!(result.unwrap_err(), FcpError::NotConfigured),
        "expected NotConfigured"
    );
}

// ============================================================================
// Unknown operation tests
// ============================================================================

/// Invoke with unknown operation returns OperationNotGranted.
#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_returns_not_granted() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.nonexistent_op"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.nonexistent_op",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.nonexistent_op",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::OperationNotGranted { operation } => {
            assert_eq!(operation, "google-ai.nonexistent_op");
        }
        e => panic!("expected OperationNotGranted, got: {e:?}"),
    }
}

// ============================================================================
// Custom model parameter tests
// ============================================================================

/// generate_content with a custom model name uses that model.
#[fcp_async_core::runtime::test]
async fn invoke_generate_content_custom_model() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/models/gemini-1.5-pro:generateContent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_response(
            "custom model",
            10,
            5,
        )))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.generate_content"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.generate_content",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.generate_content",
            "input": {
                "model": "gemini-1.5-pro",
                "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["provenance"]["model"], "gemini-1.5-pro");
}

/// list_models with page_size parameter.
#[fcp_async_core::runtime::test]
async fn invoke_list_models_with_page_size() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1beta/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "models": [{"name": "models/gemini-2.0-flash"}],
            "nextPageToken": "page2"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.list_models"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.list_models",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.list_models",
            "input": {"page_size": 1},
            "capability_token": token
        }))
        .await
        .unwrap();

    let models = result["models"].as_array().unwrap();
    assert_eq!(models.len(), 1);
    assert!(result["nextPageToken"].is_string());
}

/// google-ai.tuning.create returns a long-running operation with provenance.
#[fcp_async_core::runtime::test]
async fn invoke_tuning_create_returns_operation() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1beta/tunedModels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "tunedModels/support-bot/operations/op-123",
            "done": false,
            "metadata": { "state": "PENDING" }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.tuning"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.tuning.create",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.tuning.create",
            "input": {
                "tuned_model_id": "support-bot",
                "source_model": "models/gemini-1.5-flash-001",
                "tuning_task": {
                    "training_data": {
                        "examples": [
                            {
                                "text_input": "refund request",
                                "output": "billing"
                            }
                        ]
                    }
                }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["name"], "tunedModels/support-bot/operations/op-123");
    assert_eq!(result["provenance"]["action"], "tuning.create");
}

/// google-ai.tuning.cancel returns a structured cancel acknowledgement.
#[fcp_async_core::runtime::test]
async fn invoke_tuning_cancel_returns_acknowledgement() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/v1beta/tunedModels/support-bot/operations/op-123:cancel",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.tuning"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.tuning.cancel",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.tuning.cancel",
            "input": {
                "operation": "tunedModels/support-bot/operations/op-123"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["status"], "cancel_requested");
    assert_eq!(
        result["operation"],
        "tunedModels/support-bot/operations/op-123"
    );
}

/// google-ai.live.create_browser_session mints a constrained v1alpha Live token.
#[fcp_async_core::runtime::test]
async fn invoke_live_create_browser_session_returns_redaction_safe_contract() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1alpha/auth_tokens"))
        .and(query_param("key", "test-key-xyz"))
        .and(body_partial_json(json!({
            "uses": 1,
            "expireTime": "2026-05-05T20:30:00Z",
            "newSessionExpireTime": "2026-05-05T20:01:00Z",
            "bidiGenerateContentSetup": {
                "model": "models/gemini-live-test",
                "generationConfig": {
                    "responseModalities": ["AUDIO"],
                    "speechConfig": {
                        "voiceConfig": {
                            "prebuiltVoiceConfig": {
                                "voiceName": "Kore"
                            }
                        }
                    },
                    "temperature": 0.3
                },
                "inputAudioTranscription": {},
                "outputAudioTranscription": {},
                "sessionResumption": {},
                "contextWindowCompression": {
                    "slidingWindow": {}
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "auth_tokens/browser-session"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GoogleAiConnector::new();
    setup_configure(&mut connector, &format!("{}/v1beta", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["google-ai.live_voice"]).await;
    let token = generate_valid_token(
        &signing_key,
        "google-ai.live.create_browser_session",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "google-ai.live.create_browser_session",
            "input": {
                "model": "gemini-live-test",
                "voice": "Kore",
                "temperature": 0.3,
                "instructions": "Speak briefly.",
                "expire_time": "2026-05-05T20:30:00Z",
                "new_session_expire_time": "2026-05-05T20:01:00Z"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["provider"], "google");
    assert_eq!(result["protocol"], "google-live-bidi");
    assert_eq!(result["clientSecret"], "auth_tokens/browser-session");
    assert_eq!(
        result["websocketUrl"],
        "wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1alpha.GenerativeService.BidiGenerateContentConstrained"
    );
    assert_eq!(result["audio"]["inputSampleRateHz"], 16_000);
    assert_eq!(result["audio"]["outputSampleRateHz"], 24_000);
    assert_eq!(
        result["initialMessage"]["setup"]["model"],
        "models/gemini-live-test"
    );
    assert_eq!(
        result["provenance"]["action"],
        "live.create_browser_session"
    );
    assert_eq!(result["provenance"]["client_secret_redacted_in_logs"], true);
    assert_eq!(result["expiresAt"], 1_778_013_000);
}

/// Realtime Live loopback exercises the WebSocket lifecycle without mocking the transport.
#[fcp_async_core::runtime::test]
async fn live_realtime_loopback_covers_lifecycle_audio_tools_and_jsonl() {
    let live_credential = "live-credential-redacted";
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind live loopback");
    let addr = listener.local_addr().expect("live loopback addr");
    let server_task = task::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept live loopback");
        let (request, mut ws) = accept_live_websocket(stream).await;
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: token live-credential-redacted"),
            "ephemeral token must be sent with Token auth scheme"
        );

        let setup = recv_live_json(&mut ws, "initial setup").await;
        assert_eq!(
            setup["setup"]["model"],
            "models/gemini-2.5-flash-native-audio-preview-12-2025"
        );
        send_live_json(&mut ws, json!({ "setupComplete": {} }), "setup complete").await;

        let first_audio = recv_live_json(&mut ws, "first audio").await;
        assert_eq!(
            first_audio["realtimeInput"]["audio"]["mimeType"],
            "audio/pcm;rate=16000"
        );
        assert!(
            first_audio["realtimeInput"]["audio"]["data"]
                .as_str()
                .is_some_and(|data| !data.is_empty())
        );
        let silence_audio = recv_live_json(&mut ws, "silence audio").await;
        assert_eq!(
            silence_audio["realtimeInput"]["audio"]["mimeType"],
            "audio/pcm;rate=16000"
        );
        let audio_stream_end = recv_live_json(&mut ws, "audio stream end").await;
        assert_eq!(audio_stream_end["realtimeInput"]["audioStreamEnd"], true);
        let client_content = recv_live_json(&mut ws, "client content").await;
        assert_eq!(
            client_content["clientContent"]["turns"][0]["parts"][0]["text"],
            "Start the call"
        );
        assert_eq!(client_content["clientContent"]["turnComplete"], true);

        send_live_json(
            &mut ws,
            json!({
                "sessionResumptionUpdate": {
                    "resumable": true,
                    "newHandle": "resume-handle-1"
                }
            }),
            "session resumption update",
        )
        .await;
        send_live_json(
            &mut ws,
            json!({
                "serverContent": {
                    "interrupted": true,
                    "inputTranscription": {
                        "text": "hello",
                        "finished": true
                    },
                    "outputTranscription": {
                        "text": "hi there",
                        "finished": true
                    },
                    "modelTurn": {
                        "parts": [
                            {
                                "inlineData": {
                                    "mimeType": "audio/pcm;rate=24000",
                                    "data": BASE64_STANDARD.encode([0_u8, 0_u8, 1, 0])
                                }
                            },
                            { "text": "Visible assistant text" },
                            { "text": "private thought", "thought": true }
                        ]
                    },
                    "turnComplete": true,
                    "waitingForInput": false
                }
            }),
            "server content",
        )
        .await;
        send_live_json(
            &mut ws,
            json!({ "toolCallCancellation": { "ids": ["cancelled-call"] } }),
            "tool call cancellation",
        )
        .await;
        send_live_json(
            &mut ws,
            json!({
                "toolCall": {
                    "functionCalls": [{
                        "id": "call-1",
                        "name": "openclaw_agent_consult",
                        "args": { "question": "status" }
                    }]
                }
            }),
            "tool call",
        )
        .await;

        let tool_response = recv_live_json(&mut ws, "tool response").await;
        let response = &tool_response["toolResponse"]["functionResponses"][0];
        assert_eq!(response["id"], "call-1");
        assert_eq!(response["name"], "openclaw_agent_consult");
        assert_eq!(response["scheduling"], "WHEN_IDLE");
        assert_eq!(response["response"]["ok"], true);

        send_live_json(
            &mut ws,
            json!({ "goAway": { "timeLeft": "30s" } }),
            "go away",
        )
        .await;
        close_live_websocket(&mut ws).await;
    });

    let report = run_google_live_realtime_session(
        GoogleLiveRealtimeSessionConfig::new(
            format!("ws://{addr}"),
            live_credential,
            json!({
                "setup": {
                    "model": "models/gemini-2.5-flash-native-audio-preview-12-2025",
                    "generationConfig": {
                        "responseModalities": ["AUDIO"]
                    },
                    "inputAudioTranscription": {},
                    "outputAudioTranscription": {},
                    "sessionResumption": {},
                    "contextWindowCompression": {
                        "slidingWindow": {}
                    }
                }
            }),
        )
        .with_audio_chunks(vec![
            GoogleLiveRealtimeAudioChunk::g711_ulaw(8_000, [0x00, 0xff]),
            GoogleLiveRealtimeAudioChunk::g711_ulaw(8_000, vec![0xff; 8]),
        ])
        .with_user_messages(vec!["Start the call".into()])
        .with_silence_stream_end_ms(1)
        .with_total_timeout(StdDuration::from_secs(5)),
    )
    .await
    .expect("live realtime loopback succeeds");
    server_task.await.expect("live server task");

    assert_eq!(report.outcome, "completed");
    assert!(report.ready);
    assert_eq!(report.pending_audio_queued, 2);
    assert_eq!(report.pending_audio_drained, 2);
    assert_eq!(report.audio_frames_sent, 2);
    assert!(report.audio_stream_end_sent);
    assert_eq!(report.tool_calls, vec!["call-1"]);
    assert_eq!(report.cancelled_tool_calls, vec!["cancelled-call"]);
    assert_eq!(report.resumption_handle.as_deref(), Some("resume-handle-1"));
    assert_eq!(report.go_away_time_left.as_deref(), Some("30s"));
    assert_realtime_report_has_steps(
        &report,
        &[
            "setup_complete",
            "pending_audio_drained",
            "audio_stream_end_sent",
            "client_content_sent",
            "playback_cleared",
            "transcript",
            "server_audio",
            "assistant_text",
            "tool_call_cancellation",
            "tool_call",
            "tool_response_sent",
            "session_resumption_update",
            "go_away",
            "bounded_shutdown",
        ],
    );
    assert_redacted_realtime_jsonl(
        &report,
        &[live_credential, "Visible assistant text", "hi there"],
    );

    let resume_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind live resume loopback");
    let resume_addr = resume_listener.local_addr().expect("resume addr");
    let resume_task = task::spawn(async move {
        let (stream, _) = resume_listener.accept().await.expect("accept resume");
        let (_request, mut ws) = accept_live_websocket(stream).await;
        let setup = recv_live_json(&mut ws, "resume setup").await;
        assert_eq!(
            setup["setup"]["sessionResumption"]["handle"],
            "resume-handle-1"
        );
        send_live_json(
            &mut ws,
            json!({ "setupComplete": {} }),
            "resume setup complete",
        )
        .await;
        close_live_websocket(&mut ws).await;
    });
    let resume_report = run_google_live_realtime_session(
        GoogleLiveRealtimeSessionConfig::new(
            format!("ws://{resume_addr}"),
            live_credential,
            json!({
                "setup": {
                    "model": "models/gemini-2.5-flash-native-audio-preview-12-2025",
                    "generationConfig": {
                        "responseModalities": ["AUDIO"]
                    },
                    "sessionResumption": {
                        "handle": report.resumption_handle.expect("resumption handle")
                    }
                }
            }),
        )
        .with_total_timeout(StdDuration::from_secs(5)),
    )
    .await
    .expect("resume loopback succeeds");
    resume_task.await.expect("resume server task");
    assert_eq!(resume_report.outcome, "completed");
    assert!(resume_report.ready);
    assert_redacted_realtime_jsonl(&resume_report, &[live_credential]);
}

/// Error-path realtime loopbacks stay bounded and produce redacted JSONL evidence.
#[fcp_async_core::runtime::test]
async fn live_realtime_loopback_covers_auth_malformed_and_pending_bounds() {
    let auth_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind auth loopback");
    let auth_addr = auth_listener.local_addr().expect("auth addr");
    let auth_task = task::spawn(async move {
        let (stream, _) = auth_listener.accept().await.expect("accept auth");
        let (_request, mut ws) = accept_live_websocket(stream).await;
        let _setup = recv_live_json(&mut ws, "auth setup").await;
        send_live_json(
            &mut ws,
            json!({
                "error": {
                    "code": 401,
                    "message": "bad ephemeral credential",
                    "status": "UNAUTHENTICATED"
                }
            }),
            "auth failure",
        )
        .await;
        close_live_websocket(&mut ws).await;
    });
    let auth_report = run_google_live_realtime_session(
        GoogleLiveRealtimeSessionConfig::new(
            format!("ws://{auth_addr}"),
            "bad-live-credential",
            json!({
                "setup": {
                    "model": "models/gemini-live-test",
                    "generationConfig": {
                        "responseModalities": ["AUDIO"]
                    }
                }
            }),
        )
        .with_total_timeout(StdDuration::from_secs(5)),
    )
    .await
    .expect("auth loopback returns evidence report");
    auth_task.await.expect("auth task");
    assert_eq!(auth_report.outcome, "auth_failure");
    assert_realtime_report_has_steps(&auth_report, &["auth_failure"]);
    assert_redacted_realtime_jsonl(&auth_report, &["bad-live-credential"]);

    let malformed_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind malformed loopback");
    let malformed_addr = malformed_listener.local_addr().expect("malformed addr");
    let malformed_task = task::spawn(async move {
        let (stream, _) = malformed_listener.accept().await.expect("accept malformed");
        let (_request, mut ws) = accept_live_websocket(stream).await;
        let _setup = recv_live_json(&mut ws, "malformed setup").await;
        send_live_text(&mut ws, "{not-json", "malformed frame").await;
        close_live_websocket(&mut ws).await;
    });
    let malformed_report = run_google_live_realtime_session(
        GoogleLiveRealtimeSessionConfig::new(
            format!("ws://{malformed_addr}"),
            "malformed-live-credential",
            json!({
                "setup": {
                    "model": "models/gemini-live-test",
                    "generationConfig": {
                        "responseModalities": ["AUDIO"]
                    }
                }
            }),
        )
        .with_total_timeout(StdDuration::from_secs(5)),
    )
    .await
    .expect("malformed loopback returns evidence report");
    malformed_task.await.expect("malformed task");
    assert_eq!(malformed_report.outcome, "malformed_frame");
    assert_realtime_report_has_steps(&malformed_report, &["malformed_frame"]);
    assert_redacted_realtime_jsonl(&malformed_report, &["malformed-live-credential"]);

    let mut bounded_config = GoogleLiveRealtimeSessionConfig::new(
        "ws://127.0.0.1:9",
        "pending-bound-credential",
        json!({
            "setup": {
                "model": "models/gemini-live-test",
                "generationConfig": {
                    "responseModalities": ["AUDIO"]
                }
            }
        }),
    )
    .with_audio_chunks(vec![
        GoogleLiveRealtimeAudioChunk::pcm16(16_000, [1, 0]),
        GoogleLiveRealtimeAudioChunk::pcm16(16_000, [2, 0]),
    ]);
    bounded_config.max_pending_audio_chunks = 1;
    let bounded_report = run_google_live_realtime_session(bounded_config)
        .await
        .expect("pending bound returns evidence report");
    assert_eq!(bounded_report.outcome, "pending_audio_bound_exceeded");
    assert_realtime_report_has_steps(&bounded_report, &["pending_audio_bound"]);
    assert_redacted_realtime_jsonl(&bounded_report, &["pending-bound-credential"]);
}
