//! V3 ConnectorRuntime lifecycle E2E tests.
//!
//! Validates the full retry/timeout/shutdown lifecycle of the
//! Anthropic connector through the V3 `ConnectorRuntime` + `RetryLoop`
//! machinery in `fcp-sdk::migration`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fcp_anthropic::client::AnthropicClient;
use fcp_anthropic::error::AnthropicError;
use fcp_anthropic::types::Model;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig, RetryLoop,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// ============================================================================
// Custom responders
// ============================================================================

/// Returns a 502 on the first request (retryable server error with no
/// `retry_after` hint, so the fast backoff config applies), then 200
/// with a valid Anthropic messages response on subsequent requests.
struct TransientThen200 {
    counter: Arc<AtomicUsize>,
}

impl TransientThen200 {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        Self { counter }
    }
}

impl Respond for TransientThen200 {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let attempt = self.counter.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            // 429 triggers RateLimited with a hardcoded 30s retry_after,
            // which would make the test slow. Use 502 instead: it produces
            // an Api error with is_retryable=true and retry_after=None,
            // so the RetryLoop falls back to the configured fast backoff.
            ResponseTemplate::new(502).set_body_json(json!({
                "error": {
                    "type": "api_error",
                    "message": "Bad Gateway"
                }
            }))
        } else {
            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Hello"}],
                "model": "claude-3-opus-20240229",
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": {"input_tokens": 10, "output_tokens": 5}
            }))
        }
    }
}

/// Always returns 502 (retryable server error without a retry_after hint).
struct AlwaysTransient {
    counter: Arc<AtomicUsize>,
}

impl AlwaysTransient {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        Self { counter }
    }
}

impl Respond for AlwaysTransient {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.counter.fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(502).set_body_json(json!({
            "error": {
                "type": "api_error",
                "message": "Bad Gateway"
            }
        }))
    }
}

// ============================================================================
// Tests
// ============================================================================

/// E2E: Client retries on a transient 502, succeeds on the second attempt.
///
/// Flow: wiremock returns 502 on the first request, then 200 on the second.
/// The `RetryLoop` inside `AnthropicClient::post` should transparently
/// retry and surface the successful response.
///
/// Uses 502 rather than 429 because Anthropic's `parse_error_response`
/// hardcodes a 30s `retry_after` on 429/RateLimited, which would make the
/// test slow. Status 502 is equally retryable but falls back to the fast
/// backoff config we supply.
#[fcp_async_core::test]
async fn e2e_retry_on_429() {
    let mock_server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(TransientThen200::new(Arc::clone(&counter)))
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        // Fast retries: 2 retries max, 10ms initial delay, 100ms cap
        .with_retry_config(2, 10, 100);

    let response = client
        .chat(Model::ClaudeSonnet4, "Hi", None, 1024)
        .await
        .expect("should succeed after retry");

    assert_eq!(response, "Hello");
    // Verify wiremock received exactly 2 requests (1 failure + 1 success)
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

/// E2E: Client exhausts all retries when the server persistently fails.
///
/// With max_retries=2, the RetryLoop makes up to 3 total attempts
/// (1 initial + 2 retries). All return 502, a retryable status code,
/// so the loop exhausts and surfaces the last error.
#[fcp_async_core::test]
async fn e2e_retry_exhaustion() {
    let mock_server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(AlwaysTransient::new(Arc::clone(&counter)))
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        // 2 retries, fast backoff to keep the test quick
        .with_retry_config(2, 10, 50);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;

    assert!(result.is_err(), "should fail after retry exhaustion");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            AnthropicError::Api {
                status_code: Some(502),
                ..
            }
        ),
        "expected Api error with status 502, got: {err:?}"
    );
    // 1 initial + 2 retries = 3 total attempts
    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

/// E2E: A short `ExecutionContext` deadline enforces timeout instead of
/// allowing the operation to hang.
///
/// Creates a `ConnectorRuntime` with a 100ms request timeout and executes
/// a `RetryLoop` whose operation sleeps for 5 seconds. The context deadline
/// fires during the sleep, proving the V3 deadline enforcement path works.
///
/// This tests the runtime + RetryLoop layer directly rather than going
/// through the HTTP client, because `AnthropicClient::new` hardcodes a
/// 120s reqwest timeout that cannot be overridden from the public API.
/// The `RetryLoop` + `ExecutionContext` is the V3 deadline enforcement
/// mechanism and is the correct layer to test.
#[fcp_async_core::test]
async fn e2e_deadline_enforcement() {
    let runtime = ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(100)),
    );

    let ctx = runtime.request_context();

    let start = std::time::Instant::now();

    // Execute a RetryLoop where each attempt "hangs" (sleeps 5s).
    // The 100ms context deadline should cancel the sleep.
    let result: Result<(), AnthropicError> =
        RetryLoop::execute(&ctx, &fcp_sdk::migration::HttpRetryConfig::default().to_retry_policy(), |_attempt| async {
            // Simulate a slow operation by sleeping under the context.
            // The context's 100ms deadline will fire, returning an error.
            match ctx.sleep(Duration::from_secs(5)).await {
                Ok(()) => AttemptOutcome::Success(()),
                Err(async_err) => {
                    AttemptOutcome::Terminal(AnthropicError::from_async_error(async_err))
                }
            }
        })
        .await;

    let elapsed = start.elapsed();

    assert!(result.is_err(), "should timeout, not succeed");
    let err = result.unwrap_err();
    // The error should indicate a deadline timeout or cancellation
    let err_str = err.to_string();
    assert!(
        err_str.contains("deadline") || err_str.contains("timeout") || err_str.contains("cancelled"),
        "expected timeout/deadline error, got: {err_str}"
    );

    // Verify it completed quickly (well under the 5s simulated delay)
    assert!(
        elapsed < Duration::from_secs(2),
        "should not wait for 5s simulated delay; elapsed: {elapsed:?}"
    );
}

/// E2E: ConnectorRuntime graceful shutdown cancels background contexts.
///
/// Creates a runtime, obtains a background context, calls shutdown(), and
/// verifies that `is_shutting_down()` returns true and the background
/// context is cancelled. No HTTP needed.
#[fcp_async_core::test]
async fn e2e_graceful_shutdown() {
    let runtime = ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(5)),
    );

    // Obtain contexts before shutdown
    let bg_ctx = runtime.background_context();
    let req_ctx = runtime.request_context();

    // Pre-shutdown: nothing is cancelled
    assert!(
        !runtime.is_shutting_down(),
        "runtime should not be shutting down before shutdown()"
    );
    assert!(
        !bg_ctx.is_cancelled(),
        "background context should not be cancelled before shutdown"
    );
    assert!(
        !req_ctx.is_cancelled(),
        "request context should not be cancelled before shutdown"
    );

    // Trigger graceful shutdown
    runtime.shutdown();

    // Post-shutdown: runtime reports shutting down
    assert!(
        runtime.is_shutting_down(),
        "runtime should report shutting down after shutdown()"
    );

    // Background context derived from the runtime's root is now cancelled
    assert!(
        bg_ctx.is_cancelled(),
        "background context should be cancelled after shutdown"
    );

    // Calling shutdown again is idempotent
    runtime.shutdown();
    assert!(runtime.is_shutting_down());
    assert!(bg_ctx.is_cancelled());

    // New background contexts obtained after shutdown are also cancelled
    let bg_ctx_post = runtime.background_context();
    assert!(
        bg_ctx_post.is_cancelled(),
        "background context created after shutdown should be cancelled"
    );
}
