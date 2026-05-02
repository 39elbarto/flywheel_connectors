//! Wolfram Alpha HTTP client with bounded retry budget.
//!
//! Bead: `flywheel_connectors-0a9hv` (H.2 production hardening). The
//! historical implementation carried `ConnectorRuntime` +
//! `HttpRetryConfig` fields but performed a single `reqwest::send()`
//! per query — the retry config was dead code and transient
//! 429/5xx/connect failures had no bounded retry budget. This module
//! integrates [`RetryLoop`] from `fcp-sdk::migration` so each public
//! method wraps the HTTP call in the canonical retry-budget pattern,
//! respects `Retry-After` headers, and surfaces structured terminal
//! errors on 4xx (other than 429).
//!
//! ## Retry classification
//!
//! | HTTP status / error class    | Outcome              | Notes                          |
//! |------------------------------|----------------------|--------------------------------|
//! | 200 OK                       | `Success(parsed)`    |                                |
//! | 429 Too Many Requests        | `Retryable`          | Honors `Retry-After` header    |
//! | 500-599                      | `Retryable`          | Default backoff per policy     |
//! | 408 Request Timeout          | `Retryable`          | Treated as transient           |
//! | 401 / 403                    | `Terminal`           | Auth failure — no retry        |
//! | 404                          | `Terminal`           | Resource missing — no retry    |
//! | other 4xx                    | `Terminal`           | Client error — no retry        |
//! | reqwest connect/timeout err  | `Retryable`          | Network glitch — retry         |
//! | reqwest other err            | `Terminal`           | Unrecoverable transport        |
//!
//! After `HttpRetryConfig::max_retries` retries are exhausted the
//! last error surfaces unchanged.

use std::time::Duration;

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
    classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use serde_json::json;
use tracing::{info, warn};

use crate::error::WolframError;
use crate::types::{QueryResult, WolframConfig};

/// Wolfram Alpha API client.
pub struct WolframClient {
    client: reqwest::Client,
    base_url: String,
    timeout: Duration,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl WolframClient {
    /// Create a new Wolfram Alpha client.
    #[must_use]
    pub fn new(config: &WolframConfig) -> Self {
        let base_url =
            if config.base_url.starts_with("http://") || config.base_url.starts_with("https://") {
                config.base_url.clone()
            } else {
                format!("https://{}", config.base_url)
            };
        let timeout = Duration::from_millis(config.timeout_ms);
        Self {
            client: reqwest::Client::new(),
            base_url,
            timeout,
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Create a client with a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            timeout: Duration::from_secs(30),
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Create a client with a custom base URL AND custom retry
    /// config (test seam — production callers should use
    /// [`Self::new`] with a `WolframConfig`). Used by the
    /// retry-budget tests to exercise the loop with `max_retries=0`
    /// for fast deterministic terminal-on-first-failure assertions
    /// AND with `max_retries=N` for retry-then-succeed scenarios.
    #[must_use]
    pub fn with_base_url_and_retry(base_url: String, retry_config: HttpRetryConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            timeout: Duration::from_secs(30),
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config,
        }
    }

    /// Perform a full query against the Wolfram Alpha API.
    pub async fn query(&self, input: &str, app_id: &str) -> Result<QueryResult, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v2/query", self.base_url);
        info!(
            input_len = input.chars().count(),
            "Wolfram Alpha full query"
        );

        let value: serde_json::Value = self
            .send_with_retry(&url, &[
                ("input", input.to_string()),
                ("appid", app_id.to_string()),
                ("output", "json".to_string()),
                ("format", "plaintext,image".to_string()),
            ], ResponseShape::Json)
            .await?;

        // Wolfram wraps the result in a "queryresult" key.
        let query_result = value
            .get("queryresult")
            .cloned()
            .unwrap_or(value);

        serde_json::from_value(query_result).map_err(|e| WolframError::Serialization(e.to_string()))
    }

    /// Get a short text answer from Wolfram Alpha.
    pub async fn short_answer(
        &self,
        input: &str,
        app_id: &str,
    ) -> Result<serde_json::Value, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v1/result", self.base_url);
        info!(
            input_len = input.chars().count(),
            "Wolfram Alpha short answer"
        );

        let text: String = self
            .send_with_retry(
                &url,
                &[("i", input.to_string()), ("appid", app_id.to_string())],
                ResponseShape::Text,
            )
            .await?;
        Ok(json!({ "answer": text }))
    }

    /// Get a spoken-word text answer from Wolfram Alpha.
    pub async fn spoken_result(
        &self,
        input: &str,
        app_id: &str,
    ) -> Result<serde_json::Value, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v1/spoken", self.base_url);
        info!(
            input_len = input.chars().count(),
            "Wolfram Alpha spoken result"
        );

        let text: String = self
            .send_with_retry(
                &url,
                &[("i", input.to_string()), ("appid", app_id.to_string())],
                ResponseShape::Text,
            )
            .await?;
        Ok(json!({ "spoken": text }))
    }

    /// Health check — single connectivity probe with no retry budget.
    /// Health is meant to fail fast on transient unavailability so
    /// the connector can be marked degraded immediately; retrying
    /// would mask the very condition health-check is designed to
    /// surface.
    pub async fn health_check(&self) -> Result<(), WolframError> {
        let url = format!("{}/v1/result", self.base_url);
        let resp = self
            .client
            .get(&url)
            .query(&[("i", "1+1"), ("appid", "DEMO")])
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(WolframError::Http)?;
        let _status = resp.status();
        Ok(())
    }

    /// Internal: send a GET with the retry-budget pattern.
    ///
    /// `shape` controls how the success body is interpreted —
    /// JSON for `/v2/query`, raw text for the `/v1/result` and
    /// `/v1/spoken` endpoints. The return type is generic over
    /// the deserialized representation so callers can pick the
    /// shape per endpoint.
    async fn send_with_retry<T: ResponseDeserialize>(
        &self,
        url: &str,
        query: &[(&str, String)],
        shape: ResponseShape,
    ) -> Result<T, WolframError> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        // reqwest query params must be `&[(&str, &str)]`-shaped at
        // call time. Snapshot the values into owned Strings the
        // closure can re-take per attempt.
        let query: Vec<(&'static str, String)> = query
            .iter()
            .map(|(k, v)| (Self::query_key_static(k), v.clone()))
            .collect();
        let timeout = self.timeout;

        RetryLoop::execute(&ctx, &policy, move |attempt| {
            let url = url.clone();
            let query = query.clone();
            let client = self.client.clone();
            async move {
                tracing::debug!(attempt, "Wolfram retry-budget attempt");
                let resp = match client
                    .get(&url)
                    .query(&query)
                    .timeout(timeout)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        if e.is_timeout() || e.is_connect() {
                            return AttemptOutcome::Retryable {
                                error: WolframError::Http(e),
                                retry_after: None,
                            };
                        }
                        return AttemptOutcome::Terminal(WolframError::Http(e));
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: WolframError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis()
                                as u64,
                        },
                        retry_after,
                    };
                }

                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    warn!(status_code = status, "Wolfram Alpha request failed");
                    let decision = classify_http_status(status, None);
                    let err = WolframError::Api {
                        status_code: status,
                        message: body,
                    };
                    return match decision {
                        RetryDecision::Terminal => AttemptOutcome::Terminal(err),
                        _ => AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        },
                    };
                }

                match T::from_response(resp, shape).await {
                    Ok(v) => AttemptOutcome::Success(v),
                    Err(e) => AttemptOutcome::Terminal(e),
                }
            }
        })
        .await
    }

    /// Map a small fixed set of query-parameter names onto static
    /// string slices so the per-attempt query Vec can carry
    /// `&'static str` keys (which reqwest's query() needs to
    /// borrow) while values stay owned. Wolfram's parameter set is
    /// closed (`input`, `appid`, `output`, `format`, `i`) so this
    /// is safe; an unknown key panics so the constraint is visible.
    const fn query_key_static(name: &str) -> &'static str {
        // const-context byte comparison (no string ops in const fn yet
        // for stable nightly comparisons of &str).
        let bytes = name.as_bytes();
        match bytes {
            b"input" => "input",
            b"appid" => "appid",
            b"output" => "output",
            b"format" => "format",
            b"i" => "i",
            _ => panic!("unsupported wolfram query key — extend query_key_static"),
        }
    }
}

/// Indicates how to interpret the response body.
#[derive(Debug, Clone, Copy)]
enum ResponseShape {
    Json,
    Text,
}

/// Trait for parsing the response body into the caller's expected
/// shape. Implemented for `serde_json::Value` (JSON endpoints) and
/// `String` (text endpoints). The trait is sealed by living in this
/// module — external impls would need to add another shape variant.
trait ResponseDeserialize: Sized {
    fn from_response(
        resp: reqwest::Response,
        shape: ResponseShape,
    ) -> impl std::future::Future<Output = Result<Self, WolframError>> + Send;
}

impl ResponseDeserialize for serde_json::Value {
    async fn from_response(
        resp: reqwest::Response,
        shape: ResponseShape,
    ) -> Result<Self, WolframError> {
        match shape {
            ResponseShape::Json => resp.json().await.map_err(WolframError::Http),
            ResponseShape::Text => Err(WolframError::Internal {
                message: "JSON deserializer used with Text shape".into(),
            }),
        }
    }
}

impl ResponseDeserialize for String {
    async fn from_response(
        resp: reqwest::Response,
        shape: ResponseShape,
    ) -> Result<Self, WolframError> {
        match shape {
            ResponseShape::Text => resp.text().await.map_err(WolframError::Http),
            ResponseShape::Json => Err(WolframError::Internal {
                message: "Text deserializer used with JSON shape".into(),
            }),
        }
    }
}

impl std::fmt::Debug for WolframClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WolframClient")
            .field("base_url", &self.base_url)
            .field("max_retries", &self.retry_config.max_retries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Test helper: zero-retry config so terminal-on-first-failure
    /// tests don't sleep through retry backoff.
    fn no_retry() -> HttpRetryConfig {
        HttpRetryConfig {
            max_retries: 0,
            ..HttpRetryConfig::default()
        }
    }

    /// Test helper: fast-retry config (small backoff) for retry-then-
    /// succeed tests so the suite stays under a second.
    fn fast_retry(max: u32) -> HttpRetryConfig {
        HttpRetryConfig {
            max_retries: max,
            initial_delay_ms: 5,
            max_delay_ms: 20,
            jitter_enabled: false,
            ..HttpRetryConfig::default()
        }
    }

    #[fcp_async_core::runtime::test]
    async fn query_success() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "queryresult": {
                "success": true,
                "numpods": 1,
                "pods": [{
                    "title": "Result",
                    "id": "Result",
                    "primary": true,
                    "subpods": [{"plaintext": "4"}]
                }],
                "assumptions": []
            }
        });

        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .and(query_param("input", "2+2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let result = client.query("2+2", "test-app-id").await.expect("query");
        assert!(result.success);
        assert_eq!(result.pods[0].subpods[0].plaintext.as_deref(), Some("4"));
    }

    #[fcp_async_core::runtime::test]
    async fn query_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.query("", "test").await.unwrap_err();
        assert!(matches!(err, WolframError::InvalidInput { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn short_answer_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .and(query_param("i", "population of France"))
            .respond_with(ResponseTemplate::new(200).set_body_string("67.39 million people"))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let result = client
            .short_answer("population of France", "test-id")
            .await
            .expect("short answer");
        assert_eq!(result["answer"], "67.39 million people");
    }

    #[fcp_async_core::runtime::test]
    async fn spoken_result_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/spoken"))
            .respond_with(ResponseTemplate::new(200).set_body_string("The answer is 4"))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let result = client
            .spoken_result("what is 2+2", "test-id")
            .await
            .expect("spoken");
        assert_eq!(result["spoken"], "The answer is 4");
    }

    // ── Retry-budget contract tests (0a9hv) ───────────────────────────

    #[fcp_async_core::runtime::test]
    async fn terminal_on_403_no_retry_consumed() {
        // 403 is terminal — must NOT consume retry budget. Use
        // no_retry() so we'd see if the loop tried to retry.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .expect(1) // Pin: exactly one request, no retries.
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url_and_retry(server.uri(), no_retry());
        let err = client.query("test", "bad-id").await.unwrap_err();
        match err {
            WolframError::Api { status_code, .. } => assert_eq!(status_code, 403),
            other => panic!("expected Api 403, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn retries_on_503_then_succeeds() {
        // 503 is retryable. First attempt 503, subsequent attempts
        // succeed. With max_retries=2 the budget allows up to 3
        // attempts total — the second one succeeds.
        let server = MockServer::start().await;
        let counter = Arc::new(AtomicUsize::new(0));

        struct FlakyResponder {
            counter: Arc<AtomicUsize>,
        }
        impl Respond for FlakyResponder {
            fn respond(&self, _: &Request) -> ResponseTemplate {
                let n = self.counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(503).set_body_string("Service Unavailable")
                } else {
                    ResponseTemplate::new(200).set_body_string("OK")
                }
            }
        }
        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .respond_with(FlakyResponder {
                counter: counter.clone(),
            })
            .expect(2) // 1 503 + 1 success.
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(2));
        let result = client
            .short_answer("test", "test-id")
            .await
            .expect("eventually succeeds");
        assert_eq!(result["answer"], "OK");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn retries_on_429_then_succeeds_honoring_retry_after() {
        // 429 with a Retry-After header. First attempt 429,
        // second attempt 200.
        let server = MockServer::start().await;
        let counter = Arc::new(AtomicUsize::new(0));

        struct RateLimitResponder {
            counter: Arc<AtomicUsize>,
        }
        impl Respond for RateLimitResponder {
            fn respond(&self, _: &Request) -> ResponseTemplate {
                let n = self.counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(429)
                        .insert_header("retry-after", "0")
                        .set_body_string("Too Many Requests")
                } else {
                    ResponseTemplate::new(200).set_body_string("after backoff")
                }
            }
        }
        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .respond_with(RateLimitResponder {
                counter: counter.clone(),
            })
            .expect(2)
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(2));
        let result = client
            .short_answer("rate-limited", "test-id")
            .await
            .expect("eventually succeeds");
        assert_eq!(result["answer"], "after backoff");
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_exhaustion_returns_rate_limited_error() {
        // Mock always returns 429. RetryLoop exhausts max_retries,
        // returns the last error (WolframError::RateLimited per the
        // 429 mapping).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "0")
                    .set_body_string("Too Many Requests"),
            )
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(1));
        let err = client.short_answer("test", "test-id").await.unwrap_err();
        match err {
            WolframError::RateLimited { .. } => (),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn server_error_exhaustion_returns_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url_and_retry(server.uri(), fast_retry(1));
        let err = client.query("test", "id").await.unwrap_err();
        match err {
            WolframError::Api {
                status_code: 503, ..
            } => (),
            other => panic!("expected Api 503, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn no_retry_budget_terminal_on_first_failure() {
        // max_retries=0 ⇒ exactly 1 attempt, retryable error
        // surfaces as the final error.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url_and_retry(server.uri(), no_retry());
        let err = client.query("test", "id").await.unwrap_err();
        assert!(matches!(
            err,
            WolframError::Api {
                status_code: 503,
                ..
            }
        ));
    }

    // ── Existing behavior preserved ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn short_answer_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.short_answer("", "test").await.unwrap_err();
        assert!(matches!(err, WolframError::InvalidInput { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn spoken_result_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.spoken_result("", "test").await.unwrap_err();
        assert!(matches!(err, WolframError::InvalidInput { .. }));
    }

    #[test]
    fn debug_redacts_nothing_sensitive() {
        let client = WolframClient::with_base_url("https://api.wolframalpha.com".into());
        let debug = format!("{client:?}");
        assert!(debug.contains("WolframClient"));
        assert!(debug.contains("api.wolframalpha.com"));
        // The retry budget should be in Debug output for operator
        // diagnostics — but no app_id or other sensitive material.
        assert!(debug.contains("max_retries"));
    }

    #[test]
    fn query_key_static_panics_on_unknown_key() {
        let result = std::panic::catch_unwind(|| WolframClient::query_key_static("evil"));
        assert!(result.is_err(), "unsupported key must panic");
    }
}
