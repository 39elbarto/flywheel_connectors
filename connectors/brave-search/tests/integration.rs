//! Brave Search connector end-to-end integration tests.
//!
//! Mock-free at the connector boundary — every test drives the real
//! `BraveSearchConnector` through its public lifecycle (configure →
//! handshake → invoke) and asserts on the real `FcpError` taxonomy.
//! HTTP is stood up via `wiremock` so the tests are deterministic and
//! hermetic; no network, no live Brave Search calls, no mocks inside
//! the crate under test.
//!
//! Coverage (mirrors the `crates/fcp-oauth/tests/no_mock_integration.rs`
//! shape):
//!   - happy path: 200 OK → JSON payload round-trips through invoke
//!   - auth error: 401 Unauthorized → FcpError::External, status=401,
//!     NOT retryable (Brave's own API returns 401 on a bad
//!     X-Subscription-Token and the connector's error mapper
//!     classifies 4xx-non-429 as non-retryable)
//!   - rate limit: 429 + Retry-After → FcpError::External,
//!     status=429, retryable=true, retry_after=Some
//!   - network timeout: configured 100ms request_timeout_ms against a
//!     1s delayed response → FcpError::UpstreamTimeout
//!
//! Structured logging: each test emits JSON-line tracing events so the
//! suite output is grep-able by test name on CI. Uses
//! `tracing-subscriber` at debug level, scoped to this test binary.

use std::sync::Once;
use std::time::Duration;

use fcp_brave_search::BraveSearchConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

const TEST_API_KEY: &str = "brave-subscription-token-for-tests";

// ─────────────────────────────────────────────────────────────────────────
// Structured logging — one JSON line per tracing event
// ─────────────────────────────────────────────────────────────────────────
static LOG_INIT: Once = Once::new();

fn init_logging() {
    LOG_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
            )
            .json()
            .with_test_writer()
            .try_init();
    });
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

/// Bring up a configured + handshaken connector pointed at the given
/// wiremock server. Uses a generous 5s timeout so happy-path tests
/// don't race the default.
async fn configured_connector(server: &MockServer) -> BraveSearchConnector {
    configured_connector_with_timeout(server, 5_000).await
}

async fn configured_connector_with_timeout(
    server: &MockServer,
    request_timeout_ms: u64,
) -> BraveSearchConnector {
    let mut connector = BraveSearchConnector::new();
    connector
        .handle_configure(json!({
            "api_key": TEST_API_KEY,
            "base_url": server.uri(),
            "request_timeout_ms": request_timeout_ms,
        }))
        .await
        .expect("configure must succeed against a wiremock server URI");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake must succeed once configured");
    connector
}

fn invoke_web_search(query: &str) -> Value {
    json!({
        "operation_id": "brave-search.web.search",
        "input": { "query": query, "count": 1 }
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Happy path: 200 OK with a realistic Brave Search response shape
// ─────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn web_search_happy_path_returns_json_payload() {
    init_logging();
    tracing::info!(test = "web_search_happy_path", "starting");

    let server = MockServer::start().await;
    // The real Brave API returns a top-level `web.results[]` object
    // among other sibling sections (news, videos, etc.). The connector
    // itself is transport-layer — it doesn't post-process — so we
    // assert the payload reaches the caller verbatim.
    Mock::given(method("GET"))
        .and(path("/web/search"))
        .and(query_param("q", "rust async"))
        .and(query_param("count", "1"))
        .and(header("X-Subscription-Token", TEST_API_KEY))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "search",
            "web": {
                "results": [{
                    "title": "Rust async book",
                    "url": "https://rust-lang.github.io/async-book/",
                    "description": "The Async Book"
                }]
            }
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let payload = connector
        .handle_invoke(invoke_web_search("rust async"))
        .await
        .expect("200 OK must decode as Ok(Value)");

    tracing::info!(
        test = "web_search_happy_path",
        payload_type = %payload["type"],
        result_count = payload["web"]["results"].as_array().map_or(0, Vec::len),
        "got response",
    );

    assert_eq!(payload["type"], "search");
    assert_eq!(payload["web"]["results"][0]["title"], "Rust async book");
    assert_eq!(
        payload["web"]["results"][0]["url"],
        "https://rust-lang.github.io/async-book/",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// 401 Unauthorized — bad API key path
// ─────────────────────────────────────────────────────────────────────────
//
// Real Brave Search returns HTTP 401 when the X-Subscription-Token is
// missing or invalid. The connector's `send_json` classifies everything
// that isn't 429 or 5xx as non-retryable, so the caller gets a typed
// FcpError::External with status=401 and retryable=false.

#[fcp_async_core::runtime::test]
async fn web_search_401_unauthorized_maps_to_non_retryable_external_error() {
    init_logging();
    tracing::info!(test = "web_search_401", "starting");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/web/search"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error": "Invalid subscription token"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let err = connector
        .handle_invoke(invoke_web_search("anything"))
        .await
        .expect_err("401 response must surface as Err");

    match err {
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            message,
        } => {
            tracing::info!(
                test = "web_search_401",
                service,
                status_code = ?status_code,
                retryable,
                retry_after = ?retry_after,
                "got external error",
            );
            assert_eq!(
                service, "brave-search",
                "service label must be brave-search"
            );
            assert_eq!(status_code, Some(401), "status_code must be 401");
            assert!(!retryable, "401 is an auth problem, not a transient one");
            assert!(
                retry_after.is_none(),
                "401 without Retry-After must not fabricate one"
            );
            assert!(
                message.contains("401"),
                "error message should carry the HTTP status for diagnosability; got {message:?}",
            );
        }
        other => panic!("expected FcpError::External, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 429 Too Many Requests with Retry-After
// ─────────────────────────────────────────────────────────────────────────
//
// Brave Search returns HTTP 429 + Retry-After when the token's rate
// limit is exhausted. The connector's send_json must:
//   - set FcpError::External { status_code: Some(429) }
//   - set retryable: true
//   - parse Retry-After as seconds into retry_after: Some(Duration)

#[fcp_async_core::runtime::test]
async fn web_search_429_with_retry_after_maps_to_retryable_external_error() {
    init_logging();
    tracing::info!(test = "web_search_429", "starting");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/web/search"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "7")
                .set_body_json(json!({"error": "Too Many Requests"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let err = connector
        .handle_invoke(invoke_web_search("whatever"))
        .await
        .expect_err("429 response must surface as Err");

    match err {
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            ..
        } => {
            tracing::info!(
                test = "web_search_429",
                service,
                status_code = ?status_code,
                retryable,
                retry_after_secs = retry_after.map(|d| d.as_secs()),
                "got rate-limit error",
            );
            assert_eq!(service, "brave-search");
            assert_eq!(status_code, Some(429));
            assert!(retryable, "429 is the canonical retryable class");
            assert_eq!(
                retry_after,
                Some(Duration::from_secs(7)),
                "Retry-After seconds header must round-trip into the error",
            );
        }
        other => panic!("expected FcpError::External for 429, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Network timeout — configured request_timeout_ms expires before the
// server responds.
// ─────────────────────────────────────────────────────────────────────────
//
// The connector builds its reqwest::Client with `.timeout(Duration)`
// derived from request_timeout_ms. reqwest surfaces timeouts with
// `error.is_timeout()` → map_reqwest_error → FcpError::UpstreamTimeout.

#[fcp_async_core::runtime::test]
async fn web_search_network_timeout_maps_to_upstream_timeout() {
    init_logging();
    tracing::info!(test = "web_search_timeout", "starting");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/web/search"))
        .respond_with(
            ResponseTemplate::new(200)
                // Delay past the connector's 100ms timeout so the
                // reqwest client raises a timeout error before the
                // server gets to respond.
                .set_delay(Duration::from_secs(1))
                .set_body_json(json!({"web": {"results": []}})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector_with_timeout(&server, 100).await;
    let err = connector
        .handle_invoke(invoke_web_search("slow"))
        .await
        .expect_err("request must time out before the server responds");

    match err {
        FcpError::UpstreamTimeout { service } => {
            tracing::info!(test = "web_search_timeout", service, "got upstream timeout");
            assert_eq!(
                service, "brave-search",
                "timeout error must carry the brave-search service label",
            );
        }
        other => panic!("expected FcpError::UpstreamTimeout, got {other:?}"),
    }
}
