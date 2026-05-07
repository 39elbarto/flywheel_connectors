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
//!   - happy path: 200 OK → normalized FCP result envelope
//!   - auth error: 401 Unauthorized -> `FcpError::External`, status=401,
//!     NOT retryable (Brave's own API returns 401 on a bad
//!     X-Subscription-Token and the connector's error mapper
//!     classifies 4xx-non-429 as non-retryable)
//!   - rate limit: 429 + Retry-After -> `FcpError::External`,
//!     status=429, retryable=true, `retry_after=Some`
//!   - network timeout: configured 100ms `request_timeout_ms` against a
//!     1s delayed response -> `FcpError::UpstreamTimeout`
//!   - OpenClaw-informed contract parity: `/res/v1/...` endpoint joining,
//!     LLM-context mode, input normalization, and untrusted-content wrapping
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
    configured_connector_with_base_url(&server.uri(), request_timeout_ms).await
}

async fn configured_connector_with_base_url(
    base_url: &str,
    request_timeout_ms: u64,
) -> BraveSearchConnector {
    let mut connector = BraveSearchConnector::new();
    connector
        .handle_configure(json!({
            "api_key": TEST_API_KEY,
            "base_url": base_url,
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

fn invoke_llm_context_search(query: &str) -> Value {
    json!({
        "operation_id": "brave-search.llm-context.search",
        "input": { "query": query }
    })
}

fn expect_invoke_error(result: Result<Value, FcpError>, context: &str) -> Result<FcpError, String> {
    match result {
        Ok(value) => Err(format!("{context}; got Ok({value:?})")),
        Err(error) => Ok(error),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Happy path: 200 OK with normalized, untrusted result wrapping
// ─────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn web_search_happy_path_returns_json_payload() {
    init_logging();
    tracing::info!(test = "web_search_happy_path", "starting");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/web/search"))
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
        provider = %payload["provider"],
        result_count = payload["results"].as_array().map_or(0, Vec::len),
        "got response",
    );

    assert_eq!(payload["provider"], "brave");
    assert_eq!(payload["mode"], "web");
    assert_eq!(payload["count"], 1);
    assert_eq!(payload["external_content"]["untrusted"], true);
    assert_eq!(payload["external_content"]["wrapped"], true);
    assert!(
        payload["results"][0]["title"]
            .as_str()
            .expect("wrapped title should be a string")
            .contains("Rust async book")
    );
    assert!(
        payload["results"][0]["description"]
            .as_str()
            .expect("wrapped description should be a string")
            .contains("<<<EXTERNAL_UNTRUSTED_CONTENT")
    );
    assert_eq!(
        payload["results"][0]["url"],
        "https://rust-lang.github.io/async-book/",
    );
    assert_eq!(payload["results"][0]["site_name"], "rust-lang.github.io");
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
async fn web_search_401_unauthorized_maps_to_non_retryable_external_error() -> Result<(), String> {
    init_logging();
    tracing::info!(test = "web_search_401", "starting");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/web/search"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error": "Invalid subscription token"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let err = expect_invoke_error(
        connector.handle_invoke(invoke_web_search("anything")).await,
        "401 response must surface as Err",
    )?;

    let FcpError::External {
        service,
        status_code,
        retryable,
        retry_after,
        message,
    } = err
    else {
        return Err(format!("expected FcpError::External, got {err:?}"));
    };

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
    Ok(())
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
async fn web_search_429_with_retry_after_maps_to_retryable_external_error() -> Result<(), String> {
    init_logging();
    tracing::info!(test = "web_search_429", "starting");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/web/search"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "7")
                .set_body_json(json!({"error": "Too Many Requests"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let err = expect_invoke_error(
        connector.handle_invoke(invoke_web_search("whatever")).await,
        "429 response must surface as Err",
    )?;

    let FcpError::External {
        service,
        status_code,
        retryable,
        retry_after,
        ..
    } = err
    else {
        return Err(format!("expected FcpError::External for 429, got {err:?}"));
    };

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
    Ok(())
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
async fn web_search_network_timeout_maps_to_upstream_timeout() -> Result<(), String> {
    init_logging();
    tracing::info!(test = "web_search_timeout", "starting");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/web/search"))
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
    let err = expect_invoke_error(
        connector.handle_invoke(invoke_web_search("slow")).await,
        "request must time out before the server responds",
    )?;

    let FcpError::UpstreamTimeout { service } = err else {
        return Err(format!("expected FcpError::UpstreamTimeout, got {err:?}"));
    };

    tracing::info!(test = "web_search_timeout", service, "got upstream timeout");
    assert_eq!(
        service, "brave-search",
        "timeout error must carry the brave-search service label",
    );
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn proxy_base_path_appends_brave_web_endpoint() {
    init_logging();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/proxy/res/v1/web/search"))
        .and(query_param("q", "proxy path"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "web": { "results": [] }
        })))
        .mount(&server)
        .await;

    let connector =
        configured_connector_with_base_url(&format!("{}/proxy/", server.uri()), 5_000).await;
    let payload = connector
        .handle_invoke(invoke_web_search("proxy path"))
        .await
        .expect("proxy base path should append /res/v1/web/search");

    assert_eq!(payload["provider"], "brave");
    assert_eq!(payload["count"], 0);
}

#[fcp_async_core::runtime::test]
async fn llm_context_success_returns_wrapped_results_and_sources() {
    init_logging();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/llm/context"))
        .and(query_param("q", "grounded answer"))
        .and(header("X-Subscription-Token", TEST_API_KEY))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "grounding": {
                "generic": [{
                    "url": "https://example.com/post",
                    "title": "Example post",
                    "snippets": ["first chunk", "", "second chunk"]
                }]
            },
            "sources": [{
                "url": "https://example.com/post",
                "date": "2025-01-02"
            }]
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let payload = connector
        .handle_invoke(invoke_llm_context_search("grounded answer"))
        .await
        .expect("llm-context response should decode");

    assert_eq!(payload["mode"], "llm-context");
    assert_eq!(payload["count"], 1);
    assert_eq!(payload["external_content"]["kind"], "llm_context_results");
    assert!(
        payload["results"][0]["title"]
            .as_str()
            .expect("title should be wrapped")
            .contains("Example post")
    );
    assert_eq!(
        payload["results"][0]["snippets"]
            .as_array()
            .expect("snippets should be an array")
            .len(),
        2
    );
    assert_eq!(payload["results"][0]["site_name"], "example.com");
    assert_eq!(payload["sources"][0]["hostname"], "example.com");
}

#[fcp_async_core::runtime::test]
async fn validation_normalizes_count_country_language_and_dates_before_request() {
    init_logging();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/web/search"))
        .and(query_param("q", "normalization"))
        .and(query_param("count", "10"))
        .and(query_param("country", "ALL"))
        .and(query_param("search_lang", "zh-hans"))
        .and(query_param("ui_lang", "en-US"))
        .and(query_param("freshness", "2025-01-01to2025-01-31"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "web": { "results": [] }
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    connector
        .handle_invoke(json!({
            "operation_id": "brave-search.web.search",
            "input": {
                "query": "normalization",
                "count": 99,
                "country": "VN",
                "language": "zh-cn",
                "ui_lang": "en-us",
                "date_after": "2025-01-01",
                "date_before": "2025-01-31"
            }
        }))
        .await
        .expect("normalized query should be accepted");
}

#[fcp_async_core::runtime::test]
async fn invalid_filters_fail_before_fetch() {
    init_logging();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/web/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "web": { "results": [] }
        })))
        .expect(0)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let invalid_language = connector
        .handle_invoke(json!({
            "operation_id": "brave-search.web.search",
            "input": { "query": "x", "search_lang": "not-a-language" }
        }))
        .await
        .expect_err("invalid search_lang should fail before request");
    assert!(invalid_language.to_string().contains("search_lang"));

    let conflicting_time_filters = connector
        .handle_invoke(json!({
            "operation_id": "brave-search.web.search",
            "input": {
                "query": "x",
                "freshness": "week",
                "date_after": "2025-01-01"
            }
        }))
        .await
        .expect_err("freshness/date conflict should fail before request");
    assert!(
        conflicting_time_filters
            .to_string()
            .contains("freshness and date_after")
    );

    let unsupported_ui_lang = connector
        .handle_invoke(json!({
            "operation_id": "brave-search.llm-context.search",
            "input": { "query": "x", "ui_lang": "en-US" }
        }))
        .await
        .expect_err("llm-context does not support ui_lang");
    assert!(unsupported_ui_lang.to_string().contains("ui_lang"));
}

#[fcp_async_core::runtime::test]
async fn malformed_upstream_json_maps_to_external_error() -> Result<(), String> {
    init_logging();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/res/v1/web/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("{not valid json"),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let err = expect_invoke_error(
        connector
            .handle_invoke(invoke_web_search("malformed"))
            .await,
        "malformed upstream JSON should be an external error",
    )?;

    let FcpError::External {
        service,
        status_code,
        retryable,
        message,
        ..
    } = err
    else {
        return Err(format!("expected FcpError::External, got {err:?}"));
    };

    assert_eq!(service, "brave-search");
    assert_eq!(status_code, Some(200));
    assert!(!retryable);
    assert!(message.contains("Failed to decode JSON"));
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn introspection_and_config_redact_auth_and_advertise_llm_context() {
    init_logging();
    let server = MockServer::start().await;
    let mut connector = BraveSearchConnector::new();
    let configure = connector
        .handle_configure(json!({
            "api_key": TEST_API_KEY,
            "base_url": server.uri(),
        }))
        .await
        .expect("configure should succeed");
    let configure_json = serde_json::to_string(&configure).expect("configure result serializes");
    assert!(!configure_json.contains(TEST_API_KEY));

    let handshake = connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    assert!(
        handshake["capabilities"]
            .as_array()
            .expect("capabilities should be an array")
            .contains(&json!("brave-search.llm-context"))
    );

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should succeed");
    let operations = introspection["operations"]
        .as_array()
        .expect("operations should be an array");
    assert_eq!(operations.len(), 2);
    let llm_context = operations
        .iter()
        .find(|operation| operation["id"] == "brave-search.llm-context.search")
        .expect("LLM context operation should be declared");
    assert_eq!(llm_context["capability"], "brave-search.llm-context");
    assert_eq!(llm_context["risk_level"], "low");
    assert_eq!(llm_context["safety_tier"], "safe");
    assert_eq!(
        llm_context["network_constraints"]["host_allow"],
        json!(["api.search.brave.com", "search.brave.com"])
    );
    assert_eq!(llm_context["input_schema"]["required"], json!(["query"]));
}
