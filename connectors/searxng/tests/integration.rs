use std::time::Duration;

use fcp_prelude::FcpError;
use fcp_searxng::SearxngConnector;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

const OP_QUERY: &str = "searxng.search.query";
const OP_IMAGES: &str = "searxng.search.images";
const OP_NEWS: &str = "searxng.search.news";
const OP_HEALTH: &str = "searxng.health";

#[fcp_async_core::runtime::test]
async fn query_search_encodes_filters_and_normalizes_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "rust privacy"))
        .and(query_param("format", "json"))
        .and(query_param("language", "en-us"))
        .and(query_param("safesearch", "2"))
        .and(query_param("time_range", "month"))
        .and(query_param("categories", "general,science"))
        .and(query_param("engines", "duckduckgo,brave"))
        .and(query_param("pageno", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(search_fixture()))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let response = connector
        .handle_invoke(invoke(
            OP_QUERY,
            &json!({
                "query": "rust privacy",
                "language": "en-us",
                "safe_search": "strict",
                "time_range": "month",
                "page": 2,
                "categories": ["general", "science"],
                "engines": "duckduckgo,brave"
            }),
        ))
        .await
        .expect("search should succeed");

    assert_eq!(response["provider"], "searxng");
    assert_eq!(response["mode"], "query");
    assert_eq!(response["base_url_class"], "loopback");
    assert_eq!(response["count"], 2);
    assert_eq!(response["results"][0]["hostname"], "rust-lang.org");
    assert!(response["suggestions"][0]["text_hash"].as_str().is_some());
    assert!(
        response["query_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("blake3:"))
    );
}

#[fcp_async_core::runtime::test]
async fn image_and_news_search_apply_default_categories() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "rust images"))
        .and(query_param("categories", "images"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Rust image",
                "url": "https://rust-lang.org/logos",
                "img_src": "https://cdn.example.invalid/rust.png",
                "engine": "bing",
                "category": "images"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "rust news"))
        .and(query_param("categories", "news"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Rust news",
                "url": "https://blog.rust-lang.org",
                "content": "release notes",
                "engine": "brave",
                "category": "news",
                "publishedDate": "2026-05-06T00:00:00Z"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let images = connector
        .handle_invoke(invoke(OP_IMAGES, &json!({"query": "rust images"})))
        .await
        .expect("images should succeed");
    assert_eq!(images["categories"][0], "images");
    assert_eq!(
        images["results"][0]["image_url"],
        "https://cdn.example.invalid/rust.png"
    );

    let news = connector
        .handle_invoke(invoke(OP_NEWS, &json!({"query": "rust news"})))
        .await
        .expect("news should succeed");
    assert_eq!(news["categories"][0], "news");
    assert_eq!(news["results"][0]["published_at"], "2026-05-06T00:00:00Z");
}

#[fcp_async_core::runtime::test]
async fn host_policy_requires_loopback_opt_in_and_supports_custom_auth_header() {
    let mut denied = SearxngConnector::new();
    let err = denied
        .handle_configure(json!({"base_url": "http://127.0.0.1:8080"}))
        .await
        .expect_err("loopback should require opt-in");
    assert!(err.to_string().contains("allow_loopback"));

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats"))
        .and(header("x-api-key", "fixture-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"instance": "ok"})))
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = SearxngConnector::new();
    let configured = connector
        .handle_configure(json!({
            "base_url": server.uri(),
            "allow_loopback": true,
            "auth_header_name": "x-api-key",
            "auth_header_value": "fixture-secret"
        }))
        .await
        .expect("custom header config should work");
    assert_eq!(configured["auth_mode"], "custom_header");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    connector
        .handle_invoke(invoke(OP_HEALTH, &json!({})))
        .await
        .expect("health should send custom header");
}

#[fcp_async_core::runtime::test]
async fn malformed_rate_limit_and_timeout_errors_are_mapped() {
    let malformed = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": {}})))
        .expect(1)
        .mount(&malformed)
        .await;
    let connector = configured_connector(&malformed).await;
    let err = connector
        .handle_invoke(invoke(OP_QUERY, &json!({"query": "rust"})))
        .await
        .expect_err("malformed response should fail");
    assert!(err.to_string().contains("results must be an array"));

    let rate = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "3")
                .set_body_string("rate limited"),
        )
        .expect(1)
        .mount(&rate)
        .await;
    let connector = configured_connector(&rate).await;
    let err = connector
        .handle_invoke(invoke(OP_QUERY, &json!({"query": "rust"})))
        .await
        .expect_err("rate limit should fail");
    match err {
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            ..
        } => {
            assert_eq!(service, "searxng");
            assert_eq!(status_code, Some(429));
            assert!(retryable);
            assert_eq!(retry_after, Some(Duration::from_secs(3)));
        }
        other => assert!(
            matches!(other, FcpError::External { .. }),
            "expected external rate-limit error"
        ),
    }

    let slow = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(search_fixture()),
        )
        .mount(&slow)
        .await;
    let timeout_connector = configured_connector_with_timeout(&slow, 10).await;
    let timeout = timeout_connector
        .handle_invoke(invoke(OP_QUERY, &json!({"query": "rust"})))
        .await
        .expect_err("request should time out");
    assert!(matches!(timeout, FcpError::UpstreamTimeout { .. }));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_advertises_privacy_and_no_fallback_boundary() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server).await;
    let health = connector.handle_health().await.expect("health should work");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["base_url_class"], "loopback");
    let doctor = connector.handle_doctor().await.expect("doctor should work");
    assert!(
        doctor["checks"]
            .as_array()
            .expect("checks should be an array")
            .iter()
            .any(|check| check["name"] == "provider_fallback" && check["passed"] == true)
    );
    let introspect = connector
        .handle_introspect()
        .await
        .expect("introspect should work");
    assert!(
        introspect["operations"]
            .as_array()
            .expect("operations should be an array")
            .iter()
            .any(|operation| operation["id"] == OP_NEWS)
    );
    let simulate = connector
        .handle_simulate(json!({"operation_id": OP_QUERY}))
        .await
        .expect("simulate should work");
    assert_eq!(simulate["allowed"], true);
}

async fn configured_connector(server: &MockServer) -> SearxngConnector {
    configured_connector_with_timeout(server, 5_000).await
}

async fn configured_connector_with_timeout(
    server: &MockServer,
    request_timeout_ms: u64,
) -> SearxngConnector {
    let mut connector = SearxngConnector::new();
    connector
        .handle_configure(json!({
            "base_url": server.uri(),
            "allow_loopback": true,
            "request_timeout_ms": request_timeout_ms,
            "default_language": "en"
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    connector
}

fn invoke(operation: &str, input: &Value) -> Value {
    json!({"operation_id": operation, "input": input})
}

fn search_fixture() -> Value {
    json!({
        "results": [
            {
                "title": "Rust Programming Language",
                "url": "https://rust-lang.org/",
                "content": "Rust is fast and memory-efficient.",
                "engine": "duckduckgo",
                "category": "general",
                "score": 1.0
            },
            {
                "title": "The Rust Book",
                "url": "https://doc.rust-lang.org/book/",
                "content": "Official book.",
                "engine": "brave",
                "category": "general"
            }
        ],
        "suggestions": ["rust book"],
        "answers": ["Rust is a programming language"],
        "infoboxes": [{"title": "Rust"}]
    })
}
