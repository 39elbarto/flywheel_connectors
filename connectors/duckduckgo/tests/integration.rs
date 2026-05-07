use std::time::Duration;

use fcp_duckduckgo::DuckDuckGoConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path, query_param},
};

const OP_TEXT: &str = "duckduckgo.search.text";
const OP_IMAGES: &str = "duckduckgo.search.images";
const OP_NEWS: &str = "duckduckgo.search.news";
const OP_SUGGESTIONS: &str = "duckduckgo.search.suggestions";
const OP_HEALTH: &str = "duckduckgo.health";
const EXPECTED_OPERATION_ORDER: [&str; 5] =
    [OP_TEXT, OP_IMAGES, OP_NEWS, OP_SUGGESTIONS, OP_HEALTH];

#[fcp_async_core::runtime::test]
async fn text_search_posts_html_form_and_normalizes_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/html/"))
        .and(body_string_contains("q=rust+programming"))
        .and(body_string_contains("kl=us-en"))
        .and(body_string_contains("kp=-1"))
        .and(header("sec-fetch-mode", "navigate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html_fixture()))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let response = connector
        .handle_invoke(invoke(OP_TEXT, &json!({"query": "rust programming"})))
        .await
        .expect("text search should succeed");

    assert_eq!(response["provider"], "duckduckgo");
    assert_eq!(response["mode"], "text");
    assert_eq!(response["count"], 2);
    assert_eq!(response["results"][0]["hostname"], "rust-lang.org");
    assert_eq!(
        response["results"][1]["url"],
        "https://doc.rust-lang.org/book/"
    );
    assert!(
        response["query_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("blake3:"))
    );
}

#[fcp_async_core::runtime::test]
async fn image_and_news_search_use_vqd_backed_json_endpoints() {
    let server = MockServer::start().await;
    mount_vqd_html(&server, 2).await;
    Mock::given(method("GET"))
        .and(path("/i.js"))
        .and(query_param("q", "rust"))
        .and(query_param("vqd", "4-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Rust Logo",
                "url": "https://rust-lang.org/logos",
                "image": "https://example.invalid/rust.png",
                "thumbnail": "https://example.invalid/thumb.png",
                "source": "Bing",
                "width": 640,
                "height": 480
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/news.js"))
        .and(query_param("q", "rust"))
        .and(query_param("vqd", "4-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Rust Release",
                "url": "https://blog.rust-lang.org/release",
                "excerpt": "Release summary",
                "source": "Rust Blog",
                "date": "2026-05-06T00:00:00Z"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let images = connector
        .handle_invoke(invoke(
            OP_IMAGES,
            &json!({"query": "rust", "max_results": 1}),
        ))
        .await
        .expect("image search should succeed");
    assert_eq!(images["mode"], "images");
    assert_eq!(images["results"][0]["hostname"], "rust-lang.org");
    assert_eq!(images["results"][0]["width"], 640);

    let news = connector
        .handle_invoke(invoke(
            OP_NEWS,
            &json!({"query": "rust", "time_range": "week"}),
        ))
        .await
        .expect("news search should succeed");
    assert_eq!(news["mode"], "news");
    assert_eq!(news["results"][0]["source"], "Rust Blog");
}

#[fcp_async_core::runtime::test]
async fn suggestions_parse_list_shape_and_are_query_hashed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ac/"))
        .and(query_param("q", "rust"))
        .and(query_param("type", "list"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!(["rust", ["rust programming", "rust book"]])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let response = connector
        .handle_invoke(invoke(OP_SUGGESTIONS, &json!({"query": "rust"})))
        .await
        .expect("suggestions should succeed");
    assert_eq!(response["count"], 2);
    assert_eq!(response["suggestions"][0]["text"], "rust programming");
    assert!(
        response["suggestions"][0]["text_hash"]
            .as_str()
            .expect("text_hash should be present")
            .starts_with("blake3:")
    );
}

#[fcp_async_core::runtime::test]
async fn rate_limit_and_timeout_map_to_fcp_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/html/"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "3")
                .set_body_string("rate limited"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let err = connector
        .handle_invoke(invoke(OP_TEXT, &json!({"query": "rust"})))
        .await
        .expect_err("rate limit should fail");
    let FcpError::External {
        service,
        status_code,
        retryable,
        retry_after,
        ..
    } = err
    else {
        assert!(
            matches!(&err, FcpError::External { .. }),
            "expected external error"
        );
        return;
    };
    assert_eq!(service, "duckduckgo");
    assert_eq!(status_code, Some(429));
    assert!(retryable);
    assert_eq!(retry_after, Some(Duration::from_secs(3)));

    let slow = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/html/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_string(html_fixture()),
        )
        .mount(&slow)
        .await;
    let timeout_connector = configured_connector_with_timeout(&slow, 10).await;
    let timeout = timeout_connector
        .handle_invoke(invoke(OP_TEXT, &json!({"query": "rust"})))
        .await
        .expect_err("request should time out");
    assert!(matches!(timeout, FcpError::UpstreamTimeout { .. }));
}

#[fcp_async_core::runtime::test]
async fn bot_blocker_and_validation_errors_are_visible() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/html/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><body><img src=\"//duckduckgo.com/t/tqadb?cc=botnet\" /></body></html>",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let blocked = connector
        .handle_invoke(invoke(OP_TEXT, &json!({"query": "rust"})))
        .await
        .expect_err("bot blocker should surface");
    assert!(blocked.to_string().contains("bot-protection"));

    let invalid = connector
        .handle_invoke(invoke(
            OP_TEXT,
            &json!({"query": "rust", "safe_search": "maybe"}),
        ))
        .await
        .expect_err("invalid option should fail before request");
    assert!(invalid.to_string().contains("safe_search"));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_advertises_no_auth_privacy_boundary() {
    let server = MockServer::start().await;
    let mut connector = DuckDuckGoConnector::new();
    let configured = connector
        .handle_configure(json!({"base_url": server.uri()}))
        .await
        .expect("configure should succeed");
    assert_eq!(configured["auth_mode"], "none");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    let health = connector.handle_health().await.expect("health should work");
    assert_eq!(health["status"], "healthy");
    let introspect = connector
        .handle_introspect()
        .await
        .expect("introspect should work");
    let operations = introspect["operations"]
        .as_array()
        .expect("operations should be an array");
    let operation_ids: Vec<_> = operations
        .iter()
        .map(|operation| operation["id"].as_str().expect("operation id"))
        .collect();
    assert_eq!(operation_ids, EXPECTED_OPERATION_ORDER);
    for operation in operations {
        assert_eq!(operation["capability"], "duckduckgo.search.read");
        assert_eq!(operation["input_schema"]["type"], "object");
        assert_eq!(operation["output_schema"]["type"], "object");
        assert!(
            operation["network_constraints"]["host_allow"]
                .as_array()
                .expect("host_allow should be present")
                .iter()
                .all(|host| host
                    .as_str()
                    .is_some_and(|value| value.ends_with("duckduckgo.com")))
        );
        assert!(
            operation["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }
    let manifest = fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("manifest should validate");
    assert_eq!(manifest.provides.operations.len(), operations.len());
    let simulate = connector
        .handle_simulate(json!({"operation_id": OP_TEXT}))
        .await
        .expect("simulate should work");
    assert_eq!(simulate["allowed"], true);
}

async fn configured_connector(server: &MockServer) -> DuckDuckGoConnector {
    configured_connector_with_timeout(server, 5_000).await
}

async fn configured_connector_with_timeout(
    server: &MockServer,
    request_timeout_ms: u64,
) -> DuckDuckGoConnector {
    let mut connector = DuckDuckGoConnector::new();
    connector
        .handle_configure(json!({
            "base_url": server.uri(),
            "request_timeout_ms": request_timeout_ms
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    connector
}

async fn mount_vqd_html(server: &MockServer, expected: u64) {
    Mock::given(method("POST"))
        .and(path("/html/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(vqd_html_fixture()))
        .expect(expected)
        .mount(server)
        .await;
}

fn invoke(operation: &str, input: &Value) -> Value {
    json!({"operation_id": operation, "input": input})
}

const fn html_fixture() -> &'static str {
    r#"
      <html><body>
        <div class="result results_links web-result">
          <a rel="nofollow" class="result__a" href="https://rust-lang.org/">Rust Programming Language</a>
          <a class="result__snippet" href="https://rust-lang.org/">Rust is fast and memory-efficient.</a>
        </div>
        <div class="result results_links web-result">
          <a rel="nofollow" class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fdoc.rust-lang.org%2Fbook%2F">The Rust Book</a>
          <a class="result__snippet" href="https://doc.rust-lang.org/book/">Official book.</a>
        </div>
        <input type="hidden" name="vqd" value="4-fixture" />
      </body></html>
    "#
}

const fn vqd_html_fixture() -> &'static str {
    r#"<html><body><input type="hidden" name="vqd" value="4-fixture" /></body></html>"#
}
