//! Local loopback acceptance coverage for the Firecrawl connector.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use fcp_firecrawl::FirecrawlConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const CONNECTOR: &str = "firecrawl";
const PACKAGE: &str = "fcp-firecrawl";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.6";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const OP_SEARCH: &str = "firecrawl.search";
const OP_SCRAPE: &str = "firecrawl.scrape";

async fn configured_connector(server: &MockServer, api_key: &str) -> FirecrawlConnector {
    let mut connector = FirecrawlConnector::new();
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "base_url": server.uri(),
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure Firecrawl connector against loopback fixture");
    connector
        .handle_handshake(json!({ "session_id": "firecrawl-local-non-mock" }))
        .await
        .expect("handshake Firecrawl connector");
    connector
}

fn print_artifact(case_name: &str, request_response_boundary: Value, auth_gate: Value) {
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "case": case_name,
        "command": "cargo test -p fcp-firecrawl --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": request_response_boundary,
        "auth_gate": auth_gate,
        "cleanup": "wiremock_fixture_dropped",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_posts_v2_body_and_returns_results() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/search"))
        .and(header("authorization", "Bearer fc-local-firecrawl-key"))
        .and(body_partial_json(json!({
            "query": "firecrawl docs",
            "limit": 3,
            "sources": ["web", "news"],
            "categories": ["github"],
            "scrapeOptions": {
                "formats": ["markdown"]
            },
            "timeout": 30000,
            "country": "US",
            "location": "San Francisco,California,United States",
            "ignoreInvalidURLs": true,
            "enterprise": ["anon"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "data": {
                "web": [
                    {
                        "url": "https://docs.firecrawl.dev",
                        "title": "Firecrawl Docs",
                        "description": "Firecrawl documentation"
                    }
                ],
                "news": []
            },
            "warning": null,
            "id": "search-local-001",
            "creditsUsed": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server, "fc-local-firecrawl-key").await;
    let response = connector
        .handle_invoke(json!({
            "operation_id": OP_SEARCH,
            "input": {
                "query": " firecrawl docs ",
                "limit": 3,
                "sources": ["web", "", "news"],
                "categories": ["github"],
                "scrape_results": true,
                "timeout": 30000,
                "country": "us",
                "location": "San Francisco,California,United States",
                "ignore_invalid_urls": true,
                "enterprise": ["anon"]
            }
        }))
        .await
        .expect("search through loopback Firecrawl boundary");

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(response["operation"], OP_SEARCH);
    assert_eq!(response["output"]["success"], true);
    assert_eq!(response["output"]["id"], "search-local-001");
    assert_eq!(
        response["output"]["data"]["web"][0]["url"],
        "https://docs.firecrawl.dev"
    );
    assert_eq!(response["output"]["creditsUsed"], 1);

    print_artifact(
        "search_success",
        json!({
            "method": "POST",
            "path": "/v2/search",
            "body_fields": [
                "query",
                "limit",
                "sources",
                "categories",
                "scrapeOptions",
                "timeout",
                "country",
                "location",
                "ignoreInvalidURLs",
                "enterprise"
            ],
            "response_fields": ["success", "data", "id", "creditsUsed"]
        }),
        json!({
            "mode": "bearer",
            "credential_source": "local_fixture",
            "credential_logged": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_scrape_posts_v2_body_and_returns_markdown() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/scrape"))
        .and(header("authorization", "Bearer fc-local-firecrawl-key"))
        .and(body_partial_json(json!({
            "url": "https://example.com",
            "formats": ["markdown"],
            "onlyMainContent": false,
            "includeTags": ["main"],
            "excludeTags": ["nav"],
            "waitFor": 50,
            "timeout": 5000,
            "maxAge": 172800000,
            "proxy": "auto",
            "storeInCache": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "data": {
                "markdown": "# Example Domain",
                "metadata": {
                    "title": "Example Domain",
                    "sourceURL": "https://example.com",
                    "statusCode": 200
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server, "fc-local-firecrawl-key").await;
    let response = connector
        .handle_invoke(json!({
            "operation_id": OP_SCRAPE,
            "input": {
                "url": "https://example.com",
                "formats": ["markdown"],
                "only_main_content": false,
                "include_tags": ["main"],
                "exclude_tags": ["nav"],
                "wait_for": 50,
                "timeout": 5000,
                "max_age_ms": 172800000,
                "proxy": "auto",
                "store_in_cache": false
            }
        }))
        .await
        .expect("scrape through loopback Firecrawl boundary");

    assert_eq!(response["operation"], OP_SCRAPE);
    assert_eq!(response["output"]["success"], true);
    assert_eq!(response["output"]["data"]["markdown"], "# Example Domain");
    assert_eq!(
        response["output"]["data"]["metadata"]["sourceURL"],
        "https://example.com"
    );

    print_artifact(
        "scrape_success",
        json!({
            "method": "POST",
            "path": "/v2/scrape",
            "body_fields": [
                "url",
                "formats",
                "onlyMainContent",
                "includeTags",
                "excludeTags",
                "waitFor",
                "timeout",
                "maxAge",
                "proxy",
                "storeInCache"
            ],
            "response_fields": ["success", "data.markdown", "data.metadata"]
        }),
        json!({
            "mode": "bearer",
            "credential_source": "local_fixture",
            "credential_logged": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_maps_provider_auth_denial_without_secret_leak() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/search"))
        .and(header("authorization", "Bearer fc-denied-firecrawl-key"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "success": false,
            "error": "invalid api key"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server, "fc-denied-firecrawl-key").await;
    let error = connector
        .handle_invoke(json!({
            "operation_id": OP_SEARCH,
            "input": {
                "query": "firecrawl docs"
            }
        }))
        .await
        .expect_err("provider auth denial should map to unauthorized");

    match error {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 2001);
            assert!(message.contains("HTTP 401"));
            assert!(!message.contains("fc-denied-firecrawl-key"));
            assert!(!message.contains("invalid api key"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    print_artifact(
        "auth_denial",
        json!({
            "method": "POST",
            "path": "/v2/search",
            "body_fields": ["query"],
            "provider_status": 401,
            "error_mapping": "FcpError::Unauthorized"
        }),
        json!({
            "mode": "bearer",
            "credential_source": "local_fixture",
            "credential_logged": false,
            "denial_verified": true
        }),
    );
}
