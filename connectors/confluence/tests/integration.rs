//! Connector-local no-mock Confluence integration proof.
//!
//! These tests exercise the real Confluence client against a local HTTP server.
//! No live Atlassian or Confluence service is called.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use base64::Engine;
use fcp_async_core::AsyncError;
use fcp_confluence::ConfluenceConnector;
use fcp_confluence::client::ConfluenceClient;
use fcp_confluence::connector::operations_info;
use fcp_confluence::error::Error;
use fcp_prelude::{ApprovalMode, FcpConnector, FcpError, IdempotencyClass, RiskLevel, SafetyTier};
use fcp_sdk::migration::{
    ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig,
};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_EMAIL: &str = "user@example.com";
const TEST_TOKEN: &str = "confluence-token-for-tests";

fn expected_auth_header() -> String {
    let credentials = format!("{TEST_EMAIL}:{TEST_TOKEN}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    format!("Basic {encoded}")
}

fn no_retry_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    }
}

fn test_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(500)),
    )
}

fn client(server: &MockServer) -> ConfluenceClient {
    ConfluenceClient::new(&server.uri(), TEST_EMAIL, TEST_TOKEN, no_retry_config())
        .expect("wiremock URI should build a Confluence client")
}

fn space_json(key: &str) -> Value {
    json!({
        "id": "space-1",
        "key": key,
        "name": "Engineering",
        "type": "global",
        "status": "current",
        "_links": {
            "self": "/rest/api/space/ENG",
            "webui": "/spaces/ENG"
        }
    })
}

fn page_json(page_id: &str, title: &str) -> Value {
    json!({
        "id": page_id,
        "title": title,
        "type": "page",
        "status": "current",
        "space": { "key": "ENG", "name": "Engineering" },
        "version": { "number": 2, "message": "updated" },
        "body": {
            "storage": {
                "value": "<p>Hello from FCP</p>",
                "representation": "storage"
            }
        },
        "_links": { "webui": "/spaces/ENG/pages/123" }
    })
}

#[fcp_async_core::runtime::test]
async fn spaces_pages_search_and_health_success_paths_use_confluence_contracts() {
    tracing::info!(
        scenario = "confluence_success_contracts",
        "starting Confluence success-path integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/rest/api/space"))
        .and(query_param("start", "0"))
        .and(query_param("limit", "2"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [space_json("ENG")],
            "start": 0,
            "limit": 2,
            "size": 1,
            "_links": { "next": "/rest/api/space?start=2", "base": "/wiki" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/space/ENG"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(space_json("ENG")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/space/ENG/content/page"))
        .and(query_param("start", "2"))
        .and(query_param("limit", "3"))
        .and(query_param("expand", "version,space"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [page_json("page-1", "Runbook")],
            "start": 2,
            "limit": 3,
            "size": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/content/page-1"))
        .and(query_param("expand", "body.storage,version,space"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("page-1", "Runbook")))
        .expect(1)
        .mount(&server)
        .await;

    let create_body = json!({
        "type": "page",
        "title": "Created by FCP",
        "space": { "key": "ENG" },
        "body": {
            "storage": {
                "value": "<p>Created</p>",
                "representation": "storage"
            }
        }
    });
    Mock::given(method("POST"))
        .and(path("/rest/api/content"))
        .and(header("Authorization", expected_auth_header()))
        .and(body_json(create_body.clone()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_json("page-created", "Created by FCP")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let update_body = json!({
        "id": "page-1",
        "type": "page",
        "title": "Runbook updated",
        "body": {
            "storage": {
                "value": "<p>Updated</p>",
                "representation": "storage"
            }
        },
        "version": {
            "number": 3,
            "message": "proof update"
        }
    });
    Mock::given(method("PUT"))
        .and(path("/rest/api/content/page-1"))
        .and(header("Authorization", expected_auth_header()))
        .and(body_json(update_body.clone()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_json("page-1", "Runbook updated")),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/rest/api/content/page-1"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/search"))
        .and(query_param("cql", "space = ENG and text ~ \"runbook\""))
        .and(query_param("start", "5"))
        .and(query_param("limit", "10"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Runbook",
                "excerpt": "Operational runbook",
                "url": "/wiki/spaces/ENG/pages/page-1",
                "content": page_json("page-1", "Runbook")
            }],
            "start": 5,
            "limit": 10,
            "size": 1,
            "_links": { "next": "/rest/api/search?start=15" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/space"))
        .and(query_param("limit", "1"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [],
            "start": 0,
            "limit": 1,
            "size": 0
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let spaces = client
        .list_spaces(&runtime, 0, 2)
        .await
        .expect("spaces should decode");
    let first_space = spaces.results.first().expect("space result");
    assert_eq!(first_space.key, "ENG");
    assert_eq!(
        spaces.links.and_then(|links| links.next).as_deref(),
        Some("/rest/api/space?start=2")
    );

    let space = client
        .get_space(&runtime, "ENG")
        .await
        .expect("space should decode");
    assert_eq!(space.name, "Engineering");

    let pages = client
        .list_pages(&runtime, "ENG", 2, 3)
        .await
        .expect("pages should decode");
    let first_page = pages.results.first().expect("page result");
    assert_eq!(first_page.id, "page-1");
    assert_eq!(pages.start, 2);

    let page = client
        .get_page(&runtime, "page-1")
        .await
        .expect("page should decode");
    assert_eq!(page.title, "Runbook");
    assert_eq!(page.space.expect("space ref").key, "ENG");

    let created = client
        .create_page(&runtime, &create_body)
        .await
        .expect("create page should decode");
    assert_eq!(created.id, "page-created");

    let updated = client
        .update_page(&runtime, "page-1", &update_body)
        .await
        .expect("update page should decode");
    assert_eq!(updated.title, "Runbook updated");

    client
        .delete_page(&runtime, "page-1")
        .await
        .expect("delete page should accept 204");

    let results = client
        .search(&runtime, "space = ENG and text ~ \"runbook\"", 5, 10)
        .await
        .expect("search results should decode");
    let first_result = results.results.first().expect("search result");
    assert_eq!(first_result.title, "Runbook");
    assert_eq!(
        results.links.and_then(|links| links.next).as_deref(),
        Some("/rest/api/search?start=15")
    );

    client
        .health_check()
        .await
        .expect("health check should pass");
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_malformed_json_and_invalid_input_are_typed() {
    tracing::info!(
        scenario = "confluence_error_taxonomy",
        "starting Confluence error-taxonomy integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/rest/api/space/BAD"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "Invalid credentials"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/search"))
        .and(query_param("cql", "text ~ \"rate\""))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({ "message": "rate limited" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/content/malformed"))
        .and(query_param("expand", "body.storage,version,space"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client
        .get_space(&runtime, "BAD")
        .await
        .expect_err("401 should map to unauthorized");
    assert!(matches!(unauthorized, Error::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());
    assert!(matches!(
        unauthorized.to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let rate_limited = client
        .search(&runtime, "text ~ \"rate\"", 0, 25)
        .await
        .expect_err("429 should map to rate limit");
    assert!(matches!(
        rate_limited,
        Error::RateLimited {
            retry_after_ms: 2_000
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(2)));
    assert!(matches!(
        rate_limited.to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 2_000,
            ..
        }
    ));

    let malformed = client
        .get_page(&runtime, "malformed")
        .await
        .expect_err("malformed JSON should be surfaced by reqwest decode");
    assert!(matches!(malformed, Error::Http(ref error) if error.is_decode()));
    assert!(matches!(
        malformed.to_fcp_error(),
        FcpError::External {
            service,
            retryable: true,
            ..
        } if service == "confluence"
    ));

    let traversal = client
        .get_space(&runtime, "../ENG")
        .await
        .expect_err("path traversal should be rejected before outbound call");
    assert!(matches!(traversal, Error::InvalidInput(_)));
    assert!(matches!(
        traversal.to_fcp_error(),
        FcpError::InvalidRequest { code: 1005, .. }
    ));
}

#[test]
fn async_timeout_and_cancellation_mapping_is_bounded() {
    let timeout = Error::from_async_error(AsyncError::Timeout { timeout_ms: 250 });
    assert_eq!(
        timeout.to_string(),
        "Async error: operation timed out after 250ms"
    );
    assert!(timeout.is_retryable());

    let cancelled = Error::from_async_error(AsyncError::Cancelled);
    assert_eq!(cancelled.to_string(), "Async error: operation cancelled");
    assert!(cancelled.is_retryable());
}

#[test]
fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let connector = ConfluenceConnector::new();
    let introspection = connector.introspect();
    assert_eq!(introspection.operations.len(), 9);
    assert!(
        !introspection
            .event_caps
            .as_ref()
            .expect("event caps")
            .streaming
    );

    let operations = operations_info();
    let operation = |id: &str| {
        operations
            .iter()
            .find(|entry| entry.id.as_str() == id)
            .expect("operation catalog should contain required Confluence operation")
    };

    let spaces_list = operation("confluence.spaces.list");
    assert_eq!(spaces_list.risk_level, RiskLevel::Low);
    assert_eq!(spaces_list.safety_tier, SafetyTier::Safe);
    assert_eq!(spaces_list.requires_approval, Some(ApprovalMode::None));

    let pages_create = operation("confluence.pages.create");
    assert_eq!(pages_create.risk_level, RiskLevel::Medium);
    assert_eq!(pages_create.safety_tier, SafetyTier::Risky);
    assert_eq!(pages_create.idempotency, IdempotencyClass::BestEffort);

    let pages_delete = operation("confluence.pages.delete");
    assert_eq!(pages_delete.risk_level, RiskLevel::High);
    assert_eq!(pages_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(
        pages_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let health = operation("confluence.health");
    assert_eq!(health.risk_level, RiskLevel::Low);
    assert_eq!(health.safety_tier, SafetyTier::Safe);
    assert_eq!(health.idempotency, IdempotencyClass::Strict);

    let capability_section = manifest_capability_section();
    assert!(capability_section.contains("\"network.dns\""));
    assert!(capability_section.contains("\"network.outbound\""));
    assert!(capability_section.contains("\"system.exec\""));
    assert!(capability_section.contains("\"system.privileged\""));
    assert!(!capability_section.contains("network.listen"));
    assert!(include_str!("../manifest.toml").contains("deny_localhost = true"));

    let client = ConfluenceClient::new(
        "https://example.atlassian.net/wiki",
        TEST_EMAIL,
        "super-secret-confluence-token",
        no_retry_config(),
    )
    .expect("redaction proof client should build");
    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains("super-secret-confluence-token"));
    assert!(debug_output.contains("[REDACTED]"));
}

fn manifest_capability_section() -> &'static str {
    let manifest = include_str!("../manifest.toml");
    let (_, capabilities) = manifest
        .split_once("[capabilities]")
        .expect("Confluence manifest should define capabilities");
    let (capability_section, _) = capabilities
        .split_once("[provides.operations.")
        .expect("Confluence manifest should separate capabilities from operations");
    capability_section
}
