//! Integration tests for the FCP Mixpanel connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_mixpanel::connector::MixpanelConnector;

async fn setup_connector(mock_url: &str) -> MixpanelConnector {
    let mut c = MixpanelConnector::new();
    c.handle_configure(json!({
        "username": "sa_test_user",
        "secret": "sa_test_secret",
        "project_id": "12345",
        "base_url": mock_url
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = MixpanelConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = MixpanelConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = MixpanelConnector::new();
    c.handle_configure(json!({
        "username": "u",
        "secret": "s",
        "project_id": "1",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Events Query --

#[fcp_async_core::runtime::test]
async fn events_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insights"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"values": {"signup": {"2025-01-01": 100}}}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.events.query",
            "input": {"from_date": "2025-01-01", "to_date": "2025-01-31"}
        }))
        .await
        .unwrap();
    assert!(result["data"].is_object());
}

#[fcp_async_core::runtime::test]
async fn events_query_with_event_filter() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insights"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"values": {"signup": {"2025-01-01": 50}}}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.events.query",
            "input": {
                "from_date": "2025-01-01",
                "to_date": "2025-01-31",
                "event": "signup"
            }
        }))
        .await
        .unwrap();
    assert!(result["data"].is_object());
}

#[fcp_async_core::runtime::test]
async fn events_query_empty_data() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insights"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.events.query",
            "input": {"from_date": "2025-01-01", "to_date": "2025-01-31"}
        }))
        .await
        .unwrap();
    assert!(result["data"].is_object());
}

#[fcp_async_core::runtime::test]
async fn events_query_missing_from_date() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.events.query",
            "input": {"to_date": "2025-01-31"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn events_query_missing_to_date() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.events.query",
            "input": {"from_date": "2025-01-01"}
        }))
        .await
        .is_err()
    );
}

// -- Funnels List --

#[fcp_async_core::runtime::test]
async fn funnels_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"funnel_id": 1, "name": "Signup Funnel"},
            {"funnel_id": 2, "name": "Checkout Funnel"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.funnels.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["funnels"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn funnels_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.funnels.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["funnels"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn funnels_list_wrapped_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "funnels": [{"funnel_id": 42, "name": "Wrapped"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.funnels.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["funnels"].as_array().unwrap().len(), 1);
}

// -- Insights Query --

#[fcp_async_core::runtime::test]
async fn insights_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insights"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"series": [10, 20, 30]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.insights.query",
            "input": {"bookmark_id": "12345"}
        }))
        .await
        .unwrap();
    assert!(result["data"].is_object());
}

#[fcp_async_core::runtime::test]
async fn insights_query_missing_bookmark_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.insights.query",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"error": "Invalid credentials"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.funnels.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.funnels.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insights"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"error": "Report not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.insights.query",
            "input": {"bookmark_id": "nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error": "Rate limit exceeded"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.funnels.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insights"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.events.query",
            "input": {"from_date": "2025-01-01", "to_date": "2025-01-31"}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mixpanel.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "mixpanel.funnels.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "mixpanel.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "mixpanel.funnels.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/funnels/list"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "mixpanel.funnels.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
