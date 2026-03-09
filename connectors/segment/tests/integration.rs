//! Integration tests for the FCP Segment CDP connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_segment::connector::SegmentConnector;

async fn setup_connector(mock_url: &str) -> SegmentConnector {
    let mut c = SegmentConnector::new();
    c.handle_configure(json!({ "api_token": "test_bearer_token_123", "base_url": mock_url }))
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
    let c = SegmentConnector::new();
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
    let mut c = SegmentConnector::new();
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
    assert_eq!(check["status"], "ok");
    assert!(check["details"]["provisioning"]["network_ok"]
        .as_bool()
        .unwrap());
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
    let mut c = SegmentConnector::new();
    c.handle_configure(json!({ "api_token": "test_token", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = SegmentConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = SegmentConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_returns_connector_info() {
    let server = MockServer::start().await;
    let mut c = SegmentConnector::new();
    c.handle_configure(json!({ "api_token": "test_token", "base_url": server.uri() }))
        .await
        .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.segment");
    assert_eq!(hs["protocol_version"], "2.0");
}

// -- Sources List --

#[fcp_async_core::runtime::test]
async fn sources_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources"))
        .and(header("Authorization", "Bearer test_bearer_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sources": [
                {"id": "src_1", "name": "Website", "slug": "website", "enabled": true},
                {"id": "src_2", "name": "Mobile App", "slug": "mobile-app", "enabled": true},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.sources.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["sources"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn sources_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sources": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.sources.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["sources"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn sources_list_no_sources_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.sources.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["sources"].as_array().unwrap().is_empty());
}

// -- Destinations List --

#[fcp_async_core::runtime::test]
async fn destinations_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources/src_abc123/destinations"))
        .and(header("Authorization", "Bearer test_bearer_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "destinations": [
                {"id": "dst_1", "name": "Google Analytics", "enabled": true, "connection_mode": "cloud"},
                {"id": "dst_2", "name": "Amplitude", "enabled": false, "connection_mode": "device"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.destinations.list",
            "input": {"source_id": "src_abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["destinations"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn destinations_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources/src_abc123/destinations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "destinations": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.destinations.list",
            "input": {"source_id": "src_abc123"}
        }))
        .await
        .unwrap();
    assert!(result["destinations"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn destinations_list_missing_source_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.destinations.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn destinations_list_no_destinations_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources/src_abc123/destinations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.destinations.list",
            "input": {"source_id": "src_abc123"}
        }))
        .await
        .unwrap();
    assert!(result["destinations"].as_array().unwrap().is_empty());
}

// -- Track --

#[fcp_async_core::runtime::test]
async fn track_event() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/track"))
        .and(header("Authorization", "Bearer test_bearer_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.track",
            "input": {
                "user_id": "user_123",
                "event": "Item Purchased",
                "properties": {"price": 9.99}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["success"], true);
}

#[fcp_async_core::runtime::test]
async fn track_event_without_properties() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/track"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.track",
            "input": {
                "user_id": "user_123",
                "event": "Page Viewed"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["success"], true);
}

#[fcp_async_core::runtime::test]
async fn track_event_missing_user_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.track",
            "input": {"event": "Item Purchased"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn track_event_missing_event() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.track",
            "input": {"user_id": "user_123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn track_event_empty_input() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.track",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn track_event_success_false() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/track"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": false
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "segment.track",
            "input": {
                "user_id": "user_123",
                "event": "Bad Event"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["success"], false);
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(
                json!({"error": {"message": "Unauthorized", "code": "AUTH_FAILED"}}),
            ),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.sources.list",
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
        .and(path("/sources"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error": {"message": "Forbidden", "code": "ACCESS_DENIED"}})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.sources.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources/missing_src/destinations"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(
                json!({"error": {"message": "Source not found", "code": "NOT_FOUND"}}),
            ),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.destinations.list",
            "input": {"source_id": "missing_src"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(
                    json!({"error": {"message": "Rate limit exceeded", "code": "RATE_LIMIT"}}),
                )
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.sources.list",
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
        .and(path("/track"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.track",
            "input": {
                "user_id": "user_123",
                "event": "Test"
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_empty_body_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "segment.sources.list",
            "input": {}
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
            "operation_id": "segment.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_sources() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "segment.sources.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_destinations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "segment.destinations.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_track() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "segment.track"}))
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
        !c.handle_simulate(json!({"operation_id": "segment.nope"}))
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
        .and(path("/sources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sources": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "segment.sources.list",
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
        .and(path("/sources"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "segment.sources.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sources": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "segment.sources.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Missing operation_id --

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "input": {}
        }))
        .await
        .is_err()
    );
}
