//! Integration tests for the FCP `Roam Research` connector.

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
use wiremock::matchers::{body_partial_json, header, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_roam::connector::RoamConnector;

async fn setup_connector(mock_url: &str) -> RoamConnector {
    let mut c = RoamConnector::new();
    c.handle_configure(json!({
        "access_token": "test-token",
        "base_url": mock_url,
        "graph_name": "test-graph"
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[tokio::test]
async fn lifecycle_health_unconfigured() {
    let c = RoamConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = RoamConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[tokio::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
}

#[tokio::test]
async fn lifecycle_self_check_unconfigured() {
    let c = RoamConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn lifecycle_introspect_connector_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["connector_id"], "fcp.roam");
}

#[tokio::test]
async fn lifecycle_handshake_capabilities() {
    let server = MockServer::start().await;
    let mut c = RoamConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
        "graph_name": "g"
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s"}))
        .await
        .unwrap();
    let caps = hs["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

// -- Pages List --

#[tokio::test]
async fn pages_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"title": "Page 1", "uid": "p1"}],
            [{"title": "Page 2", "uid": "p2"}],
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["pages"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn pages_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["pages"].as_array().unwrap().is_empty());
}

// -- Pages Get --

#[tokio::test]
async fn pages_get() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"title": "Daily Notes", "uid": "dn1", "children": []}]
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.get",
            "input": {"title": "Daily Notes"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uid"], "dn1");
}

#[tokio::test]
async fn pages_get_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn pages_get_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.get",
            "input": {"title": "Nonexistent Page"}
        }))
        .await
        .is_err()
    );
}

// -- Blocks List --

#[tokio::test]
async fn blocks_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"uid": "b1", "string": "Block 1", "order": 0}],
            [{"uid": "b2", "string": "Block 2", "order": 1}],
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.blocks.list",
            "input": {"page_uid": "p1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["blocks"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn blocks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.blocks.list",
            "input": {"page_uid": "p1"}
        }))
        .await
        .unwrap();
    assert!(result["blocks"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn blocks_list_missing_page_uid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Blocks Create --

#[tokio::test]
async fn blocks_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/write"))
        .and(body_partial_json(json!({"action": "create-block"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"uid": "new-block-1"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.blocks.create",
            "input": {"page_uid": "p1", "content": "New block content"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uid"], "new-block-1");
}

#[tokio::test]
async fn blocks_create_missing_page_uid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.create",
            "input": {"content": "some content"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn blocks_create_missing_content() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.create",
            "input": {"page_uid": "p1"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn blocks_create_missing_both_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.create",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error": true, "message": "Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error": true, "message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error": true, "message": "Not Found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error": true, "message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": true, "message": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn simulate_known_pages_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "roam.pages.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_known_blocks_create() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "roam.blocks.create"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "roam.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[tokio::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "roam.pages.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[tokio::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": true, "message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[tokio::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}
