//! Integration tests for the FCP `Logseq` connector.

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
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_logseq::connector::LogseqConnector;

async fn setup_connector(mock_url: &str) -> LogseqConnector {
    let mut c = LogseqConnector::new();
    c.handle_configure(json!({
        "access_token": "test-token",
        "base_url": mock_url,
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
    let c = LogseqConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = LogseqConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
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
    let mut c = LogseqConnector::new();
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
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = LogseqConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = LogseqConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 4);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_has_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert!(!ops.is_empty(), "introspect should list operations");
    assert!(ops[0]["id"].is_string());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_capabilities() {
    let server = MockServer::start().await;
    let mut c = LogseqConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
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

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_protocol_version() {
    let server = MockServer::start().await;
    let mut c = LogseqConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s"}))
        .await
        .unwrap();
    assert_eq!(hs["protocol_version"], "2.0");
    assert_eq!(hs["connector_id"], "fcp.logseq");
}

// -- Pages List --

#[fcp_async_core::runtime::test]
async fn pages_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"name": "page 1", "uuid": "p1"},
            {"name": "page 2", "uuid": "p2"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["pages"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn pages_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["pages"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn pages_list_many_pages() {
    let server = MockServer::start().await;
    let pages: Vec<serde_json::Value> = (0..50)
        .map(|i| json!({"name": format!("page {i}"), "uuid": format!("p{i}")}))
        .collect();
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(pages)))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["pages"].as_array().unwrap().len(), 50);
}

// -- Pages Get --

#[fcp_async_core::runtime::test]
async fn pages_get() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/page"))
        .and(body_partial_json(json!({"name": "Daily Notes"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "daily notes",
            "uuid": "dn-123",
            "original-name": "Daily Notes",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.pages.get",
            "input": {"name": "Daily Notes"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uuid"], "dn-123");
}

#[fcp_async_core::runtime::test]
async fn pages_get_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn pages_get_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.get",
            "input": {"name": "Nonexistent Page"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn pages_get_with_properties() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "research",
            "uuid": "r-1",
            "properties": {"tags": ["ai", "ml"]},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.pages.get",
            "input": {"name": "research"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uuid"], "r-1");
    assert!(result["properties"].is_object());
}

// -- Blocks List --

#[fcp_async_core::runtime::test]
async fn blocks_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/page-blocks"))
        .and(body_partial_json(json!({"page": "Daily Notes"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"uuid": "b1", "content": "Block 1"},
            {"uuid": "b2", "content": "Block 2"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.blocks.list",
            "input": {"page": "Daily Notes"}
        }))
        .await
        .unwrap();
    assert_eq!(result["blocks"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn blocks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/page-blocks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.blocks.list",
            "input": {"page": "Empty Page"}
        }))
        .await
        .unwrap();
    assert!(result["blocks"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn blocks_list_missing_page() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.blocks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn blocks_list_nested_children() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/page-blocks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "uuid": "b1",
                "content": "Parent",
                "children": [
                    {"uuid": "b2", "content": "Child 1"},
                    {"uuid": "b3", "content": "Child 2"}
                ]
            },
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.blocks.list",
            "input": {"page": "Nested Page"}
        }))
        .await
        .unwrap();
    let blocks = result["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0]["children"].is_array());
}

// -- Blocks Create --

#[fcp_async_core::runtime::test]
async fn blocks_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insert-block"))
        .and(body_partial_json(
            json!({"page": "Project Notes", "content": "New block content"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"uuid": "new-block-1"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.blocks.create",
            "input": {"page": "Project Notes", "content": "New block content"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uuid"], "new-block-1");
}

#[fcp_async_core::runtime::test]
async fn blocks_create_missing_page() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.blocks.create",
            "input": {"content": "some content"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn blocks_create_missing_content() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.blocks.create",
            "input": {"page": "Test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn blocks_create_missing_both_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.blocks.create",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn blocks_create_todo_content() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insert-block"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"uuid": "todo-1"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "logseq.blocks.create",
            "input": {"page": "Tasks", "content": "TODO Review PR #42"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uuid"], "todo-1");
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "Unauthorized"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.list",
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
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "Not Found"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.get",
            "input": {"name": "Missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.list",
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
        .and(path("/pages"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"error": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_503() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"error": "Service unavailable"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.list",
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
            "operation_id": "logseq.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

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

#[fcp_async_core::runtime::test]
async fn simulate_known_pages_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "logseq.pages.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_pages_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "logseq.pages.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_blocks_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "logseq.blocks.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_blocks_create() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "logseq.blocks.create"}))
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
        !c.handle_simulate(json!({"operation_id": "logseq.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_empty_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({})).await.unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "logseq.pages.list",
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
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "Internal error"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "logseq.pages.list",
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
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "logseq.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_mixed_success_and_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "fail"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    // Success
    c.handle_invoke(json!({
        "operation_id": "logseq.pages.list",
        "input": {}
    }))
    .await
    .unwrap();
    // Error
    let _ = c
        .handle_invoke(json!({
            "operation_id": "logseq.pages.get",
            "input": {"name": "fail"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 2);
    assert_eq!(h["errors"], 1);
}

// -- Configuration edge cases --

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut c = LogseqConnector::new();
    let result = c
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_both_auth() {
    let mut c = LogseqConnector::new();
    let result = c
        .handle_configure(json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_no_auth() {
    let mut c = LogseqConnector::new();
    let result = c.handle_configure(json!({})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_token() {
    let mut c = LogseqConnector::new();
    let result = c.handle_configure(json!({"access_token": ""})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn reconfigure_resets_state() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let mut c = setup_connector(&server.uri()).await;
    // Reconfigure
    c.handle_configure(json!({
        "access_token": "new-token",
        "base_url": &server.uri(),
    }))
    .await
    .unwrap();
    // Still configured, but handshake lost
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
}
