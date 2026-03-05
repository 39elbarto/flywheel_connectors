//! Integration tests for the FCP Monday.com connector.

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
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_monday::connector::MondayConnector;

/// Helper: GraphQL response wrapper for Monday.com API.
fn graphql_ok(data: &serde_json::Value) -> serde_json::Value {
    json!({ "data": data })
}

async fn setup_connector(mock_url: &str) -> MondayConnector {
    let mut c = MondayConnector::new();
    c.handle_configure(json!({ "api_token": "pk_test_token_123", "base_url": mock_url }))
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
    let c = MondayConnector::new();
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
    let mut c = MondayConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 7);
}

// -- Boards List --

#[tokio::test]
async fn boards_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", "pk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": [
                {"id": "1001", "name": "Sprint Board", "state": "active", "board_kind": "public"},
                {"id": "1002", "name": "Marketing", "state": "active", "board_kind": "private"},
            ]
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.boards.list",
            "input": {"limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["boards"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn boards_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": []
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.boards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["boards"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn boards_list_default_limit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": [{"id": "1", "name": "B1"}]
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.boards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["boards"].as_array().unwrap().len(), 1);
}

// -- Boards Get --

#[tokio::test]
async fn boards_get() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", "pk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": [
                {"id": "1001", "name": "Sprint Board", "description": "Main board", "state": "active"}
            ]
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.boards.get",
            "input": {"board_id": "1001"}
        }))
        .await
        .unwrap();
    assert_eq!(result["board"]["id"], "1001");
    assert_eq!(result["board"]["name"], "Sprint Board");
}

#[tokio::test]
async fn boards_get_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": []
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.boards.get",
            "input": {"board_id": "999999"}
        }))
        .await
        .unwrap();
    assert!(result["board"].is_null());
}

#[tokio::test]
async fn boards_get_missing_board_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.boards.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Items List --

#[tokio::test]
async fn items_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", "pk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": [{
                "items_page": {
                    "items": [
                        {"id": "item_1", "name": "Fix bug", "state": "active", "column_values": []},
                        {"id": "item_2", "name": "Add tests", "state": "active", "column_values": [
                            {"id": "status", "text": "Done", "value": "{\"index\":2}"}
                        ]},
                    ]
                }
            }]
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.items.list",
            "input": {"board_id": "1001"}
        }))
        .await
        .unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn items_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": [{
                "items_page": {
                    "items": []
                }
            }]
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.items.list",
            "input": {"board_id": "1001"}
        }))
        .await
        .unwrap();
    assert!(result["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn items_list_missing_board_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.items.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Items Create --

#[tokio::test]
async fn items_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "create_item": {
                "id": "new_item_123",
                "name": "Implement login page",
            }
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.items.create",
            "input": {
                "board_id": "1001",
                "item_name": "Implement login page"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_item_123");
}

#[tokio::test]
async fn items_create_with_column_values() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "create_item": {
                "id": "new_item_456",
                "name": "Deploy fix",
            }
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.items.create",
            "input": {
                "board_id": "1001",
                "item_name": "Deploy fix",
                "column_values": {"status": {"index": 1}}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_item_456");
}

#[tokio::test]
async fn items_create_missing_board_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.items.create",
            "input": {"item_name": "Some item"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn items_create_missing_item_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.items.create",
            "input": {"board_id": "1001"}
        }))
        .await
        .is_err()
    );
}

// -- Items Delete --

#[tokio::test]
async fn items_delete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "delete_item": {"id": "item_abc"}
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.items.delete",
            "input": {"item_id": "item_abc"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[tokio::test]
async fn items_delete_missing_item_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.items.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Updates List --

#[tokio::test]
async fn updates_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", "pk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "items": [{
                "updates": [
                    {"id": "upd_1", "text_body": "Looks good!", "creator": {"name": "Alice"}, "created_at": "2026-03-01T12:00:00Z"},
                    {"id": "upd_2", "text_body": "Merged.", "creator": {"name": "Bob"}, "created_at": "2026-03-02T09:00:00Z"},
                ]
            }]
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.updates.list",
            "input": {"item_id": "item_123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["updates"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn updates_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "items": [{
                "updates": []
            }]
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.updates.list",
            "input": {"item_id": "item_123"}
        }))
        .await
        .unwrap();
    assert!(result["updates"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn updates_list_missing_item_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.updates.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Updates Create --

#[tokio::test]
async fn updates_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "create_update": {
                "id": "upd_new",
                "text_body": "Great progress!"
            }
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "monday.updates.create",
            "input": {
                "item_id": "item_123",
                "body": "Great progress!"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "upd_new");
    assert_eq!(result["text_body"], "Great progress!");
}

#[tokio::test]
async fn updates_create_missing_item_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.updates.create",
            "input": {"body": "Some text"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn updates_create_missing_body() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.updates.create",
            "input": {"item_id": "item_123"}
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
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error_message": "Not Authenticated", "error_code": "NOT_AUTHENTICATED"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.boards.list",
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
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error_message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.boards.list",
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
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error_message": "Resource not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.boards.get",
            "input": {"board_id": "999999"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error_message": "Rate limit exceeded"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.boards.list",
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
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.boards.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_graphql_errors_in_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errors": [{"message": "Column not found"}],
            "data": null
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "monday.boards.list",
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
            "operation_id": "monday.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "monday.boards.list"}))
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
        !c.handle_simulate(json!({"operation_id": "monday.nope"}))
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
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(graphql_ok(&json!({
            "boards": []
        }))))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "monday.boards.list",
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
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "monday.boards.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
