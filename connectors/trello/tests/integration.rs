//! Integration tests for the FCP Trello connector.

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
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_trello::connector::TrelloConnector;

async fn setup_connector(mock_url: &str) -> TrelloConnector {
    let mut c = TrelloConnector::new();
    c.handle_configure(json!({
        "api_key": "test_key_123",
        "token": "test_token_456",
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
    let c = TrelloConnector::new();
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
    let mut c = TrelloConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 10);
}

// -- Boards List --

#[fcp_async_core::runtime::test]
async fn boards_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/members/me/boards"))
        .and(query_param("key", "test_key_123"))
        .and(query_param("token", "test_token_456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "b1", "name": "Engineering"},
            {"id": "b2", "name": "Marketing"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.boards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["boards"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn boards_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/members/me/boards"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.boards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["boards"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn boards_list_custom_member() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/members/johndoe/boards"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "b1", "name": "John's Board"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.boards.list",
            "input": {"member": "johndoe"}
        }))
        .await
        .unwrap();
    assert_eq!(result["boards"].as_array().unwrap().len(), 1);
}

// -- Boards Get --

#[fcp_async_core::runtime::test]
async fn boards_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/boards/board_abc"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "board_abc",
            "name": "Engineering",
            "desc": "Main board",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.boards.get",
            "input": {"board_id": "board_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "board_abc");
    assert_eq!(result["name"], "Engineering");
}

#[fcp_async_core::runtime::test]
async fn boards_get_missing_board_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.boards.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Lists List --

#[fcp_async_core::runtime::test]
async fn lists_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/boards/board_abc/lists"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "l1", "name": "To Do"},
            {"id": "l2", "name": "In Progress"},
            {"id": "l3", "name": "Done"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.lists.list",
            "input": {"board_id": "board_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["lists"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lists_list_missing_board_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.lists.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Cards List --

#[fcp_async_core::runtime::test]
async fn cards_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists/list_xyz/cards"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "c1", "name": "Fix login bug"},
            {"id": "c2", "name": "Add tests"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.cards.list",
            "input": {"list_id": "list_xyz"}
        }))
        .await
        .unwrap();
    assert_eq!(result["cards"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn cards_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists/list_xyz/cards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.cards.list",
            "input": {"list_id": "list_xyz"}
        }))
        .await
        .unwrap();
    assert!(result["cards"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn cards_list_missing_list_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Cards Get --

#[fcp_async_core::runtime::test]
async fn cards_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cards/card_abc"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "card_abc",
            "name": "Fix login bug",
            "desc": "Intermittent 500 errors",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.cards.get",
            "input": {"card_id": "card_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "card_abc");
    assert_eq!(result["name"], "Fix login bug");
}

#[fcp_async_core::runtime::test]
async fn cards_get_missing_card_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Cards Create --

#[fcp_async_core::runtime::test]
async fn cards_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/cards"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new_card_123",
            "name": "Fix login bug",
            "idList": "list_xyz",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.cards.create",
            "input": {
                "name": "Fix login bug",
                "idList": "list_xyz"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_card_123");
}

#[fcp_async_core::runtime::test]
async fn cards_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.create",
            "input": {"idList": "list_xyz"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn cards_create_missing_id_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.create",
            "input": {"name": "Some card"}
        }))
        .await
        .is_err()
    );
}

// -- Cards Update --

#[fcp_async_core::runtime::test]
async fn cards_update() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/cards/card_abc"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "card_abc",
            "name": "Updated card name",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.cards.update",
            "input": {
                "card_id": "card_abc",
                "name": "Updated card name"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "card_abc");
    assert_eq!(result["name"], "Updated card name");
}

#[fcp_async_core::runtime::test]
async fn cards_update_missing_card_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.update",
            "input": {"name": "New name"}
        }))
        .await
        .is_err()
    );
}

// -- Cards Delete --

#[fcp_async_core::runtime::test]
async fn cards_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/cards/card_abc"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.cards.delete",
            "input": {"card_id": "card_abc"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn cards_delete_missing_card_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Labels List --

#[fcp_async_core::runtime::test]
async fn labels_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/boards/board_abc/labels"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "lbl1", "name": "Bug", "color": "red"},
            {"id": "lbl2", "name": "Feature", "color": "green"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.labels.list",
            "input": {"board_id": "board_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["labels"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn labels_list_missing_board_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.labels.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Members List --

#[fcp_async_core::runtime::test]
async fn members_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/boards/board_abc/members"))
        .and(query_param("key", "test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "m1", "username": "johndoe", "fullName": "John Doe"},
            {"id": "m2", "username": "janedoe", "fullName": "Jane Doe"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "trello.members.list",
            "input": {"board_id": "board_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["members"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn members_list_missing_board_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.members.list",
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
        .and(path("/members/me/boards"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "invalid key", "error": "UNAUTHORIZED"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.boards.list",
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
        .and(path("/boards/board_abc"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Forbidden", "error": "ACCESS_DENIED"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.boards.get",
            "input": {"board_id": "board_abc"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cards/missing_card"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "card not found", "error": "NOT_FOUND"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.get",
            "input": {"card_id": "missing_card"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/members/me/boards"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Rate limit exceeded"}))
                .insert_header("retry-after", "10"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.boards.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lists/list_xyz/cards"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "trello.cards.list",
            "input": {"list_id": "list_xyz"}
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
            "operation_id": "trello.nope",
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
        c.handle_simulate(json!({"operation_id": "trello.cards.list"}))
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
        !c.handle_simulate(json!({"operation_id": "trello.nope"}))
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
        .and(path("/members/me/boards"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "trello.boards.list",
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
        .and(path("/members/me/boards"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "trello.boards.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
