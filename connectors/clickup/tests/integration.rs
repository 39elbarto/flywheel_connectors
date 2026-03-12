//! Integration tests for the FCP `ClickUp` connector.

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

use fcp_clickup::connector::ClickUpConnector;

async fn setup_connector(mock_url: &str) -> ClickUpConnector {
    let mut c = ClickUpConnector::new();
    c.handle_configure(json!({ "api_token": "pk_test_token_123", "base_url": mock_url }))
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
    let c = ClickUpConnector::new();
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
    let mut c = ClickUpConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

// -- Spaces List --

#[fcp_async_core::runtime::test]
async fn spaces_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team/team_123/space"))
        .and(header("Authorization", "pk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spaces": [
                {"id": "s1", "name": "Engineering"},
                {"id": "s2", "name": "Marketing"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.spaces.list",
            "input": {"team_id": "team_123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["spaces"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn spaces_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team/team_123/space"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spaces": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.spaces.list",
            "input": {"team_id": "team_123"}
        }))
        .await
        .unwrap();
    assert!(result["spaces"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn spaces_list_missing_team_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.spaces.list",
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
        .and(path("/space/space_456/list"))
        .and(header("Authorization", "pk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lists": [
                {"id": "l1", "name": "Sprint Backlog"},
                {"id": "l2", "name": "Done"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.lists.list",
            "input": {"space_id": "space_456"}
        }))
        .await
        .unwrap();
    assert_eq!(result["lists"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn lists_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/space/space_456/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lists": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.lists.list",
            "input": {"space_id": "space_456"}
        }))
        .await
        .unwrap();
    assert!(result["lists"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn lists_list_missing_space_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.lists.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks List --

#[fcp_async_core::runtime::test]
async fn tasks_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list/list_789/task"))
        .and(header("Authorization", "pk_test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tasks": [
                {"id": "t1", "name": "Implement login"},
                {"id": "t2", "name": "Write tests"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.tasks.list",
            "input": {"list_id": "list_789"}
        }))
        .await
        .unwrap();
    assert_eq!(result["tasks"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tasks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list/list_789/task"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tasks": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.tasks.list",
            "input": {"list_id": "list_789"}
        }))
        .await
        .unwrap();
    assert!(result["tasks"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn tasks_list_missing_list_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.tasks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Create --

#[fcp_async_core::runtime::test]
async fn tasks_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/list/list_789/task"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new_task_123",
            "name": "Implement login page",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.tasks.create",
            "input": {
                "list_id": "list_789",
                "name": "Implement login page"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_task_123");
}

#[fcp_async_core::runtime::test]
async fn tasks_create_missing_list_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.tasks.create",
            "input": {"name": "Some task"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn tasks_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.tasks.create",
            "input": {"list_id": "list_789"}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Delete --

#[fcp_async_core::runtime::test]
async fn tasks_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/task/task_abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "clickup.tasks.delete",
            "input": {"task_id": "task_abc"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn tasks_delete_missing_task_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.tasks.delete",
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
        .and(path("/team/team_123/space"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"err": "Token invalid", "ECODE": "OAUTH_017"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.spaces.list",
            "input": {"team_id": "team_123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team/team_123/space"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"err": "Forbidden", "ECODE": "ACCESS_DENIED"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.spaces.list",
            "input": {"team_id": "team_123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/task/missing_task"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"err": "Task not found", "ECODE": "ITEM_NOT_FOUND"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.tasks.delete",
            "input": {"task_id": "missing_task"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/team/team_123/space"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"err": "Rate limit exceeded", "ECODE": "RATE_LIMIT"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.spaces.list",
            "input": {"team_id": "team_123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list/list_789/task"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "clickup.tasks.list",
            "input": {"list_id": "list_789"}
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
            "operation_id": "clickup.nope",
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
        c.handle_simulate(json!({"operation_id": "clickup.tasks.list"}))
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
        !c.handle_simulate(json!({"operation_id": "clickup.nope"}))
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
        .and(path("/team/team_123/space"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"spaces": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "clickup.spaces.list",
        "input": {"team_id": "team_123"}
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
        .and(path("/team/team_123/space"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "clickup.spaces.list",
            "input": {"team_id": "team_123"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
