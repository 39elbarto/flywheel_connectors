//! Integration tests for the FCP `Todoist` connector.

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
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_todoist::connector::TodoistConnector;

async fn setup_connector(mock_url: &str) -> TodoistConnector {
    let mut c = TodoistConnector::new();
    c.handle_configure(json!({ "api_token": "test-api-token", "base_url": mock_url }))
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
    let c = TodoistConnector::new();
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
    let mut c = TodoistConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_reconfigure_invalidates_handshake() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_configure(json!({
        "api_token": "new-api-token",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], false);
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
    assert!(check.get("details").is_some());
    assert_eq!(check["details"]["provisioning"]["network_ok"], true);
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

// -- Projects List --

#[fcp_async_core::runtime::test]
async fn projects_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects"))
        .and(header("Authorization", "Bearer test-api-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "p1", "name": "Work"},
            {"id": "p2", "name": "Personal"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.projects.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["projects"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn projects_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.projects.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["projects"].as_array().unwrap().is_empty());
}

// -- Tasks List --

#[fcp_async_core::runtime::test]
async fn tasks_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/tasks.*"))
        .and(header("Authorization", "Bearer test-api-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "t1", "content": "Buy milk", "is_completed": false},
            {"id": "t2", "content": "Review PR", "is_completed": false},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.tasks.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["tasks"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tasks_list_with_project_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tasks"))
        .and(query_param("project_id", "proj_abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "t1", "content": "Task in project", "project_id": "proj_abc"},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.tasks.list",
            "input": {"project_id": "proj_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["tasks"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn tasks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/tasks.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.tasks.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["tasks"].as_array().unwrap().is_empty());
}

// -- Tasks Create --

#[fcp_async_core::runtime::test]
async fn tasks_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tasks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new_task_123",
            "content": "Review PR #42",
            "project_id": "proj_abc",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.tasks.create",
            "input": {
                "content": "Review PR #42",
                "project_id": "proj_abc",
                "due_string": "tomorrow"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_task_123");
}

#[fcp_async_core::runtime::test]
async fn tasks_create_minimal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tasks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new_task_456",
            "content": "Simple task",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.tasks.create",
            "input": {"content": "Simple task"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "new_task_456");
}

#[fcp_async_core::runtime::test]
async fn tasks_create_missing_content() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.tasks.create",
            "input": {"project_id": "proj_abc"}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Complete --

#[fcp_async_core::runtime::test]
async fn tasks_complete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tasks/task_abc/close"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.tasks.complete",
            "input": {"task_id": "task_abc"}
        }))
        .await
        .unwrap();
    // 204 No Content returns empty JSON object
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn tasks_complete_missing_task_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.tasks.complete",
            "input": {}
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
        .and(path("/tasks/task_abc"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "todoist.tasks.delete",
            "input": {"task_id": "task_abc"}
        }))
        .await
        .unwrap();
    // 204 No Content returns empty JSON object
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn tasks_delete_missing_task_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.tasks.delete",
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
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.projects.list",
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
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.projects.list",
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
        .and(path_regex("/tasks/.*/close"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Task not found"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.tasks.complete",
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
        .and(path("/projects"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_string("Rate limited")
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.projects.list",
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
        .and(path_regex("/tasks.*"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "todoist.tasks.list",
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
            "operation_id": "todoist.nope",
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
        c.handle_simulate(json!({"operation_id": "todoist.tasks.list"}))
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
        !c.handle_simulate(json!({"operation_id": "todoist.nope"}))
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
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "todoist.projects.list",
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
        .and(path("/projects"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "todoist.projects.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
