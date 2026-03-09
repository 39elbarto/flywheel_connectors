//! Integration tests for the FCP Asana connector.

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
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_asana::connector::AsanaConnector;

async fn setup_connector(mock_url: &str) -> AsanaConnector {
    let mut c = AsanaConnector::new();
    c.handle_configure(json!({ "access_token": "1/test_pat_token_123", "base_url": mock_url }))
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
    let c = AsanaConnector::new();
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
    let mut c = AsanaConnector::new();
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
    assert!(check.get("details").is_some());
    let provisioning = &check["details"]["provisioning"];
    assert_eq!(provisioning["auth_mode"], "personal_access_token");
    assert_eq!(provisioning["token_configured"], true);
    assert_eq!(provisioning["network_ok"], true);
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

// -- Workspaces List --

#[fcp_async_core::runtime::test]
async fn workspaces_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .and(header("Authorization", "Bearer 1/test_pat_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "ws1", "name": "My Workspace"},
                {"gid": "ws2", "name": "Another Workspace"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workspaces_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

// -- Projects List --

#[fcp_async_core::runtime::test]
async fn projects_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws_123/projects"))
        .and(header("Authorization", "Bearer 1/test_pat_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "p1", "name": "Backend Redesign"},
                {"gid": "p2", "name": "Mobile App"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.projects.list",
            "input": {"workspace_gid": "ws_123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn projects_list_missing_workspace_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.projects.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Projects Get --

#[fcp_async_core::runtime::test]
async fn projects_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "gid": "proj_456",
                "name": "My Project",
                "notes": "Important project",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.projects.get",
            "input": {"project_gid": "proj_456"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "proj_456");
    assert_eq!(result["data"]["name"], "My Project");
}

#[fcp_async_core::runtime::test]
async fn projects_get_missing_project_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.projects.get",
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
        .and(path("/projects/proj_789/tasks"))
        .and(header("Authorization", "Bearer 1/test_pat_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "t1", "name": "Implement login"},
                {"gid": "t2", "name": "Write tests"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {"project_gid": "proj_789"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tasks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_789/tasks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {"project_gid": "proj_789"}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn tasks_list_missing_project_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Get --

#[fcp_async_core::runtime::test]
async fn tasks_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tasks/task_abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "gid": "task_abc",
                "name": "Build the widget",
                "completed": false,
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.get",
            "input": {"task_gid": "task_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "task_abc");
    assert_eq!(result["data"]["completed"], false);
}

#[fcp_async_core::runtime::test]
async fn tasks_get_missing_task_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.get",
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
        .and(path("/tasks"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "data": {
                "gid": "new_task_123",
                "name": "Implement login page",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.create",
            "input": {
                "name": "Implement login page",
                "workspace": "ws_1"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "new_task_123");
}

#[fcp_async_core::runtime::test]
async fn tasks_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.create",
            "input": {"workspace": "ws_1"}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Update --

#[fcp_async_core::runtime::test]
async fn tasks_update() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/tasks/task_xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "gid": "task_xyz",
                "name": "Updated task name",
                "completed": true,
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.update",
            "input": {
                "task_gid": "task_xyz",
                "name": "Updated task name",
                "completed": true
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "task_xyz");
    assert_eq!(result["data"]["completed"], true);
}

#[fcp_async_core::runtime::test]
async fn tasks_update_missing_task_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.update",
            "input": {"name": "Updated name"}
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
        .and(path("/tasks/task_del"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.delete",
            "input": {"task_gid": "task_del"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn tasks_delete_missing_task_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Sections List --

#[fcp_async_core::runtime::test]
async fn sections_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_789/sections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "sec1", "name": "To Do"},
                {"gid": "sec2", "name": "In Progress"},
                {"gid": "sec3", "name": "Done"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.sections.list",
            "input": {"project_gid": "proj_789"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn sections_list_missing_project_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.sections.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Search --

#[fcp_async_core::runtime::test]
async fn tasks_search() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws_123/tasks/search"))
        .and(query_param("text", "login bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "t1", "name": "Fix login bug"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.search",
            "input": {"workspace_gid": "ws_123", "query": "login bug"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"][0]["name"], "Fix login bug");
}

#[fcp_async_core::runtime::test]
async fn tasks_search_missing_workspace_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.search",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn tasks_search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.search",
            "input": {"workspace_gid": "ws_123"}
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
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "errors": [{"message": "Not Authorized"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
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
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "errors": [{"message": "Forbidden"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
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
        .and(path("/tasks/missing_task"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "errors": [{"message": "task: Unknown object: missing_task"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.get",
            "input": {"task_gid": "missing_task"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "errors": [{"message": "Rate limit enforced"}]
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
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
        .and(path("/projects/proj_789/tasks"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {"project_gid": "proj_789"}
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
            "operation_id": "asana.nope",
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
        c.handle_simulate(json!({"operation_id": "asana.tasks.list"}))
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
        !c.handle_simulate(json!({"operation_id": "asana.nope"}))
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
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "asana.workspaces.list",
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
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
