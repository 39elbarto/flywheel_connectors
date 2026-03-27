//! Integration tests for the FCP `Retool` connector.

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
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_retool::connector::RetoolConnector;

async fn setup_connector(mock_url: &str) -> RetoolConnector {
    let mut c = RetoolConnector::new();
    c.handle_configure(json!({
        "api_token": "test-retool-token",
        "base_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = RetoolConnector::new();
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
    let mut c = RetoolConnector::new();
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
    let c = RetoolConnector::new();
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
    let c = RetoolConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let mut c = RetoolConnector::new();
    c.handle_configure(json!({
        "api_token": "tok",
        "base_url": "https://example.com",
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Workflows List ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn workflows_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .and(header("Authorization", "Bearer test-retool-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "wf_1", "name": "Daily Report", "isEnabled": true},
                {"id": "wf_2", "name": "Weekly Cleanup", "isEnabled": false},
            ],
            "totalCount": 2,
            "hasMore": false
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
    assert_eq!(result["totalCount"], 2);
}

#[fcp_async_core::runtime::test]
async fn workflows_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
            "totalCount": 0,
            "hasMore": false
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn workflows_list_with_pagination() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "wf_1"}],
            "totalCount": 50,
            "nextToken": "tok_abc",
            "hasMore": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
    assert_eq!(result["totalCount"], 50);
    assert!(result["hasMore"].as_bool().unwrap());
}

// -- Workflows Run -----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn workflows_run_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/workflows/wf_abc123/run"))
        .and(header("Authorization", "Bearer test-retool-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"result": "success", "rows_processed": 42},
            "workflowId": "wf_abc123",
            "success": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.run",
            "input": {"workflow_id": "wf_abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["workflowId"], "wf_abc123");
    assert!(result["success"].as_bool().unwrap());
    assert_eq!(result["data"]["rows_processed"], 42);
}

#[fcp_async_core::runtime::test]
async fn workflows_run_with_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/workflows/wf_xyz/run"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"result": "ok"},
            "success": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.run",
            "input": {
                "workflow_id": "wf_xyz",
                "body": {"param1": "value1", "param2": 42}
            }
        }))
        .await
        .unwrap();
    assert!(result["success"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn workflows_run_missing_workflow_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.run",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_run_null_workflow_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.run",
            "input": {"workflow_id": null}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_run_numeric_workflow_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.run",
            "input": {"workflow_id": 12345}
        }))
        .await
        .is_err()
    );
}

// -- Error handling ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "Invalid API token", "status": 401})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.list",
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
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Forbidden", "status": 403})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.list",
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
        .and(path_regex("/workflows/.*/run"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Workflow not found", "status": 404})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.run",
            "input": {"workflow_id": "wf_missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests", "status": 429}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.list",
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
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal server error", "status": 500})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_502() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(502).set_body_json(json!({"message": "Bad gateway"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate ---------------------------------------------------

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflows_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "retool.workflows.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflows_run() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "retool.workflows.run"}))
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
        !c.handle_simulate(json!({"operation_id": "retool.nope"}))
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

// -- Counters ----------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "retool.workflows.list",
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
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal error", "status": 500})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.list",
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
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Handshake response ------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = RetoolConnector::new();
    c.handle_configure(json!({
        "api_token": "tok",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.retool");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "retool.workflows.read"));
    assert!(caps.iter().any(|c| c == "retool.workflows.write"));
}

// -- Invoke before ready -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = RetoolConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Configure with subdomain ------------------------------------------------

#[fcp_async_core::runtime::test]
async fn configure_with_subdomain() {
    let mut c = RetoolConnector::new();
    let result = c
        .handle_configure(json!({
            "api_token": "tok_sub",
            "subdomain": "myorg",
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_with_base_url_override() {
    let server = MockServer::start().await;
    let mut c = RetoolConnector::new();
    c.handle_configure(json!({
        "api_token": "tok_override",
        "subdomain": "ignored",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "s2"}))
        .await
        .unwrap();

    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "wf_override"}]
        })))
        .mount(&server)
        .await;

    let result = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

// -- Reconfigure after shutdown ----------------------------------------------

#[fcp_async_core::runtime::test]
async fn reconfigure_after_shutdown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "wf_reconf"}]
        })))
        .mount(&server)
        .await;

    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();

    // Reconfigure
    c.handle_configure(json!({
        "api_token": "new_token",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "s3"}))
        .await
        .unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "retool.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

// -- Doctor details ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn doctor_shows_checks() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let doc = c.handle_doctor().await.unwrap();
    let checks = doc["checks"].as_array().unwrap();
    assert!(checks.len() >= 3);
    assert!(checks.iter().all(|c| c["passed"].as_bool().unwrap()));
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_shows_failures() {
    let c = RetoolConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    let checks = doc["checks"].as_array().unwrap();
    let config_check = checks
        .iter()
        .find(|c| c["name"] == "configuration")
        .unwrap();
    assert!(!config_check["passed"].as_bool().unwrap());
    assert!(config_check["message"].as_str().is_some());
}

// -- Introspect details ------------------------------------------------------

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
async fn introspect_operations_have_ids() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().unwrap();
    for op in ops {
        assert!(op["id"].as_str().is_some());
        assert!(op["summary"].as_str().is_some());
    }
}
