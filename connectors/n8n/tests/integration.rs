//! Integration tests for the FCP n8n connector.

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

use fcp_n8n::connector::N8nConnector;

async fn setup_connector(mock_url: &str) -> N8nConnector {
    let mut c = N8nConnector::new();
    c.handle_configure(json!({
        "api_key": "test-n8n-api-key-123",
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
    let c = N8nConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
    assert_eq!(h["configured"], false);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_but_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = N8nConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = N8nConnector::new();
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
async fn lifecycle_self_check_configured() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
    assert_eq!(check["connector_id"], "fcp.n8n");
    assert_eq!(check["version"], "0.1.0");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = N8nConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_healthy() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "healthy");
    assert_eq!(d["checks"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = N8nConnector::new();
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["connector_id"], "fcp.n8n");
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_response() {
    let server = MockServer::start().await;
    let mut c = N8nConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    let h = c
        .handle_handshake(json!({"session_id": "sess-1"}))
        .await
        .unwrap();
    assert_eq!(h["protocol_version"], "2.0");
    assert_eq!(h["connector_id"], "fcp.n8n");
    assert_eq!(h["connector_version"], "0.1.0");
    let caps = h["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

// -- Workflows List --

#[fcp_async_core::runtime::test]
async fn workflows_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "1001", "name": "Daily Report", "active": true},
                {"id": "1002", "name": "Sync Contacts", "active": false},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workflows_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

// -- Workflows Get --

#[fcp_async_core::runtime::test]
async fn workflows_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows/1001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Daily Report",
            "active": true,
            "createdAt": "2025-01-15T10:00:00.000Z",
            "updatedAt": "2025-02-20T14:30:00.000Z",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.get",
            "input": {"id": "1001"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "1001");
    assert_eq!(result["name"], "Daily Report");
    assert_eq!(result["active"], true);
}

#[fcp_async_core::runtime::test]
async fn workflows_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Workflows Activate --

#[fcp_async_core::runtime::test]
async fn workflows_activate() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/workflows/1001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Daily Report",
            "active": true,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.activate",
            "input": {"id": "1001", "active": true}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "1001");
    assert_eq!(result["active"], true);
}

#[fcp_async_core::runtime::test]
async fn workflows_deactivate() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/workflows/1002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1002",
            "name": "Sync Contacts",
            "active": false,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.activate",
            "input": {"id": "1002", "active": false}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "1002");
    assert_eq!(result["active"], false);
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.activate",
            "input": {"active": true}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn workflows_activate_missing_active() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.activate",
            "input": {"id": "1001"}
        }))
        .await
        .is_err()
    );
}

// -- Executions List --

#[fcp_async_core::runtime::test]
async fn executions_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/executions"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "50001", "finished": true, "status": "success", "workflowId": "1001"},
                {"id": "50002", "finished": true, "status": "error", "workflowId": "1002"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.executions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn executions_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/executions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.executions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

// -- Executions Get --

#[fcp_async_core::runtime::test]
async fn executions_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/executions/50001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "50001",
            "finished": true,
            "mode": "trigger",
            "startedAt": "2025-03-01T08:00:00.000Z",
            "stoppedAt": "2025-03-01T08:00:05.000Z",
            "workflowId": "1001",
            "status": "success",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.executions.get",
            "input": {"id": "50001"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "50001");
    assert_eq!(result["finished"], true);
    assert_eq!(result["status"], "success");
}

#[fcp_async_core::runtime::test]
async fn executions_get_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.executions.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"message": "Invalid API key"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Insufficient permissions"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows/99999"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Workflow not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.get",
            "input": {"id": "99999"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Rate limit exceeded"}))
                .insert_header("retry-after", "30"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/executions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.executions.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_502_bad_gateway() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
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
            "operation_id": "n8n.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "n8n.workflows.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "n8n.workflows.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_workflow_activate() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "n8n.workflows.activate"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_executions_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "n8n.executions.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_executions_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "n8n.executions.get"}))
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
    let result = c
        .handle_simulate(json!({"operation_id": "n8n.nope"}))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
    assert_eq!(result["reason"], "Unknown operation");
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "n8n.workflows.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_increment_on_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Configuration --

#[fcp_async_core::runtime::test]
async fn configure_rejects_missing_base_url() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "api_key": "test-key",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_base_url() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "api_key": "test-key",
            "base_url": "",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_no_auth() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut c = N8nConnector::new();
    let result = c
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .await;
    assert!(result.is_ok());
}

// -- Invoke without configure --

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = N8nConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "n8n.workflows.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Empty response body handling --

#[fcp_async_core::runtime::test]
async fn empty_response_body_returns_empty_object() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/workflows/1001"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.activate",
            "input": {"id": "1001", "active": true}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

// -- Auth header verification --

#[fcp_async_core::runtime::test]
async fn auth_header_sent_correctly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workflows/1001"))
        .and(header("X-N8N-API-KEY", "test-n8n-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1001",
            "name": "Test Workflow"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "n8n.workflows.get",
            "input": {"id": "1001"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "1001");
}

// -- Invoke with missing operation_id --

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

// -- Reconfigure --

#[fcp_async_core::runtime::test]
async fn reconfigure_succeeds() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    // Reconfigure with new key
    let result = c
        .handle_configure(json!({
            "api_key": "new-api-key",
            "base_url": server.uri()
        }))
        .await;
    assert!(result.is_ok());
}
