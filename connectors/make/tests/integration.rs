//! Integration tests for the FCP `Make` connector.

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

use fcp_make::connector::MakeConnector;

async fn setup_connector(mock_url: &str) -> MakeConnector {
    let mut c = MakeConnector::new();
    c.handle_configure(json!({ "api_token": "test_token_123", "base_url": mock_url }))
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
    let c = MakeConnector::new();
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
    let mut c = MakeConnector::new();
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_but_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = MakeConnector::new();
    c.handle_configure(json!({ "api_token": "test_token_123", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Scenarios List --

#[fcp_async_core::runtime::test]
async fn scenarios_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/scenarios"))
        .and(header("Authorization", "Token test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scenarios": [
                {"id": 1, "name": "Daily Sync", "isEnabled": true, "teamId": 99},
                {"id": 2, "name": "Weekly Report", "isEnabled": false, "teamId": 99},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "make.scenarios.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["scenarios"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn scenarios_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/scenarios"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scenarios": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "make.scenarios.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["scenarios"].as_array().unwrap().is_empty());
}

// -- Scenarios Run --

#[fcp_async_core::runtime::test]
async fn scenarios_run() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/scenarios/12345/run"))
        .and(header("Authorization", "Token test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "executionId": "exec_abc123",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "make.scenarios.run",
            "input": {"scenario_id": "12345"}
        }))
        .await
        .unwrap();
    assert_eq!(result["execution_id"], "exec_abc123");
}

#[fcp_async_core::runtime::test]
async fn scenarios_run_missing_scenario_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.scenarios.run",
            "input": {}
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
        .and(path("/scenarios/12345/executions"))
        .and(header("Authorization", "Token test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "executions": [
                {"id": 100, "scenarioId": 12345, "status": "success", "started": "2026-01-15T10:00:00Z", "finished": "2026-01-15T10:01:30Z"},
                {"id": 101, "scenarioId": 12345, "status": "failed", "started": "2026-01-15T11:00:00Z", "finished": "2026-01-15T11:00:05Z"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "make.executions.list",
            "input": {"scenario_id": "12345"}
        }))
        .await
        .unwrap();
    assert_eq!(result["executions"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn executions_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/scenarios/12345/executions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "executions": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "make.executions.list",
            "input": {"scenario_id": "12345"}
        }))
        .await
        .unwrap();
    assert!(result["executions"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn executions_list_missing_scenario_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.executions.list",
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
        .and(path("/scenarios"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "Invalid token"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.scenarios.list",
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
        .and(path("/scenarios"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.scenarios.list",
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
        .and(path("/scenarios/99999/executions"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Scenario not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.executions.list",
            "input": {"scenario_id": "99999"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/scenarios"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Rate limit exceeded"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.scenarios.list",
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
        .and(path("/scenarios"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.scenarios.list",
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
            "operation_id": "make.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_scenarios_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "make.scenarios.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_scenarios_run() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "make.scenarios.run"}))
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
        c.handle_simulate(json!({"operation_id": "make.executions.list"}))
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
        !c.handle_simulate(json!({"operation_id": "make.nope"}))
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
        .and(path("/scenarios"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"scenarios": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "make.scenarios.list",
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
        .and(path("/scenarios"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "make.scenarios.list",
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
        .and(path("/scenarios"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"scenarios": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "make.scenarios.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Auth header verification --

#[fcp_async_core::runtime::test]
async fn auth_header_uses_token_prefix() {
    let server = MockServer::start().await;
    // This mock specifically requires "Token test_token_123" in the Authorization header
    Mock::given(method("GET"))
        .and(path("/scenarios"))
        .and(header("Authorization", "Token test_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"scenarios": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "make.scenarios.list",
            "input": {}
        }))
        .await;
    // If auth header is wrong, mock won't match and we'd get an error
    assert!(result.is_ok());
}

// -- Handshake response --

#[fcp_async_core::runtime::test]
async fn handshake_response_contains_capabilities() {
    let server = MockServer::start().await;
    let mut c = MakeConnector::new();
    c.handle_configure(json!({ "api_token": "test_token_123", "base_url": server.uri() }))
        .await
        .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.make");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

// -- Self check when unconfigured --

#[fcp_async_core::runtime::test]
async fn self_check_unconfigured() {
    let c = MakeConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
}

// -- Doctor when unconfigured --

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured() {
    let c = MakeConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "unhealthy");
}

// -- Invoke before handshake --

#[fcp_async_core::runtime::test]
async fn invoke_before_handshake_fails() {
    let server = MockServer::start().await;
    let mut c = MakeConnector::new();
    c.handle_configure(json!({ "api_token": "tok", "base_url": server.uri() }))
        .await
        .unwrap();
    // Don't call handshake
    assert!(
        c.handle_invoke(json!({
            "operation_id": "make.scenarios.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}
