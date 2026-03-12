//! Integration tests for the FCP Datadog connector.

use fcp_datadog::connector::DatadogConnector;
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// -- Helper --

async fn configured_connector(mock_url: &str) -> DatadogConnector {
    let mut connector = DatadogConnector::new();
    let params = json!({
        "api_key": "test-api-key",
        "app_key": "test-app-key",
        "base_url": mock_url,
    });
    connector.handle_configure(params).await.unwrap();
    connector
        .handle_handshake(json!({"session_id": "test-session"}))
        .await
        .unwrap();
    connector
}

// -- Lifecycle tests --

#[fcp_async_core::runtime::test]
async fn configure_with_api_keys() {
    let mut connector = DatadogConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "my-api-key",
            "app_key": "my-app-key"
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_missing_app_key_fails() {
    let mut connector = DatadogConnector::new();
    let result = connector
        .handle_configure(json!({"api_key": "my-api-key"}))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_missing_all_auth_fails() {
    let mut connector = DatadogConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn handshake_before_configure_fails() {
    let mut connector = DatadogConnector::new();
    let result = connector
        .handle_handshake(json!({"session_id": "s1"}))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn handshake_after_configure_succeeds() {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({"api_key": "k", "app_key": "a"}))
        .await
        .unwrap();
    let result = connector
        .handle_handshake(json!({"session_id": "s1"}))
        .await;
    assert!(result.is_ok());
    let val = result.unwrap();
    assert_eq!(val["connector_id"], "fcp.datadog");
    assert_eq!(val["protocol_version"], "2.0");
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured() {
    let connector = DatadogConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "unconfigured");
    assert_eq!(result["configured"], false);
    assert_eq!(result["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn health_configured_not_handshaken() {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({"api_key": "k", "app_key": "a"}))
        .await
        .unwrap();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "degraded");
    assert_eq!(result["configured"], true);
    assert_eq!(result["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn health_fully_configured() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
    assert_eq!(result["configured"], true);
    assert_eq!(result["handshaken"], true);
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured() {
    let connector = DatadogConnector::new();
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn doctor_fully_configured() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn self_check_unconfigured() {
    let connector = DatadogConnector::new();
    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "unconfigured");
    assert_eq!(result["connector_id"], "fcp.datadog");
}

#[fcp_async_core::runtime::test]
async fn self_check_configured() {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({"api_key": "k", "app_key": "a"}))
        .await
        .unwrap();
    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn introspect_returns_operations() {
    let connector = DatadogConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    assert_eq!(result["connector_id"], "fcp.datadog");
    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 8);
    let op_ids: Vec<&str> = ops
        .iter()
        .filter_map(|o| o.get("id").and_then(|v| v.as_str()))
        .collect();
    assert!(op_ids.contains(&"datadog.events.create"));
    assert!(op_ids.contains(&"datadog.events.list"));
    assert!(op_ids.contains(&"datadog.logs.search"));
    assert!(op_ids.contains(&"datadog.metrics.query"));
    assert!(op_ids.contains(&"datadog.metrics.submit"));
    assert!(op_ids.contains(&"datadog.monitors.create"));
    assert!(op_ids.contains(&"datadog.monitors.delete"));
    assert!(op_ids.contains(&"datadog.monitors.list"));
}

#[fcp_async_core::runtime::test]
async fn simulate_known_operation() {
    let connector = DatadogConnector::new();
    let result = connector
        .handle_simulate(json!({"operation_id": "datadog.events.create"}))
        .await
        .unwrap();
    assert_eq!(result["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation() {
    let connector = DatadogConnector::new();
    let result = connector
        .handle_simulate(json!({"operation_id": "datadog.unknown"}))
        .await
        .unwrap();
    assert_eq!(result["allowed"], false);
}

#[fcp_async_core::runtime::test]
async fn shutdown_resets_state() {
    let server = MockServer::start().await;
    let mut connector = configured_connector(&server.uri()).await;
    connector.handle_shutdown(json!({})).await.unwrap();
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
}

// -- Events --

#[fcp_async_core::runtime::test]
async fn invoke_events_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "event": {"id": 1, "title": "Deploy v2.0"},
            "status": "ok"
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.events.create",
            "input": {"title": "Deploy v2.0", "text": "Deployed"}
        }))
        .await
        .unwrap();
    assert!(result.get("event").is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_events_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/events.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "events": [
                {"id": 1, "title": "Event 1"},
                {"id": 2, "title": "Event 2"},
            ]
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.events.list",
            "input": {"start": 1_709_251_200, "end": 1_709_337_600}
        }))
        .await
        .unwrap();
    let events = result["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn invoke_events_list_missing_start_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.events.list",
            "input": {"end": 1_709_337_600}
        }))
        .await;
    assert!(result.is_err());
}

// -- Metrics --

#[fcp_async_core::runtime::test]
async fn invoke_metrics_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "series": [
                {"metric": "system.cpu.user", "pointlist": [[1.0, 42.5]]}
            ]
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.metrics.query",
            "input": {
                "query": "avg:system.cpu.user{*}",
                "from_ts": 1_709_251_200,
                "to_ts": 1_709_337_600
            }
        }))
        .await
        .unwrap();
    let series = result["series"].as_array().unwrap();
    assert_eq!(series.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_metrics_submit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/series"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({"status": "ok"})))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.metrics.submit",
            "input": {
                "series": [{"metric": "custom.latency", "points": [[1_709_251_200.0, 42.0]], "type": "gauge"}]
            }
        }))
        .await
        .unwrap();
    assert!(result.get("status").is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_metrics_submit_missing_series_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.metrics.submit",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// -- Monitors --

#[fcp_async_core::runtime::test]
async fn invoke_monitors_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/monitor.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "name": "Monitor 1"},
            {"id": 2, "name": "Monitor 2"},
        ])))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.list",
            "input": {}
        }))
        .await
        .unwrap();
    let monitors = result["monitors"].as_array().unwrap();
    assert_eq!(monitors.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn invoke_monitors_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/monitor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 12345,
            "name": "High CPU",
            "type": "metric alert"
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.create",
            "input": {
                "name": "High CPU",
                "type": "metric alert",
                "query": "avg(last_5m):avg:system.cpu.user{*} > 90"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], 12345);
}

#[fcp_async_core::runtime::test]
async fn invoke_monitors_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/monitor/12345"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.delete",
            "input": {"monitor_id": 12345}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

// -- Logs --

#[fcp_async_core::runtime::test]
async fn invoke_logs_search() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/logs-queries/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "logs": [
                {"id": "log1", "content": {"message": "Error", "service": "api"}},
                {"id": "log2", "content": {"message": "Timeout", "service": "db"}},
            ]
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.logs.search",
            "input": {"query": "service:api status:error", "from_ts": "now-1h", "to_ts": "now", "limit": 100}
        }))
        .await
        .unwrap();
    let logs = result["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 2);
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn invoke_unauthorized_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/monitor.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"errors": ["Unauthorized"]})))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_forbidden_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/monitor.*"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"errors": ["Forbidden"]})))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_not_found_error() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/monitor/99999"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"errors": ["Monitor not found"]})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.delete",
            "input": {"monitor_id": 99999}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_rate_limited_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/monitor.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("x-ratelimit-reset", "30")
                .set_body_json(json!({"errors": ["Rate limited"]})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.unknown.op",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_id_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector.handle_invoke(json!({"input": {}})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_before_handshake_fails() {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({"api_key": "k", "app_key": "a"}))
        .await
        .unwrap();
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// -- Region configuration --

#[fcp_async_core::runtime::test]
async fn configure_with_region() {
    let mut connector = DatadogConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "k",
            "app_key": "a",
            "region": "eu1"
        }))
        .await;
    assert!(result.is_ok());
}

// -- Error counters --

#[fcp_async_core::runtime::test]
async fn error_counter_increments() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/monitor.*"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"errors": ["Server Error"]})))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    let _ = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.list",
            "input": {}
        }))
        .await;

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["errors"], 1);
    assert_eq!(health["requests"], 1);
}

// -- Simulate: all 8 operations --

#[fcp_async_core::runtime::test]
async fn simulate_all_known_operations() {
    let connector = DatadogConnector::new();
    let ops = [
        "datadog.events.create",
        "datadog.events.list",
        "datadog.logs.search",
        "datadog.metrics.query",
        "datadog.metrics.submit",
        "datadog.monitors.create",
        "datadog.monitors.delete",
        "datadog.monitors.list",
    ];
    for op in &ops {
        let result = connector
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert_eq!(result["allowed"], true, "simulate should allow {op}");
    }
}

// -- Configure: credential_id --

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut connector = DatadogConnector::new();
    let result = connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_ok());
}

// -- Configure: both methods rejected --

#[fcp_async_core::runtime::test]
async fn configure_both_auth_methods_rejected() {
    let mut connector = DatadogConnector::new();
    let result = connector
        .handle_configure(json!({
            "api_key": "k",
            "app_key": "a",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_err());
}

// -- Handshake: returns capabilities --

#[fcp_async_core::runtime::test]
async fn handshake_returns_capabilities() {
    let mut connector = DatadogConnector::new();
    connector
        .handle_configure(json!({"api_key": "k", "app_key": "a"}))
        .await
        .unwrap();
    let result = connector
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    let caps = result["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "datadog.events.read"));
    assert!(caps.iter().any(|c| c == "datadog.events.write"));
    assert!(caps.iter().any(|c| c == "datadog.metrics.read"));
    assert!(caps.iter().any(|c| c == "datadog.monitors.write"));
    assert!(caps.iter().any(|c| c == "datadog.logs.read"));
}

// -- Logs search: missing query fails --

#[fcp_async_core::runtime::test]
async fn invoke_logs_search_missing_query_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.logs.search",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// -- Metrics query: missing fields fails --

#[fcp_async_core::runtime::test]
async fn invoke_metrics_query_missing_query_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.metrics.query",
            "input": {"from_ts": 1, "to_ts": 2}
        }))
        .await;
    assert!(result.is_err());
}

// -- Request counter --

#[fcp_async_core::runtime::test]
async fn request_counter_increments_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/v1/monitor.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let connector = configured_connector(&format!("{}/api/v1", server.uri())).await;
    connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.list",
            "input": {}
        }))
        .await
        .unwrap();

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["requests"], 1);
    assert_eq!(health["errors"], 0);
}

// -- Monitors delete: missing monitor_id fails --

#[fcp_async_core::runtime::test]
async fn invoke_monitors_delete_missing_id_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "datadog.monitors.delete",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}
