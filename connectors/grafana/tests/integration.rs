//! Integration tests for the FCP Grafana connector.

use fcp_grafana::connector::GrafanaConnector;
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// -- Helper --

async fn configured_connector(mock_url: &str) -> GrafanaConnector {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({
            "auth_token": "test-token",
            "base_url": mock_url,
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({"session_id": "test-session"}))
        .await
        .unwrap();
    connector
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn configure_with_bearer_token() {
    let mut connector = GrafanaConnector::new();
    let result = connector
        .handle_configure(json!({"auth_token": "my-token"}))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_missing_auth_fails() {
    let mut connector = GrafanaConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn handshake_before_configure_fails() {
    let mut connector = GrafanaConnector::new();
    let result = connector
        .handle_handshake(json!({"session_id": "s1"}))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn handshake_after_configure_succeeds() {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({"auth_token": "tok"}))
        .await
        .unwrap();
    let result = connector
        .handle_handshake(json!({"session_id": "s1"}))
        .await;
    assert!(result.is_ok());
    let val = result.unwrap();
    assert_eq!(val["connector_id"], "fcp.grafana");
    assert_eq!(val["protocol_version"], "2.0");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_reconfigure_invalidates_handshake() {
    let server = MockServer::start().await;
    let mut connector = configured_connector(&server.uri()).await;
    connector
        .handle_configure(json!({
            "auth_token": "new-token",
            "base_url": server.uri(),
        }))
        .await
        .unwrap();
    let h = connector.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured() {
    let connector = GrafanaConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn health_fully_configured() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured() {
    let connector = GrafanaConnector::new();
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
    let connector = GrafanaConnector::new();
    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn introspect_returns_operations() {
    let connector = GrafanaConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    assert_eq!(result["connector_id"], "fcp.grafana");
    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 9);
    let op_ids: Vec<&str> = ops
        .iter()
        .filter_map(|o| o.get("id").and_then(|v| v.as_str()))
        .collect();
    assert!(op_ids.contains(&"grafana.dashboards.list"));
    assert!(op_ids.contains(&"grafana.dashboards.get"));
    assert!(op_ids.contains(&"grafana.dashboards.create"));
    assert!(op_ids.contains(&"grafana.dashboards.delete"));
    assert!(op_ids.contains(&"grafana.datasources.list"));
    assert!(op_ids.contains(&"grafana.datasources.query"));
    assert!(op_ids.contains(&"grafana.alerts.list"));
    assert!(op_ids.contains(&"grafana.alerts.create"));
    assert!(op_ids.contains(&"grafana.annotations.create"));
}

#[fcp_async_core::runtime::test]
async fn simulate_known_operation() {
    let connector = GrafanaConnector::new();
    let result = connector
        .handle_simulate(json!({"operation_id": "grafana.dashboards.list"}))
        .await
        .unwrap();
    assert_eq!(result["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation() {
    let connector = GrafanaConnector::new();
    let result = connector
        .handle_simulate(json!({"operation_id": "grafana.unknown"}))
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

// -- Dashboards --

#[fcp_async_core::runtime::test]
async fn invoke_dashboards_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "uid": "abc", "title": "Dashboard 1"},
            {"id": 2, "uid": "def", "title": "Dashboard 2"},
        ])))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.list",
            "input": {"query": "prod", "limit": 50}
        }))
        .await
        .unwrap();
    let dashboards = result["dashboards"].as_array().unwrap();
    assert_eq!(dashboards.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn invoke_dashboards_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboards/uid/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "dashboard": {"title": "My Dashboard", "panels": []},
            "meta": {"slug": "my-dash", "version": 3}
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.get",
            "input": {"uid": "abc123"}
        }))
        .await
        .unwrap();
    assert!(result.get("dashboard").is_some());
    assert!(result.get("meta").is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_dashboards_get_missing_uid_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.get",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_dashboards_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/dashboards/db"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1, "uid": "new-uid", "url": "/d/new-uid/", "status": "success"
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.create",
            "input": {
                "dashboard": {"title": "New Dashboard", "panels": []},
                "overwrite": true
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["uid"], "new-uid");
    assert!(result.get("url").is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_dashboards_create_missing_dashboard_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.create",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_dashboards_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/dashboards/uid/abc123"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"message": "Dashboard deleted"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.delete",
            "input": {"uid": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

// -- Datasources --

#[fcp_async_core::runtime::test]
async fn invoke_datasources_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/datasources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "uid": "prometheus", "name": "Prometheus", "type": "prometheus"},
            {"id": 2, "uid": "loki", "name": "Loki", "type": "loki"},
        ])))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.list",
            "input": {}
        }))
        .await
        .unwrap();
    let datasources = result["datasources"].as_array().unwrap();
    assert_eq!(datasources.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn invoke_datasources_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ds/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": {"A": {"frames": [{"data": {"values": [[1.0, 2.0]]}}]}}
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.query",
            "input": {
                "datasource_uid": "prometheus",
                "query": "rate(http_requests_total[5m])",
                "from_ts": "now-1h",
                "to_ts": "now"
            }
        }))
        .await
        .unwrap();
    assert!(result.get("results").is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_datasources_query_missing_uid_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.query",
            "input": {"query": "up"}
        }))
        .await;
    assert!(result.is_err());
}

// -- Alerts --

#[fcp_async_core::runtime::test]
async fn invoke_alerts_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/ruler/grafana/api/v1/rules.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "default": [{"name": "High CPU", "rules": []}]
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.alerts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result.get("rules").is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_alerts_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ruler/grafana/api/v1/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uid": "alert-new", "title": "High Error Rate"
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.alerts.create",
            "input": {
                "rule": {"title": "High Error Rate", "condition": "A", "data": []}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["uid"], "alert-new");
}

#[fcp_async_core::runtime::test]
async fn invoke_alerts_create_missing_rule_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.alerts.create",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// -- Annotations --

#[fcp_async_core::runtime::test]
async fn invoke_annotations_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/annotations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42, "message": "Annotation added"
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.annotations.create",
            "input": {
                "text": "Deploy v2.1.0",
                "tags": ["deploy"],
                "dashboard_uid": "abc123"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], 42);
}

#[fcp_async_core::runtime::test]
async fn invoke_annotations_create_missing_text_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.annotations.create",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn invoke_unauthorized_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/datasources"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "Unauthorized"})))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_not_found_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboards/uid/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Dashboard not found"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.get",
            "input": {"uid": "nonexistent"}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_rate_limited_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/datasources"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "30")
                .set_body_json(json!({"message": "Rate limited"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.list",
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
            "operation_id": "grafana.unknown",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_before_handshake_fails() {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({"auth_token": "tok"}))
        .await
        .unwrap();
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn error_counter_increments() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/datasources"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "Server Error"})))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let _ = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.list",
            "input": {}
        }))
        .await;

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["errors"], 1);
    assert_eq!(health["requests"], 1);
}

#[fcp_async_core::runtime::test]
async fn request_counter_increments_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.list",
            "input": {}
        }))
        .await
        .unwrap();

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["requests"], 1);
    assert_eq!(health["errors"], 0);
}

// -- Auth modes --

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut connector = GrafanaConnector::new();
    let result = connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_both_auth_methods_rejected() {
    let mut connector = GrafanaConnector::new();
    let result = connector
        .handle_configure(json!({
            "auth_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_err());
}

// -- Handshake --

#[fcp_async_core::runtime::test]
async fn handshake_returns_capabilities() {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({"auth_token": "tok"}))
        .await
        .unwrap();
    let result = connector
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    let caps = result["capabilities"].as_array().unwrap();
    assert!(!caps.is_empty());
    assert!(
        caps.iter()
            .any(|c| c.as_str() == Some("grafana.dashboards.read"))
    );
}

// -- Simulate --

#[fcp_async_core::runtime::test]
async fn simulate_all_known_operations() {
    let connector = GrafanaConnector::new();
    let ops = [
        "grafana.dashboards.list",
        "grafana.dashboards.get",
        "grafana.dashboards.create",
        "grafana.dashboards.delete",
        "grafana.datasources.list",
        "grafana.datasources.query",
        "grafana.alerts.list",
        "grafana.alerts.create",
        "grafana.annotations.create",
    ];
    for op in ops {
        let result = connector
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert_eq!(result["allowed"], true, "expected {op} to be allowed");
    }
}

// -- Missing operation --

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_id_fails() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server.uri()).await;
    let result = connector.handle_invoke(json!({"input": {}})).await;
    assert!(result.is_err());
}

// -- Additional error statuses --

#[fcp_async_core::runtime::test]
async fn invoke_api_403_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/datasources"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "Forbidden"})))
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.datasources.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_api_500_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal Server Error"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "grafana.dashboards.list",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
}

// -- Health state transitions --

#[fcp_async_core::runtime::test]
async fn health_configured_but_not_handshaken() {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({"auth_token": "tok"}))
        .await
        .unwrap();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "degraded");
    assert_eq!(result["configured"], true);
    assert_eq!(result["handshaken"], false);
}

// -- Doctor state --

#[fcp_async_core::runtime::test]
async fn doctor_configured_not_handshaken_is_degraded() {
    let mut connector = GrafanaConnector::new();
    connector
        .handle_configure(json!({"auth_token": "tok"}))
        .await
        .unwrap();
    let result = connector.handle_doctor().await.unwrap();
    // Client and config are set, but handshake not done → non-critical failure → degraded
    let checks = result["checks"].as_array().unwrap();
    let handshake_check = checks.iter().find(|c| c["name"] == "handshake");
    if let Some(hc) = handshake_check {
        assert_eq!(hc["passed"], false);
    }
}
