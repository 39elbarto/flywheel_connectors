//! Integration tests for the FCP Zapier connector.

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

use fcp_zapier::connector::{ZapierConnector, provisioning_recipe};

async fn setup_connector(mock_url: &str) -> ZapierConnector {
    let mut c = ZapierConnector::new();
    c.handle_configure(json!({ "api_key": "sk_test_zapier_key_123", "base_url": mock_url }))
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
    let c = ZapierConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
    assert_eq!(h["configured"], false);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = ZapierConnector::new();
    c.handle_configure(json!({ "api_key": "tok", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
    assert_eq!(h["configured"], true);
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
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = ZapierConnector::new();
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
async fn lifecycle_self_check_ready() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert!(check["details"]["provisioning"]["network_ok"]
        .as_bool()
        .unwrap());
    assert_eq!(
        check["details"]["provisioning"]["auth_mode"], "api_key"
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = ZapierConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_credential_id() {
    let mut c = ZapierConnector::new();
    c.handle_configure(json!({
        "credential_id": "550e8400-e29b-41d4-a716-446655440000"
    }))
    .await
    .unwrap();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "credential_injection_required");
    assert!(check["details"]["provisioning"]["requires_credential_injection"]
        .as_bool()
        .unwrap());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_bad_network() {
    let mut c = ZapierConnector::new();
    c.handle_configure(json!({
        "api_key": "tok",
        "base_url": "https://evil.example.com"
    }))
    .await
    .unwrap();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "failed");
    assert_eq!(check["reason_code"], "network_constraints_invalid");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_healthy() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unhealthy_when_unconfigured() {
    let c = ZapierConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert!(!ops.is_empty(), "introspect should list operations");
    assert!(ops[0]["id"].is_string());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = ZapierConnector::new();
    c.handle_configure(json!({ "api_key": "tok", "base_url": server.uri() }))
        .await
        .unwrap();
    let result = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(result["protocol_version"], "2.0");
    assert_eq!(result["connector_id"], "fcp.zapier");
    let caps = result["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|v| v == "zapier.zaps.read"));
    assert!(caps.iter().any(|v| v == "zapier.zaps.write"));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_reconfigure() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    // Reconfigure with new key
    c.handle_configure(json!({ "api_key": "new_key", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
}

// -- Zaps List --

#[fcp_async_core::runtime::test]
async fn zaps_list_array_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .and(header("Authorization", "Bearer sk_test_zapier_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "z1", "title": "New Lead to Slack", "is_enabled": true},
            {"id": "z2", "title": "Email Digest", "is_enabled": false},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
            "input": {}
        }))
        .await
        .unwrap();
    let zaps = result["zaps"].as_array().unwrap();
    assert_eq!(zaps.len(), 2);
    assert_eq!(zaps[0]["id"], "z1");
    assert_eq!(zaps[0]["title"], "New Lead to Slack");
    assert_eq!(zaps[1]["id"], "z2");
}

#[fcp_async_core::runtime::test]
async fn zaps_list_object_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "zaps": [
                {"id": "z1", "title": "Zap A"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["zaps"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn zaps_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["zaps"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn zaps_list_no_input_required() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    // No input field at all should work
    let result = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.list"
        }))
        .await
        .unwrap();
    assert!(result["zaps"].as_array().unwrap().is_empty());
}

// -- Zaps Execute --

#[fcp_async_core::runtime::test]
async fn zaps_execute() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/exposed/01ARZ3NDEKTSV4RRFFQ69G5FAV/execute/"))
        .and(header("Authorization", "Bearer sk_test_zapier_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "result": {"message_id": "msg_123"},
            "action_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.execute",
            "input": {
                "action_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "params": {"body": "Hello from FCP"}
            }
        }))
        .await
        .unwrap();
    assert!(result["result"].is_object());
    assert_eq!(result["result"]["status"], "success");
    assert_eq!(result["result"]["result"]["message_id"], "msg_123");
}

#[fcp_async_core::runtime::test]
async fn zaps_execute_missing_action_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.execute",
            "input": {"params": {"body": "test"}}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn zaps_execute_with_empty_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/exposed/act_123/execute/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "result": {},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.execute",
            "input": {
                "action_id": "act_123",
                "params": {}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["status"], "success");
}

#[fcp_async_core::runtime::test]
async fn zaps_execute_no_params_field() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/exposed/act_456/execute/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    // When params is omitted, defaults to {}
    let result = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.execute",
            "input": {"action_id": "act_456"}
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["status"], "success");
}

// -- Error Handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"error": "Authentication required"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
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
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
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
        .and(path("/exposed/bad_id/execute/"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"detail": "Action not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.execute",
            "input": {"action_id": "bad_id", "params": {}}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error": "Rate limit exceeded"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
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
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
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
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_empty_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
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
            "operation_id": "zapier.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

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

#[fcp_async_core::runtime::test]
async fn simulate_known_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({"operation_id": "zapier.zaps.list"}))
        .await
        .unwrap();
    assert!(result["allowed"].as_bool().unwrap());
    assert_eq!(result["reason"], "Operation supported");
}

#[fcp_async_core::runtime::test]
async fn simulate_known_execute() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({"operation_id": "zapier.zaps.execute"}))
        .await
        .unwrap();
    assert!(result["allowed"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_simulate(json!({"operation_id": "zapier.nope"}))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
    assert_eq!(result["reason"], "Unknown operation");
}

#[fcp_async_core::runtime::test]
async fn simulate_empty_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c.handle_simulate(json!({})).await.unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "zapier.zaps.list",
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
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
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
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Configuration edge cases --

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_api_key() {
    let mut c = ZapierConnector::new();
    assert!(c.handle_configure(json!({ "api_key": "" })).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_whitespace_api_key() {
    let mut c = ZapierConnector::new();
    assert!(
        c.handle_configure(json!({ "api_key": "   " }))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_no_auth() {
    let mut c = ZapierConnector::new();
    assert!(c.handle_configure(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_both_auth() {
    let mut c = ZapierConnector::new();
    assert!(
        c.handle_configure(json!({
            "api_key": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut c = ZapierConnector::new();
    c.handle_configure(json!({
        "credential_id": "550e8400-e29b-41d4-a716-446655440000"
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
}

#[fcp_async_core::runtime::test]
async fn configure_with_custom_base_url() {
    let server = MockServer::start().await;
    let mut c = ZapierConnector::new();
    c.handle_configure(json!({
        "api_key": "tok",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
}

// -- Shutdown and re-lifecycle --

#[fcp_async_core::runtime::test]
async fn shutdown_resets_counters_display() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/exposed/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let mut c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "zapier.zaps.list",
        "input": {}
    }))
    .await
    .unwrap();
    c.handle_shutdown(json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = ZapierConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "zapier.zaps.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Provisioning recipe --

#[test]
fn provisioning_recipe_integration() {
    let recipe = provisioning_recipe();
    assert_eq!(recipe.id.as_str(), "zapier.api_key");
    assert_eq!(recipe.steps.len(), 3);
    let v = serde_json::to_value(&recipe).unwrap();
    assert!(v["description"].as_str().unwrap().contains("Zapier"));
}
