//! Integration tests for the FCP `PostHog` connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
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

use fcp_posthog::connector::PostHogConnector;
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/posthog_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/posthog_connector/<timestamp>";

async fn setup_connector(mock_url: &str) -> PostHogConnector {
    let mut c = PostHogConnector::new();
    c.handle_configure(json!({
        "api_key": "phx_test_key_123",
        "project_id": "12345",
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
    let c = PostHogConnector::new();
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
    let mut c = PostHogConnector::new();
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
    Mock::given(method("GET"))
        .and(path("/projects/12345/insights"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": []
        })))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert!(
        check["details"]["provisioning"]["network_ok"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(check["details"]["provisioning"]["auth_mode"], "api_key");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = PostHogConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_credential_id() {
    let server = MockServer::start().await;
    let mut c = PostHogConnector::new();
    c.handle_configure(json!({
        "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        "project_id": "12345",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "credential_injection_required");
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
async fn health_unconfigured_includes_guidance() {
    let c = PostHogConnector::new();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert_eq!(health["ready"], false);
    assert_eq!(
        health["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(health["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert!(health["details"]["operator_guidance"]["prerequisites"].is_array());
    println!(
        "posthog_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let c = PostHogConnector::new();
    let doctor = c.handle_doctor().await.unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "posthog_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_posthog_api_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/insights"))
        .and(header("Authorization", "Bearer phx_test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": 1, "name": "Weekly Active Users"},
                {"id": 2, "name": "Signup Funnel"}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let doctor = c.handle_doctor().await.unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);

    let report = c.handle_self_check().await.unwrap();
    assert_self_check_ready(&report);
    assert_eq!(
        report["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(report["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert_eq!(report["details"]["provisioning"]["auth_mode"], "api_key");
    assert_eq!(
        report["details"]["live_probe"]["probe"],
        "posthog.insights.list"
    );
    assert_eq!(report["details"]["live_probe"]["results_count"], 2);
    println!(
        "posthog_self_check_evidence={}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_posthog_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/insights"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("retry-after", "3")
                .set_body_string("temporary outage"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let report = c.handle_self_check().await.unwrap();
    assert_self_check_not_ready(&report);
    assert_eq!(report["status"], "degraded");
    assert_eq!(report["reason_code"], "self_check_retryable");
    assert_eq!(report["details"]["live_probe"]["retryable"], true);
    assert_eq!(report["details"]["live_probe"]["retry_after_ms"], 3000);
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_v3_compliance_evidence() {
    let c = PostHogConnector::new();
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert_eq!(ops.len(), 3);
    assert!(ops.iter().all(|op| {
        op["ai_hints"]["examples"]
            .as_array()
            .is_some_and(|examples| !examples.is_empty())
    }));
    assert_eq!(intro["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(intro["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert!(
        intro["manifest_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    println!(
        "posthog_introspection_evidence={}",
        serde_json::to_string_pretty(&intro).unwrap()
    );
}

// -- Events Query --

#[fcp_async_core::runtime::test]
async fn events_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/12345/query"))
        .and(header("Authorization", "Bearer phx_test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                ["$pageview", 1500],
                ["$identify", 300],
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "posthog.events.query",
            "input": {"query": "SELECT event, count() FROM events GROUP BY event ORDER BY count() DESC LIMIT 10"}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn events_query_empty_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/12345/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "posthog.events.query",
            "input": {"query": "SELECT event FROM events WHERE 1=0"}
        }))
        .await
        .unwrap();
    assert!(result["results"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_query_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "posthog.events.query",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Insights List --

#[fcp_async_core::runtime::test]
async fn insights_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/insights"))
        .and(header("Authorization", "Bearer phx_test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": 1, "name": "Weekly Active Users", "short_id": "abc123"},
                {"id": 2, "name": "Conversion Funnel", "short_id": "def456"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "posthog.insights.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn insights_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/insights"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "posthog.insights.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["results"].as_array().unwrap().is_empty());
}

// -- Feature Flags List --

#[fcp_async_core::runtime::test]
async fn feature_flags_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/feature_flags"))
        .and(header("Authorization", "Bearer phx_test_key_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": 1, "key": "new-dashboard", "active": true},
                {"id": 2, "key": "beta-feature", "active": false},
                {"id": 3, "key": "dark-mode", "active": true},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "posthog.feature_flags.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn feature_flags_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/feature_flags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "posthog.feature_flags.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["results"].as_array().unwrap().is_empty());
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/insights"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "type": "authentication_error",
            "code": "not_authenticated",
            "detail": "Authentication credentials were not provided."
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "posthog.insights.list",
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
        .and(path("/projects/12345/feature_flags"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "type": "permission_denied",
            "code": "permission_denied",
            "detail": "You do not have permission to perform this action."
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "posthog.feature_flags.list",
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
        .and(path("/projects/12345/insights"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "type": "invalid_request",
            "code": "not_found",
            "detail": "Not found."
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "posthog.insights.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/12345/insights"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "type": "throttled",
                    "code": "throttled",
                    "detail": "Request was throttled."
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "posthog.insights.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/12345/query"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "posthog.events.query",
            "input": {"query": "SELECT 1"}
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
            "operation_id": "posthog.nope",
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
        c.handle_simulate(json!({"operation_id": "posthog.events.query"}))
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
        !c.handle_simulate(json!({"operation_id": "posthog.nope"}))
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
        .and(path("/projects/12345/insights"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "posthog.insights.list",
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
        .and(path("/projects/12345/insights"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "posthog.insights.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
