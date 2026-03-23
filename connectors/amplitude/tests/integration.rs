//! Integration tests for the FCP Amplitude connector.

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

use fcp_amplitude::connector::AmplitudeConnector;
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/amplitude_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/amplitude_connector/<timestamp>";

async fn setup_connector(mock_url: &str) -> AmplitudeConnector {
    let mut c = AmplitudeConnector::new();
    c.handle_configure(json!({
        "api_key": "test_api_key",
        "secret_key": "test_secret_key",
        "base_url": mock_url
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

/// Compute the expected Basic auth header value.
fn expected_auth_header() -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("test_api_key:test_secret_key");
    format!("Basic {encoded}")
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = AmplitudeConnector::new();
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
    let mut c = AmplitudeConnector::new();
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
        .and(path("/cohorts"))
        .and(header("Authorization", expected_auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cohorts": []
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
    assert_eq!(check["details"]["provisioning"]["auth_mode"], "basic_auth");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = AmplitudeConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = AmplitudeConnector::new();
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_has_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert!(!ops.is_empty(), "introspect should list operations");
    // Verify first operation has expected structure
    assert!(ops[0]["id"].is_string());
    assert!(ops[0]["summary"].is_string());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_but_not_handshaken() {
    let mut c = AmplitudeConnector::new();
    c.handle_configure(json!({
        "api_key": "k",
        "secret_key": "s",
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_response() {
    let server = MockServer::start().await;
    let mut c = AmplitudeConnector::new();
    c.handle_configure(json!({
        "api_key": "k",
        "secret_key": "s",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    let h = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(h["connector_id"], "fcp.amplitude");
    assert_eq!(h["protocol_version"], "2.0");
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let c = AmplitudeConnector::new();
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
        "amplitude_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let c = AmplitudeConnector::new();
    let doctor = c.handle_doctor().await.unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "amplitude_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_amplitude_api_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
        .and(header("Authorization", expected_auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cohorts": [
                {"id": 1, "name": "Power Users"},
                {"id": 2, "name": "New Users"}
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
    assert_eq!(report["details"]["provisioning"]["auth_mode"], "basic_auth");
    assert_eq!(
        report["details"]["live_probe"]["probe"],
        "amplitude.cohorts.list"
    );
    assert_eq!(report["details"]["live_probe"]["cohorts_count"], 2);
    println!(
        "amplitude_self_check_evidence={}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_amplitude_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "3")
                .set_body_json(json!({"error": "Rate limit exceeded"})),
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
    let c = AmplitudeConnector::new();
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
        "amplitude_introspection_evidence={}",
        serde_json::to_string_pretty(&intro).unwrap()
    );
}

// -- Charts Query --

#[fcp_async_core::runtime::test]
async fn charts_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/charts/chart_123/query"))
        .and(header("Authorization", expected_auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "series": [[100, 200, 300]],
                "labels": ["2025-01-01", "2025-01-02", "2025-01-03"]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "amplitude.charts.query",
            "input": {"chart_id": "chart_123"}
        }))
        .await
        .unwrap();
    assert!(result.get("data").is_some());
}

#[fcp_async_core::runtime::test]
async fn charts_query_empty_data() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/charts/chart_empty/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "amplitude.charts.query",
            "input": {"chart_id": "chart_empty"}
        }))
        .await
        .unwrap();
    assert!(result.get("data").is_some());
}

#[fcp_async_core::runtime::test]
async fn charts_query_missing_chart_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.charts.query",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Cohorts List --

#[fcp_async_core::runtime::test]
async fn cohorts_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
        .and(header("Authorization", expected_auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cohorts": [
                {"id": 1, "name": "Power Users", "size": 1500},
                {"id": 2, "name": "New Users", "size": 500},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["cohorts"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn cohorts_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cohorts": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["cohorts"].as_array().unwrap().is_empty());
}

// -- Events Export --

#[fcp_async_core::runtime::test]
async fn events_export() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"event_type": "page_view", "user_id": "u1"},
                {"event_type": "click", "user_id": "u2"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "amplitude.events.export",
            "input": {"start": "20250101T00", "end": "20250102T00"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn events_export_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "amplitude.events.export",
            "input": {"start": "20250101T00", "end": "20250101T01"}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_export_missing_start() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.events.export",
            "input": {"end": "20250102T00"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn events_export_missing_end() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.events.export",
            "input": {"start": "20250101T00"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn events_export_missing_both() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.events.export",
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
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "Invalid API key"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
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
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": "Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
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
        .and(path("/charts/missing_chart/query"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "Chart not found"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.charts.query",
            "input": {"chart_id": "missing_chart"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
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
            "operation_id": "amplitude.cohorts.list",
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
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
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
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
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
            "operation_id": "amplitude.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_charts() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "amplitude.charts.query"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_cohorts() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "amplitude.cohorts.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_events() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "amplitude.events.export"}))
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
        !c.handle_simulate(json!({"operation_id": "amplitude.nope"}))
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
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"cohorts": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "amplitude.cohorts.list",
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
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
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
        .and(path("/cohorts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"cohorts": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
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
async fn configure_rejects_no_auth() {
    let mut c = AmplitudeConnector::new();
    assert!(c.handle_configure(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_api_key_only() {
    let mut c = AmplitudeConnector::new();
    assert!(c.handle_configure(json!({"api_key": "key"})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_secret_key_only() {
    let mut c = AmplitudeConnector::new();
    assert!(
        c.handle_configure(json!({"secret_key": "secret"}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = AmplitudeConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
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
async fn introspect_operations_have_summaries() {
    let c = AmplitudeConnector::new();
    let intro = c.handle_introspect().await.unwrap();
    for op in intro["operations"].as_array().unwrap() {
        let summary = op["summary"].as_str().unwrap();
        assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
    }
}

// -- Auth header verification --

#[fcp_async_core::runtime::test]
async fn auth_header_is_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cohorts"))
        .and(header("Authorization", expected_auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"cohorts": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "amplitude.cohorts.list",
            "input": {}
        }))
        .await;
    assert!(result.is_ok());
}
