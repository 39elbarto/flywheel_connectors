//! Integration tests for the FCP `Roam Research` connector.

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
use wiremock::matchers::{body_partial_json, header, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_roam::connector::RoamConnector;
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};

const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/roam_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/roam_connector/<timestamp>";

async fn setup_connector(mock_url: &str) -> RoamConnector {
    let mut c = RoamConnector::new();
    c.handle_configure(json!({
        "access_token": "test-token",
        "base_url": mock_url,
        "graph_name": "test-graph"
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
    let c = RoamConnector::new();
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
    let mut c = RoamConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_requires_session_id() {
    let server = MockServer::start().await;
    let mut c = RoamConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
        "graph_name": "g"
    }))
    .await
    .unwrap();

    let error = c.handle_handshake(json!({})).await.unwrap_err();
    match error {
        fcp_core::FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1003);
            assert_eq!(message, "Missing session_id");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert_eq!(health["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_reconfigure_clears_handshake_state() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;

    c.handle_configure(json!({
        "access_token": "test-token-2",
        "base_url": server.uri(),
        "graph_name": "reconfigured-graph"
    }))
    .await
    .unwrap();

    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["configured"], true);
    assert_eq!(health["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"title": "Page 1", "uid": "p1"}]
        ])))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = RoamConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_self_check_not_ready(&check);
    assert_eq!(check["reason_code"], "not_configured");
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 4);
}

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
async fn lifecycle_handshake_capabilities() {
    let server = MockServer::start().await;
    let mut c = RoamConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
        "graph_name": "g"
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s"}))
        .await
        .unwrap();
    let caps = hs["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let c = RoamConnector::new();
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
        "roam_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let c = RoamConnector::new();
    let doctor = c.handle_doctor().await.unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "roam_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_roam_api_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"title": "Daily Notes", "uid": "dn1"}],
            [{"title": "Project", "uid": "pr1"}]
        ])))
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
    assert_eq!(
        report["details"]["provisioning"]["auth_mode"],
        "bearer_token"
    );
    assert_eq!(report["details"]["live_probe"]["probe"], "roam.pages.list");
    assert_eq!(report["details"]["live_probe"]["page_count"], 2);
    println!(
        "roam_self_check_evidence={}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_roam_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("retry-after", "4")
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
    assert_eq!(report["details"]["live_probe"]["retry_after_ms"], 4000);
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_v3_compliance_evidence() {
    let c = RoamConnector::new();
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert_eq!(ops.len(), 4);
    assert_eq!(intro["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(intro["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert!(
        intro["manifest_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    println!(
        "roam_introspection_evidence={}",
        serde_json::to_string_pretty(&intro).unwrap()
    );
}

// -- Pages List --

#[fcp_async_core::runtime::test]
async fn pages_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"title": "Page 1", "uid": "p1"}],
            [{"title": "Page 2", "uid": "p2"}],
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["pages"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn pages_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["pages"].as_array().unwrap().is_empty());
}

// -- Pages Get --

#[fcp_async_core::runtime::test]
async fn pages_get() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"title": "Daily Notes", "uid": "dn1", "children": []}]
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.get",
            "input": {"title": "Daily Notes"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uid"], "dn1");
}

#[fcp_async_core::runtime::test]
async fn pages_get_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn pages_get_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.get",
            "input": {"title": "Nonexistent Page"}
        }))
        .await
        .is_err()
    );
}

// -- Blocks List --

#[fcp_async_core::runtime::test]
async fn blocks_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [{"uid": "b1", "string": "Block 1", "order": 0}],
            [{"uid": "b2", "string": "Block 2", "order": 1}],
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.blocks.list",
            "input": {"page_uid": "p1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["blocks"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn blocks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.blocks.list",
            "input": {"page_uid": "p1"}
        }))
        .await
        .unwrap();
    assert!(result["blocks"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn blocks_list_missing_page_uid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Blocks Create --

#[fcp_async_core::runtime::test]
async fn blocks_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/write"))
        .and(body_partial_json(json!({"action": "create-block"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"uid": "new-block-1"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "roam.blocks.create",
            "input": {"page_uid": "p1", "content": "New block content"}
        }))
        .await
        .unwrap();
    assert_eq!(result["uid"], "new-block-1");
}

#[fcp_async_core::runtime::test]
async fn blocks_create_missing_page_uid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.create",
            "input": {"content": "some content"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn blocks_create_missing_content() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.create",
            "input": {"page_uid": "p1"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn blocks_create_missing_both_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.blocks.create",
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
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error": true, "message": "Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error": true, "message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
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
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error": true, "message": "Not Found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error": true, "message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
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
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": true, "message": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
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
            "operation_id": "roam.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_pages_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "roam.pages.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_blocks_create() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "roam.blocks.create"}))
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
        !c.handle_simulate(json!({"operation_id": "roam.nope"}))
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
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "roam.pages.list",
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
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": true, "message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "roam.pages.list",
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
    Mock::given(method("POST"))
        .and(path_regex("/test-graph/q"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "roam.pages.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}
