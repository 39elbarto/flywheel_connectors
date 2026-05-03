//! Integration tests for the FCP `GitLab` connector.

#![allow(
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::ops::{Deref, DerefMut};

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpResult};
use serde_json::Value;
use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_gitlab::connector::GitLabConnector;

struct TestConnector {
    connector: GitLabConnector,
    signing_key: Ed25519SigningKey,
}

impl Deref for TestConnector {
    type Target = GitLabConnector;

    fn deref(&self) -> &Self::Target {
        &self.connector
    }
}

impl DerefMut for TestConnector {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connector
    }
}

impl TestConnector {
    async fn handle_invoke(&self, mut params: Value) -> FcpResult<Value> {
        self.attach_capability_token(&mut params);
        self.connector.handle_invoke(params).await
    }

    async fn handle_simulate(&self, mut params: Value) -> FcpResult<Value> {
        self.attach_capability_token(&mut params);
        self.connector.handle_simulate(params).await
    }

    fn attach_capability_token(&self, params: &mut Value) {
        let Some(object) = params.as_object_mut() else {
            return;
        };
        if object.contains_key("capability_token") {
            return;
        }
        let Some(operation) = object.get("operation_id").and_then(|value| value.as_str()) else {
            return;
        };
        let Some(capability) = capability_for_operation(operation) else {
            return;
        };
        object.insert(
            "capability_token".into(),
            serde_json::to_value(generate_token_with_cap(
                &self.signing_key,
                capability,
                &[operation],
            ))
            .unwrap(),
        );
    }
}

fn capability_for_operation(operation: &str) -> Option<&'static str> {
    match operation {
        "gitlab.projects.list" => Some("gitlab.projects.read"),
        "gitlab.issues.list" => Some("gitlab.issues.read"),
        "gitlab.issues.create" => Some("gitlab.issues.write"),
        "gitlab.merge_requests.list" => Some("gitlab.merge_requests.read"),
        "gitlab.pipelines.list" => Some("gitlab.pipelines.read"),
        _ => None,
    }
}

fn input_for_operation(operation: &str) -> Value {
    match operation {
        "gitlab.issues.create" => json!({"project_id": "123", "title": "New issue"}),
        "gitlab.issues.list" | "gitlab.merge_requests.list" | "gitlab.pipelines.list" => {
            json!({"project_id": "123"})
        }
        _ => json!({}),
    }
}

fn generate_token_with_cap(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

fn handshake_params(signing_key: &Ed25519SigningKey, session_id: &str) -> Value {
    let verifying_key = signing_key.verifying_key();
    json!({
        "session_id": session_id,
        "zone": "z:work",
        "host_public_key": verifying_key.to_bytes()
    })
}

async fn setup_connector(mock_url: &str) -> TestConnector {
    let mut c = GitLabConnector::new();
    c.handle_configure(json!({ "private_token": "glpat-test", "base_url": mock_url }))
        .await
        .unwrap();
    let signing_key = Ed25519SigningKey::generate();
    c.handle_handshake(handshake_params(&signing_key, "test"))
        .await
        .unwrap();
    TestConnector {
        connector: c,
        signing_key,
    }
}

// ── Lifecycle ────────────────────────────────────────────────────────

#[fcp_async_core::test]
async fn lifecycle_health_unconfigured() {
    let c = GitLabConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = GitLabConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert_eq!(health["configured"], false);
    assert_eq!(health["handshaken"], false);
}

#[fcp_async_core::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
}

#[fcp_async_core::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

// ── Projects List ────────────────────────────────────────────────────

#[fcp_async_core::test]
async fn projects_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .and(header("PRIVATE-TOKEN", "glpat-test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "name": "proj-a", "path_with_namespace": "user/proj-a"},
            {"id": 2, "name": "proj-b", "path_with_namespace": "user/proj-b"}
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await
        .unwrap();
    assert_eq!(result["projects"].as_array().unwrap().len(), 2);
}

// ── Issues List ──────────────────────────────────────────────────────

#[fcp_async_core::test]
async fn issues_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/123/issues"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "iid": 42, "title": "Bug", "state": "opened"}
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "gitlab.issues.list", "input": {"project_id": "123"}}),
        )
        .await
        .unwrap();
    assert_eq!(result["issues"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::test]
async fn issues_list_missing_project_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.issues.list", "input": {}}))
            .await
            .is_err()
    );
}

// ── Issues Create ────────────────────────────────────────────────────

#[fcp_async_core::test]
async fn issues_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/123/issues"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 1, "iid": 43, "title": "New issue", "state": "opened"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.issues.create",
            "input": {"project_id": "123", "title": "New issue", "description": "Details here"}
        }))
        .await
        .unwrap();
    assert_eq!(result["iid"], 43);
}

#[fcp_async_core::test]
async fn issues_create_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "gitlab.issues.create", "input": {"project_id": "123"}})
        )
        .await
        .is_err()
    );
}

// ── Merge Requests List ──────────────────────────────────────────────

#[fcp_async_core::test]
async fn merge_requests_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/123/merge_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "iid": 10, "title": "Feature", "state": "merged"}
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "gitlab.merge_requests.list", "input": {"project_id": "123"}}),
        )
        .await
        .unwrap();
    assert_eq!(result["merge_requests"].as_array().unwrap().len(), 1);
}

// ── Pipelines List ───────────────────────────────────────────────────

#[fcp_async_core::test]
async fn pipelines_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/123/pipelines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "status": "success", "ref": "main", "sha": "abc123"}
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "gitlab.pipelines.list", "input": {"project_id": "123"}}),
        )
        .await
        .unwrap();
    assert_eq!(result["pipelines"].as_array().unwrap().len(), 1);
}

// ── Error handling ───────────────────────────────────────────────────

#[fcp_async_core::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"message": "401 Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/999/issues"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "404 Not Found"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "gitlab.issues.list", "input": {"project_id": "999"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .is_err()
    );
}

// ── Unknown op / Simulate ────────────────────────────────────────────

#[fcp_async_core::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.nope", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn invoke_missing_capability_token_fails() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .connector
        .handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::InvalidRequest { message, .. }
            if message.contains("capability_token")
    ));
}

#[fcp_async_core::test]
async fn invoke_wrong_capability_is_rejected() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let token = generate_token_with_cap(
        &c.signing_key,
        "gitlab.projects.read",
        &["gitlab.issues.create"],
    );
    let result = c
        .connector
        .handle_invoke(json!({
            "operation_id": "gitlab.issues.create",
            "input": {"project_id": "123", "title": "New issue"},
            "capability_token": token
        }))
        .await;
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    ));
}

#[fcp_async_core::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "gitlab.projects.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "gitlab.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::test]
async fn simulate_wrong_capability_is_denied() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let token = generate_token_with_cap(
        &c.signing_key,
        "gitlab.projects.read",
        &["gitlab.issues.create"],
    );
    let result = c
        .connector
        .handle_simulate(json!({
            "operation_id": "gitlab.issues.create",
            "input": {"project_id": "123", "title": "New issue"},
            "capability_token": token
        }))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
    assert_eq!(result["missing_capabilities"][0], "gitlab.issues.write");
}

// ── Counters ─────────────────────────────────────────────────────────

#[fcp_async_core::test]
async fn counters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

// ── Additional Lifecycle Tests ──────────────────────────────────────

#[fcp_async_core::test]
async fn lifecycle_health_degraded_no_handshake() {
    let server = MockServer::start().await;
    let mut c = GitLabConnector::new();
    c.handle_configure(json!({ "private_token": "glpat-test", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::test]
async fn lifecycle_doctor_unconfigured() {
    let c = GitLabConnector::new();
    let d = c.handle_doctor().await.unwrap();
    assert_eq!(d["status"], "unhealthy");
}

#[fcp_async_core::test]
async fn lifecycle_self_check_unconfigured() {
    let c = GitLabConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::test]
async fn lifecycle_shutdown_then_reinvoke() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let mut c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await
        .unwrap();

    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");

    // Invoking after shutdown should fail (not configured/handshaken)
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn lifecycle_reconfigure_after_shutdown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();

    // Re-configure and re-handshake
    c.handle_configure(json!({ "private_token": "glpat-new", "base_url": server.uri() }))
        .await
        .unwrap();
    let handshake = handshake_params(&c.signing_key, "new-session");
    c.handle_handshake(handshake).await.unwrap();

    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");

    let result = c
        .handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await
        .unwrap();
    assert!(result["projects"].is_array());
}

#[fcp_async_core::test]
async fn lifecycle_introspect_contains_expected_ops() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().unwrap();
    let ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
    assert!(ids.contains(&"gitlab.projects.list"));
    assert!(ids.contains(&"gitlab.issues.list"));
    assert!(ids.contains(&"gitlab.issues.create"));
    assert!(ids.contains(&"gitlab.merge_requests.list"));
    assert!(ids.contains(&"gitlab.pipelines.list"));
}

#[fcp_async_core::test]
async fn lifecycle_handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = GitLabConnector::new();
    c.handle_configure(json!({ "private_token": "glpat-test", "base_url": server.uri() }))
        .await
        .unwrap();
    let signing_key = Ed25519SigningKey::generate();
    let hs = c
        .handle_handshake(handshake_params(&signing_key, "s1"))
        .await
        .unwrap();
    assert_eq!(hs["protocol_version"], "2.0");
    assert_eq!(hs["connector_id"], "fcp.gitlab");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.len() >= 5);
}

// ── Configuration Tests ─────────────────────────────────────────────

#[fcp_async_core::test]
async fn configure_no_auth_fails() {
    let mut c = GitLabConnector::new();
    assert!(c.handle_configure(json!({})).await.is_err());
}

#[fcp_async_core::test]
async fn configure_both_auth_rejected() {
    let mut c = GitLabConnector::new();
    let result = c
        .handle_configure(json!({
            "private_token": "glpat-test",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn configure_credential_id_mode() {
    let mut c = GitLabConnector::new();
    let result = c
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::test]
async fn configure_custom_base_url() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;

    let result = c
        .handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await
        .unwrap();
    assert!(result["projects"].is_array());
}

#[fcp_async_core::test]
async fn configure_empty_token_fails() {
    let mut c = GitLabConnector::new();
    assert!(
        c.handle_configure(json!({"private_token": ""}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn configure_whitespace_token_fails() {
    let mut c = GitLabConnector::new();
    assert!(
        c.handle_configure(json!({"private_token": "   "}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn configure_invalid_credential_id_fails() {
    let mut c = GitLabConnector::new();
    assert!(
        c.handle_configure(json!({"credential_id": "not-a-uuid"}))
            .await
            .is_err()
    );
}

// ── Input Validation ────────────────────────────────────────────────

#[fcp_async_core::test]
async fn merge_requests_list_missing_project_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.merge_requests.list", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn pipelines_list_missing_project_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.pipelines.list", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn issues_create_missing_project_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "gitlab.issues.create",
            "input": {"title": "No project"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::test]
async fn invoke_missing_operation_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"input": {}})).await.is_err());
}

#[fcp_async_core::test]
async fn issues_list_project_id_not_string() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "gitlab.issues.list",
            "input": {"project_id": 123}
        }))
        .await
        .is_err()
    );
}

// ── Error Handling: 403 Forbidden ───────────────────────────────────

#[fcp_async_core::test]
async fn error_403_projects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "403 Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .is_err()
    );
}

// ── Error Handling: 500 Internal Server Error ───────────────────────

#[fcp_async_core::test]
async fn error_500_projects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal Server Error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn error_500_issues() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/1/issues"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"error": "Internal Server Error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "gitlab.issues.list",
            "input": {"project_id": "1"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::test]
async fn error_401_merge_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/1/merge_requests"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"message": "401 Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "gitlab.merge_requests.list",
            "input": {"project_id": "1"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::test]
async fn error_403_pipelines() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/1/pipelines"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "403 Forbidden"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "gitlab.pipelines.list",
            "input": {"project_id": "1"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::test]
async fn error_404_merge_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/999/merge_requests"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "404 Not Found"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "gitlab.merge_requests.list",
            "input": {"project_id": "999"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::test]
async fn error_429_issues_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/1/issues"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "30"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "gitlab.issues.create",
            "input": {"project_id": "1", "title": "Rate limited"}
        }))
        .await
        .is_err()
    );
}

// ── Empty Response Arrays ───────────────────────────────────────────

#[fcp_async_core::test]
async fn projects_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await
        .unwrap();
    assert_eq!(result["projects"].as_array().unwrap().len(), 0);
}

#[fcp_async_core::test]
async fn issues_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/42/issues"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.issues.list",
            "input": {"project_id": "42"}
        }))
        .await
        .unwrap();
    assert_eq!(result["issues"].as_array().unwrap().len(), 0);
}

#[fcp_async_core::test]
async fn merge_requests_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/42/merge_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.merge_requests.list",
            "input": {"project_id": "42"}
        }))
        .await
        .unwrap();
    assert_eq!(result["merge_requests"].as_array().unwrap().len(), 0);
}

#[fcp_async_core::test]
async fn pipelines_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/42/pipelines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.pipelines.list",
            "input": {"project_id": "42"}
        }))
        .await
        .unwrap();
    assert_eq!(result["pipelines"].as_array().unwrap().len(), 0);
}

// ── Rich Response Data ──────────────────────────────────────────────

#[fcp_async_core::test]
async fn merge_requests_rich_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/10/merge_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "id": 100, "iid": 5, "title": "Add feature",
                "state": "opened", "source_branch": "feature-x",
                "target_branch": "main", "merge_status": "can_be_merged",
                "author": {"id": 1, "username": "dev"},
                "web_url": "https://gitlab.com/proj/-/merge_requests/5"
            },
            {
                "id": 101, "iid": 6, "title": "Fix bug",
                "state": "merged", "source_branch": "fix-y",
                "target_branch": "main", "merge_status": "merged"
            }
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.merge_requests.list",
            "input": {"project_id": "10"}
        }))
        .await
        .unwrap();
    let mrs = result["merge_requests"].as_array().unwrap();
    assert_eq!(mrs.len(), 2);
    assert_eq!(mrs[0]["title"], "Add feature");
    assert_eq!(mrs[0]["state"], "opened");
    assert_eq!(mrs[1]["state"], "merged");
}

#[fcp_async_core::test]
async fn pipelines_rich_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/10/pipelines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "iid": 1, "status": "success", "ref": "main", "sha": "abc123", "source": "push"},
            {"id": 2, "iid": 2, "status": "failed", "ref": "develop", "sha": "def456", "source": "web"},
            {"id": 3, "iid": 3, "status": "running", "ref": "feature", "sha": "ghi789", "source": "trigger"}
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.pipelines.list",
            "input": {"project_id": "10"}
        }))
        .await
        .unwrap();
    let pipelines = result["pipelines"].as_array().unwrap();
    assert_eq!(pipelines.len(), 3);
    assert_eq!(pipelines[0]["status"], "success");
    assert_eq!(pipelines[1]["status"], "failed");
    assert_eq!(pipelines[2]["status"], "running");
}

#[fcp_async_core::test]
async fn issues_create_with_description() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/5/issues"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 10, "iid": 1, "title": "Test issue",
            "description": "Long description here",
            "state": "opened", "labels": ["bug"]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.issues.create",
            "input": {
                "project_id": "5",
                "title": "Test issue",
                "description": "Long description here"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["title"], "Test issue");
    assert_eq!(result["state"], "opened");
}

#[fcp_async_core::test]
async fn issues_create_without_description() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/5/issues"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 11, "iid": 2, "title": "Minimal issue", "state": "opened"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "gitlab.issues.create",
            "input": {"project_id": "5", "title": "Minimal issue"}
        }))
        .await
        .unwrap();
    assert_eq!(result["iid"], 2);
}

// ── Simulate All Operations ─────────────────────────────────────────

#[fcp_async_core::test]
async fn simulate_all_known_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let known_ops = [
        "gitlab.projects.list",
        "gitlab.issues.list",
        "gitlab.issues.create",
        "gitlab.merge_requests.list",
        "gitlab.pipelines.list",
    ];
    for op in &known_ops {
        let result = c
            .handle_simulate(json!({"operation_id": op, "input": input_for_operation(op)}))
            .await
            .unwrap();
        assert!(
            result["allowed"].as_bool().unwrap(),
            "Expected operation {op} to be allowed"
        );
    }
}

#[fcp_async_core::test]
async fn simulate_reason_fields() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;

    let allowed = c
        .handle_simulate(json!({"operation_id": "gitlab.projects.list"}))
        .await
        .unwrap();
    assert_eq!(allowed["reason"], "Operation supported");

    let denied = c
        .handle_simulate(json!({"operation_id": "gitlab.bogus"}))
        .await
        .unwrap();
    assert_eq!(denied["reason"], "Unknown operation");
}

// ── Counters: Error Tracking ────────────────────────────────────────

#[fcp_async_core::test]
async fn counters_track_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"error": "Internal Server Error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..5 {
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 5);
    assert_eq!(h["errors"], 0);
}

// ── Invoke Before Handshake ─────────────────────────────────────────

#[fcp_async_core::test]
async fn invoke_before_handshake_fails() {
    let server = MockServer::start().await;
    let mut c = GitLabConnector::new();
    c.handle_configure(json!({ "private_token": "glpat-test", "base_url": server.uri() }))
        .await
        .unwrap();
    // No handshake performed
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::test]
async fn invoke_unconfigured_fails() {
    let c = GitLabConnector::new();
    assert!(
        c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}}))
            .await
            .is_err()
    );
}

// ── Doctor Checks Detail ────────────────────────────────────────────

#[fcp_async_core::test]
async fn doctor_configured_no_handshake() {
    let server = MockServer::start().await;
    let mut c = GitLabConnector::new();
    c.handle_configure(json!({ "private_token": "glpat-test", "base_url": server.uri() }))
        .await
        .unwrap();
    let d = c.handle_doctor().await.unwrap();
    // Configuration and client are both present, but handshake is missing (non-critical)
    assert_eq!(d["status"], "degraded");
    let checks = d["checks"].as_array().unwrap();
    assert!(checks.len() >= 3);
}
