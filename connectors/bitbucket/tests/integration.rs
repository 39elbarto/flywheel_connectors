//! Integration tests for the FCP `Bitbucket` connector.

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

use std::ops::{Deref, DerefMut};

use chrono::{Duration, Utc};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpResult};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use serde_json::Value;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_bitbucket::connector::BitbucketConnector;

struct TestConnector {
    connector: BitbucketConnector,
    signing_key: Ed25519SigningKey,
}

impl Deref for TestConnector {
    type Target = BitbucketConnector;

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
        let Some(operation) = object.get("operation_id").and_then(Value::as_str) else {
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
        "bitbucket.user.get" => Some("bitbucket.user.read"),
        "bitbucket.repositories.list" | "bitbucket.repositories.get" => {
            Some("bitbucket.repositories.read")
        }
        "bitbucket.pull_requests.list" | "bitbucket.pull_requests.get" => {
            Some("bitbucket.pull_requests.read")
        }
        "bitbucket.pull_requests.create" => Some("bitbucket.pull_requests.write"),
        "bitbucket.branches.list" => Some("bitbucket.branches.read"),
        "bitbucket.commits.list" => Some("bitbucket.commits.read"),
        "bitbucket.pipelines.list" => Some("bitbucket.pipelines.read"),
        "bitbucket.workspaces.list" => Some("bitbucket.workspaces.read"),
        _ => None,
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
    let mut c = BitbucketConnector::new();
    c.handle_configure(json!({ "access_token": "test_oauth_token", "base_url": mock_url }))
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

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = BitbucketConnector::new();
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
    let mut c = BitbucketConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
    assert_eq!(health["configured"], false);
    assert_eq!(health["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert!(check.get("details").is_some());
    assert!(
        check["details"]["provisioning"]["network_ok"]
            .as_bool()
            .unwrap()
    );
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
    assert_eq!(intro["operations"].as_array().unwrap().len(), 10);
}

// -- User Get --

#[fcp_async_core::runtime::test]
async fn user_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("Authorization", "Bearer test_oauth_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": "{abc-123}",
            "username": "jdoe",
            "display_name": "John Doe",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.user.get",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["user"]["username"], "jdoe");
}

// -- Workspaces List --

#[fcp_async_core::runtime::test]
async fn workspaces_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [
                {"uuid": "{ws-1}", "slug": "myteam", "name": "My Team"},
                {"uuid": "{ws-2}", "slug": "other", "name": "Other"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.workspaces.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["workspaces"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workspaces_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.workspaces.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["workspaces"].as_array().unwrap().is_empty());
}

// -- Repositories List --

#[fcp_async_core::runtime::test]
async fn repositories_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam"))
        .and(header("Authorization", "Bearer test_oauth_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [
                {"uuid": "{r1}", "full_name": "myteam/backend", "name": "backend"},
                {"uuid": "{r2}", "full_name": "myteam/frontend", "name": "frontend"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.repositories.list",
            "input": {"workspace": "myteam"}
        }))
        .await
        .unwrap();
    assert_eq!(result["repositories"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn repositories_list_missing_workspace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.repositories.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Repository Get --

#[fcp_async_core::runtime::test]
async fn repositories_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": "{r1}",
            "full_name": "myteam/backend",
            "name": "backend",
            "is_private": true,
            "language": "rust",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.repositories.get",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
        }))
        .await
        .unwrap();
    assert_eq!(result["repository"]["name"], "backend");
    assert_eq!(result["repository"]["language"], "rust");
}

#[fcp_async_core::runtime::test]
async fn repositories_get_missing_repo_slug() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.repositories.get",
            "input": {"workspace": "myteam"}
        }))
        .await
        .is_err()
    );
}

// -- Pull Requests List --

#[fcp_async_core::runtime::test]
async fn pull_requests_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend/pullrequests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [
                {"id": 1, "title": "Fix login", "state": "OPEN"},
                {"id": 2, "title": "Add tests", "state": "MERGED"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.list",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
        }))
        .await
        .unwrap();
    assert_eq!(result["pull_requests"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn pull_requests_list_missing_workspace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.list",
            "input": {"repo_slug": "backend"}
        }))
        .await
        .is_err()
    );
}

// -- Pull Request Get --

#[fcp_async_core::runtime::test]
async fn pull_requests_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend/pullrequests/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "title": "Fix login bug",
            "state": "OPEN",
            "author": {"display_name": "Jane", "uuid": "{user-1}"},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.get",
            "input": {"workspace": "myteam", "repo_slug": "backend", "pr_id": "42"}
        }))
        .await
        .unwrap();
    assert_eq!(result["pull_request"]["id"], 42);
    assert_eq!(result["pull_request"]["title"], "Fix login bug");
}

#[fcp_async_core::runtime::test]
async fn pull_requests_get_missing_pr_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.get",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
        }))
        .await
        .is_err()
    );
}

// -- Pull Requests Create --

#[fcp_async_core::runtime::test]
async fn pull_requests_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/repositories/myteam/backend/pullrequests"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 99,
            "title": "New feature",
            "state": "OPEN",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.create",
            "input": {
                "workspace": "myteam",
                "repo_slug": "backend",
                "title": "New feature",
                "source_branch": "feature/xyz",
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], 99);
}

#[fcp_async_core::runtime::test]
async fn pull_requests_create_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.create",
            "input": {
                "workspace": "myteam",
                "repo_slug": "backend",
                "source_branch": "fix/login",
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn pull_requests_create_missing_source_branch() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.create",
            "input": {
                "workspace": "myteam",
                "repo_slug": "backend",
                "title": "New PR",
            }
        }))
        .await
        .is_err()
    );
}

// -- Branches List --

#[fcp_async_core::runtime::test]
async fn branches_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend/refs/branches"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [
                {"name": "main", "target": {"hash": "abc123"}},
                {"name": "develop", "target": {"hash": "def456"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.branches.list",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
        }))
        .await
        .unwrap();
    assert_eq!(result["branches"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn branches_list_missing_repo_slug() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.branches.list",
            "input": {"workspace": "myteam"}
        }))
        .await
        .is_err()
    );
}

// -- Commits List --

#[fcp_async_core::runtime::test]
async fn commits_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend/commits"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [
                {"hash": "abc123", "message": "Initial commit"},
                {"hash": "def456", "message": "Fix bug"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.commits.list",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
        }))
        .await
        .unwrap();
    assert_eq!(result["commits"].as_array().unwrap().len(), 2);
}

// -- Pipelines List --

#[fcp_async_core::runtime::test]
async fn pipelines_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend/pipelines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [
                {"uuid": "{p1}", "build_number": 1, "state": {"name": "COMPLETED"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.pipelines.list",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
        }))
        .await
        .unwrap();
    assert_eq!(result["pipelines"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn pipelines_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend/pipelines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.pipelines.list",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
        }))
        .await
        .unwrap();
    assert!(result["pipelines"].as_array().unwrap().is_empty());
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {"message": "Access token expired"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.user.get",
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
        .and(path("/repositories/myteam"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {"message": "Forbidden"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.repositories.list",
            "input": {"workspace": "myteam"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"message": "Repository not found"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.repositories.get",
            "input": {"workspace": "myteam", "repo_slug": "missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "error": {"message": "Rate limit exceeded"}
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.repositories.list",
            "input": {"workspace": "myteam"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/backend/commits"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bitbucket.commits.list",
            "input": {"workspace": "myteam", "repo_slug": "backend"}
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
            "operation_id": "bitbucket.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_capability_token_fails() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .connector
        .handle_invoke(json!({
            "operation_id": "bitbucket.user.get",
            "input": {}
        }))
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::InvalidRequest { message, .. }
            if message.contains("capability_token")
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_wrong_capability_is_rejected() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let token = generate_token_with_cap(
        &c.signing_key,
        "bitbucket.user.read",
        &["bitbucket.pull_requests.create"],
    );
    let result = c
        .connector
        .handle_invoke(json!({
            "operation_id": "bitbucket.pull_requests.create",
            "input": {
                "workspace": "myteam",
                "repo_slug": "backend",
                "title": "New feature",
                "source_branch": "feature/xyz"
            },
            "capability_token": token
        }))
        .await;
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({
            "operation_id": "bitbucket.repositories.list",
            "input": {"workspace": "myteam"}
        }))
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
        !c.handle_simulate(json!({"operation_id": "bitbucket.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_wrong_capability_is_denied() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let token = generate_token_with_cap(
        &c.signing_key,
        "bitbucket.user.read",
        &["bitbucket.pull_requests.create"],
    );
    let result = c
        .connector
        .handle_simulate(json!({
            "operation_id": "bitbucket.pull_requests.create",
            "input": {
                "workspace": "myteam",
                "repo_slug": "backend",
                "title": "New feature",
                "source_branch": "feature/xyz"
            },
            "capability_token": token
        }))
        .await
        .unwrap();
    assert!(!result["allowed"].as_bool().unwrap());
    assert_eq!(
        result["missing_capabilities"][0],
        "bitbucket.pull_requests.write"
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": "{u1}", "username": "test"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "bitbucket.user.get",
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
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "bitbucket.user.get",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
