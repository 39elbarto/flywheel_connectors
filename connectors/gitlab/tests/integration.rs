//! Integration tests for the FCP `GitLab` connector.

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
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_gitlab::connector::GitLabConnector;

async fn setup_connector(mock_url: &str) -> GitLabConnector {
    let mut c = GitLabConnector::new();
    c.handle_configure(json!({ "private_token": "glpat-test", "base_url": mock_url })).await.unwrap();
    c.handle_handshake(json!({"session_id": "test"})).await.unwrap();
    c
}

// ── Lifecycle ────────────────────────────────────────────────────────

#[tokio::test]
async fn lifecycle_health_unconfigured() {
    let c = GitLabConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = GitLabConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[tokio::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
}

#[tokio::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

// ── Projects List ────────────────────────────────────────────────────

#[tokio::test]
async fn projects_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .and(header("PRIVATE-TOKEN", "glpat-test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "name": "proj-a", "path_with_namespace": "user/proj-a"},
            {"id": 2, "name": "proj-b", "path_with_namespace": "user/proj-b"}
        ])))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}})).await.unwrap();
    assert_eq!(result["projects"].as_array().unwrap().len(), 2);
}

// ── Issues List ──────────────────────────────────────────────────────

#[tokio::test]
async fn issues_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/123/issues"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "iid": 42, "title": "Bug", "state": "opened"}
        ])))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "gitlab.issues.list", "input": {"project_id": "123"}})).await.unwrap();
    assert_eq!(result["issues"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn issues_list_missing_project_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "gitlab.issues.list", "input": {}})).await.is_err());
}

// ── Issues Create ────────────────────────────────────────────────────

#[tokio::test]
async fn issues_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/123/issues"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 1, "iid": 43, "title": "New issue", "state": "opened"
        })))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "gitlab.issues.create",
        "input": {"project_id": "123", "title": "New issue", "description": "Details here"}
    })).await.unwrap();
    assert_eq!(result["iid"], 43);
}

#[tokio::test]
async fn issues_create_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "gitlab.issues.create", "input": {"project_id": "123"}})).await.is_err());
}

// ── Merge Requests List ──────────────────────────────────────────────

#[tokio::test]
async fn merge_requests_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/123/merge_requests"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "iid": 10, "title": "Feature", "state": "merged"}
        ])))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "gitlab.merge_requests.list", "input": {"project_id": "123"}})).await.unwrap();
    assert_eq!(result["merge_requests"].as_array().unwrap().len(), 1);
}

// ── Pipelines List ───────────────────────────────────────────────────

#[tokio::test]
async fn pipelines_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/123/pipelines"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "status": "success", "ref": "main", "sha": "abc123"}
        ])))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "gitlab.pipelines.list", "input": {"project_id": "123"}})).await.unwrap();
    assert_eq!(result["pipelines"].as_array().unwrap().len(), 1);
}

// ── Error handling ───────────────────────────────────────────────────

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "401 Unauthorized"})))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}})).await.is_err());
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/999/issues"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "404 Not Found"})))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "gitlab.issues.list", "input": {"project_id": "999"}})).await.is_err());
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({"message": "Too many requests"})).insert_header("retry-after", "60"))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}})).await.is_err());
}

// ── Unknown op / Simulate ────────────────────────────────────────────

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "gitlab.nope", "input": {}})).await.is_err());
}

#[tokio::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_simulate(json!({"operation_id": "gitlab.projects.list"})).await.unwrap()["allowed"].as_bool().unwrap());
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(!c.handle_simulate(json!({"operation_id": "gitlab.nope"})).await.unwrap()["allowed"].as_bool().unwrap());
}

// ── Counters ─────────────────────────────────────────────────────────

#[tokio::test]
async fn counters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server).await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({"operation_id": "gitlab.projects.list", "input": {}})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}
