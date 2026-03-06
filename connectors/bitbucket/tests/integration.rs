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

use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_bitbucket::connector::BitbucketConnector;

async fn setup_connector(mock_url: &str) -> BitbucketConnector {
    let mut c = BitbucketConnector::new();
    c.handle_configure(json!({ "access_token": "test_oauth_token", "base_url": mock_url }))
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
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
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
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({
                "error": {"message": "Access token expired"}
            })),
        )
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
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({
                "error": {"message": "Forbidden"}
            })),
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
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repositories/myteam/missing"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({
                "error": {"message": "Repository not found"}
            })),
        )
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
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "bitbucket.repositories.list"}))
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
