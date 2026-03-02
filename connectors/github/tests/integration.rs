//! GitHub connector integration tests (flywheel_connectors-s73.6).
//!
//! Deterministic integration tests using wiremock to mock the GitHub REST API.
//! No real API calls. Covers:
//! - Issues (create, get, search)
//! - Pull Requests (create, get, merge)
//! - Repositories (get, search)
//! - Actions (list workflows, trigger workflow)
//! - Content (get file, search code)
//! - Error taxonomy (401/404/422/429/409/500 -> `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_github::client::GitHubClient;
use fcp_github::connector::GitHubConnector;

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[cap])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken { raw: cose }
}

async fn setup_handshake(connector: &mut GitHubConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn setup_configure(connector: &mut GitHubConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "token": "ghp_test_token_xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard GitHub issue response.
fn github_issue_response(number: u32, title: &str, state: &str) -> serde_json::Value {
    json!({
        "id": 1000 + u64::from(number),
        "number": number,
        "title": title,
        "state": state,
        "body": "Issue body",
        "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
        "labels": [],
        "assignees": [],
        "created_at": "2026-01-15T10:00:00Z",
        "updated_at": "2026-01-15T10:00:01Z",
        "html_url": format!("https://github.com/octocat/hello-world/issues/{number}"),
        "comments": 0
    })
}

/// Standard GitHub pull request response.
fn github_pr_response(number: u32, title: &str, state: &str) -> serde_json::Value {
    json!({
        "id": 2000 + u64::from(number),
        "number": number,
        "title": title,
        "state": state,
        "body": "PR body",
        "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
        "head": { "label": "octocat:feature", "ref": "feature", "sha": "abc123" },
        "base": { "label": "octocat:main", "ref": "main", "sha": "def456" },
        "labels": [],
        "assignees": [],
        "merged": false,
        "created_at": "2026-01-15T10:00:00Z",
        "updated_at": "2026-01-15T10:00:01Z",
        "html_url": format!("https://github.com/octocat/hello-world/pull/{number}"),
        "draft": false
    })
}

/// GitHub API error response.
fn github_error_response(message: &str) -> serde_json::Value {
    json!({
        "message": message,
        "documentation_url": "https://docs.github.com"
    })
}

// ============================================================================
// Issue Tests
// ============================================================================

/// Create issue happy path.
#[fcp_async_core::runtime::test]
async fn create_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.create_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(github_issue_response(43, "Bug report", "open")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_issue"]).await;
    let token = generate_valid_token(&signing_key, "github.create_issue");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.create_issue",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Bug report",
                "body": "Found a bug"
            },
            "capability_token": token
        }))
        .await
        .expect("create_issue should succeed");

    assert_eq!(result["issue"]["number"], 43);
    assert_eq!(result["issue"]["title"], "Bug report");
}

/// Get issue happy path.
#[fcp_async_core::runtime::test]
async fn get_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/issues/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(github_issue_response(42, "Found a bug", "open")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "github.get_issue");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "issue_number": 42
            },
            "capability_token": token
        }))
        .await
        .expect("get_issue should succeed");

    assert_eq!(result["issue"]["number"], 42);
    assert_eq!(result["issue"]["state"], "open");
}

/// Search issues happy path.
#[fcp_async_core::runtime::test]
async fn search_issues_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.search_issues.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search/issues"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "incomplete_results": false,
            "items": [github_issue_response(42, "Found a bug", "open")]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_issues"]).await;
    let token = generate_valid_token(&signing_key, "github.search_issues");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_issues",
            "input": { "query": "is:open is:issue repo:octocat/hello-world" },
            "capability_token": token
        }))
        .await
        .expect("search_issues should succeed");

    assert_eq!(result["total_count"], 1);
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
}

// ============================================================================
// Pull Request Tests
// ============================================================================

/// Create pull request happy path.
#[fcp_async_core::runtime::test]
async fn create_pull_request_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.create_pull_request.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/pulls"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(github_pr_response(1, "Fix typo", "open")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_pull_request"]).await;
    let token = generate_valid_token(&signing_key, "github.create_pull_request");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.create_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Fix typo",
                "head": "feature",
                "base": "main"
            },
            "capability_token": token
        }))
        .await
        .expect("create_pull_request should succeed");

    assert_eq!(result["pull_request"]["number"], 1);
    assert_eq!(result["pull_request"]["title"], "Fix typo");
}

/// Get pull request happy path.
#[fcp_async_core::runtime::test]
async fn get_pull_request_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_pull_request.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/pulls/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(github_pr_response(1, "Fix typo", "open")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_pull_request"]).await;
    let token = generate_valid_token(&signing_key, "github.get_pull_request");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "pull_number": 1
            },
            "capability_token": token
        }))
        .await
        .expect("get_pull_request should succeed");

    assert_eq!(result["pull_request"]["number"], 1);
    assert_eq!(result["pull_request"]["head"]["ref"], "feature");
}

/// Merge pull request happy path.
#[fcp_async_core::runtime::test]
async fn merge_pull_request_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.merge_pull_request.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/repos/octocat/hello-world/pulls/1/merge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sha": "abc123def456",
            "merged": true,
            "message": "Pull Request successfully merged"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.merge_pull_request"]).await;
    let token = generate_valid_token(&signing_key, "github.merge_pull_request");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.merge_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "pull_number": 1,
                "merge_method": "squash"
            },
            "capability_token": token
        }))
        .await
        .expect("merge_pull_request should succeed");

    assert!(result["merged"].as_bool().unwrap());
    assert_eq!(result["sha"], "abc123def456");
}

// ============================================================================
// Repository Tests
// ============================================================================

/// Get repository metadata.
#[fcp_async_core::runtime::test]
async fn get_repo_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_repo.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1_296_269,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
            "description": "Test repo",
            "private": false,
            "fork": false,
            "html_url": "https://github.com/octocat/hello-world",
            "default_branch": "main",
            "language": "Rust",
            "stargazers_count": 42,
            "forks_count": 10,
            "open_issues_count": 5,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_repo"]).await;
    let token = generate_valid_token(&signing_key, "github.get_repo");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect("get_repo should succeed");

    assert_eq!(result["repository"]["name"], "hello-world");
    assert_eq!(result["repository"]["stargazers_count"], 42);
}

/// Search repositories.
#[fcp_async_core::runtime::test]
async fn search_repos_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.search_repos.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search/repositories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "incomplete_results": false,
            "items": [{
                "id": 1_296_269,
                "name": "hello-world",
                "full_name": "octocat/hello-world",
                "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "private": false,
                "fork": false,
                "html_url": "https://github.com/octocat/hello-world",
                "default_branch": "main",
                "stargazers_count": 42,
                "forks_count": 10,
                "open_issues_count": 5,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-06-01T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_repos"]).await;
    let token = generate_valid_token(&signing_key, "github.search_repos");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_repos",
            "input": { "query": "language:rust stars:>1000" },
            "capability_token": token
        }))
        .await
        .expect("search_repos should succeed");

    assert_eq!(result["total_count"], 1);
}

// ============================================================================
// Actions Tests
// ============================================================================

/// List workflows.
#[fcp_async_core::runtime::test]
async fn list_workflows_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.list_workflows.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/actions/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "workflows": [{
                "id": 1,
                "name": "CI",
                "path": ".github/workflows/ci.yml",
                "state": "active",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-06-01T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.list_workflows"]).await;
    let token = generate_valid_token(&signing_key, "github.list_workflows");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.list_workflows",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect("list_workflows should succeed");

    assert_eq!(result["total_count"], 1);
    assert_eq!(result["workflows"].as_array().unwrap().len(), 1);
}

/// Trigger workflow dispatch.
#[fcp_async_core::runtime::test]
async fn trigger_workflow_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.trigger_workflow.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/repos/octocat/hello-world/actions/workflows/ci.yml/dispatches",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.trigger_workflow"]).await;
    let token = generate_valid_token(&signing_key, "github.trigger_workflow");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.trigger_workflow",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "workflow_id": "ci.yml",
                "ref": "main"
            },
            "capability_token": token
        }))
        .await
        .expect("trigger_workflow should succeed");

    assert!(result["triggered"].as_bool().unwrap());
}

// ============================================================================
// Content Tests
// ============================================================================

/// Get file content.
#[fcp_async_core::runtime::test]
async fn get_file_content_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_file_content.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/contents/README.md"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "README.md",
            "path": "README.md",
            "sha": "abc123",
            "size": 100,
            "type": "file",
            "content": "SGVsbG8gV29ybGQ=",
            "encoding": "base64",
            "html_url": "https://github.com/octocat/hello-world/blob/main/README.md"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_file_content"]).await;
    let token = generate_valid_token(&signing_key, "github.get_file_content");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_file_content",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "path": "README.md"
            },
            "capability_token": token
        }))
        .await
        .expect("get_file_content should succeed");

    assert_eq!(result["content"]["name"], "README.md");
    assert_eq!(result["content"]["encoding"], "base64");
}

/// Search code.
#[fcp_async_core::runtime::test]
async fn search_code_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.search_code.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "incomplete_results": false,
            "items": [{
                "name": "main.rs",
                "path": "src/main.rs",
                "sha": "def456",
                "html_url": "https://github.com/octocat/hello-world/blob/main/src/main.rs",
                "repository": {
                    "id": 1_296_269,
                    "name": "hello-world",
                    "full_name": "octocat/hello-world",
                    "html_url": "https://github.com/octocat/hello-world"
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_code"]).await;
    let token = generate_valid_token(&signing_key, "github.search_code");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_code",
            "input": { "query": "addClass repo:octocat/hello-world" },
            "capability_token": token
        }))
        .await
        .expect("search_code should succeed");

    assert_eq!(result["total_count"], 1);
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
}

// ============================================================================
// Error Taxonomy Tests (401/404/422/429/409/500 -> `FcpError` mapping)
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("github.error.401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(github_error_response("Bad credentials")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 401");

    assert!(
        matches!(err, fcp_github::error::GitHubError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "expected FcpError::Unauthorized, got: {fcp_err:?}"
    );
}

/// 404 Not Found maps to `FcpError::ResourceNotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_not_found() {
    let _ctx = AsyncTestContext::for_scenario("github.error.404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(github_error_response("Not Found")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "nonexistent")
        .await
        .expect_err("should fail with 404");

    assert!(
        matches!(err, fcp_github::error::GitHubError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "expected FcpError::ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 422 Validation Error maps to `FcpError::InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn error_422_maps_to_invalid_request() {
    let _ctx = AsyncTestContext::for_scenario("github.error.422");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(github_error_response("Validation Failed")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .create_issue(
            "octocat",
            "hello-world",
            &fcp_github::types::CreateIssueRequest {
                title: String::new(),
                body: None,
                assignees: None,
                labels: None,
                milestone: None,
            },
        )
        .await
        .expect_err("should fail with 422");

    assert!(
        matches!(
            err,
            fcp_github::error::GitHubError::ValidationError { .. }
        ),
        "expected ValidationError, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected FcpError::InvalidRequest, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("github.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(github_error_response("API rate limit exceeded")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 429");

    assert!(
        matches!(err, fcp_github::error::GitHubError::RateLimited { .. }),
        "expected RateLimited, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 409 Conflict maps to `FcpError::Conflict`.
#[fcp_async_core::runtime::test]
async fn error_409_maps_to_conflict() {
    let _ctx = AsyncTestContext::for_scenario("github.error.409");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/repos/octocat/hello-world/pulls/1/merge"))
        .respond_with(
            ResponseTemplate::new(409)
                .set_body_json(github_error_response("Pull Request is not mergeable")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .merge_pull_request(
            "octocat",
            "hello-world",
            1,
            &fcp_github::types::MergePullRequestRequest {
                commit_title: None,
                commit_message: None,
                merge_method: Some("merge".into()),
                sha: None,
            },
        )
        .await
        .expect_err("should fail with 409");

    assert!(
        matches!(err, fcp_github::error::GitHubError::MergeConflict { .. }),
        "expected MergeConflict, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Conflict { .. }),
        "expected FcpError::Conflict, got: {fcp_err:?}"
    );
}

/// 500 Server Error maps to `FcpError::External` with `retryable`=true.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external() {
    let _ctx = AsyncTestContext::for_scenario("github.error.500");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(github_error_response("Internal server error")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 500");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(service, "github");
            assert!(retryable, "500 should be retryable");
            assert_eq!(*status_code, Some(500));
        }
        other => panic!("expected FcpError::External, got: {other:?}"),
    }
}

/// Error `is_retryable` classification is correct.
#[test]
fn error_retryable_classification() {
    use fcp_github::error::GitHubError;

    assert!(GitHubError::RateLimited { retry_after_ms: 1000 }.is_retryable());
    assert!(
        GitHubError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            documentation_url: None,
        }
        .is_retryable()
    );
    assert!(
        GitHubError::Api {
            message: "Service unavailable".into(),
            status_code: Some(503),
            documentation_url: None,
        }
        .is_retryable()
    );

    assert!(!GitHubError::Unauthorized.is_retryable());
    assert!(
        !GitHubError::NotFound {
            resource: "test".into()
        }
        .is_retryable()
    );
    assert!(
        !GitHubError::ValidationError {
            message: "bad input".into()
        }
        .is_retryable()
    );
}

// ============================================================================
// FCP2 Default-Deny / Capability Verification Tests
// ============================================================================

/// Invoke without `capability_token` fails.
#[fcp_async_core::runtime::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.missing_token");
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    setup_handshake(&mut connector, &["github.get_repo"]).await;

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" }
        }))
        .await
        .expect_err("invoke without token should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing token, got: {err:?}"
    );
}

/// Invoke before handshake fails (no verifier).
#[fcp_async_core::runtime::test]
async fn capability_no_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.no_handshake");
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "github.get_repo");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without handshake should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Invoke before configure fails (no client).
#[fcp_async_core::runtime::test]
async fn capability_no_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.no_configure");

    let mut connector = GitHubConnector::new();
    let signing_key = setup_handshake(&mut connector, &["github.get_repo"]).await;
    let token = generate_valid_token(&signing_key, "github.get_repo");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without configure should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Token signed for wrong operation fails.
#[fcp_async_core::runtime::test]
async fn capability_wrong_operation_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.wrong_op");
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["github.get_repo", "github.create_issue"]).await;

    let wrong_token = generate_valid_token(&signing_key, "github.create_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": wrong_token
        }))
        .await
        .expect_err("wrong capability should fail");

    let is_cap_error = matches!(
        &err,
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::Unauthorized { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    );
    assert!(
        is_cap_error,
        "expected capability/operation denial, got: {err:?}"
    );
}

/// Unknown operation fails with `OperationNotGranted`.
#[fcp_async_core::runtime::test]
async fn capability_unknown_operation_fails() {
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "github.nonexistent");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("unknown operation should fail");

    assert!(
        matches!(err, fcp_core::FcpError::OperationNotGranted { .. }),
        "expected OperationNotGranted, got: {err:?}"
    );
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check before configure reports `not_configured`.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let connector = GitHubConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configure reports healthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

/// Handshake returns accepted with capabilities granted.
#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mut connector = GitHubConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["github.read", "github.write", "github.admin"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(result["status"], "accepted");
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

/// Shutdown returns clean status.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_clean() {
    let connector = GitHubConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

/// Introspect exposes all 12 operations with schemas.
#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_all_operations() {
    let connector = GitHubConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    let expected_ops = [
        "github.create_issue",
        "github.get_issue",
        "github.search_issues",
        "github.create_pull_request",
        "github.get_pull_request",
        "github.merge_pull_request",
        "github.get_repo",
        "github.search_repos",
        "github.list_workflows",
        "github.trigger_workflow",
        "github.get_file_content",
        "github.search_code",
    ];

    for expected in &expected_ops {
        assert!(op_ids.contains(expected), "missing operation: {expected}");
    }
    assert_eq!(ops.len(), 12);

    for op in ops {
        assert!(
            op["input_schema"].is_object(),
            "input_schema should be object for {}",
            op["id"]
        );
        assert!(
            op["output_schema"].is_object(),
            "output_schema should be object for {}",
            op["id"]
        );
    }
}

// ============================================================================
// Input Validation Edge Cases
// ============================================================================

/// Missing `owner` in `get_issue` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_issue_missing_owner() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "github.get_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": { "repo": "hello-world", "issue_number": 42 },
            "capability_token": token
        }))
        .await
        .expect_err("missing owner should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("owner"),
                "error should mention `owner`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `repo` in `get_issue` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_issue_missing_repo() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "github.get_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": { "owner": "octocat", "issue_number": 42 },
            "capability_token": token
        }))
        .await
        .expect_err("missing repo should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("repo"),
                "error should mention `repo`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `issue_number` in `get_issue` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_issue_missing_number() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "github.get_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("missing issue_number should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("issue_number"),
                "error should mention `issue_number`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `title` in `create_issue` fails.
#[fcp_async_core::runtime::test]
async fn validation_create_issue_missing_title() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_issue"]).await;
    let token = generate_valid_token(&signing_key, "github.create_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.create_issue",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("missing title should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("title"),
                "error should mention `title`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `head` in `create_pull_request` fails.
#[fcp_async_core::runtime::test]
async fn validation_create_pr_missing_head() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_pull_request"]).await;
    let token = generate_valid_token(&signing_key, "github.create_pull_request");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.create_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Fix typo",
                "base": "main"
            },
            "capability_token": token
        }))
        .await
        .expect_err("missing head should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("head"),
                "error should mention `head`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `query` in `search_issues` fails.
#[fcp_async_core::runtime::test]
async fn validation_search_issues_missing_query() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_issues"]).await;
    let token = generate_valid_token(&signing_key, "github.search_issues");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.search_issues",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing query should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("query"),
                "error should mention `query`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}
