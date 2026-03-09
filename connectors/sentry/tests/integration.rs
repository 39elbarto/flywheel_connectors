//! Integration tests for the FCP Sentry connector.

use serde_json::json;
use wiremock::matchers::{bearer_token, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_sentry::connector::SentryConnector;

// ── Helper ────────────────────────────────────────────────────────────

async fn configured_connector(mock_server: &MockServer) -> SentryConnector {
    let mut connector = SentryConnector::new();
    connector
        .handle_configure(json!({
            "auth_token": "test-token",
            "base_url": mock_server.uri(),
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({
            "session_id": "test-session",
        }))
        .await
        .expect("handshake should succeed");
    connector
}

// ── Lifecycle ─────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn configure_with_auth_token() {
    let mut connector = SentryConnector::new();
    let result = connector
        .handle_configure(json!({
            "auth_token": "sntrys_test_token_123",
        }))
        .await;
    assert!(result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn configure_missing_auth() {
    let mut connector = SentryConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_both_auth_methods_rejected() {
    let mut connector = SentryConnector::new();
    let result = connector
        .handle_configure(json!({
            "auth_token": "token",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn handshake_before_configure_fails() {
    let mut connector = SentryConnector::new();
    let result = connector
        .handle_handshake(json!({
            "session_id": "test",
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured() {
    let connector = SentryConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn health_configured_not_handshaken() {
    let mut connector = SentryConnector::new();
    connector
        .handle_configure(json!({"auth_token": "test"}))
        .await
        .unwrap();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn health_fully_configured() {
    let mock = MockServer::start().await;
    let connector = configured_connector(&mock).await;
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured() {
    let connector = SentryConnector::new();
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn self_check_reports_version() {
    let connector = SentryConnector::new();
    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["connector_id"], "fcp.sentry");
    assert_eq!(result["version"], "0.1.0");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_operations() {
    let connector = SentryConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().expect("operations array");
    assert!(ops.len() >= 21, "should have at least 21 operations");
    let ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
    assert!(ids.contains(&"sentry.list_issues"));
    assert!(ids.contains(&"sentry.get_event"));
    assert!(ids.contains(&"sentry.discover_query"));
    assert!(ids.contains(&"sentry.create_alert_rule"));
    assert!(ids.contains(&"sentry.issue.search"));
    assert!(ids.contains(&"sentry.issue.get_summary"));
    assert!(ids.contains(&"sentry.issue.assign"));
    assert!(ids.contains(&"sentry.issue.set_status"));
    assert!(ids.contains(&"sentry.issue.set_priority"));
}

#[fcp_async_core::runtime::test]
async fn simulate_known_operation() {
    let connector = SentryConnector::new();
    let result = connector
        .handle_simulate(json!({"operation_id": "sentry.list_issues"}))
        .await
        .unwrap();
    assert_eq!(result["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation() {
    let connector = SentryConnector::new();
    let result = connector
        .handle_simulate(json!({"operation_id": "sentry.nonexistent"}))
        .await
        .unwrap();
    assert_eq!(result["allowed"], false);
}

#[fcp_async_core::runtime::test]
async fn shutdown_resets_state() {
    let mock = MockServer::start().await;
    let mut connector = configured_connector(&mock).await;
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");

    connector.handle_shutdown(json!({})).await.unwrap();
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
}

// ── Invoke: List Projects ─────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_projects() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/my-org/projects/"))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "1", "slug": "backend", "name": "Backend", "platform": "python"},
            {"id": "2", "slug": "frontend", "name": "Frontend", "platform": "javascript"},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_projects",
            "input": {"organization_slug": "my-org"},
        }))
        .await
        .unwrap();

    let projects = result["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0]["slug"], "backend");
}

// ── Invoke: List Issues ───────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_issues() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/my-org/backend/issues/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "100", "title": "NullPointerException", "level": "error", "status": "unresolved"},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_issues",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
                "query": "is:unresolved",
            },
        }))
        .await
        .unwrap();

    let issues = result["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["title"], "NullPointerException");
}

// ── Invoke: Get Issue ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_get_issue() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/12345/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "12345",
            "title": "TypeError: undefined is not a function",
            "status": "unresolved",
            "count": "42",
            "userCount": 15,
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "12345"},
        }))
        .await
        .unwrap();

    assert_eq!(
        result["issue"]["title"],
        "TypeError: undefined is not a function"
    );
    assert_eq!(result["issue"]["count"], "42");
}

// ── Invoke: Issue Search ──────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_issue_search() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/my-org/backend/issues/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "100", "title": "NullPointerException", "level": "error", "status": "unresolved"},
            {"id": "101", "title": "TimeoutError", "level": "error", "status": "unresolved"},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.issue.search",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
                "status": "unresolved",
                "level": "error",
                "sort": "priority",
            },
        }))
        .await
        .unwrap();

    let issues = result["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 2);
    assert_eq!(issues[0]["title"], "NullPointerException");
}

// ── Invoke: Issue Get Summary ────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_issue_get_summary() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/12345/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "12345",
            "title": "TypeError: undefined is not a function",
            "shortId": "BACKEND-42",
            "status": "unresolved",
            "level": "error",
            "count": "42",
            "userCount": 15,
            "firstSeen": "2026-01-01T00:00:00Z",
            "lastSeen": "2026-03-09T12:00:00Z",
            "assignedTo": {"name": "Alice", "email": "alice@example.com"},
            "metadata": {"type": "TypeError"},
            "type": "error",
            "platform": "javascript",
            "extra_field": "should_not_appear"
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.issue.get_summary",
            "input": {"issue_id": "12345"},
        }))
        .await
        .unwrap();

    let summary = &result["summary"];
    assert_eq!(summary["id"], "12345");
    assert_eq!(summary["title"], "TypeError: undefined is not a function");
    assert_eq!(summary["shortId"], "BACKEND-42");
    assert_eq!(summary["status"], "unresolved");
    assert_eq!(summary["level"], "error");
    assert_eq!(summary["count"], "42");
    assert_eq!(summary["userCount"], 15);
    assert_eq!(summary["platform"], "javascript");
    // Ensure extra fields are not leaked
    assert!(result["summary"].get("extra_field").is_none());
}

// ── Invoke: Update Issue ──────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_update_issue() {
    let mock = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/issues/12345/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "12345",
            "status": "resolved",
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.update_issue",
            "input": {"issue_id": "12345", "status": "resolved"},
        }))
        .await
        .unwrap();

    assert_eq!(result["issue"]["status"], "resolved");
}

// ── Invoke: Delete Issue ──────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_delete_issue() {
    let mock = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/issues/12345/"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.delete_issue",
            "input": {"issue_id": "12345"},
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"], true);
}

// ── Invoke: Get Event ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_get_event() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/my-org/backend/events/abc123/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "eventID": "abc123",
            "title": "Error in handler",
            "platform": "python",
            "entries": [{"type": "exception", "data": {}}],
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_event",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
                "event_id": "abc123",
            },
        }))
        .await
        .unwrap();

    assert_eq!(result["event"]["eventID"], "abc123");
}

// ── Invoke: List Issue Events ─────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_issue_events() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/12345/events/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"eventID": "ev1", "title": "Error"},
            {"eventID": "ev2", "title": "Error 2"},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_issue_events",
            "input": {"issue_id": "12345"},
        }))
        .await
        .unwrap();

    let events = result["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
}

// ── Invoke: Releases ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_releases() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/organizations/my-org/releases/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"version": "backend@1.2.3", "dateCreated": "2026-03-01T00:00:00Z"},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_releases",
            "input": {"organization_slug": "my-org"},
        }))
        .await
        .unwrap();

    let releases = result["releases"].as_array().unwrap();
    assert_eq!(releases.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_get_release() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/organizations/my-org/releases/.*/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": "backend@1.2.3",
            "newGroups": 5,
            "commitCount": 12,
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_release",
            "input": {
                "organization_slug": "my-org",
                "version": "backend@1.2.3",
            },
        }))
        .await
        .unwrap();

    assert_eq!(result["release"]["version"], "backend@1.2.3");
}

// ── Invoke: Alert Rules ───────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_alert_rules() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/my-org/backend/rules/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "1", "name": "High error rate", "frequency": 30},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_alert_rules",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
            },
        }))
        .await
        .unwrap();

    let rules = result["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["name"], "High error rate");
}

#[fcp_async_core::runtime::test]
async fn invoke_create_alert_rule() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/my-org/backend/rules/"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "42",
            "name": "New alert",
            "frequency": 60,
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.create_alert_rule",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
                "name": "New alert",
                "conditions": [{"id": "sentry.rules.conditions.first_seen_event.FirstSeenEventCondition"}],
                "actions": [{"id": "sentry.mail.actions.NotifyEmailAction", "targetType": "IssueOwners"}],
                "frequency": 60,
            },
        }))
        .await
        .unwrap();

    assert_eq!(result["rule"]["name"], "New alert");
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_alert_rule() {
    let mock = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/projects/my-org/backend/rules/42/"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.delete_alert_rule",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
                "rule_id": "42",
            },
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"], true);
}

// ── Invoke: Discover Query ────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_discover_query() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/organizations/my-org/events/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"transaction": "/api/users", "count()": 1500, "p95()": 234.5},
            ],
            "meta": {"fields": {"transaction": "string", "count()": "integer"}},
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.discover_query",
            "input": {
                "organization_slug": "my-org",
                "query": "event.type:transaction",
                "fields": ["transaction", "count()", "p95()"],
                "statsPeriod": "24h",
            },
        }))
        .await
        .unwrap();

    let data = result["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["transaction"], "/api/users");
}

// ── Error Handling ────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation() {
    let mock = MockServer::start().await;
    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.nonexistent",
            "input": {},
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_required_field() {
    let mock = MockServer::start().await;
    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {},
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_not_configured() {
    let connector = SentryConnector::new();
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_projects",
            "input": {"organization_slug": "test"},
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_api_401_unauthorized() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/999/"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "detail": "Invalid token",
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "999"},
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_api_404_not_found() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/notfound/"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "detail": "The requested resource does not exist",
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "notfound"},
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_api_429_rate_limited() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/throttled/"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "30")
                .set_body_json(json!({"detail": "Rate limited"})),
        )
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "throttled"},
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_api_403_forbidden() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/forbidden/"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"detail": "Insufficient permissions"})),
        )
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "forbidden"},
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_api_500_server_error() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/broken/"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"detail": "Internal Server Error"})),
        )
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "broken"},
        }))
        .await;
    assert!(result.is_err());
}

// ── Invoke: Update Alert Rule ────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_update_alert_rule() {
    let mock = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/projects/my-org/backend/rules/42/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "42",
            "name": "Updated alert",
            "frequency": 120,
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.update_alert_rule",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
                "rule_id": "42",
                "name": "Updated alert",
                "frequency": 120,
            },
        }))
        .await
        .unwrap();

    assert_eq!(result["rule"]["name"], "Updated alert");
}

// ── Invoke: List Release Deploys ─────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_release_deploys() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/organizations/my-org/releases/.*/deploys/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "1", "environment": "production", "dateFinished": "2026-03-01T00:00:00Z"},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_release_deploys",
            "input": {
                "organization_slug": "my-org",
                "version": "backend@1.2.3",
            },
        }))
        .await
        .unwrap();

    let deploys = result["deploys"].as_array().unwrap();
    assert_eq!(deploys.len(), 1);
    assert_eq!(deploys[0]["environment"], "production");
}

// ── Invoke: Get Transaction ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_get_transaction() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/my-org/backend/events/tx-abc/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "eventID": "tx-abc",
            "title": "GET /api/users",
            "transaction": "/api/users",
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_transaction",
            "input": {
                "organization_slug": "my-org",
                "project_slug": "backend",
                "event_id": "tx-abc",
            },
        }))
        .await
        .unwrap();

    assert_eq!(result["event"]["transaction"], "/api/users");
}

// ── Health: error/request counters ───────────────────────────────────

#[fcp_async_core::runtime::test]
async fn health_tracks_request_count() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/1/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "1", "title": "t"})))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "1"},
        }))
        .await
        .unwrap();

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["requests"], 1);
    assert_eq!(health["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn health_tracks_error_count() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/issues/fail/"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"detail": "boom"})))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let _ = connector
        .handle_invoke(json!({
            "operation_id": "sentry.get_issue",
            "input": {"issue_id": "fail"},
        }))
        .await;

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["requests"], 1);
    assert_eq!(health["errors"], 1);
}

// ── Doctor: fully configured ─────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn doctor_fully_configured() {
    let mock = MockServer::start().await;
    let connector = configured_connector(&mock).await;
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "healthy");
    let checks = result["checks"].as_array().unwrap();
    assert!(checks.iter().all(|c| c["passed"] == true));
}

// ── Simulate: all 21 operations ──────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn simulate_all_known_operations() {
    let connector = SentryConnector::new();
    let ops = [
        "sentry.list_projects",
        "sentry.list_issues",
        "sentry.get_issue",
        "sentry.update_issue",
        "sentry.delete_issue",
        "sentry.list_issue_events",
        "sentry.get_event",
        "sentry.get_transaction",
        "sentry.list_releases",
        "sentry.get_release",
        "sentry.list_release_deploys",
        "sentry.discover_query",
        "sentry.list_alert_rules",
        "sentry.create_alert_rule",
        "sentry.update_alert_rule",
        "sentry.delete_alert_rule",
        "sentry.issue.search",
        "sentry.issue.get_summary",
        "sentry.issue.assign",
        "sentry.issue.set_status",
        "sentry.issue.set_priority",
    ];
    for op in &ops {
        let result = connector
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert_eq!(result["allowed"], true, "simulate should allow {op}");
    }
}

// ── Configure: credential_id ─────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id() {
    let mut connector = SentryConnector::new();
    let result = connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .await;
    assert!(result.is_ok());
}

// ── Handshake: returns capabilities ──────────────────────────────────

#[fcp_async_core::runtime::test]
async fn handshake_returns_capabilities() {
    let mut connector = SentryConnector::new();
    connector
        .handle_configure(json!({"auth_token": "test"}))
        .await
        .unwrap();
    let result = connector
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(result["protocol_version"], "2.0");
    assert_eq!(result["connector_id"], "fcp.sentry");
    let caps = result["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "sentry.read"));
    assert!(caps.iter().any(|c| c == "sentry.write"));
    assert!(caps.iter().any(|c| c == "sentry.alerts"));
    assert!(caps.iter().any(|c| c == "sentry.admin"));
}

// ── Invoke: missing operation_id ─────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_id() {
    let mock = MockServer::start().await;
    let connector = configured_connector(&mock).await;
    let result = connector.handle_invoke(json!({"input": {}})).await;
    assert!(result.is_err());
}

// ── List Issues Events: with full=true ───────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_issue_events_full() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/issues/12345/events/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"eventID": "ev1", "title": "Error"},
        ])))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.list_issue_events",
            "input": {"issue_id": "12345", "full": true},
        }))
        .await
        .unwrap();

    let events = result["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
}

// ── Invoke: Issue Assign ─────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_issue_assign() {
    let mock = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/issues/123/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123",
            "assignedTo": {"type": "user", "email": "alice@example.com"},
            "status": "unresolved"
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.issue.assign",
            "input": {
                "issue_id": "123",
                "assignee": "alice@example.com"
            }
        }))
        .await
        .unwrap();
    assert!(result.get("issue").is_some());
    assert_eq!(result["issue"]["assignedTo"]["email"], "alice@example.com");
}

// ── Invoke: Issue Set Status ─────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_issue_set_status() {
    let mock = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/issues/456/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "456",
            "status": "resolved"
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.issue.set_status",
            "input": {
                "issue_id": "456",
                "status": "resolved"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["issue"]["status"], "resolved");
}

// ── Invoke: Issue Set Priority ───────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_issue_set_priority() {
    let mock = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/issues/789/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "789",
            "priority": "high"
        })))
        .mount(&mock)
        .await;

    let connector = configured_connector(&mock).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "sentry.issue.set_priority",
            "input": {
                "issue_id": "789",
                "priority": "high"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["issue"]["priority"], "high");
}
