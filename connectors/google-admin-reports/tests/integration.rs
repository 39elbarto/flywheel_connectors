//! Connector-local no-mock Google Admin Reports integration proof.
//!
//! These tests exercise the real Admin Reports client against a local HTTP
//! server. No live Google Admin SDK service is called.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_google_admin_reports::client::AdminReportsClient;
use fcp_google_admin_reports::connector::AdminReportsConnector;
use fcp_google_admin_reports::error::AdminReportsError;
use fcp_google_discovery::auth::{
    GOOGLE_AUTHORIZATION_HEADER, GoogleAuthSourceKind, GoogleMaterializedAuth,
};
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "ya29.admin-reports-test-token";
const AUTH_HEADER_VALUE: &str = "Bearer ya29.admin-reports-test-token";

fn materialized_test_auth() -> GoogleMaterializedAuth {
    GoogleMaterializedAuth::BearerToken {
        access_token: TEST_TOKEN.to_string(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: Vec::new(),
        quota_project_id: None,
    }
}

fn client(server: &MockServer) -> AdminReportsClient {
    AdminReportsClient::new_with_auth(materialized_test_auth())
        .expect("test auth should build an Admin Reports client")
        .with_base_url(&format!("{}/admin/reports/v1", server.uri()))
}

async fn configured_connector(server: &MockServer) -> AdminReportsConnector {
    let mut connector = AdminReportsConnector::new();
    connector
        .handle_configure(json!({
            "access_token": TEST_TOKEN,
            "base_url": format!("{}/admin/reports/v1", server.uri()),
            "scope_triggers": [
                "User enables usage-report workflows (user, customer, or entity usage metrics)."
            ]
        }))
        .await
        .expect("loopback base_url and in-memory bearer token should configure");
    connector
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).expect("missing expected JSON field")
}

fn array_field<'a>(value: &'a Value, name: &str) -> &'a Vec<Value> {
    field(value, name)
        .as_array()
        .expect("expected JSON field to be an array")
}

fn operation_ids(introspection: &Value) -> Vec<&str> {
    array_field(introspection, "operations")
        .iter()
        .filter_map(|operation| field(operation, "id").as_str())
        .collect()
}

fn operation<'a>(introspection: &'a Value, id: &str) -> &'a Value {
    array_field(introspection, "operations")
        .iter()
        .find(|operation| field(operation, "id") == id)
        .expect("introspection should contain requested operation")
}

fn manifest_declares_operation(manifest: &str, id: &str) -> bool {
    manifest
        .lines()
        .any(|line| line.starts_with("[provides.operations.") && line.contains(id))
}

fn manifest_capability_section() -> &'static str {
    let manifest = include_str!("../manifest.toml");
    let (_, capabilities) = manifest
        .split_once("[capabilities]")
        .expect("Admin Reports manifest should define capabilities");
    let (capability_section, _) = capabilities
        .split_once("[provides.operations.")
        .expect("Admin Reports manifest should separate capabilities from operations");
    capability_section
}

fn usage_report(date: &str, entity: &Value, parameter_name: &str, parameter_value: &str) -> Value {
    json!({
        "kind": "admin#reports#usageReport",
        "date": date,
        "entity": entity,
        "parameters": [{
            "name": parameter_name,
            "intValue": parameter_value
        }]
    })
}

#[fcp_async_core::runtime::test]
async fn activities_usage_pagination_and_health_use_admin_reports_contracts() {
    tracing::info!(
        scenario = "google_admin_reports_success_contracts",
        "starting Google Admin Reports success-path integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(
            "/admin/reports/v1/activity/users/all/applications/login",
        ))
        .and(query_param("startTime", "2026-03-25T00:00:00Z"))
        .and(query_param("endTime", "2026-03-26T00:00:00Z"))
        .and(query_param("eventName", "login_success"))
        .and(query_param("filters", "ip_address==203.0.113.10"))
        .and(query_param("maxResults", "2"))
        .and(query_param("pageToken", "activity-page-1"))
        .and(query_param("customerId", "C123"))
        .and(query_param("orgUnitID", "/Engineering"))
        .and(query_param("groupIdFilter", "engineering@example.com"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "admin#reports#activities",
            "nextPageToken": "activity-page-2",
            "items": [{
                "kind": "admin#reports#activity",
                "id": {
                    "time": "2026-03-25T12:00:00Z",
                    "uniqueQualifier": "activity-1",
                    "applicationName": "login",
                    "customerId": "C123"
                },
                "actor": {
                    "email": "admin@example.com",
                    "callerType": "USER"
                },
                "events": [{
                    "type": "login",
                    "name": "login_success",
                    "parameters": [{
                        "name": "login_type",
                        "value": "google_password"
                    }]
                }],
                "ipAddress": "203.0.113.10"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/admin/reports/v1/usage/users/all/dates/2026-03-25"))
        .and(query_param("customerId", "C123"))
        .and(query_param(
            "parameters",
            "accounts:num_users,gmail:num_emails_sent",
        ))
        .and(query_param("filters", "accounts:num_users>0"))
        .and(query_param("maxResults", "3"))
        .and(query_param("pageToken", "usage-page-1"))
        .and(query_param("orgUnitID", "/Engineering"))
        .and(query_param("groupIdFilter", "engineering@example.com"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "admin#reports#usageReports",
            "nextPageToken": "usage-page-2",
            "usageReports": [
                usage_report(
                    "2026-03-25",
                    &json!({"type": "USER", "userEmail": "person@example.com"}),
                    "accounts:num_users",
                    "1"
                )
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/admin/reports/v1/usage/dates/2026-03-25"))
        .and(query_param("customerId", "C123"))
        .and(query_param("parameters", "accounts:num_users"))
        .and(query_param("pageToken", "customer-page-1"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "admin#reports#usageReports",
            "nextPageToken": "customer-page-2",
            "usageReports": [
                usage_report(
                    "2026-03-25",
                    &json!({"type": "CUSTOMER", "customerId": "C123"}),
                    "accounts:num_users",
                    "42"
                )
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/admin/reports/v1/usage/gplus_communities/community-1/dates/2026-03-25",
        ))
        .and(query_param("customerId", "C123"))
        .and(query_param("parameters", "gplus:num_posts"))
        .and(query_param("filters", "gplus:num_posts>10"))
        .and(query_param("maxResults", "4"))
        .and(query_param("pageToken", "entity-page-1"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "admin#reports#usageReports",
            "nextPageToken": "entity-page-2",
            "usageReports": [
                usage_report(
                    "2026-03-25",
                    &json!({"type": "gplus_communities", "entityKey": "community-1"}),
                    "gplus:num_posts",
                    "12"
                )
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/admin/reports/v1/activity/users/all/applications/admin",
        ))
        .and(query_param("maxResults", "1"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "admin#reports#activities",
            "items": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let activities = client
        .list_activities(
            "all",
            "login",
            Some("2026-03-25T00:00:00Z"),
            Some("2026-03-26T00:00:00Z"),
            Some("login_success"),
            Some("ip_address==203.0.113.10"),
            Some(2),
            Some("activity-page-1"),
            Some("C123"),
            Some("/Engineering"),
            Some("engineering@example.com"),
        )
        .await
        .expect("activity listing should decode");
    assert_eq!(
        activities.next_page_token.as_deref(),
        Some("activity-page-2")
    );
    let activity = activities.items.first().expect("activity item");
    assert_eq!(
        activity
            .actor
            .as_ref()
            .and_then(|actor| actor.email.as_deref()),
        Some("admin@example.com")
    );
    assert_eq!(activity.ip_address.as_deref(), Some("203.0.113.10"));

    let user_usage = client
        .list_user_usage(
            "all",
            "2026-03-25",
            Some("C123"),
            Some("accounts:num_users,gmail:num_emails_sent"),
            Some("accounts:num_users>0"),
            Some(3),
            Some("usage-page-1"),
            Some("/Engineering"),
            Some("engineering@example.com"),
        )
        .await
        .expect("user usage listing should decode");
    assert_eq!(user_usage.next_page_token.as_deref(), Some("usage-page-2"));
    assert_eq!(user_usage.usage_reports.len(), 1);
    assert_eq!(
        user_usage.usage_reports[0]
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.first())
            .and_then(|parameter| parameter.name.as_deref()),
        Some("accounts:num_users")
    );

    let customer_usage = client
        .list_customer_usage(
            "2026-03-25",
            Some("C123"),
            Some("accounts:num_users"),
            Some("customer-page-1"),
        )
        .await
        .expect("customer usage listing should decode");
    assert_eq!(
        customer_usage.next_page_token.as_deref(),
        Some("customer-page-2")
    );
    assert_eq!(
        customer_usage.usage_reports[0]
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.first())
            .and_then(|parameter| parameter.int_value.as_deref()),
        Some("42")
    );

    let entity_usage = client
        .list_entity_usage(
            "gplus_communities",
            "community-1",
            "2026-03-25",
            Some("C123"),
            Some("gplus:num_posts"),
            Some("gplus:num_posts>10"),
            Some(4),
            Some("entity-page-1"),
        )
        .await
        .expect("entity usage listing should decode");
    assert_eq!(
        entity_usage.next_page_token.as_deref(),
        Some("entity-page-2")
    );
    assert_eq!(
        entity_usage.usage_reports[0]
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.first())
            .and_then(|parameter| parameter.int_value.as_deref()),
        Some("12")
    );

    client
        .health_check()
        .await
        .expect("health check should use the lightweight activities probe");
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_malformed_json_and_fcp_mapping_are_typed() {
    tracing::info!(
        scenario = "google_admin_reports_error_taxonomy",
        "starting Google Admin Reports error-taxonomy integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(
            "/admin/reports/v1/activity/users/bad-auth/applications/login",
        ))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": 401,
                "message": "invalid credentials",
                "status": "UNAUTHENTICATED"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/admin/reports/v1/usage/users/all/dates/2026-03-26"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": {
                        "code": 429,
                        "message": "quota exhausted",
                        "status": "RESOURCE_EXHAUSTED"
                    }
                })),
        )
        .expect(3)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/admin/reports/v1/usage/dates/2026-03-27"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("{this is not json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client
        .list_activities(
            "bad-auth", "login", None, None, None, None, None, None, None, None, None,
        )
        .await
        .expect_err("401 should map to Admin Reports unauthorized");
    assert!(matches!(unauthorized, AdminReportsError::Unauthorized));
    assert!(!unauthorized.is_retryable());
    assert!(matches!(
        unauthorized.to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let rate_limited = client
        .list_user_usage(
            "all",
            "2026-03-26",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("429 should map to Admin Reports rate limit");
    assert!(matches!(
        rate_limited,
        AdminReportsError::RateLimited {
            retry_after_secs: 0
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::ZERO));
    assert!(matches!(
        rate_limited.to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 0,
            ..
        }
    ));

    let nonzero_retry_after = AdminReportsError::RateLimited {
        retry_after_secs: 7,
    };
    assert!(matches!(
        nonzero_retry_after.to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 7_000,
            ..
        }
    ));

    let malformed = client
        .list_customer_usage("2026-03-27", None, None, None)
        .await
        .expect_err("malformed JSON should be surfaced as a JSON error");
    assert!(matches!(malformed, AdminReportsError::Json(_)));
    assert!(matches!(
        malformed.to_fcp_error(),
        FcpError::Internal { .. }
    ));
}

#[test]
fn async_timeout_and_cancellation_mapping_is_bounded() {
    let timeout = AdminReportsError::from_async_error(AsyncError::Timeout { timeout_ms: 250 });
    assert!(matches!(
        &timeout,
        AdminReportsError::Api {
            status_code: 408,
            message,
        } if message.contains("250ms")
    ));
    assert!(!timeout.is_retryable());
    assert!(matches!(
        timeout.to_fcp_error(),
        FcpError::External {
            service,
            status_code: Some(408),
            retryable: false,
            ..
        } if service == "google_admin_reports"
    ));

    let cancelled = AdminReportsError::from_async_error(AsyncError::Cancelled);
    assert!(matches!(
        &cancelled,
        AdminReportsError::Api {
            status_code: 0,
            message,
        } if message == "request cancelled"
    ));
    assert!(!cancelled.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server).await;
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let ids = operation_ids(&introspection);
    for id in [
        "admin.list_activities",
        "admin.list_user_usage",
        "admin.list_customer_usage",
        "admin.list_entity_usage",
    ] {
        assert!(ids.contains(&id), "introspection missing operation {id}");
    }

    let activities = operation(&introspection, "admin.list_activities");
    assert_eq!(field(activities, "capability"), "admin.reports.audit.read");
    assert_eq!(field(activities, "risk_level"), "high");
    assert_eq!(field(activities, "safety_tier"), "safe");
    assert_eq!(field(activities, "idempotency"), "strict");
    assert_eq!(field(activities, "requires_approval"), "policy");

    let user_usage = operation(&introspection, "admin.list_user_usage");
    assert_eq!(field(user_usage, "capability"), "admin.reports.usage.read");
    assert_eq!(field(user_usage, "risk_level"), "high");
    assert_eq!(field(user_usage, "safety_tier"), "safe");
    assert_eq!(field(user_usage, "idempotency"), "strict");
    assert_eq!(field(user_usage, "requires_approval"), "policy");

    let manifest = include_str!("../manifest.toml");
    for id in ids {
        assert!(
            manifest_declares_operation(manifest, id),
            "manifest missing introspected operation {id}"
        );
    }
    assert!(manifest.contains("deny_localhost = true"));
    assert!(manifest.contains("require_sni = true"));

    let capability_section = manifest_capability_section();
    assert!(capability_section.contains("\"network.dns\""));
    assert!(capability_section.contains("\"network.egress\""));
    assert!(capability_section.contains("\"network.tls.sni\""));
    assert!(capability_section.contains("\"system.exec\""));
    assert!(capability_section.contains("\"network.listen\""));

    let health = connector
        .handle_health()
        .await
        .expect("health should serialize configured metadata");
    let health_auth_mode = field(&health, "auth_mode")
        .as_str()
        .expect("health auth_mode should be a string");
    assert_eq!(health_auth_mode, "google_auth:bearer:redacted");
    assert!(!health.to_string().contains(TEST_TOKEN));

    let configure_details = field(
        &configured_connector(&server)
            .await
            .handle_configure(json!({
                "access_token": TEST_TOKEN,
                "base_url": format!("{}/admin/reports/v1", server.uri())
            }))
            .await
            .expect("reconfigure should serialize redacted auth details"),
        "details",
    )
    .clone();
    assert_eq!(
        field(&configure_details, "auth_mode"),
        "google_auth:bearer:redacted"
    );
    assert!(!configure_details.to_string().contains(TEST_TOKEN));

    let client = client(&server);
    assert_eq!(client.auth_redacted_label(), "google_auth:bearer:redacted");
    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains(TEST_TOKEN));
    assert!(debug_output.contains("google_auth:bearer:redacted"));
}
