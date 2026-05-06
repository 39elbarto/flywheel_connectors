//! Connector-local no-mock Netlify integration proof.
//!
//! These tests exercise the real Netlify client against a local HTTP server.
//! No live Netlify service is called.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_netlify::client::NetlifyClient;
use fcp_netlify::connector::NetlifyConnector;
use fcp_netlify::error::NetlifyError;
use fcp_netlify::types::{CreateDeployRequest, CreateSiteRequest, NetlifyAuth, SetEnvVarRequest};
use fcp_netlify::types::{SetEnvVarValue, User};
use fcp_prelude::{ApprovalMode, FcpConnector, RiskLevel, SafetyTier};
use fcp_sdk::migration::{
    ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig,
};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "netlify-token-for-tests";

fn no_retry_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    }
}

fn test_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(500)),
    )
}

async fn client(server: &MockServer) -> NetlifyClient {
    NetlifyClient::new(
        &server.uri(),
        NetlifyAuth {
            access_token: TEST_TOKEN.into(),
        },
        no_retry_config(),
    )
    .await
    .expect("wiremock URI should build a Netlify client")
}

fn test_site(site_id: &str) -> Value {
    json!({
        "id": site_id,
        "name": "fcp-site",
        "url": "https://fcp-site.netlify.app",
        "ssl_url": "https://fcp-site.netlify.app",
        "custom_domain": "example.com",
        "state": "current"
    })
}

fn test_deploy(deploy_id: &str, site_id: &str, state: &str) -> Value {
    json!({
        "id": deploy_id,
        "site_id": site_id,
        "state": state,
        "branch": "main",
        "title": "FCP deploy"
    })
}

#[fcp_async_core::test]
async fn site_deploy_dns_env_and_health_success_paths_use_netlify_contracts() {
    tracing::info!(
        scenario = "netlify_success_contracts",
        "starting Netlify success-path integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/api/v1/sites"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([test_site("site-1")])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/site-1"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_site("site-1")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/sites"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!({
            "name": "fcp-created",
            "custom_domain": "created.example.com"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(test_site("site-created")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/api/v1/sites/site-1"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/site-1/deploys"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([test_deploy("deploy-1", "site-1", "ready")])),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/sites/site-1/deploys"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!({
            "branch": "main",
            "title": "FCP deploy"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(test_deploy(
            "deploy-created",
            "site-1",
            "building",
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/sites/site-1/rollback/deploy-1"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!({})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(test_deploy("deploy-1", "site-1", "ready")),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/dns_zones"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": "zone-1",
            "name": "example.com",
            "site_id": "site-1"
        }])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/acme/env"))
        .and(query_param("site_id", "site-1"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "key": "API_KEY",
            "is_secret": true,
            "values": [{
                "id": "value-1",
                "value": "redacted",
                "context": "production"
            }]
        }])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/accounts/acme/env"))
        .and(query_param("site_id", "site-1"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!([{
            "key": "API_KEY",
            "values": [{
                "value": "secret-value",
                "context": "production"
            }],
            "is_secret": true
        }])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "key": "API_KEY",
            "is_secret": true,
            "values": [{
                "id": "value-2",
                "value": "redacted",
                "context": "production"
            }]
        }])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/api/v1/accounts/acme/env/API_KEY"))
        .and(query_param("site_id", "site-1"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user-1",
            "email": "dev@example.com"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server).await;

    let sites = client
        .list_sites(&runtime)
        .await
        .expect("sites should decode");
    assert_eq!(sites[0].id, "site-1");

    let site = client
        .get_site(&runtime, "site-1")
        .await
        .expect("site should decode");
    assert_eq!(site.custom_domain.as_deref(), Some("example.com"));

    let created = client
        .create_site(
            &runtime,
            &CreateSiteRequest {
                name: "fcp-created".into(),
                custom_domain: Some("created.example.com".into()),
            },
        )
        .await
        .expect("create site should decode");
    assert_eq!(created.id, "site-created");

    let deleted = client
        .delete_site(&runtime, "site-1")
        .await
        .expect("delete site should decode");
    assert_eq!(deleted, json!({}));

    let deploys = client
        .list_deploys(&runtime, "site-1")
        .await
        .expect("deploy list should decode");
    assert_eq!(deploys[0].id, "deploy-1");

    let created_deploy = client
        .create_deploy(
            &runtime,
            "site-1",
            &CreateDeployRequest {
                branch: Some("main".into()),
                title: Some("FCP deploy".into()),
            },
        )
        .await
        .expect("create deploy should decode");
    assert_eq!(created_deploy.state.as_deref(), Some("building"));

    let rollback = client
        .rollback_deploy(&runtime, "site-1", "deploy-1")
        .await
        .expect("rollback should decode");
    assert_eq!(rollback.id, "deploy-1");
    assert_eq!(rollback.state.as_deref(), Some("ready"));

    let zones = client
        .list_dns_zones(&runtime)
        .await
        .expect("DNS zones should decode");
    assert_eq!(zones[0].name, "example.com");

    let env = client
        .list_env_vars(&runtime, "acme", "site-1")
        .await
        .expect("env vars should decode");
    assert_eq!(env[0].key, "API_KEY");
    assert_eq!(env[0].is_secret, Some(true));

    let updated_env = client
        .set_env_var(
            &runtime,
            "acme",
            "site-1",
            &[SetEnvVarRequest {
                key: "API_KEY".into(),
                values: vec![SetEnvVarValue {
                    value: "secret-value".into(),
                    context: Some("production".into()),
                }],
                scopes: None,
                is_secret: Some(true),
            }],
        )
        .await
        .expect("set env var should decode");
    assert_eq!(updated_env[0].key, "API_KEY");
    assert_eq!(
        updated_env[0].values.as_ref().expect("values")[0].value,
        "redacted"
    );

    let deleted_env = client
        .delete_env_var(&runtime, "acme", "site-1", "API_KEY")
        .await
        .expect("delete env var should decode");
    assert_eq!(deleted_env, json!({}));

    let user: User = client
        .health_check(&runtime)
        .await
        .expect("health user should decode");
    assert_eq!(user.id, "user-1");
}

#[fcp_async_core::test]
async fn auth_rate_limit_malformed_json_and_invalid_input_are_typed() {
    tracing::info!(
        scenario = "netlify_error_taxonomy",
        "starting Netlify error-taxonomy integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/bad-auth"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "invalid token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/rate-limited"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({ "message": "rate limited" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/malformed"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server).await;

    let unauthorized = client
        .get_site(&runtime, "bad-auth")
        .await
        .expect_err("401 should map to unauthorized");
    assert!(matches!(unauthorized, NetlifyError::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());

    let rate_limited = client
        .get_site(&runtime, "rate-limited")
        .await
        .expect_err("429 should map to rate limit");
    assert!(matches!(
        rate_limited,
        NetlifyError::RateLimited {
            retry_after_ms: 2_000
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(2)));

    let malformed = client
        .get_site(&runtime, "malformed")
        .await
        .expect_err("malformed JSON should be typed");
    assert!(matches!(malformed, NetlifyError::Json(_)));
    assert!(!malformed.is_retryable());

    let traversal = client
        .get_site(&runtime, "../site")
        .await
        .expect_err("path traversal should be rejected before outbound call");
    assert!(matches!(traversal, NetlifyError::InvalidInput(_)));

    let query_injection = client
        .list_env_vars(&runtime, "acme", "site-1&team=other")
        .await
        .expect_err("query injection should be rejected before outbound call");
    assert!(matches!(query_injection, NetlifyError::InvalidInput(_)));
}

#[test]
fn async_timeout_and_cancellation_mapping_is_bounded() {
    let timeout = NetlifyError::from_async_error(AsyncError::Timeout { timeout_ms: 250 });
    assert_eq!(
        timeout.to_string(),
        "Async error: request deadline exceeded after 250ms"
    );
    assert!(!timeout.is_retryable());

    let cancelled = NetlifyError::from_async_error(AsyncError::Cancelled);
    assert_eq!(cancelled.to_string(), "Async error: operation cancelled");
    assert!(!cancelled.is_retryable());
}

#[test]
fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let connector = NetlifyConnector::new();
    let introspection = connector.introspect();
    let operation = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|entry| entry.id.as_str() == id)
            .expect("operation catalog should contain required Netlify operation")
    };

    let sites_list = operation("netlify.sites.list");
    assert_eq!(sites_list.risk_level, RiskLevel::Low);
    assert_eq!(sites_list.safety_tier, SafetyTier::Safe);
    assert_eq!(sites_list.requires_approval, None);

    let sites_delete = operation("netlify.sites.delete");
    assert_eq!(sites_delete.risk_level, RiskLevel::Critical);
    assert_eq!(sites_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(
        sites_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let deploy_rollback = operation("netlify.deploys.rollback");
    assert_eq!(deploy_rollback.risk_level, RiskLevel::High);
    assert_eq!(deploy_rollback.safety_tier, SafetyTier::Risky);

    let env_set = operation("netlify.env.set");
    assert_eq!(env_set.risk_level, RiskLevel::Medium);
    assert_eq!(env_set.safety_tier, SafetyTier::Risky);

    let capability_section = manifest_capability_section();
    assert!(capability_section.contains("\"network.dns\""));
    assert!(capability_section.contains("\"network.outbound\""));
    assert!(capability_section.contains("\"system.exec\""));
    assert!(capability_section.contains("\"system.privileged\""));
    assert!(!capability_section.contains("network.listen"));

    let client = fcp_async_core::runtime::block_on_sync(async {
        NetlifyClient::new(
            "https://api.netlify.com",
            NetlifyAuth {
                access_token: "super-secret-netlify-token".into(),
            },
            no_retry_config(),
        )
        .await
    })
    .expect("runtime should complete")
    .expect("redaction proof client should build");
    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains("super-secret-netlify-token"));
    assert!(debug_output.contains("[REDACTED]"));
}

fn manifest_capability_section() -> &'static str {
    let manifest = include_str!("../manifest.toml");
    let (_, capabilities) = manifest
        .split_once("[capabilities]")
        .expect("Netlify manifest should define capabilities");
    let (capability_section, _) = capabilities
        .split_once("[provides.operations.")
        .expect("Netlify manifest should separate capabilities from operations");
    capability_section
}
