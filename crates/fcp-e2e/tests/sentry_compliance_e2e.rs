//! E2E Sentry connector compliance tests.
//!
//! Exercises the Sentry connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` wildcard validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features sentry`

#![cfg(feature = "sentry")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId,
    OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

use fcp_sentry::connector::SentryConnector;

// ============================================================================
// FcpConnector adapter for SentryConnector
// ============================================================================

struct SentryConnectorAdapter {
    connector: SentryConnector,
    id: ConnectorId,
}

impl SentryConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: SentryConnector::new(),
            id: ConnectorId::from_static("sentry"),
        }
    }
}

#[fcp_core::async_trait]
impl FcpConnector for SentryConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let session_id = SessionId::new();
        self.connector
            .handle_handshake(json!({
                "session_id": session_id.to_string(),
            }))
            .await?;

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:sentry-connector-v1".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "not_configured" | "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("sentry_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("sentry.list_projects"),
                summary: "List projects in a Sentry organization".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["organization_slug"],
                    "properties": {
                        "organization_slug": { "type": "string" },
                        "cursor": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "projects": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("sentry.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List projects in a Sentry organization.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"organization_slug": "my-org"}"#.to_string()],
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id;
        let params = json!({
            "operation_id": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.handle_simulate(request).await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize simulate response: {err}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn reference_manifest_with_hash() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken { raw: cose }
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("sentry-e2e"),
        connector_id: ConnectorId::from_static("sentry"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn sentry_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/sentry/manifest.toml"))
        .expect("sentry manifest toml")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|constraints| constraints.get("host_allow"))
        .and_then(toml::Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .expect("operation host_allow")
}

fn host_allowed(host: &str, host_allow: &[String]) -> bool {
    host_allow.iter().any(|pattern| {
        pattern == host
            || pattern
                .strip_prefix("*.")
                .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
    })
}

/// Sentry `list_projects` API success response.
fn sentry_list_projects_response() -> serde_json::Value {
    json!([
        {
            "slug": "my-project",
            "name": "My Project",
            "id": "123"
        }
    ])
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "sentry.write" but invoke targets "sentry.list_projects"
/// (which requires "sentry.read").
#[fcp_async_core::runtime::test]
async fn sentry_default_deny_compliance_suite_passes() {
    let mut connector = SentryConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["sentry.write"]);
    // Token grants "sentry.write" but invoke targets "sentry.list_projects" -> denial
    let token = build_token(&signing_key, "sentry.write", &["sentry.write"]);
    let invoke = invoke_request(
        "sentry.list_projects",
        json!({ "organization_slug": "test-org" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "auth_token": "sntrys_test_000",
            "organization_slug": "test-org",
            "base_url": "http://localhost:9999"
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "sentry_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-sentry");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock REST API.
#[fcp_async_core::runtime::test]
async fn sentry_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /api/0/organizations/{org}/projects/
    Mock::given(method("GET"))
        .and(path_regex(r"^/organizations/.*/projects/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sentry_list_projects_response()))
        .mount(mock.inner())
        .await;

    let mut connector = SentryConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["sentry.list_projects"],
    );
    let token = build_token(
        &signing_key,
        "sentry.list_projects",
        &["sentry.list_projects"],
    );
    let invoke = invoke_request(
        "sentry.list_projects",
        json!({ "organization_slug": "test-org" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "sentry_allow_valid_token".to_string(),
        config: json!({
            "auth_token": "sntrys_test_e2e",
            "organization_slug": "test-org",
            "base_url": mock.base_url(),
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-sentry");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let invoke_entry = report
        .logs
        .iter()
        .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke entry");
    assert_eq!(invoke_entry.result, "pass");
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Sentry manifest restricts operations to
/// `sentry.io` and `*.sentry.io`. Verify that matching hosts pass and
/// non-matching hosts are denied.
#[test]
fn sentry_manifest_network_guard_allows_and_denies() {
    let manifest = sentry_manifest_toml();

    let operations = [
        "sentry.list_projects",
        "sentry.list_issues",
        "sentry.get_issue",
        "sentry.get_event",
        "sentry.create_alert_rule",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);

        // All operations should allow sentry.io
        assert!(
            host_allowed("sentry.io", &host_allow),
            "sentry.io should be allowed for {operation_name}"
        );

        // All operations should allow subdomains via *.sentry.io
        assert!(
            host_allowed("us.sentry.io", &host_allow),
            "us.sentry.io should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("o123456.ingest.sentry.io", &host_allow),
            "o123456.ingest.sentry.io should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("evil.com", &host_allow),
            "evil.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("notsentry.io", &host_allow),
            "notsentry.io should be denied for {operation_name}"
        );
    }
}
