//! E2E Microsoft 365 connector compliance tests (flywheel_connectors-m6u7.10).
//!
//! Exercises the M365 connector through the E2E compliance harness:
//! - Default deny (missing capability -> error)
//! - Allow with valid token (happy path invoke via mock API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//! - Dangerous action gating (mail send, calendar write, file delete)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features microsoft365`

#![cfg(feature = "microsoft365")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
    FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use fcp_microsoft365::connector::M365Connector;

// ============================================================================
// FcpConnector adapter for M365Connector
// ============================================================================

struct M365ConnectorAdapter {
    connector: M365Connector,
    id: ConnectorId,
}

impl M365ConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: M365Connector::new(),
            id: ConnectorId::from_static("microsoft365"),
        }
    }
}

fcp_core::impl_fcp_sealed!(M365ConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for M365ConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.handle_handshake(request).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
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
                    "not_configured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("m365_status:{other}")),
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
                id: OperationId::from_static("m365.calendar.list_events"),
                summary: "List calendar events within a time range".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["user_id"],
                    "properties": {
                        "user_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["events"],
                    "properties": {
                        "events": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("m365.calendar.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List calendar events.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"user_id": "me"}"#.to_string()],
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
            "operation": req.operation.as_str(),
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
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("m365-e2e"),
        connector_id: ConnectorId::from_static("microsoft365"),
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

fn m365_manifest_toml() -> toml::Value {
    toml::from_str(include_str!(
        "../../../connectors/microsoft365/manifest.toml"
    ))
    .expect("m365 manifest toml")
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

/// JWT token helper for M365 access_token mode.
fn make_jwt_token(scopes: &[&str]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let claims = json!({
        "aud": "https://graph.microsoft.com",
        "scp": scopes.join(" "),
        "exp": 9_999_999_999u64,
    });
    let h = URL_SAFE_NO_PAD.encode(header);
    let c = URL_SAFE_NO_PAD.encode(claims.to_string());
    let s = URL_SAFE_NO_PAD.encode("fake-sig");
    format!("{h}.{c}.{s}")
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "m365.mail.send" but invoke targets "m365.calendar.list_events"
/// (which requires "m365.calendar.read").
#[fcp_async_core::runtime::test]
async fn m365_default_deny_compliance_suite_passes() {
    let mut connector = M365ConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["m365.mail.send"]);
    let token = build_token(&signing_key, "m365.mail.send", &["m365.mail.send"]);
    let invoke = invoke_request(
        "m365.calendar.list_events",
        json!({ "user_id": "me" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "access_token": make_jwt_token(&["Calendars.Read"]),
            "allow_test_api_url": true,
            "api_url": "http://localhost:9999",
            "required_permissions": ["Calendars.Read"]
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new("m365_default_deny", reference_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-microsoft365");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn m365_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path("/me/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                {
                    "id": "evt-1",
                    "subject": "Team Standup",
                    "start": { "dateTime": "2026-03-03T09:00:00", "timeZone": "UTC" },
                    "end": { "dateTime": "2026-03-03T09:30:00", "timeZone": "UTC" }
                }
            ]
        })))
        .mount(mock.inner())
        .await;

    let mut connector = M365ConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["m365.calendar.list_events"],
    );
    let token = build_token(
        &signing_key,
        "m365.calendar.list_events",
        &["m365.calendar.list_events"],
    );
    let invoke = invoke_request(
        "m365.calendar.list_events",
        json!({ "user_id": "me" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "m365_allow_valid_token".to_string(),
        config: json!({
            "access_token": make_jwt_token(&["Calendars.Read"]),
            "allow_test_api_url": true,
            "api_url": mock.base_url(),
            "required_permissions": ["Calendars.Read"]
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

    let mut runner = E2eRunner::new("fcp-e2e-microsoft365");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/me/events")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /me/events");
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

/// Network guard: M365 manifest restricts all operations to
/// `graph.microsoft.com` and `login.microsoftonline.com`.
#[test]
fn m365_manifest_network_guard_allows_and_denies() {
    let manifest = m365_manifest_toml();

    let operations = [
        "m365.calendar.list_events",
        "m365.calendar.create_event",
        "m365.calendar.delete_event",
        "m365.calendar.get_event",
        "m365.calendar.update_event",
        "m365.calendar.get_freebusy",
        "m365.mail.list_messages",
        "m365.mail.send_message",
        "m365.files.list_items",
        "m365.files.get_item",
        "m365.files.download_file",
        "m365.files.upload_file",
        "m365.files.delete_item",
        "m365.files.search",
        "m365.files.create_share_link",
    ];

    let expected_hosts = vec![
        "graph.microsoft.com".to_string(),
        "login.microsoftonline.com".to_string(),
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow graph.microsoft.com and login.microsoftonline.com"
        );

        // Allowed hosts
        assert!(
            host_allowed("graph.microsoft.com", &host_allow),
            "graph.microsoft.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("login.microsoftonline.com", &host_allow),
            "login.microsoftonline.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("microsoft.com", &host_allow),
            "microsoft.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.graph.microsoft.com", &host_allow),
            "evil.graph.microsoft.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("outlook.office365.com", &host_allow),
            "outlook.office365.com should be denied for {operation_name}"
        );
    }
}

// ============================================================================
// Test 4: Dangerous action gating -- risk level verification
// ============================================================================

/// Dangerous actions (file delete, share link creation) should have high risk
/// and dangerous safety tier in the manifest.
#[test]
fn m365_dangerous_operations_properly_gated() {
    let manifest = m365_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    // Dangerous operations should be high risk + dangerous/interactive
    let dangerous_ops = [
        "m365.files.delete_item",
        "m365.files.create_share_link",
        "m365.calendar.delete_event",
    ];

    for op_name in dangerous_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(risk, "high", "{op_name} should be high risk, got {risk}");
        assert_eq!(
            safety, "dangerous",
            "{op_name} should be dangerous safety tier, got {safety}"
        );
        assert_eq!(
            approval, "interactive",
            "{op_name} should require interactive approval, got {approval}"
        );
    }

    // Write operations should be medium risk + risky
    let write_ops = [
        "m365.calendar.create_event",
        "m365.calendar.update_event",
        "m365.files.upload_file",
    ];

    for op_name in write_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        assert_eq!(
            risk, "medium",
            "{op_name} should be medium risk, got {risk}"
        );
    }

    // Read operations should be low risk + safe
    let read_ops = [
        "m365.calendar.list_events",
        "m365.calendar.get_event",
        "m365.calendar.get_freebusy",
        "m365.files.list_items",
        "m365.files.get_item",
        "m365.files.search",
    ];

    for op_name in read_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        assert_eq!(risk, "low", "{op_name} should be low risk, got {risk}");
        assert_eq!(safety, "safe", "{op_name} should be safe, got {safety}");
    }
}
