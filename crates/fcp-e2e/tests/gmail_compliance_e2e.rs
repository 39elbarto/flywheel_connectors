//! E2E Gmail connector compliance tests (flywheel_connectors-ofw.6).
//!
//! Exercises the Gmail connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features gmail`

#![cfg(feature = "gmail")]
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

use fcp_gmail::connector::GmailConnector;

// ============================================================================
// FcpConnector adapter for GmailConnector
// ============================================================================

struct GmailConnectorAdapter {
    connector: GmailConnector,
    id: ConnectorId,
}

impl GmailConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: GmailConnector::new(),
            id: ConnectorId::from_static("gmail"),
        }
    }
}

#[fcp_core::async_trait]
impl FcpConnector for GmailConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("gmail_status:{other}")),
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
                id: OperationId::from_static("gmail.get_message"),
                summary: "Get a single email message by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["message_id"],
                    "properties": {
                        "message_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("gmail.messages.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve full details of a specific email message.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"message_id": "18d1234abc567890"}"#.to_string()],
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
    CapabilityToken { raw: cose }
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("gmail-e2e"),
        connector_id: ConnectorId::from_static("gmail"),
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

fn gmail_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/gmail/manifest.toml"))
        .expect("gmail manifest toml")
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

/// Gmail `get_message` success response.
fn gmail_get_message_success_response() -> serde_json::Value {
    json!({
        "id": "18d1234abc567890",
        "threadId": "18d1234abc567890",
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": "Hello, this is a test email from the E2E suite.",
        "historyId": "12345",
        "internalDate": "1709308800000",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                { "name": "From", "value": "sender@example.com" },
                { "name": "To", "value": "recipient@example.com" },
                { "name": "Subject", "value": "E2E Test" },
                { "name": "Date", "value": "Sat, 01 Mar 2026 12:00:00 +0000" }
            ],
            "body": {
                "size": 42,
                "data": "SGVsbG8sIHRoaXMgaXMgYSB0ZXN0IGVtYWlsLg=="
            }
        },
        "sizeEstimate": 1024
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "gmail.messages.send" but invoke targets "gmail.get_message"
/// (which requires "gmail.messages.read").
#[fcp_async_core::runtime::test]
async fn gmail_default_deny_compliance_suite_passes() {
    let mut connector = GmailConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["gmail.messages.send"],
    );
    // Token grants "gmail.messages.send" but invoke targets "gmail.get_message" → denial
    let token = build_token(
        &signing_key,
        "gmail.messages.send",
        &["gmail.messages.send"],
    );
    let invoke = invoke_request(
        "gmail.get_message",
        json!({ "message_id": "18d1234abc567890" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "token": "ya29.test-oauth-token",
            "base_url": "http://localhost:9999"
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
    let suite = ComplianceSuite::new(
        "gmail_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-gmail");
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
async fn gmail_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for the messages/{id} endpoint (GET)
    Mock::given(method("GET"))
        .and(path("/users/me/messages/18d1234abc567890"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(gmail_get_message_success_response()),
        )
        .mount(mock.inner())
        .await;

    let mut connector = GmailConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["gmail.get_message"],
    );
    let token = build_token(&signing_key, "gmail.get_message", &["gmail.get_message"]);
    let invoke = invoke_request(
        "gmail.get_message",
        json!({ "message_id": "18d1234abc567890" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "gmail_allow_valid_token".to_string(),
        config: json!({
            "token": "ya29.test-oauth-token-e2e",
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

    let mut runner = E2eRunner::new("fcp-e2e-gmail");
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

/// Network guard: Gmail manifest restricts all operations to
/// `gmail.googleapis.com` and `www.googleapis.com`.
/// Verify that allowed hosts pass and non-matching hosts are denied.
#[test]
fn gmail_manifest_network_guard_allows_and_denies() {
    let manifest = gmail_manifest_toml();

    let operations = [
        "gmail.send_message",
        "gmail.get_message",
        "gmail.list_messages",
        "gmail.search_messages",
        "gmail.create_draft",
        "gmail.modify_labels",
        "gmail.list_labels",
        "gmail.trash_message",
    ];

    let expected_hosts = vec![
        "gmail.googleapis.com".to_string(),
        "www.googleapis.com".to_string(),
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow gmail.googleapis.com and www.googleapis.com"
        );

        // Allowed hosts
        assert!(
            host_allowed("gmail.googleapis.com", &host_allow),
            "gmail.googleapis.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("www.googleapis.com", &host_allow),
            "www.googleapis.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("googleapis.com", &host_allow),
            "googleapis.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.gmail.googleapis.com", &host_allow),
            "evil.gmail.googleapis.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("mail.google.com", &host_allow),
            "mail.google.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("accounts.google.com", &host_allow),
            "accounts.google.com should be denied for {operation_name}"
        );
    }
}
