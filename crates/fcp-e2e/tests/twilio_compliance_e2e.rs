//! E2E Twilio connector compliance tests (`flywheel_connectors-1zpex`).
//!
//! Exercises the Twilio connector through the E2E compliance harness:
//! - Default deny (missing capability -> error)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//! - Risk/idempotency gating verification from connector manifest metadata
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features twilio`

#![cfg(feature = "twilio")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::sync::Mutex;
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

use fcp_twilio::connector::TwilioConnector;

const TEST_ACCOUNT_SID: &str = "ACtest123456789";

// ============================================================================
// FcpConnector adapter for TwilioConnector
// ============================================================================

struct TwilioConnectorAdapter {
    connector: Mutex<TwilioConnector>,
    id: ConnectorId,
}

impl TwilioConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(TwilioConnector::new()),
            id: ConnectorId::from_static("twilio"),
        }
    }
}

fcp_core::impl_fcp_sealed!(TwilioConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for TwilioConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector
            .lock()
            .await
            .handle_configure(config)
            .await
            .map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let req_json = serde_json::to_value(&req).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize handshake request: {e}"),
        })?;
        let resp_val = self
            .connector
            .lock()
            .await
            .handle_handshake(req_json)
            .await?;
        serde_json::from_value(resp_val).map_err(|e| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {e}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(val) => {
                let status = val
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "degraded" => HealthSnapshot::degraded("not_handshaken"),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("twilio_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.lock().await.handle_self_check().await?;
        serde_json::from_value(value).map_err(|e| FcpError::Internal {
            message: format!("Failed to parse self_check result: {e}"),
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector
            .lock()
            .await
            .handle_shutdown(json!({}))
            .await
            .map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("twilio.get_account"),
                summary: "twilio.get_account".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("twilio.get_account"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: String::new(),
                    common_mistakes: Vec::new(),
                    examples: Vec::new(),
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id.clone();
        let value = self
            .connector
            .lock()
            .await
            .handle_invoke(json!({
                "operation": req.operation.as_str(),
                "input": req.input,
                "capability_token": req.capability_token,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let value = self
            .connector
            .lock()
            .await
            .handle_simulate(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
        Ok(SimulateResponse {
            r#type: "simulate_response".to_string(),
            id: req.id,
            would_succeed: value
                .get("allowed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            failure_reason: value
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .filter(|_| {
                    !value
                        .get("allowed")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                })
                .map(str::to_string),
            denial_code: None,
            missing_capabilities: Vec::new(),
            estimated_cost: None,
            availability: None,
            response_metadata: None,
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
        nonce: [13u8; 32],
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
        id: RequestId::from("twilio-e2e"),
        connector_id: ConnectorId::from_static("twilio"),
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

fn twilio_config(base_url: &str) -> serde_json::Value {
    json!({
        "account_sid": TEST_ACCOUNT_SID,
        "auth_token": "test_auth_token_xyz",
        "base_url": format!("{base_url}/2010-04-01/Accounts/{TEST_ACCOUNT_SID}"),
    })
}

fn twilio_account_response() -> serde_json::Value {
    json!({
        "sid": TEST_ACCOUNT_SID,
        "friendly_name": "FCP Test Account",
        "status": "active",
        "type": "Full",
        "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
        "date_updated": "Wed, 15 Jan 2026 10:00:00 +0000"
    })
}

fn twilio_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/twilio/manifest.toml"))
        .expect("twilio manifest toml")
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

fn operation_table(manifest: &toml::Value) -> &toml::map::Map<String, toml::Value> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table")
}

fn operation_field_str<'a>(
    operations: &'a toml::map::Map<String, toml::Value>,
    operation_name: &str,
    field: &str,
) -> &'a str {
    operations
        .get(operation_name)
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get(field))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("operation {operation_name} missing string field {field}"))
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "twilio.voice" but invoke targets "twilio.get_account".
#[fcp_async_core::runtime::test]
async fn twilio_default_deny_compliance_suite_passes() {
    let mut connector = TwilioConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["twilio.voice"]);
    let token = build_token(&signing_key, "twilio.voice", &["twilio.voice"]);
    let invoke = invoke_request("twilio.get_account", json!({}), token);

    let dynamic = DynamicSuite {
        config: twilio_config("http://localhost:9999"),
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
        "twilio_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-twilio");
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
async fn twilio_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/2010-04-01/Accounts/{TEST_ACCOUNT_SID}.json"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(twilio_account_response()))
        .mount(mock.inner())
        .await;

    let mut connector = TwilioConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["twilio.get_account"],
    );
    let token = build_token(&signing_key, "twilio.get_account", &["twilio.get_account"]);
    let invoke = invoke_request("twilio.get_account", json!({}), token);
    let suite = ConnectorSuite {
        test_name: "twilio_allow_valid_token".to_string(),
        config: twilio_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-twilio");
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
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|r| {
            r.url.path()
                == format!("/2010-04-01/Accounts/{TEST_ACCOUNT_SID}.json")
        })
        .count();
    assert_eq!(
        hits, 1,
        "expected exactly one GET to /2010-04-01/Accounts/{TEST_ACCOUNT_SID}.json"
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Twilio operations should only allow Twilio API/CDN hosts.
#[test]
fn twilio_manifest_network_guard_allows_and_denies() {
    let manifest = twilio_manifest_toml();

    // Operations restricted to api.twilio.com only.
    let api_only_ops = [
        "twilio.send_message",
        "twilio.get_message",
        "twilio.list_messages",
        "twilio.create_call",
        "twilio.get_call",
        "twilio.list_recordings",
        "twilio.get_account",
        "twilio.list_phone_numbers",
    ];
    for operation_name in api_only_ops {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec!["api.twilio.com".to_string()],
            "operation {operation_name} should allow only api.twilio.com"
        );
        assert!(
            host_allowed("api.twilio.com", &host_allow),
            "api.twilio.com should be allowed for {operation_name}"
        );
        assert!(
            !host_allowed("twilio.com", &host_allow),
            "twilio.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("media.twiliocdn.com", &host_allow),
            "media.twiliocdn.com should be denied for {operation_name}"
        );
    }

    // Media download operations allow Twilio API + Twilio CDN host.
    let media_ops = ["twilio.download_recording", "twilio.download_media"];
    for operation_name in media_ops {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec![
                "api.twilio.com".to_string(),
                "media.twiliocdn.com".to_string()
            ],
            "operation {operation_name} should allow api.twilio.com + media.twiliocdn.com"
        );
        assert!(
            host_allowed("api.twilio.com", &host_allow),
            "api.twilio.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("media.twiliocdn.com", &host_allow),
            "media.twiliocdn.com should be allowed for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
    }
}

// ============================================================================
// Test 4: Risk + idempotency gating
// ============================================================================

/// Twilio operation metadata should enforce expected risk/approval/idempotency classes.
#[test]
fn twilio_operation_risk_and_idempotency_gating() {
    let manifest = twilio_manifest_toml();
    let operations = operation_table(&manifest);
    assert_eq!(
        operations.len(),
        10,
        "twilio manifest should define exactly 10 operations"
    );

    // High-risk write operations.
    assert_eq!(
        operation_field_str(operations, "twilio.send_message", "capability"),
        "twilio.message"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.send_message", "risk_level"),
        "high"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.send_message", "safety_tier"),
        "risky"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.send_message", "requires_approval"),
        "policy"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.send_message", "idempotency"),
        "none"
    );

    assert_eq!(
        operation_field_str(operations, "twilio.create_call", "capability"),
        "twilio.voice"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.create_call", "risk_level"),
        "high"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.create_call", "safety_tier"),
        "dangerous"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.create_call", "requires_approval"),
        "interactive"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.create_call", "idempotency"),
        "none"
    );

    // Medium-risk read-with-payload operation.
    assert_eq!(
        operation_field_str(operations, "twilio.download_recording", "capability"),
        "twilio.read"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.download_recording", "risk_level"),
        "medium"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.download_recording", "safety_tier"),
        "risky"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.download_recording", "requires_approval"),
        "policy"
    );
    assert_eq!(
        operation_field_str(operations, "twilio.download_recording", "idempotency"),
        "strict"
    );

    // Low-risk safe read operations.
    let low_safe_ops = [
        "twilio.get_message",
        "twilio.list_messages",
        "twilio.get_call",
        "twilio.list_recordings",
        "twilio.download_media",
        "twilio.get_account",
        "twilio.list_phone_numbers",
    ];
    for operation_name in low_safe_ops {
        assert_eq!(
            operation_field_str(operations, operation_name, "capability"),
            "twilio.read",
            "{operation_name} should use twilio.read capability"
        );
        assert_eq!(
            operation_field_str(operations, operation_name, "risk_level"),
            "low",
            "{operation_name} should be low risk"
        );
        assert_eq!(
            operation_field_str(operations, operation_name, "safety_tier"),
            "safe",
            "{operation_name} should be safe tier"
        );
        assert_eq!(
            operation_field_str(operations, operation_name, "requires_approval"),
            "none",
            "{operation_name} should require no approval"
        );
        assert_eq!(
            operation_field_str(operations, operation_name, "idempotency"),
            "strict",
            "{operation_name} should be strict idempotency"
        );
    }
}
