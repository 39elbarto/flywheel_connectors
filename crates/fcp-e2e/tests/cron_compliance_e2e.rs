//! E2E cron connector compliance tests (flywheel_connectors-lszk.27.4).
//!
//! Exercises the cron connector through the E2E compliance harness:
//! - Default deny path (unsupported invoke is denied)
//! - Allow path for schedule creation
//! - Execution envelope correctness for trigger/list flows
//! - Structured JSON evidence logging validation
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features cron`

#![cfg(feature = "cron")]
#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
    FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{
    ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations, validate_log_entry_value,
};
use fcp_manifest::ConnectorManifest;
use serde_json::json;

use fcp_async_core::sync::Mutex;
use fcp_cron::connector::CronConnector;

// ============================================================================
// FcpConnector adapter for CronConnector
// ============================================================================

struct CronConnectorAdapter {
    connector: Mutex<CronConnector>,
    id: ConnectorId,
}

impl CronConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(CronConnector::new()),
            id: ConnectorId::from_static("cron"),
        }
    }
}

fcp_core::impl_fcp_sealed!(CronConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for CronConnectorAdapter {
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
        let request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self
            .connector
            .lock()
            .await
            .handle_handshake(request)
            .await
            .map_err(|err| FcpError::Internal {
                message: format!("failed to process handshake request: {err}"),
            })?;

        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to decode cron handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(payload) => serde_json::from_value(payload).unwrap_or_else(|err| {
                HealthSnapshot::error(format!("failed to decode cron health snapshot: {err}"))
            }),
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
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
                id: OperationId::from_static("cron.schedules.list"),
                summary: "List configured cron schedules".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": [],
                    "properties": {}
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["schedules"],
                    "properties": {
                        "schedules": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("cron.schedules.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Inspect currently configured cron schedules.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec!["{}".to_string()],
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
        let payload = self
            .connector
            .lock()
            .await
            .handle_invoke(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
                "capability_token": req.capability_token,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, payload))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let payload = self
            .connector
            .lock()
            .await
            .handle_simulate(json!({
                "operation_id": req.operation.as_str(),
            }))
            .await?;

        if payload
            .get("allowed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            let reason = payload
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Operation not supported");
            Ok(SimulateResponse::denied(req.id, reason, "FCP-3003"))
        }
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

fn cron_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/cron/manifest.toml");
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
        nonce: [19u8; 32],
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
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize test constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .constraints_cbor(&constraints_cbor)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    request_id: &'static str,
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from(request_id),
        connector_id: ConnectorId::from_static("cron"),
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

fn cron_config() -> serde_json::Value {
    json!({
        "state_store": {
            "backend": "memory",
            "max_schedules": 128,
            "max_executions": 1024,
            "persist_to_disk": false
        },
        "clock": {
            "source": "system_utc",
            "timezone": "UTC",
            "max_clock_skew_seconds": 30
        }
    })
}

fn cron_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/cron/manifest.toml"))
        .expect("cron manifest toml")
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
    fcp_sandbox::host_matches_allow_list(host, host_allow)
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

#[fcp_async_core::runtime::test]
async fn cron_default_deny_compliance_suite_passes() {
    let mut connector = CronConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["cron.read"]);
    let token = build_token(&signing_key, "cron.read", &["cron.schedules.list"]);
    let invoke = invoke_request("cron-default-deny", "cron.unsupported", json!({}), token);

    let dynamic = DynamicSuite {
        config: cron_config(),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new("cron_default_deny", cron_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-cron");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid invoke -- connector suite
// ============================================================================

#[fcp_async_core::runtime::test]
async fn cron_allow_create_schedule_connector_suite_passes() {
    let mut connector = CronConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["cron.schedules.write"],
    );
    let token = build_token(
        &signing_key,
        "cron.schedules.write",
        &["cron.schedules.create"],
    );
    let invoke = invoke_request(
        "cron-allow-create",
        "cron.schedules.create",
        json!({
            "name": "hourly-sync",
            "expression": "0 * * * *",
            "target_operation": "slack.channels.list"
        }),
        token,
    );

    let suite = ConnectorSuite {
        test_name: "cron_allow_create_schedule".to_string(),
        config: cron_config(),
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

    let mut runner = E2eRunner::new("fcp-e2e-cron");
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
// Test 3: Execution envelope correctness
// ============================================================================

#[fcp_async_core::runtime::test]
async fn cron_execution_envelope_correctness() {
    let mut connector = CronConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    connector.configure(cron_config()).await.expect("configure");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["cron.schedules.write", "cron.executions.read"],
        ))
        .await
        .expect("handshake");

    let create_token = build_token(
        &signing_key,
        "cron.schedules.write",
        &["cron.schedules.create", "cron.trigger"],
    );
    let create_response = connector
        .invoke(invoke_request(
            "cron-envelope-create",
            "cron.schedules.create",
            json!({
                "name": "envelope-check",
                "expression": "*/5 * * * *",
                "target_operation": "slack.channels.list"
            }),
            create_token.clone(),
        ))
        .await
        .expect("create schedule");
    let schedule_id = create_response
        .result
        .as_ref()
        .and_then(|value| value.get("schedule_id"))
        .and_then(serde_json::Value::as_str)
        .expect("schedule_id string")
        .to_string();

    connector
        .invoke(invoke_request(
            "cron-envelope-trigger",
            "cron.trigger",
            json!({ "schedule_id": schedule_id }),
            create_token,
        ))
        .await
        .expect("trigger schedule");

    let list_token = build_token(
        &signing_key,
        "cron.executions.read",
        &["cron.executions.list"],
    );
    let list_response = connector
        .invoke(invoke_request(
            "cron-envelope-list",
            "cron.executions.list",
            json!({ "schedule_id": schedule_id, "limit": 10 }),
            list_token,
        ))
        .await
        .expect("list executions");

    let executions = list_response
        .result
        .as_ref()
        .and_then(|value| value.get("executions"))
        .and_then(serde_json::Value::as_array)
        .expect("executions array");
    assert!(!executions.is_empty(), "expected at least one execution");
    let envelope = &executions[0];

    let execution_id = envelope["id"].as_str().expect("execution id");
    assert!(
        execution_id.starts_with("exec_"),
        "execution id should use exec_ prefix"
    );
    assert_eq!(
        envelope["schedule_id"].as_str(),
        Some(schedule_id.as_str()),
        "execution should be linked to the triggering schedule"
    );
    assert_eq!(
        envelope["status"].as_str(),
        Some("triggered"),
        "execution status should be triggered"
    );
    let triggered_at = envelope["triggered_at"].as_str().expect("triggered_at");
    DateTime::parse_from_rfc3339(triggered_at).expect("triggered_at should be RFC3339 timestamp");
}

// ============================================================================
// Test 4: Structured evidence logging behavior
// ============================================================================

#[fcp_async_core::runtime::test]
async fn cron_evidence_logs_validate_against_schema() {
    let mut connector = CronConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["cron.schedules.write"],
    );
    let token = build_token(
        &signing_key,
        "cron.schedules.write",
        &["cron.schedules.create"],
    );
    let invoke = invoke_request(
        "cron-evidence-create",
        "cron.schedules.create",
        json!({
            "name": "evidence-check",
            "expression": "0 * * * *",
            "target_operation": "slack.channels.list"
        }),
        token,
    );

    let suite = ConnectorSuite {
        test_name: "cron_evidence_logging".to_string(),
        config: cron_config(),
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

    let mut runner = E2eRunner::new("fcp-e2e-cron");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");
    assert!(report.passed, "evidence suite should pass");

    let jsonl = report.to_json_lines();
    assert!(
        !jsonl.trim().is_empty(),
        "report should emit JSONL evidence"
    );
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("jsonl line should parse");
        validate_log_entry_value(&value).expect("jsonl line should satisfy E2E schema");
    }
}

// ============================================================================
// Test 5: Network guard constraints
// ============================================================================

#[test]
fn cron_manifest_network_guard_allows_only_localhost_localdomain() {
    let manifest = cron_manifest_toml();
    let operations = [
        "cron.schedules.list",
        "cron.schedules.create",
        "cron.schedules.delete",
        "cron.trigger",
        "cron.executions.list",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert!(
            host_allowed("localhost.localdomain", &host_allow),
            "localhost.localdomain should be allowed for {operation_name}"
        );
        assert!(
            !host_allowed("localhost", &host_allow),
            "localhost should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.slack.com", &host_allow),
            "api.slack.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
    }
}
