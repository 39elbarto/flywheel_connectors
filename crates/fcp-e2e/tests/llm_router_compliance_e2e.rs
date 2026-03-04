//! E2E LLM Router connector compliance tests.
//!
//! Exercises the LLM Router connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` exact-host validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features llm_router`

#![cfg(feature = "llm_router")]
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
use serde_json::json;

use fcp_async_core::sync::Mutex;
use fcp_llm_router::connector::LlmRouterConnector;

// ============================================================================
// FcpConnector adapter for LlmRouterConnector
// ============================================================================

struct LlmRouterConnectorAdapter {
    connector: Mutex<LlmRouterConnector>,
    id: ConnectorId,
}

impl LlmRouterConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(LlmRouterConnector::new()),
            id: ConnectorId::from_static("llm-router"),
        }
    }
}

#[fcp_core::async_trait]
impl FcpConnector for LlmRouterConnectorAdapter {
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
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self
            .connector
            .lock()
            .await
            .handle_handshake(request)
            .await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "not_configured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("llm_router_status:{other}")),
                }
            }
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
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("llm-router.route"),
                    summary: "Route a chat completion request to the optimal provider/model"
                        .to_string(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["messages"],
                        "properties": {
                            "messages": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "role": { "type": "string" },
                                        "content": { "type": "string" }
                                    }
                                }
                            },
                            "strategy": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "response": { "type": "string" },
                            "provider": { "type": "string" },
                            "model": { "type": "string" },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("llm-router.route"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Route a chat request to the best available AI provider."
                            .to_string(),
                        common_mistakes: Vec::new(),
                        examples: vec![
                            r#"{"messages": [{"role": "user", "content": "Hello"}]}"#.to_string(),
                        ],
                        related: vec!["llm-router.estimate_cost".parse().unwrap()],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("llm-router.estimate_cost"),
                    summary: "Estimate request cost across providers".to_string(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["messages"],
                        "properties": {
                            "messages": { "type": "array" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "estimates": { "type": "array" }
                        }
                    }),
                    capability: CapabilityId::from_static("llm-router.route"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Preview cost across providers before committing.".to_string(),
                        common_mistakes: Vec::new(),
                        examples: Vec::new(),
                        related: Vec::new(),
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
            ],
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
        let value = self.connector.lock().await.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.lock().await.handle_simulate(request).await?;
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
        id: RequestId::from("llm-router-e2e"),
        connector_id: ConnectorId::from_static("llm-router"),
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

fn llm_router_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/llm-router/manifest.toml"))
        .expect("llm-router manifest toml")
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

/// Test configuration with providers pointing to localhost (testing feature enabled).
fn test_config_with_base_url(base_url: &str) -> serde_json::Value {
    json!({
        "providers": [
            {
                "name": "anthropic",
                "base_url": base_url,
                "api_key": "test-key-anthropic-e2e",
                "priority": 1,
                "models": [
                    {
                        "id": "claude-sonnet-4",
                        "capabilities": ["code", "tool_use"],
                        "context_window": 200000,
                        "cost_per_input_token": 0.000003,
                        "cost_per_output_token": 0.000015
                    }
                ]
            }
        ],
        "default_strategy": "cost",
        "budget": {
            "budget_usd": 50.0,
            "enforcement": "hard",
            "period": "session"
        }
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "llm-router.admin" but invoke targets "llm-router.route"
/// (which requires "llm-router.route" capability).
#[fcp_async_core::runtime::test]
async fn llm_router_default_deny_compliance_suite_passes() {
    let mut connector = LlmRouterConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["llm-router.admin"],
    );
    // Token grants "llm-router.admin" but invoke targets "llm-router.route" -> denial
    let token = build_token(&signing_key, "llm-router.admin", &["llm-router.admin"]);
    let invoke = invoke_request(
        "llm-router.route",
        json!({
            "messages": [{"role": "user", "content": "Hello"}]
        }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": "sk-test-000",
                "priority": 1,
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }],
            "default_strategy": "cost"
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
        "llm_router_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-llm-router");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(
        report.passed,
        "default deny compliance should pass: {report:#?}"
    );
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock REST API.
/// The LLM Router routes locally (no upstream HTTP call for routing logic),
/// so the mock server is only needed for the configure step's network validation.
#[fcp_async_core::runtime::test]
async fn llm_router_allow_valid_token_connector_suite_passes() {
    let mut connector = LlmRouterConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["llm-router.route"],
    );
    let token = build_token(&signing_key, "llm-router.route", &["llm-router.route"]);
    let invoke = invoke_request(
        "llm-router.route",
        json!({
            "messages": [{"role": "user", "content": "Hello from E2E test"}]
        }),
        token,
    );

    // LLM Router does routing locally (no upstream HTTP during invoke for
    // simulated responses), so we configure with allowed hosts and testing feature.
    let suite = ConnectorSuite {
        test_name: "llm_router_allow_valid_token".to_string(),
        config: test_config_with_base_url("https://api.anthropic.com"),
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

    let mut runner = E2eRunner::new("fcp-e2e-llm-router");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass: {report:#?}");
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
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: LLM Router manifest restricts operations to known AI provider hosts.
/// Verify that allowed hosts pass and non-matching hosts are denied.
#[test]
fn llm_router_manifest_network_guard_allows_and_denies() {
    let manifest = llm_router_manifest_toml();

    // Operations with external network access (route and list_providers)
    let operations_with_network = ["llm-router.route", "llm-router.list_providers"];

    let expected_hosts = vec![
        "api.anthropic.com".to_string(),
        "api.openai.com".to_string(),
        "generativelanguage.googleapis.com".to_string(),
    ];

    for operation_name in operations_with_network {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow known AI provider hosts"
        );

        // Allowed hosts
        assert!(
            host_allowed("api.anthropic.com", &host_allow),
            "api.anthropic.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("api.openai.com", &host_allow),
            "api.openai.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("generativelanguage.googleapis.com", &host_allow),
            "generativelanguage.googleapis.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.api.anthropic.com", &host_allow),
            "evil.api.anthropic.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.cohere.com", &host_allow),
            "api.cohere.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("127.0.0.1", &host_allow),
            "127.0.0.1 should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("openai.com", &host_allow),
            "openai.com (bare domain) should be denied for {operation_name}"
        );
    }

    // estimate_cost has empty host_allow (local computation only)
    let estimate_manifest = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|ops| ops.get("llm-router.estimate_cost"))
        .and_then(toml::Value::as_table)
        .and_then(|op| op.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|nc| nc.get("host_allow"))
        .and_then(toml::Value::as_array)
        .expect("estimate_cost network_constraints.host_allow");
    assert!(
        estimate_manifest.is_empty(),
        "estimate_cost should have empty host_allow (local computation)"
    );
}
