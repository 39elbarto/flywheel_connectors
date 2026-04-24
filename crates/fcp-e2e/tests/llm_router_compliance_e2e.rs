//! E2E LLM Router connector compliance tests.
//!
//! Exercises the LLM Router connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features llm_router`

#![cfg(feature = "llm_router")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus,
    OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
    ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_llm_router::connector::LlmRouterConnector;
use fcp_manifest::ConnectorManifest;
use serde_json::json;
use std::sync::Arc;

// ============================================================================
// FcpConnector adapter for LlmRouterConnector
// ============================================================================

struct LlmRouterConnectorAdapter {
    connector: Arc<Mutex<LlmRouterConnector>>,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl LlmRouterConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Arc::new(Mutex::new(LlmRouterConnector::new())),
            id: ConnectorId::from_static("llm-router"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(LlmRouterConnectorAdapter);

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
        let params = serde_json::to_value(&req).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize handshake request: {e}"),
        })?;
        self.connector.lock().await.handle_handshake(params).await?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.instance_id.clone(),
        ));

        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: req
                .capabilities_requested
                .iter()
                .cloned()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
            session_id: SessionId::new(),
            manifest_hash: "sha256:llm-router-e2e".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(val) => {
                let status = val
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "ok" | "healthy" => HealthSnapshot::ready(),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("llm_router_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.lock().await.handle_self_check().await?;
        serde_json::from_value(value).map_err(|e| FcpError::Internal {
            message: format!("failed to deserialize LLM Router self_check: {e}"),
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.verifier = None;
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
                id: OperationId::from_static("llm-router.route"),
                summary: "llm-router.route".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("llm-router.route"),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::None,
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
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "LLM Router verifier not initialized; handshake required".into(),
        })?;
        let cap = required_capability(req.operation.as_str())?;
        verifier.verify(req.capability_token.clone(), &cap, &req.operation, &[])?;

        let request_id = req.id.clone();
        let params = json!({
            "operation": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.lock().await.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "LLM Router verifier not initialized; handshake required".into(),
        })?;
        let cap = required_capability(req.operation.as_str())?;
        verifier.verify(req.capability_token.clone(), &cap, &req.operation, &[])?;

        let value = self
            .connector
            .lock()
            .await
            .handle_simulate(json!({
                "operation": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;

        Ok(SimulateResponse {
            r#type: "simulate_response".to_string(),
            id: req.id,
            would_succeed: value
                .get("would_succeed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            failure_reason: None,
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

fn required_capability(operation: &str) -> fcp_core::FcpResult<CapabilityId> {
    let capability = match operation {
        "llm-router.route" | "llm-router.estimate_cost" => "llm-router.route",
        "llm-router.list_providers" | "llm-router.get_usage" | "llm-router.get_budget" => {
            "llm-router.admin"
        }
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };

    capability
        .parse::<CapabilityId>()
        .map_err(|err| FcpError::Internal {
            message: format!("invalid capability id mapping for {operation}: {err}"),
        })
}

// ============================================================================
// Helpers
// ============================================================================

fn llm_router_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/llm-router/manifest.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn llm_router_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/llm-router/manifest.toml"))
        .expect("llm-router manifest TOML")
}

fn llm_router_config() -> serde_json::Value {
    json!({
        "providers": [
            {
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
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

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [19_u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| {
                capability
                    .parse::<CapabilityId>()
                    .expect("capability id parse")
            })
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
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let token = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .constraints_cbor(&constraints_cbor)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(token)
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

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_name: &str,
) -> &'a toml::value::Table {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .expect("operation network_constraints")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    operation_network_constraints(manifest, operation_name)
        .get("host_allow")
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
        config: llm_router_config(),
        handshake,
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
        llm_router_manifest_with_hash(),
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

/// Allow: invoke with valid capability token succeeds.
/// The LLM Router routes locally (no upstream HTTP call for routing logic in
/// testing mode), so mock server is not needed for the invoke itself.
#[fcp_async_core::runtime::test]
async fn llm_router_happy_path_connector_suite_passes() {
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

    let suite = ConnectorSuite {
        test_name: "llm_router_happy_path".to_string(),
        config: llm_router_config(),
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

    let mut runner = E2eRunner::new("fcp-e2e-llm-router-happy");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "happy path should pass: {report:#?}");
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
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    assert_eq!(
        operations.len(),
        5,
        "LLM Router manifest should declare 5 operations"
    );

    let expected_hosts = vec![
        "api.anthropic.com".to_string(),
        "api.openai.com".to_string(),
        "generativelanguage.googleapis.com".to_string(),
    ];

    // Only route and list_providers have explicit network_constraints in the manifest.
    // The other operations (estimate_cost, get_usage, get_budget) are local/computed
    // and don't have network_constraints sections.
    let ops_with_constraints = ["llm-router.route", "llm-router.list_providers"];
    for operation_name in &ops_with_constraints {
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

        let constraints = operation_network_constraints(&manifest, operation_name);
        assert_eq!(
            constraints
                .get("deny_localhost")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny localhost"
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny private ranges"
        );
        assert_eq!(
            constraints
                .get("require_sni")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must require SNI"
        );
    }
}
