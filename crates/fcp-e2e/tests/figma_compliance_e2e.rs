//! E2E Figma connector compliance tests.
//!
//! Exercises the Figma connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//! - Dangerous operation gating (webhook deletion without capability)
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features figma`

#![cfg(feature = "figma")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_core::{
    AgentHint, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus,
    OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
    ZoneId,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_figma::connector::FigmaConnector;
use fcp_manifest::ConnectorManifest;
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

// ============================================================================
// FcpConnector adapter for FigmaConnector
// ============================================================================

struct FigmaConnectorAdapter {
    connector: FigmaConnector,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl FigmaConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: FigmaConnector::new(),
            id: ConnectorId::from_static("figma"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

#[fcp_core::async_trait]
impl FcpConnector for FigmaConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let req_json = serde_json::to_value(&req).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize handshake request: {e}"),
        })?;
        let resp_val = self.connector.handle_handshake(req_json).await?;
        self.verifier = Some(CapabilityVerifier::new(req.host_public_key, req.zone.clone(), self.instance_id.clone()));
        serde_json::from_value(resp_val).map_err(|e| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {e}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(val) => {
                let status = val
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "degraded" => HealthSnapshot::degraded("not_handshaken"),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("figma_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.handle_self_check().await?;
        serde_json::from_value(value).map_err(|e| FcpError::Internal {
            message: format!("Failed to parse self_check result: {e}"),
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.verifier = None;
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("figma.get_file"),
                summary: "figma.get_file".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("figma.get_file"),
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
        let value = self.connector.handle_invoke(json!({
            "operation": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        })).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let value = self.connector.handle_simulate(json!({
            "operation_id": req.operation.as_str(),
            "input": req.input,
        })).await?;
        Ok(SimulateResponse {
            r#type: "simulate_response".to_string(), id: req.id,
            would_succeed: value.get("allowed").and_then(serde_json::Value::as_bool).unwrap_or(false),
            failure_reason: value.get("reason").and_then(serde_json::Value::as_str)
                .filter(|_| !value.get("allowed").and_then(serde_json::Value::as_bool).unwrap_or(false))
                .map(str::to_string),
            denial_code: None, missing_capabilities: Vec::new(), estimated_cost: None,
            availability: None, response_metadata: None,
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

fn figma_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/figma/manifest.toml");
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
        nonce: [11u8; 32],
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
        id: RequestId::from("figma-e2e"),
        connector_id: ConnectorId::from_static("figma"),
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

fn figma_config(base_url: &str) -> serde_json::Value {
    json!({
        "token": "figma-test-token-xyz",
        "base_url": base_url
    })
}

fn figma_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/figma/manifest.toml"))
        .expect("figma manifest toml")
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
    host_allow.iter().any(|pattern| {
        pattern == host
            || pattern
                .strip_prefix("*.")
                .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
    })
}

fn figma_file_response() -> serde_json::Value {
    json!({
        "name": "Test Design File",
        "document": {
            "id": "0:0",
            "name": "Document",
            "type": "DOCUMENT",
            "children": []
        },
        "schemaVersion": 0,
        "lastModified": "2026-01-15T12:00:00Z",
        "thumbnailUrl": "https://figma-alpha.s3.amazonaws.com/thumbnails/test.png",
        "version": "1234567890",
        "role": "owner"
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

#[fcp_async_core::runtime::test]
async fn figma_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = FigmaConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["figma.get_file"]);
    // Token grants get_file but invoke targets delete_comment → should be denied
    let token = build_token(&signing_key, "figma.get_file", &["figma.get_file"]);
    let invoke = invoke_request(
        "figma.delete_comment",
        json!({
            "file_key": "abc123",
            "comment_id": "c1"
        }),
        token,
    );

    let dynamic = DynamicSuite {
        config: figma_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new("figma_default_deny", figma_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-figma");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass: {report:#?}");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

#[fcp_async_core::runtime::test]
async fn figma_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(figma_file_response()))
        .mount(mock.inner())
        .await;

    let mut connector = FigmaConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["figma.get_file"]);
    let token = build_token(&signing_key, "figma.get_file", &["figma.get_file"]);
    let invoke = invoke_request("figma.get_file", json!({ "file_key": "abc123" }), token);
    let suite = ConnectorSuite {
        test_name: "figma_allow_valid_token".to_string(),
        config: figma_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-figma");
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
// Test 3: Network guard -- manifest host allow/deny checks
// ============================================================================

#[test]
fn figma_manifest_network_guard_allows_and_denies() {
    let manifest = figma_manifest_toml();

    // Most operations only allow api.figma.com
    let standard_operations = [
        "figma.get_file",
        "figma.get_file_nodes",
        "figma.get_file_components",
        "figma.get_file_styles",
        "figma.list_file_versions",
        "figma.list_comments",
        "figma.post_comment",
        "figma.delete_comment",
        "figma.list_webhooks",
        "figma.create_webhook",
        "figma.delete_webhook",
    ];

    let expected_hosts = vec!["api.figma.com".to_string()];

    for operation_name in standard_operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should use api.figma.com host allowlist"
        );

        assert!(host_allowed("api.figma.com", &host_allow));
        assert!(!host_allowed("localhost", &host_allow));
        assert!(!host_allowed("example.com", &host_allow));
        assert!(!host_allowed("evil.figma.com", &host_allow));

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
    }

    // export_images also allows S3 hosts for image download
    let export_hosts = operation_host_allow_list(&manifest, "figma.export_images");
    assert!(export_hosts.contains(&"api.figma.com".to_string()));
    assert!(
        export_hosts.len() > 1,
        "export_images should allow additional S3 hosts"
    );
    assert!(!host_allowed("localhost", &export_hosts));
    assert!(!host_allowed("example.com", &export_hosts));
}

// ============================================================================
// Test 4: Dangerous operation gating (delete webhook without capability)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn figma_dangerous_delete_webhook_requires_delete_capability() {
    let mock = MockApiServer::start().await;
    let mut adapter = FigmaConnectorAdapter::new();
    adapter
        .configure(figma_config(&mock.base_url()))
        .await
        .expect("configure");

    let signing_key = Ed25519SigningKey::generate();
    adapter
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["figma.get_file"],
        ))
        .await
        .expect("handshake");

    // Token grants get_file but invoke targets delete_webhook
    let token = build_token(&signing_key, "figma.get_file", &["figma.get_file"]);
    let req = invoke_request(
        "figma.delete_webhook",
        json!({ "webhook_id": "wh-123" }),
        token,
    );
    let result = adapter.invoke(req).await;
    assert!(result.is_err(), "delete_webhook should fail without correct capability");
}

#[fcp_async_core::runtime::test]
async fn figma_dangerous_delete_webhook_allows_with_correct_capability() {
    let mock = MockApiServer::start().await;
    // Webhook v2 paths resolve via ../v2/ → /v2/webhooks/{id}
    Mock::given(method("DELETE"))
        .and(path("/v2/webhooks/wh-123"))
        .respond_with(ResponseTemplate::new(200))
        .mount(mock.inner())
        .await;

    let mut adapter = FigmaConnectorAdapter::new();
    adapter
        .configure(figma_config(&mock.base_url()))
        .await
        .expect("configure");

    let signing_key = Ed25519SigningKey::generate();
    adapter
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["figma.delete_webhook"],
        ))
        .await
        .expect("handshake");

    let token = build_token(
        &signing_key,
        "figma.delete_webhook",
        &["figma.delete_webhook"],
    );
    let req = invoke_request(
        "figma.delete_webhook",
        json!({ "webhook_id": "wh-123" }),
        token,
    );
    let response = adapter.invoke(req).await.expect("delete_webhook invoke");
    assert_eq!(response.status, InvokeStatus::Ok);
}

// ============================================================================
// Test 6: Risk level and safety tier gating across all operations
// ============================================================================

#[test]
fn figma_operation_risk_levels_properly_gated() {
    let manifest = figma_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    // Delete and webhook-create operations should be medium risk + risky + policy
    let risky_ops = [
        "figma.delete_comment",
        "figma.delete_webhook",
        "figma.create_webhook",
    ];
    for op_name in risky_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(
            risk, "medium",
            "{op_name} should be medium risk, got {risk}"
        );
        assert_eq!(safety, "risky", "{op_name} should be risky, got {safety}");
        assert_eq!(
            approval, "policy",
            "{op_name} should require policy approval, got {approval}"
        );
    }

    // Read operations should be low risk + safe + no approval
    let safe_ops = [
        "figma.list_team_projects",
        "figma.list_project_files",
        "figma.get_file_meta",
        "figma.get_file",
        "figma.get_file_nodes",
        "figma.get_file_components",
        "figma.get_file_styles",
        "figma.styles.list",
        "figma.tokens.export",
        "figma.export_images",
        "figma.list_file_versions",
        "figma.list_comments",
        "figma.list_webhooks",
    ];
    for op_name in safe_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(risk, "low", "{op_name} should be low risk, got {risk}");
        assert_eq!(safety, "safe", "{op_name} should be safe, got {safety}");
        assert_eq!(
            approval, "none",
            "{op_name} should need no approval, got {approval}"
        );
    }

    // post_comment: write but low risk + safe (non-destructive)
    let post_comment = operations.get("figma.post_comment").expect("post_comment");
    assert_eq!(
        post_comment
            .get("risk_level")
            .and_then(toml::Value::as_str)
            .unwrap(),
        "low"
    );
    assert_eq!(
        post_comment
            .get("safety_tier")
            .and_then(toml::Value::as_str)
            .unwrap(),
        "safe"
    );

    // Total operation count
    assert_eq!(
        operations.len(),
        17,
        "Figma manifest should have 17 operations"
    );
}
