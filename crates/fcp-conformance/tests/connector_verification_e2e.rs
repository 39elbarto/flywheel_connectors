//! E2E connector verification framework tests (flywheel_connectors-e3i9).
//!
//! Exercises the full connector verification pipeline:
//! - Static compliance (manifest validation)
//! - Dynamic compliance (standard method surface)
//! - Interop suite (protocol, capability, cross-zone)
//! - Capability enforcement (default deny, revocation)
//! - Lifecycle (cold start, health, shutdown, crash recovery)
//! - Security boundaries (cross-zone denial)
//!
//! All tests use in-process mock connectors. No real network calls.

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;

use fcp_conformance::{
    CheckStatus, ComplianceReport, DynamicSuite, StaticCompliance, run_dynamic_checks,
};
use fcp_core::{
    AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
    FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, HealthState,
    IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId,
    OperationInfo, RequestId, ResourceTypeInfo, RiskLevel, SafetyTier, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, SubscribeResult,
    UnsubscribeRequest, ZoneId,
};
use serde_json::json;

// ============================================================================
// Mock Connector Variants
// ============================================================================

/// Standard healthy connector that passes all compliance checks.
struct HealthyConnector;

fcp_core::impl_fcp_sealed!(HealthyConnector);

#[async_trait::async_trait]
impl FcpConnector for HealthyConnector {
    fn id(&self) -> &ConnectorId {
        static ID: std::sync::LazyLock<ConnectorId> =
            std::sync::LazyLock::new(|| ConnectorId::from_static("test.e2e:utility:1.0.0"));
        &ID
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: vec![],
            session_id: SessionId::new(),
            manifest_hash: "sha256:e2e_test".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot {
            status: HealthState::Ready,
            uptime_ms: 5000,
            load: Some(0.2),
            details: Some(json!({"version": "1.0.0", "connections": 3})),
            rate_limit: None,
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: 42,
            requests_success: 40,
            requests_error: 2,
            connections_active: 3,
            events_emitted: 0,
            latency_p50_ms: 15,
            latency_p99_ms: 120,
            bytes_sent: 4096,
            bytes_received: 1024,
        }
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("list_items"),
                    summary: "List items from the service".into(),
                    description: None,
                    input_schema: json!({"type": "object"}),
                    output_schema: json!({"type": "array"}),
                    capability: CapabilityId::from_static("cap.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "When user wants to list items".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("create_item"),
                    summary: "Create a new item".into(),
                    description: None,
                    input_schema: json!({"type": "object", "required": ["name"]}),
                    output_schema: json!({"type": "object"}),
                    capability: CapabilityId::from_static("cap.write"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "When user wants to create an item".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
            ],
            events: vec![],
            resource_types: vec![ResourceTypeInfo {
                name: "item".into(),
                uri_pattern: "fcp://test.e2e/item/{id}".into(),
                schema: json!({"type": "object"}),
            }],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({"items": [], "count": 0})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".into(),
            id: RequestId("sub_e2e".into()),
            result: SubscribeResult {
                confirmed_topics: vec![],
                cursors: HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

/// Connector that enforces default deny on capability-gated operations.
struct DenyingConnector;
fcp_core::impl_fcp_sealed!(DenyingConnector);


#[async_trait::async_trait]
impl FcpConnector for DenyingConnector {
    fn id(&self) -> &ConnectorId {
        static ID: std::sync::LazyLock<ConnectorId> =
            std::sync::LazyLock::new(|| ConnectorId::from_static("test.e2e:denying:1.0.0"));
        &ID
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: vec![],
            session_id: SessionId::new(),
            manifest_hash: "sha256:deny_test".into(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot {
            status: HealthState::Ready,
            uptime_ms: 1000,
            load: None,
            details: None,
            rate_limit: None,
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("protected_op"),
                summary: "An operation requiring capability".into(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("cap.dangerous"),
                risk_level: RiskLevel::High,
                safety_tier: SafetyTier::Dangerous,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            }],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        // Default deny: missing capability → denial with decision receipt
        Ok(InvokeResponse {
            r#type: "response".into(),
            id: req.id,
            status: InvokeStatus::Error,
            result: None,
            error: Some(FcpError::CapabilityDenied {
                capability: "cap.dangerous".into(),
                reason: "no capability token provided".into(),
            }),
            receipt_id: None,
            audit_event_id: None,
            decision_receipt_id: Some(fcp_core::ObjectId::from_unscoped_bytes(b"dr_deny_001")),
            resource_uris: Vec::new(),
            next_cursor: None,
            usage_metrics: None,
            response_metadata: None,
        })
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::denied(
            req.id,
            "capability required for protected_op",
            "FCP-3001",
        ))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::CapabilityDenied {
            capability: "cap.subscribe".into(),
            reason: "subscription requires capability".into(),
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

/// Which lifecycle phase should fail in the unstable connector.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnstablePhase {
    Configure,
    Handshake,
    HealthDegraded,
    Shutdown,
}

/// Connector that fails during lifecycle operations.
struct UnstableConnector {
    fail_phase: UnstablePhase,
}

impl UnstableConnector {
    const fn configure_failure() -> Self {
        Self {
            fail_phase: UnstablePhase::Configure,
        }
    }

    const fn handshake_failure() -> Self {
        Self {
            fail_phase: UnstablePhase::Handshake,
        }
    }

    const fn degraded() -> Self {
        Self {
            fail_phase: UnstablePhase::HealthDegraded,
        }
    }

    const fn shutdown_failure() -> Self {
        Self {
            fail_phase: UnstablePhase::Shutdown,
        }
    }
}

fcp_core::impl_fcp_sealed!(UnstableConnector);

#[async_trait::async_trait]
impl FcpConnector for UnstableConnector {
    fn id(&self) -> &ConnectorId {
        static ID: std::sync::LazyLock<ConnectorId> =
            std::sync::LazyLock::new(|| ConnectorId::from_static("test.e2e:unstable:1.0.0"));
        &ID
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        if self.fail_phase == UnstablePhase::Configure {
            Err(FcpError::NotConfigured)
        } else {
            Ok(())
        }
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if self.fail_phase == UnstablePhase::Handshake {
            Err(FcpError::ConnectorUnavailable {
                code: 5001,
                message: "handshake rejected by remote".into(),
            })
        } else {
            Ok(HandshakeResponse {
                status: "accepted".into(),
                capabilities_granted: vec![],
                session_id: SessionId::new(),
                manifest_hash: "sha256:unstable".into(),
                nonce: req.nonce,
                event_caps: None,
                auth_caps: None,
                op_catalog_hash: None,
            })
        }
    }

    async fn health(&self) -> HealthSnapshot {
        if self.fail_phase == UnstablePhase::HealthDegraded {
            HealthSnapshot {
                status: HealthState::Degraded {
                    reason: "high latency to upstream".into(),
                },
                uptime_ms: 500,
                load: Some(0.9),
                details: Some(json!({"p99_ms": 2500, "error_rate": 0.15})),
                rate_limit: None,
            }
        } else {
            HealthSnapshot {
                status: HealthState::Ready,
                uptime_ms: 1000,
                load: None,
                details: None,
                rate_limit: None,
            }
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if self.fail_phase == UnstablePhase::Shutdown {
            Err(FcpError::Internal {
                message: "shutdown timeout".into(),
            })
        } else {
            Ok(())
        }
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({"ok": true})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".into(),
            id: RequestId("sub_unstable".into()),
            result: SubscribeResult {
                confirmed_topics: vec![],
                cursors: HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

fn make_handshake() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".into(),
        zone: "z:test".parse().unwrap(),
        zone_dir: None,
        host_public_key: [0u8; 32],
        nonce: [0u8; 32],
        capabilities_requested: vec![],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn make_invoke(operation: &str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId(format!("req_{operation}")),
        connector_id: ConnectorId::from_static("test.e2e:utility:1.0.0"),
        operation: OperationId::from_static("list_items"),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: CapabilityToken::test_token(),
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

fn make_simulate(_operation: &str) -> SimulateRequest {
    SimulateRequest::new(
        ConnectorId::from_static("test.e2e:utility:1.0.0"),
        OperationId::from_static("list_items"),
        ZoneId::work(),
        json!({}),
        CapabilityToken::test_token(),
    )
}

fn valid_manifest_toml() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
    let unchecked = fcp_manifest::ConnectorManifest::parse_str_unchecked(raw)
        .expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

// ============================================================================
// Protocol Compliance Tests (Interop Suite)
// ============================================================================

/// Full interop test suite passes.
#[test]
fn interop_suite_all_pass() {
    let summary = fcp_conformance::run_all_interop_tests();
    assert!(
        summary.all_passed(),
        "interop suite: {}/{} passed, failures: {:?}",
        summary.passed,
        summary.total,
        summary.failures
    );
}

/// Session interop tests pass independently.
#[test]
fn interop_session_tests() {
    let summary = fcp_conformance::interop::session::run_tests();
    assert!(
        summary.all_passed(),
        "session tests: {} failures",
        summary.failed
    );
}

/// FCPS data-plane interop tests pass independently.
#[test]
fn interop_fcps_tests() {
    let summary = fcp_conformance::interop::fcps::run_tests();
    assert!(
        summary.all_passed(),
        "FCPS tests: {} failures",
        summary.failed
    );
}

/// FCPC control-plane interop tests pass independently.
#[test]
fn interop_fcpc_tests() {
    let summary = fcp_conformance::interop::fcpc::run_tests();
    assert!(
        summary.all_passed(),
        "FCPC tests: {} failures",
        summary.failed
    );
}

/// Capability token interop tests pass independently.
#[test]
fn interop_capability_tests() {
    let summary = fcp_conformance::interop::capability::run_tests();
    assert!(
        summary.all_passed(),
        "capability tests: {} failures",
        summary.failed
    );
}

/// Cross-zone enforcement interop tests pass independently.
#[test]
fn interop_cross_zone_tests() {
    let summary = fcp_conformance::interop::cross_zone::run_tests();
    assert!(
        summary.all_passed(),
        "cross-zone tests: {} failures",
        summary.failed
    );
}

// ============================================================================
// Static Compliance Tests (Manifest Validation)
// ============================================================================

/// Valid manifest passes static checks.
#[test]
fn static_valid_manifest_passes() {
    let toml = valid_manifest_toml();
    let result = StaticCompliance::run_manifest(&toml);
    assert!(result.passed, "valid manifest should pass static checks");
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.status == CheckStatus::Pass)
    );
}

/// Empty manifest fails static checks.
#[test]
fn static_empty_manifest_fails() {
    let result = StaticCompliance::run_manifest("");
    assert!(!result.passed, "empty manifest should fail static checks");
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.status == CheckStatus::Fail)
    );
}

/// Malformed TOML fails static checks.
#[test]
fn static_malformed_toml_fails() {
    let result = StaticCompliance::run_manifest("{{{{invalid toml}}}}");
    assert!(!result.passed);
    assert_eq!(result.findings[0].check, "manifest.parse_validate");
}

/// Manifest with invalid version fails static checks.
#[test]
fn static_invalid_version_manifest_fails() {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_invalid_version.toml");
    let result = StaticCompliance::run_manifest(raw);
    assert!(!result.passed);
}

// ============================================================================
// Dynamic Compliance Tests (Standard Method Surface)
// ============================================================================

/// Healthy connector passes all dynamic checks.
#[fcp_async_core::runtime::test]
async fn dynamic_healthy_connector_full_pass() {
    let mut connector = HealthyConnector;
    let suite = DynamicSuite::minimal(make_handshake());
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(result.passed, "healthy connector should pass all checks");
    assert_eq!(result.findings.len(), 4); // configure, handshake, introspect, health
    for finding in &result.findings {
        assert_eq!(
            finding.status,
            CheckStatus::Pass,
            "check '{}' should pass",
            finding.check
        );
    }
}

/// Healthy connector with invoke passes invoke checks.
#[fcp_async_core::runtime::test]
async fn dynamic_invoke_success_path() {
    let mut connector = HealthyConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("list_items")),
        expect_invoke_error: false,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(result.passed);
    let invoke_finding = result
        .findings
        .iter()
        .find(|f| f.check == "invoke")
        .expect("should have invoke finding");
    assert_eq!(invoke_finding.status, CheckStatus::Pass);
}

/// Simulate success path.
#[fcp_async_core::runtime::test]
async fn dynamic_simulate_success_path() {
    let mut connector = HealthyConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: None,
        expect_invoke_error: false,
        simulate: Some(make_simulate("list_items")),
        expect_simulate_would_succeed: Some(true),
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(result.passed);
    let sim_finding = result
        .findings
        .iter()
        .find(|f| f.check == "simulate")
        .expect("should have simulate finding");
    assert_eq!(sim_finding.status, CheckStatus::Pass);
}

/// Configure failure is correctly reported.
#[fcp_async_core::runtime::test]
async fn dynamic_configure_failure_detection() {
    let mut connector = UnstableConnector::configure_failure();
    let suite = DynamicSuite::minimal(make_handshake());
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(!result.passed);
    let cfg = result.findings.iter().find(|f| f.check == "configure");
    assert_eq!(cfg.unwrap().status, CheckStatus::Fail);
}

/// Handshake failure is correctly reported.
#[fcp_async_core::runtime::test]
async fn dynamic_handshake_failure_detection() {
    let mut connector = UnstableConnector::handshake_failure();
    let suite = DynamicSuite::minimal(make_handshake());
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(!result.passed);
    let hs = result.findings.iter().find(|f| f.check == "handshake");
    assert_eq!(hs.unwrap().status, CheckStatus::Fail);
}

/// Degraded health is still passing (degraded != error).
#[fcp_async_core::runtime::test]
async fn dynamic_degraded_health_still_passes() {
    let mut connector = UnstableConnector::degraded();
    let suite = DynamicSuite::minimal(make_handshake());
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(
        result.passed,
        "degraded health should still pass (not error state)"
    );
}

/// Configure failure causes invoke to be skipped.
#[fcp_async_core::runtime::test]
async fn dynamic_invoke_skipped_on_configure_failure() {
    let mut connector = UnstableConnector::configure_failure();
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("test")),
        expect_invoke_error: false,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;
    let invoke_finding = result.findings.iter().find(|f| f.check == "invoke");
    assert_eq!(invoke_finding.unwrap().status, CheckStatus::Skipped);
}

// ============================================================================
// Capability & Authority Tests
// ============================================================================

/// Default deny: invoke without capability produces expected error + receipt.
#[fcp_async_core::runtime::test]
async fn capability_default_deny_invoke() {
    let mut connector = DenyingConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("protected_op")),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: true,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(result.passed, "denial path should pass when expected");

    let cap_finding = result
        .findings
        .iter()
        .find(|f| f.check == "invoke.capability_denial");
    assert_eq!(cap_finding.unwrap().status, CheckStatus::Pass);

    let receipt_finding = result
        .findings
        .iter()
        .find(|f| f.check == "invoke.decision_receipt");
    assert_eq!(receipt_finding.unwrap().status, CheckStatus::Pass);
}

/// Simulate denial with details.
#[fcp_async_core::runtime::test]
async fn capability_simulate_denial_with_details() {
    let mut connector = DenyingConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: None,
        expect_invoke_error: false,
        simulate: Some(make_simulate("protected_op")),
        expect_simulate_would_succeed: Some(false),
        require_simulate_denial_details: true,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(result.passed);

    let details_finding = result
        .findings
        .iter()
        .find(|f| f.check == "simulate.denial_details");
    assert_eq!(details_finding.unwrap().status, CheckStatus::Pass);
}

/// When denial is expected but success returned, test fails.
#[fcp_async_core::runtime::test]
async fn capability_expected_denial_but_got_success() {
    let mut connector = HealthyConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("list_items")),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(
        !result.passed,
        "should fail when denial expected but success returned"
    );
}

/// When simulate expected denial but got success, test fails.
#[fcp_async_core::runtime::test]
async fn capability_simulate_expected_denial_got_success() {
    let mut connector = HealthyConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: None,
        expect_invoke_error: false,
        simulate: Some(make_simulate("list_items")),
        expect_simulate_would_succeed: Some(false),
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;
    assert!(
        !result.passed,
        "should fail when simulate denial expected but success returned"
    );
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check returns valid state.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_check() {
    let connector = HealthyConnector;
    let health = connector.health().await;
    assert!(
        matches!(health.status, HealthState::Ready),
        "healthy connector should report Ready"
    );
    assert!(health.uptime_ms > 0, "uptime should be positive");
}

/// Degraded health reports reason.
#[fcp_async_core::runtime::test]
async fn lifecycle_degraded_health_with_reason() {
    let connector = UnstableConnector::degraded();
    let health = connector.health().await;
    match &health.status {
        HealthState::Degraded { reason } => {
            assert!(!reason.is_empty(), "degraded state should have a reason");
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
    assert!(health.load.unwrap() > 0.0);
}

/// Graceful shutdown succeeds.
#[fcp_async_core::runtime::test]
async fn lifecycle_graceful_shutdown() {
    let mut connector = HealthyConnector;
    connector.configure(json!({})).await.unwrap();
    connector.handshake(make_handshake()).await.unwrap();

    let result = connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 5000,
            drain: false,
            reason: Some("test complete".into()),
        })
        .await;
    assert!(result.is_ok(), "graceful shutdown should succeed");
}

/// Shutdown failure is reported.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_failure() {
    let mut connector = UnstableConnector::shutdown_failure();
    connector.configure(json!({})).await.unwrap();

    let result = connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 5000,
            drain: false,
            reason: Some("test complete".into()),
        })
        .await;
    assert!(
        result.is_err(),
        "shutdown failure should be reported as error"
    );
}

/// Metrics are available.
#[fcp_async_core::runtime::test]
async fn lifecycle_metrics_accessible() {
    let connector = HealthyConnector;
    let metrics = connector.metrics();
    assert_eq!(metrics.requests_total, 42);
    assert!(metrics.latency_p99_ms > 0);
}

// ============================================================================
// Operations & Events Tests
// ============================================================================

/// Introspection returns correct operation list.
#[fcp_async_core::runtime::test]
async fn operations_introspection_accuracy() {
    let connector = HealthyConnector;
    let intro = connector.introspect();
    assert_eq!(intro.operations.len(), 2, "should have 2 operations");
    assert_eq!(
        intro.operations[0].id,
        OperationId::from_static("list_items")
    );
    assert_eq!(
        intro.operations[1].id,
        OperationId::from_static("create_item")
    );
    assert_eq!(intro.operations[0].safety_tier, SafetyTier::Safe);
    assert_eq!(intro.operations[1].safety_tier, SafetyTier::Risky);
    assert_eq!(intro.resource_types.len(), 1, "should have 1 resource type");
    assert_eq!(intro.resource_types[0].name, "item");
}

/// Introspection schemas are well-formed JSON.
#[fcp_async_core::runtime::test]
async fn operations_introspection_schemas_valid() {
    let connector = HealthyConnector;
    let intro = connector.introspect();
    for op in &intro.operations {
        assert!(
            op.input_schema.is_object(),
            "input_schema should be an object"
        );
        assert!(
            op.output_schema.is_object() || op.output_schema.is_array(),
            "output_schema should be object or array"
        );
    }
}

/// Invoke request/response correlation.
#[fcp_async_core::runtime::test]
async fn operations_request_response_correlation() {
    let connector = HealthyConnector;
    let req = make_invoke("list_items");
    let req_id = req.id.clone();
    let resp = connector.invoke(req).await.unwrap();
    assert_eq!(resp.id, req_id, "response ID should match request ID");
    assert_eq!(resp.status, InvokeStatus::Ok);
    assert!(
        resp.result.is_some(),
        "successful invoke should have result"
    );
}

/// Simulate request/response correlation.
#[fcp_async_core::runtime::test]
async fn operations_simulate_correlation() {
    let connector = HealthyConnector;
    let req = make_simulate("list_items");
    let req_id = req.id.clone();
    let resp = connector.simulate(req).await.unwrap();
    assert_eq!(resp.id, req_id, "response ID should match request ID");
    assert!(resp.would_succeed);
}

// ============================================================================
// Full Pipeline Tests (Static + Dynamic)
// ============================================================================

/// Full compliance report: valid manifest + healthy connector.
#[fcp_async_core::runtime::test]
async fn pipeline_full_pass() {
    let toml = valid_manifest_toml();
    let static_checks = StaticCompliance::run_manifest(&toml);

    let mut connector = HealthyConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("list_items")),
        expect_invoke_error: false,
        simulate: Some(make_simulate("list_items")),
        expect_simulate_would_succeed: Some(true),
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;

    let report = ComplianceReport {
        static_checks,
        dynamic_checks,
    };

    assert!(report.passed(), "full pipeline should pass");
}

/// Full compliance report: invalid manifest + healthy connector → fail.
#[fcp_async_core::runtime::test]
async fn pipeline_static_failure_fails_report() {
    let static_checks = StaticCompliance::run_manifest("");

    let mut connector = HealthyConnector;
    let suite = DynamicSuite::minimal(make_handshake());
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;

    let report = ComplianceReport {
        static_checks,
        dynamic_checks,
    };

    assert!(
        !report.passed(),
        "report should fail when static checks fail"
    );
}

/// Full compliance report: valid manifest + failing connector → fail.
#[fcp_async_core::runtime::test]
async fn pipeline_dynamic_failure_fails_report() {
    let toml = valid_manifest_toml();
    let static_checks = StaticCompliance::run_manifest(&toml);

    let mut connector = UnstableConnector::configure_failure();
    let suite = DynamicSuite::minimal(make_handshake());
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;

    let report = ComplianceReport {
        static_checks,
        dynamic_checks,
    };

    assert!(
        !report.passed(),
        "report should fail when dynamic checks fail"
    );
}

/// Full pipeline with denial path (expected deny + receipt).
#[fcp_async_core::runtime::test]
async fn pipeline_denial_path() {
    let toml = valid_manifest_toml();
    let static_checks = StaticCompliance::run_manifest(&toml);

    let mut connector = DenyingConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("protected_op")),
        expect_invoke_error: true,
        simulate: Some(make_simulate("protected_op")),
        expect_simulate_would_succeed: Some(false),
        require_simulate_denial_details: true,
        require_capability_denial: true,
        require_decision_receipt: true,
    };
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;

    let report = ComplianceReport {
        static_checks,
        dynamic_checks,
    };

    assert!(
        report.passed(),
        "denial path pipeline should pass: {:?}",
        report
            .dynamic_checks
            .findings
            .iter()
            .filter(|f| f.status == CheckStatus::Fail)
            .collect::<Vec<_>>()
    );
}

// ============================================================================
// Evidence Bundle Tests (Report Serialization)
// ============================================================================

/// Compliance report serializes to valid JSON.
#[fcp_async_core::runtime::test]
async fn evidence_report_json_serialization() {
    let mut connector = HealthyConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("list_items")),
        expect_invoke_error: false,
        simulate: Some(make_simulate("list_items")),
        expect_simulate_would_succeed: Some(true),
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;

    let report = ComplianceReport {
        static_checks: StaticCompliance::run_manifest(&valid_manifest_toml()),
        dynamic_checks,
    };

    let json_str = serde_json::to_string_pretty(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert!(parsed["static_checks"]["passed"].as_bool().unwrap());
    assert!(parsed["dynamic_checks"]["passed"].as_bool().unwrap());
    assert!(parsed["static_checks"]["findings"].is_array());
    assert!(parsed["dynamic_checks"]["findings"].is_array());

    let findings = parsed["dynamic_checks"]["findings"].as_array().unwrap();
    for finding in findings {
        assert!(
            finding["check"].is_string(),
            "finding should have check field"
        );
        assert!(
            finding["status"].is_string(),
            "finding should have status field"
        );
        assert!(
            finding["message"].is_string(),
            "finding should have message field"
        );
    }
}

/// Report round-trip (serialize + deserialize).
#[fcp_async_core::runtime::test]
async fn evidence_report_round_trip() {
    let mut connector = HealthyConnector;
    let suite = DynamicSuite::minimal(make_handshake());
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;

    let report = ComplianceReport {
        static_checks: StaticCompliance::run_manifest(&valid_manifest_toml()),
        dynamic_checks,
    };

    let json_str = serde_json::to_string(&report).unwrap();
    let restored: ComplianceReport = serde_json::from_str(&json_str).unwrap();

    assert_eq!(report.passed(), restored.passed());
    assert_eq!(
        report.static_checks.findings.len(),
        restored.static_checks.findings.len()
    );
    assert_eq!(
        report.dynamic_checks.findings.len(),
        restored.dynamic_checks.findings.len()
    );
}

/// Denial path produces machine-parseable findings with check IDs.
#[fcp_async_core::runtime::test]
async fn evidence_denial_findings_parseable() {
    let mut connector = DenyingConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("protected_op")),
        expect_invoke_error: true,
        simulate: Some(make_simulate("protected_op")),
        expect_simulate_would_succeed: Some(false),
        require_simulate_denial_details: true,
        require_capability_denial: true,
        require_decision_receipt: true,
    };
    let result = run_dynamic_checks(&mut connector, suite).await;

    let json_str = serde_json::to_string(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // All findings should have stable check IDs for CI parsing
    let check_ids: Vec<&str> = parsed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["check"].as_str().unwrap())
        .collect();

    assert!(check_ids.contains(&"configure"));
    assert!(check_ids.contains(&"handshake"));
    assert!(check_ids.contains(&"introspect"));
    assert!(check_ids.contains(&"health"));
    assert!(check_ids.contains(&"invoke"));
    assert!(check_ids.contains(&"invoke.capability_denial"));
    assert!(check_ids.contains(&"invoke.decision_receipt"));
    assert!(check_ids.contains(&"simulate"));
    assert!(check_ids.contains(&"simulate.denial_details"));
}

// ============================================================================
// Full Verification (Interop + Compliance Combined)
// ============================================================================

/// Full verification: interop suite + static + dynamic compliance.
#[fcp_async_core::runtime::test]
async fn full_verification_pipeline() {
    // 1. Interop tests (protocol conformance)
    let interop = fcp_conformance::run_all_interop_tests();
    assert!(interop.all_passed(), "interop tests should pass");

    // 2. Static compliance (manifest)
    let static_checks = StaticCompliance::run_manifest(&valid_manifest_toml());
    assert!(static_checks.passed, "static checks should pass");

    // 3. Dynamic compliance (healthy connector)
    let mut connector = HealthyConnector;
    let suite = DynamicSuite {
        config: json!({"api_key": "test"}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("list_items")),
        expect_invoke_error: false,
        simulate: Some(make_simulate("list_items")),
        expect_simulate_would_succeed: Some(true),
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;
    assert!(dynamic_checks.passed, "dynamic checks should pass");

    // 4. Generate report
    let report = ComplianceReport {
        static_checks,
        dynamic_checks,
    };

    assert!(report.passed());

    // 5. Report should be serializable for evidence bundles
    let evidence = serde_json::to_value(&report).unwrap();
    assert!(evidence["static_checks"]["passed"].as_bool().unwrap());
    assert!(evidence["dynamic_checks"]["passed"].as_bool().unwrap());
}

/// Full verification with denial path.
#[fcp_async_core::runtime::test]
async fn full_verification_denial_path() {
    let interop = fcp_conformance::run_all_interop_tests();
    assert!(interop.all_passed());

    let static_checks = StaticCompliance::run_manifest(&valid_manifest_toml());
    assert!(static_checks.passed);

    let mut connector = DenyingConnector;
    let suite = DynamicSuite {
        config: json!({}),
        handshake: make_handshake(),
        invoke: Some(make_invoke("protected_op")),
        expect_invoke_error: true,
        simulate: Some(make_simulate("protected_op")),
        expect_simulate_would_succeed: Some(false),
        require_simulate_denial_details: true,
        require_capability_denial: true,
        require_decision_receipt: true,
    };
    let dynamic_checks = run_dynamic_checks(&mut connector, suite).await;
    assert!(dynamic_checks.passed);

    let report = ComplianceReport {
        static_checks,
        dynamic_checks,
    };
    assert!(report.passed());
}
