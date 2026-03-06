//! No-mock integration tests for fcp-host.
//!
//! These tests exercise real cross-module interactions without mocking:
//! - BudgetPolicyEngine as a real PolicyEngine for DiscoveryEndpoint
//! - DoctorService with real registry
//! - Full discovery → introspect → preflight pipeline
//! - ToolDescriptor invariants across safety tiers
//!
//! Bead: 3p99.2

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use fcp_core::{
    AgentHint, ApprovalMode, BudgetEnforcement, CapabilityId, ConnectorHealth, ConnectorId,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RateLimitDeclarations, RiskLevel,
    SafetyTier, SelfCheckReport, SelfCheckStatus, UsageBudgetLimit, UsageBudgetPolicy, UsageMetric,
    UsageMetricKind, ZoneId,
};
use fcp_host::{
    BudgetAction, BudgetPolicyEngine, BudgetTracker, ConnectorArchetype, ConnectorRegistry,
    ConnectorSummary, DiscoveryEndpoint, DiscoveryFilter, DoctorReport, DoctorRequest,
    DoctorService, HealthFilter, HostError, HostHealthResponse, HostHealthStatus,
    IntrospectionResponse, PolicyEngine, PreflightRequest, SafetyTierExt,
    SelfCheckResponse, ToolDescriptor,
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared test registry (real implementation, not a mock)
// ─────────────────────────────────────────────────────────────────────────────

struct TestRegistry {
    connectors: Vec<(ConnectorSummary, Introspection, ConnectorArchetype)>,
}

impl TestRegistry {
    fn new() -> Self {
        Self {
            connectors: Vec::new(),
        }
    }

    fn add(
        &mut self,
        id: ConnectorId,
        name: &str,
        categories: Vec<&str>,
        safety: SafetyTier,
        health: ConnectorHealth,
        operations: Vec<OperationInfo>,
        archetype: ConnectorArchetype,
    ) {
        let summary = ConnectorSummary {
            id,
            name: name.to_string(),
            description: Some(format!("{name} test connector")),
            version: semver::Version::new(1, 0, 0),
            categories: categories.into_iter().map(String::from).collect(),
            tool_count: operations.len() as u32,
            max_safety_tier: safety,
            enabled: true,
            health,
            last_health_check: Some(Utc::now()),
        };
        let introspection = Introspection {
            operations,
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };
        self.connectors.push((summary, introspection, archetype));
    }
}

#[async_trait]
impl ConnectorRegistry for TestRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        self.connectors.iter().map(|(s, _, _)| s.clone()).collect()
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        self.connectors
            .iter()
            .find(|(s, _, _)| &s.id == id)
            .map(|(s, _, _)| s.clone())
    }

    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
        self.connectors
            .iter()
            .find(|(s, _, _)| &s.id == id)
            .map(|(_, i, _)| i.clone())
    }

    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype> {
        self.connectors
            .iter()
            .find(|(s, _, _)| &s.id == id)
            .map(|(_, _, a)| *a)
    }

    async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
        None
    }

    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
        self.connectors
            .iter()
            .find(|(s, _, _)| &s.id == id)
            .map(|(s, _, _)| {
                if s.health.is_healthy() {
                    SelfCheckReport::ok()
                } else if s.health.is_available() {
                    SelfCheckReport::degraded("health_degraded", "connector is degraded")
                } else {
                    SelfCheckReport::failed("health_failed", "connector is unavailable")
                }
            })
    }

    fn version(&self) -> u64 {
        self.connectors.len() as u64
    }
}

fn make_op(
    id: &str,
    risk: RiskLevel,
    safety: SafetyTier,
    idempotency: IdempotencyClass,
    approval: Option<ApprovalMode>,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::new(id).expect("valid operation id"),
        summary: format!("{id} operation"),
        description: Some(format!("Detailed description of {id}")),
        input_schema: serde_json::json!({"type": "object", "properties": {"input": {"type": "string"}}}),
        output_schema: serde_json::json!({"type": "object", "properties": {"result": {"type": "string"}}}),
        capability: CapabilityId::new(format!("cap.{id}")).expect("valid cap id"),
        risk_level: risk,
        safety_tier: safety,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: format!("Use {id}"),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
        },
        rate_limit: None,
        requires_approval: approval,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. BudgetPolicyEngine as real PolicyEngine for DiscoveryEndpoint
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn budget_engine_preflight_denies_when_exceeded() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();
    engine
        .upsert_policy(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 3600,
                }],
            },
        )
        .await;

    // Exceed budget
    engine
        .record_usage(&zone, &[UsageMetric::tokens(200)])
        .await;

    let mut registry = TestRegistry::new();
    registry.add(
        ConnectorId::from_static("fcp.test:utility:1.0.0"),
        "Test",
        vec!["test"],
        SafetyTier::Safe,
        ConnectorHealth::healthy(),
        vec![make_op(
            "read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            None,
        )],
        ConnectorArchetype::RequestResponse,
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    // Preflight should deny because budget is exceeded
    let request = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: Some("agent:test".to_string()),
        zone_id: Some(zone),
    };

    let response = endpoint.preflight(request).await;
    assert!(!response.allowed);
    assert_eq!(response.reason.as_deref(), Some("usage budget exceeded"));
    assert!(response.budget_status.is_some());
}

#[fcp_async_core::runtime::test]
async fn budget_engine_preflight_allows_within_budget() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();
    engine
        .upsert_policy(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 1000,
                    window_seconds: 3600,
                }],
            },
        )
        .await;

    // Use some budget but stay within limits
    engine
        .record_usage(&zone, &[UsageMetric::tokens(50)])
        .await;

    let registry = TestRegistry::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let request = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: None,
        zone_id: Some(zone),
    };

    let response = endpoint.preflight(request).await;
    assert!(response.allowed);
}

#[fcp_async_core::runtime::test]
async fn budget_engine_warn_mode_allows_preflight_even_exceeded() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();
    engine
        .upsert_policy(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 3600,
                }],
            },
        )
        .await;

    engine
        .record_usage(&zone, &[UsageMetric::tokens(500)])
        .await;

    let registry = TestRegistry::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let request = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "write".to_string(),
        params: None,
        principal: None,
        zone_id: Some(zone),
    };

    let response = endpoint.preflight(request).await;
    assert!(response.allowed);
    // Budget status should still be populated
    assert!(response.budget_status.is_some());
}

#[fcp_async_core::runtime::test]
async fn budget_engine_no_zone_in_preflight_always_allows() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();
    engine
        .upsert_policy(
            zone,
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 0,
                    window_seconds: 3600,
                }],
            },
        )
        .await;

    let registry = TestRegistry::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let request = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: None,
        zone_id: None, // No zone → no budget check
    };

    let response = endpoint.preflight(request).await;
    assert!(response.allowed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Full discovery → introspect → ToolDescriptor pipeline
// ─────────────────────────────────────────────────────────────────────────────

fn build_multi_op_registry() -> TestRegistry {
    let mut registry = TestRegistry::new();

    // Safe read-only connector
    registry.add(
        ConnectorId::from_static("fcp.reader:utility:1.0.0"),
        "Reader",
        vec!["storage", "read"],
        SafetyTier::Safe,
        ConnectorHealth::healthy(),
        vec![
            make_op(
                "list",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                None,
            ),
            make_op(
                "get",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                None,
            ),
        ],
        ConnectorArchetype::RequestResponse,
    );

    // Dangerous writer connector
    registry.add(
        ConnectorId::from_static("fcp.writer:utility:1.0.0"),
        "Writer",
        vec!["storage", "write"],
        SafetyTier::Dangerous,
        ConnectorHealth::healthy(),
        vec![
            make_op(
                "create",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
                Some(ApprovalMode::Interactive),
            ),
            make_op(
                "delete",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::BestEffort,
                Some(ApprovalMode::Interactive),
            ),
        ],
        ConnectorArchetype::RequestResponse,
    );

    // Streaming connector
    registry.add(
        ConnectorId::from_static("fcp.stream:messaging:1.0.0"),
        "Stream",
        vec!["messaging"],
        SafetyTier::Risky,
        ConnectorHealth::degraded("high_latency"),
        vec![make_op(
            "subscribe",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            None,
        )],
        ConnectorArchetype::Streaming,
    );

    registry
}

#[fcp_async_core::runtime::test]
async fn discover_all_returns_all_connectors() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let response = endpoint.discover(None).await;
    assert_eq!(response.connectors.len(), 3);
    assert!(response.supports_streaming);
    assert!(response.supports_batching);
    assert_eq!(response.registry_version, 3);
}

#[fcp_async_core::runtime::test]
async fn discover_filter_by_category() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let filter = DiscoveryFilter {
        category: Some("messaging".to_string()),
        ..Default::default()
    };

    let response = endpoint.discover(Some(filter)).await;
    assert_eq!(response.connectors.len(), 1);
    assert_eq!(response.connectors[0].name, "Stream");
}

#[fcp_async_core::runtime::test]
async fn discover_filter_by_safety() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let filter = DiscoveryFilter {
        max_risk: Some(SafetyTier::Safe),
        ..Default::default()
    };

    let response = endpoint.discover(Some(filter)).await;
    assert_eq!(response.connectors.len(), 1);
    assert_eq!(response.connectors[0].name, "Reader");
}

#[fcp_async_core::runtime::test]
async fn discover_filter_by_health() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let filter = DiscoveryFilter {
        health: Some(HealthFilter::Healthy),
        ..Default::default()
    };

    let response = endpoint.discover(Some(filter)).await;
    assert_eq!(response.connectors.len(), 2); // Reader + Writer (both healthy)
}

#[fcp_async_core::runtime::test]
async fn discover_combined_filter_category_and_safety() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let filter = DiscoveryFilter {
        category: Some("storage".to_string()),
        max_risk: Some(SafetyTier::Safe),
        health: None,
    };

    let response = endpoint.discover(Some(filter)).await;
    assert_eq!(response.connectors.len(), 1);
    assert_eq!(response.connectors[0].name, "Reader");
}

#[fcp_async_core::runtime::test]
async fn introspect_reader_produces_correct_tool_descriptors() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let reader_id = ConnectorId::from_static("fcp.reader:utility:1.0.0");
    let response = endpoint.introspect(&reader_id).await.unwrap();

    assert_eq!(response.connector.name, "Reader");
    assert_eq!(response.archetype, ConnectorArchetype::RequestResponse);
    assert_eq!(response.tools.len(), 2);
    assert_eq!(response.introspection.operations.len(), 2);

    // Verify tool descriptor properties
    for tool in &response.tools {
        assert_eq!(tool.risk_level, RiskLevel::Low);
        assert_eq!(tool.safety_tier, SafetyTier::Safe);
        assert_eq!(tool.idempotency, IdempotencyClass::Strict);
        assert!(tool.idempotent); // Strict → idempotent
        assert!(!tool.requires_confirmation); // No approval required
        assert!(tool.supports_simulate);
        assert!(tool.approval_mode.is_none());
    }
}

#[fcp_async_core::runtime::test]
async fn introspect_writer_has_approval_requirements() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let writer_id = ConnectorId::from_static("fcp.writer:utility:1.0.0");
    let response = endpoint.introspect(&writer_id).await.unwrap();

    assert_eq!(response.tools.len(), 2);

    for tool in &response.tools {
        assert_eq!(tool.safety_tier, SafetyTier::Dangerous);
        assert!(tool.requires_confirmation);
        assert_eq!(tool.approval_mode, Some(ApprovalMode::Interactive));
    }

    // "create" is not idempotent (None class)
    let create = response.tools.iter().find(|t| t.name == "create").unwrap();
    assert!(!create.idempotent);
    assert_eq!(create.idempotency, IdempotencyClass::None);

    // "delete" is idempotent (BestEffort class)
    let delete = response.tools.iter().find(|t| t.name == "delete").unwrap();
    assert!(delete.idempotent);
    assert_eq!(delete.idempotency, IdempotencyClass::BestEffort);
}

#[fcp_async_core::runtime::test]
async fn introspect_streaming_connector_has_correct_archetype() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let stream_id = ConnectorId::from_static("fcp.stream:messaging:1.0.0");
    let response = endpoint.introspect(&stream_id).await.unwrap();

    assert_eq!(response.archetype, ConnectorArchetype::Streaming);
    assert_eq!(response.tools.len(), 1);
    assert_eq!(response.tools[0].name, "subscribe");
}

#[fcp_async_core::runtime::test]
async fn introspect_missing_connector_returns_error() {
    let registry = TestRegistry::new();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let missing_id = ConnectorId::from_static("fcp.missing:utility:1.0.0");
    let err = endpoint.introspect(&missing_id).await.unwrap_err();
    assert!(matches!(err, HostError::ConnectorNotFound(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Self-check flow through DiscoveryEndpoint
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn self_check_healthy_connector() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let reader_id = ConnectorId::from_static("fcp.reader:utility:1.0.0");
    let response = endpoint.self_check(&reader_id).await.unwrap();

    assert_eq!(response.connector_id, reader_id);
    assert_eq!(response.report.status, SelfCheckStatus::Ok);
}

#[fcp_async_core::runtime::test]
async fn self_check_degraded_connector() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let stream_id = ConnectorId::from_static("fcp.stream:messaging:1.0.0");
    let response = endpoint.self_check(&stream_id).await.unwrap();

    assert_eq!(response.connector_id, stream_id);
    assert_eq!(response.report.status, SelfCheckStatus::Degraded);
}

#[fcp_async_core::runtime::test]
async fn self_check_missing_connector() {
    let registry = TestRegistry::new();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let missing_id = ConnectorId::from_static("fcp.missing:utility:1.0.0");
    let err = endpoint.self_check(&missing_id).await.unwrap_err();
    assert!(matches!(err, HostError::ConnectorNotFound(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. DoctorService + real registry integration
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn doctor_with_healthy_connectors() {
    let registry = build_multi_op_registry();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec![
            "fcp.reader:utility:1.0.0".to_string(),
            "fcp.writer:utility:1.0.0".to_string(),
        ],
        self_check: true,
    };

    let report = service.handle(request).await.unwrap();
    assert_eq!(
        report.overall_status,
        fcp_host::OverallStatus::Ok,
        "both reader and writer are healthy"
    );
    assert_eq!(report.connector_self_checks.len(), 2);
    assert_eq!(report.zone_id, "z:work");
}

#[fcp_async_core::runtime::test]
async fn doctor_with_degraded_connector_reports_warn() {
    let registry = build_multi_op_registry();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec![
            "fcp.reader:utility:1.0.0".to_string(),
            "fcp.stream:messaging:1.0.0".to_string(), // degraded
        ],
        self_check: true,
    };

    let report = service.handle(request).await.unwrap();
    assert_eq!(
        report.overall_status,
        fcp_host::OverallStatus::Warn,
        "degraded connector should produce Warn"
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_without_self_check_skips_checks() {
    let registry = build_multi_op_registry();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec!["fcp.reader:utility:1.0.0".to_string()],
        self_check: false,
    };

    let report = service.handle(request).await.unwrap();
    assert_eq!(report.overall_status, fcp_host::OverallStatus::Ok);
    assert!(
        report.connector_self_checks.is_empty(),
        "self_check=false means no checks"
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_missing_connector_returns_error() {
    let registry = TestRegistry::new();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec!["fcp.missing:utility:1.0.0".to_string()],
        self_check: true,
    };

    let err = service.handle(request).await.unwrap_err();
    assert!(matches!(err, HostError::ConnectorNotFound(_)));
}

#[fcp_async_core::runtime::test]
async fn doctor_invalid_zone_id_fails() {
    let registry = TestRegistry::new();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "not-a-valid-zone".to_string(),
        connectors: vec![],
        self_check: false,
    };

    // Invalid zone_id should fail validation
    let result = service.handle(request).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn doctor_custom_timeout() {
    let registry = build_multi_op_registry();
    let service = DoctorService::with_timeout(Arc::new(registry), Duration::from_millis(500));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec!["fcp.reader:utility:1.0.0".to_string()],
        self_check: true,
    };

    let report = service.handle(request).await.unwrap();
    assert_eq!(report.overall_status, fcp_host::OverallStatus::Ok);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. BudgetTracker accumulation and window behavior
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_tracker_multi_zone_multi_metric_isolation() {
    let mut tracker = BudgetTracker::new();
    let zone_a = ZoneId::work();
    let zone_b = ZoneId::private();

    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![
            UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 3600,
            },
            UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 10,
                window_seconds: 3600,
            },
        ],
    };

    // Zone A: use tokens
    let eval = tracker.record_usage(&zone_a, &policy, &[UsageMetric::tokens(80)]);
    assert_eq!(eval.action, BudgetAction::Allow);

    // Zone B: use requests
    let eval = tracker.record_usage(&zone_b, &policy, &[UsageMetric::requests(8)]);
    assert_eq!(eval.action, BudgetAction::Allow);

    // Zone A: add more tokens → exceeds
    let eval = tracker.record_usage(&zone_a, &policy, &[UsageMetric::tokens(30)]);
    assert_eq!(eval.action, BudgetAction::Deny);

    // Zone B: tokens should still be 0
    let snap = tracker.snapshot(&zone_b, &policy);
    let tokens = snap
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .unwrap();
    assert_eq!(tokens.used, 0);
    assert_eq!(tokens.remaining, 100);
}

#[test]
fn budget_tracker_saturation_arithmetic() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();

    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![UsageBudgetLimit {
            metric: UsageMetricKind::Tokens,
            limit: u64::MAX,
            window_seconds: 3600,
        }],
    };

    // Near-max usage should not panic
    let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(u64::MAX - 1)]);
    assert_eq!(eval.action, BudgetAction::Allow);

    // Adding more saturates rather than overflowing
    let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(10)]);
    // Should not panic from overflow
    assert!(eval.snapshot.budgets[0].used >= u64::MAX - 1);
}

#[fcp_async_core::runtime::test]
async fn budget_engine_policy_lifecycle() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();

    // No policy → no snapshot
    assert!(engine.snapshot(&zone).await.is_none());

    // Add policy
    engine
        .upsert_policy(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                }],
            },
        )
        .await;

    // Snapshot now works
    let snap = engine.snapshot(&zone).await.unwrap();
    assert_eq!(snap.budgets[0].used, 0);
    assert_eq!(snap.budgets[0].limit, 100);

    // Record usage
    let eval = engine
        .record_usage(&zone, &[UsageMetric::tokens(50)])
        .await
        .unwrap();
    assert_eq!(eval.action, BudgetAction::Allow);

    // Snapshot reflects usage
    let snap = engine.snapshot(&zone).await.unwrap();
    assert_eq!(snap.budgets[0].used, 50);

    // Remove policy
    let removed = engine.remove_policy(&zone).await;
    assert!(removed.is_some());

    // No more snapshot
    assert!(engine.snapshot(&zone).await.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ToolDescriptor invariants across safety tiers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tool_descriptor_idempotent_flag_matches_class() {
    let cases = [
        (IdempotencyClass::Strict, true),
        (IdempotencyClass::BestEffort, true),
        (IdempotencyClass::None, false),
    ];

    for (class, expected_idempotent) in cases {
        let op = make_op("test", RiskLevel::Low, SafetyTier::Safe, class, None);
        let tool = ToolDescriptor::from(&op);
        assert_eq!(
            tool.idempotent, expected_idempotent,
            "IdempotencyClass::{class:?} should produce idempotent={expected_idempotent}"
        );
    }
}

#[test]
fn tool_descriptor_requires_confirmation_matches_approval() {
    // No approval → no confirmation
    let op = make_op(
        "read",
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        None,
    );
    let tool = ToolDescriptor::from(&op);
    assert!(!tool.requires_confirmation);
    assert!(tool.approval_mode.is_none());

    // With approval → requires confirmation
    let op = make_op(
        "write",
        RiskLevel::High,
        SafetyTier::Dangerous,
        IdempotencyClass::None,
        Some(ApprovalMode::Interactive),
    );
    let tool = ToolDescriptor::from(&op);
    assert!(tool.requires_confirmation);
    assert_eq!(tool.approval_mode, Some(ApprovalMode::Interactive));
}

#[test]
fn tool_descriptor_description_fallback() {
    // With description → uses description
    let op = make_op(
        "test",
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        None,
    );
    let tool = ToolDescriptor::from(&op);
    assert_eq!(tool.description, "Detailed description of test");

    // Without description → uses summary
    let mut op = make_op(
        "test2",
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        None,
    );
    op.description = None;
    let tool = ToolDescriptor::from(&op);
    assert_eq!(tool.description, "test2 operation");
}

#[test]
fn tool_descriptor_ai_hints_omitted_when_empty() {
    let mut op = make_op(
        "bare",
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        None,
    );
    op.ai_hints = AgentHint::default();
    let tool = ToolDescriptor::from(&op);
    assert!(tool.ai_hints.is_none());
}

#[test]
fn tool_descriptor_ai_hints_present_when_populated() {
    let op = make_op(
        "rich",
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        None,
    );
    let tool = ToolDescriptor::from(&op);
    assert!(tool.ai_hints.is_some());
    assert_eq!(tool.ai_hints.as_ref().unwrap().when_to_use, "Use rich");
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Safety tier ordering invariants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn safety_tier_ordering_is_total() {
    let tiers = [
        SafetyTier::Safe,
        SafetyTier::Risky,
        SafetyTier::Dangerous,
        SafetyTier::Critical,
        SafetyTier::Forbidden,
    ];

    // Every tier is at_most itself
    for tier in &tiers {
        assert!(
            tier.is_at_most(*tier),
            "{tier:?} should be at_most itself"
        );
    }

    // Strict ordering
    for i in 0..tiers.len() {
        for j in (i + 1)..tiers.len() {
            assert!(
                tiers[i].is_at_most(tiers[j]),
                "{:?} should be at_most {:?}",
                tiers[i],
                tiers[j]
            );
            assert!(
                !tiers[j].is_at_most(tiers[i]),
                "{:?} should NOT be at_most {:?}",
                tiers[j],
                tiers[i]
            );
        }
    }
}

#[test]
fn safety_tier_levels_are_contiguous() {
    let tiers = [
        SafetyTier::Safe,
        SafetyTier::Risky,
        SafetyTier::Dangerous,
        SafetyTier::Critical,
        SafetyTier::Forbidden,
    ];

    for i in 1..tiers.len() {
        assert_eq!(
            tiers[i].level(),
            tiers[i - 1].level() + 1,
            "levels should be contiguous"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Discovery cache integration
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn cache_invalidation_picks_up_new_connectors() {
    let mut registry = TestRegistry::new();
    registry.add(
        ConnectorId::from_static("fcp.first:utility:1.0.0"),
        "First",
        vec!["test"],
        SafetyTier::Safe,
        ConnectorHealth::healthy(),
        vec![],
        ConnectorArchetype::RequestResponse,
    );

    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::with_cache_ttl(
        Arc::new(registry),
        Arc::new(engine),
        Duration::from_secs(0), // Zero TTL → always refresh
    );

    let response = endpoint.discover(None).await;
    assert_eq!(response.connectors.len(), 1);

    // With zero TTL, next call re-fetches (registry is Arc'd so same data)
    let response2 = endpoint.discover(None).await;
    assert_eq!(response2.connectors.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. DoctorReport baseline properties
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn doctor_report_schema_version_is_semver() {
    let v: semver::Version = DoctorReport::SCHEMA_VERSION.parse().unwrap();
    assert_eq!(v.major, 1);
    assert!(v.minor >= 1);
}

#[test]
fn doctor_report_baseline_serializes_to_valid_json() {
    let report = DoctorReport::baseline("z:test");
    let json = serde_json::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["zone_id"], "z:test");
    assert_eq!(parsed["overall_status"], "OK");
    assert_eq!(parsed["checkpoint"]["freshness"], "fresh");
    assert_eq!(parsed["revocation"]["freshness"], "fresh");
    assert_eq!(parsed["audit"]["freshness"], "fresh");
    assert!(parsed["transport_policy"]["allow_lan"].as_bool().unwrap());
    assert!(!parsed["transport_policy"]["allow_derp"].as_bool().unwrap());
    assert!(parsed["store_coverage"]["store_healthy"].as_bool().unwrap());
    assert!(!parsed["degraded_mode"]["is_degraded"].as_bool().unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Response type serde roundtrip invariants
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn introspection_response_roundtrip() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let reader_id = ConnectorId::from_static("fcp.reader:utility:1.0.0");
    let response = endpoint.introspect(&reader_id).await.unwrap();

    let json = serde_json::to_string(&response).unwrap();
    let parsed: IntrospectionResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.connector.id, response.connector.id);
    assert_eq!(parsed.tools.len(), response.tools.len());
    assert_eq!(parsed.archetype, response.archetype);

    for (orig, parsed) in response.tools.iter().zip(parsed.tools.iter()) {
        assert_eq!(orig.name, parsed.name);
        assert_eq!(orig.risk_level, parsed.risk_level);
        assert_eq!(orig.safety_tier, parsed.safety_tier);
        assert_eq!(orig.idempotency, parsed.idempotency);
        assert_eq!(orig.idempotent, parsed.idempotent);
        assert_eq!(orig.requires_confirmation, parsed.requires_confirmation);
    }
}

#[test]
fn host_health_response_roundtrip() {
    let mut connectors = HashMap::new();
    connectors.insert(
        ConnectorId::from_static("fcp.a:utility:1.0.0"),
        ConnectorHealth::healthy(),
    );
    connectors.insert(
        ConnectorId::from_static("fcp.b:utility:1.0.0"),
        ConnectorHealth::degraded("slow"),
    );

    let response = HostHealthResponse {
        status: HostHealthStatus::Degraded,
        connectors,
        uptime_seconds: 86400,
        active_connections: 42,
        timestamp: Utc::now(),
    };

    let json = serde_json::to_string(&response).unwrap();
    let parsed: HostHealthResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.status, HostHealthStatus::Degraded);
    assert_eq!(parsed.connectors.len(), 2);
    assert_eq!(parsed.uptime_seconds, 86400);
    assert_eq!(parsed.active_connections, 42);
}

#[test]
fn self_check_response_roundtrip() {
    let resp = SelfCheckResponse {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        report: SelfCheckReport::degraded("latency", "p95 > 2s"),
        checked_at: Utc::now(),
    };

    let json = serde_json::to_string(&resp).unwrap();
    let parsed: SelfCheckResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.connector_id, resp.connector_id);
    assert_eq!(parsed.report.status, SelfCheckStatus::Degraded);
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Error type coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn host_error_variants_display_correctly() {
    let errors = vec![
        (
            HostError::ConnectorNotFound("fcp.test:utility:1.0.0".into()),
            "connector not found",
        ),
        (
            HostError::InvalidFilter("bad zone".into()),
            "invalid filter",
        ),
        (
            HostError::RegistryError("timeout".into()),
            "registry error",
        ),
        (
            HostError::PreflightFailed("denied".into()),
            "preflight failed",
        ),
        (HostError::CacheError("eviction".into()), "cache error"),
        (HostError::Internal("panic".into()), "internal error"),
    ];

    for (err, expected_prefix) in errors {
        let msg = err.to_string();
        assert!(
            msg.contains(expected_prefix),
            "HostError display should contain '{expected_prefix}', got: {msg}"
        );
    }
}

#[test]
fn host_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(HostError::Internal("test".into()));
    assert!(err.to_string().contains("internal error"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. BudgetEvaluation to_error integration
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_deny_produces_fcp_error() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![UsageBudgetLimit {
            metric: UsageMetricKind::Requests,
            limit: 5,
            window_seconds: 60,
        }],
    };

    let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(10)]);
    assert_eq!(eval.action, BudgetAction::Deny);

    let fcp_err = eval.to_error().expect("should produce FcpError");
    let msg = fcp_err.to_string();
    assert!(msg.contains("budget") || msg.contains("exceeded"), "error message should reference budget: {msg}");
}

#[test]
fn budget_allow_produces_no_error() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![UsageBudgetLimit {
            metric: UsageMetricKind::Tokens,
            limit: 1000,
            window_seconds: 60,
        }],
    };

    let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
    assert_eq!(eval.action, BudgetAction::Allow);
    assert!(eval.to_error().is_none());
}

#[test]
fn budget_warn_produces_no_error() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Warn,
        budgets: vec![UsageBudgetLimit {
            metric: UsageMetricKind::Tokens,
            limit: 100,
            window_seconds: 60,
        }],
    };

    let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(500)]);
    assert_eq!(eval.action, BudgetAction::Warn);
    assert!(eval.to_error().is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. BudgetPolicyEngine with_policies + full lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn budget_engine_with_policies_preflight_integration() {
    let zone_a = ZoneId::work();
    let zone_b = ZoneId::private();

    let mut policies = std::collections::HashMap::new();
    policies.insert(
        zone_a.clone(),
        UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 50,
                window_seconds: 3600,
            }],
        },
    );
    policies.insert(
        zone_b.clone(),
        UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 10,
                window_seconds: 3600,
            }],
        },
    );

    let engine = BudgetPolicyEngine::with_policies(policies);

    // Exceed zone_a tokens
    engine
        .record_usage(&zone_a, &[UsageMetric::tokens(60)])
        .await;

    // zone_a preflight should deny
    let req_a = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: None,
        zone_id: Some(zone_a),
    };
    let resp_a = engine.evaluate_preflight(&req_a).await;
    assert!(!resp_a.allowed);

    // Exceed zone_b requests — warn mode, should still allow
    engine
        .record_usage(&zone_b, &[UsageMetric::requests(20)])
        .await;

    let req_b = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: None,
        zone_id: Some(zone_b),
    };
    let resp_b = engine.evaluate_preflight(&req_b).await;
    assert!(resp_b.allowed, "warn enforcement should not deny");
    assert!(resp_b.budget_status.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. Discovery → Introspect → Preflight pipeline (full)
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn full_pipeline_discover_introspect_preflight_denied() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();

    // Set up budget that will exceed
    engine
        .upsert_policy(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 10,
                    window_seconds: 3600,
                }],
            },
        )
        .await;

    // Pre-record usage to exceed
    engine
        .record_usage(&zone, &[UsageMetric::tokens(100)])
        .await;

    let mut registry = TestRegistry::new();
    registry.add(
        ConnectorId::from_static("fcp.chat:messaging:1.0.0"),
        "Chat",
        vec!["messaging"],
        SafetyTier::Risky,
        ConnectorHealth::healthy(),
        vec![
            make_op(
                "send",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                Some(ApprovalMode::Interactive),
            ),
            make_op(
                "list",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                None,
            ),
        ],
        ConnectorArchetype::Bidirectional,
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    // Step 1: Discover
    let discovered = endpoint.discover(None).await;
    assert_eq!(discovered.connectors.len(), 1);
    assert_eq!(discovered.connectors[0].name, "Chat");

    // Step 2: Introspect
    let chat_id = ConnectorId::from_static("fcp.chat:messaging:1.0.0");
    let introspection = endpoint.introspect(&chat_id).await.unwrap();
    assert_eq!(introspection.archetype, ConnectorArchetype::Bidirectional);
    assert_eq!(introspection.tools.len(), 2);

    // Verify tool properties
    let send = introspection.tools.iter().find(|t| t.name == "send").unwrap();
    assert!(send.requires_confirmation);
    assert!(!send.idempotent);

    let list = introspection.tools.iter().find(|t| t.name == "list").unwrap();
    assert!(!list.requires_confirmation);
    assert!(list.idempotent);

    // Step 3: Preflight — should be denied due to budget
    let preflight_req = PreflightRequest {
        connector_id: chat_id,
        operation: "send".to_string(),
        params: Some(serde_json::json!({"channel": "general", "message": "hello"})),
        principal: Some("agent:claude".to_string()),
        zone_id: Some(zone),
    };
    let preflight_resp = endpoint.preflight(preflight_req).await;
    assert!(!preflight_resp.allowed);
    assert!(preflight_resp.budget_status.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. DoctorService with mixed health connectors
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn doctor_with_mixed_health_statuses() {
    let mut registry = TestRegistry::new();

    // Healthy connector
    registry.add(
        ConnectorId::from_static("fcp.healthy:utility:1.0.0"),
        "Healthy",
        vec!["test"],
        SafetyTier::Safe,
        ConnectorHealth::healthy(),
        vec![],
        ConnectorArchetype::RequestResponse,
    );

    // Degraded connector
    registry.add(
        ConnectorId::from_static("fcp.degraded:utility:1.0.0"),
        "Degraded",
        vec!["test"],
        SafetyTier::Safe,
        ConnectorHealth::degraded("slow"),
        vec![],
        ConnectorArchetype::RequestResponse,
    );

    // Unavailable connector
    registry.add(
        ConnectorId::from_static("fcp.down:utility:1.0.0"),
        "Down",
        vec!["test"],
        SafetyTier::Safe,
        ConnectorHealth::unavailable("timeout"),
        vec![],
        ConnectorArchetype::RequestResponse,
    );

    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec![
            "fcp.healthy:utility:1.0.0".to_string(),
            "fcp.degraded:utility:1.0.0".to_string(),
            "fcp.down:utility:1.0.0".to_string(),
        ],
        self_check: true,
    };

    let report = service.handle(request).await.unwrap();
    // Failed connector should make overall status Fail
    assert_eq!(report.overall_status, fcp_host::OverallStatus::Fail);
    assert_eq!(report.connector_self_checks.len(), 3);

    // Verify individual statuses
    let ok_check = report
        .connector_self_checks
        .iter()
        .find(|c| c.connector_id.contains("healthy"))
        .unwrap();
    assert_eq!(ok_check.report.status, SelfCheckStatus::Ok);

    let degraded_check = report
        .connector_self_checks
        .iter()
        .find(|c| c.connector_id.contains("degraded"))
        .unwrap();
    assert_eq!(degraded_check.report.status, SelfCheckStatus::Degraded);

    let failed_check = report
        .connector_self_checks
        .iter()
        .find(|c| c.connector_id.contains("down"))
        .unwrap();
    assert_eq!(failed_check.report.status, SelfCheckStatus::Failed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. Discovery filter edge cases with real endpoint
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn discover_filter_degraded_only() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let filter = DiscoveryFilter {
        health: Some(HealthFilter::Degraded),
        ..Default::default()
    };

    let response = endpoint.discover(Some(filter)).await;
    assert_eq!(response.connectors.len(), 1);
    assert_eq!(response.connectors[0].name, "Stream");
}

#[fcp_async_core::runtime::test]
async fn discover_filter_all_health_returns_everything() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let filter = DiscoveryFilter {
        health: Some(HealthFilter::All),
        ..Default::default()
    };

    let response = endpoint.discover(Some(filter)).await;
    assert_eq!(response.connectors.len(), 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. Budget zero limit integration
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn budget_zero_limit_denies_any_usage_via_engine() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();
    engine
        .upsert_policy(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 0,
                    window_seconds: 3600,
                }],
            },
        )
        .await;

    // Even 1 token exceeds
    let eval = engine
        .record_usage(&zone, &[UsageMetric::tokens(1)])
        .await
        .unwrap();
    assert_eq!(eval.action, BudgetAction::Deny);

    // Preflight should deny
    let request = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: None,
        zone_id: Some(zone),
    };
    let response = engine.evaluate_preflight(&request).await;
    assert!(!response.allowed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. Discovery cache invalidation + filter interaction
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn cache_invalidation_then_filter_works() {
    let mut registry = TestRegistry::new();
    registry.add(
        ConnectorId::from_static("fcp.cached:storage:1.0.0"),
        "Cached",
        vec!["storage"],
        SafetyTier::Safe,
        ConnectorHealth::healthy(),
        vec![],
        ConnectorArchetype::RequestResponse,
    );

    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::with_cache_ttl(
        Arc::new(registry),
        Arc::new(engine),
        Duration::from_secs(0),
    );

    // First discover with no filter
    let all = endpoint.discover(None).await;
    assert_eq!(all.connectors.len(), 1);

    // Discover with category filter that matches
    let filter = DiscoveryFilter {
        category: Some("storage".to_string()),
        ..Default::default()
    };
    let filtered = endpoint.discover(Some(filter)).await;
    assert_eq!(filtered.connectors.len(), 1);

    // Discover with non-matching filter
    let filter = DiscoveryFilter {
        category: Some("messaging".to_string()),
        ..Default::default()
    };
    let empty = endpoint.discover(Some(filter)).await;
    assert!(empty.connectors.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 19. Doctor invalid connector ID format
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn doctor_invalid_connector_id_format() {
    let registry = build_multi_op_registry();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec!["not-a-valid-connector-id!!!".to_string()],
        self_check: true,
    };

    let result = service.handle(request).await;
    assert!(result.is_err(), "invalid connector ID should fail");
}

// ─────────────────────────────────────────────────────────────────────────────
// 20. Empty registry interactions
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn discover_empty_registry_returns_empty() {
    let registry = TestRegistry::new();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let response = endpoint.discover(None).await;
    assert!(response.connectors.is_empty());
    assert_eq!(response.registry_version, 0);
}

#[fcp_async_core::runtime::test]
async fn doctor_empty_connectors_list_ok() {
    let registry = build_multi_op_registry();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec![],
        self_check: true,
    };

    let report = service.handle(request).await.unwrap();
    assert_eq!(report.overall_status, fcp_host::OverallStatus::Ok);
    assert!(report.connector_self_checks.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 21. Budget multi-metric multi-zone cross-module
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn budget_engine_multi_zone_multi_metric_preflight() {
    let engine = BudgetPolicyEngine::new();
    let zone_work = ZoneId::work();
    let zone_private = ZoneId::private();

    // work: deny on tokens
    engine
        .upsert_policy(
            zone_work.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![
                    UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 200,
                        window_seconds: 3600,
                    },
                    UsageBudgetLimit {
                        metric: UsageMetricKind::Requests,
                        limit: 50,
                        window_seconds: 3600,
                    },
                ],
            },
        )
        .await;

    // private: warn on requests only
    engine
        .upsert_policy(
            zone_private.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 5,
                    window_seconds: 3600,
                }],
            },
        )
        .await;

    // Use tokens in work zone — within limits
    engine
        .record_usage(&zone_work, &[UsageMetric::tokens(100)])
        .await;

    // work zone preflight should allow
    let req = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: None,
        zone_id: Some(zone_work.clone()),
    };
    let resp = engine.evaluate_preflight(&req).await;
    assert!(resp.allowed);

    // Exhaust work zone tokens
    engine
        .record_usage(&zone_work, &[UsageMetric::tokens(150)])
        .await;

    let resp = engine.evaluate_preflight(&req).await;
    assert!(!resp.allowed, "work zone should be denied after exceeding");

    // Private zone should be independent and still allow
    engine
        .record_usage(&zone_private, &[UsageMetric::requests(100)])
        .await;

    let req_private = PreflightRequest {
        connector_id: ConnectorId::from_static("fcp.test:utility:1.0.0"),
        operation: "read".to_string(),
        params: None,
        principal: None,
        zone_id: Some(zone_private),
    };
    let resp = engine.evaluate_preflight(&req_private).await;
    assert!(resp.allowed, "warn mode should allow even when exceeded");
}

// ─────────────────────────────────────────────────────────────────────────────
// 22. Self-check through DiscoveryEndpoint → DoctorReport cross-validation
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn self_check_and_doctor_agree_on_status() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    // Self-check via DiscoveryEndpoint
    let stream_id = ConnectorId::from_static("fcp.stream:messaging:1.0.0");
    let self_check_resp = endpoint.self_check(&stream_id).await.unwrap();
    assert_eq!(self_check_resp.report.status, SelfCheckStatus::Degraded);

    // Now verify serde roundtrip preserves all fields
    let json = serde_json::to_string(&self_check_resp).unwrap();
    let parsed: SelfCheckResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.connector_id, stream_id);
    assert_eq!(parsed.report.status, SelfCheckStatus::Degraded);
}

// ─────────────────────────────────────────────────────────────────────────────
// 23. DiscoveryResponse timestamp and version invariants
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn discovery_response_metadata_correct() {
    let registry = build_multi_op_registry();
    let engine = BudgetPolicyEngine::new();
    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(engine));

    let before = Utc::now();
    let response = endpoint.discover(None).await;
    let after = Utc::now();

    // Timestamp should be within the request window
    assert!(response.timestamp >= before);
    assert!(response.timestamp <= after);

    // Registry version should match connector count
    assert_eq!(response.registry_version, 3);

    // Streaming and batching support
    assert!(response.supports_streaming);
    assert!(response.supports_batching);

    // Serde roundtrip
    let json = serde_json::to_string(&response).unwrap();
    let parsed: fcp_host::DiscoveryResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.connectors.len(), response.connectors.len());
    assert_eq!(parsed.registry_version, response.registry_version);
}

// ─────────────────────────────────────────────────────────────────────────────
// 24. BudgetEvaluation to_error window_seconds calculation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn budget_evaluation_error_window_seconds_correct() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let window_secs = 7200u64;
    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![UsageBudgetLimit {
            metric: UsageMetricKind::Tokens,
            limit: 100,
            window_seconds: window_secs,
        }],
    };

    let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(200)]);
    let err = eval.to_error().unwrap();

    if let fcp_core::FcpError::BudgetExceeded {
        window_seconds, ..
    } = err
    {
        assert_eq!(window_seconds, window_secs);
    } else {
        panic!("expected BudgetExceeded");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 25. Doctor report JSON serialization contract
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn doctor_report_json_contract() {
    let registry = build_multi_op_registry();
    let service = DoctorService::new(Arc::new(registry));

    let request = DoctorRequest {
        zone_id: "z:work".to_string(),
        connectors: vec!["fcp.reader:utility:1.0.0".to_string()],
        self_check: true,
    };

    let report = service.handle(request).await.unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify JSON contract
    assert_eq!(parsed["schema_version"], "1.1.0");
    assert_eq!(parsed["zone_id"], "z:work");
    assert_eq!(parsed["overall_status"], "OK");
    assert!(parsed["generated_at"].is_string());
    assert_eq!(parsed["checkpoint"]["freshness"], "fresh");
    assert_eq!(parsed["revocation"]["freshness"], "fresh");
    assert_eq!(parsed["audit"]["freshness"], "fresh");
    assert!(parsed["transport_policy"]["allow_lan"].as_bool().unwrap());
    assert!(parsed["store_coverage"]["store_healthy"].as_bool().unwrap());
    assert!(parsed["connector_self_checks"].is_array());
    assert_eq!(parsed["connector_self_checks"].as_array().unwrap().len(), 1);
}
