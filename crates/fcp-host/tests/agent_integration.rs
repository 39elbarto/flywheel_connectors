//! Agent integration tests for discovery/introspection/tool descriptors.
//!
//! Verifies agent-facing schemas include required fields and MCP mapping.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, ConnectorHealth, ConnectorId, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RateLimitDeclarations, RiskLevel, SafetyTier,
    SelfCheckReport,
};
use fcp_host::{
    ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint, PolicyEngine,
    PreflightRequest, PreflightResponse,
};
use fcp_testkit::LogCapture;
use serde_json::json;

struct MockConnectorRegistry {
    connectors: HashMap<ConnectorId, MockConnectorData>,
    version: u64,
}

struct MockConnectorData {
    summary: ConnectorSummary,
    introspection: Introspection,
    archetype: ConnectorArchetype,
    rate_limits: Option<RateLimitDeclarations>,
}

impl MockConnectorRegistry {
    fn new() -> Self {
        Self {
            connectors: HashMap::new(),
            version: 1,
        }
    }

    fn add_connector(&mut self, id: ConnectorId, operations: Vec<OperationInfo>) {
        let summary = ConnectorSummary {
            id: id.clone(),
            name: "Agent Test Connector".to_string(),
            description: Some("Connector used for agent integration tests".to_string()),
            version: semver::Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: operations.len() as u32,
            max_safety_tier: SafetyTier::Risky,
            enabled: true,
            health: ConnectorHealth::healthy(),
            last_health_check: Some(Utc::now()),
        };

        let introspection = Introspection {
            operations,
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        self.connectors.insert(
            id,
            MockConnectorData {
                summary,
                introspection,
                archetype: ConnectorArchetype::RequestResponse,
                rate_limits: None,
            },
        );
    }
}

#[async_trait]
impl ConnectorRegistry for MockConnectorRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        self.connectors
            .values()
            .map(|c| c.summary.clone())
            .collect()
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        self.connectors.get(id).map(|c| c.summary.clone())
    }

    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
        self.connectors.get(id).map(|c| c.introspection.clone())
    }

    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype> {
        self.connectors.get(id).map(|c| c.archetype)
    }

    async fn get_rate_limits(&self, id: &ConnectorId) -> Option<RateLimitDeclarations> {
        self.connectors.get(id).and_then(|c| c.rate_limits.clone())
    }

    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
        self.connectors.get(id).map(|_| SelfCheckReport::ok())
    }

    fn version(&self) -> u64 {
        self.version
    }
}

struct AllowPolicy;

#[async_trait]
impl PolicyEngine for AllowPolicy {
    async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
        PreflightResponse::allowed()
    }
}

fn make_operation(id: &str) -> OperationInfo {
    OperationInfo {
        id: OperationId::new(id).expect("valid operation id"),
        summary: format!("Summary for {id}"),
        description: Some(format!("Detailed description for {id}")),
        input_schema: json!({
            "type": "object",
            "properties": {
                "value": {"type": "string"}
            },
            "required": ["value"]
        }),
        output_schema: json!({
            "type": "object",
            "properties": {
                "result": {"type": "string"}
            }
        }),
        capability: CapabilityId::new("agent.test:run").expect("capability"),
        risk_level: RiskLevel::Medium,
        safety_tier: SafetyTier::Risky,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use in agent integration tests".to_string(),
            common_mistakes: vec!["Missing value".to_string()],
            examples: vec![r#"{"value": "example"}"#.to_string()],
            related: vec![CapabilityId::new("agent.test:related").expect("capability")],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::Interactive),
    }
}

#[tokio::test]
async fn introspection_includes_required_fields_for_agents() {
    let start = Instant::now();
    let capture = LogCapture::new();
    let correlation_id = format!("agent-introspection-{}", std::process::id());

    let connector_id = ConnectorId::new("agent-test", "fcp", "v1").expect("connector id");
    let mut registry = MockConnectorRegistry::new();
    registry.add_connector(
        connector_id.clone(),
        vec![make_operation("agent.test.execute")],
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
    let response = endpoint
        .introspect(&connector_id)
        .await
        .expect("introspect");

    assert_eq!(response.introspection.operations.len(), 1);
    let op = &response.introspection.operations[0];
    assert_eq!(op.capability.as_str(), "agent.test:run");
    assert_eq!(op.risk_level, RiskLevel::Medium);
    assert_eq!(op.safety_tier, SafetyTier::Risky);
    assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
    assert!(op.input_schema.get("type").is_some());
    assert!(op.output_schema.get("type").is_some());

    let tool = response.tools.first().expect("tool descriptor");
    assert_eq!(tool.name, op.id.to_string());
    assert_eq!(tool.capability.as_str(), op.capability.as_str());
    assert_eq!(tool.risk_level, op.risk_level);
    assert_eq!(tool.safety_tier, op.safety_tier);
    assert_eq!(tool.idempotency, op.idempotency);
    assert_eq!(tool.approval_mode, Some(ApprovalMode::Interactive));
    assert!(tool.ai_hints.is_some());

    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let log = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": "introspection_includes_required_fields_for_agents",
        "module": "fcp-host::agent_integration",
        "phase": "verify",
        "correlation_id": correlation_id,
        "result": "pass",
        "duration_ms": duration_ms,
        "assertions": { "passed": 14, "failed": 0 },
        "details": { "operation_id": op.id.to_string() }
    });
    capture.push_value(&log).expect("log entry");
    capture.assert_valid();
}
