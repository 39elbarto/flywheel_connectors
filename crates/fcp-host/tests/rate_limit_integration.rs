//! Integration tests for rate limit declarations in fcp-host.
//!
//! Tests that validate:
//! - Host aggregates RateLimitDeclarations from multiple connectors
//! - Introspection exposes per-tool rate limits
//! - ToolDescriptor includes correct rate limit pool references
//!
//! Bead: bd-1idx

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, ConnectorHealth, ConnectorId, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RateLimit, RateLimitConfig, RateLimitDeclarations,
    RateLimitEnforcement, RateLimitPool, RateLimitScope, RateLimitUnit, RiskLevel, SafetyTier,
    SelfCheckReport,
};
use fcp_host::{
    ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint, PolicyEngine,
    PreflightRequest, PreflightResponse,
};

// ─────────────────────────────────────────────────────────────────────────────
// Mock Implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Mock connector registry with configurable connectors and rate limits.
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

    fn add_connector(
        &mut self,
        id: ConnectorId,
        name: &str,
        operations: Vec<OperationInfo>,
        rate_limits: Option<RateLimitDeclarations>,
    ) {
        let summary = ConnectorSummary {
            id: id.clone(),
            name: name.to_string(),
            description: Some(format!("{name} test connector")),
            version: semver::Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: operations.len() as u32,
            max_safety_tier: SafetyTier::Safe,
            enabled: true,
            health: ConnectorHealth::healthy(),
            last_health_check: Some(chrono::Utc::now()),
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
                rate_limits,
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
        self.connectors.get(id)?;
        Some(SelfCheckReport::ok())
    }

    fn version(&self) -> u64 {
        self.version
    }
}

/// Mock policy engine that always allows.
struct MockPolicyEngine;

#[async_trait]
impl PolicyEngine for MockPolicyEngine {
    async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
        PreflightResponse::allowed()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_rate_limit_pool(id: &str, requests: u32, unit: RateLimitUnit) -> RateLimitPool {
    RateLimitPool {
        id: id.to_string(),
        description: format!("{id} rate limit pool"),
        config: RateLimitConfig {
            requests,
            window: Duration::from_secs(60),
            burst: Some(requests / 10),
            unit,
        },
        enforcement: RateLimitEnforcement::Hard,
        scope: RateLimitScope::Credential,
    }
}

fn make_operation(name: &str, rate_limit_scope: Option<&str>) -> OperationInfo {
    OperationInfo {
        id: OperationId::new(name).expect("valid operation id"),
        summary: format!("{name} operation"),
        description: Some(format!("Detailed description of {name}")),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: serde_json::json!({"type": "object"}),
        capability: CapabilityId::new(format!("cap.test.{name}")).expect("valid capability id"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::None,
        ai_hints: AgentHint {
            when_to_use: format!("Use {name} operation"),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
        },
        rate_limit: rate_limit_scope.map(|scope| RateLimit {
            max: 100,
            per_ms: 60000,
            burst: Some(10),
            scope: Some(scope.to_string()),
            pool_name: None,
        }),
        requires_approval: Some(ApprovalMode::None),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration Tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_introspect_returns_rate_limits() {
    let mut registry = MockConnectorRegistry::new();

    // Create a connector with rate limits
    let discord_id = ConnectorId::new("discord", "fcp", "v1").unwrap();
    let discord_limits = RateLimitDeclarations {
        limits: vec![make_rate_limit_pool(
            "discord_api",
            50,
            RateLimitUnit::Requests,
        )],
        tool_pool_map: HashMap::from([
            ("send_message".to_string(), vec!["discord_api".to_string()]),
            ("edit_message".to_string(), vec!["discord_api".to_string()]),
        ]),
    };
    registry.add_connector(
        discord_id.clone(),
        "Discord",
        vec![
            make_operation("send_message", Some("discord_api")),
            make_operation("edit_message", Some("discord_api")),
        ],
        Some(discord_limits),
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));
    let response = endpoint.introspect(&discord_id).await.unwrap();

    // Verify rate limits are present in introspection response
    assert!(response.rate_limits.is_some());
    let rate_limits = response.rate_limits.unwrap();
    assert_eq!(rate_limits.limits.len(), 1);
    assert_eq!(rate_limits.limits[0].id, "discord_api");
    assert_eq!(rate_limits.limits[0].config.requests, 50);

    // Verify tool descriptors include rate limit references
    assert_eq!(response.tools.len(), 2);
    for tool in &response.tools {
        assert!(
            tool.rate_limits.contains(&"discord_api".to_string()),
            "Tool {} should reference discord_api rate limit",
            tool.name
        );
        assert_eq!(tool.risk_level, RiskLevel::Low);
        assert_eq!(tool.safety_tier, SafetyTier::Safe);
        assert_eq!(tool.idempotency, IdempotencyClass::None);
        assert_eq!(tool.approval_mode, Some(ApprovalMode::None));
        assert!(tool.ai_hints.is_some());
    }
}

#[tokio::test]
async fn test_introspect_connector_without_rate_limits() {
    let mut registry = MockConnectorRegistry::new();

    // Create a connector without rate limits
    let echo_id = ConnectorId::new("echo", "fcp", "v1").unwrap();
    registry.add_connector(
        echo_id.clone(),
        "Echo",
        vec![make_operation("echo", None)],
        None, // No rate limits
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));
    let response = endpoint.introspect(&echo_id).await.unwrap();

    // Rate limits should be None
    assert!(response.rate_limits.is_none());

    // Tools should have empty rate_limits vec
    assert_eq!(response.tools.len(), 1);
    assert!(response.tools[0].rate_limits.is_empty());
}

#[tokio::test]
async fn test_multiple_connectors_with_different_rate_limits() {
    let mut registry = MockConnectorRegistry::new();

    // Discord connector with request-based limits
    let discord_id = ConnectorId::new("discord", "fcp", "v1").unwrap();
    let discord_limits = RateLimitDeclarations {
        limits: vec![make_rate_limit_pool(
            "discord_api",
            50,
            RateLimitUnit::Requests,
        )],
        tool_pool_map: HashMap::from([(
            "send_message".to_string(),
            vec!["discord_api".to_string()],
        )]),
    };
    registry.add_connector(
        discord_id.clone(),
        "Discord",
        vec![make_operation("send_message", Some("discord_api"))],
        Some(discord_limits),
    );

    // OpenAI connector with token-based limits
    let openai_id = ConnectorId::new("openai", "fcp", "v1").unwrap();
    let openai_limits = RateLimitDeclarations {
        limits: vec![
            make_rate_limit_pool("openai_rpm", 60, RateLimitUnit::Requests),
            make_rate_limit_pool("openai_tpm", 100000, RateLimitUnit::Tokens),
        ],
        tool_pool_map: HashMap::from([(
            "chat_completion".to_string(),
            vec!["openai_rpm".to_string(), "openai_tpm".to_string()],
        )]),
    };
    registry.add_connector(
        openai_id.clone(),
        "OpenAI",
        vec![make_operation("chat_completion", Some("openai_rpm"))],
        Some(openai_limits),
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));

    // Verify Discord
    let discord_response = endpoint.introspect(&discord_id).await.unwrap();
    let discord_limits = discord_response.rate_limits.unwrap();
    assert_eq!(discord_limits.limits.len(), 1);
    assert_eq!(
        discord_limits.limits[0].config.unit,
        RateLimitUnit::Requests
    );

    // Verify OpenAI
    let openai_response = endpoint.introspect(&openai_id).await.unwrap();
    let openai_limits = openai_response.rate_limits.unwrap();
    assert_eq!(openai_limits.limits.len(), 2);

    // Verify one is requests-based and one is token-based
    let has_requests = openai_limits
        .limits
        .iter()
        .any(|l| l.config.unit == RateLimitUnit::Requests);
    let has_tokens = openai_limits
        .limits
        .iter()
        .any(|l| l.config.unit == RateLimitUnit::Tokens);
    assert!(has_requests, "OpenAI should have request-based limit");
    assert!(has_tokens, "OpenAI should have token-based limit");
}

#[tokio::test]
async fn test_tool_with_multiple_rate_limit_pools() {
    let mut registry = MockConnectorRegistry::new();

    // Connector where one tool consumes multiple pools
    let api_id = ConnectorId::new("multipool", "fcp", "v1").unwrap();
    let limits = RateLimitDeclarations {
        limits: vec![
            make_rate_limit_pool("requests", 100, RateLimitUnit::Requests),
            make_rate_limit_pool("bandwidth", 1000000, RateLimitUnit::Bytes),
        ],
        tool_pool_map: HashMap::from([(
            "upload".to_string(),
            vec!["requests".to_string(), "bandwidth".to_string()],
        )]),
    };
    registry.add_connector(
        api_id.clone(),
        "MultiPool",
        vec![make_operation("upload", Some("requests"))],
        Some(limits),
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));
    let response = endpoint.introspect(&api_id).await.unwrap();

    let rate_limits = response.rate_limits.unwrap();
    assert_eq!(rate_limits.limits.len(), 2);

    // Verify tool_pool_map has both pools for upload
    let upload_pools = rate_limits.tool_pool_map.get("upload").unwrap();
    assert_eq!(upload_pools.len(), 2);
    assert!(upload_pools.contains(&"requests".to_string()));
    assert!(upload_pools.contains(&"bandwidth".to_string()));
}

#[tokio::test]
async fn test_rate_limit_enforcement_modes() {
    let mut registry = MockConnectorRegistry::new();

    let connector_id = ConnectorId::new("enforce", "fcp", "v1").unwrap();
    let limits = RateLimitDeclarations {
        limits: vec![
            RateLimitPool {
                id: "hard_limit".to_string(),
                description: "Hard enforcement".to_string(),
                config: RateLimitConfig {
                    requests: 10,
                    window: Duration::from_secs(60),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Hard,
                scope: RateLimitScope::Instance,
            },
            RateLimitPool {
                id: "soft_limit".to_string(),
                description: "Soft enforcement".to_string(),
                config: RateLimitConfig {
                    requests: 100,
                    window: Duration::from_secs(60),
                    burst: Some(10),
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Soft,
                scope: RateLimitScope::Credential,
            },
            RateLimitPool {
                id: "advisory_limit".to_string(),
                description: "Advisory only".to_string(),
                config: RateLimitConfig {
                    requests: 1000,
                    window: Duration::from_secs(3600),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Advisory,
                scope: RateLimitScope::Global,
            },
        ],
        tool_pool_map: HashMap::from([
            ("critical_op".to_string(), vec!["hard_limit".to_string()]),
            ("normal_op".to_string(), vec!["soft_limit".to_string()]),
            (
                "low_priority_op".to_string(),
                vec!["advisory_limit".to_string()],
            ),
        ]),
    };

    registry.add_connector(
        connector_id.clone(),
        "EnforcementTest",
        vec![
            make_operation("critical_op", Some("hard_limit")),
            make_operation("normal_op", Some("soft_limit")),
            make_operation("low_priority_op", Some("advisory_limit")),
        ],
        Some(limits),
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));
    let response = endpoint.introspect(&connector_id).await.unwrap();

    let rate_limits = response.rate_limits.unwrap();
    assert_eq!(rate_limits.limits.len(), 3);

    // Verify enforcement modes are preserved
    let hard = rate_limits
        .limits
        .iter()
        .find(|l| l.id == "hard_limit")
        .unwrap();
    assert_eq!(hard.enforcement, RateLimitEnforcement::Hard);

    let soft = rate_limits
        .limits
        .iter()
        .find(|l| l.id == "soft_limit")
        .unwrap();
    assert_eq!(soft.enforcement, RateLimitEnforcement::Soft);

    let advisory = rate_limits
        .limits
        .iter()
        .find(|l| l.id == "advisory_limit")
        .unwrap();
    assert_eq!(advisory.enforcement, RateLimitEnforcement::Advisory);
}

#[tokio::test]
async fn test_rate_limit_scopes() {
    let mut registry = MockConnectorRegistry::new();

    let connector_id = ConnectorId::new("scopes", "fcp", "v1").unwrap();
    let limits = RateLimitDeclarations {
        limits: vec![
            RateLimitPool {
                id: "instance_pool".to_string(),
                description: "Per instance".to_string(),
                config: RateLimitConfig {
                    requests: 10,
                    window: Duration::from_secs(1),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Hard,
                scope: RateLimitScope::Instance,
            },
            RateLimitPool {
                id: "credential_pool".to_string(),
                description: "Per credential/API key".to_string(),
                config: RateLimitConfig {
                    requests: 100,
                    window: Duration::from_secs(60),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Hard,
                scope: RateLimitScope::Credential,
            },
            RateLimitPool {
                id: "global_pool".to_string(),
                description: "Global across all instances".to_string(),
                config: RateLimitConfig {
                    requests: 10000,
                    window: Duration::from_secs(86400),
                    burst: None,
                    unit: RateLimitUnit::Requests,
                },
                enforcement: RateLimitEnforcement::Advisory,
                scope: RateLimitScope::Global,
            },
        ],
        tool_pool_map: HashMap::new(),
    };

    registry.add_connector(connector_id.clone(), "ScopesTest", vec![], Some(limits));

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));
    let response = endpoint.introspect(&connector_id).await.unwrap();

    let rate_limits = response.rate_limits.unwrap();

    // Verify all scopes are preserved
    let instance = rate_limits
        .limits
        .iter()
        .find(|l| l.id == "instance_pool")
        .unwrap();
    assert_eq!(instance.scope, RateLimitScope::Instance);

    let credential = rate_limits
        .limits
        .iter()
        .find(|l| l.id == "credential_pool")
        .unwrap();
    assert_eq!(credential.scope, RateLimitScope::Credential);

    let global = rate_limits
        .limits
        .iter()
        .find(|l| l.id == "global_pool")
        .unwrap();
    assert_eq!(global.scope, RateLimitScope::Global);
}

#[tokio::test]
async fn test_discovery_lists_connectors_regardless_of_rate_limits() {
    let mut registry = MockConnectorRegistry::new();

    // Add connector with rate limits
    let with_limits_id = ConnectorId::new("with_limits", "fcp", "v1").unwrap();
    registry.add_connector(
        with_limits_id,
        "WithLimits",
        vec![],
        Some(RateLimitDeclarations {
            limits: vec![make_rate_limit_pool("pool", 10, RateLimitUnit::Requests)],
            tool_pool_map: HashMap::new(),
        }),
    );

    // Add connector without rate limits
    let no_limits_id = ConnectorId::new("no_limits", "fcp", "v1").unwrap();
    registry.add_connector(no_limits_id, "NoLimits", vec![], None);

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));
    let discovery = endpoint.discover(None).await;

    // Both connectors should appear in discovery
    assert_eq!(discovery.connectors.len(), 2);
}

#[tokio::test]
async fn test_rate_limit_json_serialization_roundtrip() {
    let mut registry = MockConnectorRegistry::new();

    let connector_id = ConnectorId::new("serialize", "fcp", "v1").unwrap();
    let original_limits = RateLimitDeclarations {
        limits: vec![
            make_rate_limit_pool("api_calls", 100, RateLimitUnit::Requests),
            make_rate_limit_pool("tokens", 50000, RateLimitUnit::Tokens),
        ],
        tool_pool_map: HashMap::from([
            ("op1".to_string(), vec!["api_calls".to_string()]),
            (
                "op2".to_string(),
                vec!["api_calls".to_string(), "tokens".to_string()],
            ),
        ]),
    };

    registry.add_connector(
        connector_id.clone(),
        "SerializeTest",
        vec![
            make_operation("op1", Some("api_calls")),
            make_operation("op2", Some("api_calls")),
        ],
        Some(original_limits.clone()),
    );

    let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(MockPolicyEngine));
    let response = endpoint.introspect(&connector_id).await.unwrap();

    // Serialize to JSON and back
    let json = serde_json::to_string(&response).unwrap();
    let parsed: fcp_host::IntrospectionResponse = serde_json::from_str(&json).unwrap();

    // Verify rate limits survived roundtrip
    assert!(parsed.rate_limits.is_some());
    let parsed_limits = parsed.rate_limits.unwrap();
    assert_eq!(parsed_limits.limits.len(), original_limits.limits.len());
    assert_eq!(
        parsed_limits.tool_pool_map.len(),
        original_limits.tool_pool_map.len()
    );
}
