//! Discovery API for agents to find and introspect connectors.
//!
//! Based on bead `bd-2h7e`: [FCP2] Host Discovery Endpoint.
//!
//! Provides endpoints:
//! - `discover` - List all connectors with summary
//! - `introspect` - Get tool descriptors for one connector
//! - `preflight` - Check authz without execution
//! - `health` - Host + connector health

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, ConnectorHealth, ConnectorId, IdempotencyClass,
    Introspection, OperationInfo, RateLimitDeclarations, RiskLevel, SafetyTier, SelfCheckReport,
    UsageBudgetSnapshot, ZoneId,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{HostError, HostResult};

// ─────────────────────────────────────────────────────────────────────────────
// Discovery Types
// ─────────────────────────────────────────────────────────────────────────────

/// Filter for discovery requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryFilter {
    /// Filter by category (e.g., "messaging", "storage").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Filter by maximum safety tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_risk: Option<SafetyTier>,

    /// Filter by health status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthFilter>,
}

/// Health filter options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthFilter {
    /// Only healthy connectors.
    Healthy,
    /// Only degraded connectors.
    Degraded,
    /// Only available (healthy or degraded).
    Available,
    /// All connectors including unavailable.
    All,
}

impl DiscoveryFilter {
    /// Check if a connector summary matches this filter.
    #[must_use]
    pub fn matches(&self, connector: &ConnectorSummary) -> bool {
        // Category filter
        if let Some(ref cat) = self.category
            && !connector.categories.iter().any(|c| c == cat)
        {
            return false;
        }

        // Risk/safety tier filter
        if let Some(max_risk) = self.max_risk
            && !connector.max_safety_tier.is_at_most(max_risk)
        {
            return false;
        }

        // Health filter
        if let Some(health_filter) = self.health {
            match health_filter {
                HealthFilter::Healthy => {
                    if !connector.health.is_healthy() {
                        return false;
                    }
                }
                HealthFilter::Degraded => {
                    if !matches!(connector.health, ConnectorHealth::Degraded { .. }) {
                        return false;
                    }
                }
                HealthFilter::Available => {
                    if !connector.health.is_available() {
                        return false;
                    }
                }
                HealthFilter::All => {} // No filter
            }
        }

        true
    }
}

/// Summary information about a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorSummary {
    /// Connector identifier.
    pub id: ConnectorId,

    /// Human-readable name.
    pub name: String,

    /// Brief description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Semantic version.
    pub version: semver::Version,

    /// Categories this connector belongs to.
    #[serde(default)]
    pub categories: Vec<String>,

    /// Number of tools/operations available.
    pub tool_count: u32,

    /// Maximum safety tier across all operations.
    pub max_safety_tier: SafetyTier,

    /// Whether the connector is enabled.
    pub enabled: bool,

    /// Current health status.
    pub health: ConnectorHealth,

    /// Last health check timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_health_check: Option<DateTime<Utc>>,
}

/// Response from the discovery endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    /// List of connectors matching the filter.
    pub connectors: Vec<ConnectorSummary>,

    /// Registry version (for caching/ETag).
    pub registry_version: u64,

    /// Whether the host supports streaming events.
    pub supports_streaming: bool,

    /// Whether the host supports batch invoke.
    pub supports_batching: bool,

    /// Server timestamp.
    pub timestamp: DateTime<Utc>,
}

impl DiscoveryResponse {
    /// Create a new discovery response.
    #[must_use]
    pub fn new(connectors: Vec<ConnectorSummary>, registry_version: u64) -> Self {
        Self {
            connectors,
            registry_version,
            supports_streaming: true,
            supports_batching: true,
            timestamp: Utc::now(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Introspection Types
// ─────────────────────────────────────────────────────────────────────────────

/// Connector archetype classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorArchetype {
    /// Request-response (REST, GraphQL).
    RequestResponse,
    /// Streaming (WebSocket, SSE).
    Streaming,
    /// Bidirectional (WebSocket chat).
    Bidirectional,
    /// Polling (IMAP, RSS).
    Polling,
    /// Webhook (GitHub, Stripe).
    Webhook,
}

/// Response from the introspect endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Connector summary.
    pub connector: ConnectorSummary,

    /// Tool descriptors (operations).
    pub tools: Vec<ToolDescriptor>,

    /// Rate limit declarations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<RateLimitDeclarations>,

    /// Connector archetype.
    pub archetype: ConnectorArchetype,

    /// Full introspection data.
    pub introspection: Introspection,
}

/// Response from a connector self-check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Self-check report from the connector.
    pub report: SelfCheckReport,

    /// Timestamp when the self-check was executed.
    pub checked_at: DateTime<Utc>,
}

/// MCP-compatible tool descriptor.
///
/// Per SEP-1382 and MCP 2025 spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// Tool name (operation ID).
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// JSON Schema for input parameters.
    pub input_schema: serde_json::Value,

    /// JSON Schema for output.
    pub output_schema: serde_json::Value,

    /// Required capability.
    pub capability: CapabilityId,

    /// Risk level (for agent UX).
    pub risk_level: RiskLevel,

    /// Safety tier.
    pub safety_tier: SafetyTier,

    /// Idempotency class.
    pub idempotency: IdempotencyClass,

    /// Approval mode required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,

    /// Whether this tool requires confirmation.
    pub requires_confirmation: bool,

    /// Whether this tool is idempotent.
    pub idempotent: bool,

    /// Whether this tool supports simulate.
    pub supports_simulate: bool,

    /// Latency hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_hint: Option<LatencyHint>,

    /// Rate limit names that apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<String>,

    /// Example invocations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<ToolExample>,

    /// AI agent hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_hints: Option<AgentHint>,
}

impl From<&OperationInfo> for ToolDescriptor {
    fn from(op: &OperationInfo) -> Self {
        Self {
            name: op.id.to_string(),
            description: op.description.clone().unwrap_or_else(|| op.summary.clone()),
            input_schema: op.input_schema.clone(),
            output_schema: op.output_schema.clone(),
            capability: op.capability.clone(),
            risk_level: op.risk_level,
            safety_tier: op.safety_tier,
            idempotency: op.idempotency,
            approval_mode: op.requires_approval,
            requires_confirmation: op.requires_approval.is_some(),
            idempotent: matches!(
                op.idempotency,
                fcp_core::IdempotencyClass::Strict | fcp_core::IdempotencyClass::BestEffort
            ),
            supports_simulate: true, // Assume all support simulate by default
            latency_hint: None,
            rate_limits: op.rate_limit.as_ref().map_or_else(Vec::new, |rl| {
                rl.pool_name
                    .clone()
                    .or_else(|| rl.scope.clone())
                    .map_or_else(Vec::new, |value| vec![value])
            }),
            examples: op
                .ai_hints
                .examples
                .iter()
                .map(|e| ToolExample {
                    description: None,
                    input: serde_json::from_str(e).unwrap_or_else(|_| serde_json::json!({})),
                    output: None,
                })
                .collect(),
            ai_hints: if op.ai_hints.when_to_use.is_empty()
                && op.ai_hints.common_mistakes.is_empty()
                && op.ai_hints.examples.is_empty()
                && op.ai_hints.related.is_empty()
            {
                None
            } else {
                Some(op.ai_hints.clone())
            },
        }
    }
}

impl ToolDescriptor {
    pub(crate) fn from_operation(
        op: &OperationInfo,
        declarations: Option<&RateLimitDeclarations>,
    ) -> Self {
        let mut tool = Self::from(op);
        if let Some(decls) = declarations
            && let Some(pools) = decls.tool_pool_map.get(op.id.as_str())
        {
            tool.rate_limits.clone_from(pools);
        }
        tool
    }
}

/// Latency hint for tool execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyHint {
    /// Fast (< 100ms).
    Fast,
    /// Medium (100ms - 1s).
    Medium,
    /// Slow (1s - 10s).
    Slow,
    /// Very slow (> 10s).
    VerySlow,
}

/// Example tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExample {
    /// Description of what this example demonstrates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Example input.
    pub input: serde_json::Value,

    /// Example output (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Preflight Types
// ─────────────────────────────────────────────────────────────────────────────

/// Request for preflight authorization check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightRequest {
    /// Target connector.
    pub connector_id: ConnectorId,

    /// Operation to check.
    pub operation: String,

    /// Proposed input parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,

    /// Principal making the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,

    /// Zone the operation would execute in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<ZoneId>,
}

/// Response from preflight check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResponse {
    /// Whether the operation would be allowed.
    pub allowed: bool,

    /// Reason if not allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Required capabilities that are missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,

    /// Rate limit status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<PreflightRateLimit>,

    /// Estimated cost (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost: Option<EstimatedCost>,

    /// Usage budget snapshot (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_status: Option<UsageBudgetSnapshot>,
}

impl PreflightResponse {
    /// Create an allowed response.
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            allowed: true,
            reason: None,
            missing_capabilities: Vec::new(),
            rate_limit: None,
            estimated_cost: None,
            budget_status: None,
        }
    }

    /// Create a denied response.
    #[must_use]
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            missing_capabilities: vec![],
            rate_limit: None,
            estimated_cost: None,
            budget_status: None,
        }
    }
}

/// Rate limit info for preflight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightRateLimit {
    /// Whether currently rate limited.
    pub limited: bool,

    /// Requests remaining.
    pub remaining: u32,

    /// Window reset timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<DateTime<Utc>>,
}

/// Estimated cost for an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimatedCost {
    /// Estimated API calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_calls: Option<u32>,

    /// Estimated tokens (for LLM connectors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u32>,

    /// Estimated monetary cost (USD cents).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_cents: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Types
// ─────────────────────────────────────────────────────────────────────────────

/// Host-level health response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostHealthResponse {
    /// Overall host health.
    pub status: HostHealthStatus,

    /// Per-connector health.
    pub connectors: HashMap<ConnectorId, ConnectorHealth>,

    /// Host uptime in seconds.
    pub uptime_seconds: u64,

    /// Number of active connections.
    pub active_connections: u32,

    /// Timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Host health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostHealthStatus {
    /// All systems operational.
    Healthy,
    /// Some connectors degraded.
    Degraded,
    /// Major issues.
    Unhealthy,
}

// ─────────────────────────────────────────────────────────────────────────────
// SafetyTier Extensions
// ─────────────────────────────────────────────────────────────────────────────

/// Extension trait for `SafetyTier` comparisons.
pub trait SafetyTierExt {
    /// Check if this tier is at most the given level.
    fn is_at_most(&self, other: SafetyTier) -> bool;

    /// Get the numeric level (lower = safer).
    fn level(&self) -> u8;
}

impl SafetyTierExt for SafetyTier {
    fn is_at_most(&self, other: SafetyTier) -> bool {
        self.level() <= other.level()
    }

    fn level(&self) -> u8 {
        match self {
            Self::Safe => 0,
            Self::Risky => 1,
            Self::Dangerous => 2,
            Self::Critical => 3,
            Self::Forbidden => 4,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Registry Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for connector registry backends.
#[async_trait::async_trait]
pub trait ConnectorRegistry: Send + Sync {
    /// List all connector summaries.
    async fn list(&self) -> Vec<ConnectorSummary>;

    /// Get a specific connector summary by ID.
    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary>;

    /// Get full introspection for a connector.
    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection>;

    /// Get the archetype for a connector.
    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype>;

    /// Get rate limit declarations for a connector.
    async fn get_rate_limits(&self, id: &ConnectorId) -> Option<RateLimitDeclarations>;

    /// Run a connector self-check.
    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport>;

    /// Get the current registry version.
    fn version(&self) -> u64;
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Engine Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for policy evaluation.
#[async_trait::async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluate a preflight request.
    async fn evaluate_preflight(&self, request: &PreflightRequest) -> PreflightResponse;
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery Endpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Discovery endpoint implementation.
pub struct DiscoveryEndpoint<R, P> {
    registry: Arc<R>,
    policy_engine: Arc<P>,
    cache: DiscoveryCache,
}

impl<R, P> DiscoveryEndpoint<R, P>
where
    R: ConnectorRegistry,
    P: PolicyEngine,
{
    /// Create a new discovery endpoint.
    pub fn new(registry: Arc<R>, policy_engine: Arc<P>) -> Self {
        Self {
            registry,
            policy_engine,
            cache: DiscoveryCache::new(Duration::from_secs(30)),
        }
    }

    /// Create with custom cache TTL.
    pub fn with_cache_ttl(registry: Arc<R>, policy_engine: Arc<P>, ttl: Duration) -> Self {
        Self {
            registry,
            policy_engine,
            cache: DiscoveryCache::new(ttl),
        }
    }

    /// List all connectors (filtered).
    pub async fn discover(&self, filter: Option<DiscoveryFilter>) -> DiscoveryResponse {
        let connectors = self.cache.get_or_refresh(&*self.registry).await;

        let filtered = match filter {
            Some(f) => connectors.into_iter().filter(|c| f.matches(c)).collect(),
            None => connectors,
        };

        DiscoveryResponse::new(filtered, self.registry.version())
    }

    /// Introspect a single connector.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the connector or its
    /// introspection data is missing from the registry.
    pub async fn introspect(
        &self,
        connector_id: &ConnectorId,
    ) -> HostResult<IntrospectionResponse> {
        let summary = self
            .registry
            .get(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        let introspection = self
            .registry
            .get_introspection(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        let archetype = self
            .registry
            .get_archetype(connector_id)
            .await
            .unwrap_or(ConnectorArchetype::RequestResponse);

        let rate_limits = self.registry.get_rate_limits(connector_id).await;

        // Convert operations to tool descriptors
        let tools: Vec<ToolDescriptor> = introspection
            .operations
            .iter()
            .map(|op| ToolDescriptor::from_operation(op, rate_limits.as_ref()))
            .collect();

        Ok(IntrospectionResponse {
            connector: summary,
            tools,
            rate_limits,
            archetype,
            introspection,
        })
    }

    /// Run a connector self-check (read-only).
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the connector is missing.
    pub async fn self_check(&self, connector_id: &ConnectorId) -> HostResult<SelfCheckResponse> {
        let report = self
            .registry
            .self_check(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        Ok(SelfCheckResponse {
            connector_id: connector_id.clone(),
            report,
            checked_at: Utc::now(),
        })
    }

    /// Preflight authorization check.
    pub async fn preflight(&self, request: PreflightRequest) -> PreflightResponse {
        self.policy_engine.evaluate_preflight(&request).await
    }

    /// Invalidate the discovery cache.
    pub async fn invalidate_cache(&self) {
        self.cache.invalidate().await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery Cache
// ─────────────────────────────────────────────────────────────────────────────

/// Cache for discovery responses.
pub struct DiscoveryCache {
    /// Cached connector summaries.
    cache: RwLock<Option<CachedDiscovery>>,
    /// Time-to-live.
    ttl: Duration,
}

struct CachedDiscovery {
    connectors: Vec<ConnectorSummary>,
    cached_at: Instant,
}

impl DiscoveryCache {
    /// Create a new cache with the given TTL.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(None),
            ttl,
        }
    }

    /// Get cached connectors or refresh from registry.
    pub async fn get_or_refresh<R: ConnectorRegistry>(
        &self,
        registry: &R,
    ) -> Vec<ConnectorSummary> {
        // Try to read from cache
        {
            let read = self.cache.read().await;
            if let Some(ref cached) = *read
                && cached.cached_at.elapsed() < self.ttl
            {
                return cached.connectors.clone();
            }
        }

        // Cache miss or expired - refresh
        let connectors = registry.list().await;

        let mut write = self.cache.write().await;
        *write = Some(CachedDiscovery {
            connectors: connectors.clone(),
            cached_at: Instant::now(),
        });

        connectors
    }

    /// Invalidate the cache.
    pub async fn invalidate(&self) {
        let mut write = self.cache.write().await;
        *write = None;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::SelfCheckStatus;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Test SafetyTier extension
    #[test]
    fn safety_tier_level_ordering() {
        assert!(SafetyTier::Safe.level() < SafetyTier::Risky.level());
        assert!(SafetyTier::Risky.level() < SafetyTier::Dangerous.level());
        assert!(SafetyTier::Dangerous.level() < SafetyTier::Critical.level());
        assert!(SafetyTier::Critical.level() < SafetyTier::Forbidden.level());
    }

    #[test]
    fn safety_tier_is_at_most() {
        assert!(SafetyTier::Safe.is_at_most(SafetyTier::Safe));
        assert!(SafetyTier::Safe.is_at_most(SafetyTier::Risky));
        assert!(SafetyTier::Risky.is_at_most(SafetyTier::Dangerous));
        assert!(!SafetyTier::Dangerous.is_at_most(SafetyTier::Safe));
        assert!(!SafetyTier::Forbidden.is_at_most(SafetyTier::Critical));
    }

    // Test DiscoveryFilter
    fn make_summary(
        name: &str,
        archetype: &str,
        version: &str,
        categories: Vec<&str>,
        safety: SafetyTier,
        health: ConnectorHealth,
    ) -> ConnectorSummary {
        let id = ConnectorId::new(name, archetype, version).expect("valid connector id");
        ConnectorSummary {
            id,
            name: name.to_string(),
            description: None,
            version: semver::Version::new(1, 0, 0),
            categories: categories.into_iter().map(String::from).collect(),
            tool_count: 5,
            max_safety_tier: safety,
            enabled: true,
            health,
            last_health_check: Some(Utc::now()),
        }
    }

    #[test]
    fn filter_matches_no_filter() {
        let filter = DiscoveryFilter::default();
        let summary = make_summary(
            "test",
            "conn",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );

        assert!(filter.matches(&summary));
    }

    #[test]
    fn filter_matches_category() {
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            ..Default::default()
        };

        let messaging = make_summary(
            "test",
            "msg",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let storage = make_summary(
            "test",
            "store",
            "v1",
            vec!["storage"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );

        assert!(filter.matches(&messaging));
        assert!(!filter.matches(&storage));
    }

    #[test]
    fn filter_matches_risk() {
        let filter = DiscoveryFilter {
            max_risk: Some(SafetyTier::Risky),
            ..Default::default()
        };

        let safe = make_summary(
            "test",
            "safe",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let risky = make_summary(
            "test",
            "risky",
            "v1",
            vec![],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        let dangerous = make_summary(
            "test",
            "danger",
            "v1",
            vec![],
            SafetyTier::Dangerous,
            ConnectorHealth::healthy(),
        );

        assert!(filter.matches(&safe));
        assert!(filter.matches(&risky));
        assert!(!filter.matches(&dangerous));
    }

    #[test]
    fn filter_matches_health() {
        let healthy_filter = DiscoveryFilter {
            health: Some(HealthFilter::Healthy),
            ..Default::default()
        };

        let available_filter = DiscoveryFilter {
            health: Some(HealthFilter::Available),
            ..Default::default()
        };

        let healthy = make_summary(
            "test",
            "h",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let degraded = make_summary(
            "test",
            "d",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );
        let unavailable = make_summary(
            "test",
            "u",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::unavailable("down"),
        );

        assert!(healthy_filter.matches(&healthy));
        assert!(!healthy_filter.matches(&degraded));
        assert!(!healthy_filter.matches(&unavailable));

        assert!(available_filter.matches(&healthy));
        assert!(available_filter.matches(&degraded));
        assert!(!available_filter.matches(&unavailable));
    }

    // Test PreflightResponse
    #[test]
    fn preflight_response_allowed() {
        let resp = PreflightResponse::allowed();
        assert!(resp.allowed);
        assert!(resp.reason.is_none());
    }

    #[test]
    fn preflight_response_denied() {
        let resp = PreflightResponse::denied("insufficient permissions");
        assert!(!resp.allowed);
        assert_eq!(resp.reason.as_deref(), Some("insufficient permissions"));
    }

    // Test DiscoveryResponse
    #[test]
    fn discovery_response_new() {
        let connectors = vec![make_summary(
            "test",
            "a",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        )];
        let resp = DiscoveryResponse::new(connectors, 42);

        assert_eq!(resp.connectors.len(), 1);
        assert_eq!(resp.registry_version, 42);
        assert!(resp.supports_streaming);
        assert!(resp.supports_batching);
    }

    // Test serialization roundtrips
    #[test]
    fn discovery_filter_serialization() {
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            max_risk: Some(SafetyTier::Risky),
            health: Some(HealthFilter::Available),
        };

        let json = serde_json::to_string(&filter).unwrap();
        let parsed: DiscoveryFilter = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.category, filter.category);
        assert_eq!(parsed.max_risk, filter.max_risk);
        assert_eq!(parsed.health, filter.health);
    }

    #[test]
    fn connector_summary_serialization() {
        let summary = make_summary(
            "test",
            "serial",
            "v1",
            vec!["category1", "category2"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: ConnectorSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, summary.id);
        assert_eq!(parsed.name, summary.name);
        assert_eq!(parsed.categories, summary.categories);
        assert_eq!(parsed.max_safety_tier, summary.max_safety_tier);
    }

    #[test]
    fn tool_descriptor_serialization() {
        let tool = ToolDescriptor {
            name: "send_message".to_string(),
            description: "Send a message to a channel".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            capability: CapabilityId::new("cap.send_message").expect("capability"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            approval_mode: Some(ApprovalMode::Interactive),
            requires_confirmation: true,
            idempotent: false,
            supports_simulate: true,
            latency_hint: Some(LatencyHint::Fast),
            rate_limits: vec!["discord_api".to_string()],
            examples: vec![],
            ai_hints: Some(AgentHint {
                when_to_use: "Use for sending chat messages".to_string(),
                common_mistakes: vec!["Missing channel_id".to_string()],
                examples: vec![r#"{"channel_id":"123","content":"hi"}"#.to_string()],
                related: vec![CapabilityId::new("discord.delete_message").expect("capability")],
            }),
        };

        let json = serde_json::to_string(&tool).unwrap();
        let parsed: ToolDescriptor = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, tool.name);
        assert_eq!(parsed.safety_tier, tool.safety_tier);
        assert_eq!(parsed.latency_hint, tool.latency_hint);
    }

    #[test]
    fn health_filter_serialization() {
        for filter in [
            HealthFilter::Healthy,
            HealthFilter::Degraded,
            HealthFilter::Available,
            HealthFilter::All,
        ] {
            let json = serde_json::to_string(&filter).unwrap();
            let parsed: HealthFilter = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, filter);
        }
    }

    #[test]
    fn connector_archetype_serialization() {
        for archetype in [
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
        ] {
            let json = serde_json::to_string(&archetype).unwrap();
            let parsed: ConnectorArchetype = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, archetype);
        }
    }

    #[test]
    fn latency_hint_serialization() {
        for hint in [
            LatencyHint::Fast,
            LatencyHint::Medium,
            LatencyHint::Slow,
            LatencyHint::VerySlow,
        ] {
            let json = serde_json::to_string(&hint).unwrap();
            let parsed: LatencyHint = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, hint);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Discovery cache + endpoint behavior
    // ─────────────────────────────────────────────────────────────────────────

    struct CountingRegistry {
        connectors: Vec<ConnectorSummary>,
        list_calls: Arc<AtomicUsize>,
    }

    impl CountingRegistry {
        fn new(connectors: Vec<ConnectorSummary>, list_calls: Arc<AtomicUsize>) -> Self {
            Self {
                connectors,
                list_calls,
            }
        }

        fn find(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors.iter().find(|c| &c.id == id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for CountingRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            self.connectors.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.find(id)
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            self.find(id).map(|_| Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            self.find(id).map(|_| SelfCheckReport::ok())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    struct AllowPolicy;

    #[async_trait::async_trait]
    impl PolicyEngine for AllowPolicy {
        async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
            PreflightResponse::allowed()
        }
    }

    struct DenyPolicy;

    #[async_trait::async_trait]
    impl PolicyEngine for DenyPolicy {
        async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
            PreflightResponse::denied("policy denied")
        }
    }

    #[tokio::test]
    async fn discovery_cache_reuses_within_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = DiscoveryCache::new(Duration::from_secs(60));

        let _ = cache.get_or_refresh(&registry).await;
        let _ = cache.get_or_refresh(&registry).await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn discovery_cache_refreshes_when_expired() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "expired",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        let cache = DiscoveryCache::new(Duration::from_millis(0));

        let _ = cache.get_or_refresh(&registry).await;
        let _ = cache.get_or_refresh(&registry).await;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn discovery_endpoint_invalidate_cache_forces_refresh() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "invalidate",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(60),
        );

        let _ = endpoint.discover(None).await;
        let _ = endpoint.discover(None).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        endpoint.invalidate_cache().await;
        let _ = endpoint.discover(None).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn discovery_endpoint_introspect_missing_connector() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
        let id = ConnectorId::new("missing", "test", "v1").unwrap();

        let err = endpoint.introspect(&id).await.unwrap_err();
        assert!(matches!(err, HostError::ConnectorNotFound(_)));
    }

    #[tokio::test]
    async fn discovery_endpoint_defaults_archetype() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "default-arch",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let response = endpoint.introspect(&summary.id).await.unwrap();
        assert_eq!(response.archetype, ConnectorArchetype::RequestResponse);
    }

    #[tokio::test]
    async fn discovery_endpoint_self_check_missing_connector() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
        let id = ConnectorId::new("missing", "test", "v1").unwrap();

        let err = endpoint.self_check(&id).await.unwrap_err();
        assert!(matches!(err, HostError::ConnectorNotFound(_)));
    }

    #[tokio::test]
    async fn discovery_endpoint_self_check_ok() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "self-check",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let response = endpoint.self_check(&summary.id).await.unwrap();
        assert_eq!(response.connector_id, summary.id);
        assert_eq!(response.report.status, SelfCheckStatus::Ok);
    }

    #[tokio::test]
    async fn discovery_endpoint_preflight_passthrough() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(DenyPolicy));

        let request = PreflightRequest {
            connector_id: ConnectorId::new("preflight", "test", "v1").unwrap(),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: None,
        };

        let response = endpoint.preflight(request).await;
        assert!(!response.allowed);
        assert_eq!(response.reason.as_deref(), Some("policy denied"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Combined filter tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn filter_matches_combined_category_and_risk() {
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            max_risk: Some(SafetyTier::Risky),
            health: None,
        };

        // Matches both category and risk
        let safe_msg = make_summary(
            "test",
            "sm",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(filter.matches(&safe_msg));

        // Right category, too risky
        let dangerous_msg = make_summary(
            "test",
            "dm",
            "v1",
            vec!["messaging"],
            SafetyTier::Dangerous,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&dangerous_msg));

        // Wrong category, right risk
        let safe_storage = make_summary(
            "test",
            "ss",
            "v1",
            vec!["storage"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&safe_storage));
    }

    #[test]
    fn filter_matches_all_three_dimensions() {
        let filter = DiscoveryFilter {
            category: Some("ai".to_string()),
            max_risk: Some(SafetyTier::Risky),
            health: Some(HealthFilter::Available),
        };

        // Matches all
        let good = make_summary(
            "test",
            "g",
            "v1",
            vec!["ai"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        assert!(filter.matches(&good));

        // Matches category + risk, but unavailable
        let down = make_summary(
            "test",
            "dn",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::unavailable("down"),
        );
        assert!(!filter.matches(&down));

        // Degraded counts as available
        let degraded = make_summary(
            "test",
            "dg",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );
        assert!(filter.matches(&degraded));
    }

    #[test]
    fn filter_health_degraded_only_matches_degraded() {
        let filter = DiscoveryFilter {
            health: Some(HealthFilter::Degraded),
            ..Default::default()
        };

        let healthy = make_summary(
            "test",
            "hh",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let degraded = make_summary(
            "test",
            "dd",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );

        assert!(!filter.matches(&healthy));
        assert!(filter.matches(&degraded));
    }

    #[test]
    fn filter_health_all_matches_everything() {
        let filter = DiscoveryFilter {
            health: Some(HealthFilter::All),
            ..Default::default()
        };

        let healthy = make_summary(
            "test",
            "ah",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let degraded = make_summary(
            "test",
            "ad",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );
        let unavailable = make_summary(
            "test",
            "au",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::unavailable("down"),
        );

        assert!(filter.matches(&healthy));
        assert!(filter.matches(&degraded));
        assert!(filter.matches(&unavailable));
    }

    #[test]
    fn filter_category_with_multi_category_connector() {
        let filter = DiscoveryFilter {
            category: Some("ai".to_string()),
            ..Default::default()
        };

        let multi = make_summary(
            "test",
            "mc",
            "v1",
            vec!["messaging", "ai", "knowledge"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(filter.matches(&multi));

        let no_match = make_summary(
            "test",
            "nm",
            "v1",
            vec!["messaging", "storage"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&no_match));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PreflightResponse populated fields
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn preflight_response_with_missing_capabilities() {
        let mut resp = PreflightResponse::denied("missing caps");
        resp.missing_capabilities = vec!["cap.read".to_string(), "cap.write".to_string()];

        assert!(!resp.allowed);
        assert_eq!(resp.missing_capabilities.len(), 2);
        assert!(resp.missing_capabilities.contains(&"cap.read".to_string()));
    }

    #[test]
    fn preflight_response_with_rate_limit() {
        let mut resp = PreflightResponse::denied("rate limited");
        resp.rate_limit = Some(PreflightRateLimit {
            limited: true,
            remaining: 0,
            reset_at: Some(Utc::now()),
        });

        assert!(resp.rate_limit.as_ref().unwrap().limited);
        assert_eq!(resp.rate_limit.as_ref().unwrap().remaining, 0);
        assert!(resp.rate_limit.as_ref().unwrap().reset_at.is_some());
    }

    #[test]
    fn preflight_response_with_estimated_cost() {
        let mut resp = PreflightResponse::allowed();
        resp.estimated_cost = Some(EstimatedCost {
            api_calls: Some(3),
            tokens: Some(1500),
            cost_cents: Some(2),
        });

        let cost = resp.estimated_cost.as_ref().unwrap();
        assert_eq!(cost.api_calls, Some(3));
        assert_eq!(cost.tokens, Some(1500));
        assert_eq!(cost.cost_cents, Some(2));
    }

    #[test]
    fn preflight_response_serialization_roundtrip() {
        use fcp_core::{
            BudgetEnforcement, BudgetStatus, UsageBudgetUsage, UsageMetricKind, ZoneId,
        };

        let mut resp = PreflightResponse::denied("rate limited");
        resp.missing_capabilities = vec!["cap.send".to_string()];
        resp.rate_limit = Some(PreflightRateLimit {
            limited: true,
            remaining: 5,
            reset_at: None,
        });
        resp.estimated_cost = Some(EstimatedCost {
            api_calls: Some(1),
            tokens: None,
            cost_cents: Some(10),
        });
        resp.budget_status = Some(UsageBudgetSnapshot {
            zone_id: ZoneId::work(),
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetUsage {
                metric: UsageMetricKind::Tokens,
                used: 1500,
                limit: 2000,
                remaining: 500,
                window_started_at: 1_700_000_000,
                window_resets_at: 1_700_000_060,
                status: BudgetStatus::Ok,
            }],
            updated_at: 1_700_000_020,
        });

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: PreflightResponse = serde_json::from_str(&json).unwrap();

        assert!(!parsed.allowed);
        assert_eq!(parsed.reason.as_deref(), Some("rate limited"));
        assert_eq!(parsed.missing_capabilities, vec!["cap.send"]);
        assert!(parsed.rate_limit.as_ref().unwrap().limited);
        assert_eq!(parsed.rate_limit.as_ref().unwrap().remaining, 5);
        assert_eq!(parsed.estimated_cost.as_ref().unwrap().api_calls, Some(1));
        assert!(parsed.estimated_cost.as_ref().unwrap().tokens.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EstimatedCost + HostHealth serialization
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn estimated_cost_partial_fields() {
        let cost = EstimatedCost {
            api_calls: None,
            tokens: Some(500),
            cost_cents: None,
        };

        let json = serde_json::to_string(&cost).unwrap();
        let parsed: EstimatedCost = serde_json::from_str(&json).unwrap();
        assert!(parsed.api_calls.is_none());
        assert_eq!(parsed.tokens, Some(500));
        assert!(parsed.cost_cents.is_none());
    }

    #[test]
    fn host_health_response_serialization() {
        let response = HostHealthResponse {
            status: HostHealthStatus::Degraded,
            connectors: HashMap::new(),
            uptime_seconds: 3600,
            active_connections: 5,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: HostHealthResponse = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.status, HostHealthStatus::Degraded));
        assert_eq!(parsed.uptime_seconds, 3600);
        assert_eq!(parsed.active_connections, 5);
    }

    #[test]
    fn host_health_status_serialization() {
        for status in [
            HostHealthStatus::Healthy,
            HostHealthStatus::Degraded,
            HostHealthStatus::Unhealthy,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: HostHealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(
                std::mem::discriminant(&parsed),
                std::mem::discriminant(&status)
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Endpoint: discover with strict filter returns empty
    // ─────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn discovery_endpoint_discover_all_filtered_out() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "test",
            "only",
            "v1",
            vec!["storage"],
            SafetyTier::Dangerous,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        // Filter that excludes everything: wrong category + too strict risk
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            max_risk: Some(SafetyTier::Safe),
            health: None,
        };

        let response = endpoint.discover(Some(filter)).await;
        assert!(response.connectors.is_empty());
        assert_eq!(response.registry_version, 1);
    }

    #[tokio::test]
    async fn discovery_endpoint_discover_no_filter_returns_all() {
        let calls = Arc::new(AtomicUsize::new(0));
        let s1 = make_summary(
            "a",
            "first",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let s2 = make_summary(
            "b",
            "second",
            "v1",
            vec!["storage"],
            SafetyTier::Dangerous,
            ConnectorHealth::degraded("slow"),
        );
        let registry = CountingRegistry::new(vec![s1, s2], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let response = endpoint.discover(None).await;
        assert_eq!(response.connectors.len(), 2);
    }
}
