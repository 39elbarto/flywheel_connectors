//! Mesh context, node targeting, execution placement, and verification.
//!
//! Provides types and functions for resolving the active mesh context,
//! selecting execution targets across mesh nodes, explaining placement
//! decisions, managing rollouts with various strategies, checking offline
//! availability / mirror integrity, and running verification matrices.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Mesh Context ─────────────────────────────────────────────────────

/// Source of how the mesh context was determined.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextSource {
    /// Set via `FCP_MESH_NODE` / `FCP_MESH_ZONE` environment variables.
    Environment,
    /// Read from persistent configuration file.
    Config,
    /// Explicitly overridden by the user or a placement override.
    Override,
    /// Inferred from network topology or node discovery.
    Inferred,
}

impl fmt::Display for ContextSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment => f.write_str("environment"),
            Self::Config => f.write_str("config"),
            Self::Override => f.write_str("override"),
            Self::Inferred => f.write_str("inferred"),
        }
    }
}

/// The active mesh context describing which node and zone the CLI is operating against.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshContext {
    /// Currently active node identifier.
    pub active_node: String,
    /// Currently active zone identifier.
    pub active_zone: String,
    /// Whether this context was set via explicit override.
    pub explicit_override: bool,
    /// Whether this context was inferred (vs. explicitly configured).
    pub inferred: bool,
    /// How this context was determined.
    pub source: ContextSource,
}

impl MeshContext {
    /// Create a context from an explicit override.
    #[must_use]
    pub fn from_override(node: impl Into<String>, zone: impl Into<String>) -> Self {
        Self {
            active_node: node.into(),
            active_zone: zone.into(),
            explicit_override: true,
            inferred: false,
            source: ContextSource::Override,
        }
    }

    /// Create a context from environment variables.
    #[must_use]
    pub fn from_env(node: impl Into<String>, zone: impl Into<String>) -> Self {
        Self {
            active_node: node.into(),
            active_zone: zone.into(),
            explicit_override: false,
            inferred: false,
            source: ContextSource::Environment,
        }
    }

    /// Create a context from config.
    #[must_use]
    pub fn from_config(node: impl Into<String>, zone: impl Into<String>) -> Self {
        Self {
            active_node: node.into(),
            active_zone: zone.into(),
            explicit_override: false,
            inferred: false,
            source: ContextSource::Config,
        }
    }

    /// Create an inferred context.
    #[must_use]
    pub fn inferred(node: impl Into<String>, zone: impl Into<String>) -> Self {
        Self {
            active_node: node.into(),
            active_zone: zone.into(),
            explicit_override: false,
            inferred: true,
            source: ContextSource::Inferred,
        }
    }
}

// ── Execution Target ─────────────────────────────────────────────────

/// Reason a particular node was selected as the execution target.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlacementReason {
    /// Closest to the data source.
    DataLocality,
    /// Lowest latency from the requester.
    LowestLatency,
    /// Explicit override placed by the user.
    ExplicitOverride,
    /// Only node available for the zone.
    OnlyAvailable,
    /// Selected by affinity rule.
    Affinity,
    /// Least loaded node.
    LeastLoaded,
}

impl fmt::Display for PlacementReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataLocality => f.write_str("data-locality"),
            Self::LowestLatency => f.write_str("lowest-latency"),
            Self::ExplicitOverride => f.write_str("explicit-override"),
            Self::OnlyAvailable => f.write_str("only-available"),
            Self::Affinity => f.write_str("affinity"),
            Self::LeastLoaded => f.write_str("least-loaded"),
        }
    }
}

/// A node selected for execution, with confidence score.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionTarget {
    /// Identifier of the target node.
    pub node_id: String,
    /// Zone the node belongs to.
    pub zone_id: String,
    /// Why this node was chosen.
    pub placement_reason: PlacementReason,
    /// Confidence score from 0.0 to 1.0 in this selection.
    pub confidence: f64,
}

impl ExecutionTarget {
    /// Create a new execution target.
    #[must_use]
    pub fn new(
        node_id: impl Into<String>,
        zone_id: impl Into<String>,
        reason: PlacementReason,
        confidence: f64,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            zone_id: zone_id.into(),
            placement_reason: reason,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

// ── Placement Explanation ────────────────────────────────────────────

/// Constraint that influenced placement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementConstraint {
    /// Name of the constraint (e.g., "zone-affinity", "data-residency").
    pub name: String,
    /// Whether the constraint was satisfied.
    pub satisfied: bool,
    /// Human-readable description.
    pub description: String,
}

/// Reason why an alternative was not chosen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlternativeRejection {
    /// Node identifier of the rejected alternative.
    pub node_id: String,
    /// Why it was not chosen.
    pub reason: String,
}

/// Detailed explanation of why a particular execution target was chosen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementExplanation {
    /// The chosen target.
    pub target: ExecutionTarget,
    /// Other nodes that were considered.
    pub alternatives: Vec<ExecutionTarget>,
    /// Constraints evaluated during placement.
    pub constraints: Vec<PlacementConstraint>,
    /// Human-readable explanation of why the target was chosen.
    pub why_chosen: String,
    /// Explanations for why each alternative was rejected.
    pub why_not_alternatives: Vec<AlternativeRejection>,
}

// ── Placement Override ───────────────────────────────────────────────

/// An explicit override forcing placement to a specific node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementOverride {
    /// Node to force placement to.
    pub target_node: String,
    /// Reason for the override.
    pub reason: String,
    /// Whether to bypass safety checks.
    pub force: bool,
    /// Optional expiry timestamp (ISO-8601). Empty string means no expiry.
    pub expires_at: String,
}

impl PlacementOverride {
    /// Whether this override has expired.
    #[must_use]
    pub fn is_expired(&self, now_iso: &str) -> bool {
        if self.expires_at.is_empty() {
            return false;
        }
        self.expires_at.as_str() <= now_iso
    }

    /// Create a non-expiring override.
    #[must_use]
    pub fn permanent(node: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            target_node: node.into(),
            reason: reason.into(),
            force: false,
            expires_at: String::new(),
        }
    }

    /// Create a forced override.
    #[must_use]
    pub fn forced(node: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            target_node: node.into(),
            reason: reason.into(),
            force: true,
            expires_at: String::new(),
        }
    }

    /// Create an override that expires at the given ISO-8601 timestamp.
    #[must_use]
    pub fn expiring(
        node: impl Into<String>,
        reason: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Self {
        Self {
            target_node: node.into(),
            reason: reason.into(),
            force: false,
            expires_at: expires_at.into(),
        }
    }
}

// ── Node Lifecycle ───────────────────────────────────────────────────

/// Actions that can be taken on a mesh node.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeLifecycleAction {
    /// Enable the node for scheduling.
    Enable,
    /// Disable the node (no new work, existing work completes).
    Disable,
    /// Drain all work from the node gracefully.
    Drain,
    /// Mark node as unschedulable but let existing work continue.
    Cordon,
    /// Remove the cordon, make node schedulable again.
    Uncordon,
    /// Restart the node process.
    Restart,
}

impl fmt::Display for NodeLifecycleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enable => f.write_str("enable"),
            Self::Disable => f.write_str("disable"),
            Self::Drain => f.write_str("drain"),
            Self::Cordon => f.write_str("cordon"),
            Self::Uncordon => f.write_str("uncordon"),
            Self::Restart => f.write_str("restart"),
        }
    }
}

// ── Rollout ──────────────────────────────────────────────────────────

/// Strategy for rolling out changes across a cohort.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RolloutStrategy {
    /// Deploy to a small canary set first, then proceed.
    Canary,
    /// Roll through nodes one at a time (or in small batches).
    Rolling,
    /// Deploy to a parallel set, then swap traffic.
    BlueGreen,
    /// Deploy to all nodes simultaneously.
    AllAtOnce,
}

impl fmt::Display for RolloutStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canary => f.write_str("canary"),
            Self::Rolling => f.write_str("rolling"),
            Self::BlueGreen => f.write_str("blue-green"),
            Self::AllAtOnce => f.write_str("all-at-once"),
        }
    }
}

/// A cohort of nodes participating in a rollout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RolloutCohort {
    /// Unique cohort identifier.
    pub cohort_id: String,
    /// Node identifiers in this cohort.
    pub nodes: Vec<String>,
    /// Rollout strategy for this cohort.
    pub strategy: RolloutStrategy,
}

impl RolloutCohort {
    /// Create a new rollout cohort.
    #[must_use]
    pub fn new(
        cohort_id: impl Into<String>,
        nodes: Vec<String>,
        strategy: RolloutStrategy,
    ) -> Self {
        Self {
            cohort_id: cohort_id.into(),
            nodes,
            strategy,
        }
    }

    /// Number of nodes in the cohort.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the cohort is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// ── Convergence ──────────────────────────────────────────────────────

/// Report on rollout convergence toward a target version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvergenceReport {
    /// The cohort being checked.
    pub cohort: RolloutCohort,
    /// Target version all nodes should converge to.
    pub target_version: String,
    /// Nodes already at the target version.
    pub nodes_at_target: Vec<String>,
    /// Nodes still running an older version.
    pub nodes_behind: Vec<String>,
    /// Nodes that have drifted to an unexpected version.
    pub drift_nodes: Vec<String>,
}

impl ConvergenceReport {
    /// Whether all nodes have converged to the target.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        self.nodes_behind.is_empty() && self.drift_nodes.is_empty()
    }

    /// Fraction of nodes at target (0.0 to 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn convergence_ratio(&self) -> f64 {
        let total = self.cohort.nodes.len();
        if total == 0 {
            return 0.0;
        }
        self.nodes_at_target.len() as f64 / total as f64
    }
}

// ── Mirror / Offline Availability ────────────────────────────────────

/// A package mirror source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MirrorSource {
    /// URL of the mirror.
    pub url: String,
    /// Whether the mirror has been verified.
    pub verified: bool,
    /// ISO-8601 timestamp of last sync. Empty if never synced.
    pub last_synced: String,
    /// Whether this mirror is available for offline use.
    pub available_offline: bool,
}

impl MirrorSource {
    /// Create a verified, online mirror.
    #[must_use]
    pub fn verified_online(url: impl Into<String>, last_synced: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            verified: true,
            last_synced: last_synced.into(),
            available_offline: false,
        }
    }

    /// Create a verified, offline-capable mirror.
    #[must_use]
    pub fn verified_offline(url: impl Into<String>, last_synced: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            verified: true,
            last_synced: last_synced.into(),
            available_offline: true,
        }
    }

    /// Create an unverified mirror.
    #[must_use]
    pub fn unverified(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            verified: false,
            last_synced: String::new(),
            available_offline: false,
        }
    }
}

/// Offline availability for a specific connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineAvailability {
    /// Connector identifier.
    pub connector: String,
    /// Versions available offline.
    pub available_versions: Vec<String>,
    /// Mirror source providing offline access.
    pub mirror_source: Option<MirrorSource>,
    /// ISO-8601 timestamp when availability was last verified.
    pub last_verified: String,
}

impl OfflineAvailability {
    /// Whether any version is available offline.
    #[must_use]
    pub fn is_available(&self) -> bool {
        !self.available_versions.is_empty()
    }

    /// Create an entry with no offline versions.
    #[must_use]
    pub fn unavailable(connector: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            available_versions: Vec::new(),
            mirror_source: None,
            last_verified: String::new(),
        }
    }

    /// Create an entry with available offline versions.
    #[must_use]
    pub fn available(
        connector: impl Into<String>,
        versions: Vec<String>,
        mirror: MirrorSource,
        verified: impl Into<String>,
    ) -> Self {
        Self {
            connector: connector.into(),
            available_versions: versions,
            mirror_source: Some(mirror),
            last_verified: verified.into(),
        }
    }
}

// ── Verification ─────────────────────────────────────────────────────

/// A single verification scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationScenario {
    /// Name of the scenario.
    pub name: String,
    /// Human-readable description of what the scenario tests.
    pub description: String,
    /// Input data for the scenario (serialized as JSON value).
    pub input: serde_json::Value,
    /// Expected outcome description.
    pub expected_outcome: String,
}

impl VerificationScenario {
    /// Create a new scenario.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input: serde_json::Value,
        expected_outcome: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input,
            expected_outcome: expected_outcome.into(),
        }
    }
}

/// Result of running a verification scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    /// The scenario that was run.
    pub scenario: VerificationScenario,
    /// Whether the scenario passed.
    pub passed: bool,
    /// Actual outcome description.
    pub actual_outcome: String,
    /// Additional details or diagnostics.
    pub details: String,
}

impl VerificationResult {
    /// Create a passing result.
    #[must_use]
    pub fn pass(scenario: VerificationScenario, actual: impl Into<String>) -> Self {
        Self {
            scenario,
            passed: true,
            actual_outcome: actual.into(),
            details: String::new(),
        }
    }

    /// Create a failing result.
    #[must_use]
    pub fn fail(
        scenario: VerificationScenario,
        actual: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            scenario,
            passed: false,
            actual_outcome: actual.into(),
            details: details.into(),
        }
    }
}

// ── Node Info (for target selection) ──────────────────────────────────

/// Lightweight descriptor of a mesh node for selection purposes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node identifier.
    pub node_id: String,
    /// Zone the node belongs to.
    pub zone_id: String,
    /// Whether the node is currently schedulable.
    pub schedulable: bool,
    /// Current load as a fraction (0.0 to 1.0).
    pub load: f64,
    /// Latency from the requester in milliseconds.
    pub latency_ms: f64,
    /// Labels / tags for affinity matching.
    pub labels: HashMap<String, String>,
}

impl NodeInfo {
    /// Create a healthy, schedulable node.
    #[must_use]
    pub fn healthy(
        node_id: impl Into<String>,
        zone_id: impl Into<String>,
        load: f64,
        latency_ms: f64,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            zone_id: zone_id.into(),
            schedulable: true,
            load,
            latency_ms,
            labels: HashMap::new(),
        }
    }

    /// Create an unschedulable (cordoned) node.
    #[must_use]
    pub fn cordoned(node_id: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            zone_id: zone_id.into(),
            schedulable: false,
            load: 0.0,
            latency_ms: 0.0,
            labels: HashMap::new(),
        }
    }
}

// ── Selection constraints ────────────────────────────────────────────

/// Constraints for target selection.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SelectionConstraints {
    /// Restrict to nodes in these zones (empty = any zone).
    pub zone_filter: Vec<String>,
    /// Required labels the node must have.
    pub required_labels: HashMap<String, String>,
    /// Maximum acceptable load on the node (0.0 to 1.0).
    pub max_load: Option<f64>,
    /// Maximum acceptable latency in milliseconds.
    pub max_latency_ms: Option<f64>,
}

// ── Node version info (for convergence) ──────────────────────────────

/// Version state of a single node for convergence checking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeVersionState {
    /// Node identifier.
    pub node_id: String,
    /// Current version running on this node.
    pub current_version: String,
}

// ══════════════════════════════════════════════════════════════════════
// Functions
// ══════════════════════════════════════════════════════════════════════

/// Resolve the current mesh context from environment, config, or override.
///
/// Priority: override > environment > config > inferred.
#[must_use]
pub fn resolve_mesh_context(
    env_node: Option<&str>,
    env_zone: Option<&str>,
    config_node: Option<&str>,
    config_zone: Option<&str>,
    override_ctx: Option<&PlacementOverride>,
    now_iso: &str,
) -> MeshContext {
    // Check override first (if not expired).
    if let Some(ov) = override_ctx {
        if !ov.is_expired(now_iso) {
            return MeshContext::from_override(&ov.target_node, "override-zone");
        }
    }

    // Environment variables.
    if let (Some(node), Some(zone)) = (env_node, env_zone) {
        return MeshContext::from_env(node, zone);
    }

    // Config file.
    if let (Some(node), Some(zone)) = (config_node, config_zone) {
        return MeshContext::from_config(node, zone);
    }

    // Fallback: infer from defaults.
    MeshContext::inferred("local", "z:default")
}

/// Select the best execution target from a list of available nodes.
///
/// Filters by constraints, then picks the node with lowest load among
/// those with acceptable latency. Returns `None` if no node matches.
#[must_use]
pub fn select_execution_target(
    nodes: &[NodeInfo],
    constraints: &SelectionConstraints,
) -> Option<ExecutionTarget> {
    let candidates: Vec<&NodeInfo> = nodes
        .iter()
        .filter(|n| n.schedulable)
        .filter(|n| {
            constraints.zone_filter.is_empty() || constraints.zone_filter.contains(&n.zone_id)
        })
        .filter(|n| {
            constraints
                .required_labels
                .iter()
                .all(|(k, v)| n.labels.get(k) == Some(v))
        })
        .filter(|n| constraints.max_load.is_none_or(|max| n.load <= max))
        .filter(|n| {
            constraints
                .max_latency_ms
                .is_none_or(|max| n.latency_ms <= max)
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    if candidates.len() == 1 {
        let n = candidates[0];
        return Some(ExecutionTarget::new(
            &n.node_id,
            &n.zone_id,
            PlacementReason::OnlyAvailable,
            1.0,
        ));
    }

    // Pick least-loaded.
    let best = candidates
        .iter()
        .min_by(|a, b| {
            a.load
                .partial_cmp(&b.load)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap(); // safe: candidates.len() >= 2

    // Confidence based on how much better this is than the next-best.
    let mut loads: Vec<f64> = candidates.iter().map(|n| n.load).collect();
    loads.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let confidence = if loads.len() >= 2 && loads[1] > 0.0 {
        (1.0 - loads[0] / loads[1]).clamp(0.5, 1.0)
    } else {
        0.9
    };

    Some(ExecutionTarget::new(
        &best.node_id,
        &best.zone_id,
        PlacementReason::LeastLoaded,
        confidence,
    ))
}

/// Check whether a node should be rejected based on constraints,
/// pushing a rejection entry if so.
fn check_node_rejection(
    node: &NodeInfo,
    constraints: &SelectionConstraints,
    rejections: &mut Vec<AlternativeRejection>,
) -> bool {
    let rejected = if !constraints.zone_filter.is_empty()
        && !constraints.zone_filter.contains(&node.zone_id)
    {
        rejections.push(AlternativeRejection {
            node_id: node.node_id.clone(),
            reason: format!("zone {} not in allowed zones", node.zone_id),
        });
        true
    } else {
        false
    };

    let rejected = constraints.max_load.map_or(rejected, |max| {
        if node.load > max && !rejected {
            rejections.push(AlternativeRejection {
                node_id: node.node_id.clone(),
                reason: format!("load {:.2} exceeds max {:.2}", node.load, max),
            });
            true
        } else {
            rejected
        }
    });

    constraints.max_latency_ms.map_or(rejected, |max| {
        if node.latency_ms > max && !rejected {
            rejections.push(AlternativeRejection {
                node_id: node.node_id.clone(),
                reason: format!("latency {:.1}ms exceeds max {:.1}ms", node.latency_ms, max),
            });
            true
        } else {
            rejected
        }
    })
}

/// Build constraint check results for the explanation.
fn build_constraint_results(
    constraints: &SelectionConstraints,
    target: &ExecutionTarget,
) -> Vec<PlacementConstraint> {
    let mut results = Vec::new();
    if !constraints.zone_filter.is_empty() {
        results.push(PlacementConstraint {
            name: "zone-filter".to_string(),
            satisfied: constraints.zone_filter.contains(&target.zone_id)
                || target.node_id == "none",
            description: format!("node must be in zones: {:?}", constraints.zone_filter),
        });
    }
    if let Some(max) = constraints.max_load {
        results.push(PlacementConstraint {
            name: "max-load".to_string(),
            satisfied: true,
            description: format!("node load must be <= {max:.2}"),
        });
    }
    if let Some(max) = constraints.max_latency_ms {
        results.push(PlacementConstraint {
            name: "max-latency".to_string(),
            satisfied: true,
            description: format!("node latency must be <= {max:.1}ms"),
        });
    }
    results
}

/// Build a detailed placement explanation for a target selection.
#[must_use]
pub fn explain_placement(
    nodes: &[NodeInfo],
    constraints: &SelectionConstraints,
) -> PlacementExplanation {
    let chosen = select_execution_target(nodes, constraints);

    let target = chosen.unwrap_or_else(|| {
        ExecutionTarget::new("none", "none", PlacementReason::OnlyAvailable, 0.0)
    });

    let mut alternatives = Vec::new();
    let mut rejections = Vec::new();

    for node in nodes {
        if node.node_id == target.node_id {
            continue;
        }
        if !node.schedulable {
            rejections.push(AlternativeRejection {
                node_id: node.node_id.clone(),
                reason: "node is not schedulable (cordoned/disabled)".to_string(),
            });
            continue;
        }
        if !check_node_rejection(node, constraints, &mut rejections) {
            alternatives.push(ExecutionTarget::new(
                &node.node_id,
                &node.zone_id,
                PlacementReason::LeastLoaded,
                0.5,
            ));
        }
    }

    let constraint_results = build_constraint_results(constraints, &target);

    let why = if target.node_id == "none" {
        "no eligible nodes found matching constraints".to_string()
    } else {
        format!(
            "node {} selected: {} (confidence {:.0}%)",
            target.node_id,
            target.placement_reason,
            target.confidence * 100.0
        )
    };

    PlacementExplanation {
        target,
        alternatives,
        constraints: constraint_results,
        why_chosen: why,
        why_not_alternatives: rejections,
    }
}

/// Apply a placement override to force execution on a specific node.
///
/// Returns `Ok(())` if applied, or `Err` with reason if the node is not
/// schedulable and `force` is false.
pub fn apply_placement_override(
    ov: &PlacementOverride,
    known_nodes: &[NodeInfo],
) -> Result<(), String> {
    // If the node exists and is not schedulable, reject unless forced.
    if let Some(node) = known_nodes.iter().find(|n| n.node_id == ov.target_node) {
        if !node.schedulable && !ov.force {
            return Err(format!(
                "node {} is not schedulable; use force=true to override",
                ov.target_node
            ));
        }
    }
    // Otherwise accept (unknown nodes accepted for forward-compatibility).
    Ok(())
}

/// Plan a rollout across the given nodes with the specified strategy.
#[must_use]
pub fn plan_rollout(
    cohort_id: impl Into<String>,
    nodes: Vec<String>,
    strategy: RolloutStrategy,
) -> RolloutCohort {
    RolloutCohort::new(cohort_id, nodes, strategy)
}

/// Check convergence of a cohort toward a target version.
#[must_use]
pub fn check_convergence(
    cohort: &RolloutCohort,
    target_version: &str,
    node_states: &[NodeVersionState],
) -> ConvergenceReport {
    let state_map: HashMap<&str, &str> = node_states
        .iter()
        .map(|s| (s.node_id.as_str(), s.current_version.as_str()))
        .collect();

    let mut at_target = Vec::new();
    let mut behind = Vec::new();
    let mut drift = Vec::new();

    for node_id in &cohort.nodes {
        match state_map.get(node_id.as_str()) {
            Some(&v) if v == target_version => at_target.push(node_id.clone()),
            Some(&v) if v < target_version => behind.push(node_id.clone()),
            Some(_) => drift.push(node_id.clone()),
            None => behind.push(node_id.clone()), // unknown = behind
        }
    }

    ConvergenceReport {
        cohort: cohort.clone(),
        target_version: target_version.to_string(),
        nodes_at_target: at_target,
        nodes_behind: behind,
        drift_nodes: drift,
    }
}

/// Check offline availability for a list of connectors.
#[must_use]
pub fn check_offline_availability(
    connectors: &[&str],
    available: &HashMap<String, OfflineAvailability>,
) -> Vec<OfflineAvailability> {
    connectors
        .iter()
        .map(|c| {
            available
                .get(*c)
                .cloned()
                .unwrap_or_else(|| OfflineAvailability::unavailable(*c))
        })
        .collect()
}

/// Check mirror status for a list of mirrors. Returns a map of url -> verified.
#[must_use]
pub fn check_mirror_status(mirrors: &[MirrorSource]) -> HashMap<String, bool> {
    mirrors
        .iter()
        .map(|m| (m.url.clone(), m.verified))
        .collect()
}

/// Run a verification matrix: apply each scenario and collect results.
///
/// The `runner` function receives a scenario and returns `(passed, actual_outcome, details)`.
#[must_use]
pub fn run_verification_matrix<F>(
    scenarios: &[VerificationScenario],
    runner: F,
) -> Vec<VerificationResult>
where
    F: Fn(&VerificationScenario) -> (bool, String, String),
{
    scenarios
        .iter()
        .map(|s| {
            let (passed, actual, details) = runner(s);
            if passed {
                let mut r = VerificationResult::pass(s.clone(), actual);
                r.details = details;
                r
            } else {
                VerificationResult::fail(s.clone(), actual, details)
            }
        })
        .collect()
}

// ══════════════════════════════════════════════════════════════════════
// TOON Formatters
// ══════════════════════════════════════════════════════════════════════

/// Format mesh context as TOON lines.
#[must_use]
pub fn format_context_toon(ctx: &MeshContext) -> Vec<String> {
    let mut out = Vec::new();
    out.push("=== Mesh Context ===".to_string());
    out.push(format!("Active node: {}", ctx.active_node));
    out.push(format!("Active zone: {}", ctx.active_zone));
    out.push(format!("Source:      {}", ctx.source));
    if ctx.explicit_override {
        out.push("Override:    yes".to_string());
    }
    if ctx.inferred {
        out.push("Inferred:    yes".to_string());
    }
    out
}

/// Format execution target as TOON lines.
#[must_use]
pub fn format_placement_toon(target: &ExecutionTarget) -> Vec<String> {
    let mut out = Vec::new();
    out.push("=== Execution Target ===".to_string());
    out.push(format!("Node:       {}", target.node_id));
    out.push(format!("Zone:       {}", target.zone_id));
    out.push(format!("Reason:     {}", target.placement_reason));
    out.push(format!("Confidence: {:.0}%", target.confidence * 100.0));
    out
}

/// Format placement explanation as TOON lines.
#[must_use]
pub fn format_explanation_toon(exp: &PlacementExplanation) -> Vec<String> {
    let mut out = Vec::new();
    out.push("=== Placement Explanation ===".to_string());
    out.push(format!(
        "Chosen: {} ({})",
        exp.target.node_id, exp.target.zone_id
    ));
    out.push(format!("Why:    {}", exp.why_chosen));

    if !exp.constraints.is_empty() {
        out.push("Constraints:".to_string());
        for c in &exp.constraints {
            let mark = if c.satisfied { "[ok]" } else { "[FAIL]" };
            out.push(format!("  {} {} -- {}", mark, c.name, c.description));
        }
    }

    if !exp.alternatives.is_empty() {
        out.push(format!("Alternatives ({}):", exp.alternatives.len()));
        for alt in &exp.alternatives {
            out.push(format!(
                "  {} ({}, confidence {:.0}%)",
                alt.node_id,
                alt.zone_id,
                alt.confidence * 100.0
            ));
        }
    }

    if !exp.why_not_alternatives.is_empty() {
        out.push("Rejections:".to_string());
        for rej in &exp.why_not_alternatives {
            out.push(format!("  {} -- {}", rej.node_id, rej.reason));
        }
    }

    out
}

/// Format rollout cohort as TOON lines.
#[must_use]
pub fn format_rollout_toon(cohort: &RolloutCohort) -> Vec<String> {
    let mut out = Vec::new();
    out.push("=== Rollout Cohort ===".to_string());
    out.push(format!("Cohort:   {}", cohort.cohort_id));
    out.push(format!("Strategy: {}", cohort.strategy));
    out.push(format!(
        "Nodes ({}): {}",
        cohort.nodes.len(),
        cohort.nodes.join(", ")
    ));
    out
}

/// Format convergence report as TOON lines.
#[must_use]
pub fn format_convergence_toon(report: &ConvergenceReport) -> Vec<String> {
    let mut out = Vec::new();
    out.push("=== Convergence Report ===".to_string());
    out.push(format!("Target version: {}", report.target_version));
    out.push(format!(
        "Converged: {:.0}%",
        report.convergence_ratio() * 100.0
    ));
    out.push(format!(
        "At target ({}): {}",
        report.nodes_at_target.len(),
        report.nodes_at_target.join(", ")
    ));
    out.push(format!(
        "Behind ({}):    {}",
        report.nodes_behind.len(),
        report.nodes_behind.join(", ")
    ));
    out.push(format!(
        "Drift ({}):     {}",
        report.drift_nodes.len(),
        report.drift_nodes.join(", ")
    ));
    if report.is_converged() {
        out.push("Status: CONVERGED".to_string());
    } else {
        out.push("Status: IN PROGRESS".to_string());
    }
    out
}

/// Format offline availability as TOON lines.
#[must_use]
pub fn format_offline_toon(avail: &[OfflineAvailability]) -> Vec<String> {
    let mut out = Vec::new();
    out.push("=== Offline Availability ===".to_string());
    for a in avail {
        if a.is_available() {
            out.push(format!(
                "[available] {} -- versions: {}",
                a.connector,
                a.available_versions.join(", ")
            ));
            if let Some(ref m) = a.mirror_source {
                out.push(format!(
                    "  mirror: {} (verified={}, offline={})",
                    m.url, m.verified, m.available_offline
                ));
            }
        } else {
            out.push(format!("[unavailable] {}", a.connector));
        }
    }
    out
}

/// Format verification results as TOON lines.
#[must_use]
pub fn format_verification_toon(results: &[VerificationResult]) -> Vec<String> {
    let mut out = Vec::new();
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;
    out.push("=== Verification Matrix ===".to_string());
    out.push(format!(
        "Total: {total}  Passed: {passed}  Failed: {failed}"
    ));
    for r in results {
        let mark = if r.passed { "PASS" } else { "FAIL" };
        out.push(format!("[{}] {}", mark, r.scenario.name));
        if !r.passed {
            out.push(format!("  Expected: {}", r.scenario.expected_outcome));
            out.push(format!("  Actual:   {}", r.actual_outcome));
            if !r.details.is_empty() {
                out.push(format!("  Details:  {}", r.details));
            }
        }
    }
    out
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper builders ──────────────────────────────────────────────

    fn sample_nodes() -> Vec<NodeInfo> {
        vec![
            NodeInfo::healthy("node-a", "z:us-east", 0.3, 10.0),
            NodeInfo::healthy("node-b", "z:us-east", 0.6, 20.0),
            NodeInfo::healthy("node-c", "z:eu-west", 0.2, 50.0),
            NodeInfo::healthy("node-d", "z:eu-west", 0.8, 30.0),
        ]
    }

    fn sample_nodes_with_labels() -> Vec<NodeInfo> {
        let mut nodes = sample_nodes();
        nodes[0]
            .labels
            .insert("tier".to_string(), "premium".to_string());
        nodes[2]
            .labels
            .insert("tier".to_string(), "premium".to_string());
        nodes
    }

    fn empty_constraints() -> SelectionConstraints {
        SelectionConstraints::default()
    }

    fn sample_scenarios() -> Vec<VerificationScenario> {
        vec![
            VerificationScenario::new(
                "basic-invoke",
                "Invoke a simple operation",
                serde_json::json!({"op": "list"}),
                "returns 200 OK",
            ),
            VerificationScenario::new(
                "auth-required",
                "Operation requiring auth",
                serde_json::json!({"op": "create", "auth": true}),
                "returns 401 without token",
            ),
            VerificationScenario::new(
                "rate-limit",
                "Exceed rate limit",
                serde_json::json!({"op": "list", "burst": 100}),
                "returns 429",
            ),
        ]
    }

    fn sample_version_states(target: &str) -> Vec<NodeVersionState> {
        vec![
            NodeVersionState {
                node_id: "n1".to_string(),
                current_version: target.to_string(),
            },
            NodeVersionState {
                node_id: "n2".to_string(),
                current_version: target.to_string(),
            },
            NodeVersionState {
                node_id: "n3".to_string(),
                current_version: "0.9.0".to_string(),
            },
        ]
    }

    // ── Context resolution tests ─────────────────────────────────────

    #[test]
    fn resolve_context_from_override() {
        let ov = PlacementOverride::permanent("node-x", "maintenance");
        let ctx = resolve_mesh_context(
            Some("env-node"),
            Some("env-zone"),
            Some("cfg-node"),
            Some("cfg-zone"),
            Some(&ov),
            "2026-03-12T00:00:00Z",
        );
        assert_eq!(ctx.active_node, "node-x");
        assert!(ctx.explicit_override);
        assert_eq!(ctx.source, ContextSource::Override);
    }

    #[test]
    fn resolve_context_expired_override_falls_through() {
        let ov = PlacementOverride::expiring("node-x", "temp", "2026-03-01T00:00:00Z");
        let ctx = resolve_mesh_context(
            Some("env-node"),
            Some("env-zone"),
            None,
            None,
            Some(&ov),
            "2026-03-12T00:00:00Z",
        );
        assert_eq!(ctx.active_node, "env-node");
        assert_eq!(ctx.source, ContextSource::Environment);
    }

    #[test]
    fn resolve_context_from_env() {
        let ctx = resolve_mesh_context(
            Some("env-node"),
            Some("env-zone"),
            Some("cfg-node"),
            Some("cfg-zone"),
            None,
            "2026-03-12T00:00:00Z",
        );
        assert_eq!(ctx.active_node, "env-node");
        assert_eq!(ctx.active_zone, "env-zone");
        assert_eq!(ctx.source, ContextSource::Environment);
        assert!(!ctx.explicit_override);
        assert!(!ctx.inferred);
    }

    #[test]
    fn resolve_context_from_config() {
        let ctx = resolve_mesh_context(
            None,
            None,
            Some("cfg-node"),
            Some("cfg-zone"),
            None,
            "2026-03-12T00:00:00Z",
        );
        assert_eq!(ctx.active_node, "cfg-node");
        assert_eq!(ctx.active_zone, "cfg-zone");
        assert_eq!(ctx.source, ContextSource::Config);
    }

    #[test]
    fn resolve_context_inferred() {
        let ctx = resolve_mesh_context(None, None, None, None, None, "2026-03-12T00:00:00Z");
        assert_eq!(ctx.active_node, "local");
        assert_eq!(ctx.active_zone, "z:default");
        assert!(ctx.inferred);
        assert_eq!(ctx.source, ContextSource::Inferred);
    }

    #[test]
    fn resolve_context_partial_env_falls_to_config() {
        // Only node set in env, no zone => fall through to config.
        let ctx = resolve_mesh_context(
            Some("env-node"),
            None,
            Some("cfg-node"),
            Some("cfg-zone"),
            None,
            "2026-03-12T00:00:00Z",
        );
        assert_eq!(ctx.active_node, "cfg-node");
        assert_eq!(ctx.source, ContextSource::Config);
    }

    #[test]
    fn resolve_context_partial_config_falls_to_inferred() {
        let ctx = resolve_mesh_context(
            None,
            None,
            Some("cfg-node"),
            None,
            None,
            "2026-03-12T00:00:00Z",
        );
        assert_eq!(ctx.active_node, "local");
        assert_eq!(ctx.source, ContextSource::Inferred);
    }

    #[test]
    fn resolve_context_forced_override() {
        let ov = PlacementOverride::forced("forced-node", "emergency");
        let ctx = resolve_mesh_context(None, None, None, None, Some(&ov), "2026-03-12T00:00:00Z");
        assert_eq!(ctx.active_node, "forced-node");
        assert!(ctx.explicit_override);
    }

    // ── Target selection tests ───────────────────────────────────────

    #[test]
    fn select_target_picks_least_loaded() {
        let nodes = sample_nodes();
        let target = select_execution_target(&nodes, &empty_constraints()).unwrap();
        assert_eq!(target.node_id, "node-c"); // load 0.2
        assert_eq!(target.placement_reason, PlacementReason::LeastLoaded);
    }

    #[test]
    fn select_target_single_node() {
        let nodes = vec![NodeInfo::healthy("solo", "z:us", 0.5, 10.0)];
        let target = select_execution_target(&nodes, &empty_constraints()).unwrap();
        assert_eq!(target.node_id, "solo");
        assert_eq!(target.placement_reason, PlacementReason::OnlyAvailable);
        assert!((target.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn select_target_empty_mesh() {
        let nodes: Vec<NodeInfo> = vec![];
        assert!(select_execution_target(&nodes, &empty_constraints()).is_none());
    }

    #[test]
    fn select_target_all_cordoned() {
        let nodes = vec![
            NodeInfo::cordoned("n1", "z:a"),
            NodeInfo::cordoned("n2", "z:b"),
        ];
        assert!(select_execution_target(&nodes, &empty_constraints()).is_none());
    }

    #[test]
    fn select_target_zone_filter() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            zone_filter: vec!["z:us-east".to_string()],
            ..Default::default()
        };
        let target = select_execution_target(&nodes, &constraints).unwrap();
        assert_eq!(target.zone_id, "z:us-east");
        assert_eq!(target.node_id, "node-a"); // least loaded in us-east
    }

    #[test]
    fn select_target_zone_filter_no_match() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            zone_filter: vec!["z:ap-south".to_string()],
            ..Default::default()
        };
        assert!(select_execution_target(&nodes, &constraints).is_none());
    }

    #[test]
    fn select_target_max_load_constraint() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            max_load: Some(0.25),
            ..Default::default()
        };
        let target = select_execution_target(&nodes, &constraints).unwrap();
        assert_eq!(target.node_id, "node-c"); // load 0.2, only one <= 0.25
    }

    #[test]
    fn select_target_max_load_excludes_all() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            max_load: Some(0.1),
            ..Default::default()
        };
        assert!(select_execution_target(&nodes, &constraints).is_none());
    }

    #[test]
    fn select_target_max_latency_constraint() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            max_latency_ms: Some(25.0),
            ..Default::default()
        };
        let target = select_execution_target(&nodes, &constraints).unwrap();
        // Nodes a (10ms) and b (20ms) qualify; a is least loaded.
        assert_eq!(target.node_id, "node-a");
    }

    #[test]
    fn select_target_label_constraint() {
        let nodes = sample_nodes_with_labels();
        let mut required = HashMap::new();
        required.insert("tier".to_string(), "premium".to_string());
        let constraints = SelectionConstraints {
            required_labels: required,
            ..Default::default()
        };
        let target = select_execution_target(&nodes, &constraints).unwrap();
        // node-a (0.3) and node-c (0.2) have premium; node-c wins.
        assert_eq!(target.node_id, "node-c");
    }

    #[test]
    fn select_target_label_no_match() {
        let nodes = sample_nodes();
        let mut required = HashMap::new();
        required.insert("gpu".to_string(), "true".to_string());
        let constraints = SelectionConstraints {
            required_labels: required,
            ..Default::default()
        };
        assert!(select_execution_target(&nodes, &constraints).is_none());
    }

    #[test]
    fn select_target_combined_constraints() {
        let nodes = sample_nodes_with_labels();
        let mut required = HashMap::new();
        required.insert("tier".to_string(), "premium".to_string());
        let constraints = SelectionConstraints {
            zone_filter: vec!["z:us-east".to_string()],
            required_labels: required,
            max_load: Some(0.5),
            ..Default::default()
        };
        let target = select_execution_target(&nodes, &constraints).unwrap();
        assert_eq!(target.node_id, "node-a");
        assert_eq!(target.placement_reason, PlacementReason::OnlyAvailable);
    }

    #[test]
    fn select_target_confidence_varies_with_load_gap() {
        let nodes = vec![
            NodeInfo::healthy("low", "z:a", 0.1, 10.0),
            NodeInfo::healthy("high", "z:a", 0.9, 10.0),
        ];
        let target = select_execution_target(&nodes, &empty_constraints()).unwrap();
        assert_eq!(target.node_id, "low");
        // Large gap => high confidence.
        assert!(target.confidence >= 0.8);
    }

    #[test]
    fn select_target_confidence_lower_with_similar_loads() {
        let nodes = vec![
            NodeInfo::healthy("a", "z:a", 0.49, 10.0),
            NodeInfo::healthy("b", "z:a", 0.50, 10.0),
        ];
        let target = select_execution_target(&nodes, &empty_constraints()).unwrap();
        assert_eq!(target.node_id, "a");
        // Narrow gap => confidence closer to 0.5.
        assert!(target.confidence <= 0.55);
    }

    // ── Placement explanation tests ──────────────────────────────────

    #[test]
    fn explain_placement_with_alternatives() {
        let nodes = sample_nodes();
        let exp = explain_placement(&nodes, &empty_constraints());
        assert_eq!(exp.target.node_id, "node-c");
        assert!(!exp.alternatives.is_empty());
        assert!(!exp.why_chosen.is_empty());
    }

    #[test]
    fn explain_placement_verbose_contains_target() {
        let nodes = sample_nodes();
        let exp = explain_placement(&nodes, &empty_constraints());
        assert!(exp.why_chosen.contains("node-c"));
    }

    #[test]
    fn explain_placement_with_cordoned_shows_rejection() {
        let mut nodes = sample_nodes();
        nodes.push(NodeInfo::cordoned("cordoned-node", "z:us-east"));
        let exp = explain_placement(&nodes, &empty_constraints());
        let rejection = exp
            .why_not_alternatives
            .iter()
            .find(|r| r.node_id == "cordoned-node");
        assert!(rejection.is_some());
        assert!(rejection.unwrap().reason.contains("schedulable"));
    }

    #[test]
    fn explain_placement_with_zone_filter_shows_zone_rejection() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            zone_filter: vec!["z:us-east".to_string()],
            ..Default::default()
        };
        let exp = explain_placement(&nodes, &constraints);
        let eu_rejection = exp
            .why_not_alternatives
            .iter()
            .find(|r| r.node_id == "node-c" || r.node_id == "node-d");
        assert!(eu_rejection.is_some());
    }

    #[test]
    fn explain_placement_empty_mesh() {
        let nodes: Vec<NodeInfo> = vec![];
        let exp = explain_placement(&nodes, &empty_constraints());
        assert_eq!(exp.target.node_id, "none");
        assert!(exp.why_chosen.contains("no eligible"));
    }

    #[test]
    fn explain_placement_constraints_recorded() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            zone_filter: vec!["z:us-east".to_string()],
            max_load: Some(0.7),
            max_latency_ms: Some(100.0),
            ..Default::default()
        };
        let exp = explain_placement(&nodes, &constraints);
        assert_eq!(exp.constraints.len(), 3);
        assert!(exp.constraints.iter().any(|c| c.name == "zone-filter"));
        assert!(exp.constraints.iter().any(|c| c.name == "max-load"));
        assert!(exp.constraints.iter().any(|c| c.name == "max-latency"));
    }

    #[test]
    fn explain_placement_terse_no_constraints() {
        let nodes = vec![NodeInfo::healthy("solo", "z:a", 0.5, 10.0)];
        let exp = explain_placement(&nodes, &empty_constraints());
        assert!(exp.constraints.is_empty());
        assert!(exp.alternatives.is_empty());
    }

    #[test]
    fn explain_placement_load_rejection() {
        let nodes = vec![
            NodeInfo::healthy("low", "z:a", 0.1, 10.0),
            NodeInfo::healthy("high", "z:a", 0.9, 10.0),
        ];
        let constraints = SelectionConstraints {
            max_load: Some(0.5),
            ..Default::default()
        };
        let exp = explain_placement(&nodes, &constraints);
        assert_eq!(exp.target.node_id, "low");
        let rej = exp
            .why_not_alternatives
            .iter()
            .find(|r| r.node_id == "high");
        assert!(rej.is_some());
        assert!(rej.unwrap().reason.contains("load"));
    }

    #[test]
    fn explain_placement_latency_rejection() {
        let nodes = vec![
            NodeInfo::healthy("fast", "z:a", 0.5, 5.0),
            NodeInfo::healthy("slow", "z:a", 0.5, 500.0),
        ];
        let constraints = SelectionConstraints {
            max_latency_ms: Some(100.0),
            ..Default::default()
        };
        let exp = explain_placement(&nodes, &constraints);
        let rej = exp
            .why_not_alternatives
            .iter()
            .find(|r| r.node_id == "slow");
        assert!(rej.is_some());
        assert!(rej.unwrap().reason.contains("latency"));
    }

    // ── Override tests ───────────────────────────────────────────────

    #[test]
    fn override_set_on_schedulable_node() {
        let nodes = vec![NodeInfo::healthy("target", "z:a", 0.5, 10.0)];
        let ov = PlacementOverride::permanent("target", "migration");
        assert!(apply_placement_override(&ov, &nodes).is_ok());
    }

    #[test]
    fn override_rejected_on_cordoned_node() {
        let nodes = vec![NodeInfo::cordoned("target", "z:a")];
        let ov = PlacementOverride::permanent("target", "migration");
        let result = apply_placement_override(&ov, &nodes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not schedulable"));
    }

    #[test]
    fn override_forced_on_cordoned_node() {
        let nodes = vec![NodeInfo::cordoned("target", "z:a")];
        let ov = PlacementOverride::forced("target", "emergency");
        assert!(apply_placement_override(&ov, &nodes).is_ok());
    }

    #[test]
    fn override_clear_by_expiry() {
        let ov = PlacementOverride::expiring("node-x", "temp", "2026-03-01T00:00:00Z");
        assert!(ov.is_expired("2026-03-12T00:00:00Z"));
    }

    #[test]
    fn override_not_expired_yet() {
        let ov = PlacementOverride::expiring("node-x", "temp", "2026-12-31T23:59:59Z");
        assert!(!ov.is_expired("2026-03-12T00:00:00Z"));
    }

    #[test]
    fn override_permanent_never_expires() {
        let ov = PlacementOverride::permanent("node-x", "perm");
        assert!(!ov.is_expired("2099-12-31T23:59:59Z"));
    }

    #[test]
    fn override_unknown_node_accepted() {
        let nodes = vec![NodeInfo::healthy("other", "z:a", 0.5, 10.0)];
        let ov = PlacementOverride::permanent("unknown-node", "speculative");
        assert!(apply_placement_override(&ov, &nodes).is_ok());
    }

    #[test]
    fn override_expiring_boundary() {
        let ov = PlacementOverride::expiring("node-x", "temp", "2026-03-12T12:00:00Z");
        assert!(ov.is_expired("2026-03-12T12:00:00Z")); // exact boundary = expired
        assert!(!ov.is_expired("2026-03-12T11:59:59Z"));
    }

    // ── Rollout strategy tests ───────────────────────────────────────

    #[test]
    fn plan_rollout_canary() {
        let cohort = plan_rollout(
            "canary-1",
            vec!["n1".to_string(), "n2".to_string()],
            RolloutStrategy::Canary,
        );
        assert_eq!(cohort.strategy, RolloutStrategy::Canary);
        assert_eq!(cohort.nodes.len(), 2);
        assert_eq!(cohort.cohort_id, "canary-1");
    }

    #[test]
    fn plan_rollout_rolling() {
        let nodes: Vec<String> = (0..10).map(|i| format!("node-{i}")).collect();
        let cohort = plan_rollout("rolling-1", nodes, RolloutStrategy::Rolling);
        assert_eq!(cohort.strategy, RolloutStrategy::Rolling);
        assert_eq!(cohort.len(), 10);
    }

    #[test]
    fn plan_rollout_blue_green() {
        let cohort = plan_rollout(
            "bg-1",
            vec!["blue-1".to_string(), "green-1".to_string()],
            RolloutStrategy::BlueGreen,
        );
        assert_eq!(cohort.strategy, RolloutStrategy::BlueGreen);
    }

    #[test]
    fn plan_rollout_all_at_once() {
        let nodes: Vec<String> = (0..5).map(|i| format!("n{i}")).collect();
        let cohort = plan_rollout("blast-1", nodes, RolloutStrategy::AllAtOnce);
        assert_eq!(cohort.strategy, RolloutStrategy::AllAtOnce);
        assert_eq!(cohort.len(), 5);
    }

    #[test]
    fn plan_rollout_empty_cohort() {
        let cohort = plan_rollout("empty", vec![], RolloutStrategy::Canary);
        assert!(cohort.is_empty());
        assert_eq!(cohort.len(), 0);
    }

    #[test]
    fn plan_rollout_single_node() {
        let cohort = plan_rollout("single", vec!["solo".to_string()], RolloutStrategy::Rolling);
        assert_eq!(cohort.len(), 1);
    }

    #[test]
    fn rollout_strategy_display() {
        assert_eq!(RolloutStrategy::Canary.to_string(), "canary");
        assert_eq!(RolloutStrategy::Rolling.to_string(), "rolling");
        assert_eq!(RolloutStrategy::BlueGreen.to_string(), "blue-green");
        assert_eq!(RolloutStrategy::AllAtOnce.to_string(), "all-at-once");
    }

    // ── Convergence tests ────────────────────────────────────────────

    #[test]
    fn convergence_all_at_target() {
        let cohort = plan_rollout(
            "c1",
            vec!["n1".to_string(), "n2".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = vec![
            NodeVersionState {
                node_id: "n1".to_string(),
                current_version: "1.0.0".to_string(),
            },
            NodeVersionState {
                node_id: "n2".to_string(),
                current_version: "1.0.0".to_string(),
            },
        ];
        let report = check_convergence(&cohort, "1.0.0", &states);
        assert!(report.is_converged());
        assert!((report.convergence_ratio() - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.nodes_at_target.len(), 2);
    }

    #[test]
    fn convergence_partial() {
        let cohort = plan_rollout(
            "c2",
            vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = sample_version_states("1.0.0");
        let report = check_convergence(&cohort, "1.0.0", &states);
        assert!(!report.is_converged());
        assert_eq!(report.nodes_at_target.len(), 2);
        assert_eq!(report.nodes_behind.len(), 1);
        assert!(report.convergence_ratio() > 0.6);
        assert!(report.convergence_ratio() < 0.7);
    }

    #[test]
    fn convergence_none_at_target() {
        let cohort = plan_rollout(
            "c3",
            vec!["n1".to_string(), "n2".to_string()],
            RolloutStrategy::Canary,
        );
        let states = vec![
            NodeVersionState {
                node_id: "n1".to_string(),
                current_version: "0.8.0".to_string(),
            },
            NodeVersionState {
                node_id: "n2".to_string(),
                current_version: "0.8.0".to_string(),
            },
        ];
        let report = check_convergence(&cohort, "1.0.0", &states);
        assert!(!report.is_converged());
        assert!(report.nodes_at_target.is_empty());
        assert_eq!(report.nodes_behind.len(), 2);
        assert!((report.convergence_ratio()).abs() < f64::EPSILON);
    }

    #[test]
    fn convergence_with_drift() {
        let cohort = plan_rollout(
            "c4",
            vec!["n1".to_string(), "n2".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = vec![
            NodeVersionState {
                node_id: "n1".to_string(),
                current_version: "1.0.0".to_string(),
            },
            NodeVersionState {
                node_id: "n2".to_string(),
                current_version: "2.0.0".to_string(), // ahead = drift
            },
        ];
        let report = check_convergence(&cohort, "1.0.0", &states);
        assert!(!report.is_converged());
        assert_eq!(report.drift_nodes.len(), 1);
        assert_eq!(report.drift_nodes[0], "n2");
    }

    #[test]
    fn convergence_unknown_nodes_counted_behind() {
        let cohort = plan_rollout(
            "c5",
            vec!["n1".to_string(), "missing".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = vec![NodeVersionState {
            node_id: "n1".to_string(),
            current_version: "1.0.0".to_string(),
        }];
        let report = check_convergence(&cohort, "1.0.0", &states);
        assert!(!report.is_converged());
        assert_eq!(report.nodes_behind.len(), 1);
        assert_eq!(report.nodes_behind[0], "missing");
    }

    #[test]
    fn convergence_empty_cohort() {
        let cohort = plan_rollout("c6", vec![], RolloutStrategy::AllAtOnce);
        let report = check_convergence(&cohort, "1.0.0", &[]);
        assert!(report.nodes_at_target.is_empty());
        assert!(report.nodes_behind.is_empty());
        assert!((report.convergence_ratio()).abs() < f64::EPSILON);
    }

    // ── Offline availability tests ───────────────────────────────────

    #[test]
    fn offline_all_available() {
        let mirror = MirrorSource::verified_offline("https://mirror.local", "2026-03-12T00:00:00Z");
        let mut available = HashMap::new();
        available.insert(
            "slack".to_string(),
            OfflineAvailability::available(
                "slack",
                vec!["1.0.0".to_string(), "1.1.0".to_string()],
                mirror.clone(),
                "2026-03-12T00:00:00Z",
            ),
        );
        available.insert(
            "github".to_string(),
            OfflineAvailability::available(
                "github",
                vec!["2.0.0".to_string()],
                mirror,
                "2026-03-12T00:00:00Z",
            ),
        );
        let results = check_offline_availability(&["slack", "github"], &available);
        assert!(results.iter().all(|r| r.is_available()));
    }

    #[test]
    fn offline_none_available() {
        let available = HashMap::new();
        let results = check_offline_availability(&["slack", "github"], &available);
        assert!(results.iter().all(|r| !r.is_available()));
    }

    #[test]
    fn offline_partial() {
        let mirror = MirrorSource::verified_offline("https://mirror.local", "2026-03-12T00:00:00Z");
        let mut available = HashMap::new();
        available.insert(
            "slack".to_string(),
            OfflineAvailability::available(
                "slack",
                vec!["1.0.0".to_string()],
                mirror,
                "2026-03-12T00:00:00Z",
            ),
        );
        let results = check_offline_availability(&["slack", "github"], &available);
        assert!(results[0].is_available());
        assert!(!results[1].is_available());
    }

    #[test]
    fn offline_empty_connectors() {
        let available = HashMap::new();
        let results = check_offline_availability(&[], &available);
        assert!(results.is_empty());
    }

    #[test]
    fn offline_availability_unavailable_has_no_versions() {
        let u = OfflineAvailability::unavailable("test");
        assert!(!u.is_available());
        assert!(u.available_versions.is_empty());
        assert!(u.mirror_source.is_none());
    }

    // ── Mirror status tests ──────────────────────────────────────────

    #[test]
    fn mirror_status_verified() {
        let mirrors = vec![
            MirrorSource::verified_online("https://m1.example.com", "2026-03-12T00:00:00Z"),
            MirrorSource::verified_offline("https://m2.example.com", "2026-03-11T00:00:00Z"),
        ];
        let status = check_mirror_status(&mirrors);
        assert_eq!(status.len(), 2);
        assert!(status["https://m1.example.com"]);
        assert!(status["https://m2.example.com"]);
    }

    #[test]
    fn mirror_status_unverified() {
        let mirrors = vec![MirrorSource::unverified("https://sketchy.example.com")];
        let status = check_mirror_status(&mirrors);
        assert!(!status["https://sketchy.example.com"]);
    }

    #[test]
    fn mirror_status_mixed() {
        let mirrors = vec![
            MirrorSource::verified_online("https://good.example.com", "2026-03-12T00:00:00Z"),
            MirrorSource::unverified("https://bad.example.com"),
        ];
        let status = check_mirror_status(&mirrors);
        assert!(status["https://good.example.com"]);
        assert!(!status["https://bad.example.com"]);
    }

    #[test]
    fn mirror_status_empty() {
        let status = check_mirror_status(&[]);
        assert!(status.is_empty());
    }

    #[test]
    fn mirror_stale_detection() {
        let m = MirrorSource::verified_online("https://m.example.com", "2025-01-01T00:00:00Z");
        // "Stale" = last_synced far in the past. The struct records this; policy is up to caller.
        assert!(m.verified);
        assert!(!m.last_synced.is_empty());
        assert!(m.last_synced.as_str() < "2026-03-12T00:00:00Z");
    }

    #[test]
    fn mirror_never_synced() {
        let m = MirrorSource::unverified("https://new.example.com");
        assert!(m.last_synced.is_empty());
        assert!(!m.available_offline);
    }

    // ── Verification matrix tests ────────────────────────────────────

    #[test]
    fn verification_all_pass() {
        let scenarios = sample_scenarios();
        let results =
            run_verification_matrix(&scenarios, |_s| (true, "ok".to_string(), String::new()));
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn verification_all_fail() {
        let scenarios = sample_scenarios();
        let results = run_verification_matrix(&scenarios, |s| {
            (false, "error".to_string(), format!("{} failed", s.name))
        });
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| !r.passed));
        assert!(results[0].details.contains("basic-invoke"));
    }

    #[test]
    fn verification_partial() {
        let scenarios = sample_scenarios();
        let results = run_verification_matrix(&scenarios, |s| {
            if s.name == "basic-invoke" {
                (true, "200 OK".to_string(), String::new())
            } else {
                (false, "unexpected".to_string(), "mismatch".to_string())
            }
        });
        assert!(results[0].passed);
        assert!(!results[1].passed);
        assert!(!results[2].passed);
    }

    #[test]
    fn verification_empty_matrix() {
        let results = run_verification_matrix(&[], |_| (true, String::new(), String::new()));
        assert!(results.is_empty());
    }

    #[test]
    fn verification_result_details_preserved() {
        let scenarios = vec![VerificationScenario::new(
            "detail-test",
            "check details",
            serde_json::json!({}),
            "should pass",
        )];
        let results = run_verification_matrix(&scenarios, |_| {
            (
                false,
                "bad".to_string(),
                "detailed error message".to_string(),
            )
        });
        assert_eq!(results[0].details, "detailed error message");
        assert_eq!(results[0].actual_outcome, "bad");
    }

    #[test]
    fn verification_scenario_input_accessible() {
        let scenarios = vec![VerificationScenario::new(
            "input-test",
            "verify input",
            serde_json::json!({"key": "value"}),
            "ok",
        )];
        let results = run_verification_matrix(&scenarios, |s| {
            let has_key = s.input.get("key").is_some();
            (has_key, "checked".to_string(), String::new())
        });
        assert!(results[0].passed);
    }

    // ── TOON formatting tests ────────────────────────────────────────

    #[test]
    fn toon_context_basic() {
        let ctx = MeshContext::from_env("node-1", "z:work");
        let lines = format_context_toon(&ctx);
        assert!(lines.iter().any(|l| l.contains("Mesh Context")));
        assert!(lines.iter().any(|l| l.contains("node-1")));
        assert!(lines.iter().any(|l| l.contains("z:work")));
        assert!(lines.iter().any(|l| l.contains("environment")));
    }

    #[test]
    fn toon_context_override() {
        let ctx = MeshContext::from_override("node-x", "z:override");
        let lines = format_context_toon(&ctx);
        assert!(lines.iter().any(|l| l.contains("Override")));
    }

    #[test]
    fn toon_context_inferred() {
        let ctx = MeshContext::inferred("local", "z:default");
        let lines = format_context_toon(&ctx);
        assert!(lines.iter().any(|l| l.contains("Inferred")));
    }

    #[test]
    fn toon_placement_basic() {
        let target = ExecutionTarget::new("node-a", "z:us", PlacementReason::LeastLoaded, 0.85);
        let lines = format_placement_toon(&target);
        assert!(lines.iter().any(|l| l.contains("Execution Target")));
        assert!(lines.iter().any(|l| l.contains("node-a")));
        assert!(lines.iter().any(|l| l.contains("z:us")));
        assert!(lines.iter().any(|l| l.contains("85%")));
    }

    #[test]
    fn toon_placement_reason_displayed() {
        let target = ExecutionTarget::new("n", "z", PlacementReason::DataLocality, 0.9);
        let lines = format_placement_toon(&target);
        assert!(lines.iter().any(|l| l.contains("data-locality")));
    }

    #[test]
    fn toon_explanation_with_alternatives() {
        let nodes = sample_nodes();
        let exp = explain_placement(&nodes, &empty_constraints());
        let lines = format_explanation_toon(&exp);
        assert!(lines.iter().any(|l| l.contains("Placement Explanation")));
        assert!(lines.iter().any(|l| l.contains("Chosen")));
        assert!(lines.iter().any(|l| l.contains("Alternatives")));
    }

    #[test]
    fn toon_explanation_with_rejections() {
        let mut nodes = sample_nodes();
        nodes.push(NodeInfo::cordoned("bad", "z:us-east"));
        let exp = explain_placement(&nodes, &empty_constraints());
        let lines = format_explanation_toon(&exp);
        assert!(lines.iter().any(|l| l.contains("Rejections")));
    }

    #[test]
    fn toon_explanation_with_constraints() {
        let nodes = sample_nodes();
        let constraints = SelectionConstraints {
            zone_filter: vec!["z:us-east".to_string()],
            max_load: Some(0.7),
            ..Default::default()
        };
        let exp = explain_placement(&nodes, &constraints);
        let lines = format_explanation_toon(&exp);
        assert!(lines.iter().any(|l| l.contains("Constraints")));
        assert!(lines.iter().any(|l| l.contains("zone-filter")));
        assert!(lines.iter().any(|l| l.contains("max-load")));
    }

    #[test]
    fn toon_explanation_empty_mesh() {
        let exp = explain_placement(&[], &empty_constraints());
        let lines = format_explanation_toon(&exp);
        assert!(lines.iter().any(|l| l.contains("none")));
    }

    #[test]
    fn toon_rollout_basic() {
        let cohort = plan_rollout(
            "rollout-1",
            vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
            RolloutStrategy::Canary,
        );
        let lines = format_rollout_toon(&cohort);
        assert!(lines.iter().any(|l| l.contains("Rollout Cohort")));
        assert!(lines.iter().any(|l| l.contains("rollout-1")));
        assert!(lines.iter().any(|l| l.contains("canary")));
        assert!(lines.iter().any(|l| l.contains("3")));
    }

    #[test]
    fn toon_rollout_empty() {
        let cohort = plan_rollout("empty", vec![], RolloutStrategy::AllAtOnce);
        let lines = format_rollout_toon(&cohort);
        assert!(lines.iter().any(|l| l.contains("0")));
    }

    #[test]
    fn toon_convergence_converged() {
        let cohort = plan_rollout(
            "c1",
            vec!["n1".to_string(), "n2".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = vec![
            NodeVersionState {
                node_id: "n1".to_string(),
                current_version: "1.0.0".to_string(),
            },
            NodeVersionState {
                node_id: "n2".to_string(),
                current_version: "1.0.0".to_string(),
            },
        ];
        let report = check_convergence(&cohort, "1.0.0", &states);
        let lines = format_convergence_toon(&report);
        assert!(lines.iter().any(|l| l.contains("CONVERGED")));
        assert!(lines.iter().any(|l| l.contains("100%")));
    }

    #[test]
    fn toon_convergence_in_progress() {
        let cohort = plan_rollout(
            "c2",
            vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = sample_version_states("1.0.0");
        let report = check_convergence(&cohort, "1.0.0", &states);
        let lines = format_convergence_toon(&report);
        assert!(lines.iter().any(|l| l.contains("IN PROGRESS")));
        assert!(lines.iter().any(|l| l.contains("Behind")));
    }

    #[test]
    fn toon_convergence_with_drift() {
        let cohort = plan_rollout(
            "c3",
            vec!["n1".to_string(), "n2".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = vec![
            NodeVersionState {
                node_id: "n1".to_string(),
                current_version: "1.0.0".to_string(),
            },
            NodeVersionState {
                node_id: "n2".to_string(),
                current_version: "2.0.0".to_string(),
            },
        ];
        let report = check_convergence(&cohort, "1.0.0", &states);
        let lines = format_convergence_toon(&report);
        assert!(lines.iter().any(|l| l.contains("Drift")));
    }

    #[test]
    fn toon_offline_all_available() {
        let mirror = MirrorSource::verified_offline("https://m.local", "2026-03-12T00:00:00Z");
        let avail = vec![OfflineAvailability::available(
            "slack",
            vec!["1.0.0".to_string()],
            mirror,
            "2026-03-12T00:00:00Z",
        )];
        let lines = format_offline_toon(&avail);
        assert!(lines.iter().any(|l| l.contains("Offline Availability")));
        assert!(lines.iter().any(|l| l.contains("[available]")));
        assert!(lines.iter().any(|l| l.contains("slack")));
    }

    #[test]
    fn toon_offline_none_available() {
        let avail = vec![OfflineAvailability::unavailable("github")];
        let lines = format_offline_toon(&avail);
        assert!(lines.iter().any(|l| l.contains("[unavailable]")));
        assert!(lines.iter().any(|l| l.contains("github")));
    }

    #[test]
    fn toon_offline_mirror_details() {
        let mirror = MirrorSource::verified_offline("https://m.local", "2026-03-12T00:00:00Z");
        let avail = vec![OfflineAvailability::available(
            "jira",
            vec!["1.0.0".to_string()],
            mirror,
            "2026-03-12T00:00:00Z",
        )];
        let lines = format_offline_toon(&avail);
        assert!(lines.iter().any(|l| l.contains("mirror")));
        assert!(lines.iter().any(|l| l.contains("https://m.local")));
    }

    #[test]
    fn toon_verification_all_pass() {
        let scenarios = sample_scenarios();
        let results =
            run_verification_matrix(&scenarios, |_| (true, "ok".to_string(), String::new()));
        let lines = format_verification_toon(&results);
        assert!(lines.iter().any(|l| l.contains("Verification Matrix")));
        assert!(lines.iter().any(|l| l.contains("Passed: 3")));
        assert!(lines.iter().any(|l| l.contains("Failed: 0")));
        assert!(lines.iter().any(|l| l.contains("[PASS]")));
    }

    #[test]
    fn toon_verification_all_fail() {
        let scenarios = sample_scenarios();
        let results = run_verification_matrix(&scenarios, |s| {
            (false, "error".to_string(), format!("{} failed", s.name))
        });
        let lines = format_verification_toon(&results);
        assert!(lines.iter().any(|l| l.contains("Failed: 3")));
        assert!(lines.iter().any(|l| l.contains("[FAIL]")));
        assert!(lines.iter().any(|l| l.contains("Expected")));
        assert!(lines.iter().any(|l| l.contains("Actual")));
    }

    #[test]
    fn toon_verification_partial() {
        let scenarios = sample_scenarios();
        let results = run_verification_matrix(&scenarios, |s| {
            if s.name == "basic-invoke" {
                (true, "200 OK".to_string(), String::new())
            } else {
                (false, "err".to_string(), "detail".to_string())
            }
        });
        let lines = format_verification_toon(&results);
        assert!(lines.iter().any(|l| l.contains("Passed: 1")));
        assert!(lines.iter().any(|l| l.contains("Failed: 2")));
    }

    #[test]
    fn toon_verification_failure_details() {
        let scenarios = vec![VerificationScenario::new(
            "detail-check",
            "check",
            serde_json::json!({}),
            "expected good",
        )];
        let results = run_verification_matrix(&scenarios, |_| {
            (
                false,
                "actual bad".to_string(),
                "something went wrong".to_string(),
            )
        });
        let lines = format_verification_toon(&results);
        assert!(lines.iter().any(|l| l.contains("Details")));
        assert!(lines.iter().any(|l| l.contains("something went wrong")));
    }

    #[test]
    fn toon_verification_empty() {
        let lines = format_verification_toon(&[]);
        assert!(lines.iter().any(|l| l.contains("Total: 0")));
    }

    // ── Serialization round-trip tests ───────────────────────────────

    #[test]
    fn mesh_context_serialization_roundtrip() {
        let ctx = MeshContext::from_env("node-1", "z:work");
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: MeshContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.active_node, "node-1");
        assert_eq!(parsed.active_zone, "z:work");
        assert_eq!(parsed.source, ContextSource::Environment);
    }

    #[test]
    fn execution_target_serialization_roundtrip() {
        let target = ExecutionTarget::new("n1", "z:a", PlacementReason::LeastLoaded, 0.85);
        let json = serde_json::to_string(&target).unwrap();
        let parsed: ExecutionTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.node_id, "n1");
        assert_eq!(parsed.placement_reason, PlacementReason::LeastLoaded);
    }

    #[test]
    fn rollout_strategy_serialization_roundtrip() {
        for strategy in [
            RolloutStrategy::Canary,
            RolloutStrategy::Rolling,
            RolloutStrategy::BlueGreen,
            RolloutStrategy::AllAtOnce,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let parsed: RolloutStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, strategy);
        }
    }

    #[test]
    fn placement_override_serialization_roundtrip() {
        let ov = PlacementOverride::expiring("node-x", "migration", "2026-06-01T00:00:00Z");
        let json = serde_json::to_string(&ov).unwrap();
        let parsed: PlacementOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target_node, "node-x");
        assert_eq!(parsed.reason, "migration");
        assert!(!parsed.force);
    }

    #[test]
    fn convergence_report_serialization() {
        let cohort = plan_rollout("test", vec!["n1".to_string()], RolloutStrategy::Canary);
        let report = ConvergenceReport {
            cohort,
            target_version: "1.0.0".to_string(),
            nodes_at_target: vec!["n1".to_string()],
            nodes_behind: vec![],
            drift_nodes: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"target_version\":\"1.0.0\""));
    }

    #[test]
    fn mirror_source_serialization_roundtrip() {
        let m = MirrorSource::verified_offline("https://m.local", "2026-03-12T00:00:00Z");
        let json = serde_json::to_string(&m).unwrap();
        let parsed: MirrorSource = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, "https://m.local");
        assert!(parsed.verified);
        assert!(parsed.available_offline);
    }

    #[test]
    fn verification_scenario_serialization() {
        let s = VerificationScenario::new("test", "desc", serde_json::json!({"a": 1}), "ok");
        let json = serde_json::to_string(&s).unwrap();
        let parsed: VerificationScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.input["a"], 1);
    }

    #[test]
    fn node_lifecycle_action_serialization() {
        for action in [
            NodeLifecycleAction::Enable,
            NodeLifecycleAction::Disable,
            NodeLifecycleAction::Drain,
            NodeLifecycleAction::Cordon,
            NodeLifecycleAction::Uncordon,
            NodeLifecycleAction::Restart,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: NodeLifecycleAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    // ── Display trait tests ──────────────────────────────────────────

    #[test]
    fn context_source_display() {
        assert_eq!(ContextSource::Environment.to_string(), "environment");
        assert_eq!(ContextSource::Config.to_string(), "config");
        assert_eq!(ContextSource::Override.to_string(), "override");
        assert_eq!(ContextSource::Inferred.to_string(), "inferred");
    }

    #[test]
    fn placement_reason_display() {
        assert_eq!(PlacementReason::DataLocality.to_string(), "data-locality");
        assert_eq!(PlacementReason::LowestLatency.to_string(), "lowest-latency");
        assert_eq!(
            PlacementReason::ExplicitOverride.to_string(),
            "explicit-override"
        );
        assert_eq!(PlacementReason::OnlyAvailable.to_string(), "only-available");
        assert_eq!(PlacementReason::Affinity.to_string(), "affinity");
        assert_eq!(PlacementReason::LeastLoaded.to_string(), "least-loaded");
    }

    #[test]
    fn node_lifecycle_action_display() {
        assert_eq!(NodeLifecycleAction::Enable.to_string(), "enable");
        assert_eq!(NodeLifecycleAction::Disable.to_string(), "disable");
        assert_eq!(NodeLifecycleAction::Drain.to_string(), "drain");
        assert_eq!(NodeLifecycleAction::Cordon.to_string(), "cordon");
        assert_eq!(NodeLifecycleAction::Uncordon.to_string(), "uncordon");
        assert_eq!(NodeLifecycleAction::Restart.to_string(), "restart");
    }

    // ── Edge case tests ──────────────────────────────────────────────

    #[test]
    fn execution_target_confidence_clamped() {
        let t = ExecutionTarget::new("n", "z", PlacementReason::Affinity, 1.5);
        assert!((t.confidence - 1.0).abs() < f64::EPSILON);

        let t2 = ExecutionTarget::new("n", "z", PlacementReason::Affinity, -0.5);
        assert!(t2.confidence.abs() < f64::EPSILON);
    }

    #[test]
    fn node_info_cordoned_is_not_schedulable() {
        let n = NodeInfo::cordoned("n1", "z:a");
        assert!(!n.schedulable);
    }

    #[test]
    fn node_info_healthy_is_schedulable() {
        let n = NodeInfo::healthy("n1", "z:a", 0.5, 10.0);
        assert!(n.schedulable);
    }

    #[test]
    fn select_target_mixed_schedulable_and_cordoned() {
        let nodes = vec![
            NodeInfo::cordoned("n1", "z:a"),
            NodeInfo::healthy("n2", "z:a", 0.5, 10.0),
            NodeInfo::cordoned("n3", "z:a"),
        ];
        let target = select_execution_target(&nodes, &empty_constraints()).unwrap();
        assert_eq!(target.node_id, "n2");
        assert_eq!(target.placement_reason, PlacementReason::OnlyAvailable);
    }

    #[test]
    fn convergence_ratio_precision() {
        let cohort = plan_rollout(
            "c",
            vec!["n1".to_string(), "n2".to_string(), "n3".to_string()],
            RolloutStrategy::Rolling,
        );
        let states = vec![NodeVersionState {
            node_id: "n1".to_string(),
            current_version: "1.0.0".to_string(),
        }];
        let report = check_convergence(&cohort, "1.0.0", &states);
        // 1/3 ~ 0.333
        assert!((report.convergence_ratio() - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn offline_availability_multiple_versions() {
        let mirror = MirrorSource::verified_offline("https://m.local", "2026-03-12T00:00:00Z");
        let a = OfflineAvailability::available(
            "slack",
            vec![
                "1.0.0".to_string(),
                "1.1.0".to_string(),
                "2.0.0".to_string(),
            ],
            mirror,
            "2026-03-12T00:00:00Z",
        );
        assert!(a.is_available());
        assert_eq!(a.available_versions.len(), 3);
    }

    #[test]
    fn verification_result_pass_has_empty_details() {
        let s = VerificationScenario::new("t", "d", serde_json::json!({}), "ok");
        let r = VerificationResult::pass(s, "ok");
        assert!(r.passed);
        assert!(r.details.is_empty());
    }

    #[test]
    fn verification_result_fail_has_details() {
        let s = VerificationScenario::new("t", "d", serde_json::json!({}), "ok");
        let r = VerificationResult::fail(s, "bad", "error details");
        assert!(!r.passed);
        assert_eq!(r.details, "error details");
    }

    #[test]
    fn placement_constraint_satisfied() {
        let c = PlacementConstraint {
            name: "zone".to_string(),
            satisfied: true,
            description: "must be in z:us".to_string(),
        };
        assert!(c.satisfied);
    }

    #[test]
    fn placement_constraint_not_satisfied() {
        let c = PlacementConstraint {
            name: "zone".to_string(),
            satisfied: false,
            description: "must be in z:us".to_string(),
        };
        assert!(!c.satisfied);
    }

    #[test]
    fn alternative_rejection_reason() {
        let r = AlternativeRejection {
            node_id: "n1".to_string(),
            reason: "too slow".to_string(),
        };
        assert_eq!(r.node_id, "n1");
        assert!(r.reason.contains("slow"));
    }

    #[test]
    fn node_version_state_fields() {
        let s = NodeVersionState {
            node_id: "n1".to_string(),
            current_version: "1.0.0".to_string(),
        };
        assert_eq!(s.node_id, "n1");
        assert_eq!(s.current_version, "1.0.0");
    }

    #[test]
    fn selection_constraints_default() {
        let c = SelectionConstraints::default();
        assert!(c.zone_filter.is_empty());
        assert!(c.required_labels.is_empty());
        assert!(c.max_load.is_none());
        assert!(c.max_latency_ms.is_none());
    }

    #[test]
    fn toon_rollout_all_strategies() {
        for strategy in [
            RolloutStrategy::Canary,
            RolloutStrategy::Rolling,
            RolloutStrategy::BlueGreen,
            RolloutStrategy::AllAtOnce,
        ] {
            let label = strategy.to_string();
            let cohort = plan_rollout("test", vec!["n1".to_string()], strategy);
            let lines = format_rollout_toon(&cohort);
            assert!(lines.iter().any(|l| l.contains(&label)));
        }
    }

    #[test]
    fn toon_placement_all_reasons() {
        for reason in [
            PlacementReason::DataLocality,
            PlacementReason::LowestLatency,
            PlacementReason::ExplicitOverride,
            PlacementReason::OnlyAvailable,
            PlacementReason::Affinity,
            PlacementReason::LeastLoaded,
        ] {
            let label = reason.to_string();
            let target = ExecutionTarget::new("n", "z", reason, 0.5);
            let lines = format_placement_toon(&target);
            assert!(lines.iter().any(|l| l.contains(&label)));
        }
    }

    #[test]
    fn format_context_toon_line_count() {
        let ctx = MeshContext::from_env("n", "z");
        let lines = format_context_toon(&ctx);
        // Header + node + zone + source = at least 4 lines.
        assert!(lines.len() >= 4);
    }

    #[test]
    fn format_placement_toon_line_count() {
        let target = ExecutionTarget::new("n", "z", PlacementReason::Affinity, 0.5);
        let lines = format_placement_toon(&target);
        assert!(lines.len() >= 4); // header + node + zone + reason + confidence
    }

    #[test]
    fn toon_offline_empty_list() {
        let lines = format_offline_toon(&[]);
        assert_eq!(lines.len(), 1); // just the header
    }

    // ── Additional edge case and coverage tests ──────────────────────

    #[test]
    fn select_target_two_nodes_same_load() {
        let nodes = vec![
            NodeInfo::healthy("a", "z:a", 0.5, 10.0),
            NodeInfo::healthy("b", "z:a", 0.5, 10.0),
        ];
        let target = select_execution_target(&nodes, &empty_constraints()).unwrap();
        // Either is acceptable; both have same load.
        assert!(target.node_id == "a" || target.node_id == "b");
    }

    #[test]
    fn select_target_three_nodes_different_zones() {
        let nodes = vec![
            NodeInfo::healthy("n1", "z:us", 0.5, 10.0),
            NodeInfo::healthy("n2", "z:eu", 0.3, 20.0),
            NodeInfo::healthy("n3", "z:ap", 0.1, 50.0),
        ];
        let constraints = SelectionConstraints {
            zone_filter: vec!["z:eu".to_string(), "z:ap".to_string()],
            ..Default::default()
        };
        let target = select_execution_target(&nodes, &constraints).unwrap();
        assert_eq!(target.node_id, "n3"); // lowest load among eu and ap
    }

    #[test]
    fn select_target_multiple_labels_required() {
        let mut node = NodeInfo::healthy("n1", "z:a", 0.1, 10.0);
        node.labels.insert("env".to_string(), "prod".to_string());
        node.labels.insert("region".to_string(), "us".to_string());
        let nodes = vec![node];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        required.insert("region".to_string(), "us".to_string());
        let constraints = SelectionConstraints {
            required_labels: required,
            ..Default::default()
        };
        let target = select_execution_target(&nodes, &constraints).unwrap();
        assert_eq!(target.node_id, "n1");
    }

    #[test]
    fn select_target_partial_label_match_rejected() {
        let mut node = NodeInfo::healthy("n1", "z:a", 0.1, 10.0);
        node.labels.insert("env".to_string(), "prod".to_string());
        let nodes = vec![node];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        required.insert("gpu".to_string(), "true".to_string());
        let constraints = SelectionConstraints {
            required_labels: required,
            ..Default::default()
        };
        assert!(select_execution_target(&nodes, &constraints).is_none());
    }

    #[test]
    fn override_reason_preserved() {
        let ov = PlacementOverride::permanent("n1", "data migration to new cluster");
        assert_eq!(ov.reason, "data migration to new cluster");
    }

    #[test]
    fn override_force_flag() {
        let ov = PlacementOverride::forced("n1", "emergency");
        assert!(ov.force);
        let ov2 = PlacementOverride::permanent("n1", "routine");
        assert!(!ov2.force);
    }

    #[test]
    fn context_source_equality() {
        assert_eq!(ContextSource::Environment, ContextSource::Environment);
        assert_ne!(ContextSource::Environment, ContextSource::Config);
        assert_ne!(ContextSource::Override, ContextSource::Inferred);
    }

    #[test]
    fn placement_reason_equality() {
        assert_eq!(PlacementReason::DataLocality, PlacementReason::DataLocality);
        assert_ne!(PlacementReason::LeastLoaded, PlacementReason::Affinity);
    }

    #[test]
    fn node_lifecycle_action_equality() {
        assert_eq!(NodeLifecycleAction::Enable, NodeLifecycleAction::Enable);
        assert_ne!(NodeLifecycleAction::Drain, NodeLifecycleAction::Cordon);
    }

    #[test]
    fn rollout_strategy_equality() {
        assert_eq!(RolloutStrategy::Canary, RolloutStrategy::Canary);
        assert_ne!(RolloutStrategy::Canary, RolloutStrategy::Rolling);
    }

    #[test]
    fn convergence_all_drift() {
        let cohort = plan_rollout(
            "drift-all",
            vec!["n1".to_string(), "n2".to_string()],
            RolloutStrategy::AllAtOnce,
        );
        let states = vec![
            NodeVersionState {
                node_id: "n1".to_string(),
                current_version: "3.0.0".to_string(),
            },
            NodeVersionState {
                node_id: "n2".to_string(),
                current_version: "2.0.0".to_string(),
            },
        ];
        let report = check_convergence(&cohort, "1.0.0", &states);
        assert_eq!(report.drift_nodes.len(), 2);
        assert!(report.nodes_at_target.is_empty());
    }

    #[test]
    fn convergence_single_node_at_target() {
        let cohort = plan_rollout("c", vec!["n1".to_string()], RolloutStrategy::Canary);
        let states = vec![NodeVersionState {
            node_id: "n1".to_string(),
            current_version: "1.0.0".to_string(),
        }];
        let report = check_convergence(&cohort, "1.0.0", &states);
        assert!(report.is_converged());
        assert!((report.convergence_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn offline_availability_with_no_mirror() {
        let a = OfflineAvailability {
            connector: "test".to_string(),
            available_versions: vec!["1.0.0".to_string()],
            mirror_source: None,
            last_verified: "2026-03-12T00:00:00Z".to_string(),
        };
        assert!(a.is_available());
        assert!(a.mirror_source.is_none());
    }

    #[test]
    fn mirror_source_online_not_offline() {
        let m = MirrorSource::verified_online("https://m.local", "2026-03-12T00:00:00Z");
        assert!(m.verified);
        assert!(!m.available_offline);
    }

    #[test]
    fn mirror_source_offline_is_offline() {
        let m = MirrorSource::verified_offline("https://m.local", "2026-03-12T00:00:00Z");
        assert!(m.verified);
        assert!(m.available_offline);
    }

    #[test]
    fn toon_context_config_source() {
        let ctx = MeshContext::from_config("cfg-node", "z:cfg");
        let lines = format_context_toon(&ctx);
        assert!(lines.iter().any(|l| l.contains("config")));
        assert!(lines.iter().any(|l| l.contains("cfg-node")));
    }

    #[test]
    fn toon_placement_100_percent_confidence() {
        let target = ExecutionTarget::new("n", "z", PlacementReason::OnlyAvailable, 1.0);
        let lines = format_placement_toon(&target);
        assert!(lines.iter().any(|l| l.contains("100%")));
    }

    #[test]
    fn toon_placement_zero_confidence() {
        let target = ExecutionTarget::new("n", "z", PlacementReason::LeastLoaded, 0.0);
        let lines = format_placement_toon(&target);
        assert!(lines.iter().any(|l| l.contains("0%")));
    }

    #[test]
    fn toon_explanation_no_rejections() {
        let nodes = vec![
            NodeInfo::healthy("a", "z:a", 0.2, 10.0),
            NodeInfo::healthy("b", "z:a", 0.3, 10.0),
        ];
        let exp = explain_placement(&nodes, &empty_constraints());
        let lines = format_explanation_toon(&exp);
        // Should not have "Rejections" line since all nodes passed.
        assert!(!lines.iter().any(|l| l == "Rejections:"));
    }

    #[test]
    fn toon_convergence_target_version_shown() {
        let cohort = plan_rollout("c", vec!["n1".to_string()], RolloutStrategy::Canary);
        let states = vec![NodeVersionState {
            node_id: "n1".to_string(),
            current_version: "2.5.3".to_string(),
        }];
        let report = check_convergence(&cohort, "2.5.3", &states);
        let lines = format_convergence_toon(&report);
        assert!(lines.iter().any(|l| l.contains("2.5.3")));
    }

    #[test]
    fn toon_offline_multiple_connectors() {
        let mirror = MirrorSource::verified_offline("https://m.local", "2026-03-12T00:00:00Z");
        let avail = vec![
            OfflineAvailability::available(
                "slack",
                vec!["1.0.0".to_string()],
                mirror.clone(),
                "2026-03-12T00:00:00Z",
            ),
            OfflineAvailability::unavailable("github"),
            OfflineAvailability::available(
                "jira",
                vec!["2.0.0".to_string()],
                mirror,
                "2026-03-12T00:00:00Z",
            ),
        ];
        let lines = format_offline_toon(&avail);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("[available]") && l.contains("slack"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("[unavailable]") && l.contains("github"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("[available]") && l.contains("jira"))
        );
    }

    #[test]
    fn toon_verification_single_pass() {
        let scenarios = vec![VerificationScenario::new(
            "solo",
            "single test",
            serde_json::json!({}),
            "pass",
        )];
        let results =
            run_verification_matrix(&scenarios, |_| (true, "ok".to_string(), String::new()));
        let lines = format_verification_toon(&results);
        assert!(lines.iter().any(|l| l.contains("Total: 1")));
        assert!(lines.iter().any(|l| l.contains("Passed: 1")));
        assert!(lines.iter().any(|l| l.contains("Failed: 0")));
    }

    #[test]
    fn toon_verification_single_fail() {
        let scenarios = vec![VerificationScenario::new(
            "bad",
            "failing test",
            serde_json::json!({}),
            "should pass",
        )];
        let results = run_verification_matrix(&scenarios, |_| {
            (false, "failed".to_string(), "reason".to_string())
        });
        let lines = format_verification_toon(&results);
        assert!(lines.iter().any(|l| l.contains("[FAIL]")));
        assert!(lines.iter().any(|l| l.contains("Expected")));
        assert!(lines.iter().any(|l| l.contains("Actual")));
    }

    #[test]
    fn context_from_override_fields() {
        let ctx = MeshContext::from_override("node-x", "z:override");
        assert_eq!(ctx.active_node, "node-x");
        assert_eq!(ctx.active_zone, "z:override");
        assert!(ctx.explicit_override);
        assert!(!ctx.inferred);
    }

    #[test]
    fn context_inferred_fields() {
        let ctx = MeshContext::inferred("local", "z:default");
        assert!(!ctx.explicit_override);
        assert!(ctx.inferred);
    }

    #[test]
    fn rollout_cohort_large() {
        let nodes: Vec<String> = (0..100).map(|i| format!("node-{i}")).collect();
        let cohort = plan_rollout("big", nodes, RolloutStrategy::Rolling);
        assert_eq!(cohort.len(), 100);
        assert!(!cohort.is_empty());
    }

    #[test]
    fn explain_placement_single_node_no_zones() {
        let nodes = vec![NodeInfo::healthy("solo", "z:a", 0.5, 10.0)];
        let exp = explain_placement(&nodes, &empty_constraints());
        assert_eq!(exp.target.node_id, "solo");
        assert!(exp.alternatives.is_empty());
        assert!(exp.why_not_alternatives.is_empty());
    }

    #[test]
    fn check_offline_single_connector() {
        let mut available = HashMap::new();
        let mirror = MirrorSource::verified_offline("https://m.local", "2026-03-12T00:00:00Z");
        available.insert(
            "slack".to_string(),
            OfflineAvailability::available(
                "slack",
                vec!["1.0.0".to_string()],
                mirror,
                "2026-03-12T00:00:00Z",
            ),
        );
        let results = check_offline_availability(&["slack"], &available);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_available());
    }

    #[test]
    fn check_mirror_status_single() {
        let mirrors = vec![MirrorSource::verified_online(
            "https://m.local",
            "2026-03-12T00:00:00Z",
        )];
        let status = check_mirror_status(&mirrors);
        assert_eq!(status.len(), 1);
        assert!(status["https://m.local"]);
    }

    #[test]
    fn node_info_labels_empty_by_default() {
        let n = NodeInfo::healthy("n1", "z:a", 0.5, 10.0);
        assert!(n.labels.is_empty());
    }

    #[test]
    fn node_info_cordoned_zero_load() {
        let n = NodeInfo::cordoned("n1", "z:a");
        assert!((n.load).abs() < f64::EPSILON);
        assert!((n.latency_ms).abs() < f64::EPSILON);
    }
}
