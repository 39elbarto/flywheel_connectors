//! FCP2 Execution Planner - Device-aware operation routing.
//!
//! This module provides a deterministic scoring and selection algorithm for
//! routing operations to the most suitable mesh nodes. It produces a ranked
//! candidate set with explainable decision reasons.
//!
//! # Scoring Algorithm
//!
//! The planner combines multiple factors into a final score:
//!
//! 1. **Device Fitness** (base): Uses [`FitnessScore`] from device module
//! 2. **Connector Availability**: Required connector must be installed with compatible version
//! 3. **Data Locality**: Bonus for nodes that already have required symbols
//! 4. **Lease Constraints**: Nodes holding conflicting leases are excluded
//!
//! # Example
//!
//! ```ignore
//! use fcp_mesh::planner::{ExecutionPlanner, PlannerContext, PlannerInput};
//!
//! let planner = ExecutionPlanner::new();
//! let context = PlannerContext::new(connector_id)
//!     .with_min_memory_mb(256)
//!     .with_required_symbols(vec![symbol_id]);
//!
//! let candidates = planner.plan(&input, &context);
//! if let Some(best) = candidates.first() {
//!     // Route to best.node_id
//! }
//! ```

use std::cmp::Ordering;
use std::collections::HashSet;

use fcp_core::{ConnectorId, ObjectId, ZoneId};
use fcp_tailscale::NodeId;

use crate::device::{DeviceProfile, FitnessContext};

// ============================================================================
// Scoring Constants
// ============================================================================

/// Bonus for having a required symbol locally (reduces network transfer).
const DATA_LOCALITY_BONUS: f64 = 15.0;

/// Penalty for missing required connector.
const MISSING_CONNECTOR_PENALTY: f64 = 1000.0;

/// Penalty for incompatible connector version.
const VERSION_MISMATCH_PENALTY: f64 = 500.0;

/// Penalty for singleton lease conflict.
const LEASE_CONFLICT_PENALTY: f64 = 1000.0;

/// Maximum candidates to return in ranked list.
const MAX_CANDIDATES: usize = 10;

// ============================================================================
// Core Types
// ============================================================================

/// A candidate node for operation execution with its score and decision reasons.
#[derive(Debug, Clone)]
pub struct CandidateNode {
    /// The node identifier.
    pub node_id: NodeId,
    /// Final computed score (higher is better).
    pub score: f64,
    /// Base fitness score from device profile.
    pub base_fitness: f64,
    /// Individual score adjustments with explanations.
    pub adjustments: Vec<ScoreAdjustment>,
    /// Whether this node is eligible (score > 0 and no hard constraints violated).
    pub eligible: bool,
    /// Reasons why this node was selected or rejected.
    pub decision_reasons: Vec<DecisionReason>,
}

impl CandidateNode {
    /// Create a new candidate with initial fitness score.
    fn new(node_id: NodeId, base_fitness: f64) -> Self {
        Self {
            node_id,
            score: base_fitness,
            base_fitness,
            adjustments: Vec::new(),
            eligible: true,
            decision_reasons: Vec::new(),
        }
    }

    /// Apply a score adjustment.
    fn adjust(&mut self, adjustment: ScoreAdjustment) {
        self.score += adjustment.delta;
        self.adjustments.push(adjustment);
    }

    /// Mark as ineligible with reason.
    fn mark_ineligible(&mut self, reason: DecisionReason) {
        self.eligible = false;
        self.score = 0.0;
        self.decision_reasons.push(reason);
    }

    /// Add a decision reason.
    fn add_reason(&mut self, reason: DecisionReason) {
        self.decision_reasons.push(reason);
    }
}

impl PartialEq for CandidateNode {
    fn eq(&self, other: &Self) -> bool {
        self.node_id.as_str() == other.node_id.as_str()
    }
}

impl Eq for CandidateNode {}

impl PartialOrd for CandidateNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CandidateNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher score is better, then break ties by node_id string for determinism
        match other.score.partial_cmp(&self.score) {
            Some(Ordering::Equal) | None => self.node_id.as_str().cmp(other.node_id.as_str()),
            Some(ord) => ord,
        }
    }
}

/// A score adjustment with explanation.
#[derive(Debug, Clone)]
pub struct ScoreAdjustment {
    /// The factor that caused this adjustment.
    pub factor: AdjustmentFactor,
    /// The score delta (positive = bonus, negative = penalty).
    pub delta: f64,
    /// Human-readable explanation.
    pub explanation: String,
}

impl ScoreAdjustment {
    fn bonus(factor: AdjustmentFactor, delta: f64, explanation: impl Into<String>) -> Self {
        Self {
            factor,
            delta,
            explanation: explanation.into(),
        }
    }

    fn penalty(factor: AdjustmentFactor, delta: f64, explanation: impl Into<String>) -> Self {
        Self {
            factor,
            delta: -delta.abs(),
            explanation: explanation.into(),
        }
    }
}

/// Categories of score adjustments for analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdjustmentFactor {
    /// Connector availability and version.
    Connector,
    /// Data locality (symbol presence).
    DataLocality,
    /// Lease constraints.
    LeaseConstraint,
    /// Zone restrictions.
    ZoneRestriction,
    /// Custom factor.
    Custom,
}

/// Decision reasons for audit and explainability.
#[derive(Debug, Clone)]
pub enum DecisionReason {
    /// Node selected as best candidate.
    SelectedAsBest { rank: usize },
    /// Node eligible but not selected.
    EligibleNotSelected { rank: usize, better_count: usize },
    /// Missing required connector.
    MissingConnector { connector_id: String },
    /// Connector version incompatible.
    IncompatibleVersion {
        connector_id: String,
        required: String,
        installed: String,
    },
    /// Lease conflict prevents execution.
    LeaseConflict {
        holder: NodeId,
        lease_purpose: String,
    },
    /// Zone restriction prevents execution.
    ZoneRestriction { zone: String, reason: String },
    /// Node has required data locally.
    HasLocalData { symbol_count: usize },
    /// Missing required symbol.
    MissingRequiredSymbol { symbol_prefix: String },
    /// Custom reason.
    Custom(String),
}

// ============================================================================
// Planner Context
// ============================================================================

/// Requirements and constraints for an operation execution.
#[derive(Debug, Clone)]
pub struct PlannerContext {
    /// Required connector ID.
    pub connector_id: ConnectorId,
    /// Minimum required connector version (semver string).
    pub min_connector_version: Option<String>,
    /// Minimum memory in MB.
    pub min_memory_mb: Option<u32>,
    /// Whether GPU is required.
    pub requires_gpu: bool,
    /// Whether TPU is required.
    pub requires_tpu: bool,
    /// Symbols that should be present locally (for data locality scoring).
    pub preferred_symbols: Vec<ObjectId>,
    /// Symbols that MUST be present locally (hard constraint).
    pub required_symbols: Vec<ObjectId>,
    /// If true, operation requires singleton_writer semantics.
    pub singleton_writer: bool,
    /// Target zone for zone-aware routing.
    pub target_zone: Option<ZoneId>,
    /// Nodes to exclude from consideration.
    pub excluded_nodes: HashSet<String>,
}

impl PlannerContext {
    /// Create a new context with required connector.
    #[must_use]
    pub fn new(connector_id: ConnectorId) -> Self {
        Self {
            connector_id,
            min_connector_version: None,
            min_memory_mb: None,
            requires_gpu: false,
            requires_tpu: false,
            preferred_symbols: Vec::new(),
            required_symbols: Vec::new(),
            singleton_writer: false,
            target_zone: None,
            excluded_nodes: HashSet::new(),
        }
    }

    /// Set minimum connector version requirement.
    #[must_use]
    pub fn with_min_version(mut self, version: impl Into<String>) -> Self {
        self.min_connector_version = Some(version.into());
        self
    }

    /// Set minimum memory requirement.
    #[must_use]
    pub const fn with_min_memory_mb(mut self, mb: u32) -> Self {
        self.min_memory_mb = Some(mb);
        self
    }

    /// Set GPU requirement.
    #[must_use]
    pub const fn with_gpu(mut self) -> Self {
        self.requires_gpu = true;
        self
    }

    /// Set TPU requirement.
    #[must_use]
    pub const fn with_tpu(mut self) -> Self {
        self.requires_tpu = true;
        self
    }

    /// Add preferred symbols for locality scoring.
    #[must_use]
    pub fn with_preferred_symbols(mut self, symbols: Vec<ObjectId>) -> Self {
        self.preferred_symbols = symbols;
        self
    }

    /// Add required symbols (hard constraint).
    #[must_use]
    pub fn with_required_symbols(mut self, symbols: Vec<ObjectId>) -> Self {
        self.required_symbols = symbols;
        self
    }

    /// Enable singleton writer semantics.
    #[must_use]
    pub const fn with_singleton_writer(mut self) -> Self {
        self.singleton_writer = true;
        self
    }

    /// Set target zone.
    #[must_use]
    pub fn with_target_zone(mut self, zone: ZoneId) -> Self {
        self.target_zone = Some(zone);
        self
    }

    /// Exclude specific nodes by ID string.
    #[must_use]
    pub fn excluding(mut self, nodes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.excluded_nodes
            .extend(nodes.into_iter().map(Into::into));
        self
    }
}

// ============================================================================
// Planner Input
// ============================================================================

/// Information about a node available for planning.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Device profile for fitness scoring.
    pub profile: DeviceProfile,
    /// Symbols present on this node.
    pub local_symbols: HashSet<ObjectId>,
    /// Active leases held by this node.
    pub held_leases: Vec<HeldLease>,
}

impl NodeInfo {
    /// Get the node ID from the profile.
    #[must_use]
    pub fn node_id(&self) -> &NodeId {
        &self.profile.node_id
    }
}

/// A lease held by a node.
#[derive(Debug, Clone)]
pub struct HeldLease {
    /// Subject object ID the lease is for.
    pub subject_id: ObjectId,
    /// Purpose of the lease.
    pub purpose: LeasePurpose,
    /// Expiration timestamp (seconds since epoch).
    pub expires_at: u64,
}

/// Simplified lease purpose for planner decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeasePurpose {
    /// Exclusive write access for singleton-writer connector state.
    SingletonWriter,
    /// Operation execution lock.
    OperationExecution,
    /// Coordinator election.
    CoordinatorElection,
    /// Other purposes.
    Other,
}

impl std::fmt::Display for LeasePurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingletonWriter => write!(f, "singleton_writer"),
            Self::OperationExecution => write!(f, "operation_execution"),
            Self::CoordinatorElection => write!(f, "coordinator_election"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Input to the execution planner.
#[derive(Debug, Clone)]
pub struct PlannerInput {
    /// Available nodes with their profiles and state.
    pub nodes: Vec<NodeInfo>,
    /// Current timestamp for lease expiration checks.
    pub current_time: u64,
    /// Node ID that currently holds singleton writer lease (if any).
    pub singleton_lease_holder: Option<String>,
}

impl PlannerInput {
    /// Create a new planner input.
    #[must_use]
    pub fn new(nodes: Vec<NodeInfo>, current_time: u64) -> Self {
        Self {
            nodes,
            current_time,
            singleton_lease_holder: None,
        }
    }

    /// Set the singleton lease holder by node ID.
    #[must_use]
    pub fn with_singleton_holder(mut self, holder: impl Into<String>) -> Self {
        self.singleton_lease_holder = Some(holder.into());
        self
    }
}

// ============================================================================
// Execution Planner
// ============================================================================

/// The execution planner for routing operations to suitable nodes.
///
/// This planner produces a deterministic ranking of candidate nodes based on:
/// - Device fitness (CPU, memory, GPU, network, etc.)
/// - Connector availability and version compatibility
/// - Data locality (symbol presence)
/// - Lease constraints
#[derive(Debug, Default)]
pub struct ExecutionPlanner {
    /// Optional tie-breaker seed for deterministic ordering.
    _tiebreaker_seed: Option<u64>,
}

impl ExecutionPlanner {
    /// Create a new execution planner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _tiebreaker_seed: None,
        }
    }

    /// Plan execution by ranking available nodes.
    ///
    /// Returns a list of candidates sorted by score (highest first).
    /// Only eligible candidates are included.
    #[must_use]
    pub fn plan(&self, input: &PlannerInput, context: &PlannerContext) -> Vec<CandidateNode> {
        let mut candidates: Vec<CandidateNode> = input
            .nodes
            .iter()
            .filter(|n| !context.excluded_nodes.contains(n.profile.node_id.as_str()))
            .map(|node| self.score_node(node, input, context))
            .collect();

        // Sort by score descending, then by node_id for determinism
        candidates.sort();

        // Filter to eligible only and limit count
        let mut result: Vec<CandidateNode> = candidates
            .into_iter()
            .filter(|c| c.eligible)
            .take(MAX_CANDIDATES)
            .collect();

        // Add ranking reasons
        for (rank, candidate) in result.iter_mut().enumerate() {
            if rank == 0 {
                candidate.add_reason(DecisionReason::SelectedAsBest { rank: 1 });
            } else {
                candidate.add_reason(DecisionReason::EligibleNotSelected {
                    rank: rank + 1,
                    better_count: rank,
                });
            }
        }

        result
    }

    /// Score a single node.
    fn score_node(
        &self,
        node: &NodeInfo,
        input: &PlannerInput,
        context: &PlannerContext,
    ) -> CandidateNode {
        // Check data locality for fitness context
        let has_preferred_symbols = !context.preferred_symbols.is_empty()
            && context
                .preferred_symbols
                .iter()
                .any(|s| node.local_symbols.contains(s));

        // Build fitness context from planner context
        let mut fitness_ctx = FitnessContext::new()
            .with_requires_gpu(context.requires_gpu)
            .with_requires_tpu(context.requires_tpu)
            .with_required_connector(context.connector_id.clone())
            .with_symbols_present(has_preferred_symbols);

        if let Some(min_mem) = context.min_memory_mb {
            fitness_ctx = fitness_ctx.with_min_memory_mb(min_mem);
        }

        // Get base fitness score
        let fitness = node.profile.compute_fitness(&fitness_ctx);
        let mut candidate = CandidateNode::new(node.profile.node_id.clone(), fitness.score);

        // If base fitness already marked as ineligible, return early
        if !fitness.eligible {
            candidate.eligible = false;
            return candidate;
        }

        // Check connector version if specified
        self.check_connector_version(&mut candidate, node, context);

        // Check required symbols (hard constraint)
        self.check_required_symbols(&mut candidate, node, context);

        // Check data locality (soft bonus, already partially handled by fitness)
        self.add_data_locality_bonus(&mut candidate, node, context);

        // Check lease constraints
        self.check_lease_constraints(&mut candidate, node, input, context);

        candidate
    }

    /// Check connector version compatibility.
    fn check_connector_version(
        &self,
        candidate: &mut CandidateNode,
        node: &NodeInfo,
        context: &PlannerContext,
    ) {
        let Some(ref min_version) = context.min_connector_version else {
            return;
        };

        let connector_id = &context.connector_id;
        let Some(installed) = node.profile.get_connector(connector_id) else {
            // Missing connector already handled by fitness, but add reason
            candidate.adjust(ScoreAdjustment::penalty(
                AdjustmentFactor::Connector,
                MISSING_CONNECTOR_PENALTY,
                format!("missing required connector: {}", connector_id.as_str()),
            ));
            candidate.mark_ineligible(DecisionReason::MissingConnector {
                connector_id: connector_id.as_str().to_string(),
            });
            return;
        };

        // Simple string comparison for semver (works for well-formed versions)
        if !version_gte(&installed.version, min_version) {
            candidate.adjust(ScoreAdjustment::penalty(
                AdjustmentFactor::Connector,
                VERSION_MISMATCH_PENALTY,
                format!(
                    "connector version {} < required {}",
                    installed.version, min_version
                ),
            ));
            candidate.mark_ineligible(DecisionReason::IncompatibleVersion {
                connector_id: connector_id.as_str().to_string(),
                required: min_version.clone(),
                installed: installed.version.clone(),
            });
        }
    }

    /// Check required symbols are present.
    fn check_required_symbols(
        &self,
        candidate: &mut CandidateNode,
        node: &NodeInfo,
        context: &PlannerContext,
    ) {
        for symbol in &context.required_symbols {
            if !node.local_symbols.contains(symbol) {
                let prefix = hex::encode(&symbol.as_bytes()[..8]);
                candidate.mark_ineligible(DecisionReason::MissingRequiredSymbol {
                    symbol_prefix: prefix,
                });
                return;
            }
        }
    }

    /// Add data locality bonus for preferred symbols.
    fn add_data_locality_bonus(
        &self,
        candidate: &mut CandidateNode,
        node: &NodeInfo,
        context: &PlannerContext,
    ) {
        if context.preferred_symbols.is_empty() {
            return;
        }

        let local_count = context
            .preferred_symbols
            .iter()
            .filter(|s| node.local_symbols.contains(s))
            .count();

        if local_count > 0 {
            // Additional bonus beyond what fitness already gives
            let local_count_f64 = f64::from(u32::try_from(local_count).unwrap_or(u32::MAX));
            let bonus = DATA_LOCALITY_BONUS * local_count_f64 / 2.0;
            candidate.adjust(ScoreAdjustment::bonus(
                AdjustmentFactor::DataLocality,
                bonus,
                format!("{local_count} preferred symbols available locally"),
            ));
            candidate.add_reason(DecisionReason::HasLocalData {
                symbol_count: local_count,
            });
        }
    }

    /// Check lease constraints.
    fn check_lease_constraints(
        &self,
        candidate: &mut CandidateNode,
        _node: &NodeInfo,
        input: &PlannerInput,
        context: &PlannerContext,
    ) {
        // For singleton_writer operations, only the lease holder can execute
        if context.singleton_writer {
            if let Some(ref holder_id) = input.singleton_lease_holder {
                if candidate.node_id.as_str() != holder_id {
                    candidate.adjust(ScoreAdjustment::penalty(
                        AdjustmentFactor::LeaseConstraint,
                        LEASE_CONFLICT_PENALTY,
                        format!("singleton writer lease held by {holder_id}"),
                    ));
                    candidate.mark_ineligible(DecisionReason::LeaseConflict {
                        holder: NodeId::new(holder_id),
                        lease_purpose: "singleton_writer".to_string(),
                    });
                }
            }
        }
    }

    /// Select the best candidate, if any are eligible.
    #[must_use]
    pub fn select_best(
        &self,
        input: &PlannerInput,
        context: &PlannerContext,
    ) -> Option<CandidateNode> {
        self.plan(input, context).into_iter().next()
    }
}

/// Compare semver strings (simple comparison).
fn version_gte(installed: &str, required: &str) -> bool {
    // Parse as semver-like: split on dots and compare numerically
    let parse =
        |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse::<u32>().ok()).collect() };

    let inst = parse(installed);
    let req = parse(required);

    for (i, r) in req.iter().enumerate() {
        let i_val = inst.get(i).copied().unwrap_or(0);
        if i_val > *r {
            return true;
        }
        if i_val < *r {
            return false;
        }
    }
    true
}

// ============================================================================
// Execution Plan (Decision Receipt)
// ============================================================================

/// A complete execution plan with selected node and alternatives.
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// The selected node for execution.
    pub selected: Option<CandidateNode>,
    /// Alternative candidates in ranked order.
    pub alternatives: Vec<CandidateNode>,
    /// Total nodes considered.
    pub nodes_considered: usize,
    /// Nodes excluded by hard constraints.
    pub nodes_excluded: usize,
    /// Planning timestamp.
    pub planned_at: u64,
}

impl ExecutionPlan {
    /// Create an execution plan from candidates.
    #[must_use]
    pub fn from_candidates(
        candidates: &[CandidateNode],
        total_nodes: usize,
        timestamp: u64,
    ) -> Self {
        let selected = candidates.first().cloned();
        let alternatives = if candidates.len() > 1 {
            candidates[1..].to_vec()
        } else {
            Vec::new()
        };
        let nodes_excluded = total_nodes.saturating_sub(candidates.len());

        Self {
            selected,
            alternatives,
            nodes_considered: total_nodes,
            nodes_excluded,
            planned_at: timestamp,
        }
    }

    /// Check if a valid execution target was found.
    #[must_use]
    pub const fn has_target(&self) -> bool {
        self.selected.is_some()
    }

    /// Get the selected node ID, if any.
    #[must_use]
    pub fn target_node(&self) -> Option<&NodeId> {
        self.selected.as_ref().map(|c| &c.node_id)
    }
}

// ============================================================================
// Delegation Mechanism
// ============================================================================

/// A delegation request to route an operation to a remote node.
#[derive(Debug, Clone)]
pub struct DelegationRequest {
    /// Target node to delegate to.
    pub target_node: NodeId,
    /// Original requester node.
    pub requester_node: NodeId,
    /// Connector ID for the operation.
    pub connector_id: ConnectorId,
    /// Operation ID.
    pub operation_id: String,
    /// Planning decision that led to this delegation.
    pub decision: ExecutionPlan,
}

impl DelegationRequest {
    /// Create a new delegation request.
    #[must_use]
    pub fn new(
        target_node: NodeId,
        requester_node: NodeId,
        connector_id: ConnectorId,
        operation_id: String,
        decision: ExecutionPlan,
    ) -> Self {
        Self {
            target_node,
            requester_node,
            connector_id,
            operation_id,
            decision,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{AvailabilityProfile, InstalledConnector, LatencyClass, PowerSource};

    fn test_connector_id() -> ConnectorId {
        ConnectorId::new("fcp", "test", "1.0.0").unwrap()
    }

    fn test_node_id(suffix: &str) -> NodeId {
        NodeId::new(format!("node-{suffix}"))
    }

    fn test_object_id(n: u8) -> ObjectId {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        ObjectId::from_bytes(bytes)
    }

    fn make_profile(
        suffix: &str,
        memory_mb: u32,
        has_connector: bool,
        connector_version: &str,
    ) -> DeviceProfile {
        let mut builder = DeviceProfile::builder(test_node_id(suffix))
            .memory_mb(memory_mb)
            .power_source(PowerSource::Mains)
            .latency_class(LatencyClass::Lan)
            .availability(AvailabilityProfile::AlwaysOn);

        if has_connector {
            let connector = InstalledConnector::new(
                test_connector_id(),
                connector_version,
                ObjectId::from_bytes([0xAA; 32]),
            );
            builder = builder.add_connector(connector);
        }

        builder.build()
    }

    fn make_node_info(
        suffix: &str,
        memory_mb: u32,
        has_connector: bool,
        connector_version: &str,
        symbols: Vec<ObjectId>,
    ) -> NodeInfo {
        NodeInfo {
            profile: make_profile(suffix, memory_mb, has_connector, connector_version),
            local_symbols: symbols.into_iter().collect(),
            held_leases: Vec::new(),
        }
    }

    #[test]
    fn planner_ranks_by_fitness() {
        let planner = ExecutionPlanner::new();

        let nodes = vec![
            make_node_info("low", 512, true, "1.0.0", vec![]),
            make_node_info("high", 8192, true, "1.0.0", vec![]),
            make_node_info("mid", 2048, true, "1.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());

        let candidates = planner.plan(&input, &context);

        assert_eq!(candidates.len(), 3);
        // Higher memory should score better due to fitness
        assert!(candidates[0].score >= candidates[1].score);
        assert!(candidates[1].score >= candidates[2].score);
    }

    #[test]
    fn planner_excludes_missing_connector() {
        let planner = ExecutionPlanner::new();

        let nodes = vec![
            make_node_info("with", 2048, true, "1.0.0", vec![]),
            make_node_info("without", 4096, false, "1.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());

        let candidates = planner.plan(&input, &context);

        // Only node with connector should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-with");
    }

    #[test]
    fn planner_checks_version_compatibility() {
        let planner = ExecutionPlanner::new();

        let nodes = vec![
            make_node_info("old", 2048, true, "1.0.0", vec![]),
            make_node_info("new", 2048, true, "2.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id()).with_min_version("2.0.0");

        let candidates = planner.plan(&input, &context);

        // Only node with version >= 2.0.0 should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-new");
    }

    #[test]
    fn planner_scores_data_locality() {
        let planner = ExecutionPlanner::new();

        let symbol = test_object_id(1);

        let nodes = vec![
            make_node_info("remote", 2048, true, "1.0.0", vec![]),
            make_node_info("local", 2048, true, "1.0.0", vec![symbol]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id()).with_preferred_symbols(vec![symbol]);

        let candidates = planner.plan(&input, &context);

        assert_eq!(candidates.len(), 2);
        // Node with local data should score higher
        assert_eq!(candidates[0].node_id.as_str(), "node-local");
        assert!(candidates[0].score > candidates[1].score);
    }

    #[test]
    fn planner_enforces_required_symbols() {
        let planner = ExecutionPlanner::new();

        let symbol = test_object_id(42);

        let nodes = vec![
            make_node_info("has_it", 2048, true, "1.0.0", vec![symbol]),
            make_node_info("missing", 4096, true, "1.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id()).with_required_symbols(vec![symbol]);

        let candidates = planner.plan(&input, &context);

        // Only node with required symbol should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-has_it");
    }

    #[test]
    fn planner_enforces_singleton_lease() {
        let planner = ExecutionPlanner::new();

        let nodes = vec![
            make_node_info("holder", 2048, true, "1.0.0", vec![]),
            make_node_info("other", 4096, true, "1.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-holder");
        let context = PlannerContext::new(test_connector_id()).with_singleton_writer();

        let candidates = planner.plan(&input, &context);

        // Only the lease holder should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-holder");
    }

    #[test]
    fn planner_deterministic_ordering() {
        let planner = ExecutionPlanner::new();

        // Create nodes with identical scores
        let nodes = vec![
            make_node_info("aaa", 2048, true, "1.0.0", vec![]),
            make_node_info("zzz", 2048, true, "1.0.0", vec![]),
            make_node_info("mmm", 2048, true, "1.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());

        // Run multiple times to verify determinism
        let candidates1 = planner.plan(&input, &context);
        let candidates2 = planner.plan(&input, &context);

        assert_eq!(candidates1.len(), candidates2.len());
        for (c1, c2) in candidates1.iter().zip(candidates2.iter()) {
            assert_eq!(c1.node_id.as_str(), c2.node_id.as_str());
            assert!((c1.score - c2.score).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn planner_excludes_specified_nodes() {
        let planner = ExecutionPlanner::new();

        let nodes = vec![
            make_node_info("keep", 2048, true, "1.0.0", vec![]),
            make_node_info("exclude", 4096, true, "1.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id()).excluding(["node-exclude"]);

        let candidates = planner.plan(&input, &context);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-keep");
    }

    #[test]
    fn execution_plan_from_candidates() {
        let planner = ExecutionPlanner::new();

        let nodes = vec![
            make_node_info("a", 4096, true, "1.0.0", vec![]),
            make_node_info("b", 2048, true, "1.0.0", vec![]),
            make_node_info("c", 1024, true, "1.0.0", vec![]),
        ];

        let input = PlannerInput::new(nodes.clone(), 1000);
        let context = PlannerContext::new(test_connector_id());

        let candidates = planner.plan(&input, &context);
        let plan = ExecutionPlan::from_candidates(&candidates, nodes.len(), 1000);

        assert!(plan.has_target());
        assert_eq!(plan.alternatives.len(), 2);
        assert_eq!(plan.nodes_considered, 3);
    }

    #[test]
    fn version_comparison_works() {
        assert!(version_gte("2.0.0", "1.0.0"));
        assert!(version_gte("1.1.0", "1.0.0"));
        assert!(version_gte("1.0.1", "1.0.0"));
        assert!(version_gte("1.0.0", "1.0.0"));
        assert!(!version_gte("1.0.0", "2.0.0"));
        assert!(!version_gte("1.0.0", "1.1.0"));
        assert!(version_gte("10.0.0", "9.0.0"));
    }

    // === version_gte edge cases ===

    #[test]
    fn version_gte_shorter_installed() {
        // "1.0" vs "1.0.0" — missing part treated as 0
        assert!(version_gte("1.0", "1.0.0"));
    }

    #[test]
    fn version_gte_shorter_required() {
        // "1.0.5" vs "1.0" — extra installed parts ignored once required exhausted
        assert!(version_gte("1.0.5", "1.0"));
    }

    #[test]
    fn version_gte_empty_strings() {
        // Both empty → equal → true
        assert!(version_gte("", ""));
    }

    #[test]
    fn version_gte_non_numeric_parts() {
        // Non-numeric parts are filtered out by parse::<u32>().ok()
        // "1.2.beta" → [1, 2], "1.2.0" → [1, 2, 0]
        assert!(version_gte("1.2.beta", "1.2.0"));
    }

    #[test]
    fn version_gte_major_dominates() {
        assert!(version_gte("3.0.0", "2.99.99"));
        assert!(!version_gte("2.99.99", "3.0.0"));
    }

    // === LeasePurpose Display ===

    #[test]
    fn lease_purpose_display() {
        assert_eq!(
            LeasePurpose::SingletonWriter.to_string(),
            "singleton_writer"
        );
        assert_eq!(
            LeasePurpose::OperationExecution.to_string(),
            "operation_execution"
        );
        assert_eq!(
            LeasePurpose::CoordinatorElection.to_string(),
            "coordinator_election"
        );
        assert_eq!(LeasePurpose::Other.to_string(), "other");
    }

    #[test]
    fn lease_purpose_equality() {
        assert_eq!(LeasePurpose::SingletonWriter, LeasePurpose::SingletonWriter);
        assert_ne!(LeasePurpose::SingletonWriter, LeasePurpose::Other);
    }

    // === CandidateNode ordering ===

    #[test]
    fn candidate_node_ord_higher_score_first() {
        let a = CandidateNode::new(test_node_id("a"), 100.0);
        let b = CandidateNode::new(test_node_id("b"), 50.0);
        // sort() puts lesser first; Ord is defined so higher score < lower score
        let mut v = [b, a];
        v.sort();
        assert_eq!(v[0].node_id.as_str(), "node-a"); // higher score
        assert_eq!(v[1].node_id.as_str(), "node-b");
    }

    #[test]
    fn candidate_node_ord_tiebreak_by_node_id() {
        let a = CandidateNode::new(test_node_id("alpha"), 50.0);
        let b = CandidateNode::new(test_node_id("beta"), 50.0);
        let mut v = [b, a];
        v.sort();
        // Same score → alphabetical by node_id
        assert_eq!(v[0].node_id.as_str(), "node-alpha");
        assert_eq!(v[1].node_id.as_str(), "node-beta");
    }

    #[test]
    fn candidate_node_eq_by_node_id() {
        let a = CandidateNode::new(test_node_id("x"), 100.0);
        let b = CandidateNode::new(test_node_id("x"), 50.0);
        // PartialEq compares only node_id
        assert_eq!(a, b);
    }

    // === CandidateNode::adjust and mark_ineligible ===

    #[test]
    fn candidate_adjust_adds_delta() {
        let mut c = CandidateNode::new(test_node_id("n"), 100.0);
        c.adjust(ScoreAdjustment::bonus(
            AdjustmentFactor::DataLocality,
            15.0,
            "test bonus",
        ));
        assert!((c.score - 115.0).abs() < f64::EPSILON);
        assert_eq!(c.adjustments.len(), 1);
        assert!(c.eligible);
    }

    #[test]
    fn candidate_adjust_penalty_subtracts() {
        let mut c = CandidateNode::new(test_node_id("n"), 100.0);
        c.adjust(ScoreAdjustment::penalty(
            AdjustmentFactor::Connector,
            30.0,
            "test penalty",
        ));
        assert!((c.score - 70.0).abs() < f64::EPSILON);
    }

    #[test]
    fn candidate_mark_ineligible_zeroes_score() {
        let mut c = CandidateNode::new(test_node_id("n"), 100.0);
        c.mark_ineligible(DecisionReason::Custom("test".to_string()));
        assert!(!c.eligible);
        assert!((c.score - 0.0).abs() < f64::EPSILON);
        assert_eq!(c.decision_reasons.len(), 1);
    }

    #[test]
    fn candidate_add_reason() {
        let mut c = CandidateNode::new(test_node_id("n"), 50.0);
        c.add_reason(DecisionReason::SelectedAsBest { rank: 1 });
        c.add_reason(DecisionReason::HasLocalData { symbol_count: 3 });
        assert_eq!(c.decision_reasons.len(), 2);
    }

    // === ScoreAdjustment bonus vs penalty sign ===

    #[test]
    fn score_adjustment_bonus_positive_delta() {
        let adj = ScoreAdjustment::bonus(AdjustmentFactor::DataLocality, 10.0, "bonus");
        assert!(adj.delta > 0.0);
        assert!((adj.delta - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_adjustment_penalty_negative_delta() {
        let adj = ScoreAdjustment::penalty(AdjustmentFactor::Connector, 10.0, "penalty");
        assert!(adj.delta < 0.0);
        assert!((adj.delta - (-10.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn score_adjustment_penalty_abs_negative_input() {
        // penalty with already-negative input → still negative via -delta.abs()
        let adj = ScoreAdjustment::penalty(AdjustmentFactor::Connector, -5.0, "neg");
        assert!((adj.delta - (-5.0)).abs() < f64::EPSILON);
    }

    // === AdjustmentFactor traits ===

    #[test]
    fn adjustment_factor_copy_eq() {
        let a = AdjustmentFactor::Custom;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(AdjustmentFactor::Connector, AdjustmentFactor::DataLocality);
    }

    // === PlannerContext builder ===

    #[test]
    fn planner_context_builder_defaults() {
        let ctx = PlannerContext::new(test_connector_id());
        assert!(ctx.min_connector_version.is_none());
        assert!(ctx.min_memory_mb.is_none());
        assert!(!ctx.requires_gpu);
        assert!(!ctx.requires_tpu);
        assert!(ctx.preferred_symbols.is_empty());
        assert!(ctx.required_symbols.is_empty());
        assert!(!ctx.singleton_writer);
        assert!(ctx.target_zone.is_none());
        assert!(ctx.excluded_nodes.is_empty());
    }

    #[test]
    fn planner_context_with_min_version() {
        let ctx = PlannerContext::new(test_connector_id()).with_min_version("2.1.0");
        assert_eq!(ctx.min_connector_version.as_deref(), Some("2.1.0"));
    }

    #[test]
    fn planner_context_with_min_memory() {
        let ctx = PlannerContext::new(test_connector_id()).with_min_memory_mb(512);
        assert_eq!(ctx.min_memory_mb, Some(512));
    }

    #[test]
    fn planner_context_with_gpu_tpu() {
        let ctx = PlannerContext::new(test_connector_id())
            .with_gpu()
            .with_tpu();
        assert!(ctx.requires_gpu);
        assert!(ctx.requires_tpu);
    }

    #[test]
    fn planner_context_with_symbols() {
        let sym = test_object_id(7);
        let ctx = PlannerContext::new(test_connector_id())
            .with_preferred_symbols(vec![sym])
            .with_required_symbols(vec![sym]);
        assert_eq!(ctx.preferred_symbols.len(), 1);
        assert_eq!(ctx.required_symbols.len(), 1);
    }

    #[test]
    fn planner_context_with_singleton_writer() {
        let ctx = PlannerContext::new(test_connector_id()).with_singleton_writer();
        assert!(ctx.singleton_writer);
    }

    #[test]
    fn planner_context_with_target_zone() {
        let zone: ZoneId = "z:test".parse().unwrap();
        let ctx = PlannerContext::new(test_connector_id()).with_target_zone(zone);
        assert!(ctx.target_zone.is_some());
    }

    #[test]
    fn planner_context_excluding_multiple() {
        let ctx =
            PlannerContext::new(test_connector_id()).excluding(["node-a", "node-b", "node-c"]);
        assert_eq!(ctx.excluded_nodes.len(), 3);
        assert!(ctx.excluded_nodes.contains("node-a"));
    }

    // === PlannerInput builder ===

    #[test]
    fn planner_input_defaults() {
        let input = PlannerInput::new(vec![], 500);
        assert!(input.nodes.is_empty());
        assert_eq!(input.current_time, 500);
        assert!(input.singleton_lease_holder.is_none());
    }

    #[test]
    fn planner_input_with_singleton_holder() {
        let input = PlannerInput::new(vec![], 0).with_singleton_holder("node-x");
        assert_eq!(input.singleton_lease_holder.as_deref(), Some("node-x"));
    }

    // === NodeInfo::node_id accessor ===

    #[test]
    fn node_info_node_id() {
        let info = make_node_info("abc", 1024, true, "1.0.0", vec![]);
        assert_eq!(info.node_id().as_str(), "node-abc");
    }

    // === ExecutionPlan ===

    #[test]
    fn execution_plan_empty_candidates() {
        let plan = ExecutionPlan::from_candidates(&[], 5, 1000);
        assert!(!plan.has_target());
        assert!(plan.target_node().is_none());
        assert!(plan.alternatives.is_empty());
        assert_eq!(plan.nodes_considered, 5);
        assert_eq!(plan.nodes_excluded, 5);
    }

    #[test]
    fn execution_plan_single_candidate() {
        let c = CandidateNode::new(test_node_id("only"), 80.0);
        let plan = ExecutionPlan::from_candidates(&[c], 3, 2000);
        assert!(plan.has_target());
        assert_eq!(plan.target_node().unwrap().as_str(), "node-only");
        assert!(plan.alternatives.is_empty());
        assert_eq!(plan.nodes_excluded, 2);
        assert_eq!(plan.planned_at, 2000);
    }

    // === select_best ===

    #[test]
    fn select_best_returns_highest_score() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("low", 512, true, "1.0.0", vec![]),
            make_node_info("high", 8192, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        let best = planner.select_best(&input, &context);
        assert!(best.is_some());
        assert_eq!(best.unwrap().node_id.as_str(), "node-high");
    }

    #[test]
    fn select_best_none_when_no_eligible() {
        let planner = ExecutionPlanner::new();
        // All nodes missing connector
        let nodes = vec![
            make_node_info("a", 2048, false, "1.0.0", vec![]),
            make_node_info("b", 4096, false, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        assert!(planner.select_best(&input, &context).is_none());
    }

    #[test]
    fn select_best_none_when_empty_nodes() {
        let planner = ExecutionPlanner::new();
        let input = PlannerInput::new(vec![], 1000);
        let context = PlannerContext::new(test_connector_id());
        assert!(planner.select_best(&input, &context).is_none());
    }

    // === plan with empty nodes ===

    #[test]
    fn plan_empty_nodes_returns_empty() {
        let planner = ExecutionPlanner::new();
        let input = PlannerInput::new(vec![], 1000);
        let context = PlannerContext::new(test_connector_id());
        let candidates = planner.plan(&input, &context);
        assert!(candidates.is_empty());
    }

    // === decision reasons on ranked candidates ===

    #[test]
    fn plan_adds_selected_as_best_to_first() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("a", 4096, true, "1.0.0", vec![]),
            make_node_info("b", 2048, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        let candidates = planner.plan(&input, &context);
        assert_eq!(candidates.len(), 2);
        // First candidate has SelectedAsBest
        assert!(
            candidates[0]
                .decision_reasons
                .iter()
                .any(|r| matches!(r, DecisionReason::SelectedAsBest { rank: 1 }))
        );
        // Second has EligibleNotSelected
        assert!(candidates[1].decision_reasons.iter().any(|r| matches!(
            r,
            DecisionReason::EligibleNotSelected {
                rank: 2,
                better_count: 1
            }
        )));
    }

    // === Multiple preferred symbols ===

    #[test]
    fn data_locality_bonus_scales_with_symbol_count() {
        let planner = ExecutionPlanner::new();
        let s1 = test_object_id(1);
        let s2 = test_object_id(2);
        let s3 = test_object_id(3);

        let nodes = vec![
            make_node_info("one", 2048, true, "1.0.0", vec![s1]),
            make_node_info("three", 2048, true, "1.0.0", vec![s1, s2, s3]),
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context =
            PlannerContext::new(test_connector_id()).with_preferred_symbols(vec![s1, s2, s3]);

        let candidates = planner.plan(&input, &context);
        // Node with 3 symbols should score higher than node with 1
        assert_eq!(candidates[0].node_id.as_str(), "node-three");
        assert!(candidates[0].score > candidates[1].score);
    }

    // === Singleton writer: holder gets through ===

    #[test]
    fn singleton_writer_no_holder_set() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("a", 2048, true, "1.0.0", vec![]),
            make_node_info("b", 4096, true, "1.0.0", vec![]),
        ];
        // singleton_writer context but no holder set → all eligible
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id()).with_singleton_writer();
        let candidates = planner.plan(&input, &context);
        assert_eq!(candidates.len(), 2);
    }

    // === ExecutionPlanner Default ===

    #[test]
    fn execution_planner_default() {
        let planner = ExecutionPlanner::default();
        // Should behave identically to new()
        let nodes = vec![make_node_info("a", 2048, true, "1.0.0", vec![])];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        let candidates = planner.plan(&input, &context);
        assert_eq!(candidates.len(), 1);
    }

    // === DelegationRequest ===

    #[test]
    fn delegation_request_new() {
        let plan = ExecutionPlan::from_candidates(&[], 0, 1000);
        let req = DelegationRequest::new(
            test_node_id("target"),
            test_node_id("requester"),
            test_connector_id(),
            "op-1".to_string(),
            plan,
        );
        assert_eq!(req.target_node.as_str(), "node-target");
        assert_eq!(req.requester_node.as_str(), "node-requester");
        assert_eq!(req.operation_id, "op-1");
    }

    // === DecisionReason Debug ===

    #[test]
    fn decision_reason_variants_debug() {
        let reasons: Vec<DecisionReason> = vec![
            DecisionReason::SelectedAsBest { rank: 1 },
            DecisionReason::EligibleNotSelected {
                rank: 2,
                better_count: 1,
            },
            DecisionReason::MissingConnector {
                connector_id: "c".to_string(),
            },
            DecisionReason::IncompatibleVersion {
                connector_id: "c".to_string(),
                required: "2.0".to_string(),
                installed: "1.0".to_string(),
            },
            DecisionReason::LeaseConflict {
                holder: test_node_id("h"),
                lease_purpose: "singleton_writer".to_string(),
            },
            DecisionReason::ZoneRestriction {
                zone: "z".to_string(),
                reason: "r".to_string(),
            },
            DecisionReason::HasLocalData { symbol_count: 5 },
            DecisionReason::MissingRequiredSymbol {
                symbol_prefix: "ab".to_string(),
            },
            DecisionReason::Custom("test".to_string()),
        ];
        for r in &reasons {
            let s = format!("{r:?}");
            assert!(!s.is_empty());
        }
    }

    // === HeldLease construction ===

    #[test]
    fn held_lease_fields() {
        let lease = HeldLease {
            subject_id: test_object_id(1),
            purpose: LeasePurpose::OperationExecution,
            expires_at: 9999,
        };
        assert_eq!(lease.purpose, LeasePurpose::OperationExecution);
        assert_eq!(lease.expires_at, 9999);
    }

    // ============================================================
    // Additional tests
    // ============================================================

    // ---- version_gte extended edge cases ----

    #[test]
    fn version_gte_equal_multipart() {
        assert!(version_gte("1.2.3", "1.2.3"));
    }

    #[test]
    fn version_gte_patch_less() {
        assert!(!version_gte("1.0.0", "1.0.1"));
    }

    #[test]
    fn version_gte_minor_dominates() {
        assert!(version_gte("1.5.0", "1.4.99"));
        assert!(!version_gte("1.4.99", "1.5.0"));
    }

    #[test]
    fn version_gte_single_component() {
        assert!(version_gte("3", "2"));
        assert!(version_gte("2", "2"));
        assert!(!version_gte("1", "2"));
    }

    #[test]
    fn version_gte_four_components() {
        assert!(version_gte("1.2.3.4", "1.2.3.4"));
        assert!(version_gte("1.2.3.5", "1.2.3.4"));
        assert!(!version_gte("1.2.3.3", "1.2.3.4"));
    }

    #[test]
    fn version_gte_installed_longer_than_required() {
        // "1.2.3" vs "1.2" => after "1.2" is exhausted, it's >=
        assert!(version_gte("1.2.3", "1.2"));
    }

    #[test]
    fn version_gte_installed_shorter_than_required() {
        // "1.2" vs "1.2.3" => missing installed component treated as 0 < 3
        assert!(!version_gte("1.2", "1.2.3"));
    }

    #[test]
    fn version_gte_all_non_numeric() {
        // "alpha.beta" => [] vs [] => true (vacuously)
        assert!(version_gte("alpha.beta", "gamma.delta"));
    }

    #[test]
    fn version_gte_zero_versions() {
        assert!(version_gte("0.0.0", "0.0.0"));
        assert!(!version_gte("0.0.0", "0.0.1"));
    }

    #[test]
    fn version_gte_large_numbers() {
        assert!(version_gte("999.999.999", "999.999.999"));
        assert!(version_gte("1000.0.0", "999.999.999"));
    }

    // ---- LeasePurpose ----

    #[test]
    fn lease_purpose_copy_semantics() {
        let a = LeasePurpose::CoordinatorElection;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn lease_purpose_all_variants_distinct() {
        let variants = [
            LeasePurpose::SingletonWriter,
            LeasePurpose::OperationExecution,
            LeasePurpose::CoordinatorElection,
            LeasePurpose::Other,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v1, v2);
                } else {
                    assert_ne!(v1, v2);
                }
            }
        }
    }

    #[test]
    fn lease_purpose_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LeasePurpose::SingletonWriter);
        set.insert(LeasePurpose::OperationExecution);
        set.insert(LeasePurpose::CoordinatorElection);
        set.insert(LeasePurpose::Other);
        assert_eq!(set.len(), 4);
        // Inserting duplicate should not increase size
        set.insert(LeasePurpose::Other);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn lease_purpose_debug() {
        let dbg = format!("{:?}", LeasePurpose::SingletonWriter);
        assert!(dbg.contains("SingletonWriter"));
    }

    // ---- AdjustmentFactor ----

    #[test]
    fn adjustment_factor_all_variants_debug() {
        let variants = [
            AdjustmentFactor::Connector,
            AdjustmentFactor::DataLocality,
            AdjustmentFactor::LeaseConstraint,
            AdjustmentFactor::ZoneRestriction,
            AdjustmentFactor::Custom,
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn adjustment_factor_hash_all_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AdjustmentFactor::Connector);
        set.insert(AdjustmentFactor::DataLocality);
        set.insert(AdjustmentFactor::LeaseConstraint);
        set.insert(AdjustmentFactor::ZoneRestriction);
        set.insert(AdjustmentFactor::Custom);
        assert_eq!(set.len(), 5);
    }

    // ---- CandidateNode ----

    #[test]
    fn candidate_node_new_defaults() {
        let c = CandidateNode::new(test_node_id("test"), 75.5);
        assert_eq!(c.node_id.as_str(), "node-test");
        assert!((c.score - 75.5).abs() < f64::EPSILON);
        assert!((c.base_fitness - 75.5).abs() < f64::EPSILON);
        assert!(c.adjustments.is_empty());
        assert!(c.eligible);
        assert!(c.decision_reasons.is_empty());
    }

    #[test]
    fn candidate_node_multiple_adjustments() {
        let mut c = CandidateNode::new(test_node_id("m"), 100.0);
        c.adjust(ScoreAdjustment::bonus(
            AdjustmentFactor::DataLocality,
            10.0,
            "local data",
        ));
        c.adjust(ScoreAdjustment::penalty(
            AdjustmentFactor::Connector,
            20.0,
            "old version",
        ));
        c.adjust(ScoreAdjustment::bonus(
            AdjustmentFactor::Custom,
            5.0,
            "custom boost",
        ));
        assert_eq!(c.adjustments.len(), 3);
        // 100 + 10 - 20 + 5 = 95
        assert!((c.score - 95.0).abs() < f64::EPSILON);
    }

    #[test]
    fn candidate_node_mark_ineligible_clears_score() {
        let mut c = CandidateNode::new(test_node_id("x"), 200.0);
        c.adjust(ScoreAdjustment::bonus(
            AdjustmentFactor::DataLocality,
            50.0,
            "boost",
        ));
        assert!((c.score - 250.0).abs() < f64::EPSILON);
        c.mark_ineligible(DecisionReason::MissingConnector {
            connector_id: "c".to_string(),
        });
        assert!(!c.eligible);
        assert!((c.score).abs() < f64::EPSILON);
    }

    #[test]
    fn candidate_node_ord_nan_handling() {
        // If scores are NaN, the comparison falls through to node_id string comparison
        let a = CandidateNode::new(test_node_id("a"), f64::NAN);
        let b = CandidateNode::new(test_node_id("b"), f64::NAN);
        let mut v = [b, a];
        v.sort();
        // NaN partial_cmp returns None, so tiebreak by node_id
        assert_eq!(v[0].node_id.as_str(), "node-a");
        assert_eq!(v[1].node_id.as_str(), "node-b");
    }

    #[test]
    fn candidate_node_eq_ignores_score_and_adjustments() {
        let mut a = CandidateNode::new(test_node_id("same"), 100.0);
        a.adjust(ScoreAdjustment::bonus(
            AdjustmentFactor::DataLocality,
            50.0,
            "bonus",
        ));
        let b = CandidateNode::new(test_node_id("same"), 0.0);
        assert_eq!(a, b); // PartialEq only on node_id
    }

    #[test]
    fn candidate_node_clone() {
        let mut c = CandidateNode::new(test_node_id("c"), 80.0);
        c.adjust(ScoreAdjustment::bonus(
            AdjustmentFactor::Custom,
            5.0,
            "test",
        ));
        c.add_reason(DecisionReason::SelectedAsBest { rank: 1 });
        let cloned = c.clone();
        assert_eq!(c.node_id.as_str(), cloned.node_id.as_str());
        assert!((c.score - cloned.score).abs() < f64::EPSILON);
        assert_eq!(c.adjustments.len(), cloned.adjustments.len());
    }

    #[test]
    fn candidate_node_ord_zero_vs_positive() {
        let zero = CandidateNode::new(test_node_id("z"), 0.0);
        let pos = CandidateNode::new(test_node_id("p"), 1.0);
        let mut v = [zero, pos];
        v.sort();
        assert_eq!(v[0].node_id.as_str(), "node-p"); // higher score first
    }

    #[test]
    fn candidate_node_ord_negative_score() {
        let neg = CandidateNode::new(test_node_id("n"), -50.0);
        let pos = CandidateNode::new(test_node_id("p"), 50.0);
        let mut v = [neg, pos];
        v.sort();
        assert_eq!(v[0].node_id.as_str(), "node-p");
    }

    // ---- ScoreAdjustment ----

    #[test]
    fn score_adjustment_bonus_zero() {
        let adj = ScoreAdjustment::bonus(AdjustmentFactor::Custom, 0.0, "zero bonus");
        assert!((adj.delta).abs() < f64::EPSILON);
    }

    #[test]
    fn score_adjustment_penalty_zero() {
        let adj = ScoreAdjustment::penalty(AdjustmentFactor::Custom, 0.0, "zero penalty");
        assert!((adj.delta).abs() < f64::EPSILON);
    }

    #[test]
    fn score_adjustment_clone() {
        let adj = ScoreAdjustment::bonus(AdjustmentFactor::DataLocality, 15.0, "locality");
        let cloned = adj.clone();
        assert!((adj.delta - cloned.delta).abs() < f64::EPSILON);
        assert_eq!(adj.explanation, cloned.explanation);
    }

    #[test]
    fn score_adjustment_debug() {
        let adj = ScoreAdjustment::penalty(AdjustmentFactor::LeaseConstraint, 100.0, "conflict");
        let dbg = format!("{adj:?}");
        assert!(dbg.contains("LeaseConstraint"));
        assert!(dbg.contains("conflict"));
    }

    // ---- PlannerContext ----

    #[test]
    fn planner_context_excluding_empty() {
        let ctx = PlannerContext::new(test_connector_id()).excluding(Vec::<String>::new());
        assert!(ctx.excluded_nodes.is_empty());
    }

    #[test]
    fn planner_context_excluding_duplicates() {
        let ctx =
            PlannerContext::new(test_connector_id()).excluding(["node-a", "node-a", "node-b"]);
        assert_eq!(ctx.excluded_nodes.len(), 2);
    }

    #[test]
    fn planner_context_clone() {
        let ctx = PlannerContext::new(test_connector_id())
            .with_min_version("2.0.0")
            .with_min_memory_mb(1024)
            .with_gpu()
            .with_singleton_writer()
            .excluding(["x"]);
        let cloned = ctx.clone();
        assert_eq!(ctx.min_connector_version.as_deref(), Some("2.0.0"));
        assert_eq!(cloned.min_memory_mb, Some(1024));
        assert!(cloned.requires_gpu);
        assert!(cloned.singleton_writer);
        assert_eq!(ctx.excluded_nodes.len(), 1);
    }

    #[test]
    fn planner_context_debug() {
        let ctx = PlannerContext::new(test_connector_id());
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("connector_id"));
    }

    // ---- PlannerInput ----

    #[test]
    fn planner_input_clone() {
        let nodes = vec![make_node_info("a", 2048, true, "1.0.0", vec![])];
        let input = PlannerInput::new(nodes, 500).with_singleton_holder("node-a");
        let cloned = input.clone();
        assert_eq!(input.nodes.len(), 1);
        assert_eq!(cloned.current_time, 500);
        assert_eq!(input.singleton_lease_holder.as_deref(), Some("node-a"));
    }

    #[test]
    fn planner_input_debug() {
        let input = PlannerInput::new(vec![], 0);
        let dbg = format!("{input:?}");
        assert!(dbg.contains("current_time"));
    }

    // ---- NodeInfo ----

    #[test]
    fn node_info_clone() {
        let info = make_node_info("x", 4096, true, "1.0.0", vec![test_object_id(1)]);
        let cloned = info.clone();
        assert_eq!(info.node_id().as_str(), cloned.node_id().as_str());
        assert_eq!(cloned.local_symbols.len(), 1);
    }

    #[test]
    fn node_info_empty_symbols() {
        let info = make_node_info("empty", 1024, true, "1.0.0", vec![]);
        assert!(info.local_symbols.is_empty());
    }

    #[test]
    fn node_info_many_symbols() {
        let syms: Vec<ObjectId> = (0..20).map(test_object_id).collect();
        let info = make_node_info("many", 2048, true, "1.0.0", syms);
        assert_eq!(info.local_symbols.len(), 20);
    }

    // ---- HeldLease ----

    #[test]
    fn held_lease_clone() {
        let lease = HeldLease {
            subject_id: test_object_id(5),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 12345,
        };
        let cloned = lease.clone();
        assert_eq!(lease.purpose, LeasePurpose::SingletonWriter);
        assert_eq!(cloned.expires_at, 12345);
    }

    #[test]
    fn held_lease_debug() {
        let lease = HeldLease {
            subject_id: test_object_id(1),
            purpose: LeasePurpose::Other,
            expires_at: 0,
        };
        let dbg = format!("{lease:?}");
        assert!(dbg.contains("Other"));
    }

    // ---- ExecutionPlan ----

    #[test]
    fn execution_plan_multiple_candidates() {
        let c1 = CandidateNode::new(test_node_id("a"), 100.0);
        let c2 = CandidateNode::new(test_node_id("b"), 90.0);
        let c3 = CandidateNode::new(test_node_id("c"), 80.0);
        let plan = ExecutionPlan::from_candidates(&[c1, c2, c3], 5, 999);
        assert!(plan.has_target());
        assert_eq!(plan.target_node().unwrap().as_str(), "node-a");
        assert_eq!(plan.alternatives.len(), 2);
        assert_eq!(plan.nodes_excluded, 2);
        assert_eq!(plan.planned_at, 999);
    }

    #[test]
    fn execution_plan_clone() {
        let c = CandidateNode::new(test_node_id("x"), 50.0);
        let plan = ExecutionPlan::from_candidates(&[c], 1, 100);
        let cloned = plan.clone();
        assert!(cloned.has_target());
        assert_eq!(
            cloned.target_node().unwrap().as_str(),
            plan.target_node().unwrap().as_str()
        );
    }

    #[test]
    fn execution_plan_debug() {
        let plan = ExecutionPlan::from_candidates(&[], 0, 0);
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("selected"));
    }

    #[test]
    fn execution_plan_nodes_excluded_saturates() {
        // total_nodes < candidates.len() shouldn't underflow (saturating_sub)
        let c1 = CandidateNode::new(test_node_id("a"), 100.0);
        let c2 = CandidateNode::new(test_node_id("b"), 90.0);
        let plan = ExecutionPlan::from_candidates(&[c1, c2], 1, 0);
        // 1 - 2 saturates to 0
        assert_eq!(plan.nodes_excluded, 0);
    }

    // ---- DelegationRequest ----

    #[test]
    fn delegation_request_clone() {
        let plan = ExecutionPlan::from_candidates(&[], 0, 0);
        let req = DelegationRequest::new(
            test_node_id("t"),
            test_node_id("r"),
            test_connector_id(),
            "op-x".to_string(),
            plan,
        );
        let cloned = req.clone();
        assert_eq!(req.target_node.as_str(), "node-t");
        assert_eq!(req.requester_node.as_str(), "node-r");
        assert_eq!(cloned.operation_id, "op-x");
    }

    #[test]
    fn delegation_request_debug() {
        let plan = ExecutionPlan::from_candidates(&[], 0, 0);
        let req = DelegationRequest::new(
            test_node_id("t"),
            test_node_id("r"),
            test_connector_id(),
            "op-z".to_string(),
            plan,
        );
        let dbg = format!("{req:?}");
        assert!(dbg.contains("op-z"));
    }

    // ---- Planner integration: combined constraints ----

    #[test]
    fn planner_version_and_symbols_combined() {
        let planner = ExecutionPlanner::new();
        let sym = test_object_id(10);
        let nodes = vec![
            make_node_info("old_no_sym", 2048, true, "1.0.0", vec![]),
            make_node_info("new_has_sym", 2048, true, "2.0.0", vec![sym]),
            make_node_info("new_no_sym", 2048, true, "2.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id())
            .with_min_version("2.0.0")
            .with_required_symbols(vec![sym]);

        let candidates = planner.plan(&input, &context);
        // Only new_has_sym has both version >= 2.0.0 AND required symbol
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-new_has_sym");
    }

    #[test]
    fn planner_singleton_and_version_combined() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("holder", 2048, true, "1.0.0", vec![]),
            make_node_info("other", 4096, true, "2.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-holder");
        let context = PlannerContext::new(test_connector_id())
            .with_min_version("2.0.0")
            .with_singleton_writer();

        let candidates = planner.plan(&input, &context);
        // holder has old version → ineligible for version
        // other has new version but not singleton holder → ineligible for lease
        // Both should be excluded
        assert!(candidates.is_empty());
    }

    #[test]
    fn planner_all_excluded() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("a", 2048, true, "1.0.0", vec![]),
            make_node_info("b", 2048, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id()).excluding(["node-a", "node-b"]);
        let candidates = planner.plan(&input, &context);
        assert!(candidates.is_empty());
    }

    #[test]
    fn planner_max_candidates_limit() {
        let planner = ExecutionPlanner::new();
        // Create more than MAX_CANDIDATES (10) nodes
        let nodes: Vec<NodeInfo> = (0_u32..15)
            .map(|i| make_node_info(&format!("n{i:02}"), 1024 + i * 100, true, "1.0.0", vec![]))
            .collect();
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        let candidates = planner.plan(&input, &context);
        assert!(candidates.len() <= 10);
    }

    #[test]
    fn planner_preferred_but_not_required_symbols() {
        let planner = ExecutionPlanner::new();
        let sym = test_object_id(20);
        let nodes = vec![
            make_node_info("has", 2048, true, "1.0.0", vec![sym]),
            make_node_info("no", 2048, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        // preferred but NOT required => both eligible, but "has" scores higher
        let context = PlannerContext::new(test_connector_id()).with_preferred_symbols(vec![sym]);
        let candidates = planner.plan(&input, &context);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].node_id.as_str(), "node-has");
    }

    #[test]
    fn planner_no_preferred_no_required_symbols() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("a", 2048, true, "1.0.0", vec![test_object_id(1)]),
            make_node_info("b", 2048, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        // No preferred symbols => no locality bonus applied
        let candidates = planner.plan(&input, &context);
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn planner_multiple_required_symbols_all_needed() {
        let planner = ExecutionPlanner::new();
        let s1 = test_object_id(1);
        let s2 = test_object_id(2);
        let s3 = test_object_id(3);

        let nodes = vec![
            make_node_info("has_all", 2048, true, "1.0.0", vec![s1, s2, s3]),
            make_node_info("has_some", 2048, true, "1.0.0", vec![s1, s2]),
            make_node_info("has_none", 2048, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context =
            PlannerContext::new(test_connector_id()).with_required_symbols(vec![s1, s2, s3]);
        let candidates = planner.plan(&input, &context);
        // Only has_all has all 3 required symbols
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-has_all");
    }

    #[test]
    fn planner_singleton_writer_no_context_flag() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("a", 2048, true, "1.0.0", vec![]),
            make_node_info("b", 4096, true, "1.0.0", vec![]),
        ];
        // Singleton holder set on input but context does NOT have singleton_writer
        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-a");
        let context = PlannerContext::new(test_connector_id());
        let candidates = planner.plan(&input, &context);
        // Both should be eligible since singleton_writer is false in context
        assert_eq!(candidates.len(), 2);
    }

    // ---- DecisionReason Clone ----

    #[test]
    fn decision_reason_clone_all_variants() {
        let reasons = vec![
            DecisionReason::SelectedAsBest { rank: 1 },
            DecisionReason::EligibleNotSelected {
                rank: 3,
                better_count: 2,
            },
            DecisionReason::MissingConnector {
                connector_id: "fcp.test".to_string(),
            },
            DecisionReason::IncompatibleVersion {
                connector_id: "c".to_string(),
                required: "2.0".to_string(),
                installed: "1.0".to_string(),
            },
            DecisionReason::LeaseConflict {
                holder: test_node_id("h"),
                lease_purpose: "op".to_string(),
            },
            DecisionReason::ZoneRestriction {
                zone: "z:prod".to_string(),
                reason: "no access".to_string(),
            },
            DecisionReason::HasLocalData { symbol_count: 10 },
            DecisionReason::MissingRequiredSymbol {
                symbol_prefix: "0a1b".to_string(),
            },
            DecisionReason::Custom("custom reason".to_string()),
        ];
        for r in &reasons {
            let cloned = r.clone();
            let dbg_orig = format!("{r:?}");
            let dbg_clone = format!("{cloned:?}");
            assert_eq!(dbg_orig, dbg_clone);
        }
    }

    // ---- ExecutionPlanner Debug ----

    #[test]
    fn execution_planner_debug() {
        let planner = ExecutionPlanner::new();
        let dbg = format!("{planner:?}");
        assert!(dbg.contains("ExecutionPlanner"));
    }

    // ---- select_best with multiple eligible ----

    #[test]
    fn select_best_picks_highest_memory() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("small", 1024, true, "1.0.0", vec![]),
            make_node_info("medium", 4096, true, "1.0.0", vec![]),
            make_node_info("large", 16384, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        let best = planner.select_best(&input, &context).unwrap();
        assert_eq!(best.node_id.as_str(), "node-large");
    }

    // ---- Planner plan ranking correctness ----

    #[test]
    fn plan_ranks_are_sequential() {
        let planner = ExecutionPlanner::new();
        let nodes = vec![
            make_node_info("x", 8192, true, "1.0.0", vec![]),
            make_node_info("y", 4096, true, "1.0.0", vec![]),
            make_node_info("z", 2048, true, "1.0.0", vec![]),
        ];
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(test_connector_id());
        let candidates = planner.plan(&input, &context);
        assert_eq!(candidates.len(), 3);

        // First should have SelectedAsBest { rank: 1 }
        assert!(
            candidates[0]
                .decision_reasons
                .iter()
                .any(|r| matches!(r, DecisionReason::SelectedAsBest { rank: 1 }))
        );

        // Second should have rank 2
        assert!(candidates[1].decision_reasons.iter().any(|r| matches!(
            r,
            DecisionReason::EligibleNotSelected {
                rank: 2,
                better_count: 1
            }
        )));

        // Third should have rank 3
        assert!(candidates[2].decision_reasons.iter().any(|r| matches!(
            r,
            DecisionReason::EligibleNotSelected {
                rank: 3,
                better_count: 2
            }
        )));
    }
}
