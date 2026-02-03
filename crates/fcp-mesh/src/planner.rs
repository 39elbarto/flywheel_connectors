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
        let nodes_excluded = total_nodes - candidates.len();

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
}
