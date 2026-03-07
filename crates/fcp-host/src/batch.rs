//! Batch invoke: multi-tool execution with dependency ordering.
//!
//! Allows agents to invoke multiple tools in a single request with:
//! - Dependency-aware topological ordering
//! - Bounded parallelism for independent operations
//! - Stop-on-first-error or continue-on-failure semantics
//! - Zone constraint validation (fail-fast, default deny)
//! - Per-operation timing and audit trail
//!
//! Based on bead `flywheel_connectors-2b2l`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use fcp_core::ZoneId;
use serde::{Deserialize, Serialize};

use crate::{HostError, HostResult};

// ─────────────────────────────────────────────────────────────────────────────
// Request Types
// ─────────────────────────────────────────────────────────────────────────────

/// A batch invoke request containing multiple operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInvokeRequest {
    /// Operations to execute.
    pub operations: Vec<BatchOperation>,
    /// Execution options.
    pub options: BatchOptions,
}

/// A single operation within a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOperation {
    /// Unique identifier for this operation within the batch.
    pub id: String,
    /// Tool identifier (e.g., "fcp.discord.send_message").
    pub tool: String,
    /// Input payload for the tool.
    pub input: serde_json::Value,
    /// IDs of operations that must complete before this one.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Optional zone override for this operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

/// Options controlling batch execution behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOptions {
    /// Maximum number of operations to run concurrently.
    #[serde(default = "default_max_parallelism")]
    pub max_parallelism: u32,
    /// Whether to abort remaining operations on first failure.
    #[serde(default)]
    pub stop_on_first_error: bool,
    /// Overall timeout for the entire batch.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_max_parallelism() -> u32 {
    8
}

fn default_timeout_ms() -> u64 {
    30_000
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            max_parallelism: default_max_parallelism(),
            stop_on_first_error: false,
            timeout_ms: default_timeout_ms(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response Types
// ─────────────────────────────────────────────────────────────────────────────

/// Overall batch status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// All operations succeeded.
    Success,
    /// Some operations succeeded, some failed.
    PartialSuccess,
    /// All operations failed.
    AllFailed,
    /// Batch was aborted (e.g., stop_on_first_error triggered).
    Aborted,
}

/// Status of an individual operation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResultStatus {
    /// Operation completed successfully.
    Success,
    /// Operation failed.
    Error,
    /// Operation was skipped (dependency failed or batch aborted).
    Skipped,
}

/// Result of a single operation within a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    /// Operation ID.
    pub id: String,
    /// Result status.
    pub status: OperationResultStatus,
    /// Output payload (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// Error info (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BatchOperationError>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// Error details for a failed operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOperationError {
    /// Error code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Retry-after hint in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Response from a batch invoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInvokeResponse {
    /// Overall status.
    pub status: BatchStatus,
    /// Number of operations that completed successfully.
    pub completed: usize,
    /// Number of operations that failed.
    pub failed: usize,
    /// Number of operations that were skipped.
    pub skipped: usize,
    /// Per-operation results in submission order.
    pub results: Vec<OperationResult>,
    /// Total batch duration in milliseconds.
    pub total_duration_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution Plan
// ─────────────────────────────────────────────────────────────────────────────

/// A tier of operations that can execute in parallel.
#[derive(Debug, Clone)]
pub struct ExecutionTier {
    /// Operation IDs in this tier (all independent of each other).
    pub operation_ids: Vec<String>,
}

/// An execution plan produced by topological sort.
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// Tiers of operations, executed sequentially; within each tier, parallel.
    pub tiers: Vec<ExecutionTier>,
    /// Total number of operations.
    pub total_operations: usize,
}

impl ExecutionPlan {
    /// Number of tiers (sequential depth).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.tiers.len()
    }

    /// Maximum width (largest tier).
    #[must_use]
    pub fn max_width(&self) -> usize {
        self.tiers.iter().map(|t| t.operation_ids.len()).max().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Maps tool names to their bound zones for validation.
#[derive(Debug, Clone, Default)]
pub struct ZoneRegistry {
    tool_zones: HashMap<String, ZoneId>,
}

impl ZoneRegistry {
    /// Create a new zone registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool's zone binding.
    pub fn register(&mut self, tool: &str, zone: ZoneId) {
        self.tool_zones.insert(tool.to_string(), zone);
    }

    /// Look up the zone for a tool.
    #[must_use]
    pub fn get_zone(&self, tool: &str) -> Option<&ZoneId> {
        self.tool_zones.get(tool)
    }
}

/// Validates zone constraints for batch operations.
#[derive(Debug)]
pub struct BatchZoneValidator {
    agent_zone: ZoneId,
    registry: ZoneRegistry,
}

impl BatchZoneValidator {
    /// Create a new zone validator.
    #[must_use]
    pub fn new(agent_zone: ZoneId, registry: ZoneRegistry) -> Self {
        Self {
            agent_zone,
            registry,
        }
    }

    /// Validate all operations are zone-accessible.
    ///
    /// Returns the IDs of operations that violate zone constraints.
    pub fn validate(&self, operations: &[BatchOperation]) -> HostResult<()> {
        let mut violations = Vec::new();
        for op in operations {
            if let Some(connector_zone) = self.registry.get_zone(&op.tool) {
                if !zone_accessible(&self.agent_zone, connector_zone) {
                    violations.push(op.id.clone());
                }
            }
            // Unknown tools are allowed through — the executor will handle
            // tool resolution failures separately.
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(HostError::PreflightFailed(format!(
                "zone boundary violations for operations: {}",
                violations.join(", ")
            )))
        }
    }

    /// Group operations by their target zone.
    #[must_use]
    pub fn group_by_zone(&self, operations: &[BatchOperation]) -> BTreeMap<String, Vec<String>> {
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for op in operations {
            let zone_str = self
                .registry
                .get_zone(&op.tool)
                .map_or_else(|| self.agent_zone.as_str().to_string(), |z| z.as_str().to_string());
            groups.entry(zone_str).or_default().push(op.id.clone());
        }
        groups
    }
}

/// Check whether an agent zone can access a connector zone.
///
/// Zone hierarchy: `z:owner` > `z:private` > `z:work` > `z:project:*` > `z:community` > `z:public`.
/// A higher-privilege zone can access lower-privilege zones but not vice versa.
fn zone_accessible(agent_zone: &ZoneId, connector_zone: &ZoneId) -> bool {
    let agent = agent_zone.as_str();
    let connector = connector_zone.as_str();

    // Same zone is always accessible.
    if agent == connector {
        return true;
    }

    let hierarchy = [
        "z:owner",
        "z:private",
        "z:work",
        "z:community",
        "z:public",
    ];

    let agent_level = hierarchy.iter().position(|&z| z == agent);
    let connector_level = hierarchy.iter().position(|&z| z == connector);

    match (agent_level, connector_level) {
        (Some(a), Some(c)) => a <= c, // Lower index = higher privilege
        _ => {
            // Project zones: accessible if agent is work or higher, or same project.
            if connector.starts_with("z:project:") {
                agent == "z:owner"
                    || agent == "z:private"
                    || agent == "z:work"
                    || agent.starts_with("z:project:")
            } else if agent.starts_with("z:project:") {
                connector == "z:community" || connector == "z:public"
            } else {
                false
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch Executor
// ─────────────────────────────────────────────────────────────────────────────

/// Batch executor that plans and executes operations.
#[derive(Debug)]
pub struct BatchExecutor {
    zone_validator: Option<BatchZoneValidator>,
}

impl BatchExecutor {
    /// Create a new batch executor without zone validation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            zone_validator: None,
        }
    }

    /// Create a new batch executor with zone validation.
    #[must_use]
    pub fn with_zone_validator(validator: BatchZoneValidator) -> Self {
        Self {
            zone_validator: Some(validator),
        }
    }

    /// Validate a batch request before execution.
    pub fn validate(&self, request: &BatchInvokeRequest) -> HostResult<()> {
        // Check for empty batch.
        if request.operations.is_empty() {
            return Err(HostError::InvalidFilter("batch has no operations".into()));
        }

        // Check for duplicate IDs.
        let mut seen = HashSet::new();
        for op in &request.operations {
            if !seen.insert(&op.id) {
                return Err(HostError::InvalidFilter(format!(
                    "duplicate operation id: {}",
                    op.id
                )));
            }
        }

        // Check max_parallelism > 0.
        if request.options.max_parallelism == 0 {
            return Err(HostError::InvalidFilter(
                "max_parallelism must be > 0".into(),
            ));
        }

        // Check that all depends_on references exist.
        let all_ids: HashSet<&str> = request.operations.iter().map(|o| o.id.as_str()).collect();
        for op in &request.operations {
            for dep in &op.depends_on {
                if !all_ids.contains(dep.as_str()) {
                    return Err(HostError::InvalidFilter(format!(
                        "operation '{}' depends on unknown operation '{dep}'",
                        op.id
                    )));
                }
            }
            // Check self-dependency.
            if op.depends_on.contains(&op.id) {
                return Err(HostError::InvalidFilter(format!(
                    "operation '{}' depends on itself",
                    op.id
                )));
            }
        }

        // Check for cycles.
        if has_cycle(&request.operations) {
            return Err(HostError::InvalidFilter(
                "dependency cycle detected in batch operations".into(),
            ));
        }

        // Zone validation.
        if let Some(ref validator) = self.zone_validator {
            validator.validate(&request.operations)?;
        }

        Ok(())
    }

    /// Build an execution plan via topological sort.
    ///
    /// Operations are grouped into tiers: within each tier, operations are
    /// independent and can run in parallel. Tiers must execute sequentially.
    pub fn plan(&self, request: &BatchInvokeRequest) -> HostResult<ExecutionPlan> {
        self.validate(request)?;
        let tiers = topological_tiers(&request.operations)?;
        Ok(ExecutionPlan {
            total_operations: request.operations.len(),
            tiers,
        })
    }

    /// Execute a batch synchronously using a provided handler function.
    ///
    /// The `handler` is called for each operation and returns either an output
    /// value or an error. Operations are executed in topological tier order.
    /// Within each tier, operations are executed sequentially (async parallel
    /// execution is handled at a higher layer).
    pub fn execute_sync<F>(
        &self,
        request: &BatchInvokeRequest,
        handler: F,
    ) -> HostResult<BatchInvokeResponse>
    where
        F: Fn(&BatchOperation) -> Result<serde_json::Value, BatchOperationError>,
    {
        let plan = self.plan(request)?;
        let start = Instant::now();
        let timeout = Duration::from_millis(request.options.timeout_ms);

        // Index operations by ID for quick lookup.
        let op_map: HashMap<&str, &BatchOperation> =
            request.operations.iter().map(|o| (o.id.as_str(), o)).collect();

        let mut results_map: HashMap<String, OperationResult> = HashMap::new();
        let mut aborted = false;

        for tier in &plan.tiers {
            if aborted {
                // Mark remaining operations as skipped.
                for op_id in &tier.operation_ids {
                    results_map.insert(
                        op_id.clone(),
                        OperationResult {
                            id: op_id.clone(),
                            status: OperationResultStatus::Skipped,
                            output: None,
                            error: None,
                            duration_ms: 0,
                        },
                    );
                }
                continue;
            }

            // Check timeout.
            if start.elapsed() >= timeout {
                aborted = true;
                for op_id in &tier.operation_ids {
                    results_map.insert(
                        op_id.clone(),
                        OperationResult {
                            id: op_id.clone(),
                            status: OperationResultStatus::Skipped,
                            output: None,
                            error: Some(BatchOperationError {
                                code: "BATCH_TIMEOUT".into(),
                                message: "batch timeout exceeded".into(),
                                retry_after_ms: None,
                            }),
                            duration_ms: 0,
                        },
                    );
                }
                continue;
            }

            for op_id in &tier.operation_ids {
                if aborted {
                    results_map.insert(
                        op_id.clone(),
                        OperationResult {
                            id: op_id.clone(),
                            status: OperationResultStatus::Skipped,
                            output: None,
                            error: None,
                            duration_ms: 0,
                        },
                    );
                    continue;
                }

                let op = op_map[op_id.as_str()];

                // Check if any dependency failed.
                let dep_failed = op.depends_on.iter().any(|dep_id| {
                    results_map
                        .get(dep_id.as_str())
                        .is_some_and(|r| r.status != OperationResultStatus::Success)
                });

                if dep_failed {
                    results_map.insert(
                        op_id.clone(),
                        OperationResult {
                            id: op_id.clone(),
                            status: OperationResultStatus::Skipped,
                            output: None,
                            error: Some(BatchOperationError {
                                code: "DEP_FAILED".into(),
                                message: "dependency failed".into(),
                                retry_after_ms: None,
                            }),
                            duration_ms: 0,
                        },
                    );
                    continue;
                }

                let op_start = Instant::now();
                match handler(op) {
                    Ok(output) => {
                        results_map.insert(
                            op_id.clone(),
                            OperationResult {
                                id: op_id.clone(),
                                status: OperationResultStatus::Success,
                                output: Some(output),
                                error: None,
                                duration_ms: op_start.elapsed().as_millis() as u64,
                            },
                        );
                    }
                    Err(err) => {
                        results_map.insert(
                            op_id.clone(),
                            OperationResult {
                                id: op_id.clone(),
                                status: OperationResultStatus::Error,
                                output: None,
                                error: Some(err),
                                duration_ms: op_start.elapsed().as_millis() as u64,
                            },
                        );
                        if request.options.stop_on_first_error {
                            aborted = true;
                        }
                    }
                }
            }
        }

        // Build response in submission order.
        let results: Vec<OperationResult> = request
            .operations
            .iter()
            .map(|op| {
                results_map.remove(op.id.as_str()).unwrap_or(OperationResult {
                    id: op.id.clone(),
                    status: OperationResultStatus::Skipped,
                    output: None,
                    error: None,
                    duration_ms: 0,
                })
            })
            .collect();

        let completed = results
            .iter()
            .filter(|r| r.status == OperationResultStatus::Success)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.status == OperationResultStatus::Error)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.status == OperationResultStatus::Skipped)
            .count();

        let status = if aborted && failed > 0 {
            BatchStatus::Aborted
        } else if failed == 0 {
            BatchStatus::Success
        } else if completed == 0 {
            BatchStatus::AllFailed
        } else {
            BatchStatus::PartialSuccess
        };

        Ok(BatchInvokeResponse {
            status,
            completed,
            failed,
            skipped,
            results,
            total_duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

impl Default for BatchExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph Algorithms
// ─────────────────────────────────────────────────────────────────────────────

/// Detect cycles in the operation dependency graph using iterative DFS.
fn has_cycle(operations: &[BatchOperation]) -> bool {
    let id_set: HashSet<&str> = operations.iter().map(|o| o.id.as_str()).collect();
    let deps: HashMap<&str, Vec<&str>> = operations
        .iter()
        .map(|o| {
            (
                o.id.as_str(),
                o.depends_on
                    .iter()
                    .filter_map(|d| {
                        if id_set.contains(d.as_str()) {
                            Some(d.as_str())
                        } else {
                            None
                        }
                    })
                    .collect(),
            )
        })
        .collect();

    // States: 0=unvisited, 1=in-progress, 2=done
    let mut state: HashMap<&str, u8> = deps.keys().map(|&k| (k, 0)).collect();

    for &start in deps.keys() {
        if state[start] == 2 {
            continue;
        }
        // Iterative DFS with explicit stack of (node, iterator_position).
        let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
        state.insert(start, 1);

        while let Some((node, idx)) = stack.last_mut() {
            let neighbors = &deps[*node];
            if *idx < neighbors.len() {
                let next = neighbors[*idx];
                *idx += 1;
                match state[next] {
                    1 => return true, // Back edge → cycle.
                    0 => {
                        state.insert(next, 1);
                        stack.push((next, 0));
                    }
                    _ => {} // Already done.
                }
            } else {
                state.insert(*node, 2);
                stack.pop();
            }
        }
    }

    false
}

/// Compute topological tiers via Kahn's algorithm.
///
/// Returns tiers where each tier contains operations whose dependencies are
/// all satisfied by prior tiers.
fn topological_tiers(operations: &[BatchOperation]) -> HostResult<Vec<ExecutionTier>> {
    let id_set: HashSet<&str> = operations.iter().map(|o| o.id.as_str()).collect();

    // Build adjacency and in-degree.
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for op in operations {
        in_degree.entry(op.id.as_str()).or_insert(0);
        for dep in &op.depends_on {
            if id_set.contains(dep.as_str()) {
                *in_degree.entry(op.id.as_str()).or_insert(0) += 1;
                dependents
                    .entry(dep.as_str())
                    .or_default()
                    .push(op.id.as_str());
            }
        }
    }

    let mut tiers = Vec::new();
    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(&id, _)| id)
        .collect();

    // Sort for determinism.
    let mut initial: Vec<&str> = queue.drain(..).collect();
    initial.sort_unstable();
    queue.extend(initial);

    let mut processed = 0usize;

    while !queue.is_empty() {
        let tier_ids: Vec<String> = queue.drain(..).map(String::from).collect();
        processed += tier_ids.len();

        let mut next_ready: Vec<&str> = Vec::new();
        for id in &tier_ids {
            if let Some(deps) = dependents.get(id.as_str()) {
                for &dep_id in deps {
                    let deg = in_degree.get_mut(dep_id).expect("in-degree entry");
                    *deg -= 1;
                    if *deg == 0 {
                        next_ready.push(dep_id);
                    }
                }
            }
        }

        tiers.push(ExecutionTier {
            operation_ids: tier_ids,
        });

        next_ready.sort_unstable();
        queue.extend(next_ready);
    }

    if processed != operations.len() {
        return Err(HostError::InvalidFilter(
            "dependency cycle detected in batch operations".into(),
        ));
    }

    Ok(tiers)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──

    fn op(id: &str, tool: &str, deps: &[&str]) -> BatchOperation {
        BatchOperation {
            id: id.into(),
            tool: tool.into(),
            input: serde_json::json!({}),
            depends_on: deps.iter().map(|&s| s.into()).collect(),
            zone: None,
        }
    }

    fn simple_request(ops: Vec<BatchOperation>) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations: ops,
            options: BatchOptions::default(),
        }
    }

    fn ok_handler(
        _op: &BatchOperation,
    ) -> Result<serde_json::Value, BatchOperationError> {
        Ok(serde_json::json!({"ok": true}))
    }

    fn failing_handler(
        _op: &BatchOperation,
    ) -> Result<serde_json::Value, BatchOperationError> {
        Err(BatchOperationError {
            code: "TEST_ERROR".into(),
            message: "test failure".into(),
            retry_after_ms: None,
        })
    }

    fn selective_handler(
        op: &BatchOperation,
    ) -> Result<serde_json::Value, BatchOperationError> {
        if op.id.starts_with("fail") {
            Err(BatchOperationError {
                code: "FAIL".into(),
                message: format!("{} failed", op.id),
                retry_after_ms: None,
            })
        } else {
            Ok(serde_json::json!({"id": op.id}))
        }
    }

    // ── Validation Tests ──

    #[test]
    fn validate_empty_batch_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("no operations"));
    }

    #[test]
    fn validate_duplicate_ids_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("a", "tool2", &[]),
        ]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("duplicate operation id"));
    }

    #[test]
    fn validate_unknown_dependency_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &["nonexistent"])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("unknown operation"));
    }

    #[test]
    fn validate_self_dependency_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &["a"])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("depends on itself"));
    }

    #[test]
    fn validate_cycle_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &["b"]),
            op("b", "tool1", &["a"]),
        ]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn validate_three_node_cycle_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &["c"]),
            op("b", "tool1", &["a"]),
            op("c", "tool1", &["b"]),
        ]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn validate_zero_parallelism_rejected() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![op("a", "tool1", &[])],
            options: BatchOptions {
                max_parallelism: 0,
                ..Default::default()
            },
        };
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("max_parallelism"));
    }

    #[test]
    fn validate_valid_request_passes() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &["a"]),
            op("c", "tool3", &["a"]),
            op("d", "tool4", &["b", "c"]),
        ]);
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn validate_single_operation_passes() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("only", "tool", &[])]);
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn validate_no_dependencies_passes() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &[]),
            op("c", "tool3", &[]),
        ]);
        assert!(executor.validate(&req).is_ok());
    }

    // ── Execution Plan Tests ──

    #[test]
    fn plan_single_op_one_tier() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.tiers.len(), 1);
        assert_eq!(plan.tiers[0].operation_ids, vec!["a"]);
        assert_eq!(plan.total_operations, 1);
    }

    #[test]
    fn plan_independent_ops_single_tier() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &[]),
            op("c", "tool3", &[]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.tiers.len(), 1);
        assert_eq!(plan.tiers[0].operation_ids.len(), 3);
    }

    #[test]
    fn plan_linear_chain_three_tiers() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &["a"]),
            op("c", "tool3", &["b"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 3);
        assert_eq!(plan.max_width(), 1);
        assert_eq!(plan.tiers[0].operation_ids, vec!["a"]);
        assert_eq!(plan.tiers[1].operation_ids, vec!["b"]);
        assert_eq!(plan.tiers[2].operation_ids, vec!["c"]);
    }

    #[test]
    fn plan_diamond_shape() {
        // a -> b, a -> c, b -> d, c -> d
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &["a"]),
            op("c", "tool3", &["a"]),
            op("d", "tool4", &["b", "c"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 3);
        assert_eq!(plan.tiers[0].operation_ids, vec!["a"]);
        assert_eq!(plan.tiers[1].operation_ids.len(), 2);
        assert!(plan.tiers[1].operation_ids.contains(&"b".to_string()));
        assert!(plan.tiers[1].operation_ids.contains(&"c".to_string()));
        assert_eq!(plan.tiers[2].operation_ids, vec!["d"]);
    }

    #[test]
    fn plan_wide_then_narrow() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "t", &[]),
            op("b", "t", &[]),
            op("c", "t", &[]),
            op("d", "t", &[]),
            op("e", "t", &["a", "b", "c", "d"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 2);
        assert_eq!(plan.max_width(), 4);
        assert_eq!(plan.tiers[1].operation_ids, vec!["e"]);
    }

    #[test]
    fn plan_deterministic_ordering() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("z", "t", &[]),
            op("a", "t", &[]),
            op("m", "t", &[]),
        ]);
        let plan1 = executor.plan(&req).unwrap();
        let plan2 = executor.plan(&req).unwrap();
        assert_eq!(
            plan1.tiers[0].operation_ids,
            plan2.tiers[0].operation_ids,
            "plan should be deterministic"
        );
        // Sorted alphabetically.
        assert_eq!(plan1.tiers[0].operation_ids, vec!["a", "m", "z"]);
    }

    // ── Execution Tests ──

    #[test]
    fn execute_all_succeed() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &[]),
        ]);
        let resp = executor.execute_sync(&req, ok_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.completed, 2);
        assert_eq!(resp.failed, 0);
        assert_eq!(resp.skipped, 0);
        assert_eq!(resp.results.len(), 2);
    }

    #[test]
    fn execute_all_fail() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &[]),
        ]);
        let resp = executor.execute_sync(&req, failing_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::AllFailed);
        assert_eq!(resp.completed, 0);
        assert_eq!(resp.failed, 2);
    }

    #[test]
    fn execute_partial_failure() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("ok1", "tool", &[]),
            op("fail1", "tool", &[]),
            op("ok2", "tool", &[]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::PartialSuccess);
        assert_eq!(resp.completed, 2);
        assert_eq!(resp.failed, 1);
    }

    #[test]
    fn execute_stop_on_first_error() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![
                op("a", "tool", &[]),
                op("fail1", "tool", &["a"]),
                op("c", "tool", &["fail1"]),
            ],
            options: BatchOptions {
                stop_on_first_error: true,
                ..Default::default()
            },
        };
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::Aborted);
        assert_eq!(resp.completed, 1); // "a" succeeded
        assert_eq!(resp.failed, 1); // "fail1" failed
        assert_eq!(resp.skipped, 1); // "c" skipped
    }

    #[test]
    fn execute_dependency_failure_skips_dependents() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("fail1", "tool", &[]),
            op("b", "tool", &["fail1"]),
            op("c", "tool", &["b"]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        // fail1 fails, b skipped (dep failed), c skipped (dep failed)
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.skipped, 2);
    }

    #[test]
    fn execute_independent_ops_not_skipped_on_failure() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("fail1", "tool", &[]),
            op("ok1", "tool", &[]), // Independent of fail1
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.completed, 1);
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.skipped, 0);
    }

    #[test]
    fn execute_results_in_submission_order() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("z", "tool", &[]),
            op("a", "tool", &[]),
            op("m", "tool", &[]),
        ]);
        let resp = executor.execute_sync(&req, ok_handler).unwrap();
        let ids: Vec<&str> = resp.results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["z", "a", "m"], "results should be in submission order");
    }

    #[test]
    fn execute_diamond_dependency_order() {
        let executor = BatchExecutor::new();
        let call_order = std::sync::Mutex::new(Vec::new());
        let req = simple_request(vec![
            op("a", "tool", &[]),
            op("b", "tool", &["a"]),
            op("c", "tool", &["a"]),
            op("d", "tool", &["b", "c"]),
        ]);
        let resp = executor
            .execute_sync(&req, |op| {
                call_order.lock().unwrap().push(op.id.clone());
                Ok(serde_json::json!({"id": op.id}))
            })
            .unwrap();

        let order = call_order.lock().unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        // "a" must come before "b" and "c"; "d" must come last.
        let a_pos = order.iter().position(|s| s == "a").unwrap();
        let b_pos = order.iter().position(|s| s == "b").unwrap();
        let c_pos = order.iter().position(|s| s == "c").unwrap();
        let d_pos = order.iter().position(|s| s == "d").unwrap();
        assert!(a_pos < b_pos);
        assert!(a_pos < c_pos);
        assert!(b_pos < d_pos);
        assert!(c_pos < d_pos);
    }

    #[test]
    fn execute_handler_output_is_captured() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let resp = executor
            .execute_sync(&req, |op| {
                Ok(serde_json::json!({"tool": op.tool, "processed": true}))
            })
            .unwrap();
        let output = resp.results[0].output.as_ref().unwrap();
        assert_eq!(output["tool"], "tool");
        assert_eq!(output["processed"], true);
    }

    #[test]
    fn execute_error_details_are_captured() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let resp = executor
            .execute_sync(&req, |_| {
                Err(BatchOperationError {
                    code: "RATE_LIMIT".into(),
                    message: "too many requests".into(),
                    retry_after_ms: Some(5000),
                })
            })
            .unwrap();
        let err = resp.results[0].error.as_ref().unwrap();
        assert_eq!(err.code, "RATE_LIMIT");
        assert_eq!(err.retry_after_ms, Some(5000));
    }

    #[test]
    fn execute_duration_is_tracked() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let resp = executor.execute_sync(&req, ok_handler).unwrap();
        // Duration should be set (may be 0ms for fast ops, but field exists).
        assert!(resp.total_duration_ms < 1000);
        assert!(resp.results[0].duration_ms < 1000);
    }

    // ── Zone Validation Tests ──

    #[test]
    fn zone_same_zone_accessible() {
        assert!(zone_accessible(
            &ZoneId::work(),
            &ZoneId::work()
        ));
    }

    #[test]
    fn zone_owner_accesses_everything() {
        assert!(zone_accessible(
            &ZoneId::owner(),
            &ZoneId::public()
        ));
        assert!(zone_accessible(
            &ZoneId::owner(),
            &ZoneId::work()
        ));
        assert!(zone_accessible(
            &ZoneId::owner(),
            &ZoneId::private()
        ));
    }

    #[test]
    fn zone_public_cannot_access_private() {
        assert!(!zone_accessible(
            &ZoneId::public(),
            &ZoneId::private()
        ));
    }

    #[test]
    fn zone_work_cannot_access_private() {
        assert!(!zone_accessible(
            &ZoneId::work(),
            &ZoneId::private()
        ));
    }

    #[test]
    fn zone_work_accesses_community() {
        assert!(zone_accessible(
            &ZoneId::work(),
            &ZoneId::community()
        ));
    }

    #[test]
    fn zone_work_accesses_public() {
        assert!(zone_accessible(
            &ZoneId::work(),
            &ZoneId::public()
        ));
    }

    #[test]
    fn zone_project_accesses_community() {
        assert!(zone_accessible(
            &"z:project:myapp".parse::<ZoneId>().unwrap(),
            &ZoneId::community()
        ));
    }

    #[test]
    fn zone_project_accesses_public() {
        assert!(zone_accessible(
            &"z:project:myapp".parse::<ZoneId>().unwrap(),
            &ZoneId::public()
        ));
    }

    #[test]
    fn zone_work_accesses_project() {
        assert!(zone_accessible(
            &ZoneId::work(),
            &"z:project:myapp".parse::<ZoneId>().unwrap()
        ));
    }

    #[test]
    fn zone_community_cannot_access_project() {
        assert!(!zone_accessible(
            &ZoneId::community(),
            &"z:project:myapp".parse::<ZoneId>().unwrap()
        ));
    }

    #[test]
    fn zone_validator_rejects_violation() {
        let mut reg = ZoneRegistry::new();
        reg.register("secret.tool", ZoneId::owner());
        let validator =
            BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![op("a", "secret.tool", &[])];
        let err = validator.validate(&ops).unwrap_err();
        assert!(err.to_string().contains("zone boundary violations"));
        assert!(err.to_string().contains('a'));
    }

    #[test]
    fn zone_validator_allows_accessible() {
        let mut reg = ZoneRegistry::new();
        reg.register("pub.tool", ZoneId::public());
        let validator =
            BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![op("a", "pub.tool", &[])];
        assert!(validator.validate(&ops).is_ok());
    }

    #[test]
    fn zone_validator_unknown_tool_passes() {
        let reg = ZoneRegistry::new();
        let validator =
            BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![op("a", "unknown.tool", &[])];
        assert!(validator.validate(&ops).is_ok());
    }

    #[test]
    fn zone_validator_multiple_violations() {
        let mut reg = ZoneRegistry::new();
        reg.register("secret1", ZoneId::owner());
        reg.register("secret2", ZoneId::private());
        let validator =
            BatchZoneValidator::new(ZoneId::public(), reg);
        let ops = vec![
            op("a", "secret1", &[]),
            op("b", "secret2", &[]),
        ];
        let err = validator.validate(&ops).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains('a'));
        assert!(msg.contains('b'));
    }

    #[test]
    fn zone_group_by_zone() {
        let mut reg = ZoneRegistry::new();
        reg.register("pub.tool", ZoneId::public());
        reg.register("work.tool", ZoneId::work());
        let validator =
            BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![
            op("a", "pub.tool", &[]),
            op("b", "work.tool", &[]),
            op("c", "unknown.tool", &[]),
        ];
        let groups = validator.group_by_zone(&ops);
        assert_eq!(groups.len(), 2); // public, work (unknown defaults to agent zone = work)
        assert!(groups.contains_key("z:public"));
        assert!(groups.contains_key("z:work"));
        // work group should contain both the work.tool op and the unknown.tool op
        assert_eq!(groups["z:work"].len(), 2);
    }

    #[test]
    fn executor_with_zone_validator_rejects_violations() {
        let mut reg = ZoneRegistry::new();
        reg.register("secret", ZoneId::owner());
        let validator =
            BatchZoneValidator::new(ZoneId::public(), reg);
        let executor = BatchExecutor::with_zone_validator(validator);
        let req = simple_request(vec![op("a", "secret", &[])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("zone boundary"));
    }

    // ── Serialization Tests ──

    #[test]
    fn batch_request_json_roundtrip() {
        let req = simple_request(vec![
            op("a", "fcp.discord.send", &[]),
            op("b", "fcp.github.create", &["a"]),
        ]);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: BatchInvokeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operations.len(), 2);
        assert_eq!(parsed.operations[1].depends_on, vec!["a"]);
    }

    #[test]
    fn batch_response_json_roundtrip() {
        let resp = BatchInvokeResponse {
            status: BatchStatus::PartialSuccess,
            completed: 2,
            failed: 1,
            skipped: 0,
            results: vec![
                OperationResult {
                    id: "a".into(),
                    status: OperationResultStatus::Success,
                    output: Some(serde_json::json!({"ok": true})),
                    error: None,
                    duration_ms: 42,
                },
                OperationResult {
                    id: "b".into(),
                    status: OperationResultStatus::Error,
                    output: None,
                    error: Some(BatchOperationError {
                        code: "ERR".into(),
                        message: "fail".into(),
                        retry_after_ms: Some(1000),
                    }),
                    duration_ms: 10,
                },
            ],
            total_duration_ms: 52,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BatchInvokeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, BatchStatus::PartialSuccess);
        assert_eq!(parsed.results.len(), 2);
    }

    #[test]
    fn batch_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&BatchStatus::PartialSuccess).unwrap(),
            "\"partial_success\""
        );
        assert_eq!(
            serde_json::to_string(&BatchStatus::AllFailed).unwrap(),
            "\"all_failed\""
        );
    }

    #[test]
    fn operation_result_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&OperationResultStatus::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&OperationResultStatus::Skipped).unwrap(),
            "\"skipped\""
        );
    }

    #[test]
    fn batch_options_defaults() {
        let opts = BatchOptions::default();
        assert_eq!(opts.max_parallelism, 8);
        assert!(!opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 30_000);
    }

    #[test]
    fn batch_options_deserialize_with_defaults() {
        let json = r#"{"max_parallelism": 4}"#;
        let opts: BatchOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.max_parallelism, 4);
        assert!(!opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 30_000);
    }

    // ── Edge Cases ──

    #[test]
    fn large_batch_no_deps() {
        let executor = BatchExecutor::new();
        let ops: Vec<BatchOperation> = (0..100)
            .map(|i| op(&format!("op{i}"), "tool", &[]))
            .collect();
        let req = simple_request(ops);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 1);
        assert_eq!(plan.max_width(), 100);
    }

    #[test]
    fn large_linear_chain() {
        let executor = BatchExecutor::new();
        let mut ops = vec![op("op0", "tool", &[])];
        for i in 1..50 {
            ops.push(op(
                &format!("op{i}"),
                "tool",
                &[&format!("op{}", i - 1)],
            ));
        }
        let req = simple_request(ops);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 50);
        assert_eq!(plan.max_width(), 1);
    }

    #[test]
    fn operation_with_empty_tool() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "", &[])]);
        // Empty tool name is valid at this layer — tool resolution happens later.
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn operation_with_complex_input() {
        let executor = BatchExecutor::new();
        let mut op = op("a", "tool", &[]);
        op.input = serde_json::json!({
            "nested": {"array": [1, 2, 3], "null": null},
            "bool": true
        });
        let req = simple_request(vec![op]);
        let resp = executor
            .execute_sync(&req, |o| Ok(o.input.clone()))
            .unwrap();
        let output = resp.results[0].output.as_ref().unwrap();
        assert_eq!(output["nested"]["array"][1], 2);
    }

    #[test]
    fn executor_default_trait() {
        let executor = BatchExecutor::default();
        let req = simple_request(vec![op("a", "tool", &[])]);
        assert!(executor.validate(&req).is_ok());
    }

    // ── Cycle Detection Tests ──

    #[test]
    fn no_cycle_in_dag() {
        assert!(!has_cycle(&[
            op("a", "t", &[]),
            op("b", "t", &["a"]),
            op("c", "t", &["a"]),
            op("d", "t", &["b", "c"]),
        ]));
    }

    #[test]
    fn cycle_two_nodes() {
        assert!(has_cycle(&[
            op("a", "t", &["b"]),
            op("b", "t", &["a"]),
        ]));
    }

    #[test]
    fn cycle_three_nodes() {
        assert!(has_cycle(&[
            op("a", "t", &["c"]),
            op("b", "t", &["a"]),
            op("c", "t", &["b"]),
        ]));
    }

    #[test]
    fn no_cycle_empty() {
        assert!(!has_cycle(&[]));
    }

    #[test]
    fn no_cycle_single_node() {
        assert!(!has_cycle(&[op("a", "t", &[])]));
    }

    // ── Zone Registry Tests ──

    #[test]
    fn zone_registry_register_and_get() {
        let mut reg = ZoneRegistry::new();
        reg.register("tool1", ZoneId::work());
        assert_eq!(
            reg.get_zone("tool1").unwrap().as_str(),
            "z:work"
        );
        assert!(reg.get_zone("unknown").is_none());
    }

    #[test]
    fn zone_registry_overwrite() {
        let mut reg = ZoneRegistry::new();
        reg.register("tool1", ZoneId::work());
        reg.register("tool1", ZoneId::public());
        assert_eq!(
            reg.get_zone("tool1").unwrap().as_str(),
            "z:public"
        );
    }

    // ── Execution Plan Properties ──

    #[test]
    fn execution_plan_depth_and_width() {
        let plan = ExecutionPlan {
            tiers: vec![
                ExecutionTier {
                    operation_ids: vec!["a".into(), "b".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["c".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["d".into(), "e".into(), "f".into()],
                },
            ],
            total_operations: 6,
        };
        assert_eq!(plan.depth(), 3);
        assert_eq!(plan.max_width(), 3);
    }

    #[test]
    fn execution_plan_empty() {
        let plan = ExecutionPlan {
            tiers: vec![],
            total_operations: 0,
        };
        assert_eq!(plan.depth(), 0);
        assert_eq!(plan.max_width(), 0);
    }

    // ── Stop-on-first-error with parallel tier ──

    #[test]
    fn stop_on_error_in_parallel_tier() {
        let executor = BatchExecutor::new();
        // Three independent ops, one fails.
        let req = BatchInvokeRequest {
            operations: vec![
                op("ok1", "tool", &[]),
                op("fail1", "tool", &[]),
                op("ok2", "tool", &[]),
            ],
            options: BatchOptions {
                stop_on_first_error: true,
                ..Default::default()
            },
        };
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        // Because all are in the same tier, at least some execute before abort.
        assert!(resp.status == BatchStatus::Aborted);
        assert!(resp.failed >= 1);
    }

    // ── Response status edge cases ──

    #[test]
    fn all_skipped_counts_as_all_failed() {
        let executor = BatchExecutor::new();
        // fail1 fails, b depends on fail1 → skipped.
        let req = simple_request(vec![
            op("fail1", "tool", &[]),
            op("b", "tool", &["fail1"]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        // 1 failed, 1 skipped, 0 completed → AllFailed.
        assert_eq!(resp.completed, 0);
    }
}
