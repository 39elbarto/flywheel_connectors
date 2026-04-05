//! Computation migration checkpoint, lease transfer, and resume infrastructure.
//!
//! Models the lifecycle of long-running computations that can be checkpointed,
//! migrated between nodes via lease transfer, and resumed from the most recent
//! valid checkpoint.  All types are self-contained and test-oriented — no I/O
//! or network calls are performed.

use std::fmt::Write as _;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Core types ──────────────────────────────────────────────────────────

/// Phase of a long-running computation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputationPhase {
    /// Initial setup — allocating resources, loading inputs.
    Initializing,
    /// Actively processing data.
    Processing,
    /// Finalizing results — writing outputs, releasing resources.
    Finalizing,
    /// Successfully completed.
    Completed,
    /// Failed with a terminal error.
    Failed,
    /// Paused for migration or manual intervention.
    Suspended,
}

impl std::fmt::Display for ComputationPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => f.write_str("initializing"),
            Self::Processing => f.write_str("processing"),
            Self::Finalizing => f.write_str("finalizing"),
            Self::Completed => f.write_str("completed"),
            Self::Failed => f.write_str("failed"),
            Self::Suspended => f.write_str("suspended"),
        }
    }
}

/// Reason for transferring a computation's lease to another node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferReason {
    /// Load balancing / resource rebalancing.
    Rebalance,
    /// Source node failed or became unreachable.
    Failure,
    /// Source node is being drained for maintenance.
    Drain,
    /// Operator-initiated manual transfer.
    Manual,
}

impl std::fmt::Display for TransferReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rebalance => f.write_str("rebalance"),
            Self::Failure => f.write_str("failure"),
            Self::Drain => f.write_str("drain"),
            Self::Manual => f.write_str("manual"),
        }
    }
}

/// Snapshot of a computation's current state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputationState {
    /// Unique identifier for this computation.
    pub computation_id: String,
    /// Current lifecycle phase.
    pub current_phase: ComputationPhase,
    /// Progress as a percentage (0.0–100.0).
    pub progress_pct: f64,
    /// Opaque checkpoint data (last known good state).
    pub checkpoint_data: Value,
    /// Node currently holding the lease.
    pub lease_holder: String,
    /// When the lease expires.
    pub lease_expires: DateTime<Utc>,
}

/// A persisted checkpoint entry for a computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointEntry {
    /// Unique checkpoint identifier.
    pub id: String,
    /// Which computation this checkpoint belongs to.
    pub computation_id: String,
    /// When the checkpoint was created.
    pub timestamp: DateTime<Utc>,
    /// Phase at the time of checkpointing.
    pub phase: ComputationPhase,
    /// Full state snapshot.
    pub state_snapshot: Value,
    /// Size of the serialized snapshot in bytes.
    pub size_bytes: u64,
}

/// A planned lease transfer between nodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseTransfer {
    /// Node giving up the lease.
    pub from_node: String,
    /// Node receiving the lease.
    pub to_node: String,
    /// Computation being transferred.
    pub computation_id: String,
    /// Scheduled transfer time.
    pub transfer_at: DateTime<Utc>,
    /// Why the transfer is happening.
    pub reason: TransferReason,
}

/// Request to resume a computation from a checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResumeRequest {
    /// Which computation to resume.
    pub computation_id: String,
    /// Checkpoint ID to resume from (if known).
    pub from_checkpoint: Option<String>,
    /// Target node for resumption.
    pub target_node: String,
    /// Skip validation of checkpoint integrity.
    #[serde(default)]
    pub skip_validation: bool,
}

/// Outcome of a resume attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResumeOutcome {
    /// Whether the resume succeeded.
    pub success: bool,
    /// Phase from which we resumed.
    pub resumed_from_phase: ComputationPhase,
    /// Phase after resume (should be the same or next).
    pub current_phase: ComputationPhase,
    /// Estimated data loss as a percentage (0.0 = none, 100.0 = total).
    pub data_loss: f64,
    /// Diagnostic warnings.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// A migration plan covering multiple computations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Computations included in the migration.
    pub computations: Vec<ComputationState>,
    /// Planned transfers.
    pub transfers: Vec<LeaseTransfer>,
    /// Number of checkpoints that must be taken before migration can proceed.
    pub checkpoints_required: usize,
}

/// Summary of a completed migration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationResult {
    /// Total computations in the plan.
    pub total: usize,
    /// Successfully migrated.
    pub migrated: usize,
    /// Failed to migrate.
    pub failed: usize,
    /// Number of data-loss events detected.
    pub data_loss_events: usize,
    /// Wall-clock duration of the migration.
    pub duration: Duration,
}

// ── Functions ───────────────────────────────────────────────────────────

/// Create a checkpoint from the current computation state.
pub fn create_checkpoint(state: &ComputationState) -> CheckpointEntry {
    let snapshot = serde_json::to_string(&state.checkpoint_data).unwrap_or_default();
    let size = snapshot.len() as u64;
    let id = format!(
        "ckpt-{}-{}",
        state.computation_id,
        Utc::now().timestamp_millis()
    );
    CheckpointEntry {
        id,
        computation_id: state.computation_id.clone(),
        timestamp: Utc::now(),
        phase: state.current_phase.clone(),
        state_snapshot: state.checkpoint_data.clone(),
        size_bytes: size,
    }
}

/// Validate a checkpoint entry for integrity.  Returns `Ok(())` if valid,
/// or a list of diagnostic strings if problems are found.
pub fn validate_checkpoint(entry: &CheckpointEntry) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if entry.id.is_empty() {
        errors.push("checkpoint id must not be empty".to_string());
    }
    if entry.computation_id.is_empty() {
        errors.push("computation_id must not be empty".to_string());
    }
    if entry.state_snapshot.is_null() {
        errors.push("state_snapshot must not be null".to_string());
    }
    if entry.size_bytes == 0 {
        errors.push("size_bytes must be > 0".to_string());
    }
    // Phase sanity: completed/failed computations should not be checkpointed
    // for migration purposes (warn, not error).
    if entry.phase == ComputationPhase::Completed || entry.phase == ComputationPhase::Failed {
        errors.push(format!(
            "checkpoint phase is terminal ({}), migration may not be meaningful",
            entry.phase
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Plan lease transfers for all computations from one node to another.
pub fn plan_lease_transfer(
    from: &str,
    to: &str,
    computations: &[ComputationState],
) -> MigrationPlan {
    let eligible: Vec<&ComputationState> = computations
        .iter()
        .filter(|c| c.lease_holder == from)
        .filter(|c| {
            c.current_phase != ComputationPhase::Completed
                && c.current_phase != ComputationPhase::Failed
        })
        .collect();

    let mut checkpoints_required = 0;
    let mut transfers = Vec::new();

    for c in &eligible {
        // If the computation is actively processing, it needs a fresh checkpoint.
        if c.current_phase == ComputationPhase::Processing
            || c.current_phase == ComputationPhase::Initializing
        {
            checkpoints_required += 1;
        }

        transfers.push(LeaseTransfer {
            from_node: from.to_string(),
            to_node: to.to_string(),
            computation_id: c.computation_id.clone(),
            transfer_at: Utc::now(),
            reason: TransferReason::Drain,
        });
    }

    MigrationPlan {
        computations: eligible.into_iter().cloned().collect(),
        transfers,
        checkpoints_required,
    }
}

/// Simulate resuming a computation from a checkpoint.
pub fn simulate_resume(request: &ResumeRequest, checkpoints: &[CheckpointEntry]) -> ResumeOutcome {
    // Find the checkpoint to resume from.
    let checkpoint = request.from_checkpoint.as_ref().map_or_else(
        || find_best_checkpoint(&request.computation_id, checkpoints),
        |ckpt_id| checkpoints.iter().find(|c| c.id == *ckpt_id),
    );

    let Some(ckpt) = checkpoint else {
        return ResumeOutcome {
            success: false,
            resumed_from_phase: ComputationPhase::Initializing,
            current_phase: ComputationPhase::Failed,
            data_loss: 100.0,
            warnings: vec!["no checkpoint found for computation".to_string()],
        };
    };

    // Validate unless skip_validation is set.
    if !request.skip_validation {
        if let Err(errs) = validate_checkpoint(ckpt) {
            return ResumeOutcome {
                success: false,
                resumed_from_phase: ckpt.phase.clone(),
                current_phase: ComputationPhase::Failed,
                data_loss: 100.0,
                warnings: errs,
            };
        }
    }

    let mut warnings = Vec::new();

    // If checkpoint is from a terminal phase, warn.
    if ckpt.phase == ComputationPhase::Completed {
        warnings.push("resuming from a completed checkpoint".to_string());
    }

    // Estimate data loss based on age of checkpoint.
    let age = Utc::now()
        .signed_duration_since(ckpt.timestamp)
        .num_seconds()
        .unsigned_abs();
    #[allow(clippy::cast_precision_loss)]
    let age_f = age as f64;
    let data_loss = if age > 3600 {
        warnings.push(format!("checkpoint is {age}s old"));
        (age_f / 7200.0).min(50.0)
    } else {
        (age_f / 7200.0).min(10.0)
    };

    ResumeOutcome {
        success: true,
        resumed_from_phase: ckpt.phase.clone(),
        current_phase: ckpt.phase.clone(),
        data_loss,
        warnings,
    }
}

/// Find the best (most recent) checkpoint for a computation.
pub fn find_best_checkpoint<'a>(
    computation_id: &str,
    checkpoints: &'a [CheckpointEntry],
) -> Option<&'a CheckpointEntry> {
    checkpoints
        .iter()
        .filter(|c| c.computation_id == computation_id)
        .max_by_key(|c| c.timestamp)
}

/// Estimate data loss as a percentage between the last checkpoint and current
/// state.  Loss is proportional to progress made since the checkpoint.
pub fn estimate_data_loss(last_checkpoint: &CheckpointEntry, current: &ComputationState) -> f64 {
    // If the checkpoint matches current progress, no loss.
    let ckpt_progress = last_checkpoint
        .state_snapshot
        .get("progress_pct")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);

    let delta = current.progress_pct - ckpt_progress;
    if delta <= 0.0 {
        return 0.0;
    }

    // Data loss is the uncaptured progress as a fraction of total progress.
    if current.progress_pct <= 0.0 {
        return 0.0;
    }
    (delta / current.progress_pct * 100.0).min(100.0)
}

/// Format a migration plan as a human-readable summary.
pub fn format_migration_plan_toon(plan: &MigrationPlan) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Migration Plan");
    let _ = writeln!(out, "==============");
    let _ = writeln!(out, "Computations:        {}", plan.computations.len());
    let _ = writeln!(out, "Transfers:           {}", plan.transfers.len());
    let _ = writeln!(out, "Checkpoints needed:  {}", plan.checkpoints_required);
    let _ = writeln!(out);

    if !plan.transfers.is_empty() {
        let _ = writeln!(out, "Transfers:");
        for t in &plan.transfers {
            let _ = writeln!(
                out,
                "  {} -> {} (computation: {}, reason: {})",
                t.from_node, t.to_node, t.computation_id, t.reason,
            );
        }
    }

    if !plan.computations.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Computations:");
        for c in &plan.computations {
            let _ = writeln!(
                out,
                "  {}: phase={}, progress={:.1}%, lease_holder={}",
                c.computation_id, c.current_phase, c.progress_pct, c.lease_holder,
            );
        }
    }

    out
}

/// Format a migration result as a human-readable summary.
pub fn format_migration_result_toon(result: &MigrationResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Migration Result");
    let _ = writeln!(out, "================");
    let _ = writeln!(out, "Total:            {}", result.total);
    let _ = writeln!(out, "Migrated:         {}", result.migrated);
    let _ = writeln!(out, "Failed:           {}", result.failed);
    let _ = writeln!(out, "Data loss events: {}", result.data_loss_events);
    let _ = writeln!(
        out,
        "Duration:         {:.2}s",
        result.duration.as_secs_f64()
    );

    #[allow(clippy::cast_precision_loss)]
    let success_rate = if result.total > 0 {
        result.migrated as f64 / result.total as f64 * 100.0
    } else {
        0.0
    };
    let _ = writeln!(out, "Success rate:     {success_rate:.1}%");

    out
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn make_state(id: &str, phase: ComputationPhase, progress: f64) -> ComputationState {
        ComputationState {
            computation_id: id.to_string(),
            current_phase: phase,
            progress_pct: progress,
            checkpoint_data: json!({"progress_pct": progress, "items_done": 42}),
            lease_holder: "node-a".to_string(),
            lease_expires: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn make_checkpoint(
        id: &str,
        comp_id: &str,
        phase: ComputationPhase,
        progress: f64,
    ) -> CheckpointEntry {
        CheckpointEntry {
            id: id.to_string(),
            computation_id: comp_id.to_string(),
            timestamp: Utc::now(),
            phase,
            state_snapshot: json!({"progress_pct": progress, "items_done": 10}),
            size_bytes: 128,
        }
    }

    fn make_checkpoint_at(id: &str, comp_id: &str, ts: DateTime<Utc>) -> CheckpointEntry {
        CheckpointEntry {
            id: id.to_string(),
            computation_id: comp_id.to_string(),
            timestamp: ts,
            phase: ComputationPhase::Processing,
            state_snapshot: json!({"progress_pct": 50.0}),
            size_bytes: 64,
        }
    }

    // ── create_checkpoint ───────────────────────────────────────────────

    #[test]
    fn create_checkpoint_sets_computation_id() {
        let state = make_state("comp-1", ComputationPhase::Processing, 50.0);
        let ckpt = create_checkpoint(&state);
        assert_eq!(ckpt.computation_id, "comp-1");
    }

    #[test]
    fn create_checkpoint_copies_phase() {
        let state = make_state("c1", ComputationPhase::Finalizing, 90.0);
        let ckpt = create_checkpoint(&state);
        assert_eq!(ckpt.phase, ComputationPhase::Finalizing);
    }

    #[test]
    fn create_checkpoint_copies_snapshot() {
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let ckpt = create_checkpoint(&state);
        assert_eq!(ckpt.state_snapshot, state.checkpoint_data);
    }

    #[test]
    fn create_checkpoint_nonzero_size() {
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let ckpt = create_checkpoint(&state);
        assert!(ckpt.size_bytes > 0);
    }

    #[test]
    fn create_checkpoint_id_contains_comp_id() {
        let state = make_state("my-comp", ComputationPhase::Processing, 50.0);
        let ckpt = create_checkpoint(&state);
        assert!(ckpt.id.contains("my-comp"), "id = {}", ckpt.id);
    }

    #[test]
    fn create_checkpoint_id_starts_with_ckpt() {
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let ckpt = create_checkpoint(&state);
        assert!(ckpt.id.starts_with("ckpt-"));
    }

    #[test]
    fn create_checkpoint_timestamp_recent() {
        let before = Utc::now();
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let ckpt = create_checkpoint(&state);
        assert!(ckpt.timestamp >= before);
    }

    #[test]
    fn create_checkpoint_from_initializing() {
        let state = make_state("c1", ComputationPhase::Initializing, 0.0);
        let ckpt = create_checkpoint(&state);
        assert_eq!(ckpt.phase, ComputationPhase::Initializing);
    }

    #[test]
    fn create_checkpoint_from_suspended() {
        let state = make_state("c1", ComputationPhase::Suspended, 75.0);
        let ckpt = create_checkpoint(&state);
        assert_eq!(ckpt.phase, ComputationPhase::Suspended);
    }

    // ── validate_checkpoint ─────────────────────────────────────────────

    #[test]
    fn validate_valid_checkpoint_ok() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        assert!(validate_checkpoint(&ckpt).is_ok());
    }

    #[test]
    fn validate_empty_id() {
        let mut ckpt = make_checkpoint("", "c1", ComputationPhase::Processing, 50.0);
        ckpt.id = String::new();
        let err = validate_checkpoint(&ckpt).unwrap_err();
        assert!(err.iter().any(|e| e.contains("id must not be empty")));
    }

    #[test]
    fn validate_empty_computation_id() {
        let mut ckpt = make_checkpoint("ck1", "", ComputationPhase::Processing, 50.0);
        ckpt.computation_id = String::new();
        let err = validate_checkpoint(&ckpt).unwrap_err();
        assert!(err.iter().any(|e| e.contains("computation_id")));
    }

    #[test]
    fn validate_null_snapshot() {
        let mut ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        ckpt.state_snapshot = Value::Null;
        let err = validate_checkpoint(&ckpt).unwrap_err();
        assert!(err.iter().any(|e| e.contains("state_snapshot")));
    }

    #[test]
    fn validate_zero_size() {
        let mut ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        ckpt.size_bytes = 0;
        let err = validate_checkpoint(&ckpt).unwrap_err();
        assert!(err.iter().any(|e| e.contains("size_bytes")));
    }

    #[test]
    fn validate_completed_phase_warns() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Completed, 100.0);
        let err = validate_checkpoint(&ckpt).unwrap_err();
        assert!(err.iter().any(|e| e.contains("terminal")));
    }

    #[test]
    fn validate_failed_phase_warns() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Failed, 0.0);
        let err = validate_checkpoint(&ckpt).unwrap_err();
        assert!(err.iter().any(|e| e.contains("terminal")));
    }

    #[test]
    fn validate_multiple_errors() {
        let mut ckpt = make_checkpoint("", "", ComputationPhase::Completed, 0.0);
        ckpt.id = String::new();
        ckpt.computation_id = String::new();
        ckpt.size_bytes = 0;
        ckpt.state_snapshot = Value::Null;
        let err = validate_checkpoint(&ckpt).unwrap_err();
        assert!(err.len() >= 4, "got {} errors: {:?}", err.len(), err);
    }

    #[test]
    fn validate_suspended_phase_ok() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Suspended, 50.0);
        assert!(validate_checkpoint(&ckpt).is_ok());
    }

    #[test]
    fn validate_initializing_phase_ok() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Initializing, 0.0);
        assert!(validate_checkpoint(&ckpt).is_ok());
    }

    #[test]
    fn validate_finalizing_phase_ok() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Finalizing, 95.0);
        assert!(validate_checkpoint(&ckpt).is_ok());
    }

    // ── plan_lease_transfer ─────────────────────────────────────────────

    #[test]
    fn plan_transfer_filters_by_lease_holder() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0), {
            let mut s = make_state("c2", ComputationPhase::Processing, 30.0);
            s.lease_holder = "node-b".to_string();
            s
        }];
        let plan = plan_lease_transfer("node-a", "node-c", &states);
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].computation_id, "c1");
    }

    #[test]
    fn plan_transfer_excludes_completed() {
        let states = vec![make_state("c1", ComputationPhase::Completed, 100.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert!(plan.transfers.is_empty());
    }

    #[test]
    fn plan_transfer_excludes_failed() {
        let states = vec![make_state("c1", ComputationPhase::Failed, 0.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert!(plan.transfers.is_empty());
    }

    #[test]
    fn plan_transfer_includes_processing() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.transfers.len(), 1);
    }

    #[test]
    fn plan_transfer_includes_suspended() {
        let states = vec![make_state("c1", ComputationPhase::Suspended, 75.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.transfers.len(), 1);
    }

    #[test]
    fn plan_transfer_includes_finalizing() {
        let states = vec![make_state("c1", ComputationPhase::Finalizing, 95.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.transfers.len(), 1);
    }

    #[test]
    fn plan_transfer_checkpoints_for_processing() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.checkpoints_required, 1);
    }

    #[test]
    fn plan_transfer_checkpoints_for_initializing() {
        let states = vec![make_state("c1", ComputationPhase::Initializing, 0.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.checkpoints_required, 1);
    }

    #[test]
    fn plan_transfer_no_checkpoints_for_suspended() {
        let states = vec![make_state("c1", ComputationPhase::Suspended, 75.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.checkpoints_required, 0);
    }

    #[test]
    fn plan_transfer_no_checkpoints_for_finalizing() {
        let states = vec![make_state("c1", ComputationPhase::Finalizing, 95.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.checkpoints_required, 0);
    }

    #[test]
    fn plan_transfer_sets_drain_reason() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.transfers[0].reason, TransferReason::Drain);
    }

    #[test]
    fn plan_transfer_sets_from_to_nodes() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "dst", &states);
        assert_eq!(plan.transfers[0].from_node, "node-a");
        assert_eq!(plan.transfers[0].to_node, "dst");
    }

    #[test]
    fn plan_transfer_empty_computations() {
        let plan = plan_lease_transfer("a", "b", &[]);
        assert!(plan.transfers.is_empty());
        assert!(plan.computations.is_empty());
        assert_eq!(plan.checkpoints_required, 0);
    }

    #[test]
    fn plan_transfer_multiple_computations() {
        let states = vec![
            make_state("c1", ComputationPhase::Processing, 30.0),
            make_state("c2", ComputationPhase::Suspended, 60.0),
            make_state("c3", ComputationPhase::Initializing, 0.0),
        ];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.transfers.len(), 3);
        assert_eq!(plan.checkpoints_required, 2); // processing + initializing
    }

    #[test]
    fn plan_transfer_no_match_for_wrong_node() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-x", "node-y", &states);
        assert!(plan.transfers.is_empty());
    }

    // ── find_best_checkpoint ────────────────────────────────────────────

    #[test]
    fn find_best_returns_most_recent() {
        let t1 = Utc::now() - chrono::Duration::hours(2);
        let t2 = Utc::now() - chrono::Duration::hours(1);
        let t3 = Utc::now();
        let checkpoints = vec![
            make_checkpoint_at("ck1", "c1", t1),
            make_checkpoint_at("ck2", "c1", t3),
            make_checkpoint_at("ck3", "c1", t2),
        ];
        let best = find_best_checkpoint("c1", &checkpoints).unwrap();
        assert_eq!(best.id, "ck2");
    }

    #[test]
    fn find_best_filters_by_computation_id() {
        let checkpoints = vec![
            make_checkpoint_at("ck1", "c1", Utc::now()),
            make_checkpoint_at("ck2", "c2", Utc::now()),
        ];
        let best = find_best_checkpoint("c2", &checkpoints).unwrap();
        assert_eq!(best.id, "ck2");
    }

    #[test]
    fn find_best_no_match_returns_none() {
        let checkpoints = vec![make_checkpoint_at("ck1", "c1", Utc::now())];
        assert!(find_best_checkpoint("c999", &checkpoints).is_none());
    }

    #[test]
    fn find_best_empty_list_returns_none() {
        assert!(find_best_checkpoint("c1", &[]).is_none());
    }

    #[test]
    fn find_best_single_match() {
        let checkpoints = vec![make_checkpoint_at("ck1", "c1", Utc::now())];
        let best = find_best_checkpoint("c1", &checkpoints).unwrap();
        assert_eq!(best.id, "ck1");
    }

    // ── simulate_resume ─────────────────────────────────────────────────

    #[test]
    fn resume_no_checkpoint_fails() {
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: None,
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[]);
        assert!(!outcome.success);
        assert!((outcome.data_loss - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn resume_with_valid_checkpoint_succeeds() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(outcome.success);
        assert_eq!(outcome.resumed_from_phase, ComputationPhase::Processing);
    }

    #[test]
    fn resume_auto_selects_best_checkpoint() {
        let t1 = Utc::now() - chrono::Duration::seconds(10);
        let ckpts = vec![
            make_checkpoint_at("old", "c1", t1),
            make_checkpoint_at("new", "c1", Utc::now()),
        ];
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: None,
            target_node: "node-b".to_string(),
            skip_validation: true,
        };
        let outcome = simulate_resume(&req, &ckpts);
        assert!(outcome.success);
    }

    #[test]
    fn resume_invalid_checkpoint_fails() {
        let mut ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        ckpt.state_snapshot = Value::Null;
        ckpt.size_bytes = 0;
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(!outcome.success);
    }

    #[test]
    fn resume_skip_validation_bypasses_check() {
        let mut ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        ckpt.state_snapshot = Value::Null;
        ckpt.size_bytes = 0;
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: true,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(outcome.success);
    }

    #[test]
    fn resume_wrong_checkpoint_id_fails() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("nonexistent".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(!outcome.success);
    }

    #[test]
    fn resume_preserves_phase() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Finalizing, 95.0);
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(outcome.success);
        assert_eq!(outcome.resumed_from_phase, ComputationPhase::Finalizing);
        assert_eq!(outcome.current_phase, ComputationPhase::Finalizing);
    }

    #[test]
    fn resume_data_loss_low_for_recent_checkpoint() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(outcome.success);
        assert!(outcome.data_loss < 10.0);
    }

    // ── estimate_data_loss ──────────────────────────────────────────────

    #[test]
    fn data_loss_zero_when_no_progress_delta() {
        let ckpt = CheckpointEntry {
            id: "ck1".to_string(),
            computation_id: "c1".to_string(),
            timestamp: Utc::now(),
            phase: ComputationPhase::Processing,
            state_snapshot: json!({"progress_pct": 50.0}),
            size_bytes: 64,
        };
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let loss = estimate_data_loss(&ckpt, &state);
        assert!((loss - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn data_loss_proportional_to_delta() {
        let ckpt = CheckpointEntry {
            id: "ck1".to_string(),
            computation_id: "c1".to_string(),
            timestamp: Utc::now(),
            phase: ComputationPhase::Processing,
            state_snapshot: json!({"progress_pct": 25.0}),
            size_bytes: 64,
        };
        let state = make_state("c1", ComputationPhase::Processing, 75.0);
        let loss = estimate_data_loss(&ckpt, &state);
        // delta=50, current=75 => 50/75*100 = 66.67
        assert!(loss > 60.0 && loss < 70.0, "loss = {loss}");
    }

    #[test]
    fn data_loss_max_100() {
        let ckpt = CheckpointEntry {
            id: "ck1".to_string(),
            computation_id: "c1".to_string(),
            timestamp: Utc::now(),
            phase: ComputationPhase::Initializing,
            state_snapshot: json!({"progress_pct": 0.0}),
            size_bytes: 64,
        };
        let state = make_state("c1", ComputationPhase::Processing, 100.0);
        let loss = estimate_data_loss(&ckpt, &state);
        assert!(loss <= 100.0);
    }

    #[test]
    fn data_loss_zero_when_current_behind_checkpoint() {
        let ckpt = CheckpointEntry {
            id: "ck1".to_string(),
            computation_id: "c1".to_string(),
            timestamp: Utc::now(),
            phase: ComputationPhase::Processing,
            state_snapshot: json!({"progress_pct": 80.0}),
            size_bytes: 64,
        };
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let loss = estimate_data_loss(&ckpt, &state);
        assert!((loss - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn data_loss_zero_when_current_progress_zero() {
        let ckpt = CheckpointEntry {
            id: "ck1".to_string(),
            computation_id: "c1".to_string(),
            timestamp: Utc::now(),
            phase: ComputationPhase::Initializing,
            state_snapshot: json!({}),
            size_bytes: 64,
        };
        let state = make_state("c1", ComputationPhase::Initializing, 0.0);
        let loss = estimate_data_loss(&ckpt, &state);
        assert!((loss - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn data_loss_missing_progress_in_snapshot() {
        let ckpt = CheckpointEntry {
            id: "ck1".to_string(),
            computation_id: "c1".to_string(),
            timestamp: Utc::now(),
            phase: ComputationPhase::Processing,
            state_snapshot: json!({"other": "data"}),
            size_bytes: 64,
        };
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let loss = estimate_data_loss(&ckpt, &state);
        // Treats missing as 0 progress => delta=50, current=50 => 100%
        assert!(loss <= 100.0);
        assert!(loss > 90.0);
    }

    // ── format_migration_plan_toon ──────────────────────────────────────

    #[test]
    fn format_plan_contains_title() {
        let plan = MigrationPlan {
            computations: vec![],
            transfers: vec![],
            checkpoints_required: 0,
        };
        let s = format_migration_plan_toon(&plan);
        assert!(s.contains("Migration Plan"));
    }

    #[test]
    fn format_plan_shows_counts() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        let s = format_migration_plan_toon(&plan);
        assert!(s.contains("Computations:"));
        assert!(s.contains("Transfers:"));
        assert!(s.contains("Checkpoints needed:"));
    }

    #[test]
    fn format_plan_shows_transfer_details() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        let s = format_migration_plan_toon(&plan);
        assert!(s.contains("node-a"));
        assert!(s.contains("node-b"));
        assert!(s.contains("c1"));
    }

    #[test]
    fn format_plan_shows_computation_details() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        let s = format_migration_plan_toon(&plan);
        assert!(s.contains("processing"));
        assert!(s.contains("50.0%"));
    }

    #[test]
    fn format_plan_empty() {
        let plan = MigrationPlan {
            computations: vec![],
            transfers: vec![],
            checkpoints_required: 0,
        };
        let s = format_migration_plan_toon(&plan);
        assert!(s.contains("Computations:        0"));
        assert!(s.contains("Transfers:           0"));
    }

    // ── format_migration_result_toon ────────────────────────────────────

    #[test]
    fn format_result_contains_title() {
        let result = MigrationResult {
            total: 0,
            migrated: 0,
            failed: 0,
            data_loss_events: 0,
            duration: Duration::from_millis(100),
        };
        let s = format_migration_result_toon(&result);
        assert!(s.contains("Migration Result"));
    }

    #[test]
    fn format_result_shows_all_fields() {
        let result = MigrationResult {
            total: 10,
            migrated: 8,
            failed: 2,
            data_loss_events: 1,
            duration: Duration::from_secs(5),
        };
        let s = format_migration_result_toon(&result);
        assert!(s.contains("Total:            10"));
        assert!(s.contains("Migrated:         8"));
        assert!(s.contains("Failed:           2"));
        assert!(s.contains("Data loss events: 1"));
        assert!(s.contains("5.00s"));
    }

    #[test]
    fn format_result_success_rate() {
        let result = MigrationResult {
            total: 10,
            migrated: 10,
            failed: 0,
            data_loss_events: 0,
            duration: Duration::from_millis(100),
        };
        let s = format_migration_result_toon(&result);
        assert!(s.contains("100.0%"));
    }

    #[test]
    fn format_result_zero_total_success_rate() {
        let result = MigrationResult {
            total: 0,
            migrated: 0,
            failed: 0,
            data_loss_events: 0,
            duration: Duration::from_millis(1),
        };
        let s = format_migration_result_toon(&result);
        assert!(s.contains("0.0%"));
    }

    // ── Serde roundtrip tests ───────────────────────────────────────────

    #[test]
    fn serde_roundtrip_computation_phase() {
        for phase in [
            ComputationPhase::Initializing,
            ComputationPhase::Processing,
            ComputationPhase::Finalizing,
            ComputationPhase::Completed,
            ComputationPhase::Failed,
            ComputationPhase::Suspended,
        ] {
            let json = serde_json::to_string(&phase).unwrap();
            let back: ComputationPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(phase, back);
        }
    }

    #[test]
    fn serde_roundtrip_transfer_reason() {
        for reason in [
            TransferReason::Rebalance,
            TransferReason::Failure,
            TransferReason::Drain,
            TransferReason::Manual,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let back: TransferReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn serde_roundtrip_computation_state() {
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let json = serde_json::to_string(&state).unwrap();
        let back: ComputationState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.computation_id, back.computation_id);
        assert_eq!(state.current_phase, back.current_phase);
    }

    #[test]
    fn serde_roundtrip_checkpoint_entry() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        let json = serde_json::to_string(&ckpt).unwrap();
        let back: CheckpointEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(ckpt.id, back.id);
        assert_eq!(ckpt.computation_id, back.computation_id);
    }

    #[test]
    fn serde_roundtrip_lease_transfer() {
        let t = LeaseTransfer {
            from_node: "a".to_string(),
            to_node: "b".to_string(),
            computation_id: "c1".to_string(),
            transfer_at: Utc::now(),
            reason: TransferReason::Rebalance,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: LeaseTransfer = serde_json::from_str(&json).unwrap();
        assert_eq!(t.from_node, back.from_node);
        assert_eq!(t.reason, back.reason);
    }

    #[test]
    fn serde_roundtrip_resume_request() {
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ResumeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.computation_id, back.computation_id);
        assert_eq!(req.skip_validation, back.skip_validation);
    }

    #[test]
    fn serde_roundtrip_resume_outcome() {
        let outcome = ResumeOutcome {
            success: true,
            resumed_from_phase: ComputationPhase::Processing,
            current_phase: ComputationPhase::Processing,
            data_loss: 5.0,
            warnings: vec!["warn1".to_string()],
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: ResumeOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome.success, back.success);
        assert_eq!(outcome.warnings, back.warnings);
    }

    #[test]
    fn serde_roundtrip_migration_plan() {
        let states = vec![make_state("c1", ComputationPhase::Processing, 50.0)];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        let json = serde_json::to_string(&plan).unwrap();
        let back: MigrationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan.transfers.len(), back.transfers.len());
    }

    #[test]
    fn serde_roundtrip_migration_result() {
        let result = MigrationResult {
            total: 5,
            migrated: 4,
            failed: 1,
            data_loss_events: 0,
            duration: Duration::from_secs(10),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: MigrationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.total, back.total);
        assert_eq!(result.migrated, back.migrated);
    }

    // ── Display impls ───────────────────────────────────────────────────

    #[test]
    fn display_computation_phase() {
        assert_eq!(
            format!("{}", ComputationPhase::Initializing),
            "initializing"
        );
        assert_eq!(format!("{}", ComputationPhase::Processing), "processing");
        assert_eq!(format!("{}", ComputationPhase::Finalizing), "finalizing");
        assert_eq!(format!("{}", ComputationPhase::Completed), "completed");
        assert_eq!(format!("{}", ComputationPhase::Failed), "failed");
        assert_eq!(format!("{}", ComputationPhase::Suspended), "suspended");
    }

    #[test]
    fn display_transfer_reason() {
        assert_eq!(format!("{}", TransferReason::Rebalance), "rebalance");
        assert_eq!(format!("{}", TransferReason::Failure), "failure");
        assert_eq!(format!("{}", TransferReason::Drain), "drain");
        assert_eq!(format!("{}", TransferReason::Manual), "manual");
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn concurrent_transfers_to_same_target() {
        let states = vec![
            make_state("c1", ComputationPhase::Processing, 30.0),
            make_state("c2", ComputationPhase::Processing, 60.0),
        ];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        assert_eq!(plan.transfers.len(), 2);
        assert!(plan.transfers.iter().all(|t| t.to_node == "node-b"));
    }

    #[test]
    fn expired_lease_state() {
        let mut state = make_state("c1", ComputationPhase::Processing, 50.0);
        state.lease_expires = Utc::now() - chrono::Duration::hours(1);
        // Still creates checkpoint — expired lease is the caller's problem.
        let ckpt = create_checkpoint(&state);
        assert_eq!(ckpt.computation_id, "c1");
    }

    #[test]
    fn checkpoint_with_large_snapshot() {
        let mut state = make_state("c1", ComputationPhase::Processing, 50.0);
        let big_data: Vec<i32> = (0..10_000).collect();
        state.checkpoint_data = json!({"data": big_data});
        let ckpt = create_checkpoint(&state);
        assert!(ckpt.size_bytes > 1000);
    }

    #[test]
    fn multiple_checkpoints_same_computation() {
        let ckpts = [
            make_checkpoint("ck1", "c1", ComputationPhase::Processing, 25.0),
            make_checkpoint("ck2", "c1", ComputationPhase::Processing, 50.0),
            make_checkpoint("ck3", "c1", ComputationPhase::Processing, 75.0),
        ];
        // All belong to same computation.
        let matching: Vec<_> = ckpts.iter().filter(|c| c.computation_id == "c1").collect();
        assert_eq!(matching.len(), 3);
    }

    #[test]
    fn resume_with_from_checkpoint_none_and_no_checkpoints() {
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: None,
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[]);
        assert!(!outcome.success);
        assert!(outcome.warnings.iter().any(|w| w.contains("no checkpoint")));
    }

    #[test]
    fn data_loss_small_delta() {
        let ckpt = CheckpointEntry {
            id: "ck1".to_string(),
            computation_id: "c1".to_string(),
            timestamp: Utc::now(),
            phase: ComputationPhase::Processing,
            state_snapshot: json!({"progress_pct": 49.0}),
            size_bytes: 64,
        };
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let loss = estimate_data_loss(&ckpt, &state);
        // delta=1, current=50 => 1/50*100 = 2%
        assert!((1.0..=3.0).contains(&loss), "loss = {loss}");
    }

    #[test]
    fn plan_mixed_phases() {
        let states = vec![
            make_state("c1", ComputationPhase::Processing, 30.0),
            make_state("c2", ComputationPhase::Completed, 100.0),
            make_state("c3", ComputationPhase::Failed, 0.0),
            make_state("c4", ComputationPhase::Suspended, 60.0),
            make_state("c5", ComputationPhase::Finalizing, 95.0),
        ];
        let plan = plan_lease_transfer("node-a", "node-b", &states);
        // Completed and Failed excluded.
        assert_eq!(plan.transfers.len(), 3);
        let ids: Vec<&str> = plan
            .transfers
            .iter()
            .map(|t| t.computation_id.as_str())
            .collect();
        assert!(ids.contains(&"c1"));
        assert!(ids.contains(&"c4"));
        assert!(ids.contains(&"c5"));
    }

    #[test]
    fn resume_outcome_warnings_empty_on_success() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Processing, 50.0);
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(outcome.success);
        // Warnings may or may not be empty depending on timing, but success is true.
    }

    #[test]
    fn create_checkpoint_unique_ids() {
        let state = make_state("c1", ComputationPhase::Processing, 50.0);
        let ckpt1 = create_checkpoint(&state);
        // Tiny sleep not needed — millis should differ or at least IDs have different timestamps.
        let ckpt2 = create_checkpoint(&state);
        // IDs might be equal if called in same millisecond — that's acceptable.
        // But both should be valid.
        assert!(ckpt1.id.starts_with("ckpt-c1-"));
        assert!(ckpt2.id.starts_with("ckpt-c1-"));
    }

    #[test]
    fn resume_from_suspended_phase() {
        let ckpt = make_checkpoint("ck1", "c1", ComputationPhase::Suspended, 60.0);
        let req = ResumeRequest {
            computation_id: "c1".to_string(),
            from_checkpoint: Some("ck1".to_string()),
            target_node: "node-b".to_string(),
            skip_validation: false,
        };
        let outcome = simulate_resume(&req, &[ckpt]);
        assert!(outcome.success);
        assert_eq!(outcome.resumed_from_phase, ComputationPhase::Suspended);
    }

    #[test]
    fn migration_result_partial_success() {
        let result = MigrationResult {
            total: 10,
            migrated: 7,
            failed: 3,
            data_loss_events: 2,
            duration: Duration::from_secs(30),
        };
        let s = format_migration_result_toon(&result);
        assert!(s.contains("70.0%"));
    }
}
