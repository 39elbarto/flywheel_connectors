//! Shared computation migration lifecycle and lease-transfer data model.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Phase of a long-running computation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputationPhase {
    /// Initial setup: allocating resources, loading inputs.
    Initializing,
    /// Actively processing data.
    Processing,
    /// Finalizing results: writing outputs, releasing resources.
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
    /// Load balancing or resource rebalancing.
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
    /// Progress as a percentage from 0.0 through 100.0.
    pub progress_pct: f64,
    /// Opaque checkpoint data: last known good state.
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
    /// Checkpoint ID to resume from, if known.
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
    /// Phase after resume.
    pub current_phase: ComputationPhase,
    /// Estimated data loss as a percentage, where 0.0 is none and 100.0 is total.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn computation_phase_display_matches_wire_names() {
        assert_eq!(ComputationPhase::Initializing.to_string(), "initializing");
        assert_eq!(ComputationPhase::Processing.to_string(), "processing");
        assert_eq!(ComputationPhase::Finalizing.to_string(), "finalizing");
        assert_eq!(ComputationPhase::Completed.to_string(), "completed");
        assert_eq!(ComputationPhase::Failed.to_string(), "failed");
        assert_eq!(ComputationPhase::Suspended.to_string(), "suspended");
    }

    #[test]
    fn transfer_reason_display_matches_wire_names() {
        assert_eq!(TransferReason::Rebalance.to_string(), "rebalance");
        assert_eq!(TransferReason::Failure.to_string(), "failure");
        assert_eq!(TransferReason::Drain.to_string(), "drain");
        assert_eq!(TransferReason::Manual.to_string(), "manual");
    }

    #[test]
    fn lease_transfer_serde_round_trips() {
        let transfer = LeaseTransfer {
            from_node: "node-a".to_string(),
            to_node: "node-b".to_string(),
            computation_id: "comp-1".to_string(),
            transfer_at: Utc::now(),
            reason: TransferReason::Rebalance,
        };

        let encoded = serde_json::to_string(&transfer).expect("lease transfer serializes");
        let decoded: LeaseTransfer =
            serde_json::from_str(&encoded).expect("lease transfer deserializes");

        assert_eq!(decoded.from_node, transfer.from_node);
        assert_eq!(decoded.to_node, transfer.to_node);
        assert_eq!(decoded.computation_id, transfer.computation_id);
        assert_eq!(decoded.reason, transfer.reason);
    }

    #[test]
    fn migration_plan_serde_round_trips() {
        let state = ComputationState {
            computation_id: "comp-1".to_string(),
            current_phase: ComputationPhase::Processing,
            progress_pct: 42.0,
            checkpoint_data: json!({"progress_pct": 42.0}),
            lease_holder: "node-a".to_string(),
            lease_expires: Utc::now(),
        };
        let plan = MigrationPlan {
            computations: vec![state],
            transfers: Vec::new(),
            checkpoints_required: 1,
        };

        let encoded = serde_json::to_string(&plan).expect("migration plan serializes");
        let decoded: MigrationPlan =
            serde_json::from_str(&encoded).expect("migration plan deserializes");

        assert_eq!(decoded.computations.len(), 1);
        assert_eq!(decoded.checkpoints_required, 1);
        assert_eq!(
            decoded.computations[0].current_phase,
            ComputationPhase::Processing
        );
    }
}
