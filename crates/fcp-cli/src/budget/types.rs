//! Budget report output types for CLI.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use fcp_core::{BudgetEnforcement, BudgetStatus, UsageMetricKind};

/// CLI budget report wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetReport {
    /// Schema version for CLI consumers.
    pub schema_version: String,
    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,
    /// Per-zone budget snapshots.
    pub zones: Vec<ZoneBudgetReport>,
}

impl BudgetReport {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";
}

/// Budget snapshot for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneBudgetReport {
    /// Zone identifier.
    pub zone_id: String,
    /// Enforcement mode.
    pub enforcement: BudgetEnforcement,
    /// Budget entries.
    pub budgets: Vec<BudgetLineItem>,
    /// Last update timestamp (Unix seconds).
    pub updated_at: u64,
}

/// Usage vs budget line item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetLineItem {
    /// Usage metric kind.
    pub metric: UsageMetricKind,
    /// Usage observed in window.
    pub used: u64,
    /// Budget limit for window.
    pub limit: u64,
    /// Remaining budget for window.
    pub remaining: u64,
    /// Window length in seconds.
    pub window_seconds: u64,
    /// Window start timestamp (Unix seconds).
    pub window_started_at: u64,
    /// Window reset timestamp (Unix seconds).
    pub window_resets_at: u64,
    /// Status for this budget.
    pub status: BudgetStatus,
}
