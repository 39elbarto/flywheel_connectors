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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_line_item() -> BudgetLineItem {
        BudgetLineItem {
            metric: UsageMetricKind::Tokens,
            used: 500,
            limit: 1000,
            remaining: 500,
            window_seconds: 3600,
            window_started_at: 1_700_000_000,
            window_resets_at: 1_700_003_600,
            status: BudgetStatus::Ok,
        }
    }

    #[test]
    fn budget_report_schema_version() {
        assert_eq!(BudgetReport::SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn budget_report_serde_roundtrip() {
        let report = BudgetReport {
            schema_version: BudgetReport::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zones: vec![ZoneBudgetReport {
                zone_id: "z:test".to_string(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![sample_line_item()],
                updated_at: 1_700_000_000,
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: BudgetReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, "1.0.0");
        assert_eq!(back.zones.len(), 1);
        assert_eq!(back.zones[0].zone_id, "z:test");
    }

    #[test]
    fn budget_report_empty_zones() {
        let report = BudgetReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: BudgetReport = serde_json::from_str(&json).unwrap();
        assert!(back.zones.is_empty());
    }

    #[test]
    fn zone_budget_report_serde_roundtrip() {
        let zone = ZoneBudgetReport {
            zone_id: "z:private".to_string(),
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![sample_line_item()],
            updated_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&zone).unwrap();
        let back: ZoneBudgetReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_id, "z:private");
        assert_eq!(back.enforcement, BudgetEnforcement::Deny);
        assert_eq!(back.updated_at, 1_700_000_000);
    }

    #[test]
    fn budget_line_item_serde_roundtrip() {
        let item = sample_line_item();
        let json = serde_json::to_string(&item).unwrap();
        let back: BudgetLineItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metric, UsageMetricKind::Tokens);
        assert_eq!(back.used, 500);
        assert_eq!(back.limit, 1000);
        assert_eq!(back.remaining, 500);
        assert_eq!(back.status, BudgetStatus::Ok);
    }

    #[test]
    fn budget_line_item_exceeded() {
        let item = BudgetLineItem {
            metric: UsageMetricKind::Requests,
            used: 200,
            limit: 100,
            remaining: 0,
            window_seconds: 60,
            window_started_at: 1_700_000_000,
            window_resets_at: 1_700_000_060,
            status: BudgetStatus::Exceeded,
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: BudgetLineItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, BudgetStatus::Exceeded);
        assert!(back.used > back.limit);
    }

    #[test]
    fn budget_line_item_bytes_metric() {
        let item = BudgetLineItem {
            metric: UsageMetricKind::Bytes,
            used: 5_000_000,
            limit: 10_000_000,
            remaining: 5_000_000,
            window_seconds: 3600,
            window_started_at: 1_700_000_000,
            window_resets_at: 1_700_003_600,
            status: BudgetStatus::Ok,
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: BudgetLineItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metric, UsageMetricKind::Bytes);
    }

    #[test]
    fn budget_report_debug() {
        let report = BudgetReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![],
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("BudgetReport"));
    }

    #[test]
    fn budget_report_clone() {
        let report = BudgetReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![ZoneBudgetReport {
                zone_id: "z:test".to_string(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![],
                updated_at: 0,
            }],
        };
        let moved = report;
        assert_eq!(moved.zones.len(), 1);
        assert_eq!(moved.zones[0].zone_id, "z:test");
    }
}
