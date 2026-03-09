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
        let cloned = report.clone();
        assert_eq!(report.zones.len(), 1);
        assert_eq!(cloned.zones[0].zone_id, "z:test");
        assert_eq!(cloned.schema_version, "1.0.0");
    }

    // ── BudgetLineItem edge cases ─────────────────────────────

    #[test]
    fn budget_line_item_zero_usage() {
        let item = BudgetLineItem {
            metric: UsageMetricKind::Tokens,
            used: 0,
            limit: 1000,
            remaining: 1000,
            window_seconds: 3600,
            window_started_at: 1_700_000_000,
            window_resets_at: 1_700_003_600,
            status: BudgetStatus::Ok,
        };
        assert_eq!(item.used, 0);
        assert_eq!(item.remaining, item.limit);
    }

    #[test]
    fn budget_line_item_at_limit() {
        let item = BudgetLineItem {
            metric: UsageMetricKind::Requests,
            used: 100,
            limit: 100,
            remaining: 0,
            window_seconds: 60,
            window_started_at: 1_700_000_000,
            window_resets_at: 1_700_000_060,
            status: BudgetStatus::Ok,
        };
        assert_eq!(item.used, item.limit);
        assert_eq!(item.remaining, 0);
    }

    #[test]
    fn budget_line_item_clone() {
        let item = sample_line_item();
        let cloned = item.clone();
        assert_eq!(cloned.metric, item.metric);
        assert_eq!(cloned.used, item.used);
        assert_eq!(cloned.limit, item.limit);
        assert_eq!(cloned.remaining, item.remaining);
        assert_eq!(cloned.status, item.status);
    }

    #[test]
    fn budget_line_item_debug() {
        let item = sample_line_item();
        let dbg = format!("{item:?}");
        assert!(dbg.contains("BudgetLineItem"));
        assert!(dbg.contains("Tokens"));
    }

    #[test]
    fn budget_line_item_window_fields() {
        let item = sample_line_item();
        assert_eq!(
            item.window_resets_at - item.window_started_at,
            item.window_seconds
        );
    }

    // ── ZoneBudgetReport ──────────────────────────────────────

    #[test]
    fn zone_budget_report_empty_budgets() {
        let zone = ZoneBudgetReport {
            zone_id: "z:empty".to_string(),
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![],
            updated_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&zone).unwrap();
        let back: ZoneBudgetReport = serde_json::from_str(&json).unwrap();
        assert!(back.budgets.is_empty());
        assert_eq!(back.enforcement, BudgetEnforcement::Deny);
    }

    #[test]
    fn zone_budget_report_multiple_budgets() {
        let zone = ZoneBudgetReport {
            zone_id: "z:multi".to_string(),
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![
                BudgetLineItem {
                    metric: UsageMetricKind::Tokens,
                    used: 100,
                    limit: 200,
                    remaining: 100,
                    window_seconds: 3600,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_003_600,
                    status: BudgetStatus::Ok,
                },
                BudgetLineItem {
                    metric: UsageMetricKind::Requests,
                    used: 50,
                    limit: 100,
                    remaining: 50,
                    window_seconds: 60,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_000_060,
                    status: BudgetStatus::Ok,
                },
                BudgetLineItem {
                    metric: UsageMetricKind::Bytes,
                    used: 1_000_000,
                    limit: 5_000_000,
                    remaining: 4_000_000,
                    window_seconds: 86400,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_086_400,
                    status: BudgetStatus::Ok,
                },
            ],
            updated_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&zone).unwrap();
        let back: ZoneBudgetReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.budgets.len(), 3);
    }

    #[test]
    fn zone_budget_report_clone() {
        let zone = ZoneBudgetReport {
            zone_id: "z:clone-test".to_string(),
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![sample_line_item()],
            updated_at: 42,
        };
        let cloned = zone.clone();
        assert_eq!(cloned.zone_id, zone.zone_id);
        assert_eq!(cloned.enforcement, zone.enforcement);
        assert_eq!(cloned.budgets.len(), zone.budgets.len());
        assert_eq!(cloned.updated_at, zone.updated_at);
    }

    #[test]
    fn zone_budget_report_debug() {
        let zone = ZoneBudgetReport {
            zone_id: "z:debug".to_string(),
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![],
            updated_at: 0,
        };
        let dbg = format!("{zone:?}");
        assert!(dbg.contains("ZoneBudgetReport"));
        assert!(dbg.contains("z:debug"));
    }

    // ── BudgetReport multiple zones ───────────────────────────

    #[test]
    fn budget_report_multiple_zones() {
        let report = BudgetReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![
                ZoneBudgetReport {
                    zone_id: "z:a".to_string(),
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![sample_line_item()],
                    updated_at: 1,
                },
                ZoneBudgetReport {
                    zone_id: "z:b".to_string(),
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![],
                    updated_at: 2,
                },
            ],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: BudgetReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zones.len(), 2);
        assert_eq!(back.zones[0].zone_id, "z:a");
        assert_eq!(back.zones[1].zone_id, "z:b");
    }

    #[test]
    fn budget_report_json_pretty() {
        let report = BudgetReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![ZoneBudgetReport {
                zone_id: "z:pretty".to_string(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![sample_line_item()],
                updated_at: 100,
            }],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("z:pretty"));
        assert!(json.contains("enforcement"));
    }
}
