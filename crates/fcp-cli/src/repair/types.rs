//! Repair report types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for coverage/repair reports,
//! enabling automation and operator tooling integration.

// Allow public API items that aren't used yet within this crate
#![allow(dead_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::trivially_copy_pass_by_ref)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete repair status report for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Zone being analyzed.
    pub zone_id: String,

    /// Overall coverage status.
    pub overall_status: CoverageStatus,

    /// Coverage metrics.
    pub coverage: CoverageMetrics,

    /// Placement policy summary.
    pub placement: PlacementSummary,

    /// Pending repair actions.
    pub pending_repairs: Vec<RepairAction>,

    /// Last repair cycle summary.
    pub last_repair_cycle: Option<RepairCycleSummary>,
}

impl RepairReport {
    /// Schema version constant.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";

    /// Create a new repair report builder.
    #[must_use]
    pub fn builder(zone_id: impl Into<String>) -> RepairReportBuilder {
        RepairReportBuilder::new(zone_id)
    }
}

/// Builder for RepairReport.
pub struct RepairReportBuilder {
    zone_id: String,
    coverage: Option<CoverageMetrics>,
    placement: Option<PlacementSummary>,
    pending_repairs: Vec<RepairAction>,
    last_repair_cycle: Option<RepairCycleSummary>,
}

impl RepairReportBuilder {
    fn new(zone_id: impl Into<String>) -> Self {
        Self {
            zone_id: zone_id.into(),
            coverage: None,
            placement: None,
            pending_repairs: Vec::new(),
            last_repair_cycle: None,
        }
    }

    #[must_use]
    pub fn coverage(mut self, metrics: CoverageMetrics) -> Self {
        self.coverage = Some(metrics);
        self
    }

    #[must_use]
    pub fn placement(mut self, summary: PlacementSummary) -> Self {
        self.placement = Some(summary);
        self
    }

    #[must_use]
    pub fn add_pending_repair(mut self, action: RepairAction) -> Self {
        self.pending_repairs.push(action);
        self
    }

    #[must_use]
    pub fn last_repair_cycle(mut self, summary: RepairCycleSummary) -> Self {
        self.last_repair_cycle = Some(summary);
        self
    }

    #[must_use]
    pub fn build(self) -> RepairReport {
        let coverage = self.coverage.unwrap_or_default();
        let placement = self.placement.unwrap_or_default();

        let overall_status = compute_coverage_status(&coverage);

        RepairReport {
            schema_version: RepairReport::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zone_id: self.zone_id,
            overall_status,
            coverage,
            placement,
            pending_repairs: self.pending_repairs,
            last_repair_cycle: self.last_repair_cycle,
        }
    }
}

fn compute_coverage_status(coverage: &CoverageMetrics) -> CoverageStatus {
    if !coverage.is_available {
        return CoverageStatus::Unavailable;
    }
    if coverage.coverage_bps < 5000 {
        return CoverageStatus::Critical;
    }
    if coverage.coverage_bps < 8000 {
        return CoverageStatus::Degraded;
    }
    CoverageStatus::Healthy
}

/// Overall coverage status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CoverageStatus {
    /// Full coverage, all SLOs met.
    Healthy,
    /// Reduced coverage, SLOs at risk.
    Degraded,
    /// Critical coverage, SLOs breached.
    Critical,
    /// Zone is unavailable (cannot reconstruct).
    Unavailable,
}

impl CoverageStatus {
    /// Get ANSI color code for terminal output.
    #[must_use]
    pub const fn ansi_color(&self) -> &'static str {
        match self {
            Self::Healthy => "\x1b[32m",     // Green
            Self::Degraded => "\x1b[33m",    // Yellow
            Self::Critical => "\x1b[31m",    // Red
            Self::Unavailable => "\x1b[35m", // Magenta
        }
    }

    /// Get symbol for terminal output.
    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Healthy => "✓",
            Self::Degraded => "⚠",
            Self::Critical => "✗",
            Self::Unavailable => "☠",
        }
    }
}

/// Coverage metrics for offline availability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageMetrics {
    /// Number of distinct nodes holding symbols.
    pub distinct_nodes: u32,

    /// Maximum fraction held by any single node (basis points).
    pub max_node_fraction_bps: u32,

    /// Overall coverage (basis points, 10000 = 100%).
    pub coverage_bps: u32,

    /// Whether the zone is available (can reconstruct).
    pub is_available: bool,

    /// Minimum symbols required for reconstruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_symbols_required: Option<u32>,

    /// Current symbol count available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols_available: Option<u32>,

    /// Target coverage from policy (basis points).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_coverage_bps: Option<u32>,

    /// Deficit from target (basis points, positive = under target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deficit_bps: Option<i32>,
}

/// Placement policy summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlacementSummary {
    /// Placement policy name.
    pub policy_name: String,

    /// Target replication factor.
    pub target_replicas: u32,

    /// Current average replication factor.
    pub current_avg_replicas: f64,

    /// Nodes in the placement group.
    pub placement_nodes: Vec<String>,

    /// Nodes currently healthy.
    pub healthy_nodes: u32,

    /// Nodes currently degraded or offline.
    pub degraded_nodes: u32,
}

/// Pending repair action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairAction {
    /// Action type.
    pub action_type: RepairActionType,

    /// Object ID requiring repair.
    pub object_id: String,

    /// Source nodes for symbols.
    pub source_nodes: Vec<String>,

    /// Target nodes for placement.
    pub target_nodes: Vec<String>,

    /// Symbols to transfer.
    pub symbols_needed: u32,

    /// Priority (lower = more urgent).
    pub priority: u32,

    /// Reason for repair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Type of repair action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairActionType {
    /// Replicate symbols to additional nodes.
    Replicate,
    /// Redistribute symbols for better coverage.
    Redistribute,
    /// Recover missing symbols from other nodes.
    Recover,
    /// Pre-stage symbols for expected load.
    Prestage,
}

/// Summary of last repair cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairCycleSummary {
    /// When the cycle started.
    pub started_at: DateTime<Utc>,

    /// When the cycle completed.
    pub completed_at: DateTime<Utc>,

    /// Duration in milliseconds.
    pub duration_ms: u64,

    /// Number of actions completed.
    pub actions_completed: u32,

    /// Number of actions failed.
    pub actions_failed: u32,

    /// Symbols transferred.
    pub symbols_transferred: u64,

    /// Bytes transferred.
    pub bytes_transferred: u64,

    /// Coverage before repair (basis points).
    pub coverage_before_bps: u32,

    /// Coverage after repair (basis points).
    pub coverage_after_bps: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn repair_report_builder_defaults() {
        let report = RepairReport::builder("z:work").build();

        assert_eq!(report.schema_version, "1.0.0");
        assert_eq!(report.zone_id, "z:work");
        assert_eq!(report.overall_status, CoverageStatus::Unavailable);
        assert!(!report.coverage.is_available);
    }

    #[test]
    fn coverage_status_healthy() {
        let report = RepairReport::builder("z:test")
            .coverage(CoverageMetrics {
                distinct_nodes: 5,
                max_node_fraction_bps: 2500,
                coverage_bps: 10000,
                is_available: true,
                ..Default::default()
            })
            .build();

        assert_eq!(report.overall_status, CoverageStatus::Healthy);
    }

    #[test]
    fn coverage_status_degraded() {
        let report = RepairReport::builder("z:test")
            .coverage(CoverageMetrics {
                distinct_nodes: 3,
                max_node_fraction_bps: 4000,
                coverage_bps: 7000,
                is_available: true,
                ..Default::default()
            })
            .build();

        assert_eq!(report.overall_status, CoverageStatus::Degraded);
    }

    #[test]
    fn coverage_status_critical() {
        let report = RepairReport::builder("z:test")
            .coverage(CoverageMetrics {
                distinct_nodes: 2,
                max_node_fraction_bps: 6000,
                coverage_bps: 4000,
                is_available: true,
                ..Default::default()
            })
            .build();

        assert_eq!(report.overall_status, CoverageStatus::Critical);
    }

    #[test]
    fn repair_report_json_snapshot() {
        let generated_at = Utc.with_ymd_and_hms(2026, 1, 23, 12, 0, 0).unwrap();

        let report = RepairReport {
            schema_version: "1.0.0".to_string(),
            generated_at,
            zone_id: "z:work".to_string(),
            overall_status: CoverageStatus::Healthy,
            coverage: CoverageMetrics {
                distinct_nodes: 5,
                max_node_fraction_bps: 2500,
                coverage_bps: 10000,
                is_available: true,
                min_symbols_required: Some(100),
                symbols_available: Some(150),
                target_coverage_bps: Some(10000),
                deficit_bps: Some(0),
            },
            placement: PlacementSummary {
                policy_name: "default".to_string(),
                target_replicas: 3,
                current_avg_replicas: 3.0,
                placement_nodes: vec![
                    "node-0".to_string(),
                    "node-1".to_string(),
                    "node-2".to_string(),
                ],
                healthy_nodes: 3,
                degraded_nodes: 0,
            },
            pending_repairs: vec![],
            last_repair_cycle: None,
        };

        let json = serde_json::to_string_pretty(&report).unwrap();

        // Verify key fields are present
        assert!(json.contains("\"schema_version\": \"1.0.0\""));
        assert!(json.contains("\"zone_id\": \"z:work\""));
        assert!(json.contains("\"overall_status\": \"HEALTHY\""));
        assert!(json.contains("\"coverage_bps\": 10000"));

        // Verify roundtrip
        let parsed: RepairReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.zone_id, "z:work");
        assert_eq!(parsed.overall_status, CoverageStatus::Healthy);
    }

    #[test]
    fn coverage_status_symbols() {
        assert_eq!(CoverageStatus::Healthy.symbol(), "✓");
        assert_eq!(CoverageStatus::Degraded.symbol(), "⚠");
        assert_eq!(CoverageStatus::Critical.symbol(), "✗");
        assert_eq!(CoverageStatus::Unavailable.symbol(), "☠");
    }

    // ---- CoverageStatus ansi_color ----

    #[test]
    fn coverage_status_ansi_colors() {
        assert_eq!(CoverageStatus::Healthy.ansi_color(), "\x1b[32m");
        assert_eq!(CoverageStatus::Degraded.ansi_color(), "\x1b[33m");
        assert_eq!(CoverageStatus::Critical.ansi_color(), "\x1b[31m");
        assert_eq!(CoverageStatus::Unavailable.ansi_color(), "\x1b[35m");
    }

    // ---- CoverageStatus serde ----

    #[test]
    fn coverage_status_serde_roundtrip() {
        for status in [
            CoverageStatus::Healthy,
            CoverageStatus::Degraded,
            CoverageStatus::Critical,
            CoverageStatus::Unavailable,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: CoverageStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn coverage_status_uppercase_serde() {
        assert_eq!(
            serde_json::to_string(&CoverageStatus::Healthy).unwrap(),
            "\"HEALTHY\""
        );
        assert_eq!(
            serde_json::to_string(&CoverageStatus::Unavailable).unwrap(),
            "\"UNAVAILABLE\""
        );
    }

    // ---- Coverage boundary values ----

    #[test]
    fn coverage_boundary_exactly_8000_is_healthy() {
        let status = compute_coverage_status(&CoverageMetrics {
            coverage_bps: 8000,
            is_available: true,
            ..Default::default()
        });
        assert_eq!(status, CoverageStatus::Healthy);
    }

    #[test]
    fn coverage_boundary_7999_is_degraded() {
        let status = compute_coverage_status(&CoverageMetrics {
            coverage_bps: 7999,
            is_available: true,
            ..Default::default()
        });
        assert_eq!(status, CoverageStatus::Degraded);
    }

    #[test]
    fn coverage_boundary_exactly_5000_is_degraded() {
        let status = compute_coverage_status(&CoverageMetrics {
            coverage_bps: 5000,
            is_available: true,
            ..Default::default()
        });
        assert_eq!(status, CoverageStatus::Degraded);
    }

    #[test]
    fn coverage_boundary_4999_is_critical() {
        let status = compute_coverage_status(&CoverageMetrics {
            coverage_bps: 4999,
            is_available: true,
            ..Default::default()
        });
        assert_eq!(status, CoverageStatus::Critical);
    }

    #[test]
    fn coverage_unavailable_overrides_high_bps() {
        let status = compute_coverage_status(&CoverageMetrics {
            coverage_bps: 10000,
            is_available: false,
            ..Default::default()
        });
        assert_eq!(status, CoverageStatus::Unavailable);
    }

    // ---- Default impls ----

    #[test]
    fn coverage_metrics_default() {
        let d = CoverageMetrics::default();
        assert_eq!(d.distinct_nodes, 0);
        assert_eq!(d.coverage_bps, 0);
        assert!(!d.is_available);
        assert!(d.min_symbols_required.is_none());
    }

    #[test]
    fn placement_summary_default() {
        let d = PlacementSummary::default();
        assert!(d.policy_name.is_empty());
        assert_eq!(d.target_replicas, 0);
        assert!(d.placement_nodes.is_empty());
    }

    // ---- RepairActionType serde ----

    #[test]
    fn repair_action_type_serde() {
        for action in [
            RepairActionType::Replicate,
            RepairActionType::Redistribute,
            RepairActionType::Recover,
            RepairActionType::Prestage,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: RepairActionType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    #[test]
    fn repair_action_type_snake_case() {
        assert_eq!(
            serde_json::to_string(&RepairActionType::Replicate).unwrap(),
            "\"replicate\""
        );
        assert_eq!(
            serde_json::to_string(&RepairActionType::Prestage).unwrap(),
            "\"prestage\""
        );
    }

    // ---- RepairAction serde ----

    #[test]
    fn repair_action_serde_roundtrip() {
        let action = RepairAction {
            action_type: RepairActionType::Replicate,
            object_id: "obj-123".to_string(),
            source_nodes: vec!["node-0".to_string()],
            target_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            symbols_needed: 42,
            priority: 1,
            reason: Some("under-replicated".to_string()),
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: RepairAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.object_id, "obj-123");
        assert_eq!(back.symbols_needed, 42);
        assert_eq!(back.reason.as_deref(), Some("under-replicated"));
    }

    // ---- RepairCycleSummary serde ----

    #[test]
    fn repair_cycle_summary_serde_roundtrip() {
        let now = Utc::now();
        let cycle = RepairCycleSummary {
            started_at: now,
            completed_at: now,
            duration_ms: 1500,
            actions_completed: 10,
            actions_failed: 1,
            symbols_transferred: 200,
            bytes_transferred: 50000,
            coverage_before_bps: 7000,
            coverage_after_bps: 9500,
        };
        let json = serde_json::to_string(&cycle).unwrap();
        let back: RepairCycleSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.duration_ms, 1500);
        assert_eq!(back.actions_completed, 10);
        assert_eq!(back.coverage_after_bps, 9500);
    }

    // ---- Builder with repairs and cycle ----

    #[test]
    fn builder_with_pending_repairs() {
        let action = RepairAction {
            action_type: RepairActionType::Recover,
            object_id: "obj-1".to_string(),
            source_nodes: vec![],
            target_nodes: vec!["node-0".to_string()],
            symbols_needed: 10,
            priority: 0,
            reason: None,
        };
        let report = RepairReport::builder("z:test")
            .coverage(CoverageMetrics {
                is_available: true,
                coverage_bps: 9000,
                ..Default::default()
            })
            .add_pending_repair(action)
            .build();
        assert_eq!(report.pending_repairs.len(), 1);
        assert_eq!(report.pending_repairs[0].object_id, "obj-1");
    }

    #[test]
    fn builder_with_last_repair_cycle() {
        let now = Utc::now();
        let cycle = RepairCycleSummary {
            started_at: now,
            completed_at: now,
            duration_ms: 500,
            actions_completed: 5,
            actions_failed: 0,
            symbols_transferred: 100,
            bytes_transferred: 25000,
            coverage_before_bps: 8000,
            coverage_after_bps: 10000,
        };
        let report = RepairReport::builder("z:test")
            .coverage(CoverageMetrics {
                is_available: true,
                coverage_bps: 10000,
                ..Default::default()
            })
            .last_repair_cycle(cycle)
            .build();
        assert!(report.last_repair_cycle.is_some());
        assert_eq!(report.last_repair_cycle.unwrap().duration_ms, 500);
    }

    // ---- Schema version ----

    #[test]
    fn schema_version_constant() {
        let report = RepairReport::builder("z:test").build();
        assert_eq!(report.schema_version, RepairReport::SCHEMA_VERSION);
    }
}
