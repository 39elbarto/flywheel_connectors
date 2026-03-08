//! Capability report output types for CLI.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use fcp_core::SafetyTier;
use fcp_telemetry::{CapabilityRecommendationReport, CapabilitySuggestionKind};

/// CLI capabilities report wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesReport {
    /// Schema version for CLI consumers.
    pub schema_version: String,
    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,
    /// Per-zone usage summaries.
    pub zones: Vec<ZoneCapabilityReport>,
    /// Overall totals.
    pub totals: CapabilityTotals,
}

impl CapabilitiesReport {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";
}

/// Capability usage summary for a single zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneCapabilityReport {
    /// Zone identifier.
    pub zone_id: String,
    /// Number of distinct capabilities observed.
    pub capability_count: usize,
    /// Total invocations across all capabilities.
    pub total_invocations: u64,
    /// Number of unused capabilities (no activity in window).
    pub unused_count: usize,
    /// Capabilities sorted by usage (descending).
    pub capabilities: Vec<CapabilityUsageLine>,
}

/// Single capability usage line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUsageLine {
    /// Connector identifier.
    pub connector_id: String,
    /// Capability identifier.
    pub capability_id: String,
    /// Total invocations.
    pub total: u64,
    /// Allowed invocations.
    pub allowed: u64,
    /// Denied invocations.
    pub denied: u64,
    /// Error invocations.
    pub errors: u64,
    /// Risk tier of last usage.
    pub risk_tier: SafetyTier,
    /// First seen timestamp (Unix seconds).
    pub first_seen: u64,
    /// Last seen timestamp (Unix seconds).
    pub last_seen: u64,
}

/// Aggregate totals across all zones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTotals {
    /// Total distinct capabilities.
    pub total_capabilities: usize,
    /// Total invocations.
    pub total_invocations: u64,
    /// Total unused capabilities.
    pub unused_capabilities: usize,
    /// Total risky+ tier capabilities.
    pub risky_capabilities: usize,
}

/// CLI suggest report wrapping the telemetry recommendation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestReport {
    /// Schema version for CLI consumers.
    pub schema_version: String,
    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,
    /// Inner recommendation report from telemetry engine.
    pub recommendations: CapabilityRecommendationReport,
    /// Quick summary counts.
    pub summary: SuggestSummary,
}

impl SuggestReport {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";
}

/// Quick summary of suggestion kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestSummary {
    /// Total recommendations.
    pub total: usize,
    /// Number suggesting removal.
    pub remove_unused: usize,
    /// Number suggesting review.
    pub review_risky: usize,
    /// Number suggesting keep.
    pub keep: usize,
}

impl From<&CapabilityRecommendationReport> for SuggestSummary {
    fn from(report: &CapabilityRecommendationReport) -> Self {
        let s = report.summary();
        Self {
            total: s.total,
            remove_unused: s.remove_unused,
            review_risky: s.review_risky,
            keep: s.keep,
        }
    }
}

/// Export payload wrapping raw aggregates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportPayload {
    /// Schema version for consumers.
    pub schema_version: String,
    /// Timestamp when the export was generated.
    pub generated_at: DateTime<Utc>,
    /// Number of entries.
    pub count: usize,
    /// Raw usage aggregates.
    pub aggregates: Vec<fcp_telemetry::CapabilityUsageAggregate>,
}

impl ExportPayload {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";
}

/// Filter for suggest command output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SuggestionFilter {
    /// Show only unused capability suggestions.
    Unused,
    /// Show only risky capability suggestions.
    Risky,
    /// Show only keep suggestions.
    Keep,
    /// Show all suggestions (default).
    All,
}

impl SuggestionFilter {
    /// Convert to optional `CapabilitySuggestionKind`.
    #[must_use]
    pub const fn to_kind(self) -> Option<CapabilitySuggestionKind> {
        match self {
            Self::Unused => Some(CapabilitySuggestionKind::RemoveUnused),
            Self::Risky => Some(CapabilitySuggestionKind::ReviewRisky),
            Self::Keep => Some(CapabilitySuggestionKind::Keep),
            Self::All => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_line() -> CapabilityUsageLine {
        CapabilityUsageLine {
            connector_id: "fcp.slack".to_string(),
            capability_id: "slack.send_message".to_string(),
            total: 100,
            allowed: 95,
            denied: 3,
            errors: 2,
            risk_tier: SafetyTier::Safe,
            first_seen: 1_700_000_000,
            last_seen: 1_700_100_000,
        }
    }

    #[test]
    fn capabilities_report_schema_version() {
        assert_eq!(CapabilitiesReport::SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn suggest_report_schema_version() {
        assert_eq!(SuggestReport::SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn export_payload_schema_version() {
        assert_eq!(ExportPayload::SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn capabilities_report_serde_roundtrip() {
        let report = CapabilitiesReport {
            schema_version: CapabilitiesReport::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zones: vec![ZoneCapabilityReport {
                zone_id: "z:work".to_string(),
                capability_count: 1,
                total_invocations: 100,
                unused_count: 0,
                capabilities: vec![sample_line()],
            }],
            totals: CapabilityTotals {
                total_capabilities: 1,
                total_invocations: 100,
                unused_capabilities: 0,
                risky_capabilities: 0,
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: CapabilitiesReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, "1.0.0");
        assert_eq!(back.zones.len(), 1);
        assert_eq!(back.totals.total_capabilities, 1);
    }

    #[test]
    fn capabilities_report_empty_zones() {
        let report = CapabilitiesReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![],
            totals: CapabilityTotals {
                total_capabilities: 0,
                total_invocations: 0,
                unused_capabilities: 0,
                risky_capabilities: 0,
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: CapabilitiesReport = serde_json::from_str(&json).unwrap();
        assert!(back.zones.is_empty());
    }

    #[test]
    fn zone_report_serde_roundtrip() {
        let zone = ZoneCapabilityReport {
            zone_id: "z:private".to_string(),
            capability_count: 2,
            total_invocations: 200,
            unused_count: 1,
            capabilities: vec![sample_line()],
        };
        let json = serde_json::to_string(&zone).unwrap();
        let back: ZoneCapabilityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_id, "z:private");
        assert_eq!(back.capability_count, 2);
    }

    #[test]
    fn capability_usage_line_serde_roundtrip() {
        let line = sample_line();
        let json = serde_json::to_string(&line).unwrap();
        let back: CapabilityUsageLine = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "fcp.slack");
        assert_eq!(back.total, 100);
        assert_eq!(back.risk_tier, SafetyTier::Safe);
    }

    #[test]
    fn capability_totals_serde_roundtrip() {
        let totals = CapabilityTotals {
            total_capabilities: 10,
            total_invocations: 5000,
            unused_capabilities: 2,
            risky_capabilities: 3,
        };
        let json = serde_json::to_string(&totals).unwrap();
        let back: CapabilityTotals = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_capabilities, 10);
        assert_eq!(back.total_invocations, 5000);
    }

    #[test]
    fn export_payload_serde_roundtrip() {
        let payload = ExportPayload {
            schema_version: ExportPayload::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            count: 0,
            aggregates: vec![],
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: ExportPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, "1.0.0");
        assert_eq!(back.count, 0);
    }

    #[test]
    fn suggestion_filter_to_kind() {
        assert_eq!(
            SuggestionFilter::Unused.to_kind(),
            Some(CapabilitySuggestionKind::RemoveUnused)
        );
        assert_eq!(
            SuggestionFilter::Risky.to_kind(),
            Some(CapabilitySuggestionKind::ReviewRisky)
        );
        assert_eq!(
            SuggestionFilter::Keep.to_kind(),
            Some(CapabilitySuggestionKind::Keep)
        );
        assert_eq!(SuggestionFilter::All.to_kind(), None);
    }

    #[test]
    fn capabilities_report_debug() {
        let report = CapabilitiesReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![],
            totals: CapabilityTotals {
                total_capabilities: 0,
                total_invocations: 0,
                unused_capabilities: 0,
                risky_capabilities: 0,
            },
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("CapabilitiesReport"));
    }

    #[test]
    fn capabilities_report_clone() {
        let report = CapabilitiesReport {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![ZoneCapabilityReport {
                zone_id: "z:test".to_string(),
                capability_count: 0,
                total_invocations: 0,
                unused_count: 0,
                capabilities: vec![],
            }],
            totals: CapabilityTotals {
                total_capabilities: 0,
                total_invocations: 0,
                unused_capabilities: 0,
                risky_capabilities: 0,
            },
        };
        let moved = report;
        assert_eq!(moved.zones.len(), 1);
        assert_eq!(moved.zones[0].zone_id, "z:test");
    }
}
