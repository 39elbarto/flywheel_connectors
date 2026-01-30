//! Doctor report types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for health/freshness reports,
//! enabling automation and operator tooling integration.

// Allow public API items that aren't used yet within this crate
#![allow(dead_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::trivially_copy_pass_by_ref)]

use chrono::{DateTime, Utc};
use fcp_core::{SelfCheckReport, SelfCheckStatus};
use serde::{Deserialize, Serialize};

/// Complete doctor report including zone health and freshness status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Zone being diagnosed.
    pub zone_id: String,

    /// Overall status summary.
    pub overall_status: OverallStatus,

    /// Checkpoint freshness status.
    pub checkpoint: CheckpointStatus,

    /// Revocation head freshness status.
    pub revocation: RevocationStatus,

    /// Audit head freshness status.
    pub audit: AuditStatus,

    /// Transport policy settings.
    pub transport_policy: TransportPolicyStatus,

    /// Store coverage summary for key roots.
    pub store_coverage: StoreCoverageStatus,

    /// Degraded mode status and reasons.
    pub degraded_mode: DegradedModeStatus,

    /// Individual check results.
    pub checks: Vec<CheckResult>,

    /// Connector self-check results (when requested).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connector_self_checks: Vec<ConnectorSelfCheck>,
}

impl DoctorReport {
    /// Schema version constant.
    pub const SCHEMA_VERSION: &'static str = "1.1.0";

    /// Create a new doctor report builder.
    #[must_use]
    pub fn builder(zone_id: impl Into<String>) -> DoctorReportBuilder {
        DoctorReportBuilder::new(zone_id)
    }
}

/// Builder for DoctorReport.
pub struct DoctorReportBuilder {
    zone_id: String,
    checkpoint: Option<CheckpointStatus>,
    revocation: Option<RevocationStatus>,
    audit: Option<AuditStatus>,
    transport_policy: Option<TransportPolicyStatus>,
    store_coverage: Option<StoreCoverageStatus>,
    degraded_mode: Option<DegradedModeStatus>,
    checks: Vec<CheckResult>,
    connector_self_checks: Vec<ConnectorSelfCheck>,
}

impl DoctorReportBuilder {
    fn new(zone_id: impl Into<String>) -> Self {
        Self {
            zone_id: zone_id.into(),
            checkpoint: None,
            revocation: None,
            audit: None,
            transport_policy: None,
            store_coverage: None,
            degraded_mode: None,
            checks: Vec::new(),
            connector_self_checks: Vec::new(),
        }
    }

    #[must_use]
    pub fn checkpoint(mut self, status: CheckpointStatus) -> Self {
        self.checkpoint = Some(status);
        self
    }

    #[must_use]
    pub fn revocation(mut self, status: RevocationStatus) -> Self {
        self.revocation = Some(status);
        self
    }

    #[must_use]
    pub fn audit(mut self, status: AuditStatus) -> Self {
        self.audit = Some(status);
        self
    }

    #[must_use]
    pub fn transport_policy(mut self, status: TransportPolicyStatus) -> Self {
        self.transport_policy = Some(status);
        self
    }

    #[must_use]
    pub fn store_coverage(mut self, status: StoreCoverageStatus) -> Self {
        self.store_coverage = Some(status);
        self
    }

    #[must_use]
    pub fn degraded_mode(mut self, status: DegradedModeStatus) -> Self {
        self.degraded_mode = Some(status);
        self
    }

    #[must_use]
    pub fn add_check(mut self, check: CheckResult) -> Self {
        self.checks.push(check);
        self
    }

    #[must_use]
    pub fn add_self_check(mut self, check: ConnectorSelfCheck) -> Self {
        self.connector_self_checks.push(check);
        self
    }

    #[must_use]
    pub fn build(self) -> DoctorReport {
        let checkpoint = self.checkpoint.unwrap_or_default();
        let revocation = self.revocation.unwrap_or_default();
        let audit = self.audit.unwrap_or_default();
        let transport_policy = self.transport_policy.unwrap_or_default();
        let store_coverage = self.store_coverage.unwrap_or_default();
        let degraded_mode = self.degraded_mode.unwrap_or_default();

        // Compute overall status from component statuses
        let overall_status = compute_overall_status(
            &checkpoint,
            &revocation,
            &audit,
            &degraded_mode,
            &self.checks,
            &self.connector_self_checks,
        );

        DoctorReport {
            schema_version: DoctorReport::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zone_id: self.zone_id,
            overall_status,
            checkpoint,
            revocation,
            audit,
            transport_policy,
            store_coverage,
            degraded_mode,
            checks: self.checks,
            connector_self_checks: self.connector_self_checks,
        }
    }
}

fn compute_overall_status(
    checkpoint: &CheckpointStatus,
    revocation: &RevocationStatus,
    audit: &AuditStatus,
    degraded_mode: &DegradedModeStatus,
    checks: &[CheckResult],
    connector_self_checks: &[ConnectorSelfCheck],
) -> OverallStatus {
    // FAIL if any critical check failed
    if checks
        .iter()
        .any(|c| c.status == CheckStatus::Fail && c.severity == CheckSeverity::Critical)
    {
        return OverallStatus::Fail;
    }

    // FAIL if any connector self-check failed
    if connector_self_checks
        .iter()
        .any(|check| check.report.status == SelfCheckStatus::Failed)
    {
        return OverallStatus::Fail;
    }

    // FAIL if checkpoint/revocation/audit is too stale
    if checkpoint.freshness == FreshnessLevel::TooStale
        || revocation.freshness == FreshnessLevel::TooStale
        || audit.freshness == FreshnessLevel::TooStale
    {
        return OverallStatus::Fail;
    }

    // WARN if in degraded mode
    if degraded_mode.is_degraded {
        return OverallStatus::Warn;
    }

    // WARN if any connector self-check is degraded
    if connector_self_checks
        .iter()
        .any(|check| check.report.status == SelfCheckStatus::Degraded)
    {
        return OverallStatus::Warn;
    }

    // WARN if any checkpoint/revocation/audit is stale
    if checkpoint.freshness == FreshnessLevel::Stale
        || revocation.freshness == FreshnessLevel::Stale
        || audit.freshness == FreshnessLevel::Stale
    {
        return OverallStatus::Warn;
    }

    // WARN if any non-critical check is warning
    if checks.iter().any(|c| c.status == CheckStatus::Warn) {
        return OverallStatus::Warn;
    }

    OverallStatus::Ok
}

/// Connector self-check entry in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorSelfCheck {
    /// Connector identifier.
    pub connector_id: String,

    /// Self-check report from connector.
    pub report: SelfCheckReport,
}

/// Overall status of the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OverallStatus {
    /// Zone is healthy and all checks pass.
    Ok,
    /// Zone has warnings but operations can proceed.
    Warn,
    /// Zone has critical failures; Risky/Dangerous operations should fail.
    Fail,
}

impl OverallStatus {
    /// Get ANSI color code for terminal output.
    #[must_use]
    pub const fn ansi_color(&self) -> &'static str {
        match self {
            Self::Ok => "\x1b[32m",   // Green
            Self::Warn => "\x1b[33m", // Yellow
            Self::Fail => "\x1b[31m", // Red
        }
    }

    /// Get symbol for terminal output.
    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Warn => "⚠",
            Self::Fail => "✗",
        }
    }
}

/// Checkpoint freshness status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckpointStatus {
    /// Latest pinned checkpoint object ID (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,

    /// Checkpoint sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<u64>,

    /// Age of checkpoint in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,

    /// Freshness level.
    pub freshness: FreshnessLevel,

    /// When the checkpoint was last updated (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated_at: Option<u64>,

    /// Associated audit head sequence at checkpoint time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_head_seq: Option<u64>,

    /// Associated revocation head sequence at checkpoint time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_head_seq: Option<u64>,

    /// Reason for status (if not fresh).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Revocation head freshness status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationStatus {
    /// Revocation head object ID (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_id: Option<String>,

    /// Revocation head sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,

    /// Age of revocation head in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,

    /// Freshness level.
    pub freshness: FreshnessLevel,

    /// Reason for status (if not fresh).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Audit head freshness status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStatus {
    /// Audit head object ID (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_id: Option<String>,

    /// Audit head sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,

    /// Age of audit head in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,

    /// Freshness level.
    pub freshness: FreshnessLevel,

    /// Coverage (fraction of nodes contributing, 0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<f64>,

    /// Reason for status (if not fresh).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Freshness level for heads/checkpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessLevel {
    /// Data is fresh and up-to-date.
    #[default]
    Fresh,
    /// Data is stale but operations allowed in degraded mode.
    Stale,
    /// Data is too stale; operations must fail.
    TooStale,
    /// Data is missing/unavailable.
    Missing,
}

impl FreshnessLevel {
    /// Check if operations can proceed.
    #[must_use]
    pub const fn allows_operation(&self) -> bool {
        !matches!(self, Self::TooStale | Self::Missing)
    }
}

/// Transport policy status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportPolicyStatus {
    /// Whether LAN transport is allowed.
    pub allow_lan: bool,

    /// Whether DERP relay transport is allowed.
    pub allow_derp: bool,

    /// Whether Funnel ingress is allowed.
    pub allow_funnel: bool,
}

/// Store coverage status for key roots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreCoverageStatus {
    /// Coverage for checkpoint objects (basis points, 10000 = 100%).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_coverage_bps: Option<u32>,

    /// Coverage for policy head objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_head_coverage_bps: Option<u32>,

    /// Coverage for revocation head objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_head_coverage_bps: Option<u32>,

    /// Overall store health.
    pub store_healthy: bool,

    /// Reason for degraded store status (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Degraded mode status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DegradedModeStatus {
    /// Whether the system is in degraded mode.
    pub is_degraded: bool,

    /// Reasons for degraded mode (may be multiple).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<DegradedReason>,

    /// When degraded mode started (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

/// Reason for degraded mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedReason {
    /// Reason code (FCP-XXXX).
    pub code: String,

    /// Human-readable description.
    pub description: String,
}

/// Individual check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Check name.
    pub name: String,

    /// Check status.
    pub status: CheckStatus,

    /// Check severity.
    pub severity: CheckSeverity,

    /// Human-readable message.
    pub message: String,

    /// Associated reason code (FCP-XXXX).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

impl CheckResult {
    /// Create a passing check.
    #[must_use]
    pub fn ok(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: message.into(),
            reason_code: None,
        }
    }

    /// Create a warning check.
    #[must_use]
    pub fn warn(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: message.into(),
            reason_code: None,
        }
    }

    /// Create a failing check.
    #[must_use]
    pub fn fail(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Fail,
            severity: CheckSeverity::Critical,
            message: message.into(),
            reason_code: None,
        }
    }

    /// Add a reason code to the check.
    #[must_use]
    pub fn with_reason_code(mut self, code: impl Into<String>) -> Self {
        self.reason_code = Some(code.into());
        self
    }

    /// Set severity level.
    #[must_use]
    pub const fn with_severity(mut self, severity: CheckSeverity) -> Self {
        self.severity = severity;
        self
    }
}

/// Check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

/// Check severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    Info,
    Warning,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn doctor_report_builder_defaults() {
        let report = DoctorReport::builder("z:work").build();

        assert_eq!(report.schema_version, "1.1.0");
        assert_eq!(report.zone_id, "z:work");
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.revocation.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.audit.freshness, FreshnessLevel::Fresh);
        assert!(report.connector_self_checks.is_empty());
    }

    #[test]
    fn overall_status_fail_on_stale_checkpoint() {
        let report = DoctorReport::builder("z:test")
            .checkpoint(CheckpointStatus {
                freshness: FreshnessLevel::TooStale,
                reason: Some("checkpoint too old".to_string()),
                ..Default::default()
            })
            .build();

        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn overall_status_warn_on_degraded() {
        let report = DoctorReport::builder("z:test")
            .degraded_mode(DegradedModeStatus {
                is_degraded: true,
                reasons: vec![DegradedReason {
                    code: "FCP-5001".to_string(),
                    description: "Checkpoint stale".to_string(),
                }],
                since: Some(1_700_000_000),
            })
            .build();

        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    #[test]
    fn overall_status_warn_on_stale_freshness() {
        let report = DoctorReport::builder("z:test")
            .revocation(RevocationStatus {
                freshness: FreshnessLevel::Stale,
                ..Default::default()
            })
            .build();

        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    #[test]
    fn overall_status_fail_on_critical_check() {
        let report = DoctorReport::builder("z:test")
            .add_check(CheckResult::fail("fork_detection", "Fork detected!"))
            .build();

        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn check_result_with_reason_code() {
        let check = CheckResult::warn("checkpoint_age", "Checkpoint is 5 minutes old")
            .with_reason_code("FCP-5002");

        assert_eq!(check.status, CheckStatus::Warn);
        assert_eq!(check.reason_code, Some("FCP-5002".to_string()));
    }

    #[test]
    fn freshness_level_allows_operation() {
        assert!(FreshnessLevel::Fresh.allows_operation());
        assert!(FreshnessLevel::Stale.allows_operation());
        assert!(!FreshnessLevel::TooStale.allows_operation());
        assert!(!FreshnessLevel::Missing.allows_operation());
    }

    #[test]
    fn doctor_report_json_snapshot() {
        let generated_at = Utc.with_ymd_and_hms(2026, 1, 16, 12, 0, 0).unwrap();

        let report = DoctorReport {
            schema_version: "1.1.0".to_string(),
            generated_at,
            zone_id: "z:work".to_string(),
            overall_status: OverallStatus::Ok,
            checkpoint: CheckpointStatus {
                checkpoint_id: Some("abc123".to_string()),
                checkpoint_seq: Some(42),
                age_secs: Some(30),
                freshness: FreshnessLevel::Fresh,
                last_updated_at: Some(1_700_000_000),
                audit_head_seq: Some(100),
                revocation_head_seq: Some(50),
                reason: None,
            },
            revocation: RevocationStatus {
                head_id: Some("def456".to_string()),
                head_seq: Some(50),
                age_secs: Some(30),
                freshness: FreshnessLevel::Fresh,
                reason: None,
            },
            audit: AuditStatus {
                head_id: Some("ghi789".to_string()),
                head_seq: Some(100),
                age_secs: Some(30),
                freshness: FreshnessLevel::Fresh,
                coverage: Some(0.95),
                reason: None,
            },
            transport_policy: TransportPolicyStatus {
                allow_lan: true,
                allow_derp: false,
                allow_funnel: false,
            },
            store_coverage: StoreCoverageStatus {
                checkpoint_coverage_bps: Some(9500),
                policy_head_coverage_bps: Some(10000),
                revocation_head_coverage_bps: Some(9800),
                store_healthy: true,
                reason: None,
            },
            degraded_mode: DegradedModeStatus {
                is_degraded: false,
                reasons: vec![],
                since: None,
            },
            checks: vec![CheckResult::ok(
                "checkpoint_freshness",
                "Checkpoint is fresh (30s old)",
            )],
            connector_self_checks: vec![],
        };

        let json = serde_json::to_string_pretty(&report).unwrap();

        // Verify key fields are present
        assert!(json.contains("\"schema_version\": \"1.1.0\""));
        assert!(json.contains("\"zone_id\": \"z:work\""));
        assert!(json.contains("\"overall_status\": \"OK\""));
        assert!(json.contains("\"checkpoint_seq\": 42"));
        assert!(json.contains("\"allow_derp\": false"));

        // Verify roundtrip
        let parsed: DoctorReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.zone_id, "z:work");
        assert_eq!(parsed.overall_status, OverallStatus::Ok);
        assert_eq!(parsed.checkpoint.checkpoint_seq, Some(42));
    }

    #[test]
    fn overall_status_fail_on_self_check_failure() {
        let report = DoctorReport::builder("z:test")
            .add_self_check(ConnectorSelfCheck {
                connector_id: "fcp.test:example:v1".to_string(),
                report: SelfCheckReport::failed("self_check_failed", "boom"),
            })
            .build();

        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn overall_status_ok_on_self_check_success() {
        let report = DoctorReport::builder("z:test")
            .add_self_check(ConnectorSelfCheck {
                connector_id: "fcp.test:example:v1".to_string(),
                report: SelfCheckReport::ok(),
            })
            .build();

        assert_eq!(report.overall_status, OverallStatus::Ok);
    }

    #[test]
    fn overall_status_fail_on_self_check_timeout() {
        let report = DoctorReport::builder("z:test")
            .add_self_check(ConnectorSelfCheck {
                connector_id: "fcp.test:example:v1".to_string(),
                report: SelfCheckReport::failed("timeout", "self-check timed out"),
            })
            .build();

        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn overall_status_warn_on_self_check_degraded() {
        let report = DoctorReport::builder("z:test")
            .add_self_check(ConnectorSelfCheck {
                connector_id: "fcp.test:example:v1".to_string(),
                report: SelfCheckReport::degraded("self_check_degraded", "slow"),
            })
            .build();

        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    #[test]
    fn overall_status_symbols() {
        assert_eq!(OverallStatus::Ok.symbol(), "✓");
        assert_eq!(OverallStatus::Warn.symbol(), "⚠");
        assert_eq!(OverallStatus::Fail.symbol(), "✗");
    }
}
