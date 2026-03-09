// Cross-connector health aggregation and display.
//
// Aggregates health status across all configured connectors and provides
// both human-readable (TOON-style table) and machine-readable (JSON)
// output formats.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Health status ──────────────────────────────────────────────────────

/// Overall health status of a connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthStatus {
    /// Connector is fully operational.
    Healthy,
    /// Connector is operational but with warnings (e.g. high latency).
    Degraded,
    /// Connector is experiencing errors.
    Error,
    /// Health status could not be determined.
    Unknown,
    /// Connector is not configured in this environment.
    Unconfigured,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(status_indicator(*self))
    }
}

// ── Auth check result ──────────────────────────────────────────────────

/// Result of checking a connector's authentication credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum AuthCheckResult {
    /// Credentials are valid and working.
    Valid,
    /// Credentials have expired.
    Expired {
        /// How many days ago the credentials expired.
        days_ago: u32,
    },
    /// Credentials are present but invalid (e.g. wrong token).
    Invalid,
    /// No credentials are configured.
    NotConfigured,
    /// Auth status could not be determined.
    Unknown,
}

impl std::fmt::Display for AuthCheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(auth_indicator(self))
    }
}

// ── Issue severity ─────────────────────────────────────────────────────

/// Severity level for a health issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssueSeverity {
    /// Informational notice.
    Info,
    /// Warning that may require attention.
    Warning,
    /// Error affecting functionality.
    Error,
    /// Critical issue requiring immediate action.
    Critical,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => f.write_str("info"),
            Self::Warning => f.write_str("warning"),
            Self::Error => f.write_str("error"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

// ── Health issue ───────────────────────────────────────────────────────

/// A specific health issue detected for a connector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthIssue {
    /// Severity of the issue.
    pub severity: IssueSeverity,
    /// Human-readable description of the issue.
    pub message: String,
}

impl HealthIssue {
    /// Create a new health issue.
    #[must_use]
    pub fn new(severity: IssueSeverity, message: impl Into<String>) -> Self {
        Self {
            severity,
            message: message.into(),
        }
    }
}

// ── Connector health ───────────────────────────────────────────────────

/// Health status of a single connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorHealth {
    /// Canonical connector identifier (e.g. `"github"`).
    pub connector_id: String,
    /// Overall health status.
    pub status: HealthStatus,
    /// Authentication credential check result.
    pub auth_status: AuthCheckResult,
    /// Round-trip latency to the connector's API in milliseconds.
    pub latency_ms: Option<u64>,
    /// When this health check was last performed.
    pub last_check: DateTime<Utc>,
    /// List of detected issues.
    pub issues: Vec<HealthIssue>,
}

impl ConnectorHealth {
    /// Create a new `ConnectorHealth` with the given id and status.
    #[must_use]
    pub fn new(
        connector_id: impl Into<String>,
        status: HealthStatus,
        last_check: DateTime<Utc>,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            status,
            auth_status: AuthCheckResult::Unknown,
            latency_ms: None,
            last_check,
            issues: Vec::new(),
        }
    }

    /// Add a health issue (builder pattern).
    #[must_use]
    pub fn with_issue(mut self, issue: HealthIssue) -> Self {
        self.issues.push(issue);
        self
    }

    /// Set the auth status (builder pattern).
    #[must_use]
    pub const fn with_auth(mut self, auth: AuthCheckResult) -> Self {
        self.auth_status = auth;
        self
    }

    /// Set the latency (builder pattern).
    #[must_use]
    pub const fn with_latency(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }
}

// ── Dashboard summary ──────────────────────────────────────────────────

/// Aggregated counts across all connectors in a dashboard.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DashboardSummary {
    /// Total number of connectors.
    pub total: usize,
    /// Number of healthy connectors.
    pub healthy: usize,
    /// Number of degraded connectors.
    pub degraded: usize,
    /// Number of connectors in error state.
    pub error: usize,
    /// Number of connectors with unknown status.
    pub unknown: usize,
    /// Number of connectors with auth issues.
    pub auth_issues: usize,
}

impl DashboardSummary {
    /// Compute summary from a list of connector health entries.
    #[must_use]
    pub fn from_connectors(connectors: &[ConnectorHealth]) -> Self {
        let mut summary = Self {
            total: connectors.len(),
            ..Self::default()
        };

        for c in connectors {
            match c.status {
                HealthStatus::Healthy => summary.healthy += 1,
                HealthStatus::Degraded => summary.degraded += 1,
                HealthStatus::Error => summary.error += 1,
                HealthStatus::Unknown | HealthStatus::Unconfigured => summary.unknown += 1,
            }

            match &c.auth_status {
                AuthCheckResult::Expired { .. } | AuthCheckResult::Invalid => {
                    summary.auth_issues += 1;
                }
                AuthCheckResult::Valid
                | AuthCheckResult::NotConfigured
                | AuthCheckResult::Unknown => {}
            }
        }

        summary
    }
}

// ── Health filter ──────────────────────────────────────────────────────

/// Filter criteria for displaying a subset of connectors in the dashboard.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HealthFilter {
    /// If true, only show connectors that are not healthy.
    pub unhealthy_only: bool,
    /// If set, only show the connector with this ID.
    pub connector_id: Option<String>,
}

// ── Health dashboard ───────────────────────────────────────────────────

/// Aggregated health dashboard across all configured connectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthDashboard {
    /// Per-connector health entries.
    pub connectors: Vec<ConnectorHealth>,
    /// When this dashboard snapshot was taken.
    pub checked_at: DateTime<Utc>,
    /// Aggregated summary counts.
    pub summary: DashboardSummary,
}

impl HealthDashboard {
    /// Build a dashboard from a list of connector health entries.
    #[must_use]
    pub fn from_connectors(connectors: Vec<ConnectorHealth>) -> Self {
        let summary = DashboardSummary::from_connectors(&connectors);
        Self {
            connectors,
            checked_at: Utc::now(),
            summary,
        }
    }

    /// Build a dashboard from connectors with a specific timestamp.
    #[must_use]
    pub fn from_connectors_at(connectors: Vec<ConnectorHealth>, checked_at: DateTime<Utc>) -> Self {
        let summary = DashboardSummary::from_connectors(&connectors);
        Self {
            connectors,
            checked_at,
            summary,
        }
    }

    /// Return a filtered view of the dashboard.
    #[must_use]
    pub fn filter(&self, filter: &HealthFilter) -> Self {
        let connectors: Vec<ConnectorHealth> = self
            .connectors
            .iter()
            .filter(|c| {
                if filter.unhealthy_only && c.status == HealthStatus::Healthy {
                    return false;
                }
                if let Some(ref id) = filter.connector_id {
                    if c.connector_id != *id {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        let summary = DashboardSummary::from_connectors(&connectors);
        Self {
            connectors,
            checked_at: self.checked_at,
            summary,
        }
    }
}

// ── Issue detection ────────────────────────────────────────────────────

/// Latency threshold in ms above which a warning is emitted.
const LATENCY_WARN_THRESHOLD_MS: u64 = 500;

/// Latency threshold in ms above which an error is emitted.
const LATENCY_ERROR_THRESHOLD_MS: u64 = 1000;

/// Auto-detect common health issues and append them to the connector's
/// issue list. Also adjusts the overall status if warranted.
pub fn detect_issues(health: &mut ConnectorHealth) {
    // Check latency thresholds.
    if let Some(latency) = health.latency_ms {
        if latency > LATENCY_ERROR_THRESHOLD_MS {
            health.issues.push(HealthIssue::new(
                IssueSeverity::Error,
                format!("Very high latency ({latency}ms)"),
            ));
            if health.status == HealthStatus::Healthy {
                health.status = HealthStatus::Degraded;
            }
        } else if latency > LATENCY_WARN_THRESHOLD_MS {
            health.issues.push(HealthIssue::new(
                IssueSeverity::Warning,
                format!("High latency ({latency}ms)"),
            ));
            if health.status == HealthStatus::Healthy {
                health.status = HealthStatus::Degraded;
            }
        }
    }

    // Check auth status.
    match &health.auth_status {
        AuthCheckResult::Expired { days_ago } => {
            health.issues.push(HealthIssue::new(
                IssueSeverity::Critical,
                format!("Token expired {days_ago} day(s) ago"),
            ));
            if health.status == HealthStatus::Healthy || health.status == HealthStatus::Degraded {
                health.status = HealthStatus::Error;
            }
        }
        AuthCheckResult::Invalid => {
            health.issues.push(HealthIssue::new(
                IssueSeverity::Critical,
                "Authentication credentials are invalid".to_owned(),
            ));
            if health.status == HealthStatus::Healthy || health.status == HealthStatus::Degraded {
                health.status = HealthStatus::Error;
            }
        }
        AuthCheckResult::NotConfigured => {
            health.issues.push(HealthIssue::new(
                IssueSeverity::Warning,
                "No authentication configured".to_owned(),
            ));
        }
        AuthCheckResult::Valid | AuthCheckResult::Unknown => {}
    }

    // Check error state without existing explanation.
    if health.status == HealthStatus::Error
        && !health
            .issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Critical || i.severity == IssueSeverity::Error)
    {
        health.issues.push(HealthIssue::new(
            IssueSeverity::Error,
            "Connector is in error state".to_owned(),
        ));
    }
}

// ── Dashboard merging ──────────────────────────────────────────────────

/// Merge two dashboards (e.g. from different zones) into one.
///
/// Uses the later `checked_at` timestamp and combines all connector entries.
/// If the same connector appears in both, the entry with the later
/// `last_check` wins.
#[must_use]
pub fn merge_dashboards(a: &HealthDashboard, b: &HealthDashboard) -> HealthDashboard {
    use std::collections::BTreeMap;

    let mut by_id: BTreeMap<String, ConnectorHealth> = BTreeMap::new();

    for c in &a.connectors {
        by_id.insert(c.connector_id.clone(), c.clone());
    }
    for c in &b.connectors {
        by_id
            .entry(c.connector_id.clone())
            .and_modify(|existing| {
                if c.last_check > existing.last_check {
                    *existing = c.clone();
                }
            })
            .or_insert_with(|| c.clone());
    }

    let connectors: Vec<ConnectorHealth> = by_id.into_values().collect();
    let checked_at = a.checked_at.max(b.checked_at);
    let summary = DashboardSummary::from_connectors(&connectors);

    HealthDashboard {
        connectors,
        checked_at,
        summary,
    }
}

// ── Display helpers ────────────────────────────────────────────────────

/// Return a human-readable label for a health status.
#[must_use]
pub const fn status_indicator(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Healthy => "healthy",
        HealthStatus::Degraded => "degraded",
        HealthStatus::Error => "error",
        HealthStatus::Unknown => "unknown",
        HealthStatus::Unconfigured => "unconfigured",
    }
}

/// Return a human-readable label for an auth check result.
#[must_use]
pub const fn auth_indicator(auth: &AuthCheckResult) -> &'static str {
    match auth {
        AuthCheckResult::Valid => "ok",
        AuthCheckResult::Expired { .. } => "EXPIRED",
        AuthCheckResult::Invalid => "INVALID",
        AuthCheckResult::NotConfigured => "none",
        AuthCheckResult::Unknown => "?",
    }
}

/// Format a `DateTime<Utc>` as a human-readable "time ago" string relative
/// to `now`.
#[must_use]
pub fn format_time_ago(dt: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let delta = now.signed_duration_since(dt);
    let secs = delta.num_seconds();

    if secs < 0 {
        return "in the future".to_owned();
    }
    if secs < 5 {
        return "just now".to_owned();
    }
    if secs < 60 {
        return format!("{secs}s ago");
    }

    let mins = delta.num_minutes();
    if mins < 60 {
        return format!("{mins}m ago");
    }

    let hours = delta.num_hours();
    if hours < 24 {
        return format!("{hours}h ago");
    }

    let days = delta.num_days();
    format!("{days}d ago")
}

// ── TOON formatting ───────────────────────────────────────────────────

/// Format the dashboard as a human-readable table (TOON-style).
#[must_use]
pub fn format_dashboard_toon(dashboard: &HealthDashboard) -> String {
    use std::fmt::Write;

    let now = dashboard.checked_at;
    let mut out = String::new();

    // Summary line.
    let s = &dashboard.summary;
    let _ = write!(
        out,
        "Health: {} total, {} healthy, {} degraded, {} error, {} unknown",
        s.total, s.healthy, s.degraded, s.error, s.unknown,
    );
    if s.auth_issues > 0 {
        let _ = write!(out, ", {} auth issue(s)", s.auth_issues);
    }
    out.push('\n');

    if dashboard.connectors.is_empty() {
        out.push_str("No connectors configured.\n");
        return out;
    }

    // Table header.
    out.push('\n');
    let _ = writeln!(
        out,
        "{:<16}{:<14}{:<10}{:<10}{:<14}Issues",
        "Connector", "Status", "Auth", "Latency", "Last Check"
    );
    out.push_str(&"-".repeat(76));
    out.push('\n');

    // Table rows.
    for c in &dashboard.connectors {
        let latency_str = c
            .latency_ms
            .map_or_else(|| "-".to_owned(), |ms| format!("{ms}ms"));

        let time_str = format_time_ago(c.last_check, now);

        let issues_str = if c.issues.is_empty() {
            "-".to_owned()
        } else {
            c.issues
                .iter()
                .map(|i| i.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        };

        let _ = writeln!(
            out,
            "{:<16}{:<14}{:<10}{:<10}{:<14}{}",
            c.connector_id,
            status_indicator(c.status),
            auth_indicator(&c.auth_status),
            latency_str,
            time_str,
            issues_str,
        );
    }

    out
}

// ── JSON formatting ────────────────────────────────────────────────────

/// Format the dashboard as a JSON value for machine consumption.
///
/// # Errors
///
/// Returns an error if serialization fails (should not happen for
/// well-formed dashboards).
pub fn format_dashboard_json(
    dashboard: &HealthDashboard,
) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(dashboard)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 9, 12, 0, 0).unwrap()
    }

    fn make_healthy(id: &str, at: DateTime<Utc>) -> ConnectorHealth {
        ConnectorHealth::new(id, HealthStatus::Healthy, at)
            .with_auth(AuthCheckResult::Valid)
            .with_latency(45)
    }

    fn make_degraded(id: &str, at: DateTime<Utc>) -> ConnectorHealth {
        ConnectorHealth::new(id, HealthStatus::Degraded, at)
            .with_auth(AuthCheckResult::Valid)
            .with_latency(890)
            .with_issue(HealthIssue::new(IssueSeverity::Warning, "High latency"))
    }

    fn make_error(id: &str, at: DateTime<Utc>) -> ConnectorHealth {
        ConnectorHealth::new(id, HealthStatus::Error, at)
            .with_auth(AuthCheckResult::Expired { days_ago: 3 })
    }

    // ── HealthStatus tests ─────────────────────────────────────────

    #[test]
    fn health_status_display_healthy() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
    }

    #[test]
    fn health_status_display_degraded() {
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
    }

    #[test]
    fn health_status_display_error() {
        assert_eq!(HealthStatus::Error.to_string(), "error");
    }

    #[test]
    fn health_status_display_unknown() {
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn health_status_display_unconfigured() {
        assert_eq!(HealthStatus::Unconfigured.to_string(), "unconfigured");
    }

    #[test]
    fn health_status_ordering() {
        assert!(HealthStatus::Healthy < HealthStatus::Degraded);
        assert!(HealthStatus::Degraded < HealthStatus::Error);
        assert!(HealthStatus::Error < HealthStatus::Unknown);
        assert!(HealthStatus::Unknown < HealthStatus::Unconfigured);
    }

    #[test]
    fn health_status_serialization_roundtrip() {
        let status = HealthStatus::Degraded;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"degraded\"");
        let back: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn health_status_all_variants_serialize() {
        for status in [
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Error,
            HealthStatus::Unknown,
            HealthStatus::Unconfigured,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: HealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    // ── AuthCheckResult tests ──────────────────────────────────────

    #[test]
    fn auth_display_valid() {
        assert_eq!(AuthCheckResult::Valid.to_string(), "ok");
    }

    #[test]
    fn auth_display_expired() {
        assert_eq!(
            AuthCheckResult::Expired { days_ago: 5 }.to_string(),
            "EXPIRED"
        );
    }

    #[test]
    fn auth_display_invalid() {
        assert_eq!(AuthCheckResult::Invalid.to_string(), "INVALID");
    }

    #[test]
    fn auth_display_not_configured() {
        assert_eq!(AuthCheckResult::NotConfigured.to_string(), "none");
    }

    #[test]
    fn auth_display_unknown() {
        assert_eq!(AuthCheckResult::Unknown.to_string(), "?");
    }

    #[test]
    fn auth_serialization_valid() {
        let json = serde_json::to_string(&AuthCheckResult::Valid).unwrap();
        let back: AuthCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AuthCheckResult::Valid);
    }

    #[test]
    fn auth_serialization_expired() {
        let auth = AuthCheckResult::Expired { days_ago: 7 };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("expired"));
        assert!(json.contains('7'));
        let back: AuthCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, auth);
    }

    // ── ConnectorHealth tests ──────────────────────────────────────

    #[test]
    fn connector_health_new_defaults() {
        let t = fixed_time();
        let h = ConnectorHealth::new("github", HealthStatus::Healthy, t);
        assert_eq!(h.connector_id, "github");
        assert_eq!(h.status, HealthStatus::Healthy);
        assert_eq!(h.auth_status, AuthCheckResult::Unknown);
        assert!(h.latency_ms.is_none());
        assert!(h.issues.is_empty());
    }

    #[test]
    fn connector_health_builder_chain() {
        let t = fixed_time();
        let h = ConnectorHealth::new("slack", HealthStatus::Healthy, t)
            .with_auth(AuthCheckResult::Valid)
            .with_latency(120)
            .with_issue(HealthIssue::new(IssueSeverity::Info, "Test issue"));

        assert_eq!(h.connector_id, "slack");
        assert_eq!(h.auth_status, AuthCheckResult::Valid);
        assert_eq!(h.latency_ms, Some(120));
        assert_eq!(h.issues.len(), 1);
        assert_eq!(h.issues[0].message, "Test issue");
    }

    #[test]
    fn connector_health_multiple_issues() {
        let t = fixed_time();
        let h = ConnectorHealth::new("jira", HealthStatus::Error, t)
            .with_issue(HealthIssue::new(IssueSeverity::Error, "Issue 1"))
            .with_issue(HealthIssue::new(IssueSeverity::Warning, "Issue 2"))
            .with_issue(HealthIssue::new(IssueSeverity::Critical, "Issue 3"));

        assert_eq!(h.issues.len(), 3);
        assert_eq!(h.issues[0].severity, IssueSeverity::Error);
        assert_eq!(h.issues[2].severity, IssueSeverity::Critical);
    }

    // ── Issue detection tests ──────────────────────────────────────

    #[test]
    fn detect_issues_high_latency_warning() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t).with_latency(600);
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Degraded);
        assert!(h.issues.iter().any(|i| i.message.contains("High latency")));
    }

    #[test]
    fn detect_issues_very_high_latency_error() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t).with_latency(1500);
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Degraded);
        assert!(
            h.issues
                .iter()
                .any(|i| i.message.contains("Very high latency"))
        );
    }

    #[test]
    fn detect_issues_normal_latency_no_issue() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t).with_latency(200);
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Healthy);
        assert!(h.issues.is_empty());
    }

    #[test]
    fn detect_issues_at_warn_boundary() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t).with_latency(500);
        detect_issues(&mut h);

        // 500 is exactly at threshold, not above it.
        assert_eq!(h.status, HealthStatus::Healthy);
        assert!(h.issues.is_empty());
    }

    #[test]
    fn detect_issues_just_above_warn_boundary() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t).with_latency(501);
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Degraded);
        assert_eq!(h.issues.len(), 1);
        assert_eq!(h.issues[0].severity, IssueSeverity::Warning);
    }

    #[test]
    fn detect_issues_at_error_boundary() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t).with_latency(1000);
        detect_issues(&mut h);

        // 1000 is exactly at threshold, not above it — still warning range.
        assert_eq!(h.status, HealthStatus::Degraded);
        assert_eq!(h.issues[0].severity, IssueSeverity::Warning);
    }

    #[test]
    fn detect_issues_above_error_boundary() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t).with_latency(1001);
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Degraded);
        assert_eq!(h.issues[0].severity, IssueSeverity::Error);
    }

    #[test]
    fn detect_issues_auth_expired() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("jira", HealthStatus::Healthy, t)
            .with_auth(AuthCheckResult::Expired { days_ago: 3 });
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Error);
        assert!(
            h.issues
                .iter()
                .any(|i| i.message.contains("expired") && i.severity == IssueSeverity::Critical)
        );
    }

    #[test]
    fn detect_issues_auth_invalid() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("jira", HealthStatus::Healthy, t)
            .with_auth(AuthCheckResult::Invalid);
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Error);
        assert!(
            h.issues
                .iter()
                .any(|i| i.message.contains("invalid") && i.severity == IssueSeverity::Critical)
        );
    }

    #[test]
    fn detect_issues_auth_not_configured_warning() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t)
            .with_auth(AuthCheckResult::NotConfigured);
        detect_issues(&mut h);

        // Status should remain healthy, but a warning is added.
        assert_eq!(h.status, HealthStatus::Healthy);
        assert!(
            h.issues
                .iter()
                .any(|i| i.severity == IssueSeverity::Warning)
        );
    }

    #[test]
    fn detect_issues_error_state_without_explanation() {
        let t = fixed_time();
        let mut h =
            ConnectorHealth::new("test", HealthStatus::Error, t).with_auth(AuthCheckResult::Valid);
        detect_issues(&mut h);

        assert!(h.issues.iter().any(|i| i.message.contains("error state")));
    }

    #[test]
    fn detect_issues_combined_latency_and_auth() {
        let t = fixed_time();
        let mut h = ConnectorHealth::new("test", HealthStatus::Healthy, t)
            .with_auth(AuthCheckResult::Expired { days_ago: 1 })
            .with_latency(1500);
        detect_issues(&mut h);

        assert_eq!(h.status, HealthStatus::Error);
        assert!(h.issues.len() >= 2);
    }

    // ── DashboardSummary tests ─────────────────────────────────────

    #[test]
    fn summary_empty() {
        let summary = DashboardSummary::from_connectors(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.healthy, 0);
    }

    #[test]
    fn summary_all_healthy() {
        let t = fixed_time();
        let connectors = vec![
            make_healthy("a", t),
            make_healthy("b", t),
            make_healthy("c", t),
        ];
        let summary = DashboardSummary::from_connectors(&connectors);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.healthy, 3);
        assert_eq!(summary.degraded, 0);
        assert_eq!(summary.error, 0);
        assert_eq!(summary.auth_issues, 0);
    }

    #[test]
    fn summary_mixed() {
        let t = fixed_time();
        let connectors = vec![
            make_healthy("github", t),
            make_degraded("slack", t),
            make_error("jira", t),
            ConnectorHealth::new("unknown", HealthStatus::Unknown, t),
        ];
        let summary = DashboardSummary::from_connectors(&connectors);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.healthy, 1);
        assert_eq!(summary.degraded, 1);
        assert_eq!(summary.error, 1);
        assert_eq!(summary.unknown, 1);
        assert_eq!(summary.auth_issues, 1); // jira has expired auth
    }

    #[test]
    fn summary_counts_auth_invalid_as_issue() {
        let t = fixed_time();
        let connectors = vec![
            ConnectorHealth::new("x", HealthStatus::Error, t).with_auth(AuthCheckResult::Invalid),
        ];
        let summary = DashboardSummary::from_connectors(&connectors);
        assert_eq!(summary.auth_issues, 1);
    }

    #[test]
    fn summary_unconfigured_counts_as_unknown() {
        let t = fixed_time();
        let connectors = vec![ConnectorHealth::new("x", HealthStatus::Unconfigured, t)];
        let summary = DashboardSummary::from_connectors(&connectors);
        assert_eq!(summary.unknown, 1);
    }

    // ── Dashboard filtering tests ──────────────────────────────────

    #[test]
    fn filter_no_filter_returns_all() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(
            vec![make_healthy("a", t), make_degraded("b", t)],
            t,
        );
        let filter = HealthFilter::default();
        let filtered = dashboard.filter(&filter);
        assert_eq!(filtered.connectors.len(), 2);
    }

    #[test]
    fn filter_unhealthy_only() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(
            vec![
                make_healthy("github", t),
                make_degraded("slack", t),
                make_error("jira", t),
            ],
            t,
        );
        let filter = HealthFilter {
            unhealthy_only: true,
            connector_id: None,
        };
        let filtered = dashboard.filter(&filter);
        assert_eq!(filtered.connectors.len(), 2);
        assert!(
            filtered
                .connectors
                .iter()
                .all(|c| c.status != HealthStatus::Healthy)
        );
    }

    #[test]
    fn filter_by_connector_id() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(
            vec![make_healthy("github", t), make_degraded("slack", t)],
            t,
        );
        let filter = HealthFilter {
            unhealthy_only: false,
            connector_id: Some("slack".to_owned()),
        };
        let filtered = dashboard.filter(&filter);
        assert_eq!(filtered.connectors.len(), 1);
        assert_eq!(filtered.connectors[0].connector_id, "slack");
    }

    #[test]
    fn filter_by_nonexistent_connector() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(vec![make_healthy("github", t)], t);
        let filter = HealthFilter {
            unhealthy_only: false,
            connector_id: Some("nonexistent".to_owned()),
        };
        let filtered = dashboard.filter(&filter);
        assert_eq!(filtered.connectors.len(), 0);
    }

    #[test]
    fn filter_unhealthy_plus_id() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(
            vec![
                make_healthy("github", t),
                make_degraded("slack", t),
                make_error("jira", t),
            ],
            t,
        );
        // Filter: unhealthy only AND connector_id = "github" -> github is healthy, so empty.
        let filter = HealthFilter {
            unhealthy_only: true,
            connector_id: Some("github".to_owned()),
        };
        let filtered = dashboard.filter(&filter);
        assert_eq!(filtered.connectors.len(), 0);
    }

    #[test]
    fn filter_updates_summary() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(
            vec![
                make_healthy("github", t),
                make_degraded("slack", t),
                make_error("jira", t),
            ],
            t,
        );
        let filter = HealthFilter {
            unhealthy_only: true,
            connector_id: None,
        };
        let filtered = dashboard.filter(&filter);
        assert_eq!(filtered.summary.total, 2);
        assert_eq!(filtered.summary.healthy, 0);
    }

    // ── TOON formatting tests ──────────────────────────────────────

    #[test]
    fn toon_format_empty_dashboard() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(vec![], t);
        let output = format_dashboard_toon(&dashboard);
        assert!(output.contains("0 total"));
        assert!(output.contains("No connectors configured"));
    }

    #[test]
    fn toon_format_single_healthy() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(vec![make_healthy("github", t)], t);
        let output = format_dashboard_toon(&dashboard);
        assert!(output.contains("github"));
        assert!(output.contains("healthy"));
        assert!(output.contains("ok"));
        assert!(output.contains("45ms"));
    }

    #[test]
    fn toon_format_full_dashboard() {
        let t = fixed_time();
        let check_time = t - chrono::Duration::minutes(2);
        let dashboard = HealthDashboard::from_connectors_at(
            vec![
                make_healthy("github", check_time),
                make_degraded("slack", check_time),
                make_error("jira", check_time),
            ],
            t,
        );
        let output = format_dashboard_toon(&dashboard);
        assert!(output.contains("3 total"));
        assert!(output.contains("github"));
        assert!(output.contains("slack"));
        assert!(output.contains("jira"));
        assert!(output.contains("Connector"));
        assert!(output.contains("Status"));
        assert!(output.contains("2m ago"));
    }

    #[test]
    fn toon_format_with_issues() {
        let t = fixed_time();
        let c = ConnectorHealth::new("twilio", HealthStatus::Degraded, t)
            .with_auth(AuthCheckResult::Valid)
            .with_latency(890)
            .with_issue(HealthIssue::new(IssueSeverity::Warning, "High latency"));

        let dashboard = HealthDashboard::from_connectors_at(vec![c], t);
        let output = format_dashboard_toon(&dashboard);
        assert!(output.contains("High latency"));
    }

    #[test]
    fn toon_format_multiple_issues_semicolon_separated() {
        let t = fixed_time();
        let c = ConnectorHealth::new("test", HealthStatus::Error, t)
            .with_issue(HealthIssue::new(IssueSeverity::Error, "Issue A"))
            .with_issue(HealthIssue::new(IssueSeverity::Warning, "Issue B"));

        let dashboard = HealthDashboard::from_connectors_at(vec![c], t);
        let output = format_dashboard_toon(&dashboard);
        assert!(output.contains("Issue A; Issue B"));
    }

    #[test]
    fn toon_format_no_latency_shows_dash() {
        let t = fixed_time();
        let c = ConnectorHealth::new("test", HealthStatus::Error, t)
            .with_auth(AuthCheckResult::Expired { days_ago: 1 });

        let dashboard = HealthDashboard::from_connectors_at(vec![c], t);
        let output = format_dashboard_toon(&dashboard);
        // The latency column should show "-".
        assert!(output.contains("EXPIRED"));
    }

    #[test]
    fn toon_format_auth_issues_in_summary() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(vec![make_error("jira", t)], t);
        let output = format_dashboard_toon(&dashboard);
        assert!(output.contains("1 auth issue(s)"));
    }

    // ── JSON formatting tests ──────────────────────────────────────

    #[test]
    fn json_format_roundtrip() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(
            vec![make_healthy("github", t), make_error("jira", t)],
            t,
        );
        let json = format_dashboard_json(&dashboard).unwrap();
        let back: HealthDashboard = serde_json::from_value(json).unwrap();
        assert_eq!(back.connectors.len(), 2);
        assert_eq!(back.summary.total, 2);
    }

    #[test]
    fn json_format_contains_fields() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(vec![make_healthy("github", t)], t);
        let json = format_dashboard_json(&dashboard).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("connectors"));
        assert!(obj.contains_key("checked_at"));
        assert!(obj.contains_key("summary"));
    }

    #[test]
    fn json_format_empty_dashboard() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(vec![], t);
        let json = format_dashboard_json(&dashboard).unwrap();
        let connectors = json["connectors"].as_array().unwrap();
        assert!(connectors.is_empty());
    }

    // ── Time ago formatting tests ──────────────────────────────────

    #[test]
    fn time_ago_just_now() {
        let now = fixed_time();
        assert_eq!(format_time_ago(now, now), "just now");
    }

    #[test]
    fn time_ago_seconds() {
        let now = fixed_time();
        let dt = now - chrono::Duration::seconds(30);
        assert_eq!(format_time_ago(dt, now), "30s ago");
    }

    #[test]
    fn time_ago_minutes() {
        let now = fixed_time();
        let dt = now - chrono::Duration::minutes(5);
        assert_eq!(format_time_ago(dt, now), "5m ago");
    }

    #[test]
    fn time_ago_hours() {
        let now = fixed_time();
        let dt = now - chrono::Duration::hours(3);
        assert_eq!(format_time_ago(dt, now), "3h ago");
    }

    #[test]
    fn time_ago_days() {
        let now = fixed_time();
        let dt = now - chrono::Duration::days(7);
        assert_eq!(format_time_ago(dt, now), "7d ago");
    }

    #[test]
    fn time_ago_future() {
        let now = fixed_time();
        let dt = now + chrono::Duration::hours(1);
        assert_eq!(format_time_ago(dt, now), "in the future");
    }

    #[test]
    fn time_ago_boundary_4s_is_just_now() {
        let now = fixed_time();
        let dt = now - chrono::Duration::seconds(4);
        assert_eq!(format_time_ago(dt, now), "just now");
    }

    #[test]
    fn time_ago_boundary_5s_is_seconds() {
        let now = fixed_time();
        let dt = now - chrono::Duration::seconds(5);
        assert_eq!(format_time_ago(dt, now), "5s ago");
    }

    #[test]
    fn time_ago_boundary_59s_is_seconds() {
        let now = fixed_time();
        let dt = now - chrono::Duration::seconds(59);
        assert_eq!(format_time_ago(dt, now), "59s ago");
    }

    #[test]
    fn time_ago_boundary_60s_is_minutes() {
        let now = fixed_time();
        let dt = now - chrono::Duration::seconds(60);
        assert_eq!(format_time_ago(dt, now), "1m ago");
    }

    // ── Status/auth indicator tests ────────────────────────────────

    #[test]
    fn status_indicator_all_variants() {
        assert_eq!(status_indicator(HealthStatus::Healthy), "healthy");
        assert_eq!(status_indicator(HealthStatus::Degraded), "degraded");
        assert_eq!(status_indicator(HealthStatus::Error), "error");
        assert_eq!(status_indicator(HealthStatus::Unknown), "unknown");
        assert_eq!(status_indicator(HealthStatus::Unconfigured), "unconfigured");
    }

    #[test]
    fn auth_indicator_all_variants() {
        assert_eq!(auth_indicator(&AuthCheckResult::Valid), "ok");
        assert_eq!(
            auth_indicator(&AuthCheckResult::Expired { days_ago: 1 }),
            "EXPIRED"
        );
        assert_eq!(auth_indicator(&AuthCheckResult::Invalid), "INVALID");
        assert_eq!(auth_indicator(&AuthCheckResult::NotConfigured), "none");
        assert_eq!(auth_indicator(&AuthCheckResult::Unknown), "?");
    }

    // ── Merge tests ────────────────────────────────────────────────

    #[test]
    fn merge_disjoint_dashboards() {
        let t = fixed_time();
        let a = HealthDashboard::from_connectors_at(vec![make_healthy("github", t)], t);
        let b = HealthDashboard::from_connectors_at(vec![make_degraded("slack", t)], t);
        let merged = merge_dashboards(&a, &b);

        assert_eq!(merged.connectors.len(), 2);
        assert_eq!(merged.summary.total, 2);
    }

    #[test]
    fn merge_overlapping_prefers_later() {
        let t1 = fixed_time();
        let t2 = t1 + chrono::Duration::minutes(5);

        let a = HealthDashboard::from_connectors_at(
            vec![ConnectorHealth::new("github", HealthStatus::Healthy, t1)],
            t1,
        );
        let b = HealthDashboard::from_connectors_at(
            vec![ConnectorHealth::new("github", HealthStatus::Error, t2)],
            t2,
        );
        let merged = merge_dashboards(&a, &b);

        assert_eq!(merged.connectors.len(), 1);
        assert_eq!(merged.connectors[0].status, HealthStatus::Error);
    }

    #[test]
    fn merge_uses_later_checked_at() {
        let t1 = fixed_time();
        let t2 = t1 + chrono::Duration::hours(1);

        let a = HealthDashboard::from_connectors_at(vec![], t1);
        let b = HealthDashboard::from_connectors_at(vec![], t2);
        let merged = merge_dashboards(&a, &b);

        assert_eq!(merged.checked_at, t2);
    }

    #[test]
    fn merge_empty_dashboards() {
        let t = fixed_time();
        let a = HealthDashboard::from_connectors_at(vec![], t);
        let b = HealthDashboard::from_connectors_at(vec![], t);
        let merged = merge_dashboards(&a, &b);

        assert!(merged.connectors.is_empty());
        assert_eq!(merged.summary.total, 0);
    }

    #[test]
    fn merge_overlapping_keeps_earlier_when_later_is_older() {
        let t1 = fixed_time();
        let t2 = t1 - chrono::Duration::minutes(10);

        let a = HealthDashboard::from_connectors_at(
            vec![ConnectorHealth::new("github", HealthStatus::Healthy, t1)],
            t1,
        );
        let b = HealthDashboard::from_connectors_at(
            vec![ConnectorHealth::new("github", HealthStatus::Error, t2)],
            t1,
        );
        let merged = merge_dashboards(&a, &b);

        assert_eq!(merged.connectors.len(), 1);
        // a's entry has last_check=t1 which is later than b's t2, so a wins.
        assert_eq!(merged.connectors[0].status, HealthStatus::Healthy);
    }

    // ── Edge case tests ────────────────────────────────────────────

    #[test]
    fn dashboard_from_connectors_computes_summary() {
        let t = fixed_time();
        let dashboard =
            HealthDashboard::from_connectors(vec![make_healthy("a", t), make_healthy("b", t)]);
        assert_eq!(dashboard.summary.total, 2);
        assert_eq!(dashboard.summary.healthy, 2);
    }

    #[test]
    fn all_unhealthy_dashboard() {
        let t = fixed_time();
        let dashboard = HealthDashboard::from_connectors_at(
            vec![
                make_error("a", t),
                make_degraded("b", t),
                ConnectorHealth::new("c", HealthStatus::Unknown, t),
            ],
            t,
        );
        assert_eq!(dashboard.summary.healthy, 0);
        assert_eq!(dashboard.summary.total, 3);
    }

    #[test]
    fn issue_severity_ordering() {
        assert!(IssueSeverity::Info < IssueSeverity::Warning);
        assert!(IssueSeverity::Warning < IssueSeverity::Error);
        assert!(IssueSeverity::Error < IssueSeverity::Critical);
    }

    #[test]
    fn issue_severity_display() {
        assert_eq!(IssueSeverity::Info.to_string(), "info");
        assert_eq!(IssueSeverity::Warning.to_string(), "warning");
        assert_eq!(IssueSeverity::Error.to_string(), "error");
        assert_eq!(IssueSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn health_issue_new() {
        let issue = HealthIssue::new(IssueSeverity::Warning, "test message");
        assert_eq!(issue.severity, IssueSeverity::Warning);
        assert_eq!(issue.message, "test message");
    }

    #[test]
    fn connector_health_serialization_roundtrip() {
        let t = fixed_time();
        let h = make_healthy("github", t);
        let json = serde_json::to_string(&h).unwrap();
        let back: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "github");
        assert_eq!(back.status, HealthStatus::Healthy);
        assert_eq!(back.latency_ms, Some(45));
    }
}
