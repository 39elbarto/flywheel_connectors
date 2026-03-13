//! Fleet-wide health aggregation and bulk cohort operations.
//!
//! Provides types and functions for aggregating health status across all
//! connectors in a fleet, selecting cohorts by various criteria, planning
//! bulk operations with wave-based concurrency, and enforcing health thresholds.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── Connector state ─────────────────────────────────────────────────────

/// State of an individual connector in the fleet.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorState {
    /// Connector is running and healthy.
    Healthy,
    /// Connector is running but experiencing issues.
    Degraded,
    /// Connector has failed and is not operational.
    Failed,
    /// Connector state cannot be determined.
    Unknown,
    /// Connector is stopped.
    Stopped,
    /// Connector is starting up.
    Starting,
}

impl fmt::Display for ConnectorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => f.write_str("healthy"),
            Self::Degraded => f.write_str("degraded"),
            Self::Failed => f.write_str("failed"),
            Self::Unknown => f.write_str("unknown"),
            Self::Stopped => f.write_str("stopped"),
            Self::Starting => f.write_str("starting"),
        }
    }
}

// ── Connector health ────────────────────────────────────────────────────

/// Health snapshot for a single connector in the fleet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorHealth {
    /// Canonical connector identifier.
    pub connector_id: String,
    /// Current state.
    pub state: ConnectorState,
    /// Uptime in seconds.
    pub uptime: u64,
    /// ISO-8601 timestamp of last health check.
    pub last_check: String,
    /// Error rate as a fraction (0.0 to 1.0).
    pub error_rate: f64,
    /// Median latency in milliseconds.
    pub latency_p50: f64,
    /// 99th percentile latency in milliseconds.
    pub latency_p99: f64,
    /// Optional tags for cohort selection.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional archetype classification.
    #[serde(default)]
    pub archetype: String,
}

impl ConnectorHealth {
    /// Create a healthy connector with default metrics.
    #[must_use]
    pub fn healthy(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            state: ConnectorState::Healthy,
            uptime: 86400,
            last_check: "2026-03-12T00:00:00Z".to_string(),
            error_rate: 0.0,
            latency_p50: 50.0,
            latency_p99: 200.0,
            tags: Vec::new(),
            archetype: String::new(),
        }
    }

    /// Create a degraded connector.
    #[must_use]
    pub fn degraded(connector_id: impl Into<String>) -> Self {
        Self {
            state: ConnectorState::Degraded,
            error_rate: 0.05,
            latency_p50: 200.0,
            latency_p99: 800.0,
            ..Self::healthy(connector_id)
        }
    }

    /// Create a failed connector.
    #[must_use]
    pub fn failed(connector_id: impl Into<String>) -> Self {
        Self {
            state: ConnectorState::Failed,
            error_rate: 1.0,
            latency_p50: 0.0,
            latency_p99: 0.0,
            uptime: 0,
            ..Self::healthy(connector_id)
        }
    }

    /// Builder: set tags.
    #[must_use]
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Builder: set archetype.
    #[must_use]
    pub fn with_archetype(mut self, archetype: impl Into<String>) -> Self {
        self.archetype = archetype.into();
        self
    }

    /// Builder: set error rate.
    #[must_use]
    pub const fn with_error_rate(mut self, rate: f64) -> Self {
        self.error_rate = rate;
        self
    }

    /// Builder: set latencies.
    #[must_use]
    pub const fn with_latency(mut self, p50: f64, p99: f64) -> Self {
        self.latency_p50 = p50;
        self.latency_p99 = p99;
        self
    }

    /// Builder: set uptime.
    #[must_use]
    pub const fn with_uptime(mut self, uptime: u64) -> Self {
        self.uptime = uptime;
        self
    }
}

// ── Fleet status ────────────────────────────────────────────────────────

/// Aggregated fleet-wide status.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FleetStatus {
    /// Total number of connectors in the fleet.
    pub total_connectors: usize,
    /// Count of connectors grouped by state.
    pub by_state: HashMap<String, usize>,
    /// Number of healthy connectors.
    pub healthy: usize,
    /// Number of degraded connectors.
    pub degraded: usize,
    /// Number of failed connectors.
    pub failed: usize,
    /// Number of connectors in unknown state.
    pub unknown: usize,
}

// ── Cohort selector ─────────────────────────────────────────────────────

/// Criteria for selecting a subset of connectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortSelector {
    /// Select all connectors.
    All,
    /// Select connectors in specific states.
    ByState { states: Vec<String> },
    /// Select connectors with specific tags.
    ByTag { tags: Vec<String> },
    /// Select connectors whose ID matches a substring pattern.
    ByPattern { pattern: String },
    /// Select connectors of a specific archetype.
    ByArchetype { archetype: String },
}

// ── Bulk operation ──────────────────────────────────────────────────────

/// Specification for a bulk operation across multiple connectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BulkOperation {
    /// Action to perform (e.g. "restart", "update", "stop").
    pub action: String,
    /// Target connector IDs.
    pub targets: Vec<String>,
    /// If true, only simulate the operation.
    pub dry_run: bool,
    /// Maximum number of concurrent operations.
    pub concurrency: usize,
    /// Error handling strategy: "abort", "continue", or "skip".
    pub on_error: String,
}

// ── Bulk result ─────────────────────────────────────────────────────────

/// Outcome of a bulk operation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BulkResult {
    /// Total number of targets.
    pub total: usize,
    /// Number that succeeded.
    pub succeeded: usize,
    /// Number that failed.
    pub failed: usize,
    /// Number that were skipped.
    pub skipped: usize,
    /// Per-connector results.
    pub results: Vec<ConnectorBulkResult>,
}

/// Result for a single connector in a bulk operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorBulkResult {
    /// Connector identifier.
    pub connector_id: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// How long the operation took.
    pub duration: Duration,
    /// Error message if the operation failed.
    pub error: Option<String>,
}

// ── Health threshold ────────────────────────────────────────────────────

/// Threshold configuration for health violation detection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthThreshold {
    /// Maximum acceptable error rate (0.0 to 1.0).
    pub error_rate_max: f64,
    /// Maximum acceptable p99 latency in milliseconds.
    pub latency_p99_max: f64,
    /// Minimum required uptime in seconds.
    pub min_uptime: u64,
}

impl Default for HealthThreshold {
    fn default() -> Self {
        Self {
            error_rate_max: 0.01,
            latency_p99_max: 1000.0,
            min_uptime: 3600,
        }
    }
}

// ── Fleet aggregation ───────────────────────────────────────────────────

/// Aggregate health data from individual connectors into a fleet status summary.
#[must_use]
pub fn aggregate_fleet_status(connectors: &[ConnectorHealth]) -> FleetStatus {
    let mut status = FleetStatus {
        total_connectors: connectors.len(),
        ..FleetStatus::default()
    };

    for c in connectors {
        let state_key = c.state.to_string();
        *status.by_state.entry(state_key).or_insert(0) += 1;

        match c.state {
            ConnectorState::Healthy => status.healthy += 1,
            ConnectorState::Degraded => status.degraded += 1,
            ConnectorState::Failed => status.failed += 1,
            ConnectorState::Unknown | ConnectorState::Stopped | ConnectorState::Starting => {
                status.unknown += 1;
            }
        }
    }

    status
}

// ── Cohort selection ────────────────────────────────────────────────────

/// Select connectors matching the given cohort selector.
#[must_use]
pub fn select_cohort<'a>(
    connectors: &'a [ConnectorHealth],
    selector: &CohortSelector,
) -> Vec<&'a ConnectorHealth> {
    match selector {
        CohortSelector::All => connectors.iter().collect(),
        CohortSelector::ByState { states } => connectors
            .iter()
            .filter(|c| states.iter().any(|s| s == &c.state.to_string()))
            .collect(),
        CohortSelector::ByTag { tags } => connectors
            .iter()
            .filter(|c| tags.iter().any(|t| c.tags.contains(t)))
            .collect(),
        CohortSelector::ByPattern { pattern } => connectors
            .iter()
            .filter(|c| c.connector_id.contains(pattern.as_str()))
            .collect(),
        CohortSelector::ByArchetype { archetype } => connectors
            .iter()
            .filter(|c| c.archetype == *archetype)
            .collect(),
    }
}

// ── Wave planning ───────────────────────────────────────────────────────

/// Plan execution waves for a bulk operation based on concurrency limits.
/// Returns a list of waves, each containing connector IDs to process in parallel.
#[must_use]
pub fn plan_bulk_operation(
    op: &BulkOperation,
    connectors: &[ConnectorHealth],
) -> Vec<Vec<String>> {
    // Filter to only connectors that are in the target list
    let target_ids: Vec<&String> = op
        .targets
        .iter()
        .filter(|t| connectors.iter().any(|c| &c.connector_id == *t))
        .collect();

    if target_ids.is_empty() || op.concurrency == 0 {
        return Vec::new();
    }

    let mut waves = Vec::new();
    let mut current_wave = Vec::new();

    for id in &target_ids {
        current_wave.push((*id).clone());
        if current_wave.len() >= op.concurrency {
            waves.push(current_wave);
            current_wave = Vec::new();
        }
    }

    if !current_wave.is_empty() {
        waves.push(current_wave);
    }

    waves
}

// ── Threshold checking ──────────────────────────────────────────────────

/// Check a connector's health against thresholds, returning a list of violations.
#[must_use]
pub fn check_thresholds(
    health: &ConnectorHealth,
    thresholds: &HealthThreshold,
) -> Vec<String> {
    let mut violations = Vec::new();

    if health.error_rate > thresholds.error_rate_max {
        violations.push(format!(
            "error_rate {:.4} exceeds max {:.4}",
            health.error_rate, thresholds.error_rate_max
        ));
    }

    if health.latency_p99 > thresholds.latency_p99_max {
        violations.push(format!(
            "latency_p99 {:.1}ms exceeds max {:.1}ms",
            health.latency_p99, thresholds.latency_p99_max
        ));
    }

    if health.uptime < thresholds.min_uptime {
        violations.push(format!(
            "uptime {}s below minimum {}s",
            health.uptime, thresholds.min_uptime
        ));
    }

    violations
}

// ── Fleet score ─────────────────────────────────────────────────────────

/// Compute a fleet health score from 0.0 (all failed) to 1.0 (all healthy).
/// Degraded connectors count as 0.5, unknown as 0.25.
#[must_use]
pub fn compute_fleet_score(status: &FleetStatus) -> f64 {
    if status.total_connectors == 0 {
        return 1.0;
    }

    let score = (status.healthy as f64)
        + (status.degraded as f64 * 0.5)
        + (status.unknown as f64 * 0.25);
    // failed contributes 0.0

    score / status.total_connectors as f64
}

// ── Formatting (TOON-style) ─────────────────────────────────────────────

/// Format the fleet status as a human-readable dashboard.
#[must_use]
pub fn format_fleet_status_toon(status: &FleetStatus) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Fleet Health Dashboard ===");
    let _ = writeln!(out, "Total connectors: {}", status.total_connectors);
    let _ = writeln!(
        out, "  Healthy:  {} ({:.0}%)",
        status.healthy,
        pct(status.healthy, status.total_connectors)
    );
    let _ = writeln!(
        out, "  Degraded: {} ({:.0}%)",
        status.degraded,
        pct(status.degraded, status.total_connectors)
    );
    let _ = writeln!(
        out, "  Failed:   {} ({:.0}%)",
        status.failed,
        pct(status.failed, status.total_connectors)
    );
    let _ = writeln!(
        out, "  Unknown:  {} ({:.0}%)",
        status.unknown,
        pct(status.unknown, status.total_connectors)
    );

    let score = compute_fleet_score(status);
    let _ = writeln!(out, "Fleet score: {:.1}%", score * 100.0);
    out
}

/// Format a bulk result for human-readable display.
#[must_use]
pub fn format_bulk_result_toon(result: &BulkResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Bulk Operation Result ===");
    let _ = writeln!(out, "Total:     {}", result.total);
    let _ = writeln!(out, "Succeeded: {}", result.succeeded);
    let _ = writeln!(out, "Failed:    {}", result.failed);
    let _ = writeln!(out, "Skipped:   {}", result.skipped);

    if !result.results.is_empty() {
        let _ = writeln!(out, "Details:");
        for r in &result.results {
            let status = if r.success { "OK" } else { "FAIL" };
            let _ = write!(
                out, "  {} [{}] {:.2}s",
                r.connector_id,
                status,
                r.duration.as_secs_f64()
            );
            if let Some(err) = &r.error {
                let _ = write!(out, " -- {err}");
            }
            out.push('\n');
        }
    }
    out
}

/// Format a single connector's health for human-readable display.
#[must_use]
pub fn format_connector_health_toon(health: &ConnectorHealth) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[{}] {}", health.state, health.connector_id);
    let _ = writeln!(out, "  Uptime:      {}s", health.uptime);
    let _ = writeln!(out, "  Error rate:  {:.4}", health.error_rate);
    let _ = writeln!(out, "  Latency p50: {:.1}ms", health.latency_p50);
    let _ = writeln!(out, "  Latency p99: {:.1}ms", health.latency_p99);
    let _ = writeln!(out, "  Last check:  {}", health.last_check);
    out
}

/// Helper: compute percentage, guarding against division by zero.
fn pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (part as f64 / total as f64) * 100.0
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn fleet_connectors() -> Vec<ConnectorHealth> {
        vec![
            ConnectorHealth::healthy("github"),
            ConnectorHealth::healthy("slack"),
            ConnectorHealth::degraded("jira"),
            ConnectorHealth::failed("pagerduty"),
            ConnectorHealth {
                state: ConnectorState::Unknown,
                ..ConnectorHealth::healthy("custom")
            },
        ]
    }

    fn sample_thresholds() -> HealthThreshold {
        HealthThreshold {
            error_rate_max: 0.01,
            latency_p99_max: 500.0,
            min_uptime: 3600,
        }
    }

    // ── ConnectorState Display ─────────────────────────────────────────

    #[test]
    fn state_display_healthy() {
        assert_eq!(ConnectorState::Healthy.to_string(), "healthy");
    }

    #[test]
    fn state_display_degraded() {
        assert_eq!(ConnectorState::Degraded.to_string(), "degraded");
    }

    #[test]
    fn state_display_failed() {
        assert_eq!(ConnectorState::Failed.to_string(), "failed");
    }

    #[test]
    fn state_display_unknown() {
        assert_eq!(ConnectorState::Unknown.to_string(), "unknown");
    }

    #[test]
    fn state_display_stopped() {
        assert_eq!(ConnectorState::Stopped.to_string(), "stopped");
    }

    #[test]
    fn state_display_starting() {
        assert_eq!(ConnectorState::Starting.to_string(), "starting");
    }

    // ── ConnectorHealth constructors ───────────────────────────────────

    #[test]
    fn healthy_constructor_defaults() {
        let c = ConnectorHealth::healthy("github");
        assert_eq!(c.connector_id, "github");
        assert_eq!(c.state, ConnectorState::Healthy);
        assert_eq!(c.error_rate, 0.0);
        assert!(c.uptime > 0);
    }

    #[test]
    fn degraded_constructor_defaults() {
        let c = ConnectorHealth::degraded("slack");
        assert_eq!(c.state, ConnectorState::Degraded);
        assert!(c.error_rate > 0.0);
    }

    #[test]
    fn failed_constructor_defaults() {
        let c = ConnectorHealth::failed("pagerduty");
        assert_eq!(c.state, ConnectorState::Failed);
        assert_eq!(c.error_rate, 1.0);
        assert_eq!(c.uptime, 0);
    }

    #[test]
    fn builder_with_tags() {
        let c = ConnectorHealth::healthy("github")
            .with_tags(vec!["prod".to_string(), "critical".to_string()]);
        assert_eq!(c.tags.len(), 2);
        assert!(c.tags.contains(&"prod".to_string()));
    }

    #[test]
    fn builder_with_archetype() {
        let c = ConnectorHealth::healthy("github").with_archetype("api-gateway");
        assert_eq!(c.archetype, "api-gateway");
    }

    #[test]
    fn builder_with_error_rate() {
        let c = ConnectorHealth::healthy("github").with_error_rate(0.05);
        assert!((c.error_rate - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn builder_with_latency() {
        let c = ConnectorHealth::healthy("github").with_latency(10.0, 100.0);
        assert!((c.latency_p50 - 10.0).abs() < f64::EPSILON);
        assert!((c.latency_p99 - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn builder_with_uptime() {
        let c = ConnectorHealth::healthy("github").with_uptime(999);
        assert_eq!(c.uptime, 999);
    }

    // ── Fleet aggregation ──────────────────────────────────────────────

    #[test]
    fn aggregate_empty_fleet() {
        let status = aggregate_fleet_status(&[]);
        assert_eq!(status.total_connectors, 0);
        assert_eq!(status.healthy, 0);
    }

    #[test]
    fn aggregate_all_healthy() {
        let connectors = vec![
            ConnectorHealth::healthy("a"),
            ConnectorHealth::healthy("b"),
        ];
        let status = aggregate_fleet_status(&connectors);
        assert_eq!(status.total_connectors, 2);
        assert_eq!(status.healthy, 2);
        assert_eq!(status.degraded, 0);
        assert_eq!(status.failed, 0);
    }

    #[test]
    fn aggregate_mixed_fleet() {
        let status = aggregate_fleet_status(&fleet_connectors());
        assert_eq!(status.total_connectors, 5);
        assert_eq!(status.healthy, 2);
        assert_eq!(status.degraded, 1);
        assert_eq!(status.failed, 1);
        assert_eq!(status.unknown, 1);
    }

    #[test]
    fn aggregate_by_state_map() {
        let status = aggregate_fleet_status(&fleet_connectors());
        assert_eq!(status.by_state.get("healthy"), Some(&2));
        assert_eq!(status.by_state.get("degraded"), Some(&1));
        assert_eq!(status.by_state.get("failed"), Some(&1));
        assert_eq!(status.by_state.get("unknown"), Some(&1));
    }

    #[test]
    fn aggregate_single_connector() {
        let connectors = vec![ConnectorHealth::failed("x")];
        let status = aggregate_fleet_status(&connectors);
        assert_eq!(status.total_connectors, 1);
        assert_eq!(status.failed, 1);
        assert_eq!(status.healthy, 0);
    }

    #[test]
    fn aggregate_stopped_counts_as_unknown() {
        let connectors = vec![ConnectorHealth {
            state: ConnectorState::Stopped,
            ..ConnectorHealth::healthy("x")
        }];
        let status = aggregate_fleet_status(&connectors);
        assert_eq!(status.unknown, 1);
    }

    #[test]
    fn aggregate_starting_counts_as_unknown() {
        let connectors = vec![ConnectorHealth {
            state: ConnectorState::Starting,
            ..ConnectorHealth::healthy("x")
        }];
        let status = aggregate_fleet_status(&connectors);
        assert_eq!(status.unknown, 1);
    }

    // ── Cohort selection ───────────────────────────────────────────────

    #[test]
    fn select_all() {
        let conns = fleet_connectors();
        let selected = select_cohort(&conns, &CohortSelector::All);
        assert_eq!(selected.len(), conns.len());
    }

    #[test]
    fn select_by_state_healthy() {
        let conns = fleet_connectors();
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByState { states: vec!["healthy".to_string()] },
        );
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_by_state_failed() {
        let conns = fleet_connectors();
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByState { states: vec!["failed".to_string()] },
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].connector_id, "pagerduty");
    }

    #[test]
    fn select_by_state_multiple() {
        let conns = fleet_connectors();
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByState { states: vec!["healthy".to_string(), "degraded".to_string()] },
        );
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn select_by_state_no_match() {
        let conns = fleet_connectors();
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByState { states: vec!["stopped".to_string()] },
        );
        assert!(selected.is_empty());
    }

    #[test]
    fn select_by_tag() {
        let conns = vec![
            ConnectorHealth::healthy("github").with_tags(vec!["prod".to_string()]),
            ConnectorHealth::healthy("slack").with_tags(vec!["staging".to_string()]),
            ConnectorHealth::healthy("jira").with_tags(vec!["prod".to_string()]),
        ];
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByTag { tags: vec!["prod".to_string()] },
        );
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_by_tag_no_match() {
        let conns = vec![
            ConnectorHealth::healthy("github").with_tags(vec!["prod".to_string()]),
        ];
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByTag { tags: vec!["nonexistent".to_string()] },
        );
        assert!(selected.is_empty());
    }

    #[test]
    fn select_by_pattern() {
        let conns = fleet_connectors();
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByPattern { pattern: "git".to_string() },
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].connector_id, "github");
    }

    #[test]
    fn select_by_pattern_multiple_match() {
        let conns = vec![
            ConnectorHealth::healthy("aws-s3"),
            ConnectorHealth::healthy("aws-lambda"),
            ConnectorHealth::healthy("gcp-bigquery"),
        ];
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByPattern { pattern: "aws".to_string() },
        );
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_by_archetype() {
        let conns = vec![
            ConnectorHealth::healthy("github").with_archetype("vcs"),
            ConnectorHealth::healthy("gitlab").with_archetype("vcs"),
            ConnectorHealth::healthy("slack").with_archetype("messaging"),
        ];
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByArchetype { archetype: "vcs".to_string() },
        );
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn select_by_archetype_no_match() {
        let conns = vec![
            ConnectorHealth::healthy("github").with_archetype("vcs"),
        ];
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByArchetype { archetype: "messaging".to_string() },
        );
        assert!(selected.is_empty());
    }

    // ── Wave planning ──────────────────────────────────────────────────

    #[test]
    fn plan_waves_basic() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "restart".to_string(),
            targets: vec!["github".to_string(), "slack".to_string(), "jira".to_string()],
            dry_run: false,
            concurrency: 2,
            on_error: "continue".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].len(), 2);
        assert_eq!(waves[1].len(), 1);
    }

    #[test]
    fn plan_waves_single_concurrency() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "restart".to_string(),
            targets: vec!["github".to_string(), "slack".to_string()],
            dry_run: false,
            concurrency: 1,
            on_error: "abort".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].len(), 1);
        assert_eq!(waves[1].len(), 1);
    }

    #[test]
    fn plan_waves_high_concurrency() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "update".to_string(),
            targets: vec!["github".to_string(), "slack".to_string()],
            dry_run: false,
            concurrency: 100,
            on_error: "continue".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 2);
    }

    #[test]
    fn plan_waves_empty_targets() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "restart".to_string(),
            targets: vec![],
            dry_run: false,
            concurrency: 2,
            on_error: "continue".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert!(waves.is_empty());
    }

    #[test]
    fn plan_waves_unknown_targets_filtered() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "restart".to_string(),
            targets: vec!["nonexistent".to_string()],
            dry_run: false,
            concurrency: 2,
            on_error: "continue".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert!(waves.is_empty());
    }

    #[test]
    fn plan_waves_zero_concurrency() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "restart".to_string(),
            targets: vec!["github".to_string()],
            dry_run: false,
            concurrency: 0,
            on_error: "continue".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert!(waves.is_empty());
    }

    #[test]
    fn plan_waves_mixed_known_unknown() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "restart".to_string(),
            targets: vec!["github".to_string(), "nonexistent".to_string(), "slack".to_string()],
            dry_run: false,
            concurrency: 5,
            on_error: "continue".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 2);
    }

    // ── Threshold checking ─────────────────────────────────────────────

    #[test]
    fn thresholds_healthy_no_violations() {
        let c = ConnectorHealth::healthy("github");
        let violations = check_thresholds(&c, &sample_thresholds());
        assert!(violations.is_empty());
    }

    #[test]
    fn thresholds_high_error_rate() {
        let c = ConnectorHealth::healthy("github").with_error_rate(0.05);
        let violations = check_thresholds(&c, &sample_thresholds());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("error_rate"));
    }

    #[test]
    fn thresholds_high_latency() {
        let c = ConnectorHealth::healthy("github").with_latency(50.0, 600.0);
        let violations = check_thresholds(&c, &sample_thresholds());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("latency_p99"));
    }

    #[test]
    fn thresholds_low_uptime() {
        let c = ConnectorHealth::healthy("github").with_uptime(100);
        let violations = check_thresholds(&c, &sample_thresholds());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("uptime"));
    }

    #[test]
    fn thresholds_multiple_violations() {
        let c = ConnectorHealth::healthy("github")
            .with_error_rate(0.1)
            .with_latency(50.0, 2000.0)
            .with_uptime(10);
        let violations = check_thresholds(&c, &sample_thresholds());
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn thresholds_exactly_at_limit_no_violation() {
        let c = ConnectorHealth::healthy("github")
            .with_error_rate(0.01)
            .with_latency(50.0, 500.0)
            .with_uptime(3600);
        let violations = check_thresholds(&c, &sample_thresholds());
        assert!(violations.is_empty());
    }

    #[test]
    fn thresholds_barely_over_error_rate() {
        let c = ConnectorHealth::healthy("github").with_error_rate(0.011);
        let violations = check_thresholds(&c, &sample_thresholds());
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn thresholds_default_values() {
        let t = HealthThreshold::default();
        assert!((t.error_rate_max - 0.01).abs() < f64::EPSILON);
        assert!((t.latency_p99_max - 1000.0).abs() < f64::EPSILON);
        assert_eq!(t.min_uptime, 3600);
    }

    // ── Fleet score ────────────────────────────────────────────────────

    #[test]
    fn fleet_score_all_healthy() {
        let status = FleetStatus {
            total_connectors: 3,
            healthy: 3,
            ..FleetStatus::default()
        };
        let score = compute_fleet_score(&status);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fleet_score_all_failed() {
        let status = FleetStatus {
            total_connectors: 3,
            failed: 3,
            ..FleetStatus::default()
        };
        let score = compute_fleet_score(&status);
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fleet_score_mixed() {
        let status = FleetStatus {
            total_connectors: 4,
            healthy: 2,
            degraded: 1,
            failed: 1,
            ..FleetStatus::default()
        };
        // (2 + 0.5 + 0) / 4 = 0.625
        let score = compute_fleet_score(&status);
        assert!((score - 0.625).abs() < 0.001);
    }

    #[test]
    fn fleet_score_empty_fleet() {
        let status = FleetStatus::default();
        let score = compute_fleet_score(&status);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fleet_score_all_degraded() {
        let status = FleetStatus {
            total_connectors: 2,
            degraded: 2,
            ..FleetStatus::default()
        };
        let score = compute_fleet_score(&status);
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn fleet_score_all_unknown() {
        let status = FleetStatus {
            total_connectors: 4,
            unknown: 4,
            ..FleetStatus::default()
        };
        let score = compute_fleet_score(&status);
        assert!((score - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn fleet_score_from_aggregated() {
        let conns = fleet_connectors();
        let status = aggregate_fleet_status(&conns);
        let score = compute_fleet_score(&status);
        // 2 healthy (2.0) + 1 degraded (0.5) + 1 failed (0.0) + 1 unknown (0.25) = 2.75 / 5 = 0.55
        assert!((score - 0.55).abs() < 0.001);
    }

    // ── Format fleet status ────────────────────────────────────────────

    #[test]
    fn format_fleet_status_has_title() {
        let status = aggregate_fleet_status(&fleet_connectors());
        let out = format_fleet_status_toon(&status);
        assert!(out.contains("Fleet Health Dashboard"));
    }

    #[test]
    fn format_fleet_status_shows_total() {
        let status = aggregate_fleet_status(&fleet_connectors());
        let out = format_fleet_status_toon(&status);
        assert!(out.contains("Total connectors: 5"));
    }

    #[test]
    fn format_fleet_status_shows_healthy_count() {
        let status = aggregate_fleet_status(&fleet_connectors());
        let out = format_fleet_status_toon(&status);
        assert!(out.contains("Healthy:  2"));
    }

    #[test]
    fn format_fleet_status_shows_score() {
        let status = aggregate_fleet_status(&fleet_connectors());
        let out = format_fleet_status_toon(&status);
        assert!(out.contains("Fleet score:"));
    }

    #[test]
    fn format_fleet_status_empty_fleet() {
        let status = aggregate_fleet_status(&[]);
        let out = format_fleet_status_toon(&status);
        assert!(out.contains("Total connectors: 0"));
    }

    // ── Format bulk result ─────────────────────────────────────────────

    #[test]
    fn format_bulk_result_basic() {
        let result = BulkResult {
            total: 3,
            succeeded: 2,
            failed: 1,
            skipped: 0,
            results: vec![
                ConnectorBulkResult {
                    connector_id: "github".to_string(),
                    success: true,
                    duration: Duration::from_millis(500),
                    error: None,
                },
                ConnectorBulkResult {
                    connector_id: "slack".to_string(),
                    success: false,
                    duration: Duration::from_millis(100),
                    error: Some("timeout".to_string()),
                },
            ],
        };
        let out = format_bulk_result_toon(&result);
        assert!(out.contains("Succeeded: 2"));
        assert!(out.contains("Failed:    1"));
        assert!(out.contains("github"));
        assert!(out.contains("OK"));
        assert!(out.contains("FAIL"));
        assert!(out.contains("timeout"));
    }

    #[test]
    fn format_bulk_result_empty() {
        let result = BulkResult::default();
        let out = format_bulk_result_toon(&result);
        assert!(out.contains("Total:     0"));
    }

    // ── Format connector health ────────────────────────────────────────

    #[test]
    fn format_connector_health_shows_state() {
        let c = ConnectorHealth::healthy("github");
        let out = format_connector_health_toon(&c);
        assert!(out.contains("[healthy]"));
    }

    #[test]
    fn format_connector_health_shows_id() {
        let c = ConnectorHealth::healthy("github");
        let out = format_connector_health_toon(&c);
        assert!(out.contains("github"));
    }

    #[test]
    fn format_connector_health_shows_uptime() {
        let c = ConnectorHealth::healthy("github");
        let out = format_connector_health_toon(&c);
        assert!(out.contains("Uptime:"));
    }

    #[test]
    fn format_connector_health_shows_error_rate() {
        let c = ConnectorHealth::healthy("github").with_error_rate(0.05);
        let out = format_connector_health_toon(&c);
        assert!(out.contains("0.0500"));
    }

    #[test]
    fn format_connector_health_shows_latency() {
        let c = ConnectorHealth::healthy("github").with_latency(25.0, 150.0);
        let out = format_connector_health_toon(&c);
        assert!(out.contains("25.0ms"));
        assert!(out.contains("150.0ms"));
    }

    // ── Serialization round-trips ──────────────────────────────────────

    #[test]
    fn connector_health_serde_roundtrip() {
        let c = ConnectorHealth::healthy("github")
            .with_tags(vec!["prod".to_string()])
            .with_archetype("vcs");
        let json = serde_json::to_string(&c).unwrap();
        let decoded: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.connector_id, "github");
        assert_eq!(decoded.tags, vec!["prod"]);
        assert_eq!(decoded.archetype, "vcs");
    }

    #[test]
    fn fleet_status_serde_roundtrip() {
        let status = aggregate_fleet_status(&fleet_connectors());
        let json = serde_json::to_string(&status).unwrap();
        let decoded: FleetStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.total_connectors, status.total_connectors);
    }

    #[test]
    fn bulk_result_serde_roundtrip() {
        let result = BulkResult {
            total: 1,
            succeeded: 1,
            failed: 0,
            skipped: 0,
            results: vec![ConnectorBulkResult {
                connector_id: "github".to_string(),
                success: true,
                duration: Duration::from_millis(100),
                error: None,
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: BulkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.succeeded, 1);
    }

    #[test]
    fn health_threshold_serde_roundtrip() {
        let t = sample_thresholds();
        let json = serde_json::to_string(&t).unwrap();
        let decoded: HealthThreshold = serde_json::from_str(&json).unwrap();
        assert!((decoded.error_rate_max - t.error_rate_max).abs() < f64::EPSILON);
    }

    #[test]
    fn cohort_selector_serde_all() {
        let s = CohortSelector::All;
        let json = serde_json::to_string(&s).unwrap();
        let decoded: CohortSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, CohortSelector::All));
    }

    #[test]
    fn cohort_selector_serde_by_pattern() {
        let s = CohortSelector::ByPattern { pattern: "aws".to_string() };
        let json = serde_json::to_string(&s).unwrap();
        let decoded: CohortSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, CohortSelector::ByPattern { ref pattern } if pattern == "aws"));
    }

    #[test]
    fn connector_state_serde_roundtrip() {
        let s = ConnectorState::Degraded;
        let json = serde_json::to_string(&s).unwrap();
        let decoded: ConnectorState = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, s);
    }

    // ── pct helper ─────────────────────────────────────────────────────

    #[test]
    fn pct_zero_total() {
        assert!((pct(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn pct_all() {
        assert!((pct(5, 5) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn pct_half() {
        assert!((pct(1, 2) - 50.0).abs() < f64::EPSILON);
    }

    // ── Additional coverage ────────────────────────────────────────────

    #[test]
    fn aggregate_large_fleet() {
        let mut conns = Vec::new();
        for i in 0..100 {
            conns.push(ConnectorHealth::healthy(format!("conn-{i}")));
        }
        let status = aggregate_fleet_status(&conns);
        assert_eq!(status.total_connectors, 100);
        assert_eq!(status.healthy, 100);
    }

    #[test]
    fn select_by_tag_multiple_tags() {
        let conns = vec![
            ConnectorHealth::healthy("a").with_tags(vec!["prod".to_string(), "us-east".to_string()]),
            ConnectorHealth::healthy("b").with_tags(vec!["staging".to_string()]),
            ConnectorHealth::healthy("c").with_tags(vec!["prod".to_string()]),
        ];
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByTag { tags: vec!["us-east".to_string()] },
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].connector_id, "a");
    }

    #[test]
    fn select_by_pattern_empty_matches_all() {
        let conns = fleet_connectors();
        let selected = select_cohort(
            &conns,
            &CohortSelector::ByPattern { pattern: String::new() },
        );
        assert_eq!(selected.len(), conns.len());
    }

    #[test]
    fn bulk_operation_serde_roundtrip() {
        let op = BulkOperation {
            action: "restart".to_string(),
            targets: vec!["a".to_string(), "b".to_string()],
            dry_run: true,
            concurrency: 3,
            on_error: "abort".to_string(),
        };
        let json = serde_json::to_string(&op).unwrap();
        let decoded: BulkOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.action, "restart");
        assert!(decoded.dry_run);
    }

    #[test]
    fn connector_bulk_result_serde_roundtrip() {
        let r = ConnectorBulkResult {
            connector_id: "github".to_string(),
            success: false,
            duration: Duration::from_secs(2),
            error: Some("timeout".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let decoded: ConnectorBulkResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn fleet_score_one_healthy_one_failed() {
        let status = FleetStatus {
            total_connectors: 2,
            healthy: 1,
            failed: 1,
            ..FleetStatus::default()
        };
        let score = compute_fleet_score(&status);
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn check_thresholds_zero_error_rate() {
        let c = ConnectorHealth::healthy("x").with_error_rate(0.0);
        let violations = check_thresholds(&c, &sample_thresholds());
        assert!(violations.is_empty());
    }

    #[test]
    fn check_thresholds_custom_high_limits() {
        let t = HealthThreshold {
            error_rate_max: 0.5,
            latency_p99_max: 10000.0,
            min_uptime: 0,
        };
        let c = ConnectorHealth::degraded("x");
        let violations = check_thresholds(&c, &t);
        assert!(violations.is_empty());
    }

    #[test]
    fn plan_waves_exact_concurrency_match() {
        let conns = fleet_connectors();
        let op = BulkOperation {
            action: "stop".to_string(),
            targets: vec!["github".to_string(), "slack".to_string()],
            dry_run: false,
            concurrency: 2,
            on_error: "continue".to_string(),
        };
        let waves = plan_bulk_operation(&op, &conns);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].len(), 2);
    }

    #[test]
    fn format_connector_health_degraded() {
        let c = ConnectorHealth::degraded("slack");
        let out = format_connector_health_toon(&c);
        assert!(out.contains("[degraded]"));
        assert!(out.contains("slack"));
    }

    #[test]
    fn format_connector_health_failed() {
        let c = ConnectorHealth::failed("pagerduty");
        let out = format_connector_health_toon(&c);
        assert!(out.contains("[failed]"));
    }

    #[test]
    fn format_fleet_status_percentages() {
        let conns = vec![
            ConnectorHealth::healthy("a"),
            ConnectorHealth::healthy("b"),
            ConnectorHealth::healthy("c"),
            ConnectorHealth::healthy("d"),
        ];
        let status = aggregate_fleet_status(&conns);
        let out = format_fleet_status_toon(&status);
        assert!(out.contains("100%"));
    }

    #[test]
    fn format_bulk_result_with_skipped() {
        let result = BulkResult {
            total: 3,
            succeeded: 1,
            failed: 0,
            skipped: 2,
            results: vec![],
        };
        let out = format_bulk_result_toon(&result);
        assert!(out.contains("Skipped:   2"));
    }

    #[test]
    fn cohort_selector_serde_by_state() {
        let s = CohortSelector::ByState { states: vec!["healthy".to_string()] };
        let json = serde_json::to_string(&s).unwrap();
        let decoded: CohortSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, CohortSelector::ByState { .. }));
    }

    #[test]
    fn cohort_selector_serde_by_tag() {
        let s = CohortSelector::ByTag { tags: vec!["prod".to_string()] };
        let json = serde_json::to_string(&s).unwrap();
        let decoded: CohortSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, CohortSelector::ByTag { .. }));
    }

    #[test]
    fn cohort_selector_serde_by_archetype() {
        let s = CohortSelector::ByArchetype { archetype: "vcs".to_string() };
        let json = serde_json::to_string(&s).unwrap();
        let decoded: CohortSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, CohortSelector::ByArchetype { .. }));
    }
}
