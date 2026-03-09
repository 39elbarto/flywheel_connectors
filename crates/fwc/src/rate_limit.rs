//! Rate limit status tracking and dashboard data model.
//!
//! Tracks quota usage across connector rate limit pools, calculates usage
//! percentages, and provides status classification (OK/WARNING/CRITICAL)
//! for agent decision-making before batch operations.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

// ── Types ──────────────────────────────────────────────────────────

/// Usage status of a rate limit pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    /// Under 80% usage.
    Ok,
    /// 80-95% usage.
    Warning,
    /// Over 95% usage or exhausted.
    Critical,
    /// No data available.
    Unknown,
}

impl PoolStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Whether this status indicates the pool is approaching or at its limit.
    pub const fn is_concerning(self) -> bool {
        matches!(self, Self::Warning | Self::Critical)
    }
}

impl std::fmt::Display for PoolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A single rate limit pool's current state.
#[derive(Clone, Debug, Serialize)]
pub struct PoolSnapshot {
    /// Pool identifier (e.g. `"core.read"`, `"search"`, `"sms.send"`).
    pub pool: String,
    /// Number of requests used in the current window.
    pub used: u64,
    /// Maximum requests allowed in the window.
    pub limit: u64,
    /// When the window resets and usage returns to zero.
    pub resets_at: Option<DateTime<Utc>>,
    /// Computed usage percentage (0-100).
    pub percent: u8,
    /// Computed status based on usage percentage.
    pub status: PoolStatus,
}

impl PoolSnapshot {
    /// Create a snapshot from raw usage data.
    pub fn new(
        pool: impl Into<String>,
        used: u64,
        limit: u64,
        resets_at: Option<DateTime<Utc>>,
    ) -> Self {
        let percent = (used * 100)
            .checked_div(limit)
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(100);
        let status = classify_usage(percent);
        Self {
            pool: pool.into(),
            used,
            limit,
            resets_at,
            percent,
            status,
        }
    }

    /// Remaining requests in this pool.
    pub const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Time until the window resets. Returns zero if already reset or no reset time.
    pub fn time_to_reset(&self) -> Duration {
        self.resets_at.map_or_else(Duration::zero, |reset| {
            let now = Utc::now();
            if reset > now { reset - now } else { Duration::zero() }
        })
    }

    /// Human-readable time to reset.
    pub fn reset_display(&self) -> String {
        if self.resets_at.is_none() {
            return "—".to_string();
        }
        let dur = self.time_to_reset();
        if dur.is_zero() {
            return "now".to_string();
        }
        let secs = dur.num_seconds();
        if secs < 60 {
            format!("{secs}s")
        } else if secs < 3600 {
            format!("{}m", secs / 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }

    /// Display string for used/limit ratio.
    pub fn ratio_display(&self) -> String {
        format!("{}/{}", self.used, self.limit)
    }
}

/// Rate limit status for a single connector (all pools).
#[derive(Clone, Debug, Serialize)]
pub struct ConnectorRateLimits {
    /// Connector identifier.
    pub connector_id: String,
    /// Per-pool snapshots.
    pub pools: Vec<PoolSnapshot>,
}

impl ConnectorRateLimits {
    /// Create rate limit status for a connector.
    pub fn new(connector_id: impl Into<String>, pools: Vec<PoolSnapshot>) -> Self {
        Self {
            connector_id: connector_id.into(),
            pools,
        }
    }

    /// Worst status across all pools.
    pub fn worst_status(&self) -> PoolStatus {
        self.pools
            .iter()
            .map(|p| p.status)
            .max()
            .unwrap_or(PoolStatus::Unknown)
    }

    /// Whether any pool is at WARNING or CRITICAL.
    pub fn has_concerns(&self) -> bool {
        self.pools.iter().any(|p| p.status.is_concerning())
    }

    /// Total remaining across all pools.
    pub fn total_remaining(&self) -> u64 {
        self.pools.iter().map(PoolSnapshot::remaining).sum()
    }

    /// Filter to only concerning pools (WARNING or CRITICAL).
    pub fn concerning_pools(&self) -> Vec<&PoolSnapshot> {
        self.pools
            .iter()
            .filter(|p| p.status.is_concerning())
            .collect()
    }
}

/// Aggregated rate limit dashboard across all connectors.
#[derive(Clone, Debug, Serialize)]
pub struct RateLimitDashboard {
    /// Per-connector rate limit status.
    pub connectors: BTreeMap<String, ConnectorRateLimits>,
    /// Timestamp when this dashboard was computed.
    pub computed_at: DateTime<Utc>,
}

impl RateLimitDashboard {
    /// Create a new empty dashboard.
    pub fn new() -> Self {
        Self {
            connectors: BTreeMap::new(),
            computed_at: Utc::now(),
        }
    }

    /// Add rate limit status for a connector.
    pub fn add(&mut self, limits: ConnectorRateLimits) {
        self.connectors.insert(limits.connector_id.clone(), limits);
    }

    /// Get rate limit status for a specific connector.
    pub fn get(&self, connector_id: &str) -> Option<&ConnectorRateLimits> {
        self.connectors.get(connector_id)
    }

    /// All pools across all connectors, flattened.
    pub fn all_pools(&self) -> Vec<(&str, &PoolSnapshot)> {
        self.connectors
            .iter()
            .flat_map(|(id, c)| c.pools.iter().map(move |p| (id.as_str(), p)))
            .collect()
    }

    /// Count of connectors with concerning rate limits.
    pub fn concerning_connector_count(&self) -> usize {
        self.connectors
            .values()
            .filter(|c| c.has_concerns())
            .count()
    }

    /// All pools at WARNING or CRITICAL, with their connector ID.
    pub fn concerning_pools(&self) -> Vec<(&str, &PoolSnapshot)> {
        self.all_pools()
            .into_iter()
            .filter(|(_, p)| p.status.is_concerning())
            .collect()
    }

    /// Whether the overall dashboard is clear (no concerns).
    pub fn is_clear(&self) -> bool {
        self.concerning_connector_count() == 0
    }

    /// Total number of tracked pools.
    pub fn pool_count(&self) -> usize {
        self.connectors.values().map(|c| c.pools.len()).sum()
    }

    /// Summary line for TOON output.
    pub fn summary_line(&self) -> String {
        let total = self.pool_count();
        let concerning = self.concerning_pools().len();
        if concerning == 0 {
            format!("{total} rate limit pools tracked, all OK")
        } else {
            format!(
                "{total} pools tracked, {concerning} need attention ({} connector(s))",
                self.concerning_connector_count()
            )
        }
    }
}

impl Default for RateLimitDashboard {
    fn default() -> Self {
        Self::new()
    }
}

// ── Classification ─────────────────────────────────────────────────

/// Classify usage percentage into a pool status.
const fn classify_usage(percent: u8) -> PoolStatus {
    if percent >= 95 {
        PoolStatus::Critical
    } else if percent >= 80 {
        PoolStatus::Warning
    } else {
        PoolStatus::Ok
    }
}

/// Estimate how many operations can be performed before hitting the limit,
/// given current usage and a per-operation cost.
pub const fn estimate_budget(remaining: u64, cost_per_op: u64) -> u64 {
    if cost_per_op == 0 {
        return u64::MAX;
    }
    remaining / cost_per_op
}

/// Recommend a delay between operations to spread usage across the reset window.
pub fn recommend_delay(
    remaining: u64,
    operations_needed: u64,
    time_to_reset: Duration,
) -> Duration {
    if operations_needed == 0 || remaining == 0 {
        return Duration::zero();
    }
    let total_ms = time_to_reset.num_milliseconds();
    if total_ms <= 0 {
        return Duration::zero();
    }
    // Distribute ops across the divisor: available budget or total needed.
    let divisor = if operations_needed <= remaining {
        operations_needed
    } else {
        remaining
    };
    let delay_ms = total_ms / i64::try_from(divisor).unwrap_or(i64::MAX);
    Duration::milliseconds(delay_ms)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PoolStatus ────────────────────────────────────────────────

    #[test]
    fn pool_status_ordering() {
        assert!(PoolStatus::Critical > PoolStatus::Warning);
        assert!(PoolStatus::Warning > PoolStatus::Ok);
    }

    #[test]
    fn pool_status_labels() {
        assert_eq!(PoolStatus::Ok.label(), "OK");
        assert_eq!(PoolStatus::Warning.label(), "WARNING");
        assert_eq!(PoolStatus::Critical.label(), "CRITICAL");
        assert_eq!(PoolStatus::Unknown.label(), "UNKNOWN");
    }

    #[test]
    fn pool_status_display() {
        assert_eq!(format!("{}", PoolStatus::Ok), "OK");
    }

    #[test]
    fn pool_status_concerning() {
        assert!(!PoolStatus::Ok.is_concerning());
        assert!(PoolStatus::Warning.is_concerning());
        assert!(PoolStatus::Critical.is_concerning());
        assert!(!PoolStatus::Unknown.is_concerning());
    }

    // ── classify_usage ────────────────────────────────────────────

    #[test]
    fn classify_ok() {
        assert_eq!(classify_usage(0), PoolStatus::Ok);
        assert_eq!(classify_usage(50), PoolStatus::Ok);
        assert_eq!(classify_usage(79), PoolStatus::Ok);
    }

    #[test]
    fn classify_warning() {
        assert_eq!(classify_usage(80), PoolStatus::Warning);
        assert_eq!(classify_usage(90), PoolStatus::Warning);
        assert_eq!(classify_usage(94), PoolStatus::Warning);
    }

    #[test]
    fn classify_critical() {
        assert_eq!(classify_usage(95), PoolStatus::Critical);
        assert_eq!(classify_usage(99), PoolStatus::Critical);
        assert_eq!(classify_usage(100), PoolStatus::Critical);
    }

    // ── PoolSnapshot ──────────────────────────────────────────────

    #[test]
    fn snapshot_basic() {
        let snap = PoolSnapshot::new("core.read", 4500, 5000, None);
        assert_eq!(snap.percent, 90);
        assert_eq!(snap.status, PoolStatus::Warning);
        assert_eq!(snap.remaining(), 500);
    }

    #[test]
    fn snapshot_zero_limit() {
        let snap = PoolSnapshot::new("empty", 0, 0, None);
        assert_eq!(snap.percent, 100);
        assert_eq!(snap.status, PoolStatus::Critical);
    }

    #[test]
    fn snapshot_full() {
        let snap = PoolSnapshot::new("full", 100, 100, None);
        assert_eq!(snap.percent, 100);
        assert_eq!(snap.remaining(), 0);
    }

    #[test]
    fn snapshot_empty() {
        let snap = PoolSnapshot::new("fresh", 0, 5000, None);
        assert_eq!(snap.percent, 0);
        assert_eq!(snap.status, PoolStatus::Ok);
        assert_eq!(snap.remaining(), 5000);
    }

    #[test]
    fn snapshot_ratio_display() {
        let snap = PoolSnapshot::new("test", 450, 500, None);
        assert_eq!(snap.ratio_display(), "450/500");
    }

    #[test]
    fn snapshot_reset_display_no_reset() {
        let snap = PoolSnapshot::new("test", 0, 100, None);
        assert_eq!(snap.reset_display(), "—");
    }

    #[test]
    fn snapshot_reset_display_future() {
        let snap = PoolSnapshot::new("test", 0, 100, Some(Utc::now() + Duration::minutes(12)));
        let display = snap.reset_display();
        assert!(display.contains('m'));
    }

    #[test]
    fn snapshot_reset_display_past() {
        let snap = PoolSnapshot::new("test", 0, 100, Some(Utc::now() - Duration::hours(1)));
        assert_eq!(snap.reset_display(), "now");
    }

    #[test]
    fn snapshot_time_to_reset_future() {
        let snap = PoolSnapshot::new("test", 0, 100, Some(Utc::now() + Duration::minutes(5)));
        assert!(snap.time_to_reset().num_seconds() > 0);
    }

    #[test]
    fn snapshot_time_to_reset_past() {
        let snap = PoolSnapshot::new("test", 0, 100, Some(Utc::now() - Duration::hours(1)));
        assert!(snap.time_to_reset().is_zero());
    }

    #[test]
    fn snapshot_time_to_reset_none() {
        let snap = PoolSnapshot::new("test", 0, 100, None);
        assert!(snap.time_to_reset().is_zero());
    }

    #[test]
    fn snapshot_serializes() {
        let snap = PoolSnapshot::new("core.read", 4500, 5000, None);
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["pool"], "core.read");
        assert_eq!(json["percent"], 90);
        assert_eq!(json["status"], "warning");
    }

    // ── ConnectorRateLimits ───────────────────────────────────────

    #[test]
    fn connector_limits_worst_status() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("core.read", 100, 5000, None), // OK
                PoolSnapshot::new("search", 27, 30, None),       // Warning
            ],
        );
        assert_eq!(limits.worst_status(), PoolStatus::Warning);
    }

    #[test]
    fn connector_limits_has_concerns() {
        let ok = ConnectorRateLimits::new("ok", vec![PoolSnapshot::new("pool", 10, 100, None)]);
        assert!(!ok.has_concerns());

        let warning =
            ConnectorRateLimits::new("warn", vec![PoolSnapshot::new("pool", 90, 100, None)]);
        assert!(warning.has_concerns());
    }

    #[test]
    fn connector_limits_total_remaining() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("a", 100, 500, None),
                PoolSnapshot::new("b", 50, 200, None),
            ],
        );
        assert_eq!(limits.total_remaining(), 550);
    }

    #[test]
    fn connector_limits_concerning_pools() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("ok", 10, 100, None),
                PoolSnapshot::new("warn", 90, 100, None),
                PoolSnapshot::new("crit", 99, 100, None),
            ],
        );
        let concerning = limits.concerning_pools();
        assert_eq!(concerning.len(), 2);
    }

    #[test]
    fn connector_limits_empty_pools() {
        let limits = ConnectorRateLimits::new("empty", vec![]);
        assert_eq!(limits.worst_status(), PoolStatus::Unknown);
        assert!(!limits.has_concerns());
    }

    // ── RateLimitDashboard ────────────────────────────────────────

    #[test]
    fn dashboard_new_is_empty() {
        let dash = RateLimitDashboard::new();
        assert!(dash.is_clear());
        assert_eq!(dash.pool_count(), 0);
    }

    #[test]
    fn dashboard_add_and_get() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 100, 5000, None)],
        ));
        assert!(dash.get("github").is_some());
        assert!(dash.get("slack").is_none());
    }

    #[test]
    fn dashboard_all_pools() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("a", 0, 100, None),
                PoolSnapshot::new("b", 0, 200, None),
            ],
        ));
        dash.add(ConnectorRateLimits::new(
            "slack",
            vec![PoolSnapshot::new("c", 0, 50, None)],
        ));
        assert_eq!(dash.all_pools().len(), 3);
    }

    #[test]
    fn dashboard_pool_count() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("a", 0, 100, None),
                PoolSnapshot::new("b", 0, 200, None),
            ],
        ));
        assert_eq!(dash.pool_count(), 2);
    }

    #[test]
    fn dashboard_concerning() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("ok", 10, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "slack",
            vec![PoolSnapshot::new("warn", 90, 100, None)],
        ));
        assert_eq!(dash.concerning_connector_count(), 1);
        assert!(!dash.is_clear());
    }

    #[test]
    fn dashboard_concerning_pools() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("ok", 10, 100, None),
                PoolSnapshot::new("warn", 85, 100, None),
            ],
        ));
        let concerning = dash.concerning_pools();
        assert_eq!(concerning.len(), 1);
        assert_eq!(concerning[0].0, "github");
        assert_eq!(concerning[0].1.pool, "warn");
    }

    #[test]
    fn dashboard_summary_all_ok() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 10, 100, None)],
        ));
        let summary = dash.summary_line();
        assert!(summary.contains("all OK"));
    }

    #[test]
    fn dashboard_summary_with_concerns() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 96, 100, None)],
        ));
        let summary = dash.summary_line();
        assert!(summary.contains("need attention"));
    }

    #[test]
    fn dashboard_default() {
        let dash = RateLimitDashboard::default();
        assert!(dash.is_clear());
    }

    // ── estimate_budget ───────────────────────────────────────────

    #[test]
    fn budget_normal() {
        assert_eq!(estimate_budget(500, 1), 500);
        assert_eq!(estimate_budget(500, 2), 250);
        assert_eq!(estimate_budget(100, 3), 33);
    }

    #[test]
    fn budget_zero_cost() {
        assert_eq!(estimate_budget(500, 0), u64::MAX);
    }

    #[test]
    fn budget_zero_remaining() {
        assert_eq!(estimate_budget(0, 1), 0);
    }

    // ── recommend_delay ───────────────────────────────────────────

    #[test]
    fn delay_enough_budget() {
        let delay = recommend_delay(100, 10, Duration::minutes(10));
        // 10 ops in 10 minutes = 1 per minute = 60s delay
        assert_eq!(delay.num_seconds(), 60);
    }

    #[test]
    fn delay_tight_budget() {
        let delay = recommend_delay(5, 10, Duration::minutes(5));
        // Only 5 remaining but need 10 — spread 5 ops across 5 min = 60s each
        assert_eq!(delay.num_seconds(), 60);
    }

    #[test]
    fn delay_zero_operations() {
        let delay = recommend_delay(100, 0, Duration::minutes(10));
        assert!(delay.is_zero());
    }

    #[test]
    fn delay_zero_remaining() {
        let delay = recommend_delay(0, 10, Duration::minutes(10));
        assert!(delay.is_zero());
    }

    #[test]
    fn delay_zero_time() {
        let delay = recommend_delay(100, 10, Duration::zero());
        assert!(delay.is_zero());
    }
}
