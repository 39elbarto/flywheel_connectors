//! Rate limit status tracking and dashboard data model.
//!
//! Tracks quota usage across connector rate limit pools, calculates usage
//! percentages, and provides status classification (OK/WARNING/CRITICAL)
//! for agent decision-making before batch operations.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ── Types ──────────────────────────────────────────────────────────

/// Usage status of a rate limit pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
            if reset > now {
                reset - now
            } else {
                Duration::zero()
            }
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

    // ── PoolStatus additional ────────────────────────────────────

    #[test]
    fn pool_status_display_all_variants() {
        assert_eq!(PoolStatus::Ok.to_string(), "OK");
        assert_eq!(PoolStatus::Warning.to_string(), "WARNING");
        assert_eq!(PoolStatus::Critical.to_string(), "CRITICAL");
        assert_eq!(PoolStatus::Unknown.to_string(), "UNKNOWN");
    }

    #[test]
    fn pool_status_serde_roundtrip() {
        for status in &[
            PoolStatus::Ok,
            PoolStatus::Warning,
            PoolStatus::Critical,
            PoolStatus::Unknown,
        ] {
            let json = serde_json::to_string(status).unwrap();
            let status2: PoolStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, status2);
        }
    }

    #[test]
    fn pool_status_snake_case_serde() {
        let json = serde_json::to_value(PoolStatus::Ok).unwrap();
        assert_eq!(json, "ok");
        let json = serde_json::to_value(PoolStatus::Unknown).unwrap();
        assert_eq!(json, "unknown");
    }

    #[test]
    fn pool_status_copy() {
        let s = PoolStatus::Warning;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── classify_usage boundary ──────────────────────────────────

    #[test]
    fn classify_boundary_79_80() {
        assert_eq!(classify_usage(79), PoolStatus::Ok);
        assert_eq!(classify_usage(80), PoolStatus::Warning);
    }

    #[test]
    fn classify_boundary_94_95() {
        assert_eq!(classify_usage(94), PoolStatus::Warning);
        assert_eq!(classify_usage(95), PoolStatus::Critical);
    }

    #[test]
    fn classify_max() {
        assert_eq!(classify_usage(255), PoolStatus::Critical);
    }

    // ── PoolSnapshot additional ──────────────────────────────────

    #[test]
    fn snapshot_overused() {
        // used > limit (shouldn't happen but shouldn't panic)
        let snap = PoolSnapshot::new("overshoot", 6000, 5000, None);
        assert_eq!(snap.percent, 120); // 6000*100/5000 = 120, fits in u8
        assert_eq!(snap.status, PoolStatus::Critical);
        assert_eq!(snap.remaining(), 0); // saturating_sub
    }

    #[test]
    fn snapshot_percent_50() {
        let snap = PoolSnapshot::new("half", 250, 500, None);
        assert_eq!(snap.percent, 50);
        assert_eq!(snap.status, PoolStatus::Ok);
    }

    #[test]
    fn snapshot_percent_boundary_80() {
        let snap = PoolSnapshot::new("warn", 80, 100, None);
        assert_eq!(snap.percent, 80);
        assert_eq!(snap.status, PoolStatus::Warning);
    }

    #[test]
    fn snapshot_percent_boundary_95() {
        let snap = PoolSnapshot::new("crit", 95, 100, None);
        assert_eq!(snap.percent, 95);
        assert_eq!(snap.status, PoolStatus::Critical);
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let snap = PoolSnapshot::new("core", 300, 1000, None);
        let json = serde_json::to_string(&snap).unwrap();
        let snap2: PoolSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap2.pool, "core");
        assert_eq!(snap2.used, 300);
        assert_eq!(snap2.limit, 1000);
        assert_eq!(snap2.percent, 30);
    }

    #[test]
    fn snapshot_reset_display_seconds() {
        let snap = PoolSnapshot::new("test", 0, 100, Some(Utc::now() + Duration::seconds(30)));
        let display = snap.reset_display();
        assert!(display.contains('s'));
        assert!(!display.contains('m'));
    }

    #[test]
    fn snapshot_reset_display_hours() {
        let snap = PoolSnapshot::new(
            "test",
            0,
            100,
            Some(Utc::now() + Duration::hours(2) + Duration::minutes(15)),
        );
        let display = snap.reset_display();
        assert!(display.contains('h'));
        assert!(display.contains('m'));
    }

    #[test]
    fn snapshot_ratio_display_zero() {
        let snap = PoolSnapshot::new("test", 0, 100, None);
        assert_eq!(snap.ratio_display(), "0/100");
    }

    #[test]
    fn snapshot_ratio_display_full() {
        let snap = PoolSnapshot::new("test", 5000, 5000, None);
        assert_eq!(snap.ratio_display(), "5000/5000");
    }

    #[test]
    fn snapshot_large_numbers() {
        let snap = PoolSnapshot::new("big", 1_000_000, 10_000_000, None);
        assert_eq!(snap.percent, 10);
        assert_eq!(snap.remaining(), 9_000_000);
    }

    #[test]
    fn snapshot_clone_independence() {
        let snap = PoolSnapshot::new("core", 100, 500, None);
        let snap2 = snap.clone();
        assert_eq!(snap.pool, snap2.pool);
        assert_eq!(snap.percent, snap2.percent);
    }

    // ── ConnectorRateLimits additional ───────────────────────────

    #[test]
    fn connector_limits_worst_status_all_ok() {
        let limits = ConnectorRateLimits::new(
            "test",
            vec![
                PoolSnapshot::new("a", 10, 100, None),
                PoolSnapshot::new("b", 20, 100, None),
            ],
        );
        assert_eq!(limits.worst_status(), PoolStatus::Ok);
    }

    #[test]
    fn connector_limits_worst_status_critical() {
        let limits = ConnectorRateLimits::new(
            "test",
            vec![
                PoolSnapshot::new("a", 10, 100, None),
                PoolSnapshot::new("b", 96, 100, None),
            ],
        );
        assert_eq!(limits.worst_status(), PoolStatus::Critical);
    }

    #[test]
    fn connector_limits_total_remaining_empty() {
        let limits = ConnectorRateLimits::new("empty", vec![]);
        assert_eq!(limits.total_remaining(), 0);
    }

    #[test]
    fn connector_limits_serde() {
        let limits =
            ConnectorRateLimits::new("github", vec![PoolSnapshot::new("core", 100, 5000, None)]);
        let json = serde_json::to_value(&limits).unwrap();
        assert_eq!(json["connector_id"], "github");
        assert_eq!(json["pools"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn connector_limits_concerning_pools_none() {
        let limits = ConnectorRateLimits::new(
            "test",
            vec![
                PoolSnapshot::new("a", 10, 100, None),
                PoolSnapshot::new("b", 20, 100, None),
            ],
        );
        assert!(limits.concerning_pools().is_empty());
    }

    // ── RateLimitDashboard additional ────────────────────────────

    #[test]
    fn dashboard_add_replaces_existing() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 10, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 90, 100, None)],
        ));
        // Should replace, not accumulate
        assert_eq!(dash.pool_count(), 1);
        assert!(dash.get("github").unwrap().has_concerns());
    }

    #[test]
    fn dashboard_multiple_connectors_pool_count() {
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
        dash.add(ConnectorRateLimits::new(
            "jira",
            vec![
                PoolSnapshot::new("d", 0, 100, None),
                PoolSnapshot::new("e", 0, 100, None),
            ],
        ));
        assert_eq!(dash.pool_count(), 5);
    }

    #[test]
    fn dashboard_concerning_multiple_connectors() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 90, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "slack",
            vec![PoolSnapshot::new("api", 96, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "jira",
            vec![PoolSnapshot::new("rest", 10, 100, None)],
        ));
        assert_eq!(dash.concerning_connector_count(), 2);
        assert!(!dash.is_clear());
    }

    #[test]
    fn dashboard_serde() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 100, 5000, None)],
        ));
        let json = serde_json::to_value(&dash).unwrap();
        assert!(json.get("computed_at").is_some());
        assert!(json["connectors"].get("github").is_some());
    }

    #[test]
    fn dashboard_summary_multiple_concerns() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 96, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "slack",
            vec![PoolSnapshot::new("api", 85, 100, None)],
        ));
        let summary = dash.summary_line();
        assert!(summary.contains("need attention"));
        assert!(summary.contains("2 connector(s)"));
    }

    #[test]
    fn dashboard_clone() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 10, 100, None)],
        ));
        let dash2 = dash.clone();
        assert_eq!(dash.pool_count(), dash2.pool_count());
    }

    // ── estimate_budget additional ───────────────────────────────

    #[test]
    fn budget_large_remaining() {
        assert_eq!(estimate_budget(1_000_000, 100), 10_000);
    }

    #[test]
    fn budget_cost_greater_than_remaining() {
        assert_eq!(estimate_budget(5, 10), 0);
    }

    #[test]
    fn budget_exact_division() {
        assert_eq!(estimate_budget(100, 25), 4);
    }

    // ── recommend_delay additional ───────────────────────────────

    #[test]
    fn delay_single_operation() {
        let delay = recommend_delay(100, 1, Duration::minutes(10));
        // 1 op across 10 min → 600s delay
        assert_eq!(delay.num_seconds(), 600);
    }

    #[test]
    fn delay_negative_time() {
        let delay = recommend_delay(100, 10, Duration::seconds(-5));
        assert!(delay.is_zero());
    }

    #[test]
    fn delay_very_large_window() {
        let delay = recommend_delay(100, 10, Duration::hours(24));
        // 10 ops in 24 hours = 8640s each
        assert_eq!(delay.num_seconds(), 8640);
    }

    #[test]
    fn delay_both_zero() {
        let delay = recommend_delay(0, 0, Duration::minutes(10));
        assert!(delay.is_zero());
    }

    // ── PoolStatus exhaustive ordering ──────────────────────────

    #[test]
    fn pool_status_ord_ok_less_than_unknown() {
        assert!(PoolStatus::Ok < PoolStatus::Unknown);
    }

    #[test]
    fn pool_status_ord_unknown_greater_than_ok() {
        assert!(PoolStatus::Unknown > PoolStatus::Ok);
    }

    #[test]
    fn pool_status_ord_warning_less_than_critical() {
        assert!(PoolStatus::Warning < PoolStatus::Critical);
    }

    #[test]
    fn pool_status_eq_reflexive() {
        assert_eq!(PoolStatus::Ok, PoolStatus::Ok);
        assert_eq!(PoolStatus::Warning, PoolStatus::Warning);
        assert_eq!(PoolStatus::Critical, PoolStatus::Critical);
        assert_eq!(PoolStatus::Unknown, PoolStatus::Unknown);
    }

    #[test]
    fn pool_status_ne_across_variants() {
        assert_ne!(PoolStatus::Ok, PoolStatus::Warning);
        assert_ne!(PoolStatus::Warning, PoolStatus::Critical);
        assert_ne!(PoolStatus::Critical, PoolStatus::Unknown);
        assert_ne!(PoolStatus::Ok, PoolStatus::Unknown);
    }

    #[test]
    fn pool_status_debug_format() {
        let dbg = format!("{:?}", PoolStatus::Critical);
        assert_eq!(dbg, "Critical");
    }

    #[test]
    fn pool_status_debug_all_variants() {
        assert_eq!(format!("{:?}", PoolStatus::Ok), "Ok");
        assert_eq!(format!("{:?}", PoolStatus::Warning), "Warning");
        assert_eq!(format!("{:?}", PoolStatus::Unknown), "Unknown");
    }

    #[test]
    fn pool_status_clone_is_equal() {
        let s = PoolStatus::Warning;
        let cloned = s;
        assert_eq!(s, cloned);
    }

    #[test]
    fn pool_status_copy_independence() {
        let a = PoolStatus::Critical;
        let b = a;
        // Both usable after copy
        assert_eq!(a.label(), "CRITICAL");
        assert_eq!(b.label(), "CRITICAL");
    }

    #[test]
    fn pool_status_serde_warning_snake_case() {
        let json = serde_json::to_value(PoolStatus::Warning).unwrap();
        assert_eq!(json, "warning");
    }

    #[test]
    fn pool_status_serde_critical_snake_case() {
        let json = serde_json::to_value(PoolStatus::Critical).unwrap();
        assert_eq!(json, "critical");
    }

    #[test]
    fn pool_status_deserialize_from_string() {
        let ok: PoolStatus = serde_json::from_str("\"ok\"").unwrap();
        assert_eq!(ok, PoolStatus::Ok);
        let crit: PoolStatus = serde_json::from_str("\"critical\"").unwrap();
        assert_eq!(crit, PoolStatus::Critical);
    }

    #[test]
    fn pool_status_deserialize_invalid_fails() {
        let result: Result<PoolStatus, _> = serde_json::from_str("\"panic\"");
        assert!(result.is_err());
    }

    #[test]
    fn pool_status_is_concerning_ok_and_unknown_false() {
        // Ensure both non-concerning statuses consistently return false
        assert!(!PoolStatus::Ok.is_concerning());
        assert!(!PoolStatus::Unknown.is_concerning());
    }

    #[test]
    fn pool_status_display_matches_label() {
        for status in &[
            PoolStatus::Ok,
            PoolStatus::Warning,
            PoolStatus::Critical,
            PoolStatus::Unknown,
        ] {
            assert_eq!(status.to_string(), status.label());
        }
    }

    #[test]
    fn pool_status_sorted_vec() {
        let mut statuses = vec![
            PoolStatus::Critical,
            PoolStatus::Ok,
            PoolStatus::Unknown,
            PoolStatus::Warning,
        ];
        statuses.sort();
        assert_eq!(
            statuses,
            vec![
                PoolStatus::Ok,
                PoolStatus::Warning,
                PoolStatus::Critical,
                PoolStatus::Unknown,
            ]
        );
    }

    // ── classify_usage additional boundaries ─────────────────────

    #[test]
    fn classify_usage_at_1() {
        assert_eq!(classify_usage(1), PoolStatus::Ok);
    }

    #[test]
    fn classify_usage_at_50() {
        assert_eq!(classify_usage(50), PoolStatus::Ok);
    }

    #[test]
    fn classify_usage_at_81() {
        assert_eq!(classify_usage(81), PoolStatus::Warning);
    }

    #[test]
    fn classify_usage_at_96() {
        assert_eq!(classify_usage(96), PoolStatus::Critical);
    }

    #[test]
    fn classify_usage_at_200() {
        // Over 100% still critical
        assert_eq!(classify_usage(200), PoolStatus::Critical);
    }

    #[test]
    fn classify_usage_at_0() {
        assert_eq!(classify_usage(0), PoolStatus::Ok);
    }

    // ── PoolSnapshot additional edge cases ───────────────────────

    #[test]
    fn snapshot_used_equals_limit_minus_one() {
        let snap = PoolSnapshot::new("almost", 99, 100, None);
        assert_eq!(snap.percent, 99);
        assert_eq!(snap.status, PoolStatus::Critical);
        assert_eq!(snap.remaining(), 1);
    }

    #[test]
    fn snapshot_limit_one() {
        let snap = PoolSnapshot::new("tiny", 1, 1, None);
        assert_eq!(snap.percent, 100);
        assert_eq!(snap.remaining(), 0);
        assert_eq!(snap.status, PoolStatus::Critical);
    }

    #[test]
    fn snapshot_limit_one_unused() {
        let snap = PoolSnapshot::new("tiny_fresh", 0, 1, None);
        assert_eq!(snap.percent, 0);
        assert_eq!(snap.remaining(), 1);
        assert_eq!(snap.status, PoolStatus::Ok);
    }

    #[test]
    fn snapshot_very_large_limit() {
        let snap = PoolSnapshot::new("huge", 500_000, 1_000_000_000, None);
        assert_eq!(snap.percent, 0); // 500000*100/1000000000 = 0 (integer division)
        assert_eq!(snap.remaining(), 999_500_000);
    }

    #[test]
    fn snapshot_used_much_greater_than_limit() {
        // used*100 could overflow u64 for very large values, but
        // we test moderate overflow scenario
        let snap = PoolSnapshot::new("wild", 300, 100, None);
        // 300*100/100 = 300, u8::try_from(300) fails → unwrap_or(100)
        assert_eq!(snap.percent, 100);
        assert_eq!(snap.remaining(), 0);
    }

    #[test]
    fn snapshot_overflow_u8_boundary() {
        // used*100/limit = 256, which overflows u8
        let snap = PoolSnapshot::new("overflow", 256, 100, None);
        // u8::try_from(256) fails → 100
        assert_eq!(snap.percent, 100);
    }

    #[test]
    fn snapshot_debug_contains_pool_name() {
        let snap = PoolSnapshot::new("my_pool", 10, 100, None);
        let dbg = format!("{:?}", snap);
        assert!(dbg.contains("my_pool"));
        assert!(dbg.contains("PoolSnapshot"));
    }

    #[test]
    fn snapshot_clone_with_reset() {
        let reset = Utc::now() + Duration::hours(1);
        let snap = PoolSnapshot::new("core", 50, 100, Some(reset));
        let snap2 = snap.clone();
        assert_eq!(snap.resets_at, snap2.resets_at);
        assert_eq!(snap.pool, snap2.pool);
    }

    #[test]
    fn snapshot_serde_with_reset_time() {
        let reset = Utc::now() + Duration::hours(1);
        let snap = PoolSnapshot::new("timed", 30, 100, Some(reset));
        let json = serde_json::to_string(&snap).unwrap();
        let snap2: PoolSnapshot = serde_json::from_str(&json).unwrap();
        assert!(snap2.resets_at.is_some());
        assert_eq!(snap2.pool, "timed");
        assert_eq!(snap2.used, 30);
    }

    #[test]
    fn snapshot_serde_null_reset() {
        let snap = PoolSnapshot::new("no_reset", 10, 100, None);
        let json = serde_json::to_value(&snap).unwrap();
        assert!(json["resets_at"].is_null());
    }

    #[test]
    fn snapshot_serde_status_field_value() {
        let snap = PoolSnapshot::new("warn", 85, 100, None);
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["status"], "warning");
    }

    #[test]
    fn snapshot_serde_ok_status_field() {
        let snap = PoolSnapshot::new("ok", 10, 100, None);
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[test]
    fn snapshot_reset_display_exactly_60_seconds() {
        let snap = PoolSnapshot::new("test", 0, 100, Some(Utc::now() + Duration::seconds(62)));
        let display = snap.reset_display();
        // 62 seconds → "1m"
        assert!(display.contains('m'));
    }

    #[test]
    fn snapshot_reset_display_exactly_one_hour() {
        let snap = PoolSnapshot::new(
            "test",
            0,
            100,
            Some(Utc::now() + Duration::hours(1) + Duration::seconds(5)),
        );
        let display = snap.reset_display();
        assert!(display.contains('h'));
    }

    #[test]
    fn snapshot_ratio_display_large_numbers() {
        let snap = PoolSnapshot::new("big", 999_999, 1_000_000, None);
        assert_eq!(snap.ratio_display(), "999999/1000000");
    }

    #[test]
    fn snapshot_remaining_saturates_at_zero() {
        // used > limit case
        let snap = PoolSnapshot::new("over", 200, 100, None);
        assert_eq!(snap.remaining(), 0);
    }

    #[test]
    fn snapshot_pool_name_empty_string() {
        let snap = PoolSnapshot::new("", 0, 100, None);
        assert_eq!(snap.pool, "");
        assert_eq!(snap.percent, 0);
    }

    #[test]
    fn snapshot_pool_name_with_dots() {
        let snap = PoolSnapshot::new("api.v2.core.read", 50, 100, None);
        assert_eq!(snap.pool, "api.v2.core.read");
    }

    // ── ConnectorRateLimits additional ───────────────────────────

    #[test]
    fn connector_limits_clone() {
        let limits =
            ConnectorRateLimits::new("github", vec![PoolSnapshot::new("core", 10, 100, None)]);
        let cloned = limits.clone();
        assert_eq!(limits.connector_id, cloned.connector_id);
        assert_eq!(limits.pools.len(), cloned.pools.len());
    }

    #[test]
    fn connector_limits_debug() {
        let limits =
            ConnectorRateLimits::new("slack", vec![PoolSnapshot::new("api", 50, 100, None)]);
        let dbg = format!("{:?}", limits);
        assert!(dbg.contains("slack"));
        assert!(dbg.contains("ConnectorRateLimits"));
    }

    #[test]
    fn connector_limits_many_pools() {
        let pools: Vec<_> = (0..20)
            .map(|i| PoolSnapshot::new(format!("pool_{i}"), i * 5, 100, None))
            .collect();
        let limits = ConnectorRateLimits::new("multi", pools);
        assert_eq!(limits.pools.len(), 20);
        assert_eq!(limits.worst_status(), PoolStatus::Critical); // pool_19: 95%
    }

    #[test]
    fn connector_limits_worst_with_mix_of_all() {
        let limits = ConnectorRateLimits::new(
            "mix",
            vec![
                PoolSnapshot::new("a", 10, 100, None), // Ok
                PoolSnapshot::new("b", 85, 100, None), // Warning
                PoolSnapshot::new("c", 96, 100, None), // Critical
            ],
        );
        assert_eq!(limits.worst_status(), PoolStatus::Critical);
    }

    #[test]
    fn connector_limits_concerning_returns_only_concerning() {
        let limits = ConnectorRateLimits::new(
            "test",
            vec![
                PoolSnapshot::new("ok1", 10, 100, None),
                PoolSnapshot::new("ok2", 20, 100, None),
                PoolSnapshot::new("warn", 85, 100, None),
                PoolSnapshot::new("ok3", 30, 100, None),
            ],
        );
        let concerning = limits.concerning_pools();
        assert_eq!(concerning.len(), 1);
        assert_eq!(concerning[0].pool, "warn");
    }

    #[test]
    fn connector_limits_total_remaining_large() {
        let limits = ConnectorRateLimits::new(
            "big",
            vec![
                PoolSnapshot::new("a", 0, 1_000_000, None),
                PoolSnapshot::new("b", 0, 2_000_000, None),
            ],
        );
        assert_eq!(limits.total_remaining(), 3_000_000);
    }

    #[test]
    fn connector_limits_total_remaining_all_exhausted() {
        let limits = ConnectorRateLimits::new(
            "done",
            vec![
                PoolSnapshot::new("a", 100, 100, None),
                PoolSnapshot::new("b", 200, 200, None),
            ],
        );
        assert_eq!(limits.total_remaining(), 0);
    }

    #[test]
    fn connector_limits_serde_multiple_pools() {
        let limits = ConnectorRateLimits::new(
            "jira",
            vec![
                PoolSnapshot::new("rest", 50, 100, None),
                PoolSnapshot::new("search", 80, 100, None),
            ],
        );
        let json = serde_json::to_value(&limits).unwrap();
        assert_eq!(json["pools"].as_array().unwrap().len(), 2);
        assert_eq!(json["pools"][0]["pool"], "rest");
        assert_eq!(json["pools"][1]["pool"], "search");
    }

    #[test]
    fn connector_limits_has_concerns_all_critical() {
        let limits = ConnectorRateLimits::new(
            "bad",
            vec![
                PoolSnapshot::new("a", 96, 100, None),
                PoolSnapshot::new("b", 98, 100, None),
            ],
        );
        assert!(limits.has_concerns());
        assert_eq!(limits.concerning_pools().len(), 2);
    }

    // ── RateLimitDashboard additional ────────────────────────────

    #[test]
    fn dashboard_empty_summary_line() {
        let dash = RateLimitDashboard::new();
        let summary = dash.summary_line();
        assert!(summary.contains("0 rate limit pools tracked"));
        assert!(summary.contains("all OK"));
    }

    #[test]
    fn dashboard_empty_concerning_pools() {
        let dash = RateLimitDashboard::new();
        assert!(dash.concerning_pools().is_empty());
    }

    #[test]
    fn dashboard_empty_all_pools() {
        let dash = RateLimitDashboard::new();
        assert!(dash.all_pools().is_empty());
    }

    #[test]
    fn dashboard_get_returns_none_for_missing() {
        let dash = RateLimitDashboard::new();
        assert!(dash.get("nonexistent").is_none());
    }

    #[test]
    fn dashboard_debug_format() {
        let dash = RateLimitDashboard::new();
        let dbg = format!("{:?}", dash);
        assert!(dbg.contains("RateLimitDashboard"));
    }

    #[test]
    fn dashboard_clone_independence() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 10, 100, None)],
        ));
        let mut dash2 = dash.clone();
        dash2.add(ConnectorRateLimits::new(
            "slack",
            vec![PoolSnapshot::new("api", 50, 100, None)],
        ));
        // Original should not be affected
        assert_eq!(dash.pool_count(), 1);
        assert_eq!(dash2.pool_count(), 2);
    }

    #[test]
    fn dashboard_default_is_clear() {
        let dash = RateLimitDashboard::default();
        assert!(dash.is_clear());
        assert_eq!(dash.pool_count(), 0);
        assert_eq!(dash.concerning_connector_count(), 0);
    }

    #[test]
    fn dashboard_all_pools_includes_connector_ids() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "alpha",
            vec![PoolSnapshot::new("p1", 10, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "beta",
            vec![PoolSnapshot::new("p2", 20, 100, None)],
        ));
        let all = dash.all_pools();
        let ids: Vec<&str> = all.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&"alpha"));
        assert!(ids.contains(&"beta"));
    }

    #[test]
    fn dashboard_all_pools_btree_order() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "zebra",
            vec![PoolSnapshot::new("z", 0, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "apple",
            vec![PoolSnapshot::new("a", 0, 100, None)],
        ));
        let all = dash.all_pools();
        // BTreeMap ensures alphabetical ordering
        assert_eq!(all[0].0, "apple");
        assert_eq!(all[1].0, "zebra");
    }

    #[test]
    fn dashboard_serde_empty() {
        let dash = RateLimitDashboard::new();
        let json = serde_json::to_value(&dash).unwrap();
        assert!(json["connectors"].as_object().unwrap().is_empty());
        assert!(json.get("computed_at").is_some());
    }

    #[test]
    fn dashboard_serde_with_multiple_connectors() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 10, 100, None)],
        ));
        dash.add(ConnectorRateLimits::new(
            "slack",
            vec![PoolSnapshot::new("api", 50, 100, None)],
        ));
        let json = serde_json::to_value(&dash).unwrap();
        let connectors = json["connectors"].as_object().unwrap();
        assert_eq!(connectors.len(), 2);
        assert!(connectors.contains_key("github"));
        assert!(connectors.contains_key("slack"));
    }

    #[test]
    fn dashboard_is_clear_transitions() {
        let mut dash = RateLimitDashboard::new();
        assert!(dash.is_clear());

        dash.add(ConnectorRateLimits::new(
            "ok_connector",
            vec![PoolSnapshot::new("pool", 10, 100, None)],
        ));
        assert!(dash.is_clear());

        dash.add(ConnectorRateLimits::new(
            "bad_connector",
            vec![PoolSnapshot::new("pool", 96, 100, None)],
        ));
        assert!(!dash.is_clear());
    }

    #[test]
    fn dashboard_concerning_pools_returns_correct_pairs() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("ok_pool", 10, 100, None),
                PoolSnapshot::new("crit_pool", 96, 100, None),
            ],
        ));
        let concerning = dash.concerning_pools();
        assert_eq!(concerning.len(), 1);
        assert_eq!(concerning[0].0, "github");
        assert_eq!(concerning[0].1.pool, "crit_pool");
    }

    #[test]
    fn dashboard_replace_clears_old_pools() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("a", 0, 100, None),
                PoolSnapshot::new("b", 0, 100, None),
                PoolSnapshot::new("c", 0, 100, None),
            ],
        ));
        assert_eq!(dash.pool_count(), 3);

        // Replace with single pool
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("only", 50, 100, None)],
        ));
        assert_eq!(dash.pool_count(), 1);
    }

    #[test]
    fn dashboard_summary_line_format_single_concern() {
        let mut dash = RateLimitDashboard::new();
        dash.add(ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new("core", 96, 100, None)],
        ));
        let summary = dash.summary_line();
        assert!(summary.contains("1 pools tracked"));
        assert!(summary.contains("1 need attention"));
        assert!(summary.contains("1 connector(s)"));
    }

    #[test]
    fn dashboard_computed_at_is_recent() {
        let before = Utc::now();
        let dash = RateLimitDashboard::new();
        let after = Utc::now();
        assert!(dash.computed_at >= before);
        assert!(dash.computed_at <= after);
    }

    // ── estimate_budget additional ───────────────────────────────

    #[test]
    fn budget_cost_equals_remaining() {
        assert_eq!(estimate_budget(100, 100), 1);
    }

    #[test]
    fn budget_both_zero() {
        assert_eq!(estimate_budget(0, 0), u64::MAX);
    }

    #[test]
    fn budget_one_remaining_one_cost() {
        assert_eq!(estimate_budget(1, 1), 1);
    }

    #[test]
    fn budget_max_remaining() {
        assert_eq!(estimate_budget(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn budget_large_cost() {
        assert_eq!(estimate_budget(1_000_000, 1_000_000), 1);
    }

    #[test]
    fn budget_cost_one_more_than_remaining() {
        assert_eq!(estimate_budget(99, 100), 0);
    }

    #[test]
    fn budget_integer_division_truncates() {
        // 7 / 3 = 2 (not 2.33)
        assert_eq!(estimate_budget(7, 3), 2);
    }

    // ── recommend_delay additional ───────────────────────────────

    #[test]
    fn delay_ops_equals_remaining() {
        let delay = recommend_delay(10, 10, Duration::minutes(10));
        // 10 ops in 10 min → 60s each
        assert_eq!(delay.num_seconds(), 60);
    }

    #[test]
    fn delay_one_remaining_many_ops() {
        let delay = recommend_delay(1, 100, Duration::minutes(10));
        // Only 1 remaining → divisor=1 → 600s
        assert_eq!(delay.num_seconds(), 600);
    }

    #[test]
    fn delay_many_remaining_one_op() {
        let delay = recommend_delay(1000, 1, Duration::minutes(10));
        // 1 op → divisor=1 → 600s
        assert_eq!(delay.num_seconds(), 600);
    }

    #[test]
    fn delay_small_window() {
        let delay = recommend_delay(100, 10, Duration::milliseconds(500));
        // 500ms / 10 = 50ms
        assert_eq!(delay.num_milliseconds(), 50);
    }

    #[test]
    fn delay_one_millisecond_window() {
        let delay = recommend_delay(100, 1, Duration::milliseconds(1));
        assert_eq!(delay.num_milliseconds(), 1);
    }

    #[test]
    fn delay_remaining_one_ops_one() {
        let delay = recommend_delay(1, 1, Duration::seconds(30));
        // divisor=1 → 30s
        assert_eq!(delay.num_seconds(), 30);
    }

    #[test]
    fn delay_large_numbers() {
        let delay = recommend_delay(1_000_000, 500_000, Duration::hours(1));
        // 500000 ops in 3600s → 3600000ms/500000 = 7ms
        assert_eq!(delay.num_milliseconds(), 7);
    }

    #[test]
    fn delay_zero_time_nonzero_inputs() {
        let delay = recommend_delay(50, 10, Duration::zero());
        assert!(delay.is_zero());
    }
}
