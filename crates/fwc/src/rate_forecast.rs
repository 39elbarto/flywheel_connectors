//! Rate limit forecasting and budget optimization.
//!
//! Predicts when quota will be exhausted based on usage patterns, checks
//! batch feasibility, and suggests optimal scheduling for planned operations.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::rate_limit::PoolSnapshot;

// ── Usage Rate ────────────────────────────────────────────────────

/// Observed usage rate for a pool.
#[derive(Clone, Debug, Serialize)]
pub struct UsageRate {
    /// Pool name.
    pub pool: String,
    /// Requests per hour.
    pub requests_per_hour: f64,
    /// Observation window in seconds.
    pub observation_window_secs: u64,
    /// Total requests observed in the window.
    pub observed_requests: u64,
}

impl UsageRate {
    /// Calculate usage rate from a snapshot and observation window.
    ///
    /// `used` is the total used in the current window, and `window_secs` is
    /// how long the current window has been active.
    pub fn from_snapshot(pool: &str, used: u64, window_secs: u64) -> Self {
        let requests_per_hour = if window_secs > 0 {
            (used as f64 / window_secs as f64) * 3600.0
        } else {
            0.0
        };
        Self {
            pool: pool.to_string(),
            requests_per_hour,
            observation_window_secs: window_secs,
            observed_requests: used,
        }
    }

    /// Estimate requests per second.
    pub fn requests_per_second(&self) -> f64 {
        self.requests_per_hour / 3600.0
    }

    /// Estimate requests per minute.
    pub fn requests_per_minute(&self) -> f64 {
        self.requests_per_hour / 60.0
    }

    /// Human-readable rate.
    pub fn display_rate(&self) -> String {
        if self.requests_per_hour < 1.0 {
            format!("{:.1} req/hour", self.requests_per_hour)
        } else if self.requests_per_hour < 60.0 {
            format!("{:.0} req/hour", self.requests_per_hour)
        } else {
            format!("{:.0} req/min", self.requests_per_minute())
        }
    }
}

// ── Forecast ──────────────────────────────────────────────────────

/// Prediction for when a pool's quota will be exhausted.
#[derive(Clone, Debug, Serialize)]
pub struct ExhaustionForecast {
    /// Pool name.
    pub pool: String,
    /// Remaining quota.
    pub remaining: u64,
    /// Current usage rate (requests per hour).
    pub rate_per_hour: f64,
    /// Predicted time to exhaustion.
    pub exhausts_in: Option<Duration>,
    /// Predicted exhaustion timestamp.
    pub exhausts_at: Option<DateTime<Utc>>,
    /// When the window resets.
    pub resets_at: Option<DateTime<Utc>>,
    /// Whether exhaustion will occur before reset.
    pub will_exhaust_before_reset: bool,
    /// Recommendation.
    pub recommendation: ForecastRecommendation,
}

/// Recommendation based on forecast.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForecastRecommendation {
    /// Safe to proceed — quota is plentiful.
    Safe,
    /// Caution — quota may run out before reset.
    Caution,
    /// Slow down — at current rate, will exhaust before reset.
    SlowDown,
    /// Wait for reset — not enough quota for current rate.
    WaitForReset,
    /// Idle — no significant usage detected.
    Idle,
}

impl std::fmt::Display for ForecastRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Safe => f.write_str("safe"),
            Self::Caution => f.write_str("caution"),
            Self::SlowDown => f.write_str("slow_down"),
            Self::WaitForReset => f.write_str("wait_for_reset"),
            Self::Idle => f.write_str("idle"),
        }
    }
}

/// Compute an exhaustion forecast for a pool.
pub fn forecast_pool(snapshot: &PoolSnapshot, window_elapsed_secs: u64) -> ExhaustionForecast {
    let rate = UsageRate::from_snapshot(&snapshot.pool, snapshot.used, window_elapsed_secs);
    let remaining = snapshot.remaining();

    // No usage → idle
    if rate.requests_per_hour < 0.01 {
        return ExhaustionForecast {
            pool: snapshot.pool.clone(),
            remaining,
            rate_per_hour: rate.requests_per_hour,
            exhausts_in: None,
            exhausts_at: None,
            resets_at: snapshot.resets_at,
            will_exhaust_before_reset: false,
            recommendation: ForecastRecommendation::Idle,
        };
    }

    // Time to exhaustion
    let hours_to_exhaust = remaining as f64 / rate.requests_per_hour;
    #[allow(clippy::cast_possible_truncation)]
    let secs_to_exhaust = (hours_to_exhaust * 3600.0) as i64;
    let exhausts_in = Duration::seconds(secs_to_exhaust);
    let exhausts_at = Utc::now() + exhausts_in;

    // Compare with reset time
    let will_exhaust_before_reset = snapshot.resets_at.is_none_or(|reset| exhausts_at < reset);

    let recommendation = if !will_exhaust_before_reset {
        // Will reset before exhaustion
        if snapshot.percent >= 80 {
            ForecastRecommendation::Caution
        } else {
            ForecastRecommendation::Safe
        }
    } else if remaining == 0 {
        ForecastRecommendation::WaitForReset
    } else if secs_to_exhaust < 300 {
        // Less than 5 minutes
        ForecastRecommendation::SlowDown
    } else {
        ForecastRecommendation::Caution
    };

    ExhaustionForecast {
        pool: snapshot.pool.clone(),
        remaining,
        rate_per_hour: rate.requests_per_hour,
        exhausts_in: Some(exhausts_in),
        exhausts_at: Some(exhausts_at),
        resets_at: snapshot.resets_at,
        will_exhaust_before_reset,
        recommendation,
    }
}

// ── Batch Feasibility ─────────────────────────────────────────────

/// Result of checking whether a batch of operations is feasible.
#[derive(Clone, Debug, Serialize)]
pub struct BatchFeasibility {
    /// Pool name.
    pub pool: String,
    /// Operations requested.
    pub ops_requested: u64,
    /// Currently remaining.
    pub remaining: u64,
    /// Whether the batch fits in current quota.
    pub fits_now: bool,
    /// Operations that can be done before needing to wait.
    pub ops_before_wait: u64,
    /// If doesn't fit, how long to wait for reset.
    pub wait_for_reset: Option<Duration>,
    /// Estimated time to complete the batch.
    pub estimated_completion: Duration,
    /// Whether the batch is feasible within one reset window.
    pub feasible_in_one_window: bool,
}

/// Check if a batch of operations is feasible against a pool.
pub fn check_batch_feasibility(snapshot: &PoolSnapshot, ops_requested: u64) -> BatchFeasibility {
    let remaining = snapshot.remaining();
    let fits_now = ops_requested <= remaining;
    let ops_before_wait = remaining.min(ops_requested);

    let wait_for_reset = if fits_now {
        None
    } else {
        Some(snapshot.time_to_reset())
    };

    // Feasible in one window if total limit is enough
    let feasible_in_one_window = ops_requested <= snapshot.limit;

    // Estimated completion time
    let reset_dur = snapshot.time_to_reset();
    let estimated_completion = if fits_now {
        Duration::zero()
    } else if feasible_in_one_window {
        reset_dur
    } else {
        // Need multiple windows
        let windows_needed = ops_requested.div_ceil(snapshot.limit).max(1);
        reset_dur * i32::try_from(windows_needed).unwrap_or(i32::MAX)
    };

    BatchFeasibility {
        pool: snapshot.pool.clone(),
        ops_requested,
        remaining,
        fits_now,
        ops_before_wait,
        wait_for_reset,
        estimated_completion,
        feasible_in_one_window,
    }
}

// ── Optimal Scheduling ────────────────────────────────────────────

/// Suggestion for optimal scheduling.
#[derive(Clone, Debug, Serialize)]
pub struct SchedulingSuggestion {
    /// Pool name.
    pub pool: String,
    /// Suggested max requests per hour to stay within budget.
    pub suggested_rate_per_hour: f64,
    /// Suggested delay between operations in milliseconds.
    pub suggested_delay_ms: u64,
    /// Whether to wait before starting.
    pub wait_before_start: Option<Duration>,
    /// Reasoning.
    pub reasoning: String,
}

/// Suggest optimal scheduling for operations against a pool.
pub fn suggest_scheduling(
    snapshot: &PoolSnapshot,
    ops_needed: u64,
    deadline: Option<Duration>,
) -> SchedulingSuggestion {
    let remaining = snapshot.remaining();
    let reset_dur = snapshot.time_to_reset();
    let reset_secs = reset_dur.num_seconds().max(1);

    // If we have enough quota, distribute across remaining window
    if ops_needed <= remaining {
        let rate = if ops_needed > 0 && reset_secs > 0 {
            (ops_needed as f64 / reset_secs as f64) * 3600.0
        } else {
            0.0
        };
        let delay_ms = if ops_needed > 1 && reset_secs > 0 {
            u64::try_from(reset_secs).unwrap_or(u64::MAX) * 1000 / ops_needed
        } else {
            0
        };

        return SchedulingSuggestion {
            pool: snapshot.pool.clone(),
            suggested_rate_per_hour: rate,
            suggested_delay_ms: delay_ms,
            wait_before_start: None,
            reasoning: format!(
                "{remaining} remaining, {ops_needed} needed — fits in current window"
            ),
        };
    }

    // Not enough quota — suggest waiting for reset
    let after_reset_remaining = snapshot.limit;
    let total_available = remaining + after_reset_remaining;

    if ops_needed <= total_available {
        // Can complete after one reset
        let rate = if ops_needed > 0 {
            let total_time = reset_secs + reset_secs; // current + next window
            (ops_needed as f64 / total_time as f64) * 3600.0
        } else {
            0.0
        };

        SchedulingSuggestion {
            pool: snapshot.pool.clone(),
            suggested_rate_per_hour: rate,
            suggested_delay_ms: 0,
            wait_before_start: Some(reset_dur),
            reasoning: format!(
                "Need {ops_needed} ops but only {remaining} remaining. \
                 After reset ({} left), will have {after_reset_remaining} available.",
                format_duration(reset_dur)
            ),
        }
    } else {
        // Needs multiple windows
        let windows = ops_needed.div_ceil(snapshot.limit);
        let total_time = reset_secs * i64::try_from(windows).unwrap_or(i64::MAX);
        let rate = if total_time > 0 {
            (ops_needed as f64 / total_time as f64) * 3600.0
        } else {
            0.0
        };

        let _ = deadline; // deadline info for future use

        SchedulingSuggestion {
            pool: snapshot.pool.clone(),
            suggested_rate_per_hour: rate,
            suggested_delay_ms: 0,
            wait_before_start: Some(reset_dur),
            reasoning: format!(
                "Need {ops_needed} ops, limit is {}. Requires {windows} windows.",
                snapshot.limit
            ),
        }
    }
}

// ── Display helpers ───────────────────────────────────────────────

fn format_duration(d: Duration) -> String {
    let secs = d.num_seconds();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Format a forecast for TOON display.
pub fn format_forecast(forecast: &ExhaustionForecast) -> String {
    let mut lines = vec![format!(
        "{}: {} remaining, ~{:.0} req/hour",
        forecast.pool, forecast.remaining, forecast.rate_per_hour
    )];

    if let Some(ref exhausts_in) = forecast.exhausts_in {
        lines.push(format!(
            "  At current rate: exhausted in ~{}",
            format_duration(*exhausts_in)
        ));
    }

    if let Some(ref resets_at) = forecast.resets_at {
        let reset_dur = *resets_at - Utc::now();
        lines.push(format!(
            "  Reset: in {} (full quota restored)",
            format_duration(reset_dur)
        ));
    }

    if forecast.will_exhaust_before_reset {
        lines.push("  ⚠ Will exhaust before reset!".to_string());
    }

    lines.push(format!("  Recommendation: {}", forecast.recommendation));

    lines.join("\n")
}

/// Format batch feasibility for TOON display.
pub fn format_feasibility(f: &BatchFeasibility) -> String {
    if f.fits_now {
        format!(
            "{}: {} ops requested, {} remaining — fits in current quota",
            f.pool, f.ops_requested, f.remaining
        )
    } else if f.feasible_in_one_window {
        format!(
            "{}: {} ops requested, {} remaining — need to wait for reset (est. {})",
            f.pool,
            f.ops_requested,
            f.remaining,
            format_duration(f.estimated_completion)
        )
    } else {
        format!(
            "{}: {} ops requested — needs multiple windows (est. {})",
            f.pool,
            f.ops_requested,
            format_duration(f.estimated_completion)
        )
    }
}

/// Format scheduling suggestion for TOON display.
pub fn format_suggestion(s: &SchedulingSuggestion) -> String {
    let mut lines = vec![format!("{}: {}", s.pool, s.reasoning)];

    if s.suggested_rate_per_hour > 0.0 {
        lines.push(format!(
            "  Suggested rate: {:.0} req/hour",
            s.suggested_rate_per_hour
        ));
    }

    if s.suggested_delay_ms > 0 {
        lines.push(format!("  Delay between ops: {}ms", s.suggested_delay_ms));
    }

    if let Some(ref wait) = s.wait_before_start {
        lines.push(format!(
            "  Wait before starting: {}",
            format_duration(*wait)
        ));
    }

    lines.join("\n")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_ok() -> PoolSnapshot {
        PoolSnapshot::new("core", 500, 5000, Some(Utc::now() + Duration::hours(1)))
    }

    fn pool_high() -> PoolSnapshot {
        PoolSnapshot::new("core", 4500, 5000, Some(Utc::now() + Duration::hours(1)))
    }

    fn pool_exhausted() -> PoolSnapshot {
        PoolSnapshot::new("core", 5000, 5000, Some(Utc::now() + Duration::minutes(30)))
    }

    fn pool_no_reset() -> PoolSnapshot {
        PoolSnapshot::new("core", 4500, 5000, None)
    }

    // ── UsageRate ─────────────────────────────────────────────────

    #[test]
    fn rate_from_snapshot() {
        let rate = UsageRate::from_snapshot("core", 500, 3600);
        assert!((rate.requests_per_hour - 500.0).abs() < 0.1);
    }

    #[test]
    fn rate_zero_window() {
        let rate = UsageRate::from_snapshot("core", 100, 0);
        assert!(rate.requests_per_hour.abs() < f64::EPSILON);
    }

    #[test]
    fn rate_per_second() {
        let rate = UsageRate::from_snapshot("core", 3600, 3600);
        assert!((rate.requests_per_second() - 1.0).abs() < 0.01);
    }

    #[test]
    fn rate_per_minute() {
        let rate = UsageRate::from_snapshot("core", 600, 3600);
        assert!((rate.requests_per_minute() - 10.0).abs() < 0.1);
    }

    #[test]
    fn rate_display_low() {
        let rate = UsageRate::from_snapshot("core", 1, 7200);
        let s = rate.display_rate();
        assert!(s.contains("req/hour"));
    }

    #[test]
    fn rate_display_medium() {
        let rate = UsageRate::from_snapshot("core", 50, 3600);
        let s = rate.display_rate();
        assert!(s.contains("req/hour"));
    }

    #[test]
    fn rate_display_high() {
        let rate = UsageRate::from_snapshot("core", 3600, 3600);
        let s = rate.display_rate();
        assert!(s.contains("req/min"));
    }

    #[test]
    fn rate_serializes() {
        let rate = UsageRate::from_snapshot("core", 100, 3600);
        let json = serde_json::to_value(&rate).unwrap();
        assert_eq!(json["pool"], "core");
    }

    // ── ForecastRecommendation ────────────────────────────────────

    #[test]
    fn recommendation_display() {
        assert_eq!(ForecastRecommendation::Safe.to_string(), "safe");
        assert_eq!(ForecastRecommendation::Caution.to_string(), "caution");
        assert_eq!(ForecastRecommendation::SlowDown.to_string(), "slow_down");
        assert_eq!(
            ForecastRecommendation::WaitForReset.to_string(),
            "wait_for_reset"
        );
        assert_eq!(ForecastRecommendation::Idle.to_string(), "idle");
    }

    // ── forecast_pool ─────────────────────────────────────────────

    #[test]
    fn forecast_idle() {
        let snap = PoolSnapshot::new("core", 0, 5000, Some(Utc::now() + Duration::hours(1)));
        let f = forecast_pool(&snap, 3600);
        assert_eq!(f.recommendation, ForecastRecommendation::Idle);
        assert!(f.exhausts_in.is_none());
    }

    #[test]
    fn forecast_safe() {
        let snap = pool_ok();
        let f = forecast_pool(&snap, 1800); // 500 used in 30min → 1000/hr
        // 4500 remaining at 1000/hr → 4.5 hours to exhaust, reset in 1 hour
        assert_eq!(f.recommendation, ForecastRecommendation::Safe);
        assert!(!f.will_exhaust_before_reset);
    }

    #[test]
    fn forecast_will_exhaust() {
        let snap = pool_high();
        // 4500 used in 10min → 27000/hr, only 500 remaining
        let f = forecast_pool(&snap, 600);
        assert!(f.will_exhaust_before_reset);
    }

    #[test]
    fn forecast_exhausted() {
        let snap = pool_exhausted();
        let f = forecast_pool(&snap, 3600);
        assert_eq!(f.recommendation, ForecastRecommendation::WaitForReset);
    }

    #[test]
    fn forecast_no_reset() {
        let snap = pool_no_reset();
        let f = forecast_pool(&snap, 3600); // 4500/hr, 500 remaining
        assert!(f.will_exhaust_before_reset); // No reset → always exhausts
    }

    #[test]
    fn forecast_serializes() {
        let snap = pool_ok();
        let f = forecast_pool(&snap, 3600);
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["pool"], "core");
    }

    // ── check_batch_feasibility ───────────────────────────────────

    #[test]
    fn batch_fits_now() {
        let snap = pool_ok();
        let f = check_batch_feasibility(&snap, 100);
        assert!(f.fits_now);
        assert_eq!(f.ops_before_wait, 100);
        assert!(f.wait_for_reset.is_none());
    }

    #[test]
    fn batch_needs_wait() {
        let snap = pool_high();
        let f = check_batch_feasibility(&snap, 1000);
        assert!(!f.fits_now);
        assert_eq!(f.ops_before_wait, 500);
        assert!(f.wait_for_reset.is_some());
        assert!(f.feasible_in_one_window);
    }

    #[test]
    fn batch_needs_multiple_windows() {
        let snap = pool_ok();
        let f = check_batch_feasibility(&snap, 15000);
        assert!(!f.fits_now);
        assert!(!f.feasible_in_one_window);
    }

    #[test]
    fn batch_zero_ops() {
        let snap = pool_ok();
        let f = check_batch_feasibility(&snap, 0);
        assert!(f.fits_now);
    }

    #[test]
    fn batch_serializes() {
        let snap = pool_ok();
        let f = check_batch_feasibility(&snap, 100);
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["ops_requested"], 100);
    }

    // ── suggest_scheduling ────────────────────────────────────────

    #[test]
    fn scheduling_fits() {
        let snap = pool_ok();
        let s = suggest_scheduling(&snap, 100, None);
        assert!(s.wait_before_start.is_none());
        assert!(s.reasoning.contains("fits"));
    }

    #[test]
    fn scheduling_needs_wait() {
        let snap = pool_high();
        let s = suggest_scheduling(&snap, 1000, None);
        assert!(s.wait_before_start.is_some());
    }

    #[test]
    fn scheduling_multiple_windows() {
        let snap = pool_ok();
        let s = suggest_scheduling(&snap, 20000, None);
        assert!(s.reasoning.contains("windows"));
    }

    #[test]
    fn scheduling_zero_ops() {
        let snap = pool_ok();
        let s = suggest_scheduling(&snap, 0, None);
        assert!(s.suggested_rate_per_hour.abs() < f64::EPSILON);
    }

    #[test]
    fn scheduling_serializes() {
        let snap = pool_ok();
        let s = suggest_scheduling(&snap, 100, None);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["pool"], "core");
    }

    // ── format helpers ────────────────────────────────────────────

    #[test]
    fn format_forecast_display() {
        let snap = pool_ok();
        let f = forecast_pool(&snap, 1800);
        let s = format_forecast(&f);
        assert!(s.contains("core"));
        assert!(s.contains("remaining"));
        assert!(s.contains("Recommendation"));
    }

    #[test]
    fn format_forecast_with_warning() {
        let snap = pool_high();
        let f = forecast_pool(&snap, 600);
        let s = format_forecast(&f);
        assert!(s.contains("exhaust before reset"));
    }

    #[test]
    fn format_feasibility_fits() {
        let snap = pool_ok();
        let f = check_batch_feasibility(&snap, 100);
        let s = format_feasibility(&f);
        assert!(s.contains("fits"));
    }

    #[test]
    fn format_feasibility_needs_reset() {
        let snap = pool_high();
        let f = check_batch_feasibility(&snap, 1000);
        let s = format_feasibility(&f);
        assert!(s.contains("wait"));
    }

    #[test]
    fn format_feasibility_multiple_windows() {
        let snap = pool_ok();
        let f = check_batch_feasibility(&snap, 15000);
        let s = format_feasibility(&f);
        assert!(s.contains("multiple"));
    }

    #[test]
    fn format_suggestion_display() {
        let snap = pool_ok();
        let s = suggest_scheduling(&snap, 100, None);
        let output = format_suggestion(&s);
        assert!(output.contains("core"));
    }

    #[test]
    fn format_suggestion_with_wait() {
        let snap = pool_high();
        let s = suggest_scheduling(&snap, 1000, None);
        let output = format_suggestion(&s);
        assert!(output.contains("Wait"));
    }

    // ── format_duration ───────────────────────────────────────────

    #[test]
    fn format_dur_seconds() {
        assert_eq!(format_duration(Duration::seconds(30)), "30s");
    }

    #[test]
    fn format_dur_minutes() {
        assert_eq!(format_duration(Duration::minutes(5)), "5m");
    }

    #[test]
    fn format_dur_hours() {
        assert_eq!(
            format_duration(Duration::hours(2) + Duration::minutes(15)),
            "2h 15m"
        );
    }
}
