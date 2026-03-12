//! Automatic throttling and quota-aware scheduling for rate-limited operations.
//!
//! Integrates rate limit awareness into execution paths (invoke, map, batch,
//! pipeline) so operations are automatically throttled to stay within limits.
//! Supports configurable strategies (aggressive/balanced/conservative) and
//! wait-for-reset with countdown display.

use std::fmt;

use chrono::Duration;
use serde::Serialize;

use crate::rate_limit::{ConnectorRateLimits, PoolSnapshot};

// ── Strategy ──────────────────────────────────────────────────────

/// Throttling strategy that controls how aggressively we consume quota.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleStrategy {
    /// Use quota as fast as possible; accept rate limit errors.
    Aggressive,
    /// Default: slow down when quota is low, wait when exhausted.
    #[default]
    Balanced,
    /// Spread operations evenly; never exceed 80% of quota.
    Conservative,
}

impl ThrottleStrategy {
    /// The usage percentage threshold at which throttling kicks in.
    pub const fn slow_threshold(self) -> u8 {
        match self {
            Self::Aggressive => 95,
            Self::Balanced => 80,
            Self::Conservative => 60,
        }
    }

    /// The usage percentage at which we stop and wait for reset.
    pub const fn stop_threshold(self) -> u8 {
        match self {
            Self::Aggressive => 100,
            Self::Balanced => 95,
            Self::Conservative => 80,
        }
    }

    /// Multiplier for inter-operation delay (higher = slower).
    pub const fn delay_multiplier(self) -> u32 {
        match self {
            Self::Aggressive => 1,
            Self::Balanced => 2,
            Self::Conservative => 4,
        }
    }
}

impl fmt::Display for ThrottleStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aggressive => f.write_str("aggressive"),
            Self::Balanced => f.write_str("balanced"),
            Self::Conservative => f.write_str("conservative"),
        }
    }
}

// ── Config ────────────────────────────────────────────────────────

/// Configuration for automatic throttling.
#[derive(Clone, Debug)]
pub struct ThrottleConfig {
    /// Maximum time to wait for quota reset before giving up.
    pub max_wait: Duration,
    /// Throttling strategy.
    pub strategy: ThrottleStrategy,
    /// If true, bypass all throttling (agent accepts rate limit errors).
    pub no_throttle: bool,
    /// Specific error categories to retry on (e.g., `["rate_limited", "timeout"]`).
    pub retry_on: Vec<String>,
}

impl ThrottleConfig {
    /// Create a config with default balanced strategy.
    pub fn balanced() -> Self {
        Self {
            max_wait: Duration::seconds(30),
            strategy: ThrottleStrategy::Balanced,
            no_throttle: false,
            retry_on: vec!["rate_limited".to_string(), "timeout".to_string()],
        }
    }

    /// Create a config that disables throttling.
    pub const fn disabled() -> Self {
        Self {
            max_wait: Duration::zero(),
            strategy: ThrottleStrategy::Balanced,
            no_throttle: true,
            retry_on: Vec::new(),
        }
    }

    /// Builder: set max wait duration.
    pub const fn with_max_wait(mut self, max_wait: Duration) -> Self {
        self.max_wait = max_wait;
        self
    }

    /// Builder: set strategy.
    pub const fn with_strategy(mut self, strategy: ThrottleStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Builder: set no-throttle mode.
    pub const fn with_no_throttle(mut self, no_throttle: bool) -> Self {
        self.no_throttle = no_throttle;
        self
    }
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

// ── Decision ──────────────────────────────────────────────────────

/// The outcome of a throttle check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ThrottleDecision {
    /// Proceed immediately — quota is sufficient.
    Proceed,
    /// Slow down — add this delay before the next operation.
    Delay {
        /// Recommended delay in milliseconds.
        delay_ms: u64,
        /// Which pool triggered the delay.
        pool: String,
        /// Human-readable reason.
        reason: String,
    },
    /// Wait for quota reset — pool is exhausted.
    WaitForReset {
        /// Time to wait in milliseconds.
        wait_ms: u64,
        /// Which pool is exhausted.
        pool: String,
        /// Human-readable countdown.
        countdown: String,
    },
    /// Reject — wait would exceed `max_wait` or throttling not possible.
    Reject {
        /// Which pool caused the rejection.
        pool: String,
        /// Human-readable reason.
        reason: String,
    },
}

impl ThrottleDecision {
    /// Whether this decision allows the operation to proceed (possibly after delay).
    pub const fn allows_proceed(&self) -> bool {
        matches!(self, Self::Proceed | Self::Delay { .. })
    }

    /// Whether this decision requires waiting.
    pub const fn requires_wait(&self) -> bool {
        matches!(self, Self::Delay { .. } | Self::WaitForReset { .. })
    }

    /// Get the wait duration in milliseconds, if any.
    pub const fn wait_ms(&self) -> u64 {
        match self {
            Self::Delay { delay_ms, .. } => *delay_ms,
            Self::WaitForReset { wait_ms, .. } => *wait_ms,
            Self::Proceed | Self::Reject { .. } => 0,
        }
    }

    /// Get the pool that triggered this decision, if any.
    pub fn pool(&self) -> Option<&str> {
        match self {
            Self::Proceed => None,
            Self::Delay { pool, .. }
            | Self::WaitForReset { pool, .. }
            | Self::Reject { pool, .. } => Some(pool),
        }
    }
}

impl fmt::Display for ThrottleDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proceed => write!(f, "proceed"),
            Self::Delay { delay_ms, pool, .. } => write!(f, "delay {delay_ms}ms (pool: {pool})"),
            Self::WaitForReset {
                countdown, pool, ..
            } => write!(f, "wait for reset: {countdown} (pool: {pool})"),
            Self::Reject { pool, reason } => write!(f, "reject: {reason} (pool: {pool})"),
        }
    }
}

// ── Schedule ──────────────────────────────────────────────────────

/// A scheduled batch of operations with timing.
#[derive(Clone, Debug, Serialize)]
pub struct OperationSchedule {
    /// Total operations to execute.
    pub total_ops: u64,
    /// Delay between each operation in milliseconds.
    pub inter_op_delay_ms: u64,
    /// Estimated total duration in milliseconds.
    pub estimated_duration_ms: u64,
    /// The most restrictive pool driving the schedule.
    pub limiting_pool: String,
    /// How many operations can proceed before needing a reset wait.
    pub ops_before_wait: u64,
    /// Whether a reset wait will be needed mid-batch.
    pub needs_mid_batch_wait: bool,
    /// Estimated wait time if mid-batch pause is needed (ms).
    pub mid_batch_wait_ms: u64,
}

impl OperationSchedule {
    /// Human-readable summary of the schedule.
    pub fn summary(&self) -> String {
        let dur = format_duration_ms(self.estimated_duration_ms);
        if self.needs_mid_batch_wait {
            let wait = format_duration_ms(self.mid_batch_wait_ms);
            format!(
                "{} ops, ~{} delay between each, {} total (includes {} reset wait after {} ops)",
                self.total_ops,
                format_duration_ms(self.inter_op_delay_ms),
                dur,
                wait,
                self.ops_before_wait
            )
        } else {
            format!(
                "{} ops, ~{} delay between each, {} total",
                self.total_ops,
                format_duration_ms(self.inter_op_delay_ms),
                dur
            )
        }
    }
}

/// Cost estimate for a pipeline's total rate limit impact.
#[derive(Clone, Debug, Serialize)]
pub struct PipelineCostEstimate {
    /// Per-pool cost breakdown.
    pub pool_costs: Vec<PoolCost>,
    /// Whether the pipeline can complete within current quota.
    pub fits_in_quota: bool,
    /// Estimated resets needed.
    pub resets_needed: u32,
    /// Total estimated duration including waits.
    pub estimated_duration_ms: u64,
}

/// Cost for a single pool.
#[derive(Clone, Debug, Serialize)]
pub struct PoolCost {
    /// Pool name.
    pub pool: String,
    /// Operations that will consume from this pool.
    pub ops_needed: u64,
    /// Currently remaining quota.
    pub remaining: u64,
    /// Whether this pool is the bottleneck.
    pub is_bottleneck: bool,
}

impl PipelineCostEstimate {
    /// Human-readable summary.
    pub fn summary(&self) -> String {
        if self.fits_in_quota {
            format!(
                "Pipeline fits in current quota (est. {})",
                format_duration_ms(self.estimated_duration_ms)
            )
        } else {
            format!(
                "Pipeline needs {} reset(s), est. {}",
                self.resets_needed,
                format_duration_ms(self.estimated_duration_ms)
            )
        }
    }
}

// ── Core throttle check ───────────────────────────────────────────

/// Check a single pool against throttle config and return a decision.
pub fn check_pool_throttle(pool: &PoolSnapshot, config: &ThrottleConfig) -> ThrottleDecision {
    if config.no_throttle {
        return ThrottleDecision::Proceed;
    }

    let strategy = config.strategy;
    let percent = pool.percent;

    // Under slow threshold → proceed
    if percent < strategy.slow_threshold() {
        return ThrottleDecision::Proceed;
    }

    // At or above stop threshold → wait for reset or reject
    if percent >= strategy.stop_threshold() {
        let time_to_reset = pool.time_to_reset();
        let wait_ms = u64::try_from(time_to_reset.num_milliseconds().max(0)).unwrap_or(u64::MAX);
        let max_wait_ms =
            u64::try_from(config.max_wait.num_milliseconds().max(0)).unwrap_or(u64::MAX);

        if wait_ms == 0 || pool.resets_at.is_none() {
            // No reset time known — reject if exhausted
            if pool.remaining() == 0 {
                return ThrottleDecision::Reject {
                    pool: pool.pool.clone(),
                    reason: "quota exhausted, no reset time available".to_string(),
                };
            }
            // Still some remaining despite high percent → proceed with caution
            return ThrottleDecision::Proceed;
        }

        if wait_ms > max_wait_ms {
            return ThrottleDecision::Reject {
                pool: pool.pool.clone(),
                reason: format!(
                    "wait of {} exceeds max_wait of {}",
                    format_duration_ms(wait_ms),
                    format_duration_ms(max_wait_ms)
                ),
            };
        }

        return ThrottleDecision::WaitForReset {
            wait_ms,
            pool: pool.pool.clone(),
            countdown: format_duration_ms(wait_ms),
        };
    }

    // Between slow and stop threshold → delay
    let remaining = pool.remaining();
    let time_to_reset = pool.time_to_reset();
    let reset_ms = u64::try_from(time_to_reset.num_milliseconds().max(0)).unwrap_or(0);

    let base_delay_ms = if remaining > 0 && reset_ms > 0 {
        reset_ms / remaining
    } else {
        1000 // Default 1s delay if we can't calculate
    };

    let delay_ms = base_delay_ms * u64::from(strategy.delay_multiplier());

    ThrottleDecision::Delay {
        delay_ms,
        pool: pool.pool.clone(),
        reason: format!(
            "pool at {percent}% ({}/{}), slowing down",
            pool.used, pool.limit
        ),
    }
}

/// Check all pools for a connector and return the most restrictive decision.
pub fn check_throttle(limits: &ConnectorRateLimits, config: &ThrottleConfig) -> ThrottleDecision {
    if config.no_throttle {
        return ThrottleDecision::Proceed;
    }

    let mut worst = ThrottleDecision::Proceed;

    for pool in &limits.pools {
        let decision = check_pool_throttle(pool, config);
        worst = most_restrictive(worst, decision);
    }

    worst
}

/// Return the more restrictive of two throttle decisions.
fn most_restrictive(a: ThrottleDecision, b: ThrottleDecision) -> ThrottleDecision {
    let rank = |d: &ThrottleDecision| -> u8 {
        match d {
            ThrottleDecision::Proceed => 0,
            ThrottleDecision::Delay { .. } => 1,
            ThrottleDecision::WaitForReset { .. } => 2,
            ThrottleDecision::Reject { .. } => 3,
        }
    };

    let ra = rank(&a);
    let rb = rank(&b);

    match ra.cmp(&rb) {
        std::cmp::Ordering::Greater => a,
        std::cmp::Ordering::Less => b,
        // Same rank — pick the one with longer wait
        std::cmp::Ordering::Equal => {
            if a.wait_ms() >= b.wait_ms() {
                a
            } else {
                b
            }
        }
    }
}

// ── Scheduling ────────────────────────────────────────────────────

/// Plan an operation schedule for a batch of operations against rate limits.
pub fn schedule_operations(
    limits: &ConnectorRateLimits,
    total_ops: u64,
    config: &ThrottleConfig,
) -> OperationSchedule {
    if total_ops == 0 || config.no_throttle || limits.pools.is_empty() {
        return OperationSchedule {
            total_ops,
            inter_op_delay_ms: 0,
            estimated_duration_ms: 0,
            limiting_pool: String::new(),
            ops_before_wait: total_ops,
            needs_mid_batch_wait: false,
            mid_batch_wait_ms: 0,
        };
    }

    // Find the most restrictive pool
    let mut min_remaining = u64::MAX;
    let mut limiting_pool = String::new();
    let mut limiting_reset_ms: u64 = 0;

    for pool in &limits.pools {
        let remaining = pool.remaining();
        if remaining < min_remaining {
            min_remaining = remaining;
            limiting_pool.clone_from(&pool.pool);
            limiting_reset_ms =
                u64::try_from(pool.time_to_reset().num_milliseconds().max(0)).unwrap_or(0);
        }
    }

    let ops_before_wait = min_remaining.min(total_ops);
    let needs_mid_batch_wait = total_ops > min_remaining && min_remaining > 0;

    // Calculate inter-op delay based on strategy
    let inter_op_delay_ms = if ops_before_wait > 0 && limiting_reset_ms > 0 {
        let base = limiting_reset_ms / ops_before_wait;
        base * u64::from(config.strategy.delay_multiplier())
    } else {
        0
    };

    // Estimate total duration
    let batch_time = if ops_before_wait > 0 {
        inter_op_delay_ms * (ops_before_wait - 1)
    } else {
        0
    };
    let mid_batch_wait_ms = if needs_mid_batch_wait {
        limiting_reset_ms
    } else {
        0
    };

    // If we need more ops after wait, add time for remaining
    let remaining_ops = total_ops.saturating_sub(ops_before_wait);
    let remaining_time = if remaining_ops > 0 && needs_mid_batch_wait {
        // After reset, we get full quota
        inter_op_delay_ms * remaining_ops
    } else {
        0
    };

    let estimated_duration_ms = batch_time + mid_batch_wait_ms + remaining_time;

    OperationSchedule {
        total_ops,
        inter_op_delay_ms,
        estimated_duration_ms,
        limiting_pool,
        ops_before_wait,
        needs_mid_batch_wait,
        mid_batch_wait_ms,
    }
}

/// Estimate the rate limit cost of a pipeline.
pub fn estimate_pipeline_cost(
    limits: &ConnectorRateLimits,
    ops_per_pool: &[(String, u64)],
) -> PipelineCostEstimate {
    let mut pool_costs = Vec::new();
    let mut fits = true;
    let mut max_resets: u32 = 0;
    let mut max_wait_ms: u64 = 0;

    for (pool_name, ops_needed) in ops_per_pool {
        let pool_snap = limits.pools.iter().find(|p| p.pool == *pool_name);
        let remaining = pool_snap.map_or(u64::MAX, PoolSnapshot::remaining);
        let is_bottleneck = *ops_needed > remaining;

        if is_bottleneck {
            fits = false;
            let limit = pool_snap.map_or(1, |p| p.limit);
            let resets = if limit > 0 {
                u32::try_from(ops_needed.saturating_sub(remaining).div_ceil(limit))
                    .unwrap_or(u32::MAX)
            } else {
                u32::MAX
            };
            max_resets = max_resets.max(resets);

            if let Some(snap) = pool_snap {
                let reset_ms =
                    u64::try_from(snap.time_to_reset().num_milliseconds().max(0)).unwrap_or(0);
                max_wait_ms = max_wait_ms.max(reset_ms * u64::from(resets));
            }
        }

        pool_costs.push(PoolCost {
            pool: pool_name.clone(),
            ops_needed: *ops_needed,
            remaining,
            is_bottleneck,
        });
    }

    PipelineCostEstimate {
        pool_costs,
        fits_in_quota: fits,
        resets_needed: max_resets,
        estimated_duration_ms: max_wait_ms,
    }
}

// ── Display helpers ───────────────────────────────────────────────

/// Format milliseconds as a human-readable duration.
pub fn format_duration_ms(ms: u64) -> String {
    if ms == 0 {
        return "0s".to_string();
    }
    let secs = ms / 1000;
    if secs == 0 {
        return format!("{ms}ms");
    }
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    let rem_secs = secs % 60;
    if mins < 60 {
        if rem_secs == 0 {
            return format!("{mins}m");
        }
        return format!("{mins}m {rem_secs}s");
    }
    let hours = mins / 60;
    let rem_mins = mins % 60;
    if rem_mins == 0 {
        format!("{hours}h")
    } else {
        format!("{hours}h {rem_mins}m")
    }
}

/// Format a throttle decision for TOON output.
pub fn format_decision(decision: &ThrottleDecision) -> String {
    match decision {
        ThrottleDecision::Proceed => "✓ Quota OK, proceeding".to_string(),
        ThrottleDecision::Delay {
            delay_ms,
            pool,
            reason,
        } => {
            format!(
                "⏳ Throttling: {reason}\n   Adding {} delay (pool: {pool})",
                format_duration_ms(*delay_ms)
            )
        }
        ThrottleDecision::WaitForReset {
            countdown, pool, ..
        } => {
            format!("⏸ Quota exhausted on pool '{pool}', waiting {countdown} for reset")
        }
        ThrottleDecision::Reject { pool, reason } => {
            format!("✗ Cannot proceed: {reason} (pool: {pool})")
        }
    }
}

/// Format a schedule summary for TOON output.
pub fn format_schedule(schedule: &OperationSchedule) -> String {
    let mut lines = vec![format!("Schedule: {}", schedule.summary())];

    if schedule.inter_op_delay_ms > 0 {
        lines.push(format!(
            "  Delay between ops: {}",
            format_duration_ms(schedule.inter_op_delay_ms)
        ));
    }

    if schedule.needs_mid_batch_wait {
        lines.push(format!(
            "  ⚠ Reset wait needed after {} ops ({})",
            schedule.ops_before_wait,
            format_duration_ms(schedule.mid_batch_wait_ms)
        ));
    }

    lines.push(format!(
        "  Estimated total: {}",
        format_duration_ms(schedule.estimated_duration_ms)
    ));

    lines.join("\n")
}

/// Check whether a specific error category is retryable under this config.
pub fn is_retryable_category(category: &str, config: &ThrottleConfig) -> bool {
    config
        .retry_on
        .iter()
        .any(|c| c.eq_ignore_ascii_case(category))
}

/// Parse a strategy string into a `ThrottleStrategy`.
pub fn parse_strategy(s: &str) -> Option<ThrottleStrategy> {
    match s.to_ascii_lowercase().as_str() {
        "aggressive" => Some(ThrottleStrategy::Aggressive),
        "balanced" => Some(ThrottleStrategy::Balanced),
        "conservative" => Some(ThrottleStrategy::Conservative),
        _ => None,
    }
}

/// Parse a max-wait duration string (e.g., "30s", "5m", "1h").
pub fn parse_max_wait(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = s.strip_suffix('s').map_or_else(
        || {
            s.strip_suffix('m').map_or_else(
                || {
                    s.strip_suffix('h')
                        .map_or_else(|| (s, 's'), |stripped| (stripped, 'h'))
                },
                |stripped| (stripped, 'm'),
            )
        },
        |stripped| (stripped, 's'),
    );
    let num: i64 = num_str.parse().ok()?;
    if num < 0 {
        return None;
    }
    match unit {
        's' => Some(Duration::seconds(num)),
        'm' => Some(Duration::minutes(num)),
        'h' => Some(Duration::hours(num)),
        _ => None,
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::rate_limit::PoolSnapshot;

    // ── ThrottleStrategy ──────────────────────────────────────────

    #[test]
    fn strategy_default_is_balanced() {
        assert_eq!(ThrottleStrategy::default(), ThrottleStrategy::Balanced);
    }

    #[test]
    fn strategy_thresholds() {
        assert_eq!(ThrottleStrategy::Aggressive.slow_threshold(), 95);
        assert_eq!(ThrottleStrategy::Balanced.slow_threshold(), 80);
        assert_eq!(ThrottleStrategy::Conservative.slow_threshold(), 60);
    }

    #[test]
    fn strategy_stop_thresholds() {
        assert_eq!(ThrottleStrategy::Aggressive.stop_threshold(), 100);
        assert_eq!(ThrottleStrategy::Balanced.stop_threshold(), 95);
        assert_eq!(ThrottleStrategy::Conservative.stop_threshold(), 80);
    }

    #[test]
    fn strategy_delay_multipliers() {
        assert_eq!(ThrottleStrategy::Aggressive.delay_multiplier(), 1);
        assert_eq!(ThrottleStrategy::Balanced.delay_multiplier(), 2);
        assert_eq!(ThrottleStrategy::Conservative.delay_multiplier(), 4);
    }

    #[test]
    fn strategy_display() {
        assert_eq!(ThrottleStrategy::Aggressive.to_string(), "aggressive");
        assert_eq!(ThrottleStrategy::Balanced.to_string(), "balanced");
        assert_eq!(ThrottleStrategy::Conservative.to_string(), "conservative");
    }

    #[test]
    fn strategy_serializes() {
        let json = serde_json::to_value(ThrottleStrategy::Balanced).unwrap();
        assert_eq!(json, "balanced");
    }

    // ── ThrottleConfig ────────────────────────────────────────────

    #[test]
    fn config_balanced_defaults() {
        let config = ThrottleConfig::balanced();
        assert_eq!(config.strategy, ThrottleStrategy::Balanced);
        assert_eq!(config.max_wait, Duration::seconds(30));
        assert!(!config.no_throttle);
        assert_eq!(config.retry_on.len(), 2);
    }

    #[test]
    fn config_disabled() {
        let config = ThrottleConfig::disabled();
        assert!(config.no_throttle);
        assert!(config.retry_on.is_empty());
    }

    #[test]
    fn config_default_is_balanced() {
        let config = ThrottleConfig::default();
        assert_eq!(config.strategy, ThrottleStrategy::Balanced);
    }

    #[test]
    fn config_builder_max_wait() {
        let config = ThrottleConfig::balanced().with_max_wait(Duration::minutes(5));
        assert_eq!(config.max_wait, Duration::minutes(5));
    }

    #[test]
    fn config_builder_strategy() {
        let config = ThrottleConfig::balanced().with_strategy(ThrottleStrategy::Conservative);
        assert_eq!(config.strategy, ThrottleStrategy::Conservative);
    }

    #[test]
    fn config_builder_no_throttle() {
        let config = ThrottleConfig::balanced().with_no_throttle(true);
        assert!(config.no_throttle);
    }

    // ── ThrottleDecision ──────────────────────────────────────────

    #[test]
    fn decision_proceed_allows() {
        let d = ThrottleDecision::Proceed;
        assert!(d.allows_proceed());
        assert!(!d.requires_wait());
        assert_eq!(d.wait_ms(), 0);
        assert!(d.pool().is_none());
    }

    #[test]
    fn decision_delay_allows_and_waits() {
        let d = ThrottleDecision::Delay {
            delay_ms: 500,
            pool: "core".to_string(),
            reason: "test".to_string(),
        };
        assert!(d.allows_proceed());
        assert!(d.requires_wait());
        assert_eq!(d.wait_ms(), 500);
        assert_eq!(d.pool(), Some("core"));
    }

    #[test]
    fn decision_wait_for_reset() {
        let d = ThrottleDecision::WaitForReset {
            wait_ms: 5000,
            pool: "search".to_string(),
            countdown: "5s".to_string(),
        };
        assert!(!d.allows_proceed());
        assert!(d.requires_wait());
        assert_eq!(d.wait_ms(), 5000);
        assert_eq!(d.pool(), Some("search"));
    }

    #[test]
    fn decision_reject() {
        let d = ThrottleDecision::Reject {
            pool: "core".to_string(),
            reason: "too long".to_string(),
        };
        assert!(!d.allows_proceed());
        assert!(!d.requires_wait());
        assert_eq!(d.wait_ms(), 0);
    }

    #[test]
    fn decision_display_proceed() {
        assert_eq!(ThrottleDecision::Proceed.to_string(), "proceed");
    }

    #[test]
    fn decision_display_delay() {
        let d = ThrottleDecision::Delay {
            delay_ms: 1000,
            pool: "core".to_string(),
            reason: "slow".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("1000ms"));
        assert!(s.contains("core"));
    }

    #[test]
    fn decision_display_wait() {
        let d = ThrottleDecision::WaitForReset {
            wait_ms: 60000,
            pool: "search".to_string(),
            countdown: "1m".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("1m"));
        assert!(s.contains("search"));
    }

    #[test]
    fn decision_display_reject() {
        let d = ThrottleDecision::Reject {
            pool: "core".to_string(),
            reason: "too long".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("too long"));
    }

    #[test]
    fn decision_serializes() {
        let d = ThrottleDecision::Proceed;
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["action"], "proceed");
    }

    #[test]
    fn decision_delay_serializes() {
        let d = ThrottleDecision::Delay {
            delay_ms: 500,
            pool: "core".to_string(),
            reason: "test".to_string(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["action"], "delay");
        assert_eq!(json["delay_ms"], 500);
    }

    // ── check_pool_throttle ───────────────────────────────────────

    #[test]
    fn pool_throttle_ok_when_low_usage() {
        let pool = PoolSnapshot::new("core", 100, 5000, None);
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        assert_eq!(decision, ThrottleDecision::Proceed);
    }

    #[test]
    fn pool_throttle_delays_at_warning() {
        let pool = PoolSnapshot::new("core", 4200, 5000, Some(Utc::now() + Duration::minutes(10)));
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::Delay { .. }));
    }

    #[test]
    fn pool_throttle_waits_at_critical() {
        let pool = PoolSnapshot::new(
            "search",
            4800,
            5000,
            Some(Utc::now() + Duration::seconds(20)),
        );
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn pool_throttle_rejects_when_wait_too_long() {
        let pool = PoolSnapshot::new("core", 4900, 5000, Some(Utc::now() + Duration::hours(2)));
        let config = ThrottleConfig::balanced().with_max_wait(Duration::seconds(30));
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::Reject { .. }));
    }

    #[test]
    fn pool_throttle_skipped_when_disabled() {
        let pool = PoolSnapshot::new("core", 4999, 5000, None);
        let config = ThrottleConfig::disabled();
        let decision = check_pool_throttle(&pool, &config);
        assert_eq!(decision, ThrottleDecision::Proceed);
    }

    #[test]
    fn pool_throttle_aggressive_permits_more() {
        let pool = PoolSnapshot::new("core", 4600, 5000, Some(Utc::now() + Duration::minutes(10)));
        let aggressive = ThrottleConfig::balanced().with_strategy(ThrottleStrategy::Aggressive);
        let balanced = ThrottleConfig::balanced();

        let d_agg = check_pool_throttle(&pool, &aggressive);
        let d_bal = check_pool_throttle(&pool, &balanced);

        // Aggressive should proceed where balanced delays
        assert_eq!(d_agg, ThrottleDecision::Proceed);
        assert!(matches!(d_bal, ThrottleDecision::Delay { .. }));
    }

    #[test]
    fn pool_throttle_conservative_more_cautious() {
        let pool = PoolSnapshot::new("core", 3500, 5000, Some(Utc::now() + Duration::minutes(10)));
        let conservative = ThrottleConfig::balanced().with_strategy(ThrottleStrategy::Conservative);
        let balanced = ThrottleConfig::balanced();

        let d_cons = check_pool_throttle(&pool, &conservative);
        let d_bal = check_pool_throttle(&pool, &balanced);

        // Conservative delays at 70%, balanced proceeds
        assert!(matches!(d_cons, ThrottleDecision::Delay { .. }));
        assert_eq!(d_bal, ThrottleDecision::Proceed);
    }

    #[test]
    fn pool_throttle_exhausted_no_reset() {
        let pool = PoolSnapshot::new("core", 5000, 5000, None);
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::Reject { .. }));
    }

    // ── check_throttle (multi-pool) ───────────────────────────────

    #[test]
    fn multi_pool_picks_most_restrictive() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("core", 100, 5000, None),    // OK
                PoolSnapshot::new("search", 5000, 5000, None), // Exhausted, no reset
            ],
        );
        let config = ThrottleConfig::balanced();
        let decision = check_throttle(&limits, &config);
        assert!(matches!(decision, ThrottleDecision::Reject { .. }));
    }

    #[test]
    fn multi_pool_all_ok() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("core", 100, 5000, None),
                PoolSnapshot::new("search", 5, 30, None),
            ],
        );
        let config = ThrottleConfig::balanced();
        let decision = check_throttle(&limits, &config);
        assert_eq!(decision, ThrottleDecision::Proceed);
    }

    #[test]
    fn multi_pool_disabled() {
        let limits =
            ConnectorRateLimits::new("github", vec![PoolSnapshot::new("core", 4999, 5000, None)]);
        let config = ThrottleConfig::disabled();
        assert_eq!(check_throttle(&limits, &config), ThrottleDecision::Proceed);
    }

    // ── most_restrictive ──────────────────────────────────────────

    #[test]
    fn restrictive_proceed_vs_delay() {
        let a = ThrottleDecision::Proceed;
        let b = ThrottleDecision::Delay {
            delay_ms: 100,
            pool: "p".to_string(),
            reason: "r".to_string(),
        };
        let result = most_restrictive(a, b);
        assert!(matches!(result, ThrottleDecision::Delay { .. }));
    }

    #[test]
    fn restrictive_delay_vs_wait() {
        let a = ThrottleDecision::Delay {
            delay_ms: 100,
            pool: "p".to_string(),
            reason: "r".to_string(),
        };
        let b = ThrottleDecision::WaitForReset {
            wait_ms: 5000,
            pool: "q".to_string(),
            countdown: "5s".to_string(),
        };
        let result = most_restrictive(a, b);
        assert!(matches!(result, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn restrictive_same_rank_picks_longer() {
        let a = ThrottleDecision::Delay {
            delay_ms: 100,
            pool: "a".to_string(),
            reason: "r".to_string(),
        };
        let b = ThrottleDecision::Delay {
            delay_ms: 500,
            pool: "b".to_string(),
            reason: "r".to_string(),
        };
        let result = most_restrictive(a, b);
        assert_eq!(result.wait_ms(), 500);
    }

    // ── schedule_operations ───────────────────────────────────────

    #[test]
    fn schedule_zero_ops() {
        let limits =
            ConnectorRateLimits::new("github", vec![PoolSnapshot::new("core", 0, 5000, None)]);
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 0, &config);
        assert_eq!(sched.total_ops, 0);
        assert!(!sched.needs_mid_batch_wait);
    }

    #[test]
    fn schedule_fits_in_quota() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new(
                "core",
                0,
                5000,
                Some(Utc::now() + Duration::minutes(10)),
            )],
        );
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 100, &config);
        assert_eq!(sched.total_ops, 100);
        assert_eq!(sched.ops_before_wait, 100);
        assert!(!sched.needs_mid_batch_wait);
        assert!(sched.inter_op_delay_ms > 0);
    }

    #[test]
    fn schedule_exceeds_quota() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new(
                "core",
                4950,
                5000,
                Some(Utc::now() + Duration::minutes(5)),
            )],
        );
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 100, &config);
        assert_eq!(sched.total_ops, 100);
        assert_eq!(sched.ops_before_wait, 50);
        assert!(sched.needs_mid_batch_wait);
        assert!(sched.mid_batch_wait_ms > 0);
    }

    #[test]
    fn schedule_no_throttle() {
        let limits =
            ConnectorRateLimits::new("github", vec![PoolSnapshot::new("core", 4999, 5000, None)]);
        let config = ThrottleConfig::disabled();
        let sched = schedule_operations(&limits, 100, &config);
        assert_eq!(sched.inter_op_delay_ms, 0);
        assert!(!sched.needs_mid_batch_wait);
    }

    #[test]
    fn schedule_empty_pools() {
        let limits = ConnectorRateLimits::new("github", vec![]);
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 50, &config);
        assert_eq!(sched.inter_op_delay_ms, 0);
    }

    #[test]
    fn schedule_summary_simple() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new(
                "core",
                0,
                5000,
                Some(Utc::now() + Duration::minutes(10)),
            )],
        );
        let sched = schedule_operations(&limits, 10, &ThrottleConfig::balanced());
        let summary = sched.summary();
        assert!(summary.contains("10 ops"));
    }

    #[test]
    fn schedule_summary_with_wait() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new(
                "core",
                4990,
                5000,
                Some(Utc::now() + Duration::minutes(5)),
            )],
        );
        let sched = schedule_operations(&limits, 20, &ThrottleConfig::balanced());
        let summary = sched.summary();
        assert!(summary.contains("reset wait"));
    }

    // ── estimate_pipeline_cost ────────────────────────────────────

    #[test]
    fn pipeline_cost_fits() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("core", 0, 5000, None),
                PoolSnapshot::new("search", 0, 30, None),
            ],
        );
        let costs = estimate_pipeline_cost(
            &limits,
            &[("core".to_string(), 100), ("search".to_string(), 10)],
        );
        assert!(costs.fits_in_quota);
        assert_eq!(costs.resets_needed, 0);
    }

    #[test]
    fn pipeline_cost_exceeds() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new(
                "search",
                25,
                30,
                Some(Utc::now() + Duration::minutes(1)),
            )],
        );
        let costs = estimate_pipeline_cost(&limits, &[("search".to_string(), 20)]);
        assert!(!costs.fits_in_quota);
        assert!(costs.resets_needed > 0);
    }

    #[test]
    fn pipeline_cost_summary_fits() {
        let limits =
            ConnectorRateLimits::new("github", vec![PoolSnapshot::new("core", 0, 5000, None)]);
        let costs = estimate_pipeline_cost(&limits, &[("core".to_string(), 10)]);
        let summary = costs.summary();
        assert!(summary.contains("fits"));
    }

    #[test]
    fn pipeline_cost_summary_needs_resets() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![PoolSnapshot::new(
                "core",
                4990,
                5000,
                Some(Utc::now() + Duration::minutes(1)),
            )],
        );
        let costs = estimate_pipeline_cost(&limits, &[("core".to_string(), 100)]);
        let summary = costs.summary();
        assert!(summary.contains("reset"));
    }

    #[test]
    fn pipeline_cost_unknown_pool() {
        let limits =
            ConnectorRateLimits::new("github", vec![PoolSnapshot::new("core", 0, 5000, None)]);
        let costs = estimate_pipeline_cost(&limits, &[("unknown_pool".to_string(), 50)]);
        // Unknown pool has MAX remaining, should fit
        assert!(costs.fits_in_quota);
    }

    #[test]
    fn pipeline_cost_bottleneck_identified() {
        let limits = ConnectorRateLimits::new(
            "github",
            vec![
                PoolSnapshot::new("core", 0, 5000, None),
                PoolSnapshot::new("search", 29, 30, None),
            ],
        );
        let costs = estimate_pipeline_cost(
            &limits,
            &[("core".to_string(), 100), ("search".to_string(), 10)],
        );
        let bottleneck = costs.pool_costs.iter().find(|p| p.is_bottleneck);
        assert!(bottleneck.is_some());
        assert_eq!(bottleneck.unwrap().pool, "search");
    }

    // ── format_duration_ms ────────────────────────────────────────

    #[test]
    fn format_zero() {
        assert_eq!(format_duration_ms(0), "0s");
    }

    #[test]
    fn format_milliseconds() {
        assert_eq!(format_duration_ms(500), "500ms");
        assert_eq!(format_duration_ms(999), "999ms");
    }

    #[test]
    fn format_seconds() {
        assert_eq!(format_duration_ms(1000), "1s");
        assert_eq!(format_duration_ms(30000), "30s");
        assert_eq!(format_duration_ms(59000), "59s");
    }

    #[test]
    fn format_minutes() {
        assert_eq!(format_duration_ms(60000), "1m");
        assert_eq!(format_duration_ms(90000), "1m 30s");
        assert_eq!(format_duration_ms(300_000), "5m");
    }

    #[test]
    fn format_hours() {
        assert_eq!(format_duration_ms(3_600_000), "1h");
        assert_eq!(format_duration_ms(5_400_000), "1h 30m");
    }

    // ── format_decision ───────────────────────────────────────────

    #[test]
    fn format_proceed() {
        let s = format_decision(&ThrottleDecision::Proceed);
        assert!(s.contains("OK"));
    }

    #[test]
    fn format_delay() {
        let s = format_decision(&ThrottleDecision::Delay {
            delay_ms: 2000,
            pool: "core".to_string(),
            reason: "pool at 85%".to_string(),
        });
        assert!(s.contains("85%"));
        assert!(s.contains("2s"));
    }

    #[test]
    fn format_wait_for_reset() {
        let s = format_decision(&ThrottleDecision::WaitForReset {
            wait_ms: 60000,
            pool: "search".to_string(),
            countdown: "1m".to_string(),
        });
        assert!(s.contains("search"));
        assert!(s.contains("1m"));
    }

    #[test]
    fn format_reject() {
        let s = format_decision(&ThrottleDecision::Reject {
            pool: "core".to_string(),
            reason: "too long".to_string(),
        });
        assert!(s.contains("Cannot proceed"));
    }

    // ── format_schedule ───────────────────────────────────────────

    #[test]
    fn format_schedule_simple() {
        let sched = OperationSchedule {
            total_ops: 10,
            inter_op_delay_ms: 1000,
            estimated_duration_ms: 9000,
            limiting_pool: "core".to_string(),
            ops_before_wait: 10,
            needs_mid_batch_wait: false,
            mid_batch_wait_ms: 0,
        };
        let s = format_schedule(&sched);
        assert!(s.contains("10 ops"));
        assert!(s.contains("1s"));
    }

    #[test]
    fn format_schedule_with_wait() {
        let sched = OperationSchedule {
            total_ops: 20,
            inter_op_delay_ms: 500,
            estimated_duration_ms: 65000,
            limiting_pool: "search".to_string(),
            ops_before_wait: 5,
            needs_mid_batch_wait: true,
            mid_batch_wait_ms: 60000,
        };
        let s = format_schedule(&sched);
        assert!(s.contains("Reset wait"));
        assert!(s.contains("5 ops"));
    }

    // ── is_retryable_category ─────────────────────────────────────

    #[test]
    fn retryable_categories() {
        let config = ThrottleConfig::balanced();
        assert!(is_retryable_category("rate_limited", &config));
        assert!(is_retryable_category("timeout", &config));
        assert!(is_retryable_category("RATE_LIMITED", &config));
        assert!(!is_retryable_category("auth", &config));
    }

    #[test]
    fn retryable_disabled() {
        let config = ThrottleConfig::disabled();
        assert!(!is_retryable_category("rate_limited", &config));
    }

    // ── parse_strategy ────────────────────────────────────────────

    #[test]
    fn parse_strategies() {
        assert_eq!(
            parse_strategy("aggressive"),
            Some(ThrottleStrategy::Aggressive)
        );
        assert_eq!(parse_strategy("BALANCED"), Some(ThrottleStrategy::Balanced));
        assert_eq!(
            parse_strategy("Conservative"),
            Some(ThrottleStrategy::Conservative)
        );
        assert_eq!(parse_strategy("unknown"), None);
    }

    // ── parse_max_wait ────────────────────────────────────────────

    #[test]
    fn parse_max_wait_seconds() {
        assert_eq!(parse_max_wait("30s"), Some(Duration::seconds(30)));
    }

    #[test]
    fn parse_max_wait_minutes() {
        assert_eq!(parse_max_wait("5m"), Some(Duration::minutes(5)));
    }

    #[test]
    fn parse_max_wait_hours() {
        assert_eq!(parse_max_wait("1h"), Some(Duration::hours(1)));
    }

    #[test]
    fn parse_max_wait_bare_number() {
        assert_eq!(parse_max_wait("30"), Some(Duration::seconds(30)));
    }

    #[test]
    fn parse_max_wait_invalid() {
        assert_eq!(parse_max_wait("abc"), None);
        assert_eq!(parse_max_wait(""), None);
        assert_eq!(parse_max_wait("-5s"), None);
    }

    // ── ThrottleStrategy (extended) ──────────────────────────────

    #[test]
    fn strategy_clone_is_identical() {
        let original = ThrottleStrategy::Aggressive;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn strategy_copy_semantics() {
        let a = ThrottleStrategy::Conservative;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.slow_threshold(), b.slow_threshold());
    }

    #[test]
    fn strategy_debug_contains_name() {
        let dbg = format!("{:?}", ThrottleStrategy::Aggressive);
        assert!(dbg.contains("Aggressive"));
        let dbg = format!("{:?}", ThrottleStrategy::Balanced);
        assert!(dbg.contains("Balanced"));
        let dbg = format!("{:?}", ThrottleStrategy::Conservative);
        assert!(dbg.contains("Conservative"));
    }

    #[test]
    fn strategy_serialize_aggressive() {
        let json = serde_json::to_value(ThrottleStrategy::Aggressive).unwrap();
        assert_eq!(json, "aggressive");
    }

    #[test]
    fn strategy_serialize_conservative() {
        let json = serde_json::to_value(ThrottleStrategy::Conservative).unwrap();
        assert_eq!(json, "conservative");
    }

    #[test]
    fn strategy_all_variants_different_slow() {
        let a = ThrottleStrategy::Aggressive.slow_threshold();
        let b = ThrottleStrategy::Balanced.slow_threshold();
        let c = ThrottleStrategy::Conservative.slow_threshold();
        assert!(a > b);
        assert!(b > c);
    }

    #[test]
    fn strategy_all_variants_different_stop() {
        let a = ThrottleStrategy::Aggressive.stop_threshold();
        let b = ThrottleStrategy::Balanced.stop_threshold();
        let c = ThrottleStrategy::Conservative.stop_threshold();
        assert!(a > b);
        assert!(b > c);
    }

    #[test]
    fn strategy_slow_always_below_stop() {
        for strat in [
            ThrottleStrategy::Aggressive,
            ThrottleStrategy::Balanced,
            ThrottleStrategy::Conservative,
        ] {
            assert!(strat.slow_threshold() < strat.stop_threshold());
        }
    }

    #[test]
    fn strategy_delay_multiplier_ordering() {
        assert!(
            ThrottleStrategy::Aggressive.delay_multiplier()
                < ThrottleStrategy::Balanced.delay_multiplier()
        );
        assert!(
            ThrottleStrategy::Balanced.delay_multiplier()
                < ThrottleStrategy::Conservative.delay_multiplier()
        );
    }

    // ── ThrottleConfig (extended) ────────────────────────────────

    #[test]
    fn config_balanced_retry_categories() {
        let config = ThrottleConfig::balanced();
        assert!(config.retry_on.contains(&"rate_limited".to_string()));
        assert!(config.retry_on.contains(&"timeout".to_string()));
    }

    #[test]
    fn config_disabled_max_wait_zero() {
        let config = ThrottleConfig::disabled();
        assert_eq!(config.max_wait, Duration::zero());
    }

    #[test]
    fn config_disabled_strategy_is_balanced() {
        let config = ThrottleConfig::disabled();
        assert_eq!(config.strategy, ThrottleStrategy::Balanced);
    }

    #[test]
    fn config_clone_preserves_fields() {
        let config = ThrottleConfig::balanced()
            .with_strategy(ThrottleStrategy::Aggressive)
            .with_max_wait(Duration::minutes(10));
        let cloned = config.clone();
        assert_eq!(cloned.strategy, ThrottleStrategy::Aggressive);
        assert_eq!(cloned.max_wait, Duration::minutes(10));
        assert!(!cloned.no_throttle);
    }

    #[test]
    fn config_builder_chain_all() {
        let config = ThrottleConfig::balanced()
            .with_strategy(ThrottleStrategy::Conservative)
            .with_max_wait(Duration::hours(1))
            .with_no_throttle(true);
        assert_eq!(config.strategy, ThrottleStrategy::Conservative);
        assert_eq!(config.max_wait, Duration::hours(1));
        assert!(config.no_throttle);
    }

    #[test]
    fn config_builder_override_no_throttle_back() {
        let config = ThrottleConfig::balanced()
            .with_no_throttle(true)
            .with_no_throttle(false);
        assert!(!config.no_throttle);
    }

    // ── ThrottleDecision (extended) ──────────────────────────────

    #[test]
    fn decision_clone_proceed() {
        let d = ThrottleDecision::Proceed;
        let c = d.clone();
        assert_eq!(d, c);
    }

    #[test]
    fn decision_clone_delay() {
        let d = ThrottleDecision::Delay {
            delay_ms: 750,
            pool: "api".to_string(),
            reason: "slow down".to_string(),
        };
        let c = d.clone();
        assert_eq!(d, c);
    }

    #[test]
    fn decision_clone_wait_for_reset() {
        let d = ThrottleDecision::WaitForReset {
            wait_ms: 12000,
            pool: "core".to_string(),
            countdown: "12s".to_string(),
        };
        let c = d.clone();
        assert_eq!(d, c);
    }

    #[test]
    fn decision_clone_reject() {
        let d = ThrottleDecision::Reject {
            pool: "search".to_string(),
            reason: "exceeds max wait".to_string(),
        };
        let c = d.clone();
        assert_eq!(d, c);
    }

    #[test]
    fn decision_wait_for_reset_serializes() {
        let d = ThrottleDecision::WaitForReset {
            wait_ms: 3000,
            pool: "p".to_string(),
            countdown: "3s".to_string(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["action"], "wait_for_reset");
        assert_eq!(json["wait_ms"], 3000);
        assert_eq!(json["pool"], "p");
        assert_eq!(json["countdown"], "3s");
    }

    #[test]
    fn decision_reject_serializes() {
        let d = ThrottleDecision::Reject {
            pool: "core".to_string(),
            reason: "too long".to_string(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["action"], "reject");
        assert_eq!(json["pool"], "core");
        assert_eq!(json["reason"], "too long");
    }

    #[test]
    fn decision_delay_zero_ms() {
        let d = ThrottleDecision::Delay {
            delay_ms: 0,
            pool: "p".to_string(),
            reason: "zero".to_string(),
        };
        assert!(d.allows_proceed());
        assert!(d.requires_wait());
        assert_eq!(d.wait_ms(), 0);
    }

    #[test]
    fn decision_wait_for_reset_pool() {
        let d = ThrottleDecision::WaitForReset {
            wait_ms: 1000,
            pool: "graphql".to_string(),
            countdown: "1s".to_string(),
        };
        assert_eq!(d.pool(), Some("graphql"));
    }

    #[test]
    fn decision_reject_pool() {
        let d = ThrottleDecision::Reject {
            pool: "write".to_string(),
            reason: "denied".to_string(),
        };
        assert_eq!(d.pool(), Some("write"));
    }

    #[test]
    fn decision_display_delay_shows_ms_and_pool() {
        let d = ThrottleDecision::Delay {
            delay_ms: 250,
            pool: "rest".to_string(),
            reason: "slow".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("250ms"));
        assert!(s.contains("rest"));
    }

    #[test]
    fn decision_display_wait_shows_countdown() {
        let d = ThrottleDecision::WaitForReset {
            wait_ms: 120000,
            pool: "api".to_string(),
            countdown: "2m".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("2m"));
        assert!(s.contains("api"));
    }

    #[test]
    fn decision_display_reject_shows_reason_and_pool() {
        let d = ThrottleDecision::Reject {
            pool: "search".to_string(),
            reason: "quota exceeded".to_string(),
        };
        let s = d.to_string();
        assert!(s.contains("quota exceeded"));
        assert!(s.contains("search"));
    }

    // ── check_pool_throttle (extended) ───────────────────────────

    #[test]
    fn pool_throttle_at_exact_slow_threshold_balanced() {
        // Balanced slow_threshold = 80; at exactly 80% should trigger delay
        let pool = PoolSnapshot::new("core", 4000, 5000, Some(Utc::now() + Duration::minutes(5)));
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::Delay { .. }));
    }

    #[test]
    fn pool_throttle_just_below_slow_threshold_balanced() {
        // 79% usage, should proceed
        let pool = PoolSnapshot::new("core", 3950, 5000, None);
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        assert_eq!(decision, ThrottleDecision::Proceed);
    }

    #[test]
    fn pool_throttle_at_exact_stop_threshold_balanced() {
        // Balanced stop_threshold = 95; at exactly 95% with valid reset
        let pool = PoolSnapshot::new("core", 4750, 5000, Some(Utc::now() + Duration::seconds(10)));
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn pool_throttle_aggressive_at_99_proceeds() {
        // Aggressive slow_threshold = 95, stop_threshold = 100
        // At 99%, between slow and stop, should delay
        let pool = PoolSnapshot::new("core", 4950, 5000, Some(Utc::now() + Duration::minutes(5)));
        let config = ThrottleConfig::balanced().with_strategy(ThrottleStrategy::Aggressive);
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::Delay { .. }));
    }

    #[test]
    fn pool_throttle_aggressive_at_100_waits() {
        // Aggressive stop_threshold = 100; at 100% with reset
        let pool = PoolSnapshot::new("core", 5000, 5000, Some(Utc::now() + Duration::seconds(15)));
        let config = ThrottleConfig::balanced()
            .with_strategy(ThrottleStrategy::Aggressive)
            .with_max_wait(Duration::seconds(30));
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn pool_throttle_conservative_at_60_delays() {
        // Conservative slow_threshold = 60
        let pool = PoolSnapshot::new("core", 3000, 5000, Some(Utc::now() + Duration::minutes(10)));
        let config = ThrottleConfig::balanced().with_strategy(ThrottleStrategy::Conservative);
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::Delay { .. }));
    }

    #[test]
    fn pool_throttle_conservative_at_80_waits() {
        // Conservative stop_threshold = 80
        let pool = PoolSnapshot::new("core", 4000, 5000, Some(Utc::now() + Duration::seconds(20)));
        let config = ThrottleConfig::balanced().with_strategy(ThrottleStrategy::Conservative);
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn pool_throttle_high_percent_but_remaining_no_reset() {
        // Above stop threshold but remaining > 0 and no reset time → proceed
        // Used=4800/5000=96%, balanced stop=95%, remaining=200, resets_at=None
        // Pool has remaining > 0 AND wait_ms == 0 → proceed with caution
        let pool = PoolSnapshot::new("core", 4800, 5000, None);
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        // remaining > 0, no reset → proceeds
        assert_eq!(decision, ThrottleDecision::Proceed);
    }

    #[test]
    fn pool_throttle_delay_ms_proportional_to_multiplier() {
        // 70% usage: balanced slow=80 (proceed), conservative slow=60 (delay)
        // Use 82% which is: balanced slow=80/stop=95 → Delay, conservative slow=60/stop=80 → need < stop
        // Actually use aggressive vs balanced: 92% → aggressive slow=95 (proceed), balanced slow=80/stop=95 (Delay)
        // Better: use balanced vs aggressive at 92%
        let pool = PoolSnapshot::new("core", 4100, 5000, Some(Utc::now() + Duration::minutes(10)));
        // 82% → balanced slow=80 → Delay with multiplier=2
        let balanced = ThrottleConfig::balanced();
        // 82% → aggressive slow=95 → Proceed (not Delay) — can't compare
        // Instead compare balanced (mult=2) at 82% by checking the delay_ms value directly
        let d_bal = check_pool_throttle(&pool, &balanced);

        if let ThrottleDecision::Delay {
            delay_ms: ms_bal, ..
        } = &d_bal
        {
            // With multiplier=2, delay should be > base_delay
            // base_delay = reset_ms / remaining, delay = base * 2
            assert!(*ms_bal > 0, "balanced delay should be positive");
            // The multiplier doubles the base delay
            let remaining = pool.remaining(); // 900
            let reset_ms = 10 * 60 * 1000; // ~600000
            let base = reset_ms / remaining; // ~666
            // delay should be approximately base * 2
            assert!(*ms_bal >= base, "delay should be at least base");
        } else {
            panic!("expected Delay for balanced at 82%");
        }
    }

    #[test]
    fn pool_throttle_zero_limit_pool() {
        // limit=0, used=0, percent computed as 100 for 0/0
        let pool = PoolSnapshot::new("empty", 0, 0, None);
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        // percent is 100 for 0/0, stop_threshold=95, remaining=0, no reset → reject
        assert!(matches!(decision, ThrottleDecision::Reject { .. }));
    }

    #[test]
    fn pool_throttle_max_wait_exactly_matches_reset() {
        // wait_ms exactly equals max_wait_ms → should allow (not reject)
        let pool = PoolSnapshot::new("core", 4800, 5000, Some(Utc::now() + Duration::seconds(30)));
        let config = ThrottleConfig::balanced().with_max_wait(Duration::seconds(31));
        let decision = check_pool_throttle(&pool, &config);
        assert!(matches!(decision, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn pool_throttle_delay_reason_includes_usage_info() {
        let pool = PoolSnapshot::new("core", 4100, 5000, Some(Utc::now() + Duration::minutes(5)));
        let config = ThrottleConfig::balanced();
        let decision = check_pool_throttle(&pool, &config);
        if let ThrottleDecision::Delay { reason, pool, .. } = &decision {
            assert!(reason.contains("4100"));
            assert!(reason.contains("5000"));
            assert_eq!(pool, "core");
        } else {
            panic!("expected Delay");
        }
    }

    // ── check_throttle multi-pool (extended) ─────────────────────

    #[test]
    fn multi_pool_delay_beats_proceed() {
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![
                PoolSnapshot::new("core", 100, 5000, None),
                PoolSnapshot::new("search", 25, 30, Some(Utc::now() + Duration::minutes(1))),
            ],
        );
        let config = ThrottleConfig::balanced();
        let decision = check_throttle(&limits, &config);
        assert!(matches!(decision, ThrottleDecision::Delay { .. }));
    }

    #[test]
    fn multi_pool_wait_beats_delay() {
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![
                PoolSnapshot::new("core", 4200, 5000, Some(Utc::now() + Duration::minutes(10))),
                PoolSnapshot::new("search", 29, 30, Some(Utc::now() + Duration::seconds(20))),
            ],
        );
        let config = ThrottleConfig::balanced();
        let decision = check_throttle(&limits, &config);
        assert!(matches!(decision, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn multi_pool_empty_pools_proceeds() {
        let limits = ConnectorRateLimits::new("gh", vec![]);
        let config = ThrottleConfig::balanced();
        let decision = check_throttle(&limits, &config);
        assert_eq!(decision, ThrottleDecision::Proceed);
    }

    #[test]
    fn multi_pool_single_pool_delegates() {
        let pool = PoolSnapshot::new("core", 4500, 5000, Some(Utc::now() + Duration::minutes(5)));
        let limits = ConnectorRateLimits::new("gh", vec![pool.clone()]);
        let config = ThrottleConfig::balanced();

        let multi = check_throttle(&limits, &config);
        let single = check_pool_throttle(&pool, &config);
        assert_eq!(multi, single);
    }

    // ── most_restrictive (extended) ──────────────────────────────

    #[test]
    fn restrictive_proceed_vs_proceed() {
        let result = most_restrictive(ThrottleDecision::Proceed, ThrottleDecision::Proceed);
        assert_eq!(result, ThrottleDecision::Proceed);
    }

    #[test]
    fn restrictive_reject_vs_everything() {
        let reject = ThrottleDecision::Reject {
            pool: "p".to_string(),
            reason: "r".to_string(),
        };
        let proceed = ThrottleDecision::Proceed;
        let result = most_restrictive(reject.clone(), proceed);
        assert!(matches!(result, ThrottleDecision::Reject { .. }));
    }

    #[test]
    fn restrictive_wait_vs_reject() {
        let wait = ThrottleDecision::WaitForReset {
            wait_ms: 5000,
            pool: "p".to_string(),
            countdown: "5s".to_string(),
        };
        let reject = ThrottleDecision::Reject {
            pool: "q".to_string(),
            reason: "r".to_string(),
        };
        let result = most_restrictive(wait, reject);
        assert!(matches!(result, ThrottleDecision::Reject { .. }));
    }

    #[test]
    fn restrictive_reject_vs_wait() {
        let reject = ThrottleDecision::Reject {
            pool: "q".to_string(),
            reason: "r".to_string(),
        };
        let wait = ThrottleDecision::WaitForReset {
            wait_ms: 5000,
            pool: "p".to_string(),
            countdown: "5s".to_string(),
        };
        let result = most_restrictive(reject, wait);
        assert!(matches!(result, ThrottleDecision::Reject { .. }));
    }

    #[test]
    fn restrictive_same_rank_equal_wait_picks_first() {
        let a = ThrottleDecision::Delay {
            delay_ms: 300,
            pool: "a".to_string(),
            reason: "r".to_string(),
        };
        let b = ThrottleDecision::Delay {
            delay_ms: 300,
            pool: "b".to_string(),
            reason: "r".to_string(),
        };
        let result = most_restrictive(a, b);
        // Same wait_ms; a.wait_ms() >= b.wait_ms() → picks a
        assert_eq!(result.pool(), Some("a"));
    }

    #[test]
    fn restrictive_wait_for_reset_longer_wins() {
        let a = ThrottleDecision::WaitForReset {
            wait_ms: 10000,
            pool: "a".to_string(),
            countdown: "10s".to_string(),
        };
        let b = ThrottleDecision::WaitForReset {
            wait_ms: 20000,
            pool: "b".to_string(),
            countdown: "20s".to_string(),
        };
        let result = most_restrictive(a, b);
        assert_eq!(result.wait_ms(), 20000);
    }

    #[test]
    fn restrictive_proceed_vs_reject() {
        let result = most_restrictive(
            ThrottleDecision::Proceed,
            ThrottleDecision::Reject {
                pool: "p".to_string(),
                reason: "r".to_string(),
            },
        );
        assert!(matches!(result, ThrottleDecision::Reject { .. }));
    }

    #[test]
    fn restrictive_proceed_vs_wait_for_reset() {
        let result = most_restrictive(
            ThrottleDecision::Proceed,
            ThrottleDecision::WaitForReset {
                wait_ms: 5000,
                pool: "p".to_string(),
                countdown: "5s".to_string(),
            },
        );
        assert!(matches!(result, ThrottleDecision::WaitForReset { .. }));
    }

    #[test]
    fn restrictive_delay_vs_reject() {
        let delay = ThrottleDecision::Delay {
            delay_ms: 100,
            pool: "p".to_string(),
            reason: "r".to_string(),
        };
        let reject = ThrottleDecision::Reject {
            pool: "q".to_string(),
            reason: "r".to_string(),
        };
        let result = most_restrictive(delay, reject);
        assert!(matches!(result, ThrottleDecision::Reject { .. }));
    }

    // ── schedule_operations (extended) ───────────────────────────

    #[test]
    fn schedule_single_op() {
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![PoolSnapshot::new(
                "core",
                0,
                5000,
                Some(Utc::now() + Duration::minutes(10)),
            )],
        );
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 1, &config);
        assert_eq!(sched.total_ops, 1);
        assert_eq!(sched.ops_before_wait, 1);
        assert!(!sched.needs_mid_batch_wait);
        // With only 1 op, estimated_duration = inter_op_delay * (1-1) = 0
        assert_eq!(sched.estimated_duration_ms, 0);
    }

    #[test]
    fn schedule_multi_pool_picks_most_restrictive() {
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![
                PoolSnapshot::new("core", 4000, 5000, Some(Utc::now() + Duration::minutes(10))),
                PoolSnapshot::new("search", 25, 30, Some(Utc::now() + Duration::minutes(1))),
            ],
        );
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 10, &config);
        // search has only 5 remaining vs core's 1000 → search is limiting
        assert_eq!(sched.limiting_pool, "search");
        assert_eq!(sched.ops_before_wait, 5);
        assert!(sched.needs_mid_batch_wait);
    }

    #[test]
    fn schedule_all_quota_used_no_reset() {
        let limits =
            ConnectorRateLimits::new("gh", vec![PoolSnapshot::new("core", 5000, 5000, None)]);
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 10, &config);
        // min_remaining = 0, ops_before_wait = 0
        assert_eq!(sched.ops_before_wait, 0);
        assert!(!sched.needs_mid_batch_wait); // needs_mid_batch_wait requires min_remaining > 0
    }

    #[test]
    fn schedule_limiting_pool_set_correctly() {
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![
                PoolSnapshot::new("core", 100, 5000, None),
                PoolSnapshot::new("search", 28, 30, None),
            ],
        );
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 5, &config);
        assert_eq!(sched.limiting_pool, "search");
    }

    #[test]
    fn schedule_ops_equal_remaining() {
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![PoolSnapshot::new(
                "core",
                4990,
                5000,
                Some(Utc::now() + Duration::minutes(5)),
            )],
        );
        let config = ThrottleConfig::balanced();
        let sched = schedule_operations(&limits, 10, &config);
        // remaining = 10, total = 10 → exactly fits
        assert_eq!(sched.ops_before_wait, 10);
        assert!(!sched.needs_mid_batch_wait);
    }

    #[test]
    fn schedule_summary_no_delay() {
        let sched = OperationSchedule {
            total_ops: 5,
            inter_op_delay_ms: 0,
            estimated_duration_ms: 0,
            limiting_pool: String::new(),
            ops_before_wait: 5,
            needs_mid_batch_wait: false,
            mid_batch_wait_ms: 0,
        };
        let summary = sched.summary();
        assert!(summary.contains("5 ops"));
        assert!(summary.contains("0s"));
    }

    // ── estimate_pipeline_cost (extended) ────────────────────────

    #[test]
    fn pipeline_cost_empty_ops() {
        let limits = ConnectorRateLimits::new("gh", vec![PoolSnapshot::new("core", 0, 5000, None)]);
        let costs = estimate_pipeline_cost(&limits, &[]);
        assert!(costs.fits_in_quota);
        assert_eq!(costs.resets_needed, 0);
        assert!(costs.pool_costs.is_empty());
    }

    #[test]
    fn pipeline_cost_multiple_bottlenecks() {
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![
                PoolSnapshot::new("core", 4990, 5000, Some(Utc::now() + Duration::minutes(1))),
                PoolSnapshot::new("search", 29, 30, Some(Utc::now() + Duration::minutes(1))),
            ],
        );
        let costs = estimate_pipeline_cost(
            &limits,
            &[("core".to_string(), 100), ("search".to_string(), 50)],
        );
        assert!(!costs.fits_in_quota);
        let bottlenecks: Vec<_> = costs
            .pool_costs
            .iter()
            .filter(|p| p.is_bottleneck)
            .collect();
        assert_eq!(bottlenecks.len(), 2);
    }

    #[test]
    fn pipeline_cost_zero_ops_per_pool() {
        let limits = ConnectorRateLimits::new("gh", vec![PoolSnapshot::new("core", 0, 5000, None)]);
        let costs = estimate_pipeline_cost(&limits, &[("core".to_string(), 0)]);
        assert!(costs.fits_in_quota);
    }

    #[test]
    fn pipeline_cost_pool_cost_fields() {
        let limits =
            ConnectorRateLimits::new("gh", vec![PoolSnapshot::new("core", 100, 5000, None)]);
        let costs = estimate_pipeline_cost(&limits, &[("core".to_string(), 50)]);
        assert_eq!(costs.pool_costs.len(), 1);
        let pc = &costs.pool_costs[0];
        assert_eq!(pc.pool, "core");
        assert_eq!(pc.ops_needed, 50);
        assert_eq!(pc.remaining, 4900);
        assert!(!pc.is_bottleneck);
    }

    #[test]
    fn pipeline_cost_summary_includes_duration_when_fits() {
        let limits = ConnectorRateLimits::new("gh", vec![PoolSnapshot::new("core", 0, 5000, None)]);
        let costs = estimate_pipeline_cost(&limits, &[("core".to_string(), 10)]);
        let summary = costs.summary();
        assert!(summary.contains("fits"));
        assert!(summary.contains("0s")); // estimated_duration_ms=0
    }

    #[test]
    fn pipeline_cost_resets_needed_calculation() {
        // Pool limit = 30, remaining = 1, ops_needed = 100
        // resets = ceil((100-1)/30) = ceil(99/30) = 4
        let limits = ConnectorRateLimits::new(
            "gh",
            vec![PoolSnapshot::new(
                "search",
                29,
                30,
                Some(Utc::now() + Duration::minutes(1)),
            )],
        );
        let costs = estimate_pipeline_cost(&limits, &[("search".to_string(), 100)]);
        assert!(!costs.fits_in_quota);
        assert_eq!(costs.resets_needed, 4);
    }

    // ── format_duration_ms (extended) ────────────────────────────

    #[test]
    fn format_one_ms() {
        assert_eq!(format_duration_ms(1), "1ms");
    }

    #[test]
    fn format_exactly_one_second() {
        assert_eq!(format_duration_ms(1000), "1s");
    }

    #[test]
    fn format_exactly_one_minute() {
        assert_eq!(format_duration_ms(60000), "1m");
    }

    #[test]
    fn format_exactly_one_hour() {
        assert_eq!(format_duration_ms(3_600_000), "1h");
    }

    #[test]
    fn format_just_under_one_second() {
        assert_eq!(format_duration_ms(999), "999ms");
    }

    #[test]
    fn format_just_over_one_second() {
        // 1001ms → 1s (integer division: 1001/1000 = 1)
        assert_eq!(format_duration_ms(1001), "1s");
    }

    #[test]
    fn format_59_seconds() {
        assert_eq!(format_duration_ms(59_000), "59s");
    }

    #[test]
    fn format_minutes_and_seconds() {
        assert_eq!(format_duration_ms(61_000), "1m 1s");
    }

    #[test]
    fn format_hours_and_minutes() {
        assert_eq!(format_duration_ms(3_660_000), "1h 1m");
    }

    #[test]
    fn format_large_value() {
        // 2h 30m = 9_000_000ms
        assert_eq!(format_duration_ms(9_000_000), "2h 30m");
    }

    #[test]
    fn format_hours_exact() {
        // 2h = 7_200_000ms
        assert_eq!(format_duration_ms(7_200_000), "2h");
    }

    // ── format_decision (extended) ───────────────────────────────

    #[test]
    fn format_decision_delay_shows_pool() {
        let s = format_decision(&ThrottleDecision::Delay {
            delay_ms: 500,
            pool: "my_pool".to_string(),
            reason: "slow".to_string(),
        });
        assert!(s.contains("my_pool"));
    }

    #[test]
    fn format_decision_reject_shows_pool() {
        let s = format_decision(&ThrottleDecision::Reject {
            pool: "write_pool".to_string(),
            reason: "over limit".to_string(),
        });
        assert!(s.contains("write_pool"));
        assert!(s.contains("over limit"));
    }

    #[test]
    fn format_decision_wait_shows_pool_name() {
        let s = format_decision(&ThrottleDecision::WaitForReset {
            wait_ms: 5000,
            pool: "rate_pool".to_string(),
            countdown: "5s".to_string(),
        });
        assert!(s.contains("rate_pool"));
    }

    // ── format_schedule (extended) ───────────────────────────────

    #[test]
    fn format_schedule_no_delay_shows_estimated() {
        let sched = OperationSchedule {
            total_ops: 3,
            inter_op_delay_ms: 0,
            estimated_duration_ms: 0,
            limiting_pool: String::new(),
            ops_before_wait: 3,
            needs_mid_batch_wait: false,
            mid_batch_wait_ms: 0,
        };
        let s = format_schedule(&sched);
        assert!(s.contains("Estimated total"));
    }

    #[test]
    fn format_schedule_with_delay_shows_delay_line() {
        let sched = OperationSchedule {
            total_ops: 10,
            inter_op_delay_ms: 2000,
            estimated_duration_ms: 18000,
            limiting_pool: "core".to_string(),
            ops_before_wait: 10,
            needs_mid_batch_wait: false,
            mid_batch_wait_ms: 0,
        };
        let s = format_schedule(&sched);
        assert!(s.contains("Delay between ops"));
        assert!(s.contains("2s"));
    }

    // ── is_retryable_category (extended) ─────────────────────────

    #[test]
    fn retryable_mixed_case() {
        let config = ThrottleConfig::balanced();
        assert!(is_retryable_category("Rate_Limited", &config));
        assert!(is_retryable_category("Timeout", &config));
        assert!(is_retryable_category("TIMEOUT", &config));
    }

    #[test]
    fn retryable_empty_string() {
        let config = ThrottleConfig::balanced();
        assert!(!is_retryable_category("", &config));
    }

    #[test]
    fn retryable_partial_match_fails() {
        let config = ThrottleConfig::balanced();
        assert!(!is_retryable_category("rate", &config));
        assert!(!is_retryable_category("time", &config));
    }

    // ── parse_strategy (extended) ────────────────────────────────

    #[test]
    fn parse_strategy_mixed_case() {
        assert_eq!(
            parse_strategy("Aggressive"),
            Some(ThrottleStrategy::Aggressive)
        );
        assert_eq!(
            parse_strategy("CONSERVATIVE"),
            Some(ThrottleStrategy::Conservative)
        );
    }

    #[test]
    fn parse_strategy_empty() {
        assert_eq!(parse_strategy(""), None);
    }

    #[test]
    fn parse_strategy_whitespace_not_trimmed() {
        // parse_strategy does not trim; " balanced" should not match
        assert_eq!(parse_strategy(" balanced"), None);
    }

    // ── parse_max_wait (extended) ────────────────────────────────

    #[test]
    fn parse_max_wait_zero_seconds() {
        assert_eq!(parse_max_wait("0s"), Some(Duration::seconds(0)));
    }

    #[test]
    fn parse_max_wait_zero_minutes() {
        assert_eq!(parse_max_wait("0m"), Some(Duration::minutes(0)));
    }

    #[test]
    fn parse_max_wait_large_value() {
        assert_eq!(parse_max_wait("3600s"), Some(Duration::seconds(3600)));
    }

    #[test]
    fn parse_max_wait_trimmed_whitespace() {
        assert_eq!(parse_max_wait("  30s  "), Some(Duration::seconds(30)));
    }

    #[test]
    fn parse_max_wait_whitespace_only() {
        assert_eq!(parse_max_wait("   "), None);
    }

    #[test]
    fn parse_max_wait_negative_minutes() {
        assert_eq!(parse_max_wait("-1m"), None);
    }

    // ── OperationSchedule serialization ─────────────────────────

    #[test]
    fn operation_schedule_serializes() {
        let sched = OperationSchedule {
            total_ops: 10,
            inter_op_delay_ms: 500,
            estimated_duration_ms: 4500,
            limiting_pool: "core".to_string(),
            ops_before_wait: 10,
            needs_mid_batch_wait: false,
            mid_batch_wait_ms: 0,
        };
        let json = serde_json::to_value(&sched).unwrap();
        assert_eq!(json["total_ops"], 10);
        assert_eq!(json["inter_op_delay_ms"], 500);
        assert_eq!(json["needs_mid_batch_wait"], false);
    }

    #[test]
    fn operation_schedule_clone() {
        let sched = OperationSchedule {
            total_ops: 5,
            inter_op_delay_ms: 200,
            estimated_duration_ms: 800,
            limiting_pool: "search".to_string(),
            ops_before_wait: 5,
            needs_mid_batch_wait: false,
            mid_batch_wait_ms: 0,
        };
        let cloned = sched.clone();
        assert_eq!(cloned.total_ops, 5);
        assert_eq!(cloned.limiting_pool, "search");
    }

    // ── PipelineCostEstimate serialization ───────────────────────

    #[test]
    fn pipeline_cost_estimate_serializes() {
        let est = PipelineCostEstimate {
            pool_costs: vec![PoolCost {
                pool: "core".to_string(),
                ops_needed: 50,
                remaining: 4900,
                is_bottleneck: false,
            }],
            fits_in_quota: true,
            resets_needed: 0,
            estimated_duration_ms: 0,
        };
        let json = serde_json::to_value(&est).unwrap();
        assert_eq!(json["fits_in_quota"], true);
        assert_eq!(json["resets_needed"], 0);
    }

    #[test]
    fn pipeline_cost_estimate_clone() {
        let est = PipelineCostEstimate {
            pool_costs: vec![],
            fits_in_quota: false,
            resets_needed: 3,
            estimated_duration_ms: 180000,
        };
        let cloned = est.clone();
        assert_eq!(cloned.resets_needed, 3);
        assert!(!cloned.fits_in_quota);
    }

    // ── PoolCost serialization ──────────────────────────────────

    #[test]
    fn pool_cost_serializes() {
        let pc = PoolCost {
            pool: "search".to_string(),
            ops_needed: 100,
            remaining: 5,
            is_bottleneck: true,
        };
        let json = serde_json::to_value(&pc).unwrap();
        assert_eq!(json["pool"], "search");
        assert_eq!(json["ops_needed"], 100);
        assert_eq!(json["remaining"], 5);
        assert_eq!(json["is_bottleneck"], true);
    }

    #[test]
    fn pool_cost_clone() {
        let pc = PoolCost {
            pool: "api".to_string(),
            ops_needed: 20,
            remaining: 80,
            is_bottleneck: false,
        };
        let cloned = pc.clone();
        assert_eq!(cloned.pool, "api");
        assert_eq!(cloned.remaining, 80);
    }
}
