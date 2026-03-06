//! Rate limit tracking and error helpers for connector SDK.
//!
//! This module provides utilities for tracking rate limit pools and creating
//! rate limit violation errors with retry-after hints.
//!
//! # Example
//!
//! ```ignore
//! use fcp_sdk::ratelimit::{RateLimitTracker, RateLimitError};
//! use fcp_sdk::prelude::*;
//!
//! // Create a tracker from manifest declarations
//! let tracker = RateLimitTracker::from_declarations(&declarations);
//!
//! // Record an operation that consumes from pools
//! if let Some(err) = tracker.try_consume("send_message", 1) {
//!     return Err(err.into_fcp_error());
//! }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::{
    FcpError, RateLimitConfig, RateLimitDeclarations, RateLimitEnforcement, RateLimitPool,
    RateLimitScope, RateLimitStatus, RateLimitUnit,
};

/// Error returned when a rate limit is exceeded.
#[derive(Debug, Clone)]
pub struct RateLimitError {
    /// The pool that was exceeded.
    pub pool_id: String,
    /// The limit that was exceeded.
    pub limit: u32,
    /// The current usage.
    pub current: u32,
    /// Suggested retry delay in milliseconds.
    pub retry_after_ms: u64,
    /// The enforcement level of this limit.
    pub enforcement: RateLimitEnforcement,
    /// Human-readable message.
    pub message: String,
}

impl RateLimitError {
    /// Convert to an FCP-standard error with retry-after hints.
    #[must_use]
    pub fn into_fcp_error(self) -> FcpError {
        FcpError::RateLimited {
            retry_after_ms: self.retry_after_ms,
            violation: None,
        }
    }

    /// Create a rate limit error for a pool.
    #[must_use]
    pub fn for_pool(pool: &RateLimitPool, current: u32, retry_after_ms: u64) -> Self {
        Self {
            pool_id: pool.id.clone(),
            limit: pool.config.requests,
            current,
            retry_after_ms,
            enforcement: pool.enforcement,
            message: format!(
                "Rate limit exceeded for pool '{}': {} requests used of {} limit",
                pool.id, current, pool.config.requests
            ),
        }
    }

    /// Check if this is a soft limit (warning only).
    #[must_use]
    pub const fn is_soft(&self) -> bool {
        matches!(
            self.enforcement,
            RateLimitEnforcement::Soft | RateLimitEnforcement::Advisory
        )
    }
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RateLimitError {}

/// Runtime state for a single rate limit pool.
#[derive(Debug)]
struct PoolState {
    /// Pool configuration.
    config: RateLimitPool,
    /// Current usage count in the window.
    count: u32,
    /// Window start time.
    window_start: Instant,
}

impl PoolState {
    fn new(config: RateLimitPool) -> Self {
        Self {
            config,
            count: 0,
            window_start: Instant::now(),
        }
    }

    /// Reset window if expired.
    fn maybe_reset_window(&mut self) {
        let elapsed = self.window_start.elapsed();
        if elapsed >= self.config.config.window {
            self.count = 0;
            self.window_start = Instant::now();
        }
    }

    /// Try to consume requests, returns error if exceeded.
    fn try_consume(&mut self, amount: u32) -> Result<(), RateLimitError> {
        self.check_consume(amount)?;
        self.count = self.count.saturating_add(amount);
        Ok(())
    }

    /// Check if requests can be consumed without actually consuming them.
    fn check_consume(&mut self, amount: u32) -> Result<(), RateLimitError> {
        self.maybe_reset_window();

        let effective_limit = self.config.config.requests + self.config.config.burst.unwrap_or(0);

        if self.count.saturating_add(amount) > effective_limit {
            let retry_after_ms = self.ms_until_reset();
            return Err(RateLimitError::for_pool(
                &self.config,
                self.count,
                retry_after_ms,
            ));
        }

        Ok(())
    }

    /// Force consume requests (used for soft limits).
    fn force_consume(&mut self, amount: u32) {
        self.maybe_reset_window();
        self.count = self.count.saturating_add(amount);
    }

    /// Get milliseconds until window reset.
    fn ms_until_reset(&self) -> u64 {
        let elapsed = self.window_start.elapsed();
        if elapsed >= self.config.config.window {
            0
        } else {
            let remaining = self
                .config
                .config
                .window
                .checked_sub(elapsed)
                .unwrap_or(Duration::ZERO);
            u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)
        }
    }

    /// Get current status.
    fn status(&mut self) -> RateLimitStatus {
        self.maybe_reset_window();
        let effective_limit = self.config.config.requests + self.config.config.burst.unwrap_or(0);
        let remaining = effective_limit.saturating_sub(self.count);
        let reset_at = {
            let elapsed_secs = self.window_start.elapsed().as_secs();
            let window_secs = self.config.config.window.as_secs();
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            now_secs + window_secs.saturating_sub(elapsed_secs)
        };

        RateLimitStatus {
            limit: effective_limit,
            remaining,
            reset_at,
            window_seconds: u32::try_from(self.config.config.window.as_secs()).unwrap_or(u32::MAX),
        }
    }
}

/// Thread-safe rate limit tracker for connector pools.
///
/// Tracks multiple rate limit pools and enforces limits based on
/// manifest declarations.
#[derive(Debug, Clone)]
pub struct RateLimitTracker {
    pools: Arc<RwLock<HashMap<String, PoolState>>>,
    operation_map: Arc<HashMap<String, Vec<String>>>,
}

impl Default for RateLimitTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            operation_map: Arc::new(HashMap::new()),
        }
    }

    /// Create a tracker from rate limit declarations.
    #[must_use]
    pub fn from_declarations(decls: &RateLimitDeclarations) -> Self {
        let pools: HashMap<String, PoolState> = decls
            .limits
            .iter()
            .map(|pool| (pool.id.clone(), PoolState::new(pool.clone())))
            .collect();

        Self {
            pools: Arc::new(RwLock::new(pools)),
            operation_map: Arc::new(decls.tool_pool_map.clone()),
        }
    }

    /// Add a pool to the tracker.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned (indicates a prior panic during pool access).
    pub fn add_pool(&self, pool: RateLimitPool) {
        let mut pools = self.pools.write().expect("lock poisoned");
        pools.insert(pool.id.clone(), PoolState::new(pool));
    }

    /// Try to consume requests for an operation.
    ///
    /// Returns `Some(error)` if any pool is exceeded, `None` if all pools have capacity.
    /// For soft limits, logs a warning but returns `None`.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn try_consume(&self, operation: &str, amount: u32) -> Option<RateLimitError> {
        let pool_ids = self.operation_map.get(operation)?;
        let mut pools = self.pools.write().expect("lock poisoned");

        // Phase 1: Check capacity (all-or-nothing)
        for pool_id in pool_ids {
            if let Some(pool_state) = pools.get_mut(pool_id) {
                if let Err(err) = pool_state.check_consume(amount) {
                    if !err.is_soft() {
                        return Some(err);
                    }
                }
            }
        }

        // Phase 2: Consume
        for pool_id in pool_ids {
            if let Some(pool_state) = pools.get_mut(pool_id) {
                if let Err(err) = pool_state.try_consume(amount) {
                    if err.is_soft() {
                        tracing::warn!(
                            pool = %pool_id,
                            operation = %operation,
                            "Soft rate limit exceeded: {}",
                            err.message
                        );
                        pool_state.force_consume(amount);
                    }
                }
            }
        }

        None
    }

    /// Get the status of a specific pool.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn pool_status(&self, pool_id: &str) -> Option<RateLimitStatus> {
        let mut pools = self.pools.write().expect("lock poisoned");
        pools.get_mut(pool_id).map(PoolState::status)
    }

    /// Get status for all pools affecting an operation.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn operation_status(&self, operation: &str) -> Vec<(String, RateLimitStatus)> {
        let pool_ids = match self.operation_map.get(operation) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        let mut pools = self.pools.write().expect("lock poisoned");
        pool_ids
            .into_iter()
            .filter_map(|pool_id| {
                pools
                    .get_mut(&pool_id)
                    .map(|state| (pool_id, state.status()))
            })
            .collect()
    }

    /// Get the most constrained status for an operation.
    ///
    /// Returns the pool with the lowest remaining capacity.
    #[must_use]
    pub fn most_constrained_status(&self, operation: &str) -> Option<(String, RateLimitStatus)> {
        self.operation_status(operation)
            .into_iter()
            .min_by_key(|(_, status)| status.remaining)
    }

    /// Check if an operation is currently rate limited.
    #[must_use]
    pub fn is_limited(&self, operation: &str) -> bool {
        self.operation_status(operation)
            .iter()
            .any(|(_, status)| status.is_limited())
    }

    /// Get all pool statuses.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn all_pool_statuses(&self) -> HashMap<String, RateLimitStatus> {
        let mut pools = self.pools.write().expect("lock poisoned");
        pools
            .iter_mut()
            .map(|(id, state)| (id.clone(), state.status()))
            .collect()
    }

    /// Reset all pools (for testing).
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned.
    pub fn reset_all(&self) {
        let mut pools = self.pools.write().expect("lock poisoned");
        for state in pools.values_mut() {
            state.count = 0;
            state.window_start = Instant::now();
        }
    }
}

/// Builder for creating rate limit pools with fluent API.
#[derive(Debug, Clone)]
pub struct RateLimitPoolBuilder {
    id: String,
    description: String,
    requests: u32,
    window: Duration,
    burst: Option<u32>,
    unit: RateLimitUnit,
    enforcement: RateLimitEnforcement,
    scope: RateLimitScope,
}

impl RateLimitPoolBuilder {
    /// Create a new pool builder with the given ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: String::new(),
            requests: 60,
            window: Duration::from_secs(60),
            burst: None,
            unit: RateLimitUnit::Requests,
            enforcement: RateLimitEnforcement::Hard,
            scope: RateLimitScope::Instance,
        }
    }

    /// Set the description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set requests per window.
    #[must_use]
    pub const fn requests(mut self, requests: u32) -> Self {
        self.requests = requests;
        self
    }

    /// Set window duration.
    #[must_use]
    pub const fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Set window duration in seconds.
    #[must_use]
    pub const fn window_secs(mut self, secs: u64) -> Self {
        self.window = Duration::from_secs(secs);
        self
    }

    /// Set burst allowance.
    #[must_use]
    pub const fn burst(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Set unit of measurement.
    #[must_use]
    pub const fn unit(mut self, unit: RateLimitUnit) -> Self {
        self.unit = unit;
        self
    }

    /// Set enforcement level.
    #[must_use]
    pub const fn enforcement(mut self, enforcement: RateLimitEnforcement) -> Self {
        self.enforcement = enforcement;
        self
    }

    /// Set scope.
    #[must_use]
    pub const fn scope(mut self, scope: RateLimitScope) -> Self {
        self.scope = scope;
        self
    }

    /// Build the rate limit pool.
    #[must_use]
    pub fn build(self) -> RateLimitPool {
        RateLimitPool {
            id: self.id,
            description: self.description,
            config: RateLimitConfig {
                requests: self.requests,
                window: self.window,
                burst: self.burst,
                unit: self.unit,
            },
            enforcement: self.enforcement,
            scope: self.scope,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool(id: &str, requests: u32, window_secs: u64) -> RateLimitPool {
        RateLimitPoolBuilder::new(id)
            .requests(requests)
            .window_secs(window_secs)
            .build()
    }

    #[test]
    fn tracker_from_declarations() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60), test_pool("tokens", 1000, 3600)],
            tool_pool_map: HashMap::from([
                ("send".to_string(), vec!["api".to_string()]),
                (
                    "generate".to_string(),
                    vec!["api".to_string(), "tokens".to_string()],
                ),
            ]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);

        // Should have status for both pools
        assert!(tracker.pool_status("api").is_some());
        assert!(tracker.pool_status("tokens").is_some());
        assert!(tracker.pool_status("nonexistent").is_none());
    }

    #[test]
    fn tracker_consume_and_limit() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([("send".to_string(), vec!["api".to_string()])]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);

        // Should be able to consume 3 requests
        assert!(tracker.try_consume("send", 1).is_none());
        assert!(tracker.try_consume("send", 1).is_none());
        assert!(tracker.try_consume("send", 1).is_none());

        // Fourth should fail
        let err = tracker.try_consume("send", 1);
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.pool_id, "api");
        assert_eq!(err.limit, 3);
    }

    #[test]
    fn tracker_operation_status() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60), test_pool("tokens", 1000, 3600)],
            tool_pool_map: HashMap::from([(
                "generate".to_string(),
                vec!["api".to_string(), "tokens".to_string()],
            )]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("generate", 5);

        let statuses = tracker.operation_status("generate");
        assert_eq!(statuses.len(), 2);

        // Find api pool status
        let api_status = statuses.iter().find(|(id, _)| id == "api").unwrap();
        assert_eq!(api_status.1.remaining, 5);

        // Find tokens pool status
        let tokens_status = statuses.iter().find(|(id, _)| id == "tokens").unwrap();
        assert_eq!(tokens_status.1.remaining, 995);
    }

    #[test]
    fn pool_builder_fluent_api() {
        let pool = RateLimitPoolBuilder::new("my_pool")
            .description("My rate limit pool")
            .requests(100)
            .window_secs(60)
            .burst(20)
            .unit(RateLimitUnit::Tokens)
            .enforcement(RateLimitEnforcement::Soft)
            .scope(RateLimitScope::Credential)
            .build();

        assert_eq!(pool.id, "my_pool");
        assert_eq!(pool.description, "My rate limit pool");
        assert_eq!(pool.config.requests, 100);
        assert_eq!(pool.config.window, Duration::from_secs(60));
        assert_eq!(pool.config.burst, Some(20));
        assert_eq!(pool.config.unit, RateLimitUnit::Tokens);
        assert_eq!(pool.enforcement, RateLimitEnforcement::Soft);
        assert_eq!(pool.scope, RateLimitScope::Credential);
    }

    #[test]
    fn rate_limit_error_to_fcp_error() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 10, 5000);

        assert_eq!(err.pool_id, "api");
        assert_eq!(err.limit, 10);
        assert_eq!(err.retry_after_ms, 5000);

        let fcp_err = err.into_fcp_error();
        // Should be a rate limited error with retry after
        assert!(fcp_err.to_string().contains("Rate limited"));
        assert!(fcp_err.to_string().contains("5000"));
        assert!(fcp_err.is_retryable());
        assert_eq!(fcp_err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn soft_limit_allows_through() {
        let pool = RateLimitPoolBuilder::new("soft")
            .requests(1)
            .enforcement(RateLimitEnforcement::Soft)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["soft".to_string()])]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);

        // First request succeeds
        assert!(tracker.try_consume("op", 1).is_none());

        // Second request also "succeeds" (soft limit logs warning but doesn't block)
        assert!(tracker.try_consume("op", 1).is_none());
    }

    #[test]
    fn unknown_operation_returns_none() {
        let tracker = RateLimitTracker::new();
        // Unknown operation should not error
        assert!(tracker.try_consume("unknown_op", 1).is_none());
    }

    // ---- RateLimitError coverage ----

    #[test]
    fn rate_limit_error_display() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 8, 3000);
        let msg = err.to_string();
        assert!(msg.contains("api"));
        assert!(msg.contains('8'));
        assert!(msg.contains("10"));
    }

    #[test]
    fn rate_limit_error_is_soft_hard() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 10,
            current: 10,
            retry_after_ms: 1000,
            enforcement: RateLimitEnforcement::Hard,
            message: "test".into(),
        };
        assert!(!err.is_soft());
    }

    #[test]
    fn rate_limit_error_is_soft_advisory() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 10,
            current: 10,
            retry_after_ms: 1000,
            enforcement: RateLimitEnforcement::Advisory,
            message: "test".into(),
        };
        assert!(err.is_soft());
    }

    #[test]
    fn rate_limit_error_is_soft_soft() {
        let err = RateLimitError {
            pool_id: "p".into(),
            limit: 10,
            current: 10,
            retry_after_ms: 1000,
            enforcement: RateLimitEnforcement::Soft,
            message: "test".into(),
        };
        assert!(err.is_soft());
    }

    #[test]
    fn rate_limit_error_is_std_error() {
        let pool = test_pool("api", 10, 60);
        let err = RateLimitError::for_pool(&pool, 10, 1000);
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    // ---- Tracker: add_pool ----

    #[test]
    fn tracker_add_pool() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.pool_status("dynamic").is_none());

        let pool = test_pool("dynamic", 5, 30);
        tracker.add_pool(pool);

        let status = tracker.pool_status("dynamic").unwrap();
        assert_eq!(status.limit, 5);
        assert_eq!(status.remaining, 5);
    }

    // ---- Tracker: reset_all ----

    #[test]
    fn tracker_reset_all() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 3, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume all
        tracker.try_consume("op", 3);
        assert!(tracker.try_consume("op", 1).is_some());

        // Reset
        tracker.reset_all();
        assert!(tracker.try_consume("op", 1).is_none());
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.remaining, 2); // 3 - 1
    }

    // ---- Tracker: is_limited ----

    #[test]
    fn tracker_is_limited_false_initially() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        assert!(!tracker.is_limited("op"));
    }

    #[test]
    fn tracker_is_limited_true_when_exhausted() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 2, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 2);
        assert!(tracker.is_limited("op"));
    }

    #[test]
    fn tracker_is_limited_unknown_op() {
        let tracker = RateLimitTracker::new();
        assert!(!tracker.is_limited("nonexistent"));
    }

    // ---- Tracker: most_constrained_status ----

    #[test]
    fn tracker_most_constrained_status() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("big", 100, 60), test_pool("small", 5, 60)],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["big".to_string(), "small".to_string()],
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        tracker.try_consume("op", 3);

        let (id, status) = tracker.most_constrained_status("op").unwrap();
        assert_eq!(id, "small");
        assert_eq!(status.remaining, 2);
    }

    #[test]
    fn tracker_most_constrained_status_unknown_op() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.most_constrained_status("nope").is_none());
    }

    // ---- Tracker: all_pool_statuses ----

    #[test]
    fn tracker_all_pool_statuses() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("a", 10, 60), test_pool("b", 20, 120)],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let all = tracker.all_pool_statuses();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("a"));
        assert!(all.contains_key("b"));
        assert_eq!(all["a"].limit, 10);
        assert_eq!(all["b"].limit, 20);
    }

    #[test]
    fn tracker_all_pool_statuses_empty() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.all_pool_statuses().is_empty());
    }

    // ---- Tracker: operation_status unknown ----

    #[test]
    fn tracker_operation_status_unknown_op() {
        let tracker = RateLimitTracker::new();
        assert!(tracker.operation_status("missing").is_empty());
    }

    // ---- Burst handling ----

    #[test]
    fn tracker_burst_allows_over_base_limit() {
        let pool = RateLimitPoolBuilder::new("burst_pool")
            .requests(3)
            .burst(2)
            .window_secs(60)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["burst_pool".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Should allow 5 total (3 base + 2 burst)
        for _ in 0..5 {
            assert!(tracker.try_consume("op", 1).is_none());
        }
        // 6th should fail
        assert!(tracker.try_consume("op", 1).is_some());
    }

    #[test]
    fn tracker_burst_reflected_in_status() {
        let pool = RateLimitPoolBuilder::new("bp")
            .requests(10)
            .burst(5)
            .window_secs(60)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let status = tracker.pool_status("bp").unwrap();
        // Effective limit includes burst
        assert_eq!(status.limit, 15);
        assert_eq!(status.remaining, 15);
    }

    // ---- Consume amount > 1 ----

    #[test]
    fn tracker_consume_large_amount() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        // Consume 10 at once
        assert!(tracker.try_consume("op", 10).is_none());
        // Next should fail
        assert!(tracker.try_consume("op", 1).is_some());
    }

    #[test]
    fn tracker_consume_exceeds_in_single_call() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        // Trying to consume more than limit fails immediately
        let err = tracker.try_consume("op", 6).unwrap();
        assert_eq!(err.pool_id, "api");
        assert_eq!(err.current, 0);
    }

    // ---- RateLimitPoolBuilder defaults ----

    #[test]
    fn pool_builder_defaults() {
        let pool = RateLimitPoolBuilder::new("default_pool").build();
        assert_eq!(pool.id, "default_pool");
        assert_eq!(pool.description, "");
        assert_eq!(pool.config.requests, 60);
        assert_eq!(pool.config.window, Duration::from_secs(60));
        assert_eq!(pool.config.burst, None);
        assert_eq!(pool.config.unit, RateLimitUnit::Requests);
        assert_eq!(pool.enforcement, RateLimitEnforcement::Hard);
        assert_eq!(pool.scope, RateLimitScope::Instance);
    }

    #[test]
    fn pool_builder_window_duration() {
        let pool = RateLimitPoolBuilder::new("p")
            .window(Duration::from_millis(500))
            .build();
        assert_eq!(pool.config.window, Duration::from_millis(500));
    }

    // ---- Tracker: Default impl ----

    #[test]
    fn tracker_default() {
        let t1 = RateLimitTracker::new();
        let t2 = RateLimitTracker::default();
        // Both should be empty
        assert!(t1.all_pool_statuses().is_empty());
        assert!(t2.all_pool_statuses().is_empty());
    }

    // ---- Tracker: Clone shares state ----

    #[test]
    fn tracker_clone_shares_state() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 5, 60)],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["api".to_string()])]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let cloned = tracker.clone();

        // Consume on original
        tracker.try_consume("op", 3);
        // Clone should see the same state (Arc)
        let status = cloned.pool_status("api").unwrap();
        assert_eq!(status.remaining, 2);
    }

    // ---- Advisory enforcement ----

    #[test]
    fn advisory_limit_allows_through() {
        let pool = RateLimitPoolBuilder::new("adv")
            .requests(1)
            .enforcement(RateLimitEnforcement::Advisory)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool],
            tool_pool_map: HashMap::from([("op".to_string(), vec!["adv".to_string()])]),
        };

        let tracker = RateLimitTracker::from_declarations(&decls);
        assert!(tracker.try_consume("op", 1).is_none());
        // Advisory should also allow through like soft
        assert!(tracker.try_consume("op", 1).is_none());
    }

    // ---- Multiple pools per operation ----

    #[test]
    fn tracker_multiple_pools_first_hard_limit_stops() {
        let pool1 = RateLimitPoolBuilder::new("tight")
            .requests(2)
            .enforcement(RateLimitEnforcement::Hard)
            .build();
        let pool2 = RateLimitPoolBuilder::new("loose")
            .requests(100)
            .enforcement(RateLimitEnforcement::Hard)
            .build();

        let decls = RateLimitDeclarations {
            limits: vec![pool1, pool2],
            tool_pool_map: HashMap::from([(
                "op".to_string(),
                vec!["loose".to_string(), "tight".to_string()], // Put loose first to ensure it's not consumed if tight fails
            )]),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);

        tracker.try_consume("op", 2);
        let err = tracker.try_consume("op", 1).unwrap();
        assert_eq!(err.pool_id, "tight");
        
        let status = tracker.pool_status("loose").unwrap();
        // Since the 3rd operation failed on 'tight', 'loose' should not be consumed for the 3rd time
        assert_eq!(status.remaining, 98); // 100 - 2, not 97!
    }

    // ---- Pool status window_seconds ----

    #[test]
    fn pool_status_window_seconds() {
        let decls = RateLimitDeclarations {
            limits: vec![test_pool("api", 10, 120)],
            tool_pool_map: HashMap::new(),
        };
        let tracker = RateLimitTracker::from_declarations(&decls);
        let status = tracker.pool_status("api").unwrap();
        assert_eq!(status.window_seconds, 120);
    }
}
