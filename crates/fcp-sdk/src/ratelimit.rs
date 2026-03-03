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
        self.maybe_reset_window();

        let effective_limit = self.config.config.requests + self.config.config.burst.unwrap_or(0);

        if self.count + amount > effective_limit {
            let retry_after_ms = self.ms_until_reset();
            return Err(RateLimitError::for_pool(
                &self.config,
                self.count,
                retry_after_ms,
            ));
        }

        self.count += amount;
        Ok(())
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
                    } else {
                        return Some(err);
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
}
