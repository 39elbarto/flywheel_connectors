//! Reconnection strategies and utilities.
//!
//! Provides automatic reconnection with configurable backoff.

use std::future::Future;
use std::time::Duration;

use fcp_async_core::time::sleep;
use tracing::{debug, warn};

use crate::{DEFAULT_RECONNECT_DELAY, MAX_RECONNECT_DELAY, StreamError, StreamResult};

/// Reconnection configuration.
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Maximum number of reconnection attempts.
    pub max_attempts: Option<u32>,
    /// Initial delay before first reconnection.
    pub initial_delay: Duration,
    /// Maximum delay between reconnections.
    pub max_delay: Duration,
    /// Backoff multiplier.
    pub backoff_multiplier: f64,
    /// Whether to add jitter.
    pub jitter: bool,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_attempts: Some(10),
            initial_delay: DEFAULT_RECONNECT_DELAY,
            max_delay: MAX_RECONNECT_DELAY,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl ReconnectConfig {
    /// Create a new reconnection configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum attempts.
    #[must_use]
    pub const fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = Some(attempts);
        self
    }

    /// Set unlimited reconnection attempts.
    #[must_use]
    pub const fn with_unlimited_attempts(mut self) -> Self {
        self.max_attempts = None;
        self
    }

    /// Set initial delay.
    #[must_use]
    pub const fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Set maximum delay.
    #[must_use]
    pub const fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set backoff multiplier.
    #[must_use]
    pub const fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Enable or disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, enabled: bool) -> Self {
        self.jitter = enabled;
        self
    }

    /// Calculate delay for a given attempt.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
        let base = self
            .initial_delay
            .as_secs_f64()
            .mul_add(self.backoff_multiplier.powi(exponent), 0.0);
        let jittered = if self.jitter {
            // Add jitter (0.5x to 1.5x)
            let jitter = random_float().mul_add(1.0, 0.5);
            base * jitter
        } else {
            base
        };

        Duration::from_secs_f64(jittered.min(self.max_delay.as_secs_f64()))
    }
}

/// Reconnection handler.
#[derive(Debug)]
pub struct ReconnectHandler {
    config: ReconnectConfig,
    attempts: u32,
}

impl ReconnectHandler {
    /// Create a new reconnection handler.
    #[must_use]
    pub const fn new(config: ReconnectConfig) -> Self {
        Self {
            config,
            attempts: 0,
        }
    }

    /// Reset the reconnection state.
    pub const fn reset(&mut self) {
        self.attempts = 0;
    }

    /// Get the current attempt count.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Record a failure (increment attempt count).
    pub const fn record_failure(&mut self) {
        self.attempts += 1;
    }

    /// Check if reconnection is allowed.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn can_reconnect(&self) -> bool {
        self.config
            .max_attempts
            .is_none_or(|max| self.attempts < max)
    }

    /// Wait for the next reconnection attempt.
    ///
    /// # Errors
    /// Returns [`StreamError::ReconnectLimitExceeded`] when the retry budget is exhausted.
    pub async fn wait_for_reconnect(&mut self) -> StreamResult<()> {
        if !self.can_reconnect() {
            return Err(StreamError::ReconnectLimitExceeded {
                attempts: self.attempts,
            });
        }

        let delay = self.config.delay_for_attempt(self.attempts);
        debug!(
            attempt = self.attempts,
            delay_ms = delay.as_millis(),
            "Waiting before reconnection"
        );

        sleep(delay).await;
        self.attempts += 1;

        Ok(())
    }

    /// Execute a reconnectable operation.
    ///
    /// # Errors
    /// Returns the underlying operation error or a reconnect limit error.
    pub async fn reconnect<T, F, Fut>(&mut self, mut operation: F) -> StreamResult<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = StreamResult<T>>,
    {
        loop {
            match operation().await {
                Ok(result) => {
                    self.reset();
                    return Ok(result);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        attempt = self.attempts,
                        "Operation failed, attempting reconnection"
                    );

                    if !self.can_reconnect() {
                        return Err(StreamError::ReconnectLimitExceeded {
                            attempts: self.attempts,
                        });
                    }

                    self.wait_for_reconnect().await?;
                }
            }
        }
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &ReconnectConfig {
        &self.config
    }
}

/// Execute an operation with automatic retry.
///
/// # Errors
/// Returns the underlying operation error or a reconnect limit error.
pub async fn with_retry<T, F, Fut>(config: ReconnectConfig, operation: F) -> StreamResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = StreamResult<T>>,
{
    let mut handler = ReconnectHandler::new(config);
    handler.reconnect(operation).await
}

/// Simple random float generator (0.0 to 1.0).
fn random_float() -> f64 {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconnect_config_default() {
        let config = ReconnectConfig::default();
        assert_eq!(config.max_attempts, Some(10));
        assert_eq!(config.initial_delay, DEFAULT_RECONNECT_DELAY);
        assert!(config.jitter);
    }

    #[test]
    fn test_delay_calculation_no_jitter() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(4));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(8));
        // Capped at max
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(60));
    }

    #[test]
    fn test_reconnect_handler_can_reconnect() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        assert!(handler.can_reconnect());
        handler.attempts = 2;
        assert!(handler.can_reconnect());
        handler.attempts = 3;
        assert!(!handler.can_reconnect());
    }

    #[test]
    fn test_reconnect_handler_unlimited() {
        let config = ReconnectConfig::new().with_unlimited_attempts();
        let mut handler = ReconnectHandler::new(config);

        handler.attempts = 1000;
        assert!(handler.can_reconnect());
    }

    #[test]
    fn test_reconnect_handler_reset() {
        let config = ReconnectConfig::new();
        let mut handler = ReconnectHandler::new(config);

        handler.attempts = 5;
        handler.reset();
        assert_eq!(handler.attempts(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_success() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut attempts = 0;

        let result = with_retry(config, || {
            attempts += 1;
            async move {
                if attempts < 2 {
                    Err(StreamError::ConnectionFailed("test".into()))
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_exhausted() {
        let config = ReconnectConfig::new()
            .with_max_attempts(2)
            .with_initial_delay(Duration::from_millis(1));

        let result: StreamResult<i32> = with_retry(config, || async {
            Err(StreamError::ConnectionFailed("always fails".into()))
        })
        .await;

        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { .. })
        ));
    }

    // ── New tests ──

    #[test]
    fn test_reconnect_config_builder_chain() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(10))
            .with_backoff_multiplier(3.0)
            .with_jitter(false);

        assert_eq!(config.max_attempts, Some(5));
        assert_eq!(config.initial_delay, Duration::from_millis(100));
        assert_eq!(config.max_delay, Duration::from_secs(10));
        assert!((config.backoff_multiplier - 3.0).abs() < f64::EPSILON);
        assert!(!config.jitter);
    }

    #[test]
    fn test_delay_with_jitter_bounded() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(2.0)
            .with_jitter(true);

        // With jitter (0.5x to 1.5x), attempt 0 base is 1s
        let delay = config.delay_for_attempt(0);
        assert!(delay >= Duration::from_millis(500));
        assert!(delay <= Duration::from_millis(1500));
    }

    #[test]
    fn test_delay_with_jitter_still_respects_max_delay() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(1.0)
            .with_jitter(true);

        for _ in 0..20 {
            assert_eq!(config.delay_for_attempt(0), Duration::from_secs(5));
        }
    }

    #[test]
    fn test_delay_capped_at_max() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(10.0)
            .with_jitter(false);

        // attempt 2: 1 * 10^2 = 100s, capped at 5s
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(5));
    }

    #[test]
    fn test_reconnect_handler_config_accessor() {
        let config = ReconnectConfig::new().with_max_attempts(7);
        let handler = ReconnectHandler::new(config);
        assert_eq!(handler.config().max_attempts, Some(7));
    }

    #[fcp_async_core::runtime::test]
    async fn test_wait_for_reconnect_exhausted() {
        let config = ReconnectConfig::new()
            .with_max_attempts(0)
            .with_initial_delay(Duration::from_millis(1));
        let mut handler = ReconnectHandler::new(config);

        let result = handler.wait_for_reconnect().await;
        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { attempts: 0 })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_wait_for_reconnect_increments_attempts() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        assert_eq!(handler.attempts(), 0);
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 1);
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 2);
    }

    // ── Additional ReconnectConfig tests ──

    #[test]
    fn test_delay_zero_multiplier() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(0.0)
            .with_jitter(false);

        // 0^n = 0 for n>0, so delay is 1 * 0 = 0 for attempt > 0
        // attempt 0: 1 * 0^0 = 1 * 1 = 1s
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(1));
    }

    #[test]
    fn test_delay_multiplier_one() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(2))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(1.0)
            .with_jitter(false);

        // With multiplier 1.0, delay is constant
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(5), Duration::from_secs(2));
    }

    #[test]
    fn test_delay_large_attempt_capped() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(30))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // Very large attempt: should be capped at max_delay
        let delay = config.delay_for_attempt(100);
        assert_eq!(delay, Duration::from_secs(30));
    }

    #[test]
    fn test_delay_i32_max_attempt() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(10))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // u32::MAX attempt should gracefully handle i32 overflow
        let delay = config.delay_for_attempt(u32::MAX);
        assert_eq!(delay, Duration::from_secs(10));
    }

    #[test]
    fn test_config_new_equals_default() {
        let new = ReconnectConfig::new();
        let default = ReconnectConfig::default();

        assert_eq!(new.max_attempts, default.max_attempts);
        assert_eq!(new.initial_delay, default.initial_delay);
        assert_eq!(new.max_delay, default.max_delay);
        assert!((new.backoff_multiplier - default.backoff_multiplier).abs() < f64::EPSILON);
        assert_eq!(new.jitter, default.jitter);
    }

    #[test]
    fn test_config_clone() {
        let config = ReconnectConfig::new()
            .with_max_attempts(7)
            .with_jitter(false);
        let moved = config;
        assert_eq!(moved.max_attempts, Some(7));
        assert!(!moved.jitter);
    }

    // ── Additional ReconnectHandler tests ──

    #[test]
    fn test_handler_record_failure_increments() {
        let config = ReconnectConfig::new().with_max_attempts(5);
        let mut handler = ReconnectHandler::new(config);

        assert_eq!(handler.attempts(), 0);
        handler.record_failure();
        assert_eq!(handler.attempts(), 1);
        handler.record_failure();
        assert_eq!(handler.attempts(), 2);
    }

    #[test]
    fn test_handler_record_failure_then_reset() {
        let config = ReconnectConfig::new().with_max_attempts(5);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.record_failure();
        handler.record_failure();
        assert_eq!(handler.attempts(), 3);
        handler.reset();
        assert_eq!(handler.attempts(), 0);
        assert!(handler.can_reconnect());
    }

    #[test]
    fn test_handler_can_reconnect_boundary() {
        let config = ReconnectConfig::new().with_max_attempts(2);
        let mut handler = ReconnectHandler::new(config);

        assert!(handler.can_reconnect()); // 0 < 2
        handler.record_failure();
        assert!(handler.can_reconnect()); // 1 < 2
        handler.record_failure();
        assert!(!handler.can_reconnect()); // 2 >= 2
    }

    #[test]
    fn test_handler_zero_max_attempts() {
        let config = ReconnectConfig::new().with_max_attempts(0);
        let handler = ReconnectHandler::new(config);

        // Zero max attempts means reconnection is never allowed
        assert!(!handler.can_reconnect());
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_succeeds_first_try() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1));
        let mut handler = ReconnectHandler::new(config);

        let result = handler
            .reconnect(|| async { Ok::<_, StreamError>(99) })
            .await;

        assert_eq!(result.unwrap(), 99);
        assert_eq!(handler.attempts(), 0); // reset on success
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_resets_on_success() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        let mut call_count = 0;
        let result = handler
            .reconnect(|| {
                call_count += 1;
                async move {
                    if call_count < 3 {
                        Err(StreamError::ConnectionFailed("fail".into()))
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(handler.attempts(), 0); // reset after success
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_immediate_success() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let result = with_retry(config, || async { Ok::<_, StreamError>("hello") }).await;
        assert_eq!(result.unwrap(), "hello");
    }

    // ── ReconnectConfig debug ──

    #[test]
    fn test_reconnect_config_debug() {
        let config = ReconnectConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("ReconnectConfig"));
    }

    #[test]
    fn test_reconnect_handler_debug() {
        let config = ReconnectConfig::new();
        let handler = ReconnectHandler::new(config);
        let debug = format!("{handler:?}");
        assert!(debug.contains("ReconnectHandler"));
    }

    // ── Delay calculation edge cases ──

    #[test]
    fn test_delay_fractional_multiplier() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(4))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(0.5)
            .with_jitter(false);

        // 4 * 0.5^0 = 4, 4 * 0.5^1 = 2, 4 * 0.5^2 = 1
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(4));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(1));
    }

    #[test]
    fn test_delay_very_small_initial() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(1))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(1));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(2));
        assert_eq!(config.delay_for_attempt(10), Duration::from_millis(1024));
    }

    #[test]
    fn test_delay_jitter_statistical_bounds() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(1.0)
            .with_jitter(true);

        // With jitter (0.5x to 1.5x), base is 10s → range [5s, 15s]
        for _ in 0..50 {
            let delay = config.delay_for_attempt(0);
            assert!(
                delay >= Duration::from_secs(5),
                "delay {delay:?} below lower jitter bound"
            );
            assert!(
                delay <= Duration::from_secs(15),
                "delay {delay:?} above upper jitter bound"
            );
        }
    }

    #[test]
    fn test_delay_max_exactly_equals_base() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(5))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // All attempts capped at 5s
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(5));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(5));
        assert_eq!(config.delay_for_attempt(100), Duration::from_secs(5));
    }

    // ── Handler lifecycle tests ──

    #[test]
    fn test_handler_multi_cycle_reset() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        // First cycle
        handler.record_failure();
        handler.record_failure();
        assert_eq!(handler.attempts(), 2);

        // Reset simulates successful reconnection
        handler.reset();
        assert_eq!(handler.attempts(), 0);
        assert!(handler.can_reconnect());

        // Second cycle
        handler.record_failure();
        handler.record_failure();
        handler.record_failure();
        assert!(!handler.can_reconnect());

        // Reset again
        handler.reset();
        assert!(handler.can_reconnect());
    }

    #[test]
    fn test_handler_max_attempts_one() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let mut handler = ReconnectHandler::new(config);

        assert!(handler.can_reconnect());
        handler.record_failure();
        assert!(!handler.can_reconnect());
    }

    #[test]
    fn test_handler_unlimited_many_failures() {
        let config = ReconnectConfig::new().with_unlimited_attempts();
        let mut handler = ReconnectHandler::new(config);

        for _ in 0..10_000 {
            handler.record_failure();
        }
        assert!(handler.can_reconnect());
        assert_eq!(handler.attempts(), 10_000);
    }

    // ── Async reconnect tests ──

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_multiple_failures_then_success() {
        let config = ReconnectConfig::new()
            .with_max_attempts(10)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        let mut call_count = 0;
        let result = handler
            .reconnect(|| {
                call_count += 1;
                async move {
                    if call_count < 5 {
                        Err(StreamError::ConnectionFailed(format!("fail {call_count}")))
                    } else {
                        Ok("success")
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count, 5);
        assert_eq!(handler.attempts(), 0); // reset on success
    }

    #[fcp_async_core::runtime::test]
    async fn test_wait_for_reconnect_success_then_exhausted() {
        let config = ReconnectConfig::new()
            .with_max_attempts(2)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        // First wait succeeds
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 1);

        // Second wait succeeds
        handler.wait_for_reconnect().await.unwrap();
        assert_eq!(handler.attempts(), 2);

        // Third should be exhausted
        let result = handler.wait_for_reconnect().await;
        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { attempts: 2 })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_returns_correct_type() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let result: StreamResult<Vec<i32>> =
            with_retry(config, || async { Ok(vec![1, 2, 3]) }).await;
        assert_eq!(result.unwrap(), vec![1, 2, 3]);
    }

    // ── ReconnectConfig: clone preserves all fields ─────────────────────

    #[test]
    fn test_config_clone_preserves_all_fields() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(250))
            .with_max_delay(Duration::from_secs(20))
            .with_backoff_multiplier(1.5)
            .with_jitter(false);
        let cloned = config.clone();
        assert_eq!(config.max_attempts, cloned.max_attempts);
        assert_eq!(config.initial_delay, cloned.initial_delay);
        assert_eq!(config.max_delay, cloned.max_delay);
        assert!((config.backoff_multiplier - cloned.backoff_multiplier).abs() < f64::EPSILON);
        assert_eq!(config.jitter, cloned.jitter);
    }

    // ── ReconnectConfig: unlimited clone ─────────────────────────────────

    #[test]
    fn test_config_unlimited_attempts_clone() {
        let config = ReconnectConfig::new().with_unlimited_attempts();
        let cloned = config.clone();
        assert_eq!(config.max_attempts, None);
        assert_eq!(cloned.max_attempts, None);
    }

    // ── Delay: initial_delay zero ───────────────────────────────────────

    #[test]
    fn test_delay_zero_initial_delay() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::ZERO)
            .with_max_delay(Duration::from_secs(10))
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // 0 * 2^n = 0 for all n
        assert_eq!(config.delay_for_attempt(0), Duration::ZERO);
        assert_eq!(config.delay_for_attempt(5), Duration::ZERO);
    }

    // ── Delay: max_delay zero clamps everything ─────────────────────────

    #[test]
    fn test_delay_zero_max_delay() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(5))
            .with_max_delay(Duration::ZERO)
            .with_backoff_multiplier(2.0)
            .with_jitter(false);

        // Everything capped at zero
        assert_eq!(config.delay_for_attempt(0), Duration::ZERO);
        assert_eq!(config.delay_for_attempt(10), Duration::ZERO);
    }

    // ── Handler: initial state ──────────────────────────────────────────

    #[test]
    fn test_handler_initial_state() {
        let config = ReconnectConfig::new().with_max_attempts(5);
        let handler = ReconnectHandler::new(config);
        assert_eq!(handler.attempts(), 0);
        assert!(handler.can_reconnect());
        assert_eq!(handler.config().max_attempts, Some(5));
    }

    // ── Handler: record_failure up to limit ─────────────────────────────

    #[test]
    fn test_handler_exhaust_via_record_failure() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.record_failure();
        handler.record_failure();
        assert_eq!(handler.attempts(), 3);
        assert!(!handler.can_reconnect());
    }

    // ── Handler: config backoff multiplier 1.5 ──────────────────────────

    #[test]
    fn test_delay_multiplier_one_point_five() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(30))
            .with_backoff_multiplier(1.5)
            .with_jitter(false);

        // attempt 0: 100ms * 1.5^0 = 100ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        // attempt 1: 100ms * 1.5^1 = 150ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(150));
        // attempt 2: 100ms * 1.5^2 = 225ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(225));
    }

    // ── Handler: reset then reuse ───────────────────────────────────────

    #[test]
    fn test_handler_reset_restores_can_reconnect() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        assert!(!handler.can_reconnect());

        handler.reset();
        assert!(handler.can_reconnect());
        assert_eq!(handler.attempts(), 0);
    }

    // ── Async: with_retry string result ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_with_retry_string_result() {
        let config = ReconnectConfig::new().with_max_attempts(1);
        let result: StreamResult<String> =
            with_retry(config, || async { Ok("done".to_string()) }).await;
        assert_eq!(result.unwrap(), "done");
    }

    // ── Async: reconnect with zero max_attempts ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_zero_max_attempts_fails_immediately() {
        let config = ReconnectConfig::new().with_max_attempts(0);
        let mut handler = ReconnectHandler::new(config);

        let result = handler
            .reconnect(|| async { Err::<i32, _>(StreamError::ConnectionFailed("fail".into())) })
            .await;

        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { attempts: 0 })
        ));
    }

    // ── Additional delay calculation tests ──

    #[test]
    fn test_delay_multiplier_three() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(3.0)
            .with_jitter(false);

        // attempt 0: 100ms * 3^0 = 100ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        // attempt 1: 100ms * 3^1 = 300ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(300));
        // attempt 2: 100ms * 3^2 = 900ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(900));
    }

    #[test]
    fn test_delay_multiplier_very_large() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_millis(10))
            .with_max_delay(Duration::from_secs(5))
            .with_backoff_multiplier(100.0)
            .with_jitter(false);

        // attempt 1: 10ms * 100 = 1000ms = 1s
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        // attempt 2: capped at 5s
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(5));
    }

    #[test]
    fn test_delay_jitter_multiple_samples_vary() {
        let config = ReconnectConfig::new()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(60))
            .with_backoff_multiplier(1.0)
            .with_jitter(true);

        // Sample many delays; at least one pair should differ (probabilistically)
        let delays: Vec<Duration> = (0..20).map(|_| config.delay_for_attempt(0)).collect();
        let all_same = delays.windows(2).all(|w| w[0] == w[1]);
        // With 20 samples and jitter, probability all are identical is astronomically low
        assert!(!all_same, "jitter should produce varying delays");
    }

    // ── Handler: config immutability ──

    #[test]
    fn test_handler_config_unchanged_after_failures() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(250));
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.record_failure();
        // Config should be unchanged
        assert_eq!(handler.config().max_attempts, Some(5));
        assert_eq!(handler.config().initial_delay, Duration::from_millis(250));
    }

    #[test]
    fn test_handler_config_unchanged_after_reset() {
        let config = ReconnectConfig::new().with_max_attempts(3);
        let mut handler = ReconnectHandler::new(config);

        handler.record_failure();
        handler.reset();
        assert_eq!(handler.config().max_attempts, Some(3));
    }

    // ── Config builder override behavior ──

    #[test]
    fn test_config_max_attempts_overrides() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_max_attempts(3);
        assert_eq!(config.max_attempts, Some(3));
    }

    #[test]
    fn test_config_unlimited_then_limited() {
        let config = ReconnectConfig::new()
            .with_unlimited_attempts()
            .with_max_attempts(7);
        assert_eq!(config.max_attempts, Some(7));
    }

    #[test]
    fn test_config_limited_then_unlimited() {
        let config = ReconnectConfig::new()
            .with_max_attempts(3)
            .with_unlimited_attempts();
        assert_eq!(config.max_attempts, None);
    }

    // ── ReconnectConfig Debug output ──

    #[test]
    fn test_reconnect_config_debug_contains_fields() {
        let config = ReconnectConfig::new()
            .with_max_attempts(5)
            .with_jitter(false);
        let debug = format!("{config:?}");
        assert!(debug.contains("max_attempts"));
        assert!(debug.contains("jitter"));
    }

    #[test]
    fn test_reconnect_handler_debug_contains_attempts() {
        let config = ReconnectConfig::new();
        let mut handler = ReconnectHandler::new(config);
        handler.record_failure();
        let debug = format!("{handler:?}");
        assert!(debug.contains("attempts"));
    }

    // ── Async: reconnect preserves error type ──

    #[fcp_async_core::runtime::test]
    async fn test_reconnect_exhausted_returns_reconnect_limit_error() {
        let config = ReconnectConfig::new()
            .with_max_attempts(1)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let mut handler = ReconnectHandler::new(config);

        let result: StreamResult<i32> = handler
            .reconnect(|| async { Err(StreamError::ParseError("always fail".into())) })
            .await;

        // Should get ReconnectLimitExceeded, not the original ParseError
        assert!(matches!(
            result,
            Err(StreamError::ReconnectLimitExceeded { .. })
        ));
    }
}
