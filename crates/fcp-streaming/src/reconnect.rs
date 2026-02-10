//! Reconnection strategies and utilities.
//!
//! Provides automatic reconnection with configurable backoff.

use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;
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
        let capped = base.min(self.max_delay.as_secs_f64());

        let delay = if self.jitter {
            // Add jitter (0.5x to 1.5x)
            let jitter = random_float().mul_add(1.0, 0.5);
            capped * jitter
        } else {
            capped
        };

        Duration::from_secs_f64(delay)
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
    pub fn record_failure(&mut self) {
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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

    #[tokio::test]
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
}
