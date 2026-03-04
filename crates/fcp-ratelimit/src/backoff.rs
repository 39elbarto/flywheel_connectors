//! Backoff strategies for rate limit handling.
//!
//! Provides various backoff algorithms for retry logic.

use std::time::Duration;

/// Trait for backoff strategies.
pub trait BackoffStrategy: Send + Sync {
    /// Get the next backoff duration.
    fn next_backoff(&mut self, attempt: u32) -> Duration;

    /// Reset the backoff state.
    fn reset(&mut self);

    /// Clone the strategy into a boxed trait object.
    fn clone_box(&self) -> Box<dyn BackoffStrategy>;
}

/// Exponential backoff with optional jitter.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Initial backoff duration.
    pub initial: Duration,

    /// Maximum backoff duration.
    pub max: Duration,

    /// Multiplier for each attempt.
    pub multiplier: f64,

    /// Whether to add jitter.
    pub jitter: Option<f64>,
}

impl ExponentialBackoff {
    /// Create a new exponential backoff.
    #[must_use]
    pub const fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            multiplier: 2.0,
            jitter: Some(0.5),
        }
    }

    /// Set the multiplier.
    #[must_use]
    pub const fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Enable or disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, jitter: Option<f64>) -> Self {
        self.jitter = jitter;
        self
    }

    /// Common preset: 1s initial, 60s max.
    #[must_use]
    pub const fn default_backoff() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(60))
    }

    /// Common preset: aggressive (short delays).
    #[must_use]
    pub const fn aggressive() -> Self {
        Self::new(Duration::from_millis(100), Duration::from_secs(10))
    }

    /// Common preset: conservative (longer delays).
    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(Duration::from_secs(5), Duration::from_secs(300))
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::default_backoff()
    }
}

impl BackoffStrategy for ExponentialBackoff {
    fn next_backoff(&mut self, attempt: u32) -> Duration {
        #[allow(clippy::cast_possible_wrap)]
        let base = self.initial.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped = base.min(self.max.as_secs_f64());

        self.jitter.map_or_else(
            || Duration::from_secs_f64(capped),
            |jitter| {
                let random_float = || rand::random::<f64>();
                let jitter_factor = random_float().mul_add(jitter * 2.0, 1.0 - jitter);
                Duration::from_secs_f64(capped * jitter_factor)
            },
        )
    }

    fn reset(&mut self) {
        // No state to reset for exponential backoff
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Decorrelated jitter backoff.
///
/// Each backoff is randomized independently, reducing thundering herd.
#[derive(Debug, Clone)]
pub struct DecorrelatedJitter {
    /// Base duration.
    pub base: Duration,

    /// Maximum duration.
    pub max: Duration,

    /// Previous backoff (for correlation).
    previous: Duration,
}

impl DecorrelatedJitter {
    /// Create a new decorrelated jitter backoff.
    #[must_use]
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            previous: base,
        }
    }
}

impl BackoffStrategy for DecorrelatedJitter {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        // sleep = min(cap, random_between(base, sleep * 3))
        let base_secs = self.base.as_secs_f64();
        let prev_secs = self.previous.as_secs_f64();
        let max_secs = self.max.as_secs_f64();

        let range = prev_secs.mul_add(3.0, -base_secs);
        let next = if range > 0.0 {
            random_float().mul_add(range, base_secs)
        } else {
            base_secs
        };

        let capped = next.min(max_secs);
        self.previous = Duration::from_secs_f64(capped);
        self.previous
    }

    fn reset(&mut self) {
        self.previous = self.base;
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Linear backoff with cap.
#[derive(Debug, Clone)]
pub struct LinearBackoff {
    /// Initial delay.
    pub initial: Duration,

    /// Increment per attempt.
    pub increment: Duration,

    /// Maximum delay.
    pub max: Duration,
}

impl LinearBackoff {
    /// Create a new linear backoff.
    #[must_use]
    pub const fn new(initial: Duration, increment: Duration, max: Duration) -> Self {
        Self {
            initial,
            increment,
            max,
        }
    }
}

impl BackoffStrategy for LinearBackoff {
    fn next_backoff(&mut self, attempt: u32) -> Duration {
        let delay = self.initial + self.increment * attempt;
        delay.min(self.max)
    }

    fn reset(&mut self) {
        // No state to reset
    }

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// Constant backoff (same delay each time).
#[derive(Debug, Clone)]
pub struct ConstantBackoff {
    /// Delay duration.
    pub delay: Duration,
}

impl ConstantBackoff {
    /// Create a new constant backoff.
    #[must_use]
    pub const fn new(delay: Duration) -> Self {
        Self { delay }
    }
}

impl BackoffStrategy for ConstantBackoff {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        self.delay
    }

    fn reset(&mut self) {}

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(self.clone())
    }
}

/// No backoff (immediate retry).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBackoff;

impl BackoffStrategy for NoBackoff {
    fn next_backoff(&mut self, _attempt: u32) -> Duration {
        Duration::ZERO
    }

    fn reset(&mut self) {}

    fn clone_box(&self) -> Box<dyn BackoffStrategy> {
        Box::new(*self)
    }
}

/// Retry configuration.
pub struct RetryConfig {
    /// Maximum number of retries.
    pub max_retries: u32,

    /// Maximum total time for all retries.
    pub max_total_time: Option<Duration>,

    /// Backoff strategy.
    backoff: Box<dyn BackoffStrategy>,
}

impl std::fmt::Debug for RetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryConfig")
            .field("max_retries", &self.max_retries)
            .field("max_total_time", &self.max_total_time)
            .field("backoff", &"<BackoffStrategy>")
            .finish()
    }
}

impl RetryConfig {
    /// Create a new retry configuration.
    #[must_use]
    pub fn new(max_retries: u32, backoff: impl BackoffStrategy + 'static) -> Self {
        Self {
            max_retries,
            max_total_time: None,
            backoff: Box::new(backoff),
        }
    }

    /// Set maximum total retry time.
    #[must_use]
    pub const fn with_max_total_time(mut self, duration: Duration) -> Self {
        self.max_total_time = Some(duration);
        self
    }

    /// Get the next backoff duration.
    pub fn next_backoff(&mut self, attempt: u32) -> Duration {
        self.backoff.next_backoff(attempt)
    }

    /// Reset the backoff state.
    pub fn reset(&mut self) {
        self.backoff.reset();
    }
}

impl Clone for RetryConfig {
    fn clone(&self) -> Self {
        Self {
            max_retries: self.max_retries,
            max_total_time: self.max_total_time,
            backoff: self.backoff.clone_box(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::new(3, ExponentialBackoff::default())
    }
}

/// Simple random float generator (0.0 to 1.0).
fn random_float() -> f64 {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RateLimitConfig, RateLimitError, RateLimitState};

    // ── ExponentialBackoff ──────────────────────────────────────────────

    #[test]
    fn test_exponential_backoff() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(None);

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(2));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(4));
        assert_eq!(backoff.next_backoff(3), Duration::from_secs(8));
        assert_eq!(backoff.next_backoff(10), Duration::from_secs(60)); // Capped
    }

    #[test]
    fn exponential_backoff_with_jitter_stays_within_bounds() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(Some(0.5));

        for attempt in 0..20 {
            let d = backoff.next_backoff(attempt);
            // With jitter=0.5, factor is in [0.5, 1.5), so max possible is 60*1.5 = 90s
            assert!(d <= Duration::from_secs(90), "jittered value too large");
            assert!(d > Duration::ZERO, "jittered value should be positive");
        }
    }

    #[test]
    fn exponential_backoff_custom_multiplier() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(100))
            .with_multiplier(3.0)
            .with_jitter(None);

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(3));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(9));
        assert_eq!(backoff.next_backoff(3), Duration::from_secs(27));
        assert_eq!(backoff.next_backoff(4), Duration::from_secs(81));
        assert_eq!(backoff.next_backoff(5), Duration::from_secs(100)); // Capped
    }

    #[test]
    fn exponential_backoff_presets() {
        let default = ExponentialBackoff::default_backoff();
        assert_eq!(default.initial, Duration::from_secs(1));
        assert_eq!(default.max, Duration::from_secs(60));

        let aggressive = ExponentialBackoff::aggressive();
        assert_eq!(aggressive.initial, Duration::from_millis(100));
        assert_eq!(aggressive.max, Duration::from_secs(10));

        let conservative = ExponentialBackoff::conservative();
        assert_eq!(conservative.initial, Duration::from_secs(5));
        assert_eq!(conservative.max, Duration::from_secs(300));
    }

    #[test]
    fn exponential_backoff_default_trait() {
        let backoff = ExponentialBackoff::default();
        assert_eq!(backoff.initial, Duration::from_secs(1));
        assert_eq!(backoff.max, Duration::from_secs(60));
        assert!((backoff.multiplier - 2.0).abs() < f64::EPSILON);
        assert_eq!(backoff.jitter, Some(0.5));
    }

    #[test]
    fn exponential_backoff_clone() {
        let original = ExponentialBackoff::new(Duration::from_millis(500), Duration::from_secs(30))
            .with_multiplier(1.5)
            .with_jitter(Some(0.25));
        let cloned = original.clone();
        assert_eq!(cloned.initial, original.initial);
        assert_eq!(cloned.max, original.max);
        assert!((cloned.multiplier - original.multiplier).abs() < f64::EPSILON);
        assert_eq!(cloned.jitter, original.jitter);
    }

    #[test]
    fn exponential_backoff_debug() {
        let backoff = ExponentialBackoff::default();
        let debug = format!("{backoff:?}");
        assert!(debug.contains("ExponentialBackoff"));
    }

    #[test]
    fn exponential_backoff_reset_is_no_op() {
        let mut backoff = ExponentialBackoff::default().with_jitter(None);
        let d1 = backoff.next_backoff(3);
        backoff.reset();
        let d2 = backoff.next_backoff(3);
        assert_eq!(d1, d2);
    }

    #[test]
    fn exponential_backoff_clone_box() {
        let backoff = ExponentialBackoff::default().with_jitter(None);
        let mut boxed = backoff.clone_box();
        // Should produce a valid boxed strategy
        let d = boxed.next_backoff(0);
        assert!(d > Duration::ZERO);
    }

    #[test]
    fn exponential_backoff_high_attempt_capped() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60))
            .with_jitter(None);
        // Very high attempt number should not overflow, just cap at max
        let d = backoff.next_backoff(1000);
        assert_eq!(d, Duration::from_secs(60));
    }

    // ── DecorrelatedJitter ──────────────────────────────────────────────

    #[test]
    fn decorrelated_jitter_basic() {
        let mut backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(60));

        for _ in 0..20 {
            let d = backoff.next_backoff(0);
            assert!(d >= Duration::from_secs(1), "below base");
            assert!(d <= Duration::from_secs(60), "exceeded cap");
        }
    }

    #[test]
    fn decorrelated_jitter_reset_returns_to_base() {
        let mut backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(60));

        // Run a few iterations to change previous state
        for i in 0..5 {
            backoff.next_backoff(i);
        }

        backoff.reset();
        assert_eq!(backoff.previous, backoff.base);
    }

    #[test]
    fn decorrelated_jitter_clone() {
        let original = DecorrelatedJitter::new(Duration::from_secs(2), Duration::from_secs(30));
        let cloned = original.clone();
        assert_eq!(cloned.base, original.base);
        assert_eq!(cloned.max, original.max);
        assert_eq!(cloned.previous, original.previous);
    }

    #[test]
    fn decorrelated_jitter_clone_box() {
        let backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(10));
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn decorrelated_jitter_debug() {
        let backoff = DecorrelatedJitter::new(Duration::from_secs(1), Duration::from_secs(10));
        let debug = format!("{backoff:?}");
        assert!(debug.contains("DecorrelatedJitter"));
    }

    #[test]
    fn decorrelated_jitter_small_base_large_max() {
        let mut backoff =
            DecorrelatedJitter::new(Duration::from_millis(10), Duration::from_secs(100));
        for i in 0..50 {
            let d = backoff.next_backoff(i);
            assert!(d >= Duration::from_millis(10));
            assert!(d <= Duration::from_secs(100));
        }
    }

    // ── LinearBackoff ───────────────────────────────────────────────────

    #[test]
    fn test_linear_backoff() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(10),
        );

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(3));
        assert_eq!(backoff.next_backoff(2), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(10), Duration::from_secs(10)); // Capped
    }

    #[test]
    fn linear_backoff_exact_cap_hit() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(3),
            Duration::from_secs(10),
        );
        // attempt=3: 1 + 3*3 = 10, exactly at cap
        assert_eq!(backoff.next_backoff(3), Duration::from_secs(10));
    }

    #[test]
    fn linear_backoff_zero_increment() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(5),
            Duration::ZERO,
            Duration::from_secs(10),
        );
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(100), Duration::from_secs(5));
    }

    #[test]
    fn linear_backoff_reset_is_no_op() {
        let mut backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let d1 = backoff.next_backoff(2);
        backoff.reset();
        let d2 = backoff.next_backoff(2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn linear_backoff_clone() {
        let original = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(10),
        );
        let cloned = original.clone();
        assert_eq!(cloned.initial, original.initial);
        assert_eq!(cloned.increment, original.increment);
        assert_eq!(cloned.max, original.max);
    }

    #[test]
    fn linear_backoff_clone_box() {
        let backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(5),
        );
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn linear_backoff_debug() {
        let backoff = LinearBackoff::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(5),
        );
        let debug = format!("{backoff:?}");
        assert!(debug.contains("LinearBackoff"));
    }

    // ── ConstantBackoff ─────────────────────────────────────────────────

    #[test]
    fn test_constant_backoff() {
        let mut backoff = ConstantBackoff::new(Duration::from_secs(5));

        assert_eq!(backoff.next_backoff(0), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(1), Duration::from_secs(5));
        assert_eq!(backoff.next_backoff(100), Duration::from_secs(5));
    }

    #[test]
    fn constant_backoff_zero_delay() {
        let mut backoff = ConstantBackoff::new(Duration::ZERO);
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(99), Duration::ZERO);
    }

    #[test]
    fn constant_backoff_clone() {
        let original = ConstantBackoff::new(Duration::from_secs(3));
        let cloned = original.clone();
        assert_eq!(cloned.delay, original.delay);
    }

    #[test]
    fn constant_backoff_clone_box() {
        let backoff = ConstantBackoff::new(Duration::from_secs(1));
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn constant_backoff_reset_is_no_op() {
        let mut backoff = ConstantBackoff::new(Duration::from_secs(1));
        backoff.reset();
        assert_eq!(backoff.next_backoff(0), Duration::from_secs(1));
    }

    #[test]
    fn constant_backoff_debug() {
        let backoff = ConstantBackoff::new(Duration::from_secs(1));
        let debug = format!("{backoff:?}");
        assert!(debug.contains("ConstantBackoff"));
    }

    // ── NoBackoff ───────────────────────────────────────────────────────

    #[test]
    fn test_no_backoff() {
        let mut backoff = NoBackoff;

        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
        assert_eq!(backoff.next_backoff(100), Duration::ZERO);
    }

    #[test]
    fn no_backoff_default() {
        let mut backoff = NoBackoff;
        assert_eq!(backoff.next_backoff(0), Duration::ZERO);
    }

    #[test]
    fn no_backoff_copy() {
        let original = NoBackoff;
        let mut copied = original;
        assert_eq!(copied.next_backoff(0), Duration::ZERO);
    }

    #[test]
    fn no_backoff_clone_box() {
        let backoff = NoBackoff;
        let _boxed = backoff.clone_box();
    }

    #[test]
    fn no_backoff_debug() {
        let backoff = NoBackoff;
        let debug = format!("{backoff:?}");
        assert!(debug.contains("NoBackoff"));
    }

    // ── RetryConfig ─────────────────────────────────────────────────────

    #[test]
    fn test_retry_config() {
        let mut config = RetryConfig::new(3, ExponentialBackoff::default().with_jitter(None));

        assert_eq!(config.max_retries, 3);

        let d1 = config.next_backoff(0);
        let d2 = config.next_backoff(1);
        assert!(d2 > d1);
    }

    #[test]
    fn retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert!(config.max_total_time.is_none());
    }

    #[test]
    fn retry_config_with_max_total_time() {
        let config = RetryConfig::new(5, ConstantBackoff::new(Duration::from_secs(1)))
            .with_max_total_time(Duration::from_secs(30));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.max_total_time, Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_config_clone() {
        let original = RetryConfig::new(5, ExponentialBackoff::default().with_jitter(None))
            .with_max_total_time(Duration::from_secs(10));
        let cloned = original.clone();
        assert_eq!(cloned.max_retries, original.max_retries);
        assert_eq!(cloned.max_total_time, original.max_total_time);
    }

    #[test]
    fn retry_config_reset() {
        let mut config = RetryConfig::new(3, ConstantBackoff::new(Duration::from_secs(1)));
        let d1 = config.next_backoff(0);
        config.reset();
        let d2 = config.next_backoff(0);
        assert_eq!(d1, d2);
    }

    #[test]
    fn retry_config_debug() {
        let config = RetryConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RetryConfig"));
        assert!(debug.contains("max_retries"));
        assert!(debug.contains("<BackoffStrategy>"));
    }

    #[test]
    fn retry_config_with_no_backoff() {
        let mut config = RetryConfig::new(10, NoBackoff);
        for attempt in 0..10 {
            assert_eq!(config.next_backoff(attempt), Duration::ZERO);
        }
    }

    #[test]
    fn retry_config_with_linear_backoff() {
        let mut config = RetryConfig::new(
            5,
            LinearBackoff::new(
                Duration::from_millis(100),
                Duration::from_millis(100),
                Duration::from_secs(1),
            ),
        );
        assert_eq!(config.next_backoff(0), Duration::from_millis(100));
        assert_eq!(config.next_backoff(1), Duration::from_millis(200));
    }

    // ── RateLimitConfig ─────────────────────────────────────────────────

    #[test]
    fn rate_limit_config_new() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60));
        assert_eq!(config.requests_per_window, 100);
        assert_eq!(config.window, Duration::from_secs(60));
        assert!(config.burst_size.is_none());
        assert!(!config.enable_queue);
        assert!(config.max_queue_size.is_none());
    }

    #[test]
    fn rate_limit_config_with_burst() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_burst(150);
        assert_eq!(config.burst_size, Some(150));
    }

    #[test]
    fn rate_limit_config_with_queue() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_queue(50);
        assert!(config.enable_queue);
        assert_eq!(config.max_queue_size, Some(50));
    }

    #[test]
    fn rate_limit_config_presets() {
        let one = RateLimitConfig::one_per_second();
        assert_eq!(one.requests_per_window, 1);
        assert_eq!(one.window, Duration::from_secs(1));

        let ten = RateLimitConfig::ten_per_second();
        assert_eq!(ten.requests_per_window, 10);
        assert_eq!(ten.window, Duration::from_secs(1));

        let sixty = RateLimitConfig::sixty_per_minute();
        assert_eq!(sixty.requests_per_window, 60);
        assert_eq!(sixty.window, Duration::from_secs(60));

        let thousand = RateLimitConfig::thousand_per_minute();
        assert_eq!(thousand.requests_per_window, 1000);
        assert_eq!(thousand.window, Duration::from_secs(60));
    }

    #[test]
    fn rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_window, 60);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    #[test]
    fn rate_limit_config_serde_roundtrip() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60))
            .with_burst(200)
            .with_queue(10);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.requests_per_window, 100);
        assert_eq!(deserialized.burst_size, Some(200));
        assert!(deserialized.enable_queue);
        assert_eq!(deserialized.max_queue_size, Some(10));
    }

    #[test]
    fn rate_limit_config_debug() {
        let config = RateLimitConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RateLimitConfig"));
    }

    #[test]
    fn rate_limit_config_clone() {
        let original = RateLimitConfig::new(50, Duration::from_secs(30)).with_burst(100);
        let cloned = original.clone();
        assert_eq!(cloned.requests_per_window, original.requests_per_window);
        assert_eq!(cloned.burst_size, original.burst_size);
    }

    // ── RateLimitState ──────────────────────────────────────────────────

    #[test]
    fn rate_limit_state_serialize() {
        let state = RateLimitState {
            limit: 100,
            remaining: 42,
            reset_after: Duration::from_secs(30),
            is_limited: false,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"limit\":100"));
        assert!(json.contains("\"remaining\":42"));
        assert!(json.contains("\"is_limited\":false"));
    }

    #[test]
    fn rate_limit_state_debug_and_clone() {
        let state = RateLimitState {
            limit: 10,
            remaining: 0,
            reset_after: Duration::from_millis(500),
            is_limited: true,
        };
        let cloned = state.clone();
        assert_eq!(cloned.limit, 10);
        assert_eq!(cloned.remaining, 0);
        assert!(cloned.is_limited);
        let debug = format!("{state:?}");
        assert!(debug.contains("RateLimitState"));
    }

    // ── RateLimitError ──────────────────────────────────────────────────

    #[test]
    fn rate_limit_error_exceeded_display() {
        let err = RateLimitError::Exceeded {
            retry_after: Duration::from_secs(30),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Rate limit exceeded"));
        assert!(msg.contains("30s"));
    }

    #[test]
    fn rate_limit_error_wait_exceeded_display() {
        let err = RateLimitError::WaitExceeded {
            wait_time: Duration::from_secs(60),
            max_wait: Duration::from_secs(10),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Wait time"));
        assert!(msg.contains("exceeds maximum"));
    }

    #[test]
    fn rate_limit_error_invalid_config_display() {
        let err = RateLimitError::InvalidConfig("bad value".into());
        let msg = format!("{err}");
        assert!(msg.contains("Invalid rate limit configuration"));
        assert!(msg.contains("bad value"));
    }

    #[test]
    fn rate_limit_error_is_std_error() {
        let err = RateLimitError::Exceeded {
            retry_after: Duration::from_secs(1),
        };
        let _: &dyn std::error::Error = &err;
    }

    // ── Builder chain tests ─────────────────────────────────────────────

    #[test]
    fn rate_limit_config_builder_chain() {
        let config = RateLimitConfig::new(200, Duration::from_secs(120))
            .with_burst(300)
            .with_queue(25);
        assert_eq!(config.requests_per_window, 200);
        assert_eq!(config.window, Duration::from_secs(120));
        assert_eq!(config.burst_size, Some(300));
        assert!(config.enable_queue);
        assert_eq!(config.max_queue_size, Some(25));
    }

    #[test]
    fn exponential_backoff_builder_chain() {
        let backoff = ExponentialBackoff::new(Duration::from_millis(200), Duration::from_secs(30))
            .with_multiplier(1.5)
            .with_jitter(Some(0.3));
        assert_eq!(backoff.initial, Duration::from_millis(200));
        assert_eq!(backoff.max, Duration::from_secs(30));
        assert!((backoff.multiplier - 1.5).abs() < f64::EPSILON);
        assert_eq!(backoff.jitter, Some(0.3));
    }
}
