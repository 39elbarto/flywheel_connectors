//! Token bucket rate limiter implementation.
//!
//! Classic token bucket algorithm with burst support.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::time::sleep;
use parking_lot::Mutex;

use async_trait::async_trait;

use crate::{RateLimitConfig, RateLimitError, RateLimitState, RateLimiter};

/// Token bucket rate limiter.
///
/// Tokens are added at a fixed rate up to a maximum bucket size.
/// Each request consumes one token.
pub struct TokenBucket {
    /// Maximum tokens (bucket capacity).
    capacity: u32,

    /// Tokens added per refill.
    refill_amount: u32,

    /// Time between refills.
    refill_interval: Duration,

    /// Current token count.
    tokens: AtomicU32,

    /// Last refill time.
    last_refill: Mutex<Instant>,
}

impl TokenBucket {
    /// Create a new token bucket rate limiter.
    ///
    /// # Arguments
    ///
    /// * `requests_per_window` - Maximum requests allowed per window
    /// * `window` - Duration of the rate limit window
    #[must_use]
    pub fn new(requests_per_window: u32, window: Duration) -> Self {
        // Ensure refill interval is never zero to prevent division by zero
        let refill_interval = if window.is_zero() {
            Duration::from_nanos(1)
        } else {
            window
        };

        Self {
            capacity: requests_per_window,
            refill_amount: requests_per_window,
            refill_interval,
            tokens: AtomicU32::new(requests_per_window),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Create from configuration.
    #[must_use]
    pub fn from_config(config: &RateLimitConfig) -> Self {
        let capacity = config.burst_size.unwrap_or(config.requests_per_window);

        // Normalize rate for smoothness (avoid "burst-then-wait" behavior).
        // Instead of adding N tokens every T seconds, add 1 token every T/N seconds.
        let (refill_amount, refill_interval) = if config.requests_per_window > 0 {
            let window_nanos = config.window.as_nanos();
            let nanos_per_request = window_nanos / u128::from(config.requests_per_window);

            if nanos_per_request > 0 {
                // Smooth rate: 1 token per calculated interval
                (
                    1,
                    Duration::from_nanos(u64::try_from(nanos_per_request).unwrap_or(u64::MAX)),
                )
            } else {
                // Rate too high for smooth 1-token refilling (e.g. > 1 req/ns),
                // or window is zero. Fallback to window-based.
                (config.requests_per_window, config.window)
            }
        } else {
            (0, config.window)
        };

        // Ensure refill interval is never zero
        let refill_interval = if refill_interval.is_zero() {
            Duration::from_nanos(1)
        } else {
            refill_interval
        };

        Self {
            capacity,
            refill_amount,
            refill_interval,
            tokens: AtomicU32::new(capacity),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Create with burst capacity.
    #[must_use]
    pub fn with_burst(requests_per_window: u32, window: Duration, burst: u32) -> Self {
        // Ensure refill interval is never zero
        let refill_interval = if window.is_zero() {
            Duration::from_nanos(1)
        } else {
            window
        };

        Self {
            capacity: burst,
            refill_amount: requests_per_window,
            refill_interval,
            tokens: AtomicU32::new(burst),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&self) {
        let mut last_refill = self.last_refill.lock();
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(*last_refill);

        if elapsed >= self.refill_interval {
            // Calculate how many refill periods have passed
            let periods_u128 = elapsed.as_nanos() / self.refill_interval.as_nanos();
            let tokens_to_add_u128 = periods_u128.saturating_mul(u128::from(self.refill_amount));
            let tokens_to_add = u32::try_from(tokens_to_add_u128).unwrap_or(u32::MAX);

            // Add tokens up to capacity using compare_exchange to avoid race with try_acquire
            loop {
                let current = self.tokens.load(Ordering::Acquire);
                let new_tokens = current.saturating_add(tokens_to_add).min(self.capacity);

                // If already at or above capacity after adding, just break
                if new_tokens == current {
                    break;
                }

                if self
                    .tokens
                    .compare_exchange(current, new_tokens, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
                // CAS failed, retry with fresh value
            }

            // Update last refill time, preserving phase (remainder) to avoid drift
            // If bucket is full, we clamp last_refill to now - remainder to prevent ancient history from causing bursts
            // If not full, we just advance by the number of periods processed
            let current = self.tokens.load(Ordering::Acquire);
            if current == self.capacity {
                let remainder = elapsed.as_nanos() % self.refill_interval.as_nanos();
                let rem_secs = u64::try_from(remainder / 1_000_000_000).unwrap_or(0);
                let rem_nanos = (remainder % 1_000_000_000) as u32;
                *last_refill = now
                    .checked_sub(Duration::new(rem_secs, rem_nanos))
                    .unwrap_or(now);
            } else {
                let advance_nanos = periods_u128.saturating_mul(self.refill_interval.as_nanos());
                let adv_secs = u64::try_from(advance_nanos / 1_000_000_000).unwrap_or(u64::MAX);
                let adv_nanos = (advance_nanos % 1_000_000_000) as u32;
                if adv_secs < u64::MAX {
                    if let Some(advanced) = last_refill.checked_add(Duration::new(adv_secs, adv_nanos)) {
                        *last_refill = advanced;
                    } else {
                        *last_refill = now;
                    }
                } else {
                    *last_refill = now;
                }
            }
        }
    }

    /// Try to consume `amount` tokens atomically.
    fn try_consume(&self, amount: u32) -> bool {
        if amount == 0 {
            return true;
        }
        if amount > self.capacity {
            return false;
        }

        self.refill();

        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < amount {
                return false;
            }

            if self
                .tokens
                .compare_exchange(
                    current,
                    current - amount,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Calculate time until next token is available.
    fn time_until_token(&self) -> Duration {
        let last_refill = *self.last_refill.lock();
        let elapsed = Instant::now().saturating_duration_since(last_refill);

        self.refill_interval
            .checked_sub(elapsed)
            .unwrap_or(Duration::ZERO)
    }
}

#[async_trait]
impl RateLimiter for TokenBucket {
    async fn try_acquire(&self) -> bool {
        self.try_consume(1)
    }

    async fn try_acquire_n(&self, permits: u32) -> bool {
        self.try_consume(permits)
    }

    async fn acquire(&self, max_wait: Duration) -> Result<Duration, RateLimitError> {
        let start = Instant::now();

        loop {
            if self.try_acquire().await {
                return Ok(start.elapsed());
            }

            let wait_time = self.wait_time().await;
            let total_waited = start.elapsed();
            let projected = total_waited.checked_add(wait_time).unwrap_or(Duration::MAX);

            if projected > max_wait {
                return Err(RateLimitError::WaitExceeded {
                    wait_time: projected,
                    max_wait,
                });
            }

            sleep(wait_time).await;
        }
    }

    fn remaining(&self) -> u32 {
        self.tokens.load(Ordering::Acquire)
    }

    async fn wait_time(&self) -> Duration {
        if self.capacity == 0 {
            return Duration::MAX;
        }

        if self.tokens.load(Ordering::Acquire) > 0 {
            Duration::ZERO
        } else {
            self.time_until_token()
        }
    }

    async fn reset(&self) {
        self.tokens.store(self.capacity, Ordering::Release);
        *self.last_refill.lock() = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        self.refill();
        let remaining = self.tokens.load(Ordering::Acquire);

        RateLimitState {
            limit: self.capacity,
            remaining,
            reset_after: self.time_until_token(),
            is_limited: remaining == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic behavior ──────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_basic() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }

        // 6th should fail
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_refill() {
        let limiter = TokenBucket::new(2, Duration::from_millis(100));

        // Consume all tokens
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // Wait for refill
        sleep(Duration::from_millis(150)).await;

        // Should have tokens again
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_state() {
        let limiter = TokenBucket::new(10, Duration::from_secs(1));

        let state = limiter.state();
        assert_eq!(state.limit, 10);
        assert_eq!(state.remaining, 10);
        assert!(!state.is_limited);

        // Consume some tokens
        for _ in 0..7 {
            limiter.try_acquire().await;
        }

        let state = limiter.state();
        assert_eq!(state.remaining, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_acquire_with_wait() {
        let limiter = TokenBucket::new(1, Duration::from_millis(50));

        // First request succeeds immediately
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(10));

        // Second request should wait
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited >= Duration::from_millis(40));
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_try_acquire_n_is_atomic() {
        let limiter = TokenBucket::new(2, Duration::from_secs(1));

        // Cannot atomically take 3 tokens from a bucket of 2; must not partially consume.
        assert!(!limiter.try_acquire_n(3).await);
        assert_eq!(limiter.remaining(), 2);

        // Taking 2 works.
        assert!(limiter.try_acquire_n(2).await);
        assert_eq!(limiter.remaining(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_bucket_zero_window_safety() {
        // Ensure we don't panic if window is zero (e.g. from bad config)
        let config = RateLimitConfig {
            requests_per_window: 100,
            window: Duration::ZERO,
            ..Default::default()
        };

        // Should not panic
        let limiter = TokenBucket::from_config(&config);

        // Should work safely (likely using fallback 1ns interval or similar logic)
        assert!(limiter.try_acquire().await);

        // Direct constructor safety
        let limiter_direct = TokenBucket::new(100, Duration::ZERO);
        assert!(limiter_direct.try_acquire().await);
    }

    // ── from_config ─────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn from_config_basic() {
        let config = RateLimitConfig::new(60, Duration::from_secs(60));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 60);
        assert_eq!(limiter.remaining(), 60);
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_with_burst() {
        let config = RateLimitConfig::new(60, Duration::from_secs(60)).with_burst(120);
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 120);
        assert_eq!(limiter.remaining(), 120);
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_zero_requests() {
        let config = RateLimitConfig::new(0, Duration::from_secs(60));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.capacity, 0);
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn from_config_smooth_rate() {
        // 100 requests per second → refill_amount=1, interval=10ms
        let config = RateLimitConfig::new(100, Duration::from_secs(1));
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.refill_amount, 1);
        // Interval should be 10ms (1_000_000_000 / 100 = 10_000_000 ns)
        assert_eq!(limiter.refill_interval, Duration::from_millis(10));
    }

    // ── with_burst constructor ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn with_burst_constructor() {
        let limiter = TokenBucket::with_burst(10, Duration::from_secs(1), 20);
        assert_eq!(limiter.capacity, 20);
        assert_eq!(limiter.refill_amount, 10);
        assert_eq!(limiter.remaining(), 20);

        // Should allow 20 initial requests (burst capacity)
        for _ in 0..20 {
            assert!(limiter.try_acquire().await);
        }
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn with_burst_zero_window() {
        let limiter = TokenBucket::with_burst(10, Duration::ZERO, 20);
        assert_eq!(limiter.capacity, 20);
        // refill_interval should be clamped to 1ns
        assert_eq!(limiter.refill_interval, Duration::from_nanos(1));
    }

    // ── try_acquire_n edge cases ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn try_acquire_n_zero_permits() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        // Zero permits should always succeed
        assert!(limiter.try_acquire_n(0).await);
        assert_eq!(limiter.remaining(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn try_acquire_n_exceeds_capacity() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        assert!(!limiter.try_acquire_n(6).await);
        assert_eq!(limiter.remaining(), 5); // No tokens consumed
    }

    #[fcp_async_core::runtime::test]
    async fn try_acquire_n_exact_capacity() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        assert!(limiter.try_acquire_n(5).await);
        assert_eq!(limiter.remaining(), 0);
    }

    // ── Reset ───────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn reset_restores_full_capacity() {
        let limiter = TokenBucket::new(10, Duration::from_secs(60));

        for _ in 0..10 {
            limiter.try_acquire().await;
        }
        assert_eq!(limiter.remaining(), 0);

        limiter.reset().await;
        assert_eq!(limiter.remaining(), 10);
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn state_after_reset() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        for _ in 0..5 {
            limiter.try_acquire().await;
        }

        let state_before = limiter.state();
        assert_eq!(state_before.remaining, 0);
        assert!(state_before.is_limited);

        limiter.reset().await;

        let state_after = limiter.state();
        assert_eq!(state_after.remaining, 5);
        assert!(!state_after.is_limited);
    }

    // ── wait_time ───────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn wait_time_zero_when_tokens_available() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn wait_time_positive_when_exhausted() {
        let limiter = TokenBucket::new(1, Duration::from_millis(100));
        limiter.try_acquire().await;
        let wait = limiter.wait_time().await;
        assert!(wait > Duration::ZERO);
        assert!(wait <= Duration::from_millis(100));
    }

    #[fcp_async_core::runtime::test]
    async fn wait_time_max_when_zero_capacity() {
        let limiter = TokenBucket::new(0, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::MAX);
    }

    // ── acquire error paths ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn acquire_exceeds_max_wait() {
        let limiter = TokenBucket::new(1, Duration::from_secs(60));
        limiter.try_acquire().await;

        let result = limiter.acquire(Duration::from_millis(5)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RateLimitError::WaitExceeded { max_wait, .. } => {
                assert_eq!(max_wait, Duration::from_millis(5));
            }
            other => panic!("expected WaitExceeded, got {other:?}"),
        }
    }

    // ── State snapshot details ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn state_reset_after_bounded_when_tokens_available() {
        let limiter = TokenBucket::new(5, Duration::from_secs(1));
        let state = limiter.state();
        // reset_after reflects time until next refill, bounded by the refill interval
        assert!(state.reset_after <= Duration::from_secs(1));
    }

    #[fcp_async_core::runtime::test]
    async fn state_is_limited_when_exhausted() {
        let limiter = TokenBucket::new(2, Duration::from_secs(60));
        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let state = limiter.state();
        assert!(state.is_limited);
        assert_eq!(state.remaining, 0);
    }

    // ── Single token capacity ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn single_token_bucket() {
        let limiter = TokenBucket::new(1, Duration::from_millis(50));

        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        sleep(Duration::from_millis(60)).await;

        assert!(limiter.try_acquire().await);
    }
}
