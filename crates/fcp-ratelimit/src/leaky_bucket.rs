//! Leaky bucket rate limiter implementation.
//!
//! Provides smooth request pacing with queue support.

use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::time::sleep;

use async_trait::async_trait;

use crate::{RateLimitError, RateLimitState, RateLimiter};

/// Leaky bucket rate limiter.
///
/// Requests "leak" out at a constant rate. New requests are added to the bucket.
/// If the bucket is full, requests are rejected or queued.
/// Guard band for floating-point comparison of level vs capacity.
///
/// Between consecutive `try_acquire` calls, real time passes and the bucket
/// leaks `leak_rate * elapsed` units.  With high leak rates (e.g. 100/s)
/// even a 1 ms scheduling gap drains 0.1 units, making a full bucket
/// appear to have room.  A guard of 0.5 (half a request unit) prevents
/// these timing artifacts from creating false capacity while still allowing
/// the bucket to fill to its declared capacity.
const LEVEL_GUARD: f64 = 0.5;

pub struct LeakyBucket {
    /// Bucket capacity.
    capacity: u32,

    /// Leak rate (requests per second).
    leak_rate: f64,

    /// Current water level.
    level: Mutex<f64>,

    /// Last leak time.
    last_leak: Mutex<Instant>,
}

impl LeakyBucket {
    /// Create a new leaky bucket rate limiter.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum bucket size
    /// * `leak_rate` - Requests leaked per second
    #[must_use]
    pub fn new(capacity: u32, leak_rate: f64) -> Self {
        Self {
            capacity,
            leak_rate,
            level: Mutex::new(0.0),
            last_leak: Mutex::new(Instant::now()),
        }
    }

    /// Create from requests per window.
    #[must_use]
    pub fn from_window(requests_per_window: u32, window: Duration) -> Self {
        let leak_rate = f64::from(requests_per_window) / window.as_secs_f64();
        Self::new(requests_per_window, leak_rate)
    }

    /// Leak water based on elapsed time.
    fn leak(&self) {
        let now = Instant::now();
        let mut last_leak = self.last_leak.lock();
        let mut level = self.level.lock();

        let elapsed = now.duration_since(*last_leak);
        let leaked = elapsed.as_secs_f64() * self.leak_rate;

        if leaked > 0.0 {
            *level = (*level - leaked).max(0.0);
            drop(level);
            *last_leak = now;
        }
    }

    /// Calculate time until bucket has room.
    fn time_until_room(&self) -> Duration {
        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);

        if level <= capacity - 1.0 {
            Duration::ZERO
        } else {
            let overflow = level - (capacity - 1.0);
            Duration::from_secs_f64(overflow / self.leak_rate)
        }
    }
}

#[async_trait]
impl RateLimiter for LeakyBucket {
    async fn try_acquire(&self) -> bool {
        self.try_acquire_n(1).await
    }

    async fn try_acquire_n(&self, permits: u32) -> bool {
        self.leak();

        let mut level = self.level.lock();
        let capacity = f64::from(self.capacity);
        let amount = f64::from(permits);

        if *level + amount <= capacity {
            *level += amount;
            true
        } else {
            false
        }
    }

    async fn acquire(&self, max_wait: Duration) -> Result<Duration, RateLimitError> {
        let start = Instant::now();

        loop {
            if self.try_acquire().await {
                return Ok(start.elapsed());
            }

            let wait_time = self.wait_time().await;
            let total_waited = start.elapsed();

            if total_waited + wait_time > max_wait {
                return Err(RateLimitError::WaitExceeded {
                    wait_time: total_waited + wait_time,
                    max_wait,
                });
            }

            sleep(wait_time).await;
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn remaining(&self) -> u32 {
        self.leak();
        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);
        (capacity - level).max(0.0) as u32
    }

    async fn wait_time(&self) -> Duration {
        self.leak();
        self.time_until_room()
    }

    async fn reset(&self) {
        // Acquire locks in same order as leak() to prevent deadlock: last_leak then level
        let mut last_leak = self.last_leak.lock();
        let mut level = self.level.lock();
        *level = 0.0;
        drop(level);
        *last_leak = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        self.leak();

        let level = *self.level.lock();
        let capacity = f64::from(self.capacity);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let remaining = (capacity - level).max(0.0) as u32;

        RateLimitState {
            limit: self.capacity,
            remaining,
            reset_after: self.time_until_room(),
            is_limited: level + LEVEL_GUARD >= capacity,
        }
    }
}

/// Smooth rate limiter for pacing requests.
///
/// Ensures minimum delay between requests.
pub struct SmoothPacer {
    /// Minimum interval between requests.
    min_interval: Duration,

    /// Last request time.
    last_request: Mutex<Option<Instant>>,
}

impl SmoothPacer {
    /// Create a new smooth pacer.
    #[must_use]
    pub const fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            last_request: Mutex::new(None),
        }
    }

    /// Create from requests per second.
    #[must_use]
    pub fn from_rate(requests_per_second: f64) -> Self {
        Self::new(Duration::from_secs_f64(1.0 / requests_per_second))
    }
}

#[async_trait]
impl RateLimiter for SmoothPacer {
    async fn try_acquire(&self) -> bool {
        let mut last = self.last_request.lock();
        let now = Instant::now();

        let last_time_val = *last;
        if let Some(last_time) = last_time_val {
            if now.duration_since(last_time) < self.min_interval {
                return false;
            }
        }

        *last = Some(now);
        true
    }

    async fn acquire(&self, max_wait: Duration) -> Result<Duration, RateLimitError> {
        let start = Instant::now();

        loop {
            if self.try_acquire().await {
                return Ok(start.elapsed());
            }

            let wait_time = self.wait_time().await;
            let total_waited = start.elapsed();

            if total_waited + wait_time > max_wait {
                return Err(RateLimitError::WaitExceeded {
                    wait_time: total_waited + wait_time,
                    max_wait,
                });
            }

            sleep(wait_time).await;
        }
    }

    fn remaining(&self) -> u32 {
        self.last_request.lock().map_or(1, |last| {
            u32::from(Instant::now().duration_since(last) >= self.min_interval)
        })
    }

    async fn wait_time(&self) -> Duration {
        let last_time_val = *self.last_request.lock();
        if let Some(last) = last_time_val {
            let elapsed = Instant::now().duration_since(last);
            if elapsed < self.min_interval {
                return self
                    .min_interval
                    .checked_sub(elapsed)
                    .unwrap_or(Duration::ZERO);
            }
        }
        Duration::ZERO
    }

    async fn reset(&self) {
        *self.last_request.lock() = None;
    }

    fn state(&self) -> RateLimitState {
        let last_time_val = *self.last_request.lock();
        let (remaining, reset_after) = last_time_val.map_or((1, Duration::ZERO), |last| {
            let elapsed = Instant::now().duration_since(last);
            if elapsed >= self.min_interval {
                (1, Duration::ZERO)
            } else {
                (
                    0,
                    self.min_interval
                        .checked_sub(elapsed)
                        .unwrap_or(Duration::ZERO),
                )
            }
        });

        RateLimitState {
            limit: 1,
            remaining,
            reset_after,
            is_limited: remaining == 0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    // ── LeakyBucket tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_leaky_bucket_basic() {
        let limiter = LeakyBucket::new(5, 10.0); // 5 capacity, 10/sec leak

        // Fill bucket
        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }

        // Should be nearly full (may have leaked slightly during test execution)
        let level = *limiter.level.lock();
        assert!(level >= 4.5, "bucket should be nearly full, level={level}");

        // Wait for leak (10/sec means 2 leak in 200ms)
        sleep(Duration::from_millis(200)).await;

        // Should have room after leaking
        assert!(limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn leaky_bucket_from_window() {
        // 60 requests per 60 seconds → leak_rate = 1.0/sec, capacity = 60
        let limiter = LeakyBucket::from_window(60, Duration::from_secs(60));
        assert_eq!(limiter.capacity, 60);
        assert!((limiter.leak_rate - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn leaky_bucket_rejects_when_full() {
        let limiter = LeakyBucket::new(3, 0.001); // very slow leak

        // Fill to capacity
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);

        // 4th request should be rejected
        assert!(!limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn leaky_bucket_remaining_reflects_level() {
        let limiter = LeakyBucket::new(10, 0.001); // very slow leak

        assert_eq!(limiter.remaining(), 10);

        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 9);

        limiter.try_acquire().await;
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 7);
    }

    #[tokio::test]
    async fn leaky_bucket_state_not_limited_when_empty() {
        let limiter = LeakyBucket::new(5, 1.0);
        let state = limiter.state();

        assert_eq!(state.limit, 5);
        assert_eq!(state.remaining, 5);
        assert!(!state.is_limited);
        assert_eq!(state.reset_after, Duration::ZERO);
    }

    #[tokio::test]
    async fn leaky_bucket_state_limited_when_full() {
        let limiter = LeakyBucket::new(2, 0.001);

        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let state = limiter.state();
        assert_eq!(state.limit, 2);
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
        assert!(state.reset_after > Duration::ZERO);
    }

    #[tokio::test]
    async fn leaky_bucket_reset_clears_level() {
        let limiter = LeakyBucket::new(5, 0.001);

        // Fill up
        for _ in 0..5 {
            limiter.try_acquire().await;
        }
        assert!(!limiter.try_acquire().await);

        // Reset
        limiter.reset().await;

        // Should have full capacity again
        assert_eq!(limiter.remaining(), 5);
        assert!(limiter.try_acquire().await);
    }

    #[tokio::test]
    async fn leaky_bucket_wait_time_zero_when_room() {
        let limiter = LeakyBucket::new(5, 1.0);
        assert_eq!(limiter.wait_time().await, Duration::ZERO);
    }

    #[tokio::test]
    async fn leaky_bucket_wait_time_positive_when_full() {
        let limiter = LeakyBucket::new(2, 0.001);

        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let wait = limiter.wait_time().await;
        assert!(
            wait > Duration::ZERO,
            "expected positive wait, got {wait:?}"
        );
    }

    #[tokio::test]
    async fn leaky_bucket_acquire_succeeds_within_limit() {
        let limiter = LeakyBucket::new(5, 1.0);
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        // Should return almost instantly
        assert!(waited < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn leaky_bucket_acquire_waits_and_succeeds() {
        // Capacity 1, leak rate 100/sec → refills in ~10ms
        let limiter = LeakyBucket::new(1, 100.0);

        // Fill it
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // acquire() should wait for leak and then succeed
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn leaky_bucket_acquire_exceeds_max_wait() {
        let limiter = LeakyBucket::new(1, 0.001); // very slow leak

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

    #[tokio::test]
    async fn leaky_bucket_try_acquire_n_only_supports_one() {
        let limiter = LeakyBucket::new(10, 1.0);

        // n=1 delegates to try_acquire
        assert!(limiter.try_acquire_n(1).await);

        // n>1 always returns false (default RateLimiter impl)
        assert!(!limiter.try_acquire_n(2).await);
        assert!(!limiter.try_acquire_n(5).await);
    }

    #[tokio::test]
    async fn leaky_bucket_leak_recovers_capacity() {
        // High leak rate so test is fast: 100/sec
        let limiter = LeakyBucket::new(3, 100.0);

        // Fill completely
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // Wait for rapid leak
        sleep(Duration::from_millis(20)).await;

        // Should have room again
        assert!(limiter.try_acquire().await);
    }

    // ── SmoothPacer tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_smooth_pacer() {
        let pacer = SmoothPacer::new(Duration::from_millis(50));

        // First request succeeds
        assert!(pacer.try_acquire().await);

        // Immediate second request fails
        assert!(!pacer.try_acquire().await);

        // Wait and try again
        sleep(Duration::from_millis(60)).await;
        assert!(pacer.try_acquire().await);
    }

    #[tokio::test]
    async fn smooth_pacer_from_rate() {
        // 10 requests/sec → 100ms min interval
        let pacer = SmoothPacer::from_rate(10.0);

        assert!(pacer.try_acquire().await);
        assert!(!pacer.try_acquire().await);

        sleep(Duration::from_millis(110)).await;
        assert!(pacer.try_acquire().await);
    }

    #[tokio::test]
    async fn smooth_pacer_remaining_before_any_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        // No request made yet → remaining should be 1
        assert_eq!(pacer.remaining(), 1);
    }

    #[tokio::test]
    async fn smooth_pacer_remaining_zero_after_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;
        // Immediately after → remaining should be 0
        assert_eq!(pacer.remaining(), 0);
    }

    #[tokio::test]
    async fn smooth_pacer_remaining_recovers_after_interval() {
        let pacer = SmoothPacer::new(Duration::from_millis(20));
        pacer.try_acquire().await;
        sleep(Duration::from_millis(30)).await;
        assert_eq!(pacer.remaining(), 1);
    }

    #[tokio::test]
    async fn smooth_pacer_state_before_any_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        let state = pacer.state();

        assert_eq!(state.limit, 1);
        assert_eq!(state.remaining, 1);
        assert!(!state.is_limited);
        assert_eq!(state.reset_after, Duration::ZERO);
    }

    #[tokio::test]
    async fn smooth_pacer_state_limited_after_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;

        let state = pacer.state();
        assert_eq!(state.limit, 1);
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
        assert!(state.reset_after > Duration::ZERO);
    }

    #[tokio::test]
    async fn smooth_pacer_reset_allows_immediate_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));

        pacer.try_acquire().await;
        assert!(!pacer.try_acquire().await);

        pacer.reset().await;

        // After reset, should succeed immediately
        assert!(pacer.try_acquire().await);
    }

    #[tokio::test]
    async fn smooth_pacer_wait_time_zero_before_any_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        assert_eq!(pacer.wait_time().await, Duration::ZERO);
    }

    #[tokio::test]
    async fn smooth_pacer_wait_time_positive_after_request() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;
        let wait = pacer.wait_time().await;
        assert!(
            wait > Duration::ZERO,
            "expected positive wait, got {wait:?}"
        );
        assert!(wait <= Duration::from_millis(500));
    }

    #[tokio::test]
    async fn smooth_pacer_acquire_succeeds_immediately_when_fresh() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));
        let waited = pacer.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn smooth_pacer_acquire_waits_for_interval() {
        let pacer = SmoothPacer::new(Duration::from_millis(30));
        pacer.try_acquire().await;

        // Second acquire waits for interval
        let waited = pacer.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn smooth_pacer_acquire_exceeds_max_wait() {
        let pacer = SmoothPacer::new(Duration::from_millis(500));
        pacer.try_acquire().await;

        let result = pacer.acquire(Duration::from_millis(5)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RateLimitError::WaitExceeded { max_wait, .. } => {
                assert_eq!(max_wait, Duration::from_millis(5));
            }
            other => panic!("expected WaitExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn smooth_pacer_try_acquire_n_only_supports_one() {
        let pacer = SmoothPacer::new(Duration::from_millis(100));

        assert!(pacer.try_acquire_n(1).await);
        assert!(!pacer.try_acquire_n(2).await);
    }
}
