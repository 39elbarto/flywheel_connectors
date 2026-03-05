//! Sliding window rate limiter implementation.
//!
//! Provides accurate rate limiting with smooth window transitions.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use fcp_async_core::time::sleep;
use parking_lot::Mutex;

use async_trait::async_trait;

use crate::{RateLimitError, RateLimitState, RateLimiter};

/// Sliding window rate limiter.
///
/// Tracks individual request timestamps for accurate rate limiting.
pub struct SlidingWindow {
    /// Maximum requests per window.
    limit: u32,

    /// Window duration.
    window: Duration,

    /// Request timestamps within the current window.
    timestamps: Mutex<VecDeque<Instant>>,
}

impl SlidingWindow {
    /// Create a new sliding window rate limiter.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            timestamps: Mutex::new(VecDeque::with_capacity((limit as usize).min(100_000))),
        }
    }

    /// Remove expired timestamps from the locked deque.
    fn cleanup_locked(&self, timestamps: &mut VecDeque<Instant>, now: Instant) {
        while let Some(front) = timestamps.front() {
            if now.saturating_duration_since(*front) > self.window {
                timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Calculate remaining capacity.
    fn calculate_remaining(&self) -> u32 {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock();
        self.cleanup_locked(&mut timestamps, now);
        let len_u32 = u32::try_from(timestamps.len()).unwrap_or(u32::MAX);
        drop(timestamps);
        self.limit.saturating_sub(len_u32)
    }
}

#[async_trait]
impl RateLimiter for SlidingWindow {
    async fn try_acquire(&self) -> bool {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock();
        self.cleanup_locked(&mut timestamps, now);

        if timestamps.len() < self.limit as usize {
            timestamps.push_back(now);
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
        self.calculate_remaining()
    }

    async fn wait_time(&self) -> Duration {
        if self.limit == 0 {
            return Duration::MAX;
        }

        let now = Instant::now();
        let mut timestamps = self.timestamps.lock();
        self.cleanup_locked(&mut timestamps, now);

        if timestamps.len() < self.limit as usize {
            return Duration::ZERO;
        }

        // Wait until the oldest request expires
        let result = timestamps.front().map_or(Duration::ZERO, |oldest| {
            let elapsed = now.saturating_duration_since(*oldest);
            if elapsed < self.window {
                self.window.checked_sub(elapsed).unwrap_or(Duration::ZERO)
            } else {
                Duration::ZERO
            }
        });
        drop(timestamps);

        result
    }

    async fn reset(&self) {
        self.timestamps.lock().clear();
    }

    fn state(&self) -> RateLimitState {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock();
        self.cleanup_locked(&mut timestamps, now);

        let len = u32::try_from(timestamps.len()).unwrap_or(u32::MAX);
        let remaining = self.limit.saturating_sub(len);

        let reset_after = timestamps.front().map_or(self.window, |oldest| {
            let elapsed = now.saturating_duration_since(*oldest);
            self.window.checked_sub(elapsed).unwrap_or(Duration::ZERO)
        });
        drop(timestamps);

        RateLimitState {
            limit: self.limit,
            remaining,
            reset_after,
            is_limited: remaining == 0,
        }
    }
}

/// Fixed window rate limiter (simpler, less accurate).
///
/// Resets counter at fixed intervals.
pub struct FixedWindow {
    /// Maximum requests per window.
    limit: u32,

    /// Window duration.
    window: Duration,

    /// Mutable state.
    state: Mutex<FixedWindowState>,
}

struct FixedWindowState {
    /// Current request count.
    count: u32,

    /// Window start time.
    window_start: Instant,
}

impl FixedWindow {
    /// Create a new fixed window rate limiter.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            state: Mutex::new(FixedWindowState {
                count: 0,
                window_start: Instant::now(),
            }),
        }
    }
}

#[async_trait]
impl RateLimiter for FixedWindow {
    async fn try_acquire(&self) -> bool {
        let mut state = self.state.lock();
        let now = Instant::now();

        // Check window expiry
        if now.saturating_duration_since(state.window_start) >= self.window {
            state.count = 0;
            state.window_start = now;
        }

        if state.count < self.limit {
            state.count += 1;
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
        let mut state = self.state.lock();
        let now = Instant::now();

        if now.saturating_duration_since(state.window_start) >= self.window {
            state.count = 0;
            state.window_start = now;
        }

        self.limit.saturating_sub(state.count)
    }

    async fn wait_time(&self) -> Duration {
        if self.limit == 0 {
            return Duration::MAX;
        }

        let mut state = self.state.lock();
        let now = Instant::now();

        // Check reset inside wait_time to ensure consistency
        if now.saturating_duration_since(state.window_start) >= self.window {
            state.count = 0;
            state.window_start = now;
        }

        if state.count < self.limit {
            return Duration::ZERO;
        }

        let elapsed = now.saturating_duration_since(state.window_start);
        drop(state);
        self.window.checked_sub(elapsed).unwrap_or(Duration::ZERO)
    }

    async fn reset(&self) {
        let mut state = self.state.lock();
        state.count = 0;
        state.window_start = Instant::now();
    }

    fn state(&self) -> RateLimitState {
        let mut state = self.state.lock();
        let now = Instant::now();

        if now.saturating_duration_since(state.window_start) >= self.window {
            state.count = 0;
            state.window_start = now;
        }

        let remaining = self.limit.saturating_sub(state.count);
        let elapsed = now.saturating_duration_since(state.window_start);
        drop(state);
        let reset_after = self.window.checked_sub(elapsed).unwrap_or(Duration::ZERO);

        RateLimitState {
            limit: self.limit,
            remaining,
            reset_after,
            is_limited: remaining == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SlidingWindow: basic ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_sliding_window_basic() {
        let limiter = SlidingWindow::new(5, Duration::from_secs(1));

        for _ in 0..5 {
            assert!(limiter.try_acquire().await);
        }
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_sliding_window_expiry() {
        let limiter = SlidingWindow::new(2, Duration::from_millis(100));

        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        sleep(Duration::from_millis(150)).await;

        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_sliding_window_wait_time() {
        let limiter = SlidingWindow::new(1, Duration::from_millis(100));

        // Acquire the only permit
        assert!(limiter.try_acquire().await);

        // Now it should be limited
        assert!(!limiter.try_acquire().await);

        // Check wait time - should be approx 100ms
        let wait = limiter.wait_time().await;
        assert!(wait.as_millis() > 0);
        assert!(wait.as_millis() <= 100);

        // Wait that amount
        sleep(wait).await;

        // Should be available now
        assert!(limiter.try_acquire().await);
    }

    // ── SlidingWindow: remaining ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn sliding_window_remaining_starts_at_limit() {
        let limiter = SlidingWindow::new(10, Duration::from_secs(60));
        assert_eq!(limiter.remaining(), 10);
    }

    #[fcp_async_core::runtime::test]
    async fn sliding_window_remaining_decreases_on_acquire() {
        let limiter = SlidingWindow::new(5, Duration::from_secs(60));
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 4);
        limiter.try_acquire().await;
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn sliding_window_remaining_recovers_after_expiry() {
        let limiter = SlidingWindow::new(2, Duration::from_millis(50));
        limiter.try_acquire().await;
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 0);

        sleep(Duration::from_millis(60)).await;
        assert_eq!(limiter.remaining(), 2);
    }

    // ── SlidingWindow: state ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn sliding_window_state_empty() {
        let limiter = SlidingWindow::new(5, Duration::from_secs(1));
        let state = limiter.state();
        assert_eq!(state.limit, 5);
        assert_eq!(state.remaining, 5);
        assert!(!state.is_limited);
    }

    #[fcp_async_core::runtime::test]
    async fn sliding_window_state_full() {
        let limiter = SlidingWindow::new(2, Duration::from_secs(60));
        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let state = limiter.state();
        assert_eq!(state.limit, 2);
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
        assert!(state.reset_after > Duration::ZERO);
    }

    // ── SlidingWindow: reset ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn sliding_window_reset_restores_capacity() {
        let limiter = SlidingWindow::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            limiter.try_acquire().await;
        }
        assert!(!limiter.try_acquire().await);

        limiter.reset().await;
        assert_eq!(limiter.remaining(), 3);
        assert!(limiter.try_acquire().await);
    }

    // ── SlidingWindow: acquire ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn sliding_window_acquire_immediate_when_available() {
        let limiter = SlidingWindow::new(5, Duration::from_secs(1));
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(50));
    }

    #[fcp_async_core::runtime::test]
    async fn sliding_window_acquire_waits_for_expiry() {
        let limiter = SlidingWindow::new(1, Duration::from_millis(50));
        limiter.try_acquire().await;

        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited >= Duration::from_millis(30));
    }

    #[fcp_async_core::runtime::test]
    async fn sliding_window_acquire_exceeds_max_wait() {
        let limiter = SlidingWindow::new(1, Duration::from_secs(60));
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

    // ── SlidingWindow: wait_time edge cases ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn sliding_window_wait_time_zero_when_available() {
        let limiter = SlidingWindow::new(5, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn sliding_window_wait_time_max_when_zero_limit() {
        let limiter = SlidingWindow::new(0, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::MAX);
    }

    // ── SlidingWindow: try_acquire_n ───────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn sliding_window_try_acquire_n_default_behavior() {
        let limiter = SlidingWindow::new(5, Duration::from_secs(60));

        // Default try_acquire_n only supports permits == 1
        assert!(limiter.try_acquire_n(1).await);
        assert!(!limiter.try_acquire_n(2).await);
    }

    // ── FixedWindow: basic ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_fixed_window_basic() {
        let limiter = FixedWindow::new(3, Duration::from_secs(1));

        for _ in 0..3 {
            assert!(limiter.try_acquire().await);
        }
        assert!(!limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_fixed_window_reset() {
        let limiter = FixedWindow::new(2, Duration::from_millis(100));

        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        sleep(Duration::from_millis(150)).await;

        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_fixed_window_wait_time() {
        let limiter = FixedWindow::new(1, Duration::from_millis(100));

        // Acquire
        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);

        // Check wait time
        let wait = limiter.wait_time().await;
        assert!(wait.as_millis() > 0);
        assert!(wait.as_millis() <= 100);

        sleep(wait).await;

        // Should reset
        assert!(limiter.try_acquire().await);
    }

    // ── FixedWindow: remaining ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn fixed_window_remaining_starts_at_limit() {
        let limiter = FixedWindow::new(10, Duration::from_secs(60));
        assert_eq!(limiter.remaining(), 10);
    }

    #[fcp_async_core::runtime::test]
    async fn fixed_window_remaining_decreases_on_acquire() {
        let limiter = FixedWindow::new(5, Duration::from_secs(60));
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 4);
        limiter.try_acquire().await;
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn fixed_window_remaining_resets_after_window() {
        let limiter = FixedWindow::new(2, Duration::from_millis(50));
        limiter.try_acquire().await;
        limiter.try_acquire().await;
        assert_eq!(limiter.remaining(), 0);

        sleep(Duration::from_millis(60)).await;
        assert_eq!(limiter.remaining(), 2);
    }

    // ── FixedWindow: state ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn fixed_window_state_empty() {
        let limiter = FixedWindow::new(5, Duration::from_secs(1));
        let state = limiter.state();
        assert_eq!(state.limit, 5);
        assert_eq!(state.remaining, 5);
        assert!(!state.is_limited);
    }

    #[fcp_async_core::runtime::test]
    async fn fixed_window_state_full() {
        let limiter = FixedWindow::new(2, Duration::from_secs(60));
        limiter.try_acquire().await;
        limiter.try_acquire().await;

        let state = limiter.state();
        assert_eq!(state.limit, 2);
        assert_eq!(state.remaining, 0);
        assert!(state.is_limited);
        assert!(state.reset_after > Duration::ZERO);
    }

    // ── FixedWindow: reset ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn fixed_window_manual_reset() {
        let limiter = FixedWindow::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            limiter.try_acquire().await;
        }
        assert!(!limiter.try_acquire().await);

        limiter.reset().await;
        assert_eq!(limiter.remaining(), 3);
        assert!(limiter.try_acquire().await);
    }

    // ── FixedWindow: acquire ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn fixed_window_acquire_immediate_when_available() {
        let limiter = FixedWindow::new(5, Duration::from_secs(1));
        let waited = limiter.acquire(Duration::from_secs(1)).await.unwrap();
        assert!(waited < Duration::from_millis(50));
    }

    #[fcp_async_core::runtime::test]
    async fn fixed_window_acquire_exceeds_max_wait() {
        let limiter = FixedWindow::new(1, Duration::from_secs(60));
        limiter.try_acquire().await;

        let result = limiter.acquire(Duration::from_millis(5)).await;
        assert!(result.is_err());
    }

    // ── FixedWindow: wait_time edge cases ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn fixed_window_wait_time_zero_when_available() {
        let limiter = FixedWindow::new(5, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::ZERO);
    }

    #[fcp_async_core::runtime::test]
    async fn fixed_window_wait_time_max_when_zero_limit() {
        let limiter = FixedWindow::new(0, Duration::from_secs(1));
        assert_eq!(limiter.wait_time().await, Duration::MAX);
    }

    // ── FixedWindow: try_acquire_n default ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn fixed_window_try_acquire_n_default() {
        let limiter = FixedWindow::new(5, Duration::from_secs(60));
        assert!(limiter.try_acquire_n(1).await);
        assert!(!limiter.try_acquire_n(2).await);
    }
}
