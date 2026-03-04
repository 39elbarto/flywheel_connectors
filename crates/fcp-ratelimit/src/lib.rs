//! FCP Rate Limit - Production-grade rate limiting for FCP connectors
//!
//! This crate provides comprehensive rate limiting infrastructure:
//!
//! - **Algorithms**: Token bucket, sliding window, leaky bucket
//! - **Header Parsing**: Standard and provider-specific rate limit headers
//! - **Backoff Strategies**: Exponential, jittered, and custom backoff
//! - **Async-First**: Thread-safe, async implementations
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_ratelimit::{RateLimiter, TokenBucket, RateLimitConfig};
//!
//! // Create a token bucket rate limiter (100 requests per minute)
//! let limiter = TokenBucket::new(100, std::time::Duration::from_secs(60));
//!
//! // Check if we can make a request
//! if limiter.try_acquire().await {
//!     // Make request
//! } else {
//!     // Wait or handle rate limit
//!     let wait_time = limiter.wait_time().await;
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod backoff;
mod fcp;
mod headers;
mod leaky_bucket;
mod sliding_window;
mod token_bucket;

pub use backoff::*;
pub use fcp::*;
pub use headers::*;
pub use leaky_bucket::*;
pub use sliding_window::*;
pub use token_bucket::*;

use std::time::Duration;

use async_trait::async_trait;

/// Common trait for rate limiters.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Try to acquire a permit without blocking.
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    async fn try_acquire(&self) -> bool;

    /// Try to acquire multiple permits atomically.
    ///
    /// The default implementation is conservative: it only supports `permits == 1`. Limiters
    /// that support quota/token-style accounting (e.g. token buckets) SHOULD override this.
    async fn try_acquire_n(&self, permits: u32) -> bool {
        if permits == 1 {
            self.try_acquire().await
        } else {
            false
        }
    }

    /// Acquire a permit, waiting if necessary.
    ///
    /// Returns the time waited, or an error if the wait would exceed `max_wait`.
    async fn acquire(&self, max_wait: Duration) -> Result<Duration, RateLimitError>;

    /// Get the current remaining quota.
    fn remaining(&self) -> u32;

    /// Get the time until the next permit is available.
    async fn wait_time(&self) -> Duration;

    /// Reset the rate limiter state.
    async fn reset(&self);

    /// Get the current state as a snapshot.
    fn state(&self) -> RateLimitState;
}

/// Rate limiter state snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RateLimitState {
    /// Maximum requests allowed in the window.
    pub limit: u32,

    /// Remaining requests in the current window.
    pub remaining: u32,

    /// Time until the window resets.
    pub reset_after: Duration,

    /// Whether currently rate limited.
    pub is_limited: bool,
}

/// Rate limit error.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    /// Request would exceed rate limit.
    #[error("Rate limit exceeded, retry after {retry_after:?}")]
    Exceeded {
        /// Time to wait before retrying.
        retry_after: Duration,
    },

    /// Wait time would exceed maximum allowed.
    #[error("Wait time {wait_time:?} exceeds maximum {max_wait:?}")]
    WaitExceeded {
        /// Required wait time.
        wait_time: Duration,
        /// Maximum allowed wait.
        max_wait: Duration,
    },

    /// Invalid configuration.
    #[error("Invalid rate limit configuration: {0}")]
    InvalidConfig(String),
}

/// Configuration for rate limiters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per window.
    pub requests_per_window: u32,

    /// Window duration.
    pub window: Duration,

    /// Allow burst above limit (for token bucket).
    #[serde(default)]
    pub burst_size: Option<u32>,

    /// Enable request queueing.
    #[serde(default)]
    pub enable_queue: bool,

    /// Maximum queue size.
    #[serde(default)]
    pub max_queue_size: Option<usize>,
}

impl RateLimitConfig {
    /// Create a new rate limit configuration.
    #[must_use]
    pub const fn new(requests_per_window: u32, window: Duration) -> Self {
        Self {
            requests_per_window,
            window,
            burst_size: None,
            enable_queue: false,
            max_queue_size: None,
        }
    }

    /// Set burst size.
    #[must_use]
    pub const fn with_burst(mut self, burst: u32) -> Self {
        self.burst_size = Some(burst);
        self
    }

    /// Enable request queueing.
    #[must_use]
    pub const fn with_queue(mut self, max_size: usize) -> Self {
        self.enable_queue = true;
        self.max_queue_size = Some(max_size);
        self
    }

    /// Common preset: 1 request per second.
    #[must_use]
    pub const fn one_per_second() -> Self {
        Self::new(1, Duration::from_secs(1))
    }

    /// Common preset: 10 requests per second.
    #[must_use]
    pub const fn ten_per_second() -> Self {
        Self::new(10, Duration::from_secs(1))
    }

    /// Common preset: 60 requests per minute.
    #[must_use]
    pub const fn sixty_per_minute() -> Self {
        Self::new(60, Duration::from_secs(60))
    }

    /// Common preset: 1000 requests per minute.
    #[must_use]
    pub const fn thousand_per_minute() -> Self {
        Self::new(1000, Duration::from_secs(60))
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::sixty_per_minute()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- RateLimitConfig ----

    #[test]
    fn config_new() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60));
        assert_eq!(config.requests_per_window, 100);
        assert_eq!(config.window, Duration::from_secs(60));
        assert!(config.burst_size.is_none());
        assert!(!config.enable_queue);
        assert!(config.max_queue_size.is_none());
    }

    #[test]
    fn config_default_is_sixty_per_minute() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_window, 60);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    #[test]
    fn config_with_burst() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_burst(200);
        assert_eq!(config.burst_size, Some(200));
        assert_eq!(config.requests_per_window, 100);
    }

    #[test]
    fn config_with_queue() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_queue(50);
        assert!(config.enable_queue);
        assert_eq!(config.max_queue_size, Some(50));
    }

    #[test]
    fn config_one_per_second() {
        let config = RateLimitConfig::one_per_second();
        assert_eq!(config.requests_per_window, 1);
        assert_eq!(config.window, Duration::from_secs(1));
    }

    #[test]
    fn config_ten_per_second() {
        let config = RateLimitConfig::ten_per_second();
        assert_eq!(config.requests_per_window, 10);
        assert_eq!(config.window, Duration::from_secs(1));
    }

    #[test]
    fn config_sixty_per_minute() {
        let config = RateLimitConfig::sixty_per_minute();
        assert_eq!(config.requests_per_window, 60);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    #[test]
    fn config_thousand_per_minute() {
        let config = RateLimitConfig::thousand_per_minute();
        assert_eq!(config.requests_per_window, 1000);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    #[test]
    fn config_chaining() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60))
            .with_burst(200)
            .with_queue(50);
        assert_eq!(config.requests_per_window, 100);
        assert_eq!(config.burst_size, Some(200));
        assert!(config.enable_queue);
        assert_eq!(config.max_queue_size, Some(50));
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_burst(200);
        let json = serde_json::to_string(&config).unwrap();
        let back: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.requests_per_window, 100);
        assert_eq!(back.burst_size, Some(200));
    }

    #[test]
    fn config_serde_defaults_for_optional_fields() {
        let json = r#"{"requests_per_window":50,"window":{"secs":30,"nanos":0}}"#;
        let config: RateLimitConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.requests_per_window, 50);
        assert!(config.burst_size.is_none());
        assert!(!config.enable_queue);
        assert!(config.max_queue_size.is_none());
    }

    #[test]
    fn config_debug() {
        let config = RateLimitConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("requests_per_window"));
    }

    #[test]
    fn config_clone() {
        let config = RateLimitConfig::new(100, Duration::from_secs(60)).with_burst(200);
        let cloned = config.clone();
        assert_eq!(cloned.requests_per_window, config.requests_per_window);
        assert_eq!(cloned.burst_size, config.burst_size);
    }

    // ---- RateLimitState ----

    #[test]
    fn state_serialize() {
        let state = RateLimitState {
            limit: 100,
            remaining: 50,
            reset_after: Duration::from_secs(30),
            is_limited: false,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"limit\":100"));
        assert!(json.contains("\"remaining\":50"));
    }

    #[test]
    fn state_debug() {
        let state = RateLimitState {
            limit: 10,
            remaining: 5,
            reset_after: Duration::from_secs(1),
            is_limited: false,
        };
        let dbg = format!("{state:?}");
        assert!(dbg.contains("limit"));
        assert!(dbg.contains("remaining"));
    }

    #[test]
    fn state_clone() {
        let state = RateLimitState {
            limit: 10,
            remaining: 3,
            reset_after: Duration::from_millis(500),
            is_limited: true,
        };
        let cloned = state.clone();
        assert_eq!(cloned.limit, 10);
        assert_eq!(cloned.remaining, 3);
        assert!(cloned.is_limited);
    }

    // ---- RateLimitError ----

    #[test]
    fn error_exceeded_display() {
        let err = RateLimitError::Exceeded {
            retry_after: Duration::from_secs(5),
        };
        let s = err.to_string();
        assert!(s.contains("Rate limit exceeded"));
        assert!(s.contains("5s"));
    }

    #[test]
    fn error_wait_exceeded_display() {
        let err = RateLimitError::WaitExceeded {
            wait_time: Duration::from_secs(10),
            max_wait: Duration::from_secs(5),
        };
        let s = err.to_string();
        assert!(s.contains("exceeds maximum"));
    }

    #[test]
    fn error_invalid_config_display() {
        let err = RateLimitError::InvalidConfig("bad value".into());
        assert!(err.to_string().contains("bad value"));
    }

    #[test]
    fn error_debug() {
        let err = RateLimitError::Exceeded {
            retry_after: Duration::from_secs(1),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Exceeded"));
    }
}
