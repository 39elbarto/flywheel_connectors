//! Retry taxonomy helpers for connector SDKs.
//!
//! Provides a small, deterministic policy for translating retry decisions into
//! concrete delays (including Retry-After hints).
//!
//! # Example
//!
//! ```ignore
//! use fcp_sdk::retry::{map_external_error, RetryPolicy};
//!
//! let attempt = 0;
//! let (decision, _err) = map_external_error(
//!     "example-service",
//!     Some(503),
//!     "Service Unavailable",
//!     None,
//! );
//!
//! let policy = RetryPolicy::new().with_jitter_enabled(false);
//! if let Some(delay) = policy.next_delay(attempt, decision, None) {
//!     // sleep for delay, then retry
//! }
//! ```

use std::time::Duration;

use crate::FcpError;
use crate::formatting::{ErrorClass, classify_error_message};

/// High-level retry decision for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry immediately (no delay).
    Immediate,
    /// Retry with exponential backoff (policy-controlled).
    Backoff,
    /// Retry after an explicit delay.
    After(Duration),
    /// Do not retry.
    Terminal,
}

impl RetryDecision {
    /// Returns true if this decision permits a retry.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        !matches!(self, Self::Terminal)
    }

    /// Returns an explicit retry-after duration, if present.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        match self {
            Self::After(delay) => Some(delay),
            _ => None,
        }
    }
}

/// Policy for translating retry decisions into delays.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Base delay for exponential backoff (milliseconds).
    pub base_backoff_ms: u64,
    /// Maximum backoff delay (milliseconds).
    pub max_backoff_ms: u64,
    /// Whether to add deterministic jitter to backoff delays.
    pub jitter_enabled: bool,
    /// Maximum retry attempts (0-indexed). None means unlimited.
    pub max_attempts: Option<u32>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            jitter_enabled: true,
            max_attempts: Some(5),
        }
    }
}

impl RetryPolicy {
    /// Create a policy with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set base backoff delay.
    #[must_use]
    pub const fn with_base_backoff_ms(mut self, ms: u64) -> Self {
        self.base_backoff_ms = ms;
        self
    }

    /// Builder: set max backoff delay.
    #[must_use]
    pub const fn with_max_backoff_ms(mut self, ms: u64) -> Self {
        self.max_backoff_ms = ms;
        self
    }

    /// Builder: enable/disable jitter.
    #[must_use]
    pub const fn with_jitter_enabled(mut self, enabled: bool) -> Self {
        self.jitter_enabled = enabled;
        self
    }

    /// Builder: set maximum attempts (0-indexed). None means unlimited.
    #[must_use]
    pub const fn with_max_attempts(mut self, max_attempts: Option<u32>) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Compute backoff delay for a given attempt number (0-indexed).
    #[must_use]
    pub fn compute_backoff_ms(&self, attempt: u32) -> u64 {
        let exp = attempt.min(30);
        let delay = self.base_backoff_ms.saturating_mul(1u64 << exp);
        delay.min(self.max_backoff_ms)
    }

    /// Compute backoff delay with deterministic jitter.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn compute_backoff_with_jitter_ms(&self, attempt: u32, jitter_factor: f64) -> u64 {
        let base = self.compute_backoff_ms(attempt);
        if !self.jitter_enabled {
            return base;
        }

        let factor = jitter_factor.clamp(0.0, 1.0).mul_add(0.5, 0.5);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let jittered = (base as f64 * factor) as u64;
        jittered
    }

    /// Translate a retry decision into a delay, applying Retry-After hints.
    ///
    /// Returns `None` when retry is not permitted (terminal or attempt limit).
    #[must_use]
    pub fn next_delay(
        &self,
        attempt: u32,
        decision: RetryDecision,
        retry_after_hint: Option<Duration>,
    ) -> Option<Duration> {
        if let Some(max_attempts) = self.max_attempts {
            if attempt >= max_attempts {
                return None;
            }
        }

        match decision {
            RetryDecision::Terminal => None,
            RetryDecision::Immediate => Some(Duration::from_millis(0)),
            RetryDecision::After(delay) => Some(delay),
            RetryDecision::Backoff => {
                let jitter = (f64::from(attempt) * 0.1).fract();
                let mut delay_ms = self.compute_backoff_with_jitter_ms(attempt, jitter);

                if let Some(hint) = retry_after_hint {
                    let hint_ms = duration_to_ms(hint);
                    if hint_ms > delay_ms {
                        delay_ms = hint_ms;
                    }
                }

                Some(Duration::from_millis(delay_ms))
            }
        }
    }
}

/// Default retry-after for rate limiting when no hint is provided (30s).
pub const DEFAULT_RATE_LIMIT_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Classify an HTTP status code into a retry decision.
#[must_use]
pub fn decision_from_http_status(status: u16, retry_after: Option<Duration>) -> RetryDecision {
    match status {
        429 => RetryDecision::After(retry_after.unwrap_or(DEFAULT_RATE_LIMIT_RETRY_AFTER)),
        408 | 425 | 500..=599 => RetryDecision::Backoff,
        _ => RetryDecision::Terminal,
    }
}

/// Classify a free-form error message into a retry decision.
#[must_use]
pub fn decision_from_error_message(message: &str) -> RetryDecision {
    match classify_error_message(message) {
        ErrorClass::RateLimit | ErrorClass::Transient => RetryDecision::Backoff,
        ErrorClass::ParseError | ErrorClass::Terminal => RetryDecision::Terminal,
    }
}

/// Map an external error into a retry decision and standardized FCP error.
#[must_use]
pub fn map_external_error(
    service: impl Into<String>,
    status_code: Option<u16>,
    message: impl Into<String>,
    retry_after: Option<Duration>,
) -> (RetryDecision, FcpError) {
    let service = service.into();
    let message = message.into();
    let decision = status_code.map_or_else(
        || decision_from_error_message(&message),
        |code| decision_from_http_status(code, retry_after),
    );

    let fcp_error = match status_code {
        Some(429) => FcpError::RateLimited {
            retry_after_ms: duration_to_ms(retry_after.unwrap_or(DEFAULT_RATE_LIMIT_RETRY_AFTER)),
            violation: None,
        },
        _ => FcpError::External {
            service,
            message,
            status_code,
            retryable: decision.is_retryable(),
            retry_after: retry_after.or_else(|| decision.retry_after()),
        },
    };

    (decision, fcp_error)
}

fn duration_to_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
