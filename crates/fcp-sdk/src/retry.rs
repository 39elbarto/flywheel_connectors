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

#[cfg(test)]
mod tests {
    use super::*;

    // ── RetryDecision ────────────────────────────────────────────────────

    #[test]
    fn retry_decision_immediate_is_retryable() {
        assert!(RetryDecision::Immediate.is_retryable());
    }

    #[test]
    fn retry_decision_backoff_is_retryable() {
        assert!(RetryDecision::Backoff.is_retryable());
    }

    #[test]
    fn retry_decision_after_is_retryable() {
        assert!(RetryDecision::After(Duration::from_secs(5)).is_retryable());
    }

    #[test]
    fn retry_decision_terminal_not_retryable() {
        assert!(!RetryDecision::Terminal.is_retryable());
    }

    #[test]
    fn retry_decision_retry_after_returns_duration_for_after() {
        let d = Duration::from_secs(10);
        assert_eq!(RetryDecision::After(d).retry_after(), Some(d));
    }

    #[test]
    fn retry_decision_retry_after_returns_none_for_others() {
        assert!(RetryDecision::Immediate.retry_after().is_none());
        assert!(RetryDecision::Backoff.retry_after().is_none());
        assert!(RetryDecision::Terminal.retry_after().is_none());
    }

    #[test]
    fn retry_decision_debug_and_clone() {
        let d = RetryDecision::Backoff;
        let cloned = d;
        assert_eq!(format!("{d:?}"), format!("{cloned:?}"));
    }

    #[test]
    fn retry_decision_eq() {
        assert_eq!(RetryDecision::Terminal, RetryDecision::Terminal);
        assert_ne!(RetryDecision::Immediate, RetryDecision::Terminal);
    }

    // ── RetryPolicy construction ─────────────────────────────────────────

    #[test]
    fn retry_policy_default() {
        let p = RetryPolicy::default();
        assert_eq!(p.base_backoff_ms, 1_000);
        assert_eq!(p.max_backoff_ms, 60_000);
        assert!(p.jitter_enabled);
        assert_eq!(p.max_attempts, Some(5));
    }

    #[test]
    fn retry_policy_new_equals_default() {
        let a = RetryPolicy::new();
        let b = RetryPolicy::default();
        assert_eq!(a.base_backoff_ms, b.base_backoff_ms);
        assert_eq!(a.max_backoff_ms, b.max_backoff_ms);
    }

    #[test]
    fn retry_policy_builder_chain() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(500)
            .with_max_backoff_ms(30_000)
            .with_jitter_enabled(false)
            .with_max_attempts(Some(3));
        assert_eq!(p.base_backoff_ms, 500);
        assert_eq!(p.max_backoff_ms, 30_000);
        assert!(!p.jitter_enabled);
        assert_eq!(p.max_attempts, Some(3));
    }

    #[test]
    fn retry_policy_unlimited_attempts() {
        let p = RetryPolicy::new().with_max_attempts(None);
        assert!(p.max_attempts.is_none());
    }

    #[test]
    fn retry_policy_debug_and_clone() {
        let p = RetryPolicy::new();
        let cloned = p.clone();
        let _ = format!("{p:?}");
        assert_eq!(cloned.base_backoff_ms, p.base_backoff_ms);
    }

    // ── compute_backoff_ms ───────────────────────────────────────────────

    #[test]
    fn compute_backoff_attempt_zero() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 1_000);
    }

    #[test]
    fn compute_backoff_exponential_growth() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(0), 1_000);
        assert_eq!(p.compute_backoff_ms(1), 2_000);
        assert_eq!(p.compute_backoff_ms(2), 4_000);
        assert_eq!(p.compute_backoff_ms(3), 8_000);
    }

    #[test]
    fn compute_backoff_capped_at_max() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_max_backoff_ms(10_000)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(10), 10_000);
        assert_eq!(p.compute_backoff_ms(20), 10_000);
    }

    #[test]
    fn compute_backoff_high_attempt_capped_at_30() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        // Attempt 31 should be same as 30 (capped exponent)
        let d30 = p.compute_backoff_ms(30);
        let d31 = p.compute_backoff_ms(31);
        assert_eq!(d30, d31);
    }

    #[test]
    fn compute_backoff_zero_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(0)
            .with_jitter_enabled(false);
        assert_eq!(p.compute_backoff_ms(5), 0);
    }

    // ── compute_backoff_with_jitter_ms ───────────────────────────────────

    #[test]
    fn jitter_disabled_returns_base() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        assert_eq!(
            p.compute_backoff_with_jitter_ms(0, 0.5),
            p.compute_backoff_ms(0)
        );
    }

    #[test]
    fn jitter_factor_zero_gives_half_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=0.0 → clamp(0,1)=0.0 → 0.0*0.5+0.5=0.5 → base*0.5
        let result = p.compute_backoff_with_jitter_ms(0, 0.0);
        assert_eq!(result, 500);
    }

    #[test]
    fn jitter_factor_one_gives_full_base() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=1.0 → clamp(0,1)=1.0 → 1.0*0.5+0.5=1.0 → base*1.0
        let result = p.compute_backoff_with_jitter_ms(0, 1.0);
        assert_eq!(result, 1_000);
    }

    #[test]
    fn jitter_factor_clamped_below_zero() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=-1.0 → clamp(0,1)=0.0 → same as factor=0.0
        let result = p.compute_backoff_with_jitter_ms(0, -1.0);
        assert_eq!(result, 500);
    }

    #[test]
    fn jitter_factor_clamped_above_one() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(true);
        // factor=5.0 → clamp(0,1)=1.0 → same as factor=1.0
        let result = p.compute_backoff_with_jitter_ms(0, 5.0);
        assert_eq!(result, 1_000);
    }

    // ── next_delay ───────────────────────────────────────────────────────

    #[test]
    fn next_delay_terminal_returns_none() {
        let p = RetryPolicy::new();
        assert!(p.next_delay(0, RetryDecision::Terminal, None).is_none());
    }

    #[test]
    fn next_delay_immediate_returns_zero() {
        let p = RetryPolicy::new();
        let delay = p.next_delay(0, RetryDecision::Immediate, None);
        assert_eq!(delay, Some(Duration::from_millis(0)));
    }

    #[test]
    fn next_delay_after_returns_explicit_duration() {
        let p = RetryPolicy::new();
        let d = Duration::from_secs(42);
        assert_eq!(p.next_delay(0, RetryDecision::After(d), None), Some(d));
    }

    #[test]
    fn next_delay_backoff_returns_computed_delay() {
        let p = RetryPolicy::new().with_jitter_enabled(false);
        let delay = p.next_delay(0, RetryDecision::Backoff, None);
        assert_eq!(delay, Some(Duration::from_secs(1)));
    }

    #[test]
    fn next_delay_exceeds_max_attempts_returns_none() {
        let p = RetryPolicy::new().with_max_attempts(Some(3));
        assert!(p.next_delay(3, RetryDecision::Backoff, None).is_none());
        assert!(p.next_delay(4, RetryDecision::Backoff, None).is_none());
    }

    #[test]
    fn next_delay_within_max_attempts_returns_some() {
        let p = RetryPolicy::new().with_max_attempts(Some(3));
        assert!(p.next_delay(2, RetryDecision::Backoff, None).is_some());
    }

    #[test]
    fn next_delay_unlimited_attempts_never_none_for_retryable() {
        let p = RetryPolicy::new()
            .with_max_attempts(None)
            .with_jitter_enabled(false);
        for attempt in [0, 10, 100, 1000] {
            assert!(p.next_delay(attempt, RetryDecision::Backoff, None).is_some());
        }
    }

    #[test]
    fn next_delay_retry_after_hint_overrides_when_larger() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(1_000)
            .with_jitter_enabled(false);
        let hint = Duration::from_secs(120);
        let delay = p.next_delay(0, RetryDecision::Backoff, Some(hint)).unwrap();
        assert_eq!(delay, hint);
    }

    #[test]
    fn next_delay_retry_after_hint_ignored_when_smaller() {
        let p = RetryPolicy::new()
            .with_base_backoff_ms(10_000)
            .with_jitter_enabled(false);
        let hint = Duration::from_millis(1);
        let delay = p.next_delay(0, RetryDecision::Backoff, Some(hint)).unwrap();
        // base_backoff of 10_000ms is larger than 1ms hint
        assert_eq!(delay, Duration::from_secs(10));
    }

    // ── decision_from_http_status ────────────────────────────────────────

    #[test]
    fn http_429_returns_after_with_default() {
        let d = decision_from_http_status(429, None);
        assert_eq!(d, RetryDecision::After(DEFAULT_RATE_LIMIT_RETRY_AFTER));
    }

    #[test]
    fn http_429_with_custom_retry_after() {
        let hint = Duration::from_secs(10);
        let d = decision_from_http_status(429, Some(hint));
        assert_eq!(d, RetryDecision::After(hint));
    }

    #[test]
    fn http_408_returns_backoff() {
        assert_eq!(
            decision_from_http_status(408, None),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn http_425_returns_backoff() {
        assert_eq!(
            decision_from_http_status(425, None),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn http_5xx_returns_backoff() {
        for status in [500, 502, 503, 504, 599] {
            assert_eq!(
                decision_from_http_status(status, None),
                RetryDecision::Backoff,
                "status {status} should be Backoff"
            );
        }
    }

    #[test]
    fn http_4xx_non_retryable_returns_terminal() {
        for status in [400, 401, 403, 404, 422] {
            assert_eq!(
                decision_from_http_status(status, None),
                RetryDecision::Terminal,
                "status {status} should be Terminal"
            );
        }
    }

    #[test]
    fn http_2xx_returns_terminal() {
        assert_eq!(
            decision_from_http_status(200, None),
            RetryDecision::Terminal
        );
    }

    // ── decision_from_error_message ──────────────────────────────────────

    #[test]
    fn error_message_rate_limit_returns_backoff() {
        assert_eq!(
            decision_from_error_message("rate limit exceeded"),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn error_message_timeout_returns_backoff() {
        assert_eq!(
            decision_from_error_message("connection timeout"),
            RetryDecision::Backoff
        );
    }

    #[test]
    fn error_message_parse_returns_terminal() {
        assert_eq!(
            decision_from_error_message("can't parse entities"),
            RetryDecision::Terminal
        );
    }

    #[test]
    fn error_message_unknown_returns_terminal() {
        assert_eq!(
            decision_from_error_message("something unexpected"),
            RetryDecision::Terminal
        );
    }

    // ── map_external_error ───────────────────────────────────────────────

    #[test]
    fn map_external_error_429_produces_rate_limited() {
        let (decision, error) = map_external_error("api", Some(429), "Too Many Requests", None);
        assert_eq!(decision, RetryDecision::After(DEFAULT_RATE_LIMIT_RETRY_AFTER));
        assert!(matches!(error, FcpError::RateLimited { .. }));
    }

    #[test]
    fn map_external_error_503_produces_external_retryable() {
        let (decision, error) =
            map_external_error("api", Some(503), "Service Unavailable", None);
        assert_eq!(decision, RetryDecision::Backoff);
        match error {
            FcpError::External { retryable, .. } => assert!(retryable),
            other => panic!("expected FcpError::External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_400_produces_external_non_retryable() {
        let (decision, error) = map_external_error("api", Some(400), "Bad Request", None);
        assert_eq!(decision, RetryDecision::Terminal);
        match error {
            FcpError::External { retryable, .. } => assert!(!retryable),
            other => panic!("expected FcpError::External, got {other:?}"),
        }
    }

    #[test]
    fn map_external_error_no_status_uses_message() {
        let (decision, _error) =
            map_external_error("api", None, "connection timeout", None);
        assert_eq!(decision, RetryDecision::Backoff);
    }

    #[test]
    fn map_external_error_no_status_terminal_message() {
        let (decision, _error) =
            map_external_error("api", None, "invalid token format", None);
        assert_eq!(decision, RetryDecision::Terminal);
    }

    #[test]
    fn map_external_error_429_with_custom_retry_after() {
        let hint = Duration::from_secs(60);
        let (_decision, error) =
            map_external_error("api", Some(429), "rate limited", Some(hint));
        match error {
            FcpError::RateLimited {
                retry_after_ms, ..
            } => assert_eq!(retry_after_ms, 60_000),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    // ── duration_to_ms ───────────────────────────────────────────────────

    #[test]
    fn duration_to_ms_basic() {
        assert_eq!(duration_to_ms(Duration::from_secs(1)), 1_000);
        assert_eq!(duration_to_ms(Duration::from_millis(500)), 500);
        assert_eq!(duration_to_ms(Duration::ZERO), 0);
    }

    #[test]
    fn duration_to_ms_large_value() {
        let d = Duration::from_secs(u64::MAX);
        // Should not panic, returns u64::MAX
        assert_eq!(duration_to_ms(d), u64::MAX);
    }

    // ── DEFAULT_RATE_LIMIT_RETRY_AFTER ───────────────────────────────────

    #[test]
    fn default_retry_after_is_30s() {
        assert_eq!(DEFAULT_RATE_LIMIT_RETRY_AFTER, Duration::from_secs(30));
    }
}
