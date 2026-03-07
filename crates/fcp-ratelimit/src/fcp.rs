//! FCP-specific glue for rate limiting.
//!
//! This module bridges `fcp-core` rate limit declarations (`fcp_core::RateLimit`) with the
//! enforcement algorithms in this crate and produces platform-facing artifacts like
//! `ThrottleViolation` and `BackpressureSignal`.

#![forbid(unsafe_code)]

use std::time::Duration;

use crate::{RateLimitConfig, RateLimitError, RateLimitState, RateLimiter};
use fcp_async_core::sync::{OwnedSemaphorePermit, Semaphore};
use std::sync::Arc;

/// Backpressure thresholds expressed in basis points (bps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureThresholds {
    pub warning_bps: u16,
    pub soft_limit_bps: u16,
    pub hard_limit_bps: u16,
}

impl BackpressureThresholds {
    /// Default thresholds:
    /// - warning: 80%
    /// - soft limit: 95%
    /// - hard limit: 100%
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            warning_bps: 8_000,
            soft_limit_bps: 9_500,
            hard_limit_bps: 10_000,
        }
    }
}

impl Default for BackpressureThresholds {
    fn default() -> Self {
        Self::standard()
    }
}

/// Token/quota cost breakdown for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCost {
    pub base_tokens: u32,
    pub bytes_tokens: u32,
    pub compute_tokens: u32,
}

impl TokenCost {
    #[must_use]
    pub const fn total(self) -> u32 {
        self.base_tokens + self.bytes_tokens + self.compute_tokens
    }
}

/// Compute a token cost from base + payload bytes + compute tokens.
///
/// `bytes_per_token` is a ceiling division unit; e.g. `bytes=1001` with `bytes_per_token=1000`
/// results in `bytes_tokens=2`.
///
/// # Errors
/// Returns an error if `bytes_per_token == 0` or arithmetic overflows.
pub fn compute_token_cost(
    base_tokens: u32,
    bytes: u64,
    bytes_per_token: u64,
    compute_tokens: u32,
) -> Result<TokenCost, RateLimitError> {
    if bytes_per_token == 0 {
        return Err(RateLimitError::InvalidConfig(
            "bytes_per_token must be > 0".into(),
        ));
    }

    let bytes_tokens_u64 = if bytes == 0 {
        0
    } else {
        let div = bytes / bytes_per_token;
        let rem = bytes % bytes_per_token;
        div + u64::from(rem != 0)
    };
    let bytes_tokens = u32::try_from(bytes_tokens_u64)
        .map_err(|_| RateLimitError::InvalidConfig("bytes too large".into()))?;

    let _total = base_tokens
        .checked_add(bytes_tokens)
        .and_then(|v| v.checked_add(compute_tokens))
        .ok_or_else(|| RateLimitError::InvalidConfig("token cost overflow".into()))?;

    Ok(TokenCost {
        base_tokens,
        bytes_tokens,
        compute_tokens,
    })
}

/// Context used to annotate a rate limit decision.
#[derive(Debug, Clone)]
pub struct ThrottleContext {
    pub zone_id: fcp_core::ZoneId,
    pub connector_id: Option<fcp_core::ConnectorId>,
    pub operation_id: Option<fcp_core::OperationId>,
    pub limit_type: fcp_core::LimitType,
}

/// Result of a rate limit enforcement check.
#[derive(Debug, Clone)]
pub struct EnforcementOutcome {
    pub allowed: bool,
    pub state: RateLimitState,
    pub backpressure: fcp_core::BackpressureSignal,
    pub violation: Option<fcp_core::ThrottleViolation>,
}

impl EnforcementOutcome {
    #[must_use]
    pub fn as_rate_limited_error(&self) -> Option<fcp_core::FcpError> {
        if self.allowed {
            return None;
        }

        let retry_after_ms = self
            .backpressure
            .retry_after_ms
            .or_else(|| self.violation.as_ref().map(|v| v.retry_after_ms))
            .unwrap_or(0);

        Some(fcp_core::FcpError::RateLimited {
            retry_after_ms,
            violation: self.violation.clone().map(Box::new),
        })
    }
}

/// Concurrency limiter for "max in-flight operations" style constraints.
#[derive(Debug, Clone)]
pub struct ConcurrencyLimiter {
    semaphore: Arc<Semaphore>,
    max: u32,
}

impl ConcurrencyLimiter {
    /// Create a new limiter.
    ///
    /// # Errors
    /// Returns an error if `max_concurrent == 0` or exceeds platform limits.
    pub fn new(max_concurrent: u32) -> Result<Self, RateLimitError> {
        if max_concurrent == 0 {
            return Err(RateLimitError::InvalidConfig(
                "max_concurrent must be > 0".into(),
            ));
        }
        let permits = usize::try_from(max_concurrent)
            .map_err(|_| RateLimitError::InvalidConfig("max_concurrent exceeds usize".into()))?;
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            max: max_concurrent,
        })
    }

    #[must_use]
    pub const fn max_concurrent(&self) -> u32 {
        self.max
    }

    #[must_use]
    pub fn in_flight(&self) -> u32 {
        let available = u32::try_from(self.semaphore.available_permits()).unwrap_or(0);
        self.max.saturating_sub(available)
    }

    #[must_use]
    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.semaphore).try_acquire_owned().ok()
    }

    /// Try to acquire a permit or return a throttle violation.
    ///
    /// # Errors
    ///
    /// Returns `FcpError::RateLimited` if the request is throttled.
    pub fn try_acquire_or_violation(
        &self,
        ctx: &ThrottleContext,
    ) -> Result<OwnedSemaphorePermit, fcp_core::FcpError> {
        self.try_acquire().ok_or_else(|| {
            let timestamp_ms = now_timestamp_ms();
            let in_flight = self.in_flight().saturating_add(1);
            let violation = fcp_core::ThrottleViolation::new(fcp_core::ThrottleViolationInput {
                timestamp_ms,
                zone_id: ctx.zone_id.clone(),
                connector_id: ctx.connector_id.clone(),
                operation_id: ctx.operation_id.clone(),
                limit_type: ctx.limit_type,
                limit_value: self.max,
                current_value: in_flight,
                retry_after_ms: 0,
            });

            fcp_core::FcpError::RateLimited {
                retry_after_ms: 0,
                violation: Some(Box::new(violation)),
            }
        })
    }
}

/// Convert a structured `fcp_core::RateLimit` into a concrete algorithm configuration.
///
/// Semantics:
/// - `max` → requests per window
/// - `per_ms` → window duration
/// - `burst` (if present) is interpreted as *additional* burst allowance above `max`.
///
/// # Errors
/// Returns an error if `max == 0`, `per_ms == 0`, or burst math overflows.
pub fn config_from_core(rate: &fcp_core::RateLimit) -> Result<RateLimitConfig, RateLimitError> {
    if rate.max == 0 {
        return Err(RateLimitError::InvalidConfig(
            "RateLimit.max must be > 0".into(),
        ));
    }
    if rate.per_ms == 0 {
        return Err(RateLimitError::InvalidConfig(
            "RateLimit.per_ms must be > 0".into(),
        ));
    }

    let window = Duration::from_millis(rate.per_ms);
    let mut cfg = RateLimitConfig::new(rate.max, window);

    if let Some(burst) = rate.burst {
        let capacity = rate
            .max
            .checked_add(burst)
            .ok_or_else(|| RateLimitError::InvalidConfig("burst overflow".into()))?;
        cfg = cfg.with_burst(capacity);
    }

    Ok(cfg)
}

/// Enforce a limiter, producing `BackpressureSignal` and (when rejected) `ThrottleViolation`.
pub async fn enforce(
    limiter: &dyn RateLimiter,
    permits: u32,
    ctx: &ThrottleContext,
    thresholds: BackpressureThresholds,
) -> EnforcementOutcome {
    let timestamp_ms = now_timestamp_ms();

    // Attempt to acquire permits; if the limiter does not support multi-permit acquisition,
    // it will conservatively deny.
    let allowed = limiter.try_acquire_n(permits).await;
    let state = limiter.state();
    let backpressure = backpressure_from_state(&state, thresholds);

    let violation = if allowed {
        None
    } else {
        let retry_after_ms = backpressure.retry_after_ms.unwrap_or(0);
        let current_value = state
            .limit
            .saturating_sub(state.remaining)
            .saturating_add(permits);

        Some(fcp_core::ThrottleViolation::new(
            fcp_core::ThrottleViolationInput {
                timestamp_ms,
                zone_id: ctx.zone_id.clone(),
                connector_id: ctx.connector_id.clone(),
                operation_id: ctx.operation_id.clone(),
                limit_type: ctx.limit_type,
                limit_value: state.limit,
                current_value,
                retry_after_ms,
            },
        ))
    };

    EnforcementOutcome {
        allowed,
        state,
        backpressure,
        violation,
    }
}

fn now_timestamp_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn backpressure_from_state(
    state: &RateLimitState,
    thresholds: BackpressureThresholds,
) -> fcp_core::BackpressureSignal {
    let utilization_bps = utilization_bps(state.limit, state.remaining);
    // Calculate backpressure level
    let level = if utilization_bps >= thresholds.hard_limit_bps || state.is_limited {
        fcp_core::BackpressureLevel::HardLimit
    } else if utilization_bps >= thresholds.soft_limit_bps {
        fcp_core::BackpressureLevel::SoftLimit
    } else if utilization_bps >= thresholds.warning_bps {
        fcp_core::BackpressureLevel::Warning
    } else {
        fcp_core::BackpressureLevel::Normal
    };

    let retry_after_ms = match level {
        fcp_core::BackpressureLevel::SoftLimit | fcp_core::BackpressureLevel::HardLimit => {
            Some(u64::try_from(state.reset_after.as_millis()).unwrap_or(u64::MAX))
        }
        fcp_core::BackpressureLevel::Normal | fcp_core::BackpressureLevel::Warning => None,
    };

    fcp_core::BackpressureSignal {
        level,
        utilization_bps,
        retry_after_ms,
    }
}

fn utilization_bps(limit: u32, remaining: u32) -> u16 {
    if limit == 0 {
        return 0;
    }
    let used = limit.saturating_sub(remaining);
    let bps = (u64::from(used) * 10_000_u64) / u64::from(limit);
    u16::try_from(bps).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenBucket;

    #[test]
    fn token_cost_ceil_div_bytes() {
        let cost = compute_token_cost(1, 1001, 1000, 0).unwrap();
        assert_eq!(
            cost,
            TokenCost {
                base_tokens: 1,
                bytes_tokens: 2,
                compute_tokens: 0
            }
        );
        assert_eq!(cost.total(), 3);
    }

    #[test]
    fn token_cost_rejects_zero_bytes_per_token() {
        let err = compute_token_cost(1, 10, 0, 0).unwrap_err();
        assert!(err.to_string().contains("bytes_per_token"));
    }

    #[fcp_async_core::runtime::test]
    async fn config_from_core_maps_burst_as_additional_capacity() {
        let core = fcp_core::RateLimit {
            max: 100,
            per_ms: 60_000,
            burst: Some(10),
            scope: None,
            pool_name: None,
        };

        let cfg = config_from_core(&core).unwrap();
        assert_eq!(cfg.requests_per_window, 100);
        assert_eq!(cfg.window, Duration::from_secs(60));
        assert_eq!(cfg.burst_size, Some(110));
    }

    #[test]
    fn config_from_core_rejects_zero_limits() {
        let core = fcp_core::RateLimit {
            max: 0,
            per_ms: 60_000,
            burst: None,
            scope: None,
            pool_name: None,
        };
        let err = config_from_core(&core).unwrap_err();
        assert!(err.to_string().contains("max must be > 0"));

        let core = fcp_core::RateLimit {
            max: 10,
            per_ms: 0,
            burst: None,
            scope: None,
            pool_name: None,
        };
        let err = config_from_core(&core).unwrap_err();
        assert!(err.to_string().contains("per_ms must be > 0"));
    }

    #[test]
    fn config_from_core_rejects_burst_overflow() {
        let core = fcp_core::RateLimit {
            max: u32::MAX,
            per_ms: 60_000,
            burst: Some(1),
            scope: None,
            pool_name: None,
        };
        let err = config_from_core(&core).unwrap_err();
        assert!(err.to_string().contains("burst overflow"));
    }

    #[fcp_async_core::runtime::test]
    async fn enforce_emits_soft_backpressure_without_rejecting() {
        // Create a limiter with small capacity so we can push utilization > 95% without full
        // rejection.
        let limiter = TokenBucket::new(20, Duration::from_secs(60));
        // Leave headroom for the `enforce()` call to consume one more token without exhausting.
        for _ in 0..18 {
            assert!(limiter.try_acquire().await);
        }

        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("fcp.test:request_response:0.0.1".parse().unwrap()),
            operation_id: Some("test.op".parse().unwrap()),
            limit_type: fcp_core::LimitType::Rpm,
        };

        let out = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
        assert!(out.allowed);
        assert!(matches!(
            out.backpressure.level,
            fcp_core::BackpressureLevel::SoftLimit
        ));
        assert!(out.backpressure.retry_after_ms.is_some());
        assert!(out.violation.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn enforce_rejects_and_emits_throttle_violation_at_hard_limit() {
        let limiter = TokenBucket::new(2, Duration::from_secs(60));
        assert!(limiter.try_acquire().await);
        assert!(limiter.try_acquire().await);

        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: fcp_core::LimitType::Rpm,
        };

        let out = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
        assert!(!out.allowed);
        assert!(matches!(
            out.backpressure.level,
            fcp_core::BackpressureLevel::HardLimit
        ));
        assert!(out.violation.is_some());

        let err = out.as_rate_limited_error().unwrap();
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-3002");
        assert!(resp.details.is_some());
        assert!(resp.details.unwrap().get("throttle_violation").is_some());
    }

    #[test]
    fn backpressure_threshold_boundaries() {
        let thresholds = BackpressureThresholds::standard();

        let state_warning = RateLimitState {
            limit: 10_000,
            remaining: 2_000,
            reset_after: Duration::from_secs(10),
            is_limited: false,
        };
        let signal = backpressure_from_state(&state_warning, thresholds);
        assert_eq!(signal.utilization_bps, 8_000);
        assert_eq!(signal.level, fcp_core::BackpressureLevel::Warning);

        let state_soft = RateLimitState {
            limit: 10_000,
            remaining: 500,
            reset_after: Duration::from_secs(10),
            is_limited: false,
        };
        let signal = backpressure_from_state(&state_soft, thresholds);
        assert_eq!(signal.utilization_bps, 9_500);
        assert_eq!(signal.level, fcp_core::BackpressureLevel::SoftLimit);
        assert!(signal.retry_after_ms.is_some());

        let state_hard = RateLimitState {
            limit: 10_000,
            remaining: 0,
            reset_after: Duration::from_secs(10),
            is_limited: false,
        };
        let signal = backpressure_from_state(&state_hard, thresholds);
        assert_eq!(signal.utilization_bps, 10_000);
        assert_eq!(signal.level, fcp_core::BackpressureLevel::HardLimit);
        assert!(signal.retry_after_ms.is_some());
    }

    #[test]
    fn as_rate_limited_error_prefers_backpressure_retry_after() {
        let state = RateLimitState {
            limit: 100,
            remaining: 0,
            reset_after: Duration::from_millis(700),
            is_limited: true,
        };
        let backpressure = backpressure_from_state(&state, BackpressureThresholds::standard());

        let violation = fcp_core::ThrottleViolation::new(fcp_core::ThrottleViolationInput {
            timestamp_ms: 1_000,
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: fcp_core::LimitType::Rpm,
            limit_value: 100,
            current_value: 101,
            retry_after_ms: 10,
        });

        let out = EnforcementOutcome {
            allowed: false,
            state,
            backpressure,
            violation: Some(violation),
        };

        let err = out.as_rate_limited_error().unwrap();
        if let fcp_core::FcpError::RateLimited { retry_after_ms, .. } = err {
            assert_eq!(retry_after_ms, 700);
        } else {
            panic!("expected rate limited error");
        }
    }

    #[test]
    fn backpressure_levels_transition_and_clear() {
        let thresholds = BackpressureThresholds::standard();

        let state_normal = RateLimitState {
            limit: 100,
            remaining: 60,
            reset_after: Duration::from_secs(30),
            is_limited: false,
        };
        let signal = backpressure_from_state(&state_normal, thresholds);
        assert_eq!(signal.level, fcp_core::BackpressureLevel::Normal);
        assert!(signal.retry_after_ms.is_none());

        let state_warning = RateLimitState {
            limit: 100,
            remaining: 15,
            reset_after: Duration::from_secs(30),
            is_limited: false,
        };
        let signal = backpressure_from_state(&state_warning, thresholds);
        assert_eq!(signal.level, fcp_core::BackpressureLevel::Warning);

        let state_soft = RateLimitState {
            limit: 100,
            remaining: 5,
            reset_after: Duration::from_secs(30),
            is_limited: false,
        };
        let signal = backpressure_from_state(&state_soft, thresholds);
        assert_eq!(signal.level, fcp_core::BackpressureLevel::SoftLimit);
        assert!(signal.retry_after_ms.is_some());

        let state_hard = RateLimitState {
            limit: 100,
            remaining: 0,
            reset_after: Duration::from_secs(30),
            is_limited: true,
        };
        let signal = backpressure_from_state(&state_hard, thresholds);
        assert_eq!(signal.level, fcp_core::BackpressureLevel::HardLimit);
        assert!(signal.retry_after_ms.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn enforce_quota_violation_includes_retry_after() {
        let limiter = TokenBucket::new(1, Duration::from_millis(50));
        assert!(limiter.try_acquire().await);

        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("fcp.test:quota:0.1.0".parse().unwrap()),
            operation_id: Some("quota.op".parse().unwrap()),
            limit_type: fcp_core::LimitType::Quota,
        };

        let out = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
        assert!(!out.allowed);
        let violation = out.violation.expect("expected violation");
        assert_eq!(violation.limit_type, fcp_core::LimitType::Quota);
        assert!(violation.retry_after_ms > 0);
    }

    #[test]
    fn concurrency_limiter_emits_throttle_violation_when_exhausted() {
        let limiter = ConcurrencyLimiter::new(2).unwrap();
        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: fcp_core::LimitType::Concurrent,
        };

        let _p1 = limiter.try_acquire_or_violation(&ctx).unwrap();
        let _p2 = limiter.try_acquire_or_violation(&ctx).unwrap();
        let err = limiter.try_acquire_or_violation(&ctx).unwrap_err();

        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-3002");
        assert!(resp.details.is_some());
        let details = resp.details.unwrap();
        assert_eq!(details["throttle_violation"]["limit_type"], "concurrent");
    }

    // ── ConcurrencyLimiter extended tests ───────────────────────────────

    #[test]
    fn concurrency_limiter_zero_rejects() {
        let err = ConcurrencyLimiter::new(0).unwrap_err();
        assert!(err.to_string().contains("max_concurrent must be > 0"));
    }

    #[test]
    fn concurrency_limiter_max_concurrent() {
        let limiter = ConcurrencyLimiter::new(5).unwrap();
        assert_eq!(limiter.max_concurrent(), 5);
    }

    #[test]
    fn concurrency_limiter_in_flight_tracking() {
        let limiter = ConcurrencyLimiter::new(3).unwrap();
        assert_eq!(limiter.in_flight(), 0);

        let p1 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight(), 1);

        let p2 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight(), 2);

        drop(p1);
        assert_eq!(limiter.in_flight(), 1);

        drop(p2);
        assert_eq!(limiter.in_flight(), 0);
    }

    #[test]
    fn concurrency_limiter_try_acquire_returns_none_when_exhausted() {
        let limiter = ConcurrencyLimiter::new(1).unwrap();
        let _p1 = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
    }

    #[test]
    fn concurrency_limiter_permit_release_allows_new_acquire() {
        let limiter = ConcurrencyLimiter::new(1).unwrap();
        let p1 = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(p1);
        let _p2 = limiter.try_acquire().unwrap();
    }

    #[test]
    fn concurrency_limiter_clone() {
        let limiter = ConcurrencyLimiter::new(5).unwrap();
        let cloned = limiter.clone();
        assert_eq!(cloned.max_concurrent(), 5);
        // Cloned shares the same semaphore
        let _p = limiter.try_acquire().unwrap();
        assert_eq!(cloned.in_flight(), 1);
    }

    #[test]
    fn concurrency_limiter_debug() {
        let limiter = ConcurrencyLimiter::new(3).unwrap();
        let debug = format!("{limiter:?}");
        assert!(debug.contains("ConcurrencyLimiter"));
    }

    // ── TokenCost tests ─────────────────────────────────────────────────

    #[test]
    fn token_cost_total() {
        let cost = TokenCost {
            base_tokens: 1,
            bytes_tokens: 2,
            compute_tokens: 3,
        };
        assert_eq!(cost.total(), 6);
    }

    #[test]
    fn token_cost_all_zero() {
        let cost = TokenCost {
            base_tokens: 0,
            bytes_tokens: 0,
            compute_tokens: 0,
        };
        assert_eq!(cost.total(), 0);
    }

    #[test]
    fn token_cost_debug_clone_copy_eq() {
        let cost = TokenCost {
            base_tokens: 1,
            bytes_tokens: 2,
            compute_tokens: 3,
        };
        let cloned = cost;
        assert_eq!(cloned, cost);
        let debug = format!("{cost:?}");
        assert!(debug.contains("TokenCost"));
    }

    #[test]
    fn compute_token_cost_zero_bytes() {
        let cost = compute_token_cost(5, 0, 1000, 3).unwrap();
        assert_eq!(cost.base_tokens, 5);
        assert_eq!(cost.bytes_tokens, 0);
        assert_eq!(cost.compute_tokens, 3);
        assert_eq!(cost.total(), 8);
    }

    #[test]
    fn compute_token_cost_exact_multiple() {
        let cost = compute_token_cost(1, 3000, 1000, 0).unwrap();
        assert_eq!(cost.bytes_tokens, 3);
    }

    #[test]
    fn compute_token_cost_single_byte() {
        let cost = compute_token_cost(0, 1, 1000, 0).unwrap();
        assert_eq!(cost.bytes_tokens, 1); // ceiling division
    }

    #[test]
    fn compute_token_cost_overflow() {
        let err = compute_token_cost(u32::MAX, 0, 1, u32::MAX).unwrap_err();
        assert!(err.to_string().contains("overflow"));
    }

    #[test]
    fn compute_token_cost_very_large_bytes() {
        // Should work without panic
        let cost = compute_token_cost(0, u64::MAX, u64::MAX, 0).unwrap();
        assert_eq!(cost.bytes_tokens, 1);
    }

    // ── BackpressureThresholds tests ────────────────────────────────────

    #[test]
    fn backpressure_thresholds_standard() {
        let t = BackpressureThresholds::standard();
        assert_eq!(t.warning_bps, 8_000);
        assert_eq!(t.soft_limit_bps, 9_500);
        assert_eq!(t.hard_limit_bps, 10_000);
    }

    #[test]
    fn backpressure_thresholds_default() {
        let t = BackpressureThresholds::default();
        assert_eq!(t, BackpressureThresholds::standard());
    }

    #[test]
    fn backpressure_thresholds_debug_clone_copy_eq() {
        let t = BackpressureThresholds::standard();
        let cloned = t;
        assert_eq!(cloned, t);
        let debug = format!("{t:?}");
        assert!(debug.contains("BackpressureThresholds"));
    }

    #[test]
    fn backpressure_thresholds_custom() {
        let t = BackpressureThresholds {
            warning_bps: 5_000,
            soft_limit_bps: 7_500,
            hard_limit_bps: 9_000,
        };
        assert_eq!(t.warning_bps, 5_000);
        assert_eq!(t.soft_limit_bps, 7_500);
        assert_eq!(t.hard_limit_bps, 9_000);
    }

    // ── utilization_bps edge cases ──────────────────────────────────────

    #[test]
    fn utilization_bps_zero_limit() {
        assert_eq!(utilization_bps(0, 0), 0);
    }

    #[test]
    fn utilization_bps_full() {
        assert_eq!(utilization_bps(100, 0), 10_000);
    }

    #[test]
    fn utilization_bps_half() {
        assert_eq!(utilization_bps(100, 50), 5_000);
    }

    #[test]
    fn utilization_bps_none_used() {
        assert_eq!(utilization_bps(100, 100), 0);
    }

    #[test]
    fn utilization_bps_remaining_exceeds_limit() {
        // Should saturate to 0 used
        assert_eq!(utilization_bps(10, 20), 0);
    }

    // ── ThrottleContext tests ────────────────────────────────────────────

    #[test]
    fn throttle_context_debug_and_clone() {
        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: Some("fcp.test:request_response:0.0.1".parse().unwrap()),
            operation_id: Some("test.op".parse().unwrap()),
            limit_type: fcp_core::LimitType::Rpm,
        };
        let cloned = ctx.clone();
        assert_eq!(cloned.limit_type, fcp_core::LimitType::Rpm);
        let debug = format!("{ctx:?}");
        assert!(debug.contains("ThrottleContext"));
    }

    // ── EnforcementOutcome tests ────────────────────────────────────────

    #[test]
    fn enforcement_outcome_allowed_returns_no_error() {
        let out = EnforcementOutcome {
            allowed: true,
            state: RateLimitState {
                limit: 100,
                remaining: 50,
                reset_after: Duration::from_secs(30),
                is_limited: false,
            },
            backpressure: fcp_core::BackpressureSignal {
                level: fcp_core::BackpressureLevel::Normal,
                utilization_bps: 5_000,
                retry_after_ms: None,
            },
            violation: None,
        };
        assert!(out.as_rate_limited_error().is_none());
    }

    #[test]
    fn enforcement_outcome_debug_and_clone() {
        let out = EnforcementOutcome {
            allowed: false,
            state: RateLimitState {
                limit: 10,
                remaining: 0,
                reset_after: Duration::from_secs(5),
                is_limited: true,
            },
            backpressure: fcp_core::BackpressureSignal {
                level: fcp_core::BackpressureLevel::HardLimit,
                utilization_bps: 10_000,
                retry_after_ms: Some(5_000),
            },
            violation: None,
        };
        let cloned = out.clone();
        assert!(!cloned.allowed);
        let debug = format!("{out:?}");
        assert!(debug.contains("EnforcementOutcome"));
    }

    // ── enforce with normal backpressure ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn enforce_normal_backpressure_when_under_threshold() {
        let limiter = TokenBucket::new(100, Duration::from_secs(60));

        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: fcp_core::LimitType::Rpm,
        };

        let out = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
        assert!(out.allowed);
        assert!(matches!(
            out.backpressure.level,
            fcp_core::BackpressureLevel::Normal
        ));
        assert!(out.backpressure.retry_after_ms.is_none());
        assert!(out.violation.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn enforce_warning_backpressure() {
        // 100 capacity, use 82 → 82% utilization → Warning (>80%)
        let limiter = TokenBucket::new(100, Duration::from_secs(60));
        for _ in 0..81 {
            limiter.try_acquire().await;
        }

        let ctx = ThrottleContext {
            zone_id: "z:work".parse().unwrap(),
            connector_id: None,
            operation_id: None,
            limit_type: fcp_core::LimitType::Rpm,
        };

        let out = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
        assert!(out.allowed);
        assert!(matches!(
            out.backpressure.level,
            fcp_core::BackpressureLevel::Warning
        ));
    }

    // ── config_from_core extended ────────────────────────────────────────

    #[test]
    fn config_from_core_no_burst() {
        let core = fcp_core::RateLimit {
            max: 50,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: None,
        };
        let cfg = config_from_core(&core).unwrap();
        assert_eq!(cfg.requests_per_window, 50);
        assert_eq!(cfg.window, Duration::from_secs(1));
        assert!(cfg.burst_size.is_none());
    }

    #[test]
    fn config_from_core_preserves_scope_and_pool() {
        // scope and pool_name are on the core RateLimit but not mapped to config
        let core = fcp_core::RateLimit {
            max: 10,
            per_ms: 5000,
            burst: None,
            scope: Some("connector".to_string()),
            pool_name: Some("default".to_string()),
        };
        let cfg = config_from_core(&core).unwrap();
        assert_eq!(cfg.requests_per_window, 10);
    }

    // ── compute_token_cost edge cases ──────────────────────────────────

    #[test]
    fn compute_token_cost_one_byte_per_token() {
        let cost = compute_token_cost(0, 100, 1, 0).unwrap();
        assert_eq!(cost.bytes_tokens, 100);
    }

    #[test]
    fn compute_token_cost_bytes_larger_than_u32_max() {
        // bytes = u64::MAX / 2, bytes_per_token = 1 → bytes_tokens overflows u32
        let err = compute_token_cost(0, u64::MAX / 2, 1, 0).unwrap_err();
        assert!(err.to_string().contains("bytes too large"));
    }

    // ── utilization_bps edge cases ─────────────────────────────────────

    #[test]
    fn utilization_bps_one_remaining() {
        let bps = utilization_bps(100, 1);
        assert_eq!(bps, 9_900);
    }

    #[test]
    fn utilization_bps_small_limit() {
        assert_eq!(utilization_bps(1, 0), 10_000);
        assert_eq!(utilization_bps(1, 1), 0);
    }

    // ── EnforcementOutcome as_rate_limited_error ───────────────────────

    #[test]
    fn enforcement_outcome_rejected_no_violation_uses_backpressure_retry() {
        let out = EnforcementOutcome {
            allowed: false,
            state: RateLimitState {
                limit: 10,
                remaining: 0,
                reset_after: Duration::from_secs(5),
                is_limited: true,
            },
            backpressure: fcp_core::BackpressureSignal {
                level: fcp_core::BackpressureLevel::HardLimit,
                utilization_bps: 10_000,
                retry_after_ms: Some(5_000),
            },
            violation: None,
        };
        let err = out.as_rate_limited_error().unwrap();
        if let fcp_core::FcpError::RateLimited { retry_after_ms, .. } = err {
            assert_eq!(retry_after_ms, 5_000);
        } else {
            panic!("expected RateLimited");
        }
    }

    #[test]
    fn enforcement_outcome_rejected_no_retry_info() {
        let out = EnforcementOutcome {
            allowed: false,
            state: RateLimitState {
                limit: 10,
                remaining: 0,
                reset_after: Duration::ZERO,
                is_limited: true,
            },
            backpressure: fcp_core::BackpressureSignal {
                level: fcp_core::BackpressureLevel::HardLimit,
                utilization_bps: 10_000,
                retry_after_ms: None,
            },
            violation: None,
        };
        let err = out.as_rate_limited_error().unwrap();
        if let fcp_core::FcpError::RateLimited { retry_after_ms, .. } = err {
            assert_eq!(retry_after_ms, 0);
        } else {
            panic!("expected RateLimited");
        }
    }

    // ── config_from_core: burst of zero ────────────────────────────────

    #[test]
    fn config_from_core_burst_zero_adds_no_burst() {
        let core = fcp_core::RateLimit {
            max: 10,
            per_ms: 1000,
            burst: Some(0),
            scope: None,
            pool_name: None,
        };
        let cfg = config_from_core(&core).unwrap();
        // burst=0 → capacity = max + 0 = 10
        assert_eq!(cfg.burst_size, Some(10));
    }

    // ── ConcurrencyLimiter: in_flight after full exhaust ───────────────

    #[test]
    fn concurrency_limiter_in_flight_at_max() {
        let limiter = ConcurrencyLimiter::new(2).unwrap();
        let _p1 = limiter.try_acquire().unwrap();
        let _p2 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight(), 2);
        assert!(limiter.try_acquire().is_none());
        assert_eq!(limiter.in_flight(), 2); // Still 2
    }
}
