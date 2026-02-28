//! Unit tests for rate limiting behaviors per flywheel_connectors-oz1v.
//!
//! Validates:
//! - `ThrottleViolation` detection and details
//! - Backpressure signals
//! - Quota enforcement (per-connector, per-zone, per-operation)
//! - Burst handling (token bucket behavior)

use std::time::Duration;

use fcp_async_core::time::sleep;
use fcp_core::{BackpressureLevel, LimitType, ThrottleViolation, ThrottleViolationInput};
use fcp_ratelimit::{
    BackpressureThresholds, ConcurrencyLimiter, RateLimitConfig, RateLimiter, ThrottleContext,
    TokenBucket, config_from_core, enforce,
};

// ============================================================================
// ThrottleViolation Detection Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn throttle_violation_includes_all_required_fields() {
    // Given a rate limiter at capacity
    let limiter = TokenBucket::new(1, Duration::from_secs(60));
    assert!(limiter.try_acquire().await);

    // And a context with all optional fields populated
    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: Some("fcp.anthropic:chat:1.0.0".parse().unwrap()),
        operation_id: Some("chat.completions.create".parse().unwrap()),
        limit_type: LimitType::Rpm,
    };

    // When we try to exceed the limit
    let outcome = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;

    // Then a violation is emitted with all details
    assert!(!outcome.allowed);
    let violation = outcome.violation.expect("violation should be present");

    assert_eq!(violation.zone_id.as_str(), "z:work");
    assert!(violation.connector_id.is_some());
    assert_eq!(
        violation.connector_id.as_ref().unwrap().as_str(),
        "fcp.anthropic:chat:1.0.0"
    );
    assert!(violation.operation_id.is_some());
    assert_eq!(
        violation.operation_id.as_ref().unwrap().as_str(),
        "chat.completions.create"
    );
    assert_eq!(violation.limit_type, LimitType::Rpm);
    assert_eq!(violation.limit_value, 1);
    assert!(violation.current_value >= 1);
    assert!(violation.retry_after_ms > 0);
}

#[fcp_async_core::runtime::test]
async fn throttle_violation_retry_after_reflects_reset_time() {
    // Given a limiter with a short window
    let limiter = TokenBucket::new(1, Duration::from_millis(100));
    assert!(limiter.try_acquire().await);

    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let outcome = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
    let violation = outcome.violation.expect("violation expected");

    // retry_after_ms should be ≤ 100ms (the window)
    assert!(
        violation.retry_after_ms <= 100,
        "retry_after_ms {} should be <= window 100ms",
        violation.retry_after_ms
    );
}

#[fcp_async_core::runtime::test]
async fn throttle_violation_distinguishes_limit_types() {
    // Test RPM limit type
    let violation_rpm = ThrottleViolation::new(ThrottleViolationInput {
        timestamp_ms: 1000,
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
        limit_value: 60,
        current_value: 61,
        retry_after_ms: 1000,
    });
    assert_eq!(violation_rpm.limit_type, LimitType::Rpm);

    // Test Concurrent limit type
    let violation_concurrent = ThrottleViolation::new(ThrottleViolationInput {
        timestamp_ms: 1000,
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Concurrent,
        limit_value: 5,
        current_value: 6,
        retry_after_ms: 0,
    });
    assert_eq!(violation_concurrent.limit_type, LimitType::Concurrent);

    // Test Quota limit type
    let violation_quota = ThrottleViolation::new(ThrottleViolationInput {
        timestamp_ms: 1000,
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Quota,
        limit_value: 1000,
        current_value: 1001,
        retry_after_ms: 3_600_000,
    });
    assert_eq!(violation_quota.limit_type, LimitType::Quota);

    // Test Burst limit type
    let violation_burst = ThrottleViolation::new(ThrottleViolationInput {
        timestamp_ms: 1000,
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Burst,
        limit_value: 10,
        current_value: 11,
        retry_after_ms: 100,
    });
    assert_eq!(violation_burst.limit_type, LimitType::Burst);
}

// ============================================================================
// Backpressure Signal Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn backpressure_warning_at_80_percent() {
    let limiter = TokenBucket::new(100, Duration::from_secs(60));

    // Consume 80 tokens (exactly 80% utilization)
    for _ in 0..80 {
        assert!(limiter.try_acquire().await);
    }

    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let outcome = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
    assert!(outcome.allowed);
    assert_eq!(outcome.backpressure.level, BackpressureLevel::Warning);
    assert!(outcome.backpressure.utilization_bps >= 8000);
}

#[fcp_async_core::runtime::test]
async fn backpressure_soft_limit_at_95_percent() {
    let limiter = TokenBucket::new(100, Duration::from_secs(60));

    // Consume 95 tokens
    for _ in 0..95 {
        assert!(limiter.try_acquire().await);
    }

    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let outcome = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
    assert!(outcome.allowed);
    assert_eq!(outcome.backpressure.level, BackpressureLevel::SoftLimit);
    assert!(outcome.backpressure.retry_after_ms.is_some());
}

#[fcp_async_core::runtime::test]
async fn backpressure_hard_limit_at_100_percent() {
    let limiter = TokenBucket::new(10, Duration::from_secs(60));

    // Consume all tokens
    for _ in 0..10 {
        assert!(limiter.try_acquire().await);
    }

    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let outcome = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
    assert!(!outcome.allowed);
    assert_eq!(outcome.backpressure.level, BackpressureLevel::HardLimit);
    assert!(outcome.violation.is_some());
}

#[fcp_async_core::runtime::test]
async fn backpressure_clears_after_refill() {
    let limiter = TokenBucket::new(2, Duration::from_millis(50));

    // Exhaust tokens
    assert!(limiter.try_acquire().await);
    assert!(limiter.try_acquire().await);
    assert!(!limiter.try_acquire().await);

    // Wait for refill
    sleep(Duration::from_millis(60)).await;

    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let outcome = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
    assert!(outcome.allowed);
    assert_eq!(outcome.backpressure.level, BackpressureLevel::Normal);
}

// ============================================================================
// Per-Connector/Zone/Operation Quota Enforcement Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn different_zones_have_independent_quotas() {
    // Simulate separate limiters per zone (as would be done in real enforcement)
    let limiter_work = TokenBucket::new(5, Duration::from_secs(60));
    let limiter_private = TokenBucket::new(5, Duration::from_secs(60));

    // Exhaust work zone quota
    for _ in 0..5 {
        assert!(limiter_work.try_acquire().await);
    }
    assert!(!limiter_work.try_acquire().await);

    // Private zone should still have quota
    assert!(limiter_private.try_acquire().await);

    // Verify contexts track zone correctly
    let ctx_work = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let ctx_private = ThrottleContext {
        zone_id: "z:private".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let outcome_work = enforce(
        &limiter_work,
        1,
        &ctx_work,
        BackpressureThresholds::standard(),
    )
    .await;
    assert!(!outcome_work.allowed);
    assert_eq!(
        outcome_work.violation.as_ref().unwrap().zone_id.as_str(),
        "z:work"
    );

    let outcome_private = enforce(
        &limiter_private,
        1,
        &ctx_private,
        BackpressureThresholds::standard(),
    )
    .await;
    assert!(outcome_private.allowed);
}

#[fcp_async_core::runtime::test]
async fn different_connectors_tracked_in_violations() {
    let limiter = TokenBucket::new(1, Duration::from_secs(60));
    assert!(limiter.try_acquire().await);

    let ctx_anthropic = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: Some("fcp.anthropic:chat:1.0.0".parse().unwrap()),
        operation_id: None,
        limit_type: LimitType::Rpm,
    };

    let outcome = enforce(
        &limiter,
        1,
        &ctx_anthropic,
        BackpressureThresholds::standard(),
    )
    .await;
    let violation = outcome.violation.expect("violation expected");
    assert_eq!(
        violation.connector_id.as_ref().unwrap().as_str(),
        "fcp.anthropic:chat:1.0.0"
    );
}

#[fcp_async_core::runtime::test]
async fn different_operations_tracked_in_violations() {
    let limiter = TokenBucket::new(1, Duration::from_secs(60));
    assert!(limiter.try_acquire().await);

    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: Some("fcp.openai:chat:2.0.0".parse().unwrap()),
        operation_id: Some("chat.completions.create".parse().unwrap()),
        limit_type: LimitType::Rpm,
    };

    let outcome = enforce(&limiter, 1, &ctx, BackpressureThresholds::standard()).await;
    let violation = outcome.violation.expect("violation expected");
    assert_eq!(
        violation.operation_id.as_ref().unwrap().as_str(),
        "chat.completions.create"
    );
}

// ============================================================================
// Burst Handling Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn token_bucket_allows_configured_burst() {
    // Create a bucket with base rate 10/min but burst capacity of 20
    let limiter = TokenBucket::with_burst(10, Duration::from_secs(60), 20);

    // Should allow 20 requests in burst
    for i in 0..20 {
        assert!(
            limiter.try_acquire().await,
            "request {i} should be allowed within burst"
        );
    }

    // 21st should fail
    assert!(
        !limiter.try_acquire().await,
        "burst limit should be enforced"
    );
}

#[fcp_async_core::runtime::test]
async fn burst_capacity_is_configurable() {
    let config_no_burst = RateLimitConfig::new(10, Duration::from_secs(60));
    let limiter_no_burst = TokenBucket::from_config(&config_no_burst);

    let config_with_burst = RateLimitConfig::new(10, Duration::from_secs(60)).with_burst(50);
    let limiter_with_burst = TokenBucket::from_config(&config_with_burst);

    // No-burst limiter: exactly 10 requests
    for _ in 0..10 {
        assert!(limiter_no_burst.try_acquire().await);
    }
    assert!(!limiter_no_burst.try_acquire().await);

    // With-burst limiter: 50 requests
    for _ in 0..50 {
        assert!(limiter_with_burst.try_acquire().await);
    }
    assert!(!limiter_with_burst.try_acquire().await);
}

#[fcp_async_core::runtime::test]
async fn burst_doesnt_exceed_hard_limit() {
    // Even with burst configured, cannot exceed capacity
    let limiter = TokenBucket::with_burst(5, Duration::from_secs(60), 10);

    // Try to acquire more than capacity atomically
    assert!(!limiter.try_acquire_n(11).await);

    // Remaining should be unchanged (atomic all-or-nothing)
    assert_eq!(limiter.remaining(), 10);
}

#[fcp_async_core::runtime::test]
async fn burst_refill_rate_is_correct() {
    // TokenBucket::new refills the entire bucket after the window, not smoothly.
    // Use a small window to test refill behavior
    let limiter = TokenBucket::new(2, Duration::from_millis(50));

    // Exhaust all tokens
    assert!(limiter.try_acquire().await);
    assert!(limiter.try_acquire().await);
    assert!(!limiter.try_acquire().await);
    assert_eq!(limiter.remaining(), 0);

    // Wait for full window refill
    sleep(Duration::from_millis(60)).await;

    // Should have tokens again
    assert!(
        limiter.try_acquire().await,
        "tokens should refill after window period"
    );
}

// ============================================================================
// Concurrency Limiter Tests
// ============================================================================

#[test]
fn concurrency_limiter_basic_operation() {
    let limiter = ConcurrencyLimiter::new(2).unwrap();
    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Concurrent,
    };

    // Acquire 2 permits
    let _p1 = limiter.try_acquire_or_violation(&ctx).unwrap();
    let _p2 = limiter.try_acquire_or_violation(&ctx).unwrap();

    // Third should fail
    let err = limiter.try_acquire_or_violation(&ctx).unwrap_err();
    assert!(matches!(err, fcp_core::FcpError::RateLimited { .. }));
}

#[test]
fn concurrency_limiter_releases_on_drop() {
    let limiter = ConcurrencyLimiter::new(1).unwrap();
    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: None,
        operation_id: None,
        limit_type: LimitType::Concurrent,
    };

    {
        let _permit = limiter.try_acquire_or_violation(&ctx).unwrap();
        assert!(limiter.try_acquire().is_none());
    }

    // After drop, should be able to acquire again
    assert!(limiter.try_acquire().is_some());
}

#[test]
fn concurrency_limiter_violation_has_correct_limit_type() {
    let limiter = ConcurrencyLimiter::new(1).unwrap();
    let ctx = ThrottleContext {
        zone_id: "z:work".parse().unwrap(),
        connector_id: Some("fcp.test:conn:1.0.0".parse().unwrap()),
        operation_id: None,
        limit_type: LimitType::Concurrent,
    };

    let _p = limiter.try_acquire_or_violation(&ctx).unwrap();
    let err = limiter.try_acquire_or_violation(&ctx).unwrap_err();

    if let fcp_core::FcpError::RateLimited { violation, .. } = err {
        let v = violation.expect("violation expected");
        assert_eq!(v.limit_type, LimitType::Concurrent);
        assert_eq!(v.limit_value, 1);
    } else {
        panic!("expected RateLimited error");
    }
}

// ============================================================================
// Config from Core Tests
// ============================================================================

#[test]
fn config_from_core_with_burst_interprets_as_additional() {
    let rate = fcp_core::RateLimit {
        max: 100,
        per_ms: 60_000,
        burst: Some(20),
        scope: None,
        pool_name: None,
    };

    let cfg = config_from_core(&rate).unwrap();
    // burst_size = max + burst = 100 + 20 = 120
    assert_eq!(cfg.burst_size, Some(120));
}

#[test]
fn config_from_core_without_burst() {
    let rate = fcp_core::RateLimit {
        max: 50,
        per_ms: 1_000,
        burst: None,
        scope: None,
        pool_name: None,
    };

    let cfg = config_from_core(&rate).unwrap();
    assert_eq!(cfg.requests_per_window, 50);
    assert_eq!(cfg.window, Duration::from_secs(1));
    assert_eq!(cfg.burst_size, None);
}
