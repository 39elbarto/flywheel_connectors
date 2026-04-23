//! Cross-crate conformance tests for `fcp-ratelimit`'s token bucket invariants.
//!
//! These tests pin the public `RateLimiter` contract that downstream
//! connectors rely on:
//! - multi-permit acquisition is atomic
//! - refill phase is preserved across partial intervals
//! - zero-permit requests are a no-op
//! - `reset()` restores full burst capacity

use std::time::Duration;

use fcp_async_core::time::sleep;
use fcp_ratelimit::{RateLimitConfig, RateLimiter, TokenBucket};

#[fcp_async_core::runtime::test]
async fn token_bucket_multi_permit_acquire_is_atomic() {
    let limiter = TokenBucket::new(2, Duration::from_secs(1));

    assert!(
        !limiter.try_acquire_n(3).await,
        "oversized acquisition must fail"
    );
    assert_eq!(
        limiter.remaining(),
        2,
        "failed oversized acquisition must not partially consume tokens"
    );

    assert!(
        limiter.try_acquire_n(2).await,
        "exact-capacity acquisition should succeed"
    );
    assert_eq!(limiter.remaining(), 0);
}

#[fcp_async_core::runtime::test]
async fn token_bucket_refill_preserves_elapsed_phase() {
    let limiter = TokenBucket::new(1, Duration::from_millis(100));

    assert!(
        limiter.try_acquire().await,
        "initial token should be available"
    );

    sleep(Duration::from_millis(150)).await;
    assert!(
        limiter.try_acquire().await,
        "first elapsed refill should restore one token"
    );

    sleep(Duration::from_millis(50)).await;
    assert!(
        limiter.try_acquire().await,
        "remainder from the first refill window must be preserved"
    );
}

#[fcp_async_core::runtime::test]
async fn token_bucket_zero_permit_acquire_is_a_no_op() {
    let limiter = TokenBucket::new(3, Duration::from_secs(1));

    assert!(limiter.try_acquire_n(0).await);
    assert_eq!(
        limiter.remaining(),
        3,
        "zero-permit acquisition must not mutate bucket state"
    );
}

#[fcp_async_core::runtime::test]
async fn token_bucket_reset_restores_burst_capacity() {
    let limiter =
        TokenBucket::from_config(&RateLimitConfig::new(2, Duration::from_secs(1)).with_burst(4));

    assert!(limiter.try_acquire_n(4).await);
    let exhausted = limiter.state();
    assert_eq!(exhausted.limit, 4);
    assert_eq!(exhausted.remaining, 0);
    assert!(exhausted.is_limited);

    limiter.reset().await;

    let reset = limiter.state();
    assert_eq!(reset.limit, 4);
    assert_eq!(reset.remaining, 4);
    assert!(!reset.is_limited);
    assert_eq!(limiter.wait_time().await, Duration::ZERO);
}
