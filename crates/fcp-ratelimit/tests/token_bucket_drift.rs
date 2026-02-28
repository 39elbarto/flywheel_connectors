use fcp_async_core::time::sleep;
use fcp_ratelimit::{RateLimiter, TokenBucket};
use std::time::Duration;

#[fcp_async_core::runtime::test]
async fn test_token_bucket_drift() {
    // 10 tokens per second (100ms interval)
    // Capacity 1 (no burst storage beyond 1)
    let limiter = TokenBucket::new(1, Duration::from_millis(100));

    // Consume the initial token
    assert!(limiter.try_acquire().await, "Should acquire initial token");

    // Wait 150ms (1.5 intervals)
    // Should refill 1 token.
    // Remainder 50ms should be preserved.
    sleep(Duration::from_millis(150)).await;

    // Consume the refilled token
    assert!(limiter.try_acquire().await, "Should acquire refilled token");

    // Wait another 50ms.
    // Total time since last refill "event" should be 50ms (remainder) + 50ms (sleep) = 100ms.
    // So we should have another token ready!
    sleep(Duration::from_millis(50)).await;

    // This assertion fails with the current "reset to now" logic,
    // because the 50ms remainder was discarded.
    assert!(
        limiter.try_acquire().await,
        "Should preserve phase and allow acquire after total 200ms"
    );
}
