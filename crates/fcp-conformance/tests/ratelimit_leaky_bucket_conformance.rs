//! Cross-crate conformance tests for `fcp-ratelimit`'s `LeakyBucket`
//! flow-control invariants.
//!
//! `LeakyBucket` is the pacing-style sibling of `TokenBucket` (the
//! latter is already pinned in `ratelimit_token_bucket_conformance.rs`).
//! It enforces a constant leak rate with a fixed bucket capacity, and
//! is the backpressure path connectors rely on to smooth requests
//! against an upstream service.
//!
//! These tests pin the public `RateLimiter` contract that callers
//! depend on, in particular:
//!
//! - multi-permit acquisition is atomic (no partial consumption when
//!   the bucket cannot satisfy the full request),
//! - the leak refills capacity proportionally to elapsed time,
//! - `wait_time` reports the actual time until the next permit slot,
//! - `acquire(max_wait)` surfaces `RateLimitError::WaitExceeded` when
//!   the projected wait exceeds the caller's budget — without this,
//!   the caller's deadline contract evaporates,
//! - `reset()` zeroes the bucket level,
//! - `from_window` produces an equivalent steady-state throughput.

use std::time::Duration;

use fcp_async_core::time::sleep;
use fcp_ratelimit::{LeakyBucket, RateLimitError, RateLimiter};

#[fcp_async_core::runtime::test]
async fn zero_permit_acquire_is_a_no_op() {
    let limiter = LeakyBucket::new(3, 100.0);
    assert!(
        limiter.try_acquire_n(0).await,
        "zero-permit acquire must succeed without mutating state"
    );
    assert_eq!(
        limiter.remaining(),
        3,
        "bucket must remain at full capacity after a zero-permit acquire"
    );
}

#[fcp_async_core::runtime::test]
async fn exact_capacity_acquire_succeeds() {
    let limiter = LeakyBucket::new(2, 1.0);
    assert!(
        limiter.try_acquire_n(2).await,
        "acquiring exactly the capacity must succeed"
    );
}

#[fcp_async_core::runtime::test]
async fn over_capacity_multi_permit_acquire_is_atomic() {
    // Oversized acquisition must reject without partially consuming
    // the bucket — otherwise a caller hitting an oversized burst
    // would silently drain the limiter.
    let limiter = LeakyBucket::new(2, 1.0);
    assert!(
        !limiter.try_acquire_n(3).await,
        "oversized acquisition must fail"
    );
    assert_eq!(
        limiter.remaining(),
        2,
        "failed oversized acquisition must not partially consume the bucket"
    );

    // The bucket must still satisfy a within-capacity acquire afterwards.
    assert!(
        limiter.try_acquire_n(2).await,
        "exact-capacity acquisition after a rejected oversized one must succeed"
    );
}

#[fcp_async_core::runtime::test]
async fn consecutive_acquires_drain_capacity_until_empty() {
    let limiter = LeakyBucket::new(3, 0.001); // glacial leak so drains are observable
    assert!(limiter.try_acquire().await);
    assert!(limiter.try_acquire().await);
    assert!(limiter.try_acquire().await);
    assert!(
        !limiter.try_acquire().await,
        "fourth acquire must reject — the bucket is full"
    );
}

#[fcp_async_core::runtime::test]
async fn leak_recovers_capacity_after_elapsed_time() {
    // 10 permits per second leak rate. Drain to full, sleep ~150 ms,
    // expect at least 1 permit refilled.
    let limiter = LeakyBucket::new(2, 10.0);
    assert!(limiter.try_acquire().await);
    assert!(limiter.try_acquire().await);
    assert!(
        !limiter.try_acquire().await,
        "fixture sanity: bucket is full"
    );

    sleep(Duration::from_millis(150)).await;

    assert!(
        limiter.try_acquire().await,
        "after a 150 ms wait at 10 permits/sec, at least one permit must be available"
    );
}

#[fcp_async_core::runtime::test]
async fn wait_time_is_zero_when_capacity_is_available() {
    let limiter = LeakyBucket::new(2, 1.0);
    assert_eq!(
        limiter.wait_time().await,
        Duration::ZERO,
        "wait_time on an empty bucket must be zero"
    );
}

#[fcp_async_core::runtime::test]
async fn wait_time_is_nonzero_when_bucket_is_full() {
    let limiter = LeakyBucket::new(1, 10.0);
    assert!(limiter.try_acquire().await);
    assert!(
        limiter.wait_time().await > Duration::ZERO,
        "wait_time on a saturated bucket must report nonzero remaining drain time"
    );
}

#[fcp_async_core::runtime::test]
async fn acquire_returns_wait_exceeded_when_max_wait_too_short() {
    // Bucket holds 1; leak rate is 1/sec. After acquiring once, the
    // next acquire would require ~1 second of leak. With max_wait of
    // 10ms, the limiter must surface WaitExceeded — that's the
    // contract callers rely on to honour deadlines.
    let limiter = LeakyBucket::new(1, 1.0);
    assert!(limiter.try_acquire().await);

    let result = limiter.acquire(Duration::from_millis(10)).await;
    match result {
        Err(RateLimitError::WaitExceeded {
            wait_time,
            max_wait,
        }) => {
            assert_eq!(
                max_wait,
                Duration::from_millis(10),
                "max_wait must be reported back unchanged"
            );
            assert!(
                wait_time > max_wait,
                "wait_time must exceed max_wait when WaitExceeded is returned"
            );
        }
        other => panic!("expected WaitExceeded, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn reset_clears_bucket_level_to_zero() {
    let limiter = LeakyBucket::new(3, 0.001);
    assert!(limiter.try_acquire_n(3).await);
    assert!(
        !limiter.try_acquire().await,
        "fixture sanity: drained to full"
    );

    limiter.reset().await;

    assert_eq!(limiter.remaining(), 3, "reset must restore full capacity");
    assert_eq!(
        limiter.wait_time().await,
        Duration::ZERO,
        "reset must clear any pending wait_time"
    );
    assert!(
        limiter.try_acquire_n(3).await,
        "reset must allow re-acquiring full capacity"
    );
}

#[fcp_async_core::runtime::test]
async fn from_window_produces_equivalent_throughput_to_explicit_leak_rate() {
    // from_window(10, 1s) should be equivalent to new(10, 10.0) for
    // the steady-state leak rate (10 permits per second). After
    // draining, both must report comparable wait_time.
    let from_window = LeakyBucket::from_window(10, Duration::from_secs(1));
    let from_explicit = LeakyBucket::new(10, 10.0);

    for _ in 0..10 {
        assert!(from_window.try_acquire().await);
        assert!(from_explicit.try_acquire().await);
    }

    let w1 = from_window.wait_time().await;
    let w2 = from_explicit.wait_time().await;
    // Allow a generous tolerance since wall clock between the two
    // .leak() calls advances by some small amount; the equivalence
    // claim is on the configured rate, not microsecond-perfect drain.
    let diff = if w1 > w2 { w1 - w2 } else { w2 - w1 };
    assert!(
        diff < Duration::from_millis(50),
        "from_window and explicit-rate constructors must agree to within 50 ms; \
         got w1={w1:?}, w2={w2:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn state_reports_limit_remaining_and_is_limited() {
    let limiter = LeakyBucket::new(4, 0.001);
    let s_initial = limiter.state();
    assert_eq!(s_initial.limit, 4);
    assert_eq!(s_initial.remaining, 4);
    assert!(
        !s_initial.is_limited,
        "fresh bucket must not report is_limited"
    );

    assert!(limiter.try_acquire_n(4).await);

    let s_full = limiter.state();
    assert_eq!(s_full.limit, 4, "limit must not change on acquire");
    assert!(
        s_full.is_limited,
        "saturated bucket must report is_limited=true"
    );
}
