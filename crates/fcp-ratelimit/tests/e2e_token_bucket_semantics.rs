use fcp_ratelimit::{RateLimitConfig, RateLimiter, TokenBucket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tracing::{Level, span};

#[test]
fn e2e_token_bucket_overflow_concurrent_claim_and_reset() {
    let mut phases = Vec::new();

    {
        let span = span!(
            Level::INFO,
            "e2e_ratelimit_phase",
            crate_name = "fcp-ratelimit",
            phase = "duration_overflow_guard"
        );
        let _entered = span.enter();
        phases.push("duration_overflow_guard");
        let config = RateLimitConfig::new(u32::MAX, Duration::MAX).with_burst(8);
        let limiter = TokenBucket::from_config(&config);
        assert_eq!(limiter.remaining(), 8);
        assert!(fcp_async_core::runtime::block_on_sync(limiter.try_acquire_n(8)).expect("runtime"));
        assert!(
            !fcp_async_core::runtime::block_on_sync(limiter.acquire(Duration::from_millis(1)))
                .expect("runtime")
                .is_ok()
        );
    }

    let limiter = Arc::new(TokenBucket::new(8, Duration::from_secs(60)));
    let successes = Arc::new(AtomicU32::new(0));

    {
        let span = span!(
            Level::INFO,
            "e2e_ratelimit_phase",
            crate_name = "fcp-ratelimit",
            phase = "concurrent_claim"
        );
        let _entered = span.enter();
        phases.push("concurrent_claim");
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let successes = Arc::clone(&successes);
                std::thread::spawn(move || {
                    let acquired = fcp_async_core::runtime::block_on_sync(limiter.try_acquire())
                        .expect("runtime");
                    if acquired {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("claim thread");
        }
        assert_eq!(successes.load(Ordering::SeqCst), 8);
        assert_eq!(limiter.remaining(), 0);
    }

    {
        let span = span!(
            Level::INFO,
            "e2e_ratelimit_phase",
            crate_name = "fcp-ratelimit",
            phase = "reset_semantics"
        );
        let _entered = span.enter();
        phases.push("reset_semantics");
        fcp_async_core::runtime::block_on_sync(limiter.reset()).expect("runtime");
        let state = limiter.state();
        assert_eq!(state.limit, 8);
        assert_eq!(state.remaining, 8);
        assert!(!state.is_limited);
        assert!(fcp_async_core::runtime::block_on_sync(limiter.try_acquire_n(8)).expect("runtime"));
        assert!(!fcp_async_core::runtime::block_on_sync(limiter.try_acquire()).expect("runtime"));
    }

    assert_eq!(
        phases,
        [
            "duration_overflow_guard",
            "concurrent_claim",
            "reset_semantics"
        ]
    );
}
