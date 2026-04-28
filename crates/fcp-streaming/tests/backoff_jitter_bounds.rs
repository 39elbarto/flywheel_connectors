//! Pin reconnect-backoff jitter range bounds and the floor/ceiling
//! invariants documented at reconnect.rs:93-156
//! (flywheel_connectors-5r5it, references the y54mi tightening).
//!
//! `ReconnectConfig::delay_for_attempt` enforces three NORMATIVE
//! invariants on the returned `Duration`:
//!
//!   1. **Floor**: never below `MIN_RECONNECT_DELAY` (100 ms) unless
//!      the caller pinned `max_delay` even lower.
//!   2. **Ceiling**: capped at `max_delay`.
//!   3. **Bounded jitter**: when `jitter` is enabled, the delay is
//!      `base × U[0.8, 1.2]` — a ±20 % envelope around the
//!      exponentially-scaled base. Tightened from the previous ±50 %
//!      so two clients reconnecting to the same upstream don't drift
//!      apart fast enough to lose useful batching at low attempt
//!      counts, but still wide enough to bust a synchronised
//!      reconnect storm.
//!
//! This test samples 100 iterations across multiple attempt counts
//! and asserts the jitter envelope is enforced AND the cap is never
//! exceeded. The production `random_float()` (reconnect.rs:283) wraps
//! the global `rand::random()` and is not seedable from outside; the
//! envelope assertions hold regardless of what random values are
//! drawn, which is the whole point of the contract being "bounded
//! jitter" rather than "this exact RNG sequence".

use std::time::Duration;

use fcp_streaming::{MAX_RECONNECT_DELAY, MIN_RECONNECT_DELAY, ReconnectConfig};

const ITERATIONS: usize = 100;

/// ±20 % envelope: `base * 0.8 <= delay <= base * 1.2`.
const JITTER_LOW_FACTOR: f64 = 0.8;
const JITTER_HIGH_FACTOR: f64 = 1.2;

#[test]
fn jitter_envelope_holds_across_100_samples_at_attempt_zero() {
    // attempt=0 ⇒ base = initial_delay. With initial_delay >= the
    // floor (100 ms), the floor is not binding, so the envelope is
    // [base * 0.8, base * 1.2].
    let initial = Duration::from_secs(1);
    let config = ReconnectConfig::new()
        .with_initial_delay(initial)
        .with_max_delay(Duration::from_secs(60))
        .with_backoff_multiplier(2.0)
        .with_jitter(true);

    let base_secs = initial.as_secs_f64();
    let lo = Duration::from_secs_f64(base_secs * JITTER_LOW_FACTOR);
    let hi = Duration::from_secs_f64(base_secs * JITTER_HIGH_FACTOR);

    let mut all_at_lo_bound = 0;
    let mut all_at_hi_bound = 0;
    for i in 0..ITERATIONS {
        let d = config.delay_for_attempt(0);
        assert!(
            d >= lo,
            "iteration {i}: delay {d:?} fell below jitter floor {lo:?} \
             (base={base_secs}, factor={JITTER_LOW_FACTOR})"
        );
        assert!(
            d <= hi,
            "iteration {i}: delay {d:?} exceeded jitter ceiling {hi:?} \
             (base={base_secs}, factor={JITTER_HIGH_FACTOR})"
        );
        if d == lo {
            all_at_lo_bound += 1;
        }
        if d == hi {
            all_at_hi_bound += 1;
        }
    }
    // Sanity: 100 samples should not all sit at one bound — that
    // would indicate the RNG returned the same float every call,
    // which means the jitter is effectively non-existent. We don't
    // require strict variance (the production RNG isn't seedable
    // here), but pinning a "not all clustered at the bound" check
    // catches regressions that flatten the distribution.
    assert!(
        all_at_lo_bound < ITERATIONS,
        "all 100 samples landed at the lower jitter bound — RNG appears flat"
    );
    assert!(
        all_at_hi_bound < ITERATIONS,
        "all 100 samples landed at the upper jitter bound — RNG appears flat"
    );
}

#[test]
fn jitter_envelope_holds_across_attempts_under_cap() {
    // Walk attempts 0..=4 with the default ±20% jitter and cap = 60 s,
    // initial_delay = 1 s, multiplier = 2. base sequence: 1, 2, 4, 8,
    // 16. All under the 60 s cap, so the cap doesn't clip and every
    // sample MUST land in [base * 0.8, base * 1.2].
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(60))
        .with_backoff_multiplier(2.0)
        .with_jitter(true);

    for attempt in 0..=4u32 {
        let base_secs = (1u64 << attempt) as f64;
        let lo = Duration::from_secs_f64(base_secs * JITTER_LOW_FACTOR);
        let hi = Duration::from_secs_f64(base_secs * JITTER_HIGH_FACTOR);
        for i in 0..ITERATIONS {
            let d = config.delay_for_attempt(attempt);
            assert!(
                d >= lo && d <= hi,
                "attempt={attempt}, iter={i}: delay {d:?} outside [{lo:?}, {hi:?}] \
                 (base={base_secs}s, ±20%)"
            );
        }
    }
}

#[test]
fn ceiling_is_never_exceeded_across_samples() {
    // Force the cap to be binding: enormous multiplier + small cap
    // means the post-jitter base would blow past the cap, but the
    // implementation MUST clamp.
    let cap = Duration::from_secs(5);
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_max_delay(cap)
        .with_backoff_multiplier(2.0)
        .with_jitter(true);

    // attempt=20 gives base = 2^20 = 1_048_576 seconds, way past 5 s.
    // Even with 1.2× jitter the ceiling MUST hold.
    for i in 0..ITERATIONS {
        let d = config.delay_for_attempt(20);
        assert!(
            d <= cap,
            "iter={i}: delay {d:?} exceeded the configured cap {cap:?}"
        );
    }

    // Sanity: at the cap (the most expected outcome here), the value
    // is exactly `cap`.
    let d = config.delay_for_attempt(20);
    assert_eq!(d, cap, "blown-past-cap delay must clamp exactly to cap");
}

#[test]
fn floor_holds_for_small_initial_delay() {
    // Tiny initial_delay (1 ms) — without the floor the result would
    // be sub-100ms. The floor (MIN_RECONNECT_DELAY = 100 ms) MUST
    // win.
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(1))
        .with_max_delay(Duration::from_secs(60))
        .with_backoff_multiplier(2.0)
        .with_jitter(true);

    for i in 0..ITERATIONS {
        let d = config.delay_for_attempt(0);
        assert!(
            d >= MIN_RECONNECT_DELAY,
            "iter={i}: delay {d:?} violated floor {MIN_RECONNECT_DELAY:?}"
        );
    }
}

#[test]
fn floor_yields_to_user_pinned_smaller_max_delay() {
    // If the caller pins `max_delay` BELOW the global floor, the
    // ceiling wins — we respect explicit user caps rather than
    // forcing the floor (reconnect.rs:148-152).
    let user_cap = Duration::from_millis(50);
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(1))
        .with_max_delay(user_cap)
        .with_backoff_multiplier(2.0)
        .with_jitter(true);

    for _ in 0..ITERATIONS {
        let d = config.delay_for_attempt(0);
        assert!(
            d <= user_cap,
            "user-pinned cap below MIN MUST still bind: delay={d:?}, cap={user_cap:?}"
        );
    }
}

#[test]
fn jitter_disabled_yields_deterministic_base() {
    // With jitter disabled, the result is deterministic across all
    // 100 samples — base × multiplier^attempt clamped to the
    // floor and ceiling.
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(60))
        .with_backoff_multiplier(2.0)
        .with_jitter(false);

    for attempt in 0..=4u32 {
        let expected = Duration::from_secs(1u64 << attempt);
        for i in 0..ITERATIONS {
            let d = config.delay_for_attempt(attempt);
            assert_eq!(
                d, expected,
                "attempt={attempt}, iter={i}: jitter disabled but delay {d:?} != {expected:?}"
            );
        }
    }
}

#[test]
fn cap_constants_match_module_documentation() {
    // The MIN_RECONNECT_DELAY (100 ms) and MAX_RECONNECT_DELAY (30 s)
    // are the documented FCP defaults. Any drift in those constants
    // changes the floor/ceiling semantics tested above.
    assert_eq!(
        MIN_RECONNECT_DELAY,
        Duration::from_millis(100),
        "MIN_RECONNECT_DELAY drift — jitter floor moved"
    );
    assert_eq!(
        MAX_RECONNECT_DELAY,
        Duration::from_secs(30),
        "MAX_RECONNECT_DELAY drift — default cap moved"
    );
}
