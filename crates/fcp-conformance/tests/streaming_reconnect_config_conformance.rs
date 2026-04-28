//! `ReconnectConfig::delay_for_attempt` + `ReconnectHandler` counter
//! discipline conformance.
//!
//! `ReconnectConfig::delay_for_attempt` is the documented backoff
//! function every streaming connector relies on. Its docstring
//! (capability.rs::y54mi) names THREE NORMATIVE invariants:
//!
//! 1. **Floor.** Never below `MIN_RECONNECT_DELAY` (100 ms) unless
//!    the caller pinned `max_delay` even lower. A zero or
//!    sub-millisecond `initial_delay` must NOT collapse the wait
//!    into a hot loop.
//! 2. **Ceiling.** Capped at `max_delay`.
//! 3. **Bounded jitter.** When enabled, the final delay is
//!    base × ±20 % (uniform in [0.8, 1.2]) — tighter than the
//!    legacy ±50 % so peers don't drift too far apart at low
//!    attempt counts.
//!
//! It also includes panic-safety guards: a misconfigured
//! `backoff_multiplier` (NaN / negative / extremely-large) and a
//! huge `max_delay` near `Duration::MAX` MUST NOT cause
//! `from_secs_f64` to panic. The clamp to `2^53` seconds is the
//! largest integer exactly representable in `f64`.
//!
//! `ReconnectHandler::record_failure` uses `saturating_add` so
//! `attempts` cannot wrap from `u32::MAX` back to zero — losing
//! the retry budget would let an attacker triggering many
//! synthetic failures eventually reset to "fresh".
//!
//! Zero conformance coverage for any of these despite the
//! pinning being explicitly named in source bead `y54mi`.

use std::time::Duration;

use fcp_streaming::{MIN_RECONNECT_DELAY, ReconnectConfig, ReconnectHandler};

#[test]
fn default_config_returns_floored_delay_at_attempt_zero() {
    // Default initial_delay is 1 s; jitter is on. The floor is
    // 100 ms, so at attempt 0 the returned delay MUST be >=
    // floor and <= max_delay.
    let config = ReconnectConfig::new();
    let d = config.delay_for_attempt(0);
    assert!(
        d >= MIN_RECONNECT_DELAY,
        "default attempt=0 delay must be >= floor (100 ms); got {d:?}"
    );
    assert!(
        d <= config.max_delay,
        "default attempt=0 delay must be <= max_delay; got {d:?}"
    );
}

#[test]
fn zero_initial_delay_is_floored_to_min_reconnect_delay() {
    // The documented floor invariant: a zero or sub-millisecond
    // initial_delay must NOT collapse to a hot retry loop.
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::ZERO)
        .with_jitter(false);
    for attempt in 0..5 {
        let d = config.delay_for_attempt(attempt);
        assert!(
            d >= MIN_RECONNECT_DELAY,
            "zero initial_delay must be floored to MIN_RECONNECT_DELAY at attempt {attempt}; got {d:?}"
        );
    }
}

#[test]
fn max_delay_below_floor_overrides_floor() {
    // The docstring spells out an exception: if the caller pins
    // max_delay BELOW the floor, the ceiling wins. We respect
    // explicit user caps rather than violating them to satisfy
    // the floor.
    let cap = Duration::from_millis(20);
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_millis(1))
        .with_max_delay(cap)
        .with_jitter(false);
    let d = config.delay_for_attempt(0);
    assert!(
        d <= cap,
        "explicit max_delay below the floor MUST win over the 100 ms floor; got {d:?} for cap={cap:?}"
    );
}

#[test]
fn delay_is_capped_at_max_delay() {
    let cap = Duration::from_secs(2);
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(10.0)
        .with_max_delay(cap)
        .with_jitter(false);

    for attempt in 0..30 {
        let d = config.delay_for_attempt(attempt);
        assert!(
            d <= cap,
            "delay_for_attempt({attempt}) MUST be capped at max_delay={cap:?}; got {d:?}"
        );
    }
}

#[test]
fn jitter_stays_within_plus_minus_20_percent_band() {
    // ±20 % jitter band: base × [0.8, 1.2]. Sample many times
    // and verify every result is in band.
    let base = Duration::from_secs(2);
    let config = ReconnectConfig::new()
        .with_initial_delay(base)
        .with_backoff_multiplier(1.0) // base stays at `base` regardless of attempt
        .with_max_delay(Duration::from_secs(60))
        .with_jitter(true);

    let lower = base.mul_f64(0.8);
    let upper = base.mul_f64(1.2);
    for _ in 0..256 {
        let d = config.delay_for_attempt(1);
        assert!(
            d >= lower && d <= upper,
            "jittered delay must be in [{lower:?}, {upper:?}]; got {d:?}"
        );
    }
}

#[test]
fn nan_backoff_multiplier_does_not_panic_and_falls_back_to_floor() {
    // Documented panic-safety guard: a NaN multiplier must not
    // cause from_secs_f64 to panic. The implementation clamps
    // NaN to 0 and then applies the floor.
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(f64::NAN)
        .with_jitter(false);

    let d = config.delay_for_attempt(3);
    assert!(
        d >= MIN_RECONNECT_DELAY,
        "NaN multiplier must clamp to 0 and then be floored to {MIN_RECONNECT_DELAY:?}; got {d:?}"
    );
    assert!(
        d <= config.max_delay,
        "delay must respect max_delay even with NaN multiplier; got {d:?}"
    );
}

#[test]
fn negative_backoff_multiplier_does_not_panic() {
    // Negative multipliers produce negative jittered values; the
    // clamp turns those into 0, then floor applies.
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(-2.0)
        .with_jitter(false);

    for attempt in 0..10 {
        let d = config.delay_for_attempt(attempt);
        assert!(d >= MIN_RECONNECT_DELAY);
        assert!(d <= config.max_delay);
    }
}

#[test]
fn extreme_backoff_does_not_panic_at_high_attempt_count() {
    // 10x multiplier at attempt=300 would overflow f64::powi to
    // +inf. The clamp must catch that before from_secs_f64.
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(10.0)
        .with_max_delay(Duration::from_secs(30))
        .with_jitter(false);

    for attempt in [0_u32, 50, 100, 200, 300, 1000] {
        let d = config.delay_for_attempt(attempt);
        assert!(
            d <= config.max_delay,
            "attempt={attempt} delay must remain capped at max_delay; got {d:?}"
        );
    }
}

#[test]
fn huge_max_delay_does_not_panic() {
    // The docstring explicitly calls out this case: a max_delay
    // near Duration::MAX combined with an overflowing jittered
    // value previously panicked inside from_secs_f64. The
    // implementation now clamps to 2^53 seconds.
    let config = ReconnectConfig::new()
        .with_initial_delay(Duration::from_secs(1))
        .with_backoff_multiplier(2.0)
        .with_max_delay(Duration::MAX)
        .with_jitter(false);

    // Many attempts; the only assertion is "did not panic".
    for attempt in [0_u32, 10, 50, 100, 1000] {
        let _ = config.delay_for_attempt(attempt);
    }
}

#[test]
fn record_failure_saturates_at_u32_max() {
    // The handler's saturating_add discipline (br-upgdb): extra
    // failures don't wrap from u32::MAX back to 0. Otherwise an
    // attacker could engineer u32::MAX failures to reset the
    // retry budget.
    let config = ReconnectConfig::new().with_max_attempts(5);
    let mut handler = ReconnectHandler::new(config);

    // We can't realistically call record_failure 4 billion times,
    // but we can call it past max_attempts and verify the counter
    // continues to advance (saturating, not wrapping) and the
    // can_reconnect contract holds.
    for _ in 0..20 {
        handler.record_failure();
    }
    assert_eq!(handler.attempts(), 20);
    assert!(
        !handler.can_reconnect(),
        "after >max_attempts failures, can_reconnect MUST return false"
    );
}

#[test]
fn record_failure_then_reset_clears_attempts_to_zero() {
    let config = ReconnectConfig::new().with_max_attempts(5);
    let mut handler = ReconnectHandler::new(config);
    for _ in 0..3 {
        handler.record_failure();
    }
    assert_eq!(handler.attempts(), 3);
    handler.reset();
    assert_eq!(
        handler.attempts(),
        0,
        "reset() MUST clear the attempts counter to zero"
    );
    assert!(
        handler.can_reconnect(),
        "after reset(), can_reconnect MUST return true (under the configured cap)"
    );
}

#[test]
fn unlimited_attempts_can_reconnect_remains_true() {
    // with_unlimited_attempts() sets max_attempts = None, so
    // can_reconnect MUST always return true regardless of how
    // many failures have been recorded.
    let config = ReconnectConfig::new().with_unlimited_attempts();
    let mut handler = ReconnectHandler::new(config);
    for _ in 0..1000 {
        handler.record_failure();
    }
    assert!(
        handler.can_reconnect(),
        "max_attempts=None must always allow reconnect, even after 1000 failures"
    );
}
